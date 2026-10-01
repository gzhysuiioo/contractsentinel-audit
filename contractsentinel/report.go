// Package contractsentinel report: content-addressed, persistable audit reports.
package contractsentinel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// Check statuses recorded per rule in a report.
const (
	StatusUnchecked   = "未检查"
	StatusPass        = "通过"
	StatusDefect      = "发现缺陷"
	StatusToolMissing = "工具缺失"
	StatusTimeout     = "超时"
)

// CheckRecord is an externally produced check result imported with a
// submission. It binds a rule conclusion to the artifact hash and rule
// version that were submitted alongside it; Note carries the counterexample
// or other defect evidence for 发现缺陷, and names the unavailable tool or
// unfinished check for 工具缺失/超时.
type CheckRecord struct {
	ArtifactHash string
	RuleID       string
	RuleVersion  string
	Status       string
	Note         string
}

// ReportArtifact identifies the audited artifact by name and content hash.
type ReportArtifact struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// ReportRule is one rule together with the invariant check result. Note is
// the original explanation submitted with an imported check: counterexample
// or defect evidence for 发现缺陷, the missing tool or unfinished check for
// 工具缺失/超时. It is empty for boolean-derived results and for empty 通过
// explanations, and participates in the report id.
type ReportRule struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Invariant   string `json:"invariant"`
	RequiresABI bool   `json:"requiresABI"`
	Version     string `json:"version"`
	Status      string `json:"status"`
	Note        string `json:"note,omitempty"`
}

// ReportFinding binds a defect to its artifact, rule, version and evidence.
type ReportFinding struct {
	ArtifactHash string `json:"artifactHash"`
	RuleID       string `json:"ruleId"`
	Version      string `json:"version"`
	Severity     string `json:"severity"`
	Invariant    string `json:"invariant"`
	Evidence     string `json:"evidence"`
}

// Report is the persisted audit result.
type Report struct {
	ReportID string          `json:"reportId"`
	Artifact ReportArtifact  `json:"artifact"`
	Rules    []ReportRule    `json:"rules"`
	Findings []ReportFinding `json:"findings"`
}

// wireArtifact is the JSON shape of an artifact in an audit submission.
type wireArtifact struct {
	Name     string `json:"name"`
	ABI      string `json:"abi"`
	Bytecode string `json:"bytecode"`
	Source   string `json:"source"`
}

// wireRule is the JSON shape of a rule in an audit submission.
type wireRule struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Invariant   string `json:"invariant"`
	RequiresABI bool   `json:"requiresABI"`
	Version     string `json:"version"`
}

// wireCheck is the JSON shape of one imported check result.
type wireCheck struct {
	ArtifactHash string `json:"artifactHash"`
	RuleID       string `json:"ruleId"`
	RuleVersion  string `json:"ruleVersion"`
	Status       string `json:"status"`
	Note         string `json:"note"`
}

// wireInput is the JSON object accepted by the audit command.
type wireInput struct {
	Artifact   wireArtifact               `json:"artifact"`
	Rules      []wireRule                 `json:"rules"`
	Invariants map[string]json.RawMessage `json:"invariants"`
	Checks     []wireCheck                `json:"checks"`
}

// ParseAuditInput decodes an audit submission JSON object into domain values.
// Invariant values must be JSON booleans; any other type is an error. Check
// records are decoded as submitted and fully validated by BuildReport.
func ParseAuditInput(data []byte) (Artifact, []Rule, map[string]bool, []CheckRecord, error) {
	var in wireInput
	if err := json.Unmarshal(data, &in); err != nil {
		return Artifact{}, nil, nil, nil, errInvalid("invalid JSON: " + err.Error())
	}
	invariants := make(map[string]bool, len(in.Invariants))
	for key, raw := range in.Invariants {
		var holds bool
		if err := json.Unmarshal(raw, &holds); err != nil {
			return Artifact{}, nil, nil, nil, errInvalid("invariant " + key + " must be a boolean")
		}
		invariants[key] = holds
	}
	artifact := Artifact{
		Name:     in.Artifact.Name,
		ABI:      in.Artifact.ABI,
		Bytecode: in.Artifact.Bytecode,
		Source:   in.Artifact.Source,
	}
	rules := make([]Rule, 0, len(in.Rules))
	for _, wr := range in.Rules {
		rules = append(rules, Rule{
			ID:          wr.ID,
			Kind:        wr.Kind,
			Severity:    wr.Severity,
			Invariant:   wr.Invariant,
			RequiresABI: wr.RequiresABI,
			Version:     wr.Version,
		})
	}
	checks := make([]CheckRecord, 0, len(in.Checks))
	for _, wc := range in.Checks {
		checks = append(checks, CheckRecord{
			ArtifactHash: wc.ArtifactHash,
			RuleID:       wc.RuleID,
			RuleVersion:  wc.RuleVersion,
			Status:       wc.Status,
			Note:         wc.Note,
		})
	}
	return artifact, rules, invariants, checks, nil
}

// ArtifactHash computes the content hash of an artifact. Only the raw ABI,
// bytecode and source strings contribute; field boundaries are explicit
// (length-prefixed) so that different splits never collide. The source is
// hashed as a field value, never read from disk, and the name does not
// participate.
func ArtifactHash(a Artifact) string {
	h := sha256.New()
	h.Write([]byte("contractsentinel-artifact-v1\n"))
	for _, field := range []string{a.ABI, a.Bytecode, a.Source} {
		fmt.Fprintf(h, "%d\n", len(field))
		h.Write([]byte(field))
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

// BuildReport evaluates rules against the artifact, invariant values and
// imported check records and produces the report to persist. Insufficient
// inputs (missing ABI for a rule that requires it, missing bytecode for a
// symbolic rule) fail the whole submission and are never recorded as
// defects; a 工具缺失/超时 check cannot bypass those requirements either.
func BuildReport(artifact Artifact, rules []Rule, invariants map[string]bool) (Report, error) {
	return BuildReportWithChecks(artifact, rules, invariants, nil)
}

// validCheckStatus reports whether s is one of the four statuses an imported
// check record may carry.
func validCheckStatus(s string) bool {
	switch s {
	case StatusPass, StatusDefect, StatusToolMissing, StatusTimeout:
		return true
	}
	return false
}

// noteRequired reports whether a status demands a non-whitespace explanation.
func noteRequired(status string) bool {
	return status == StatusDefect || status == StatusToolMissing || status == StatusTimeout
}

// BuildReportWithChecks is BuildReport with externally imported check
// results. Each check must target a known rule, match this submission's
// artifact hash and the rule's current version, carry a known status, and
// explain 发现缺陷/工具缺失/超时 with non-whitespace text. A rule that
// receives a check record must not also receive its invariant as a boolean
// in the same submission. Any violation rejects the whole submission.
func BuildReportWithChecks(artifact Artifact, rules []Rule, invariants map[string]bool, checks []CheckRecord) (Report, error) {
	if artifact.Name == "" {
		return Report{}, errInvalid("artifact name is required")
	}
	ruleByID := make(map[string]Rule, len(rules))
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if rule.ID == "" {
			return Report{}, errInvalid("rule id is required")
		}
		if rule.Version == "" {
			return Report{}, errInvalid("rule " + rule.ID + " version is required")
		}
		if seen[rule.ID] {
			return Report{}, errInvalid("duplicate rule id " + rule.ID)
		}
		seen[rule.ID] = true
		if rule.RequiresABI && artifact.ABI == "" {
			return Report{}, errInvalid("rule " + rule.ID + " requires an ABI")
		}
		if rule.Kind == "symbolic" && artifact.Bytecode == "" {
			return Report{}, errInvalid("symbolic rule " + rule.ID + " requires bytecode")
		}
		ruleByID[rule.ID] = rule
	}
	hash := ArtifactHash(artifact)
	checkByRule := make(map[string]CheckRecord, len(checks))
	for _, check := range checks {
		rule, ok := ruleByID[check.RuleID]
		if !ok {
			return Report{}, errInvalid("check targets unknown rule " + check.RuleID)
		}
		if _, dup := checkByRule[check.RuleID]; dup {
			return Report{}, errInvalid("duplicate check record for rule " + check.RuleID)
		}
		if !validCheckStatus(check.Status) {
			return Report{}, errInvalid("check for rule " + check.RuleID + " has unknown status " + check.Status)
		}
		if noteRequired(check.Status) && strings.TrimSpace(check.Note) == "" {
			return Report{}, errInvalid("check for rule " + check.RuleID + " with status " + check.Status + " requires a non-empty note")
		}
		if check.ArtifactHash != hash {
			return Report{}, errInvalid("check for rule " + check.RuleID + " artifact hash " + check.ArtifactHash + " does not match submission hash " + hash)
		}
		if check.RuleVersion != rule.Version {
			return Report{}, errInvalid("check for rule " + check.RuleID + " rule version " + check.RuleVersion + " does not match version " + rule.Version)
		}
		if _, hasBool := invariants[rule.Invariant]; hasBool {
			return Report{}, errInvalid("rule " + check.RuleID + " received both a check record and invariant " + rule.Invariant + " boolean")
		}
		checkByRule[check.RuleID] = check
	}
	report := Report{
		Artifact: ReportArtifact{Name: artifact.Name, Hash: hash},
		Rules:    []ReportRule{},
		Findings: []ReportFinding{},
	}
	for _, rule := range rules {
		status := StatusUnchecked
		note := ""
		if check, ok := checkByRule[rule.ID]; ok {
			status = check.Status
			note = check.Note
		} else if holds, checked := invariants[rule.Invariant]; checked {
			if holds {
				status = StatusPass
			} else {
				status = StatusDefect
			}
		}
		report.Rules = append(report.Rules, ReportRule{
			ID:          rule.ID,
			Kind:        rule.Kind,
			Severity:    rule.Severity,
			Invariant:   rule.Invariant,
			RequiresABI: rule.RequiresABI,
			Version:     rule.Version,
			Status:      status,
			Note:        note,
		})
		if status == StatusDefect {
			evidence := note
			if evidence == "" {
				evidence = "invariant " + rule.Invariant + " does not hold"
			}
			report.Findings = append(report.Findings, ReportFinding{
				ArtifactHash: hash,
				RuleID:       rule.ID,
				Version:      rule.Version,
				Severity:     rule.Severity,
				Invariant:    rule.Invariant,
				Evidence:     evidence,
			})
		}
	}
	report.ReportID = ReportID(report)
	return report, nil
}

// canonicalRule is the order-independent view of a rule used for the id.
type canonicalRule struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Invariant   string `json:"invariant"`
	RequiresABI bool   `json:"requiresABI"`
	Version     string `json:"version"`
	Status      string `json:"status"`
	Note        string `json:"note,omitempty"`
}

// canonicalFinding is the order-independent view of a finding used for the id.
type canonicalFinding struct {
	ArtifactHash string `json:"artifactHash"`
	RuleID       string `json:"ruleId"`
	Version      string `json:"version"`
	Severity     string `json:"severity"`
	Invariant    string `json:"invariant"`
	Evidence     string `json:"evidence"`
}

// canonicalReport is the deterministic content a report id is computed from.
type canonicalReport struct {
	ArtifactHash string             `json:"artifactHash"`
	Name         string             `json:"name"`
	Rules        []canonicalRule    `json:"rules"`
	Findings     []canonicalFinding `json:"findings"`
}

// canonicalize renders a report into its order-independent form.
func canonicalize(report Report) canonicalReport {
	cr := canonicalReport{
		ArtifactHash: report.Artifact.Hash,
		Name:         report.Artifact.Name,
	}
	for _, rule := range report.Rules {
		cr.Rules = append(cr.Rules, canonicalRule{
			ID: rule.ID, Kind: rule.Kind, Severity: rule.Severity,
			Invariant: rule.Invariant, RequiresABI: rule.RequiresABI,
			Version: rule.Version, Status: rule.Status, Note: rule.Note,
		})
	}
	sort.Slice(cr.Rules, func(i, j int) bool { return cr.Rules[i].ID < cr.Rules[j].ID })
	for _, finding := range report.Findings {
		cr.Findings = append(cr.Findings, canonicalFinding{
			ArtifactHash: finding.ArtifactHash, RuleID: finding.RuleID,
			Version: finding.Version, Severity: finding.Severity,
			Invariant: finding.Invariant, Evidence: finding.Evidence,
		})
	}
	sort.Slice(cr.Findings, func(i, j int) bool { return cr.Findings[i].RuleID < cr.Findings[j].RuleID })
	return cr
}

// ReportID returns the content-addressed identifier of a report. The id binds
// the artifact hash, name, complete rule definitions, the invariant value
// used by each rule (unchecked and explicit pass are distinct), and the
// findings. Rule order, invariant key order and unrelated invariant keys do
// not influence it.
func ReportID(r Report) string {
	data, err := json.Marshal(canonicalize(r))
	if err != nil {
		panic(err) // canonical values are all strings and bools
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// expectedFindings rebuilds the findings that match a report's rules. A
// defect rule with a note uses the submitted note as evidence; a boolean
// defect without a note uses the default invariant explanation. This ties
// finding evidence to the per-rule status and note, so changing either in an
// archive fails verification.
func expectedFindings(r Report) []ReportFinding {
	var out []ReportFinding
	for _, rule := range r.Rules {
		if rule.Status == StatusDefect {
			evidence := rule.Note
			if evidence == "" {
				evidence = "invariant " + rule.Invariant + " does not hold"
			}
			out = append(out, ReportFinding{
				ArtifactHash: r.Artifact.Hash,
				RuleID:       rule.ID,
				Version:      rule.Version,
				Severity:     rule.Severity,
				Invariant:    rule.Invariant,
				Evidence:     evidence,
			})
		}
	}
	return out
}

// sameFindings compares two finding sets independently of order; nil and empty
// slices are treated as equal.
func sameFindings(a, b []ReportFinding) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	ac := append([]ReportFinding(nil), a...)
	bc := append([]ReportFinding(nil), b...)
	sort.Slice(ac, func(i, j int) bool { return ac[i].RuleID < ac[j].RuleID })
	sort.Slice(bc, func(i, j int) bool { return bc[i].RuleID < bc[j].RuleID })
	return reflect.DeepEqual(ac, bc)
}

// verifyReportBytes parses stored bytes and checks they match the id and that
// the findings are consistent with the rules.
func verifyReportBytes(data []byte, id string) error {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return errCorrupt("invalid JSON in report " + id + ": " + err.Error())
	}
	if r.ReportID != id {
		return errCorrupt("report id " + r.ReportID + " does not match stored id " + id)
	}
	if ReportID(r) != id {
		return errCorrupt("report content does not match id " + id)
	}
	if !sameFindings(expectedFindings(r), r.Findings) {
		return errCorrupt("report findings do not match rules for id " + id)
	}
	return nil
}

// SaveReport persists a report under the store directory. The store is safe
// for concurrent writers: identical reports share one file and all
// submissions succeed, different reports never overwrite each other, and
// readers only ever observe complete files. A pre-existing file with the same
// id must carry the same report; a corrupted archive makes the submission
// fail while keeping the original file.
func SaveReport(dir string, r Report) error {
	if r.ReportID == "" {
		return errInvalid("report id is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	finalPath := filepath.Join(dir, r.ReportID+".json")
	if existing, err := os.ReadFile(finalPath); err == nil {
		if err := verifyReportBytes(existing, r.ReportID); err != nil {
			return err
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".report-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() { os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		cleanup()
		if existing, readErr := os.ReadFile(finalPath); readErr == nil {
			if verifyErr := verifyReportBytes(existing, r.ReportID); verifyErr != nil {
				return verifyErr
			}
			return nil
		}
		return err
	}
	return nil
}

// LoadReport reads and verifies a report by id. Missing, corrupted or tampered
// archives produce a clear error.
func LoadReport(dir, id string) (Report, error) {
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return Report{}, errNotFound("report " + id + " not found")
		}
		return Report{}, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return Report{}, errCorrupt("invalid JSON in report " + id)
	}
	if r.ReportID != id {
		return Report{}, errCorrupt("report id " + r.ReportID + " does not match requested id " + id)
	}
	if ReportID(r) != id {
		return Report{}, errCorrupt("report content does not match id " + id)
	}
	if !sameFindings(expectedFindings(r), r.Findings) {
		return Report{}, errCorrupt("report findings do not match rules for id " + id)
	}
	return r, nil
}

type errNotFound string

func (e errNotFound) Error() string { return string(e) }

type errCorrupt string

func (e errCorrupt) Error() string { return string(e) }
