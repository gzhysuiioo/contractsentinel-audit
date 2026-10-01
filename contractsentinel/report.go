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
)

// Check statuses recorded per rule in a report.
const (
	StatusUnchecked = "未检查"
	StatusPass      = "通过"
	StatusDefect    = "发现缺陷"
)

// ReportArtifact identifies the audited artifact by name and content hash.
type ReportArtifact struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// ReportRule is one rule together with the invariant check result.
type ReportRule struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Invariant   string `json:"invariant"`
	RequiresABI bool   `json:"requiresABI"`
	Version     string `json:"version"`
	Status      string `json:"status"`
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

// wireInput is the JSON object accepted by the audit command.
type wireInput struct {
	Artifact   wireArtifact               `json:"artifact"`
	Rules      []wireRule                 `json:"rules"`
	Invariants map[string]json.RawMessage `json:"invariants"`
}

// ParseAuditInput decodes an audit submission JSON object into domain values.
// Invariant values must be JSON booleans; any other type is an error.
func ParseAuditInput(data []byte) (Artifact, []Rule, map[string]bool, error) {
	var in wireInput
	if err := json.Unmarshal(data, &in); err != nil {
		return Artifact{}, nil, nil, errInvalid("invalid JSON: " + err.Error())
	}
	invariants := make(map[string]bool, len(in.Invariants))
	for key, raw := range in.Invariants {
		var holds bool
		if err := json.Unmarshal(raw, &holds); err != nil {
			return Artifact{}, nil, nil, errInvalid("invariant " + key + " must be a boolean")
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
	return artifact, rules, invariants, nil
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

// BuildReport evaluates rules against the artifact and invariant values and
// produces the report to persist. Insufficient inputs (missing ABI for a rule
// that requires it, missing bytecode for a symbolic rule) fail the whole
// submission and are never recorded as defects.
func BuildReport(artifact Artifact, rules []Rule, invariants map[string]bool) (Report, error) {
	if artifact.Name == "" {
		return Report{}, errInvalid("artifact name is required")
	}
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
	}
	hash := ArtifactHash(artifact)
	report := Report{
		Artifact: ReportArtifact{Name: artifact.Name, Hash: hash},
		Rules:    []ReportRule{},
		Findings: []ReportFinding{},
	}
	for _, rule := range rules {
		status := StatusUnchecked
		if holds, checked := invariants[rule.Invariant]; checked {
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
		})
		if status == StatusDefect {
			report.Findings = append(report.Findings, ReportFinding{
				ArtifactHash: hash,
				RuleID:       rule.ID,
				Version:      rule.Version,
				Severity:     rule.Severity,
				Invariant:    rule.Invariant,
				Evidence:     "invariant " + rule.Invariant + " does not hold",
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
			Version: rule.Version, Status: rule.Status,
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

// expectedFindings rebuilds the findings that match a report's rules.
func expectedFindings(r Report) []ReportFinding {
	var out []ReportFinding
	for _, rule := range r.Rules {
		if rule.Status == StatusDefect {
			out = append(out, ReportFinding{
				ArtifactHash: r.Artifact.Hash,
				RuleID:       rule.ID,
				Version:      rule.Version,
				Severity:     rule.Severity,
				Invariant:    rule.Invariant,
				Evidence:     "invariant " + rule.Invariant + " does not hold",
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
