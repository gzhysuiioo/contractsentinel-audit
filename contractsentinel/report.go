// Package contractsentinel report: content-addressed, persistable audit reports.
package contractsentinel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// ReportArtifact identifies the audited artifact by name and content hash.
type ReportArtifact struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// ReportRule is one rule together with the invariant check result. The note
// carries the original checker description: counterexample evidence for a
// defect, a tool availability remark for 工具缺失, a deadline remark for 超时,
// or an optional remark for a passing check. It is empty for reports built
// only from invariant booleans.
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

// CheckRecord is one imported per-rule check result: the artifact hash and
// rule version it was produced against, the conclusion status, and the
// original checker note (counterexample, tool or deadline remark).
type CheckRecord struct {
	ArtifactHash string
	RuleID       string
	Version      string
	Status       string
	Note         string
}

// wireCheck is the JSON shape of one entry in the checks array.
type wireCheck struct {
	ArtifactHash string `json:"artifactHash"`
	RuleID       string `json:"ruleId"`
	Version      string `json:"version"`
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
// Invariant values must be JSON booleans; any other type is an error.
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
			Version:      wc.Version,
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

// BuildReport evaluates rules against the artifact and invariant values and
// imported check records and produces the report to persist. Insufficient
// inputs (missing ABI for a rule that requires it, missing bytecode for a
// symbolic rule) fail the whole submission and are never recorded as defects.
// Imported checks are validated as a whole: unknown rules, duplicate records,
// unknown statuses, missing notes, hash or version mismatches, and a rule
// receiving both a check record and an invariant boolean all reject the
// submission without producing a report.
func BuildReport(artifact Artifact, rules []Rule, invariants map[string]bool, checks []CheckRecord) (Report, error) {
	if artifact.Name == "" {
		return Report{}, errInvalid("artifact name is required")
	}
	hash := ArtifactHash(artifact)
	seen := make(map[string]bool, len(rules))
	ruleByID := make(map[string]Rule, len(rules))
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
		ruleByID[rule.ID] = rule
		if rule.RequiresABI && artifact.ABI == "" {
			return Report{}, errInvalid("rule " + rule.ID + " requires an ABI")
		}
		if rule.Kind == "symbolic" && artifact.Bytecode == "" {
			return Report{}, errInvalid("symbolic rule " + rule.ID + " requires bytecode")
		}
	}
	checkByRule := make(map[string]CheckRecord, len(checks))
	for _, check := range checks {
		if check.RuleID == "" {
			return Report{}, errInvalid("check rule id is required")
		}
		rule, ok := ruleByID[check.RuleID]
		if !ok {
			return Report{}, errInvalid("check for rule " + check.RuleID + ": unknown rule")
		}
		if _, dup := checkByRule[check.RuleID]; dup {
			return Report{}, errInvalid("duplicate check for rule " + check.RuleID)
		}
		if check.ArtifactHash != hash {
			return Report{}, errInvalid("check for rule " + check.RuleID + ": artifact hash mismatch")
		}
		if check.Version != rule.Version {
			return Report{}, errInvalid("check for rule " + check.RuleID + ": version mismatch")
		}
		if !validCheckStatus(check.Status) || check.Status == StatusUnchecked {
			return Report{}, errInvalid("check for rule " + check.RuleID + ": unknown status " + check.Status)
		}
		if check.Status != StatusPass && strings.TrimSpace(check.Note) == "" {
			return Report{}, errInvalid("check for rule " + check.RuleID + ": note is required for status " + check.Status)
		}
		if _, hasInvariant := invariants[rule.Invariant]; hasInvariant {
			return Report{}, errInvalid("rule " + check.RuleID + ": both a check record and an invariant value are provided")
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

// canonicalRule is the order-independent view of a rule used for the id. The
// note is omitted when empty so reports built only from invariant booleans
// keep their original ids.
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

// validHash64 reports whether s is exactly 64 lowercase hex characters: the
// shape of a report id and an artifact content hash.
func validHash64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validCheckStatus reports whether status is one of the five recorded check
// conclusions.
func validCheckStatus(status string) bool {
	switch status {
	case StatusUnchecked, StatusPass, StatusDefect, StatusToolMissing, StatusTimeout:
		return true
	}
	return false
}

// validateReportStructure enforces the single set of admission conditions every
// report must satisfy when it is saved, loaded or compared:
//
//   - the report id and the artifact hash are 64 lowercase hex characters;
//   - the artifact name, every rule id and rule version are non-empty and rule
//     ids are unique;
//   - every rule status is one of the five known statuses, and 工具缺失/超时
//     carry a non-blank note;
//   - defect rules and findings correspond one-to-one, and every finding's
//     artifact hash, rule version, severity and invariant match the report and
//     the rule it belongs to;
//   - a defect with a note uses the note verbatim as evidence; a note-less
//     old-style boolean-invariant defect uses the standard invariant message.
//
// asInvalid chooses the error class: a caller's current submission failing the
// conditions is an input-validity error; a report read from the archive failing
// them is an archive-corruption error. Rule problems always name the rule id.
func validateReportStructure(r Report, asInvalid bool) error {
	errf := func(msg string) error {
		if asInvalid {
			return errInvalid(msg)
		}
		return errCorrupt(msg)
	}
	if !validHash64(r.ReportID) {
		return errf("invalid report id " + r.ReportID + ": want 64 lowercase hex characters")
	}
	if r.Artifact.Name == "" {
		return errf("report " + r.ReportID + " has an empty artifact name")
	}
	if !validHash64(r.Artifact.Hash) {
		return errf("report " + r.ReportID + " artifact hash is not 64 lowercase hex characters")
	}
	if asInvalid && ReportID(r) != r.ReportID {
		return errf("report content does not match id " + r.ReportID)
	}
	rules := make(map[string]ReportRule, len(r.Rules))
	for _, rule := range r.Rules {
		if rule.ID == "" {
			return errf("report " + r.ReportID + " has a rule with an empty id")
		}
		if _, dup := rules[rule.ID]; dup {
			return errf("report " + r.ReportID + " has duplicate rule id " + rule.ID)
		}
		if rule.Version == "" {
			return errf("report " + r.ReportID + " rule " + rule.ID + " has an empty version")
		}
		if !validCheckStatus(rule.Status) {
			return errf("report " + r.ReportID + " rule " + rule.ID + " has unknown status " + rule.Status)
		}
		if (rule.Status == StatusToolMissing || rule.Status == StatusTimeout) && strings.TrimSpace(rule.Note) == "" {
			return errf("report " + r.ReportID + " rule " + rule.ID + " status " + rule.Status + " has no note")
		}
		rules[rule.ID] = rule
	}
	findings := make(map[string]ReportFinding, len(r.Findings))
	for _, f := range r.Findings {
		if f.RuleID == "" {
			return errf("report " + r.ReportID + " has a finding with an empty rule id")
		}
		if _, dup := findings[f.RuleID]; dup {
			return errf("report " + r.ReportID + " has a duplicate finding for rule " + f.RuleID)
		}
		findings[f.RuleID] = f
		rule, ok := rules[f.RuleID]
		if !ok {
			return errf("report " + r.ReportID + " finding for rule " + f.RuleID + " has no defect rule")
		}
		if rule.Status != StatusDefect {
			return errf("report " + r.ReportID + " finding for rule " + f.RuleID + " has rule status " + rule.Status)
		}
		if f.ArtifactHash != r.Artifact.Hash {
			return errf("report " + r.ReportID + " rule " + f.RuleID + " finding artifact hash does not match report")
		}
		if f.Version != rule.Version {
			return errf("report " + r.ReportID + " rule " + f.RuleID + " finding version does not match rule version")
		}
		if f.Severity != rule.Severity {
			return errf("report " + r.ReportID + " rule " + f.RuleID + " finding severity does not match rule severity")
		}
		if f.Invariant != rule.Invariant {
			return errf("report " + r.ReportID + " rule " + f.RuleID + " finding invariant does not match rule invariant")
		}
		evidence := rule.Note
		if evidence == "" {
			evidence = "invariant " + rule.Invariant + " does not hold"
		}
		if f.Evidence != evidence {
			return errf("report " + r.ReportID + " rule " + f.RuleID + " finding evidence does not match the check note")
		}
	}
	for id, rule := range rules {
		if rule.Status == StatusDefect {
			if _, ok := findings[id]; !ok {
				return errf("report " + r.ReportID + " defect rule " + id + " has no finding")
			}
		}
	}
	return nil
}

// parseArchivedReport parses stored bytes and applies every archive admission
// condition. Every failure is reported as archive corruption.
func parseArchivedReport(data []byte, id string) (Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return Report{}, errCorrupt("invalid JSON in report " + id + ": " + err.Error())
	}
	if r.ReportID != id {
		return Report{}, errCorrupt("report id " + r.ReportID + " does not match stored id " + id)
	}
	if err := validateReportStructure(r, false); err != nil {
		return Report{}, err
	}
	if ReportID(r) != id {
		return Report{}, errCorrupt("report content does not match id " + id)
	}
	return r, nil
}

// verifyReportBytes parses stored bytes and checks they satisfy every archive
// admission condition.
func verifyReportBytes(data []byte, id string) error {
	_, err := parseArchivedReport(data, id)
	return err
}

// SaveReport persists a report under the store directory.
//
// The submission is validated in full before anything is written: its id and
// artifact hash must be 64 lowercase hex characters, the id must equal the id
// computed from the submitted content, and the rules and findings must satisfy
// every admission condition. An invalid submission is an input error and
// neither creates the store nor adds a file.
//
// Once an id has been archived its bytes can never be replaced: the archive is
// published with an atomic hard link that fails when the slot is already
// occupied, so the first successful archiver wins and later submissions keep
// the original bytes. A resubmission of the same logical report (for instance
// one differing only in rule or finding order) is a duplicate and succeeds
// once the stored file is verified; concurrent duplicate writers all succeed
// and leave exactly one complete file. A corrupt file already occupying the
// slot, including one created by another process during this save, is reported
// as archive corruption and left untouched; this submission can neither repair
// nor overwrite it. Readers therefore only ever observe a missing slot or a
// complete, verifiable report.
func SaveReport(dir string, r Report) error {
	if err := validateReportStructure(r, true); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	finalPath := filepath.Join(dir, r.ReportID+".json")
	// Duplicate fast path: a verifiable file at the slot ends the submission
	// without creating any temporary file.
	switch existing, err := os.ReadFile(finalPath); {
	case err == nil:
		return verifyReportBytes(existing, r.ReportID)
	case !os.IsNotExist(err):
		return err
	}
	tmp, err := os.CreateTemp(dir, ".report-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Hard link is atomic and never overwrites: exactly one writer occupies
	// the slot, and it appears complete the moment it is visible.
	const attempts = 16
	for i := 0; i < attempts; i++ {
		err := os.Link(tmpPath, finalPath)
		if err == nil {
			return nil
		}
		existing, readErr := os.ReadFile(finalPath)
		switch {
		case readErr == nil:
			// Another writer won the slot (duplicate), or a corrupt file now
			// occupies it. Either way the slot must not be replaced.
			return verifyReportBytes(existing, r.ReportID)
		case !os.IsNotExist(readErr):
			return readErr
		case !os.IsExist(err):
			// Slot is free but linking failed for another reason; retrying
			// cannot help.
			return err
		}
		// EEXIST raced with an external removal: retry the atomic publish.
	}
	return err
}

// LoadReport reads and verifies a report by id. A malformed id is an input
// error, a valid id without a file is a not-found error, and a file that fails
// any admission condition (bad JSON, id mismatch, invalid rules or findings)
// is an archive-corruption error. The store is never modified.
func LoadReport(dir, id string) (Report, error) {
	if !validHash64(id) {
		return Report{}, errInvalid("invalid report id " + id + ": want 64 lowercase hex characters")
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return Report{}, errNotFound("report " + id + " not found")
		}
		return Report{}, err
	}
	return parseArchivedReport(data, id)
}

type errNotFound string

func (e errNotFound) Error() string { return string(e) }

type errCorrupt string

func (e errCorrupt) Error() string { return string(e) }
