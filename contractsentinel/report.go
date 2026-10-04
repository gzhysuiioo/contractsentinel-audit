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

// submissionShape is the fixed-field shape of an audit submission: the agreed
// spellings at the top level and inside the artifact, every rule and every
// check record. The invariants object is a fixed top-level member but has no
// nested shape, so it passes through untouched: invariant names are
// user-defined rather than fixed fields, and "Inv" and "inv" stay two
// independent invariants and a padded name is not trimmed.
var submissionShape = fixedShape{
	keys: []string{"artifact", "rules", "invariants", "checks"},
	objects: map[string]fixedShape{
		"artifact": {keys: []string{"name", "abi", "bytecode", "source"}},
	},
	arrays: map[string]fixedShape{
		"rules":  {keys: []string{"id", "kind", "severity", "invariant", "requiresABI", "version"}},
		"checks": {keys: []string{"artifactHash", "ruleId", "version", "status", "note"}},
	},
}

// strictSubmissionJSON rewrites submission bytes to the fixed submission
// fields under their agreed spelling; see fixedShape for the recognition
// convention shared with the archive read side.
func strictSubmissionJSON(data []byte) ([]byte, error) {
	return strictFixedJSON(data, submissionShape)
}

// validateFormalCheckStatuses checks the formal "status" member of every
// strict check record. The strict rewrite dropped extension members, so the
// status seen here is the agreed-spelling one alone: a missing formal status,
// a non-string one, or an unsupported value rejects the whole submission
// even when an adjacent "StAtus" extension member carried a legal-looking
// value. The error names the rule the record is for so the offending entry is
// identifiable.
func validateFormalCheckStatuses(strict []byte) error {
	var top struct {
		Checks []map[string]json.RawMessage `json:"checks"`
	}
	if err := json.Unmarshal(strict, &top); err != nil {
		return errInvalid("invalid JSON: " + err.Error())
	}
	for _, rec := range top.Checks {
		where := "check record"
		if raw, ok := rec["ruleId"]; ok {
			var ruleID string
			if err := json.Unmarshal(raw, &ruleID); err == nil && ruleID != "" {
				where = "check for rule " + ruleID
			}
		}
		raw, ok := rec["status"]
		if !ok {
			return errInvalid(where + ": status is required")
		}
		var status string
		if err := json.Unmarshal(raw, &status); err != nil {
			return errInvalid(where + ": status must be a string")
		}
		if !validCheckStatus(status) {
			return errInvalid(where + ": unknown status " + status)
		}
	}
	return nil
}

// ParseAuditInput decodes an audit submission JSON object into domain values.
// Invariant values must be JSON booleans; any other type is an error. Any JSON
// object in the submission that repeats a member name rejects the whole
// submission: the decoder keeps only the last value silently, so a repeated
// invariant key would choose a conclusion by member order instead of giving
// one trustworthy result. A character the decoder would silently rewrite — an
// invalid UTF-8 byte, or an unpaired or wrongly ordered surrogate escape in
// any member name or string value, including values nested under unknown
// extension members — rejects the whole submission as an input error before
// any content is hashed, so evidence and hashes always reflect the submitted
// bytes rather than a U+FFFD-rewritten copy. Only the fixed fields under their
// agreed spelling participate: case variants and whitespace-padded names are
// extension data and are ignored, so they can neither override a formal value
// nor supply one when the formal member is missing or unsupported. Invariant
// names are not fixed fields — they are user-defined, compared case
// sensitively and never trimmed.
func ParseAuditInput(data []byte) (Artifact, []Rule, map[string]bool, []CheckRecord, error) {
	if charErr := validateJSONCharacters(data); charErr != nil {
		return Artifact{}, nil, nil, nil, errInvalid(charErr.Error())
	}
	if dup := findDuplicateJSONMember(data); dup != nil {
		return Artifact{}, nil, nil, nil, errInvalid(duplicateMemberMessage(data, dup))
	}
	strict, err := strictSubmissionJSON(data)
	if err != nil {
		return Artifact{}, nil, nil, nil, errInvalid("invalid JSON: " + err.Error())
	}
	if err := validateFormalCheckStatuses(strict); err != nil {
		return Artifact{}, nil, nil, nil, err
	}
	var in wireInput
	if err := json.Unmarshal(strict, &in); err != nil {
		return Artifact{}, nil, nil, nil, errInvalid("invalid JSON: " + err.Error())
	}
	invariants := make(map[string]bool, len(in.Invariants))
	for key, raw := range in.Invariants {
		// Only JSON true/false is a conclusion. Unmarshalling directly into a
		// bool would turn null into the zero value false, which would falsely
		// record a defect; require the token to be a boolean instead.
		var token any
		if err := json.Unmarshal(raw, &token); err != nil {
			return Artifact{}, nil, nil, nil, errInvalid("invariant " + key + " must be a boolean")
		}
		holds, ok := token.(bool)
		if !ok {
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

// validCheckStatus reports whether status is one of the four recorded check
// conclusions.
func validCheckStatus(status string) bool {
	switch status {
	case StatusPass, StatusDefect, StatusToolMissing, StatusTimeout:
		return true
	}
	return false
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
		if !validCheckStatus(check.Status) {
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

// validateReport checks every archive legality condition against r. It is the
// single definition of a legal report: the id and artifact hash are 64
// lowercase hex characters, the id matches the content, the artifact name is
// present, rule ids are present and unique with non-empty versions, statuses
// use the five recorded values, tool-missing and timeout notes are
// non-blank, and 发现缺陷 rules correspond one-to-one with findings whose
// artifact hash, version, severity, invariant and evidence match the rule.
// The same conditions apply to submissions and to stored archives: a
// recomputed id never makes an invalid report legal. fail is errInvalid for
// submissions and errCorrupt for stored archives.
func validateReport(r Report, fail func(string) error) error {
	if !validReportID(r.ReportID) {
		return fail("report id " + r.ReportID + " is not a 64-character lowercase hex string")
	}
	if r.Artifact.Name == "" {
		return fail("report " + r.ReportID + " artifact name is required")
	}
	if !validReportID(r.Artifact.Hash) {
		return fail("report " + r.ReportID + " artifact hash is not a 64-character lowercase hex string")
	}
	if ReportID(r) != r.ReportID {
		return fail("report content does not match id " + r.ReportID)
	}
	seenRule := make(map[string]bool, len(r.Rules))
	defectByID := make(map[string]ReportRule)
	for _, rule := range r.Rules {
		if rule.ID == "" {
			return fail("report " + r.ReportID + " has a rule with an empty id")
		}
		if seenRule[rule.ID] {
			return fail("report " + r.ReportID + " has duplicate rule id " + rule.ID)
		}
		seenRule[rule.ID] = true
		if rule.Version == "" {
			return fail("report " + r.ReportID + " rule " + rule.ID + " has an empty version")
		}
		switch rule.Status {
		case StatusUnchecked, StatusPass, StatusDefect, StatusToolMissing, StatusTimeout:
		default:
			return fail("report " + r.ReportID + " rule " + rule.ID + " has unknown status " + rule.Status)
		}
		if (rule.Status == StatusToolMissing || rule.Status == StatusTimeout) && strings.TrimSpace(rule.Note) == "" {
			return fail("report " + r.ReportID + " rule " + rule.ID + " status " + rule.Status + " has no note")
		}
		if rule.Status == StatusDefect {
			defectByID[rule.ID] = rule
		}
	}
	seenFinding := make(map[string]bool, len(r.Findings))
	for _, f := range r.Findings {
		if f.RuleID == "" {
			return fail("report " + r.ReportID + " has a finding with an empty rule id")
		}
		rule, ok := defectByID[f.RuleID]
		if !ok {
			return fail("report " + r.ReportID + " finding for rule " + f.RuleID + " does not match a 发现缺陷 rule")
		}
		if seenFinding[f.RuleID] {
			return fail("report " + r.ReportID + " has a duplicate finding for rule " + f.RuleID)
		}
		seenFinding[f.RuleID] = true
		if f.ArtifactHash != r.Artifact.Hash {
			return fail("report " + r.ReportID + " finding for rule " + f.RuleID + " has artifact hash " + f.ArtifactHash + ", want " + r.Artifact.Hash)
		}
		if f.Version != rule.Version {
			return fail("report " + r.ReportID + " finding for rule " + f.RuleID + " has version " + f.Version + ", want " + rule.Version)
		}
		if f.Severity != rule.Severity {
			return fail("report " + r.ReportID + " finding for rule " + f.RuleID + " has severity " + f.Severity + ", want " + rule.Severity)
		}
		if f.Invariant != rule.Invariant {
			return fail("report " + r.ReportID + " finding for rule " + f.RuleID + " has invariant " + f.Invariant + ", want " + rule.Invariant)
		}
		wantEvidence := rule.Note
		if wantEvidence == "" {
			wantEvidence = "invariant " + rule.Invariant + " does not hold"
		}
		if f.Evidence != wantEvidence {
			return fail("report " + r.ReportID + " finding for rule " + f.RuleID + " has evidence " + f.Evidence + ", want " + wantEvidence)
		}
	}
	for id := range defectByID {
		if !seenFinding[id] {
			return fail("report " + r.ReportID + " defect rule " + id + " has no finding")
		}
	}
	return nil
}

// validStoredReport validates archive contents.
func validStoredReport(r Report) error {
	return validateReport(r, func(msg string) error { return errCorrupt(msg) })
}

// validSubmittedReport validates a submission before any store operation.
func validSubmittedReport(r Report) error {
	return validateReport(r, func(msg string) error { return errInvalid(msg) })
}

// duplicateArchiveError classifies an archive that repeats a JSON member as
// corrupt and names the requested report id, the decoded member name and the
// object carrying it (with array position and rule id when applicable).
func duplicateArchiveError(id string, data []byte, dup *duplicateMemberError) error {
	return errCorrupt("report " + id + " archive is corrupt: " + duplicateMemberMessage(data, dup))
}

// characterArchiveError classifies an archive whose raw bytes contain a
// character the decoder would silently rewrite — an invalid UTF-8 byte, or an
// unpaired or wrongly ordered surrogate escape in any member name or string
// value — as corrupt. The message names the requested report id and keeps the
// scanner's classification (character encoding vs Unicode escape), byte
// offset, line/column and JSON path, so the original file can be repaired by
// hand; the archive itself is never rewritten.
func characterArchiveError(id string, charErr *charEncodingError) error {
	return errCorrupt("report " + id + " archive is corrupt: " + charErr.Error())
}

// reportShape is the fixed-field shape of a stored report archive: the agreed
// spellings at the top level and inside the artifact, every rule and every
// finding. The trusted content of a report is carried by these fixed fields
// alone; case variants, whitespace-padded names and unknown members are
// extension data and never reach the decoder.
var reportShape = fixedShape{
	keys: []string{"reportId", "artifact", "rules", "findings"},
	objects: map[string]fixedShape{
		"artifact": {keys: []string{"name", "hash"}},
	},
	arrays: map[string]fixedShape{
		"rules":    {keys: []string{"id", "kind", "severity", "invariant", "requiresABI", "version", "status", "note"}},
		"findings": {keys: []string{"artifactHash", "ruleId", "version", "severity", "invariant", "evidence"}},
	},
}

// strictReportJSON rewrites archive bytes to the fixed report fields under
// their original spelling; see fixedShape for the recognition convention
// shared with the submission side.
func strictReportJSON(data []byte) ([]byte, error) {
	return strictFixedJSON(data, reportShape)
}

// loadStoredReport parses archive bytes for id and fully validates them.
func loadStoredReport(data []byte, id string) (Report, error) {
	// Read-side counterpart of the submission character check: json.Unmarshal
	// silently rewrites an invalid UTF-8 byte or an unpaired / wrongly ordered
	// surrogate escape to U+FFFD, so an archive whose note and evidence were
	// damaged into lone escapes would decode back to the original text and
	// pass both the recomputed id and the rule/finding correspondence on the
	// rewritten content. A successful read must mean the archive bytes
	// themselves are legal, so any such character — in a fixed field, a
	// member name, or an unknown extension member's nested content — makes
	// the whole archive corrupt before anything is decoded.
	if charErr := validateJSONCharacters(data); charErr != nil {
		return Report{}, characterArchiveError(id, charErr)
	}
	// Read-side counterpart of the submission check: json.Unmarshal silently
	// keeps the last value for a repeated member, so an archive that writes a
	// rule status as 发现缺陷 and then 通过 would decode to whichever came
	// last. The recomputed id and the rule/finding correspondence all operate
	// on that last-wins value and could therefore pass, accepting an archive
	// with two conflicting conclusions. Any repeated member in any object
	// makes the archive corrupt, regardless of the last value.
	if dup := findDuplicateJSONMember(data); dup != nil {
		return Report{}, duplicateArchiveError(id, data, dup)
	}
	strict, err := strictReportJSON(data)
	if err != nil {
		return Report{}, errCorrupt("invalid JSON in report " + id + ": " + err.Error())
	}
	var r Report
	if err := json.Unmarshal(strict, &r); err != nil {
		return Report{}, errCorrupt("invalid JSON in report " + id + ": " + err.Error())
	}
	if r.ReportID != id {
		return Report{}, errCorrupt("report id " + r.ReportID + " does not match requested id " + id)
	}
	if err := validStoredReport(r); err != nil {
		return Report{}, err
	}
	return r, nil
}

// saveReportHook, when set, is invoked after the archive existence check and
// before the atomic publish. It lets tests simulate another process racing to
// claim the same report id.
var saveReportHook func(finalPath string)

// SaveReport persists a report under the store directory. The store is safe
// for concurrent writers: identical reports share one file and all
// submissions succeed, different reports never overwrite each other, and
// readers only ever observe complete files. A submission is fully validated
// before any store operation, so an invalid report creates no store and no
// files. A pre-existing file with the same id must be a valid archive of the
// same report; a corrupted archive makes the submission fail while keeping the
// original file, even when the corruption appears only during the save. The
// first successfully archived bytes are never replaced by later submissions.
func SaveReport(dir string, r Report) error {
	if err := validSubmittedReport(r); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	finalPath := filepath.Join(dir, r.ReportID+".json")
	if existing, err := os.ReadFile(finalPath); err == nil {
		if _, err := loadStoredReport(existing, r.ReportID); err != nil {
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
	if saveReportHook != nil {
		saveReportHook(finalPath)
	}
	if err := os.Link(tmpPath, finalPath); err != nil {
		cleanup()
		if os.IsExist(err) {
			existing, readErr := os.ReadFile(finalPath)
			if readErr != nil {
				return readErr
			}
			if _, err := loadStoredReport(existing, r.ReportID); err != nil {
				return err
			}
			return nil
		}
		return err
	}
	cleanup()
	return nil
}

// LoadReport reads and verifies a report by id. The id must be 64 lowercase
// hex characters; missing, corrupted or tampered archives produce a clear
// error. The store is only read, never created or modified.
func LoadReport(dir, id string) (Report, error) {
	if !validReportID(id) {
		return Report{}, errInvalid("invalid report id " + id + ": want 64 lowercase hex characters")
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return Report{}, errNotFound("report " + id + " not found")
		}
		return Report{}, err
	}
	return loadStoredReport(data, id)
}

type errNotFound string

func (e errNotFound) Error() string { return string(e) }

type errCorrupt string

func (e errCorrupt) Error() string { return string(e) }
