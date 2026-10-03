// Package contractsentinel report: content-addressed, persistable audit reports.
package contractsentinel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
// Invariant values must be JSON booleans; any other type is an error. Any
// JSON object in the submission that lists the same member name twice rejects
// the whole input: a duplicated name has no single trustworthy value, so no
// conclusion may be drawn from it.
func ParseAuditInput(data []byte) (Artifact, []Rule, map[string]bool, []CheckRecord, error) {
	if err := rejectDuplicateMembers(data); err != nil {
		return Artifact{}, nil, nil, nil, err
	}
	var in wireInput
	if err := json.Unmarshal(data, &in); err != nil {
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

// rejectDuplicateMembers scans the raw submission and refuses the whole input
// if any single JSON object lists the same member name twice. The check
// covers every object in the document: the top-level object, the artifact,
// each rule, each check record, and objects nested inside unknown fields.
// Names are compared after JSON string decoding, so a name and its Unicode
// escape spelling collide; comparison is case-sensitive and nothing is
// trimmed. The same name in different objects is normal input, and string
// values that merely look like JSON are content, not structure. Malformed
// JSON is left for the real decode to report as invalid JSON.
func rejectDuplicateMembers(data []byte) error {
	type frame struct {
		path     string          // location of this container, "" for the top-level value
		keys     map[string]bool // member names seen so far (objects only)
		isObject bool
		wantKey  bool   // object: the next string token is a member name
		lastKey  string // object: member name whose value is being read
		count    int    // array: elements seen so far
	}
	var stack []*frame
	// closeValue records that one value inside the current container finished.
	closeValue := func() {
		if len(stack) == 0 {
			return
		}
		top := stack[len(stack)-1]
		if top.isObject {
			top.wantKey = true
		} else {
			top.count++
		}
	}
	// childPath locates a container about to be opened inside the current one.
	childPath := func() string {
		if len(stack) == 0 {
			return ""
		}
		top := stack[len(stack)-1]
		if top.isObject {
			if top.path == "" {
				return top.lastKey
			}
			return top.path + "." + top.lastKey
		}
		return top.path + "[" + strconv.Itoa(top.count) + "]"
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			// End of input, or a syntax error the real decode will report.
			return nil
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				path := childPath()
				closeValue()
				stack = append(stack, &frame{path: path, keys: make(map[string]bool), isObject: true, wantKey: true})
			case '[':
				path := childPath()
				closeValue()
				stack = append(stack, &frame{path: path})
			case '}', ']':
				stack = stack[:len(stack)-1]
				closeValue()
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].isObject && stack[len(stack)-1].wantKey {
				top := stack[len(stack)-1]
				if top.keys[t] {
					where := "object " + top.path
					if top.path == "" {
						where = "the top-level object"
					}
					return errInvalid("duplicate member " + strconv.Quote(t) + " in " + where)
				}
				top.keys[t] = true
				top.wantKey = false
				top.lastKey = t
			} else {
				closeValue()
			}
		default:
			closeValue()
		}
	}
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

// loadStoredReport parses archive bytes for id and fully validates them.
func loadStoredReport(data []byte, id string) (Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
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
