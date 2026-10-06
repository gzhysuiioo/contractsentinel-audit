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
	"unicode/utf8"
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

// validateFormalCheckNotes checks the formal "note" member of every strict
// check record. The strict rewrite dropped extension members, so the note
// seen here is the agreed-spelling one alone: decoding it straight into the
// Go wireCheck string field turns a formal null into the zero value "",
// indistinguishable from an omitted note — a passing record written with
// "note":null would then produce the very same report (and report id) as one
// that omitted the note, laundering a malformed submission into a legal one.
// Whenever the formal note is present its value must therefore be a JSON
// string — null, a boolean, a number, an object or an array rejects the whole
// submission, for all four importable statuses and independently of the other
// records; other legal records can neither make the submission succeed nor be
// partially reported. The gate is about the JSON type alone, not non-empty
// text: an omitted note keeps the existing per-status business judgement (a
// pass needs no note; the other three statuses still require non-blank text
// in BuildReport), and an explicit "" or whitespace-only string keeps that
// same judgement. A case-variant or whitespace-padded name ("Note", " note ")
// is extension data: its value, a non-string one included, never reaches this
// gate and can neither fill a missing formal note nor rescue an illegal one,
// whatever the member order; a name written with Unicode escapes denotes the
// same formal field after decoding. The error names the record's zero-based
// position in the checks array and, when the record carries a legal non-empty
// ruleId, that rule id too — a missing or mistyped ruleId leaves the record
// locatable by position alone.
func validateFormalCheckNotes(strict []byte) error {
	return checkObjectArrayFieldTypes(strict,
		"checks",
		[]ruleFieldTypeCheck{{field: "note", typ: ruleFieldString}},
		ruleFieldTypeHooks{
			locate: func(i int, rec map[string]json.RawMessage) string {
				where := fmt.Sprintf("checks[%d]", i)
				if id := formalCheckRuleID(rec); id != "" {
					where += " (rule " + id + ")"
				}
				return where
			},
			invalidJSON: func(err error) error { return errInvalid("invalid JSON: " + err.Error()) },
			reject: func(where, field string, typ ruleFieldType) error {
				return errInvalid(where + ": " + field + " " + typ.requirement())
			},
		})
}

// validateFormalRequiresABI checks the formal "requiresABI" member of every
// strict rule definition in an audit submission; the written-means-boolean
// rule and the per-rule walk are shared with the archive side in
// checkRuleFieldTypes. The strict rewrite dropped extension members, so the
// value seen here is the agreed-spelling one alone. Decoding the member
// straight into a Go bool would turn null into the zero value false: a rule
// whose requirement was never actually stated would be recorded as not
// needing an ABI, indistinguishable from an explicit false, and could even
// produce a defect finding from a false invariant. When the formal member is
// present its value must be the JSON boolean true or false — null, a string,
// a number, an object or an array rejects the whole submission, whether or
// not the artifact carries an ABI and whether or not the rule received any
// check conclusion. An omitted member still means false. A case-variant or
// whitespace-padded name is extension data and its value, null included,
// never reaches this check; it can neither trigger the error nor rescue an
// illegal formal value. The error names the rule so the offending entry is
// identifiable and is an input error.
func validateFormalRequiresABI(strict []byte) error {
	return checkRuleFieldTypes(strict,
		[]ruleFieldTypeCheck{{field: "requiresABI", typ: ruleFieldBoolean}},
		ruleFieldTypeHooks{
			locate: func(_ int, rule map[string]json.RawMessage) string {
				if id := formalRuleID(rule); id != "" {
					return "rule " + id
				}
				return "rule"
			},
			invalidJSON: func(err error) error { return errInvalid("invalid JSON: " + err.Error()) },
			reject: func(where, field string, typ ruleFieldType) error {
				return errInvalid(where + ": " + field + " " + typ.requirement())
			},
		})
}

// submissionRuleTextFields lists the five formal rule definition members whose
// value, once the member is written out in an audit submission, must be a JSON
// string. requiresABI keeps its own boolean gate; status and note exist only in
// stored reports, where validateArchiveRuleText already gates them.
var submissionRuleTextFields = []string{"id", "kind", "severity", "invariant", "version"}

// validateFormalRuleText checks the raw JSON token of every written formal
// rule text member before the strict submission is decoded into the Go
// wireRule string fields. Decoding straight into a Go string turns a formal
// null member into the zero value "", indistinguishable from an omitted
// member or an explicitly written empty string: a rule with a legal id and
// version and "kind":null, "severity":null or "invariant":null would then
// parse, pass every business check and produce a report whose rule
// definition, report id and any defect binding were all computed from text
// the user never submitted, identical to the report an explicit "" submission
// yields. Whenever one of the five formal members is present its value must
// therefore be a JSON string — null, a boolean, a number, an object or an
// array rejects the whole submission, independently of the other rules, the
// check records and of whether the rule was checked or produced a finding.
// The check is about the JSON type alone, not non-empty text: an omitted
// member still decodes to its default and an explicit "" keeps the ordinary
// business judgement (an omitted id/version is still required, an empty
// kind/severity/invariant stays legal). The strict rewrite dropped extension
// members, so a case-variant or whitespace-padded name ("Kind", " kind ")
// neither fills a missing formal field nor rescues an illegal formal value,
// and a null it carries never reaches this gate; names written with Unicode
// escapes are compared after decoding, so "kind":null names the same formal
// field. The error names the rule's zero-based position in the rules array
// and, when the rule carries a legal non-empty id, that id too — an illegal
// id itself leaves the rule locatable by position alone.
func validateFormalRuleText(strict []byte) error {
	checks := make([]ruleFieldTypeCheck, len(submissionRuleTextFields))
	for i, field := range submissionRuleTextFields {
		checks[i] = ruleFieldTypeCheck{field: field, typ: ruleFieldString}
	}
	return checkRuleFieldTypes(strict, checks, ruleFieldTypeHooks{
		locate: func(i int, rule map[string]json.RawMessage) string {
			where := fmt.Sprintf("rules[%d]", i)
			if id := formalRuleID(rule); id != "" {
				where += " (rule " + id + ")"
			}
			return where
		},
		invalidJSON: func(err error) error { return errInvalid("invalid JSON: " + err.Error()) },
		reject: func(where, field string, typ ruleFieldType) error {
			return errInvalid(where + ": " + field + " " + typ.requirement())
		},
	})
}

// artifactTextFields lists the formal artifact members whose value, once the
// member is written out, must be a JSON string.
var artifactTextFields = []string{"name", "abi", "bytecode", "source"}

// validateFormalArtifactFields checks the raw JSON token of every written
// formal artifact member before the strict submission is decoded into the Go
// wireArtifact string fields. Decoding straight into a Go string turns a
// formal null member into the zero value "", indistinguishable from an
// omitted member or an explicitly written empty string: an artifact with a
// legal name and "source":null and no rules that need the ABI or bytecode
// would then hash exactly like one whose source was submitted as "", pass
// every business check and receive a success report, laundering a malformed
// submission into a legal one. Whenever a formal member is present its value
// must therefore be a JSON string — null, a boolean, a number, an object or
// an array rejects the whole submission, independently of the rules array,
// the check records and of whether any rule references the field. The check
// is about the JSON type alone, not non-empty text: an omitted member still
// decodes to its default and an explicit "" keeps the ordinary business
// judgement (an empty name still produces no report, a rule that needs an
// ABI still needs a non-empty one, a symbolic rule still needs non-empty
// bytecode, and legal empty text is otherwise accepted). The strict rewrite
// dropped extension members, so a case-variant or whitespace-padded name
// ("Source", " source ") neither fills a missing formal field nor rescues an
// illegal formal value; names written with Unicode escapes are compared
// after decoding, so "source":null names the same formal source field.
// The error names the exact field, e.g. "artifact.source". An absent or null
// artifact object is left untouched here: the existing "artifact name is
// required" business error keeps covering it.
func validateFormalArtifactFields(strict []byte) error {
	var top struct {
		Artifact json.RawMessage `json:"artifact"`
	}
	if err := json.Unmarshal(strict, &top); err != nil {
		return errInvalid("invalid JSON: " + err.Error())
	}
	if len(top.Artifact) == 0 || string(top.Artifact) == "null" {
		return nil
	}
	var artifact map[string]json.RawMessage
	if err := json.Unmarshal(top.Artifact, &artifact); err != nil {
		return errInvalid("invalid JSON: " + err.Error())
	}
	for _, field := range artifactTextFields {
		raw, present := artifact[field]
		if !present {
			continue
		}
		var token any
		if err := json.Unmarshal(raw, &token); err != nil {
			return errInvalid("artifact." + field + " must be a string")
		}
		if _, ok := token.(string); !ok {
			return errInvalid("artifact." + field + " must be a string")
		}
	}
	return nil
}

// ParseAuditInput decodes an audit submission JSON object into domain values.
// Invariant values must be JSON booleans; any other type is an error. A formal
// requiresABI member on a rule must likewise be a JSON boolean: null or any
// non-boolean value rejects the whole submission instead of being read as the
// zero value false, while an omitted member still means false. Each formal
// rule text member (id, kind, severity, invariant, version), each formal
// artifact member (name, abi, bytecode, source) and the formal note member of
// each check record that is written out must be a JSON string: null or any
// non-string value rejects the whole submission instead of being read as the
// zero value "", while an omitted member still takes its default and an
// explicit empty string keeps the ordinary business judgement. Any JSON
// object in the submission that repeats a member name
// rejects the whole submission: the decoder keeps only the last value
// silently, so a repeated invariant key would choose a conclusion by member
// order instead of giving one trustworthy result. A character the decoder
// would silently rewrite — an invalid UTF-8 byte, or an unpaired or wrongly
// ordered surrogate escape in any member name or string value, including
// values nested under unknown extension members — rejects the whole
// submission as an input error before any content is hashed, so evidence and
// hashes always reflect the submitted bytes rather than a U+FFFD-rewritten
// copy. Only the fixed fields under their agreed spelling participate: case
// variants and whitespace-padded names are extension data and are ignored, so
// they can neither override a formal value nor supply one when the formal
// member is missing or unsupported. Invariant names are not fixed fields —
// they are user-defined, compared case sensitively and never trimmed.
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
	if err := validateFormalCheckNotes(strict); err != nil {
		return Artifact{}, nil, nil, nil, err
	}
	if err := validateFormalRequiresABI(strict); err != nil {
		return Artifact{}, nil, nil, nil, err
	}
	if err := validateFormalRuleText(strict); err != nil {
		return Artifact{}, nil, nil, nil, err
	}
	if err := validateFormalArtifactFields(strict); err != nil {
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
		} else {
			// No imported check: the invariant booleans decide. The verdict
			// interpretation is shared with the finding-list path in Run.
			switch checkInvariant(rule, invariants) {
			case invariantHolds:
				status = StatusPass
			case invariantViolated:
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
				evidence = invariantEvidence(rule.Invariant)
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

// canonicalReport is the deterministic content a report id is computed from.
// The rules and findings are the report's own ReportRule and ReportFinding
// values: their stored JSON fields are exactly the content the id binds, so
// the id form reuses the one field representation instead of maintaining a
// parallel copy that every field change would have to be mirrored into. The
// rule note keeps its omitempty behaviour, so a note omitted and a note
// written as an empty string hash alike and reports built only from invariant
// booleans keep their original ids.
type canonicalReport struct {
	ArtifactHash string          `json:"artifactHash"`
	Name         string          `json:"name"`
	Rules        []ReportRule    `json:"rules"`
	Findings     []ReportFinding `json:"findings"`
}

// canonicalize renders a report into its order-independent form. The rule and
// finding slices are copied before sorting, so computing an id never reorders
// the report itself: a saved report keeps the submission order and a loaded
// report keeps the archive order.
func canonicalize(report Report) canonicalReport {
	cr := canonicalReport{
		ArtifactHash: report.Artifact.Hash,
		Name:         report.Artifact.Name,
	}
	cr.Rules = append(cr.Rules, report.Rules...)
	sort.Slice(cr.Rules, func(i, j int) bool { return cr.Rules[i].ID < cr.Rules[j].ID })
	cr.Findings = append(cr.Findings, report.Findings...)
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
			wantEvidence = invariantEvidence(rule.Invariant)
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

// firstInvalidUTF8ByteInString returns the first byte that is not valid UTF-8
// inside s. A Go string can carry any bytes, including bytes no JSON text may
// contain: json.Marshal (and therefore the canonical marshalling inside
// ReportID) silently replaces such a byte with U+FFFD instead of failing, so
// neither the id/content check nor the archive round trip can see it.
func firstInvalidUTF8ByteInString(s string) (byte, bool) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return s[i], true
		}
		i += size
	}
	return 0, false
}

// validateSubmittedText is the in-memory counterpart of the JSON character
// gates in ParseAuditInput and loadStoredReport. SaveReport accepts a Report
// built directly by a Go caller, whose strings never passed through JSON
// decoding; encoding/json marshals such a value without an error while
// replacing every invalid UTF-8 byte with U+FFFD, and ReportID computes from
// the same rewritten canonical form, so the recomputed id and the
// rule/finding correspondence would all match an archive whose text no
// longer equals what the caller handed over. Every caller-supplied string is
// therefore checked on the raw object — reportId, artifact name and hash,
// each rule definition field and status note, and each finding binding field
// and evidence — independently of which rules produced defects and of
// whether the report carries any finding at all. The rejection is an input
// error naming the exact field, with the array position of rules and
// findings, and it runs before any filesystem operation.
func validateSubmittedText(r Report) error {
	check := func(field, value string) error {
		if b, bad := firstInvalidUTF8ByteInString(value); bad {
			return errInvalid(fmt.Sprintf("invalid UTF-8 byte 0x%02x in report field %s", b, field))
		}
		return nil
	}
	if err := check("reportId", r.ReportID); err != nil {
		return err
	}
	if err := check("artifact.name", r.Artifact.Name); err != nil {
		return err
	}
	if err := check("artifact.hash", r.Artifact.Hash); err != nil {
		return err
	}
	ruleFields := []string{"id", "kind", "severity", "invariant", "version", "status", "note"}
	for i, rule := range r.Rules {
		values := []string{rule.ID, rule.Kind, rule.Severity, rule.Invariant, rule.Version, rule.Status, rule.Note}
		for j, value := range values {
			if err := check(fmt.Sprintf("rules[%d].%s", i, ruleFields[j]), value); err != nil {
				return err
			}
		}
	}
	findingFields := []string{"artifactHash", "ruleId", "version", "severity", "invariant", "evidence"}
	for i, finding := range r.Findings {
		values := []string{finding.ArtifactHash, finding.RuleID, finding.Version, finding.Severity, finding.Invariant, finding.Evidence}
		for j, value := range values {
			if err := check(fmt.Sprintf("findings[%d].%s", i, findingFields[j]), value); err != nil {
				return err
			}
		}
	}
	return nil
}

// duplicateArchiveError classifies an archive that repeats a JSON member as
// corrupt and names the requested report id, the decoded member name and the
// object carrying it (with array position and rule id when applicable).
func duplicateArchiveError(id string, data []byte, dup *duplicateMemberError) error {
	return errCorrupt("report " + id + " archive is corrupt: " + duplicateMemberMessage(data, dup))
}

// characterArchiveError classifies an archive whose bytes are not legal JSON
// text — an invalid UTF-8 byte anywhere, or an unpaired / wrongly ordered
// surrogate escape inside any member name or string value, including unknown
// extension members — as corrupt and names the requested report id together
// with the precise byte offset, line/column and JSON path. It is the
// read-side counterpart of the submission gate in ParseAuditInput: the decode
// below would otherwise replace both problems with U+FFFD and could accept a
// rewritten archive whose id and rule/finding evidence happened to match.
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

// validateArchiveRuleFields is the read-side counterpart of the submission
// gate in validateFormalRequiresABI. A ReportRule's typed members are Go
// bool/string fields, so decoding the strict archive straight into Report
// turns a formal null member into the zero value false or "": an archive that
// wrote "requiresABI":null, or "note":null on a passing rule without a note,
// would read byte-for-byte like one that omitted the member, the recomputed
// id and the rule/finding correspondence would all pass on that laundered
// value, and a diff could even compare the rule as unchanged. The shared
// checkRuleFieldTypes gate therefore inspects each written formal member's
// raw JSON token before that decoding happens. null or any other
// non-required type makes the whole archive corrupt, independently of the
// rule's check status and of whether it has a finding — the offending rule is
// never skipped and no partial report is returned. An omitted member still
// decodes to the zero value and an explicit empty string is still judged by
// the ordinary business rules: the string gate is about the JSON type alone,
// not about requiring text to be non-empty. The strict rewrite dropped
// extension members, so a case-variant or whitespace-padded name is invisible
// here: a correctly typed value it carries neither supplies nor rescues the
// formal value, and a null it carries never reaches this gate. locate renders
// the rule locator in the wording each gate historically used, and every
// error names the requested report id and is classified as archive
// corruption.
func validateArchiveRuleFields(strict []byte, id string, checks []ruleFieldTypeCheck,
	locate func(int, map[string]json.RawMessage) string) error {
	return checkRuleFieldTypes(strict, checks, ruleFieldTypeHooks{
		locate: locate,
		invalidJSON: func(err error) error {
			return errCorrupt("invalid JSON in report " + id + ": " + err.Error())
		},
		reject: func(where, field string, typ ruleFieldType) error {
			return errCorrupt("report " + id + " archive is corrupt: " + where + ": " + field + " " + typ.requirement())
		},
	})
}

// archiveRuleLocator names a rule in an archive error by its formal id
// ("rule r-bad"), falling back to "rule" when the id is missing, empty or not
// itself a legal string. It deliberately carries no rules-array position.
func archiveRuleLocator(_ int, rule map[string]json.RawMessage) string {
	if ruleID := formalRuleID(rule); ruleID != "" {
		return "rule " + ruleID
	}
	return "rule"
}

// archiveRulePositionLocator names a rule's position in the rules array
// ("rules[1]") and, when the rule carries a legal non-empty id, also names it
// ("rules[1] (rule r-bad)").
func archiveRulePositionLocator(i int, rule map[string]json.RawMessage) string {
	where := fmt.Sprintf("rules[%d]", i)
	if ruleID := formalRuleID(rule); ruleID != "" {
		where += " (rule " + ruleID + ")"
	}
	return where
}

// validateArchiveRequiresABI runs the read-side boolean gate for the formal
// requiresABI member.
func validateArchiveRequiresABI(strict []byte, id string) error {
	return validateArchiveRuleFields(strict, id,
		[]ruleFieldTypeCheck{{field: "requiresABI", typ: ruleFieldBoolean}},
		archiveRuleLocator)
}

// archiveRuleTextFields lists the formal rule members whose value, once the
// member is written out, must be a JSON string.
var archiveRuleTextFields = []string{"id", "kind", "severity", "invariant", "version", "status", "note"}

// validateArchiveRuleText runs the read-side string gate for the text fields
// of every stored rule; see validateArchiveRuleFields for why the raw token is
// checked before decoding.
func validateArchiveRuleText(strict []byte, id string) error {
	checks := make([]ruleFieldTypeCheck, len(archiveRuleTextFields))
	for i, field := range archiveRuleTextFields {
		checks[i] = ruleFieldTypeCheck{field: field, typ: ruleFieldString}
	}
	return validateArchiveRuleFields(strict, id, checks, archiveRulePositionLocator)
}

// archiveFindingTextFields lists the formal finding members whose value, once
// the member is written out, must be a JSON string.
var archiveFindingTextFields = []string{"artifactHash", "ruleId", "version", "severity", "invariant", "evidence"}

// archiveFindingLocator names a finding's position in the findings array
// ("findings[0]") and, when the record carries a legal non-empty formal ruleId,
// names that rule too ("findings[0] (rule r-bad)"). A missing, empty or
// mistyped ruleId leaves the record locatable by position alone.
func archiveFindingLocator(i int, finding map[string]json.RawMessage) string {
	where := fmt.Sprintf("findings[%d]", i)
	if ruleID := formalMemberString(finding, "ruleId"); ruleID != "" {
		where += " (rule " + ruleID + ")"
	}
	return where
}

// validateArchiveFindingText is the read-side string gate for the six text
// fields of every stored defect finding: artifactHash, ruleId, version,
// severity, invariant and evidence. A ReportFinding's members are Go strings,
// so decoding the strict archive straight into Report turns a formal null
// member into the zero value "": a legal report whose rule and finding both
// recorded an empty severity (or empty invariant), rewritten so the finding
// carries "severity":null instead, reads byte-for-byte like that legal report
// — the artifact hash, the requested and recomputed report ids and the
// rule/finding correspondence all match on the laundered empty text, and a
// diff could even classify the record as 无变化. Inspecting the raw JSON
// token before that decoding closes the hole: null or any other non-string
// JSON type on any written formal finding member makes the whole archive
// corrupt, independently of the other findings and of whether the artifact
// hash, report id and rule/finding correspondence still line up, and no
// partial report is returned. The gate is about the JSON type alone, not
// non-empty text: an omitted member still decodes to its zero value and an
// explicit "" keeps the existing required-and-binding rules of
// validateReport, so a legal empty severity/invariant round-trips unchanged
// and no new requirement that all text be non-empty is introduced. The
// strict rewrite dropped extension members, so a case-variant or
// whitespace-padded name ("Severity", " ruleId ") neither fills a missing
// formal member nor rescues an illegal formal value, and a null it carries
// never reaches this gate; a name written with Unicode escapes denotes the
// same formal field after decoding. Every error names the requested report
// id, the finding's zero-based position in the findings array and the member
// that must be a string, and names the owning rule when the record carries a
// legal non-empty ruleId.
func validateArchiveFindingText(strict []byte, id string) error {
	checks := make([]ruleFieldTypeCheck, len(archiveFindingTextFields))
	for i, field := range archiveFindingTextFields {
		checks[i] = ruleFieldTypeCheck{field: field, typ: ruleFieldString}
	}
	return checkObjectArrayFieldTypes(strict, "findings", checks, ruleFieldTypeHooks{
		locate: archiveFindingLocator,
		invalidJSON: func(err error) error {
			return errCorrupt("invalid JSON in report " + id + ": " + err.Error())
		},
		reject: func(where, field string, typ ruleFieldType) error {
			return errCorrupt("report " + id + " archive is corrupt: " + where + ": " + field + " " + typ.requirement())
		},
	})
}

// loadStoredReport parses archive bytes for id and fully validates them.
func loadStoredReport(data []byte, id string) (Report, error) {
	// Read-side counterpart of the submission character gate in
	// ParseAuditInput. As with a repeated member, json.Unmarshal silently
	// rewrites an invalid UTF-8 byte and an unpaired or wrongly ordered
	// surrogate escape into U+FFFD, so an archive whose note and evidence both
	// carried the substitution character could have those two spots changed to
	// lone surrogate escapes and still decode to byte-identical content: the
	// recomputed id and the rule/finding evidence comparison would then pass on
	// the rewritten copy. Every raw string literal is checked first — member
	// names and values, at every depth, inside unknown extension members too —
	// and the whole archive is corrupt when any character is illegal, whatever
	// id the rewritten content would compute.
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
	// Check the formal requiresABI member against its raw JSON token before
	// decoding into the Go bool below; otherwise a null value would silently
	// become the zero value false and could pass every later check, including
	// the content id, as if the archive had explicitly said false.
	if err := validateArchiveRequiresABI(strict, id); err != nil {
		return Report{}, err
	}
	// Same laundering hazard for the rule text fields: decoding into a Go
	// string turns a formal null member into "", so an archive that wrote
	// "note":null on a note-less passing rule would pass every later check,
	// including the content id, as if the member had been omitted. Check the
	// raw JSON token of every written formal text member before decoding.
	if err := validateArchiveRuleText(strict, id); err != nil {
		return Report{}, err
	}
	// Same laundering hazard for the finding text fields: a finding written
	// with "severity":null decodes to the zero value "", so when the rule
	// legitimately recorded an empty severity the archive would read back
	// with a matching id and rule/finding correspondence, as if the empty
	// text had been stored — and a diff could report 无变化. Check the raw
	// JSON token of every written formal finding member before decoding.
	if err := validateArchiveFindingText(strict, id); err != nil {
		return Report{}, err
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
// files. Every string in a directly constructed report must be valid UTF-8:
// json.Marshal would otherwise rewrite an invalid byte to U+FFFD while the
// content-addressed id matched the rewritten copy, reporting success for an
// archive whose text differs from the caller's; such a report is rejected as
// an input error before the store directory is touched. A pre-existing file
// with the same id must be a valid archive of the same report; a corrupted
// archive makes the submission fail while keeping the original file, even
// when the corruption appears only during the save. The first successfully
// archived bytes are never replaced by later submissions.
func SaveReport(dir string, r Report) error {
	if err := validateSubmittedText(r); err != nil {
		return err
	}
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
