package contractsentinel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Check statuses recorded in a report.
const (
	StatusPassed    = "通过"
	StatusFailed    = "发现缺陷"
	StatusUnchecked = "未检查"
)

// Check is the outcome of one rule against the submitted artifact.
type Check struct {
	Rule     Rule            `json:"rule"`
	Status   string          `json:"status"`
	Findings []ReportFinding `json:"findings"`
}

// ReportFinding is a finding bound to the artifact hash and rule version.
type ReportFinding struct {
	ArtifactHash string `json:"artifactHash"`
	Rule         string `json:"rule"`
	Version      string `json:"version"`
	Severity     string `json:"severity"`
	Invariant    string `json:"invariant"`
	Evidence     string `json:"evidence"`
}

// Report is the persistent, content-addressed audit record.
type Report struct {
	ID           string          `json:"id"`
	ArtifactName string          `json:"artifactName"`
	ArtifactHash string          `json:"artifactHash"`
	Checks       []Check         `json:"checks"`
	Findings     []ReportFinding `json:"findings"`
}

// ArtifactHash hashes the raw ABI, bytecode and source contents with
// length-prefixed field boundaries. The artifact name is not part of it,
// and Source is hashed as a field value, never resolved to a file.
func ArtifactHash(a Artifact) string {
	h := sha256.New()
	writeField(h, "abi", a.ABI)
	writeField(h, "bytecode", a.Bytecode)
	writeField(h, "source", a.Source)
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(w io.Writer, name, value string) {
	fmt.Fprintf(w, "%d:%s%d:%s", len(name), name, len(value), value)
}

// ParseAuditInput decodes and validates the audit submission JSON.
func ParseAuditInput(data []byte) (Artifact, []Rule, map[string]bool, error) {
	var raw struct {
		Artifact   Artifact                   `json:"artifact"`
		Rules      []Rule                     `json:"rules"`
		Invariants map[string]json.RawMessage `json:"invariants"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return Artifact{}, nil, nil, fmt.Errorf("invalid audit input: %w", err)
	}
	if dec.More() {
		return Artifact{}, nil, nil, errInvalid("invalid audit input: trailing data after JSON object")
	}
	invariants := map[string]bool{}
	for name, value := range raw.Invariants {
		var holds bool
		if err := json.Unmarshal(value, &holds); err != nil {
			return Artifact{}, nil, nil, errInvalid("invariant " + name + " must be a JSON boolean")
		}
		invariants[name] = holds
	}
	if err := validateRules(raw.Rules); err != nil {
		return Artifact{}, nil, nil, err
	}
	return raw.Artifact, raw.Rules, invariants, nil
}

func validateRules(rules []Rule) error {
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.ID == "" {
			return errInvalid("rule id must not be empty")
		}
		if rule.Version == "" {
			return errInvalid("rule " + rule.ID + " needs a non-empty version")
		}
		if seen[rule.ID] {
			return errInvalid("duplicate rule id " + rule.ID)
		}
		seen[rule.ID] = true
	}
	return nil
}

// BuildReport evaluates the submission and assembles the canonical report.
// Input insufficiency (missing ABI or bytecode) fails the whole submission
// before any report exists, exactly like Run.
func BuildReport(artifact Artifact, rules []Rule, invariants map[string]bool) (*Report, error) {
	if err := validateRules(rules); err != nil {
		return nil, err
	}
	findings, err := Run(artifact, rules, invariants)
	if err != nil {
		return nil, err
	}
	hash := ArtifactHash(artifact)

	sorted := append([]Rule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	versionByRule := make(map[string]string, len(rules))
	for _, rule := range rules {
		versionByRule[rule.ID] = rule.Version
	}
	bind := func(f Finding) ReportFinding {
		return ReportFinding{
			ArtifactHash: hash,
			Rule:         f.Rule,
			Version:      versionByRule[f.Rule],
			Severity:     f.Severity,
			Invariant:    f.Invariant,
			Evidence:     f.Evidence,
		}
	}

	findingsByRule := map[string][]ReportFinding{}
	for _, f := range findings {
		findingsByRule[f.Rule] = append(findingsByRule[f.Rule], bind(f))
	}

	checks := make([]Check, 0, len(sorted))
	for _, rule := range sorted {
		status := StatusUnchecked
		if holds, checked := invariants[rule.Invariant]; checked {
			if holds {
				status = StatusPassed
			} else {
				status = StatusFailed
			}
		}
		ruleFindings := findingsByRule[rule.ID]
		if ruleFindings == nil {
			ruleFindings = []ReportFinding{}
		}
		checks = append(checks, Check{Rule: rule, Status: status, Findings: ruleFindings})
	}

	all := make([]ReportFinding, 0, len(findings))
	for _, f := range findings {
		all = append(all, bind(f))
	}

	report := &Report{
		ArtifactName: artifact.Name,
		ArtifactHash: hash,
		Checks:       checks,
		Findings:     all,
	}
	report.ID = reportID(report)
	return report, nil
}

// reportID hashes the canonical report material: artifact hash, artifact
// name, every full rule definition, the invariant value each rule checked
// against (unchecked is distinct from passed), and every finding including
// its evidence. Rule order in the submission does not matter.
func reportID(report *Report) string {
	h := sha256.New()
	w := func(s string) { fmt.Fprintf(h, "%d:%s", len(s), s) }
	w("contractsentinel-report-v1")
	w(report.ArtifactHash)
	w(report.ArtifactName)
	checks := append([]Check(nil), report.Checks...)
	sort.Slice(checks, func(i, j int) bool { return checks[i].Rule.ID < checks[j].Rule.ID })
	fmt.Fprintf(h, "%d:", len(checks))
	for _, check := range checks {
		rule := check.Rule
		w(rule.ID)
		w(rule.Kind)
		w(rule.Severity)
		w(rule.Invariant)
		w(rule.Version)
		if rule.RequiresABI {
			w("1")
		} else {
			w("0")
		}
		w(check.Status)
	}
	fmt.Fprintf(h, "%d:", len(report.Findings))
	for _, f := range report.Findings {
		w(f.ArtifactHash)
		w(f.Rule)
		w(f.Version)
		w(f.Severity)
		w(f.Invariant)
		w(f.Evidence)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Marshal renders the report as deterministic, byte-stable JSON.
func (r *Report) Marshal() []byte {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

// VerifyReport parses stored report bytes and confirms the content matches
// the expected id, so any tampering — including rewritten finding evidence —
// is detected.
func VerifyReport(data []byte, wantID string) (*Report, error) {
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("stored report %s is corrupted: %w", wantID, err)
	}
	if report.ID != wantID {
		return nil, fmt.Errorf("stored report id %s does not match requested id %s", report.ID, wantID)
	}
	if actual := reportID(&report); actual != wantID {
		return nil, fmt.Errorf("stored report %s content does not match its id", wantID)
	}
	return &report, nil
}
