// Package contractsentinel implements audit rule evaluation over contract artifacts.
package contractsentinel

import "sort"

// Artifact is one compiled contract target under audit.
type Artifact struct {
	Name     string
	ABI      string
	Bytecode string
	Source   string
}

// Finding is one rule violation with the invariant it breaks.
type Finding struct {
	Rule      string
	Severity  string
	Invariant string
	Evidence  string
}

// Rule is a static or symbolic check the pipeline can run.
type Rule struct {
	ID          string
	Kind        string
	Severity    string
	Invariant   string
	RequiresABI bool
	Version     string
}

// invariantVerdict is the conclusion the submitted invariant booleans give
// one rule. Only a boolean carried under the rule's own invariant name
// counts, and only false is a defect: true and absent are distinct
// conclusions (the report path records them as 通过 and 未检查), and neither
// produces a finding.
type invariantVerdict int

const (
	invariantUnchecked invariantVerdict = iota // no value provided for the rule's invariant
	invariantHolds                             // the invariant was checked and holds
	invariantViolated                          // the invariant was checked and does not hold
)

// checkInvariant is the single interpretation of invariant booleans shared by
// the finding-list and the report paths, so the judgement rules live in one
// place. Invariant names are user-defined: they are looked up exactly as the
// rule carries them, case and whitespace included.
func checkInvariant(rule Rule, invariants map[string]bool) invariantVerdict {
	holds, checked := invariants[rule.Invariant]
	switch {
	case !checked:
		return invariantUnchecked
	case holds:
		return invariantHolds
	default:
		return invariantViolated
	}
}

// invariantEvidence is the defect evidence for a violated invariant. The name
// is the rule's original value: case, whitespace and punctuation are kept as
// written.
func invariantEvidence(invariant string) string {
	return "invariant " + invariant + " does not hold"
}

// Run executes the deterministic subset of rules and refuses inputs they need.
func Run(artifact Artifact, rules []Rule, invariants map[string]bool) ([]Finding, error) {
	if artifact.Name == "" {
		return nil, errInvalid("artifact name is required")
	}
	var findings []Finding
	for _, rule := range rules {
		if rule.RequiresABI && artifact.ABI == "" {
			return nil, errInvalid("rule " + rule.ID + " needs an ABI")
		}
		if rule.Kind == "symbolic" && artifact.Bytecode == "" {
			return nil, errInvalid("symbolic rule " + rule.ID + " needs bytecode")
		}
		if checkInvariant(rule, invariants) == invariantViolated {
			findings = append(findings, Finding{Rule: rule.ID, Severity: rule.Severity,
				Invariant: rule.Invariant, Evidence: invariantEvidence(rule.Invariant)})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			return findings[i].Rule < findings[j].Rule
		}
		return findings[i].Severity > findings[j].Severity
	})
	return findings, nil
}

type errInvalid string

func (e errInvalid) Error() string { return string(e) }
