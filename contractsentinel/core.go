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

// invariantVerdict is the conclusion the invariant booleans give one rule:
// whether a value was provided for the rule's invariant at all, and if so
// whether the invariant holds. Unchecked and passing are distinct outcomes.
type invariantVerdict struct {
	checked bool
	holds   bool
}

// judgeInvariant interprets the invariant booleans for one rule. Only a value
// recorded under the rule's exact invariant name counts — the name is compared
// as written, case sensitively and never trimmed — and a value no rule
// references is never consulted. This is the single definition of how an
// invariant boolean becomes an audit conclusion; both the finding-list API
// (Run) and the report API (BuildReport) judge rules through it.
func judgeInvariant(rule Rule, invariants map[string]bool) invariantVerdict {
	holds, checked := invariants[rule.Invariant]
	return invariantVerdict{checked: checked, holds: holds}
}

// defectEvidence is the canonical evidence text recorded when an invariant
// does not hold. The invariant name is embedded exactly as the rule states
// it, with its original case and whitespace.
func defectEvidence(invariant string) string {
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
		if verdict := judgeInvariant(rule, invariants); verdict.checked && !verdict.holds {
			findings = append(findings, Finding{Rule: rule.ID, Severity: rule.Severity,
				Invariant: rule.Invariant, Evidence: defectEvidence(rule.Invariant)})
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
