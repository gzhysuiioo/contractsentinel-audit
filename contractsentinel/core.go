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
		if holds, checked := invariants[rule.Invariant]; checked && !holds {
			findings = append(findings, Finding{Rule: rule.ID, Severity: rule.Severity,
				Invariant: rule.Invariant, Evidence: "invariant " + rule.Invariant + " does not hold"})
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
