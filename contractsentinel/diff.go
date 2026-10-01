// Package contractsentinel report: diff comparison between two saved reports.
package contractsentinel

import "sort"

// Diff change categories. A rule present on both sides whose definition
// changed is reported as a rule change regardless of its check status.
const (
	ChangeNewFinding   = "新发现缺陷"
	ChangeResolved     = "已消除缺陷"
	ChangeStatusChange = "检查状态变化"
	ChangeUnchanged    = "无变化"
	ChangeAddedRule    = "新增规则"
	ChangeRemovedRule  = "移除规则"
	ChangeChangedRule  = "规则变化"
)

// DiffReportRef identifies one side of a comparison by report id and artifact.
type DiffReportRef struct {
	ReportID string         `json:"reportId"`
	Artifact ReportArtifact `json:"artifact"`
}

// ArtifactDiff records whether the artifact name and content hash differ.
type ArtifactDiff struct {
	NameChanged bool `json:"nameChanged"`
	HashChanged bool `json:"hashChanged"`
}

// RuleDiffSide is one side of a per-rule comparison. The full rule definition
// (including check status) is always present when the side exists; the finding
// is null when the rule did not produce a defect.
type RuleDiffSide struct {
	Rule    ReportRule     `json:"rule"`
	Finding *ReportFinding `json:"finding"`
}

// RuleDiff is the comparison result for one rule id. The absent side is null.
type RuleDiff struct {
	RuleID string        `json:"ruleId"`
	Before *RuleDiffSide `json:"before"`
	After  *RuleDiffSide `json:"after"`
	Change string        `json:"change"`
}

// DiffSummary holds the aggregate counts. Every category is always reported,
// including zero counts.
type DiffSummary struct {
	NewFindings       int `json:"newFindings"`
	ResolvedFindings  int `json:"resolvedFindings"`
	StatusChanges     int `json:"statusChanges"`
	Unchanged         int `json:"unchanged"`
	AddedRules        int `json:"addedRules"`
	RemovedRules      int `json:"removedRules"`
	ChangedRules      int `json:"changedRules"`
	BeforeDefectCount int `json:"beforeDefectCount"`
	AfterDefectCount  int `json:"afterDefectCount"`
}

// ReportDiff is the full comparison output.
type ReportDiff struct {
	Before       DiffReportRef `json:"before"`
	After        DiffReportRef `json:"after"`
	ArtifactDiff ArtifactDiff  `json:"artifactDiff"`
	Rules        []RuleDiff    `json:"rules"`
	Summary      DiffSummary   `json:"summary"`
}

// ValidReportID reports whether id is a 64-character lowercase hex string.
func ValidReportID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// knownStatus reports whether s is one of the recorded check statuses.
func knownStatus(s string) bool {
	switch s {
	case StatusUnchecked, StatusPass, StatusDefect:
		return true
	}
	return false
}

// indexRules indexes a report's rules by id.
func indexRules(r Report) map[string]ReportRule {
	m := make(map[string]ReportRule, len(r.Rules))
	for _, rule := range r.Rules {
		m[rule.ID] = rule
	}
	return m
}

// indexFindings indexes a report's findings by rule id.
func indexFindings(r Report) map[string]ReportFinding {
	m := make(map[string]ReportFinding, len(r.Findings))
	for _, f := range r.Findings {
		m[f.RuleID] = f
	}
	return m
}

// validateReportForDiff checks the structural integrity that content-addressed
// storage alone does not enforce: rule ids are present, unique and non-empty,
// versions are non-empty, every status is a known check status, and each
// finding references a rule that exists with a matching version and artifact
// hash.
func validateReportForDiff(r Report) error {
	rules := make(map[string]ReportRule, len(r.Rules))
	for _, rule := range r.Rules {
		if rule.ID == "" {
			return errInvalid("report " + r.ReportID + " contains a rule with an empty id")
		}
		if _, dup := rules[rule.ID]; dup {
			return errInvalid("report " + r.ReportID + " contains duplicate rule id " + rule.ID)
		}
		rules[rule.ID] = rule
		if rule.Version == "" {
			return errInvalid("report " + r.ReportID + " rule " + rule.ID + " has an empty version")
		}
		if !knownStatus(rule.Status) {
			return errInvalid("report " + r.ReportID + " rule " + rule.ID + " has unknown check status " + rule.Status)
		}
	}
	for _, f := range r.Findings {
		rule, ok := rules[f.RuleID]
		if !ok {
			return errInvalid("report " + r.ReportID + " finding references unknown rule " + f.RuleID)
		}
		if f.Version != rule.Version {
			return errInvalid("report " + r.ReportID + " finding " + f.RuleID + " version does not match its rule")
		}
		if f.ArtifactHash != r.Artifact.Hash {
			return errInvalid("report " + r.ReportID + " finding " + f.RuleID + " artifact hash does not match the report")
		}
	}
	return nil
}

// sameDefinition reports whether two rules have identical definitions. The
// rule id is shared by construction; the check status is not part of the
// definition.
func sameDefinition(a, b ReportRule) bool {
	return a.Kind == b.Kind &&
		a.Severity == b.Severity &&
		a.Invariant == b.Invariant &&
		a.RequiresABI == b.RequiresABI &&
		a.Version == b.Version
}

// classifyChange determines the change category for one rule. A rule present
// on only one side is added or removed. A rule present on both sides whose
// definition changed is a rule change; otherwise the check statuses are
// compared.
func classifyChange(beforePresent, afterPresent bool, before, after ReportRule) string {
	switch {
	case !beforePresent && !afterPresent:
		return "" // impossible: the id comes from at least one side
	case !beforePresent:
		return ChangeAddedRule
	case !afterPresent:
		return ChangeRemovedRule
	}
	if !sameDefinition(before, after) {
		return ChangeChangedRule
	}
	switch {
	case before.Status == StatusPass && after.Status == StatusDefect:
		return ChangeNewFinding
	case before.Status == StatusDefect && after.Status == StatusPass:
		return ChangeResolved
	case before.Status != after.Status:
		return ChangeStatusChange
	default:
		return ChangeUnchanged
	}
}

// summarize counts each change category and the actual defect totals on both
// sides.
func summarize(rules []RuleDiff, before, after Report) DiffSummary {
	s := DiffSummary{}
	for _, r := range rules {
		switch r.Change {
		case ChangeNewFinding:
			s.NewFindings++
		case ChangeResolved:
			s.ResolvedFindings++
		case ChangeStatusChange:
			s.StatusChanges++
		case ChangeUnchanged:
			s.Unchanged++
		case ChangeAddedRule:
			s.AddedRules++
		case ChangeRemovedRule:
			s.RemovedRules++
		case ChangeChangedRule:
			s.ChangedRules++
		}
	}
	for _, rule := range before.Rules {
		if rule.Status == StatusDefect {
			s.BeforeDefectCount++
		}
	}
	for _, rule := range after.Rules {
		if rule.Status == StatusDefect {
			s.AfterDefectCount++
		}
	}
	return s
}

// DiffReports compares two saved reports. Both reports are validated before
// any comparison, so a structurally invalid report fails the whole diff. The
// result is independent of rule and finding storage order and contains no
// timestamps, so repeated comparisons of the same pair are byte-identical.
func DiffReports(before, after Report) (ReportDiff, error) {
	if err := validateReportForDiff(before); err != nil {
		return ReportDiff{}, err
	}
	if err := validateReportForDiff(after); err != nil {
		return ReportDiff{}, err
	}

	beforeRules := indexRules(before)
	afterRules := indexRules(after)
	beforeFindings := indexFindings(before)
	afterFindings := indexFindings(after)

	idSet := make(map[string]bool, len(beforeRules)+len(afterRules))
	for id := range beforeRules {
		idSet[id] = true
	}
	for id := range afterRules {
		idSet[id] = true
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	diff := ReportDiff{
		Before: DiffReportRef{ReportID: before.ReportID, Artifact: before.Artifact},
		After:  DiffReportRef{ReportID: after.ReportID, Artifact: after.Artifact},
		ArtifactDiff: ArtifactDiff{
			NameChanged: before.Artifact.Name != after.Artifact.Name,
			HashChanged: before.Artifact.Hash != after.Artifact.Hash,
		},
		Rules: []RuleDiff{},
	}

	for _, id := range ids {
		bRule, bOk := beforeRules[id]
		aRule, aOk := afterRules[id]

		var bSide, aSide *RuleDiffSide
		if bOk {
			side := &RuleDiffSide{Rule: bRule}
			if f, ok := beforeFindings[id]; ok {
				side.Finding = &f
			}
			bSide = side
		}
		if aOk {
			side := &RuleDiffSide{Rule: aRule}
			if f, ok := afterFindings[id]; ok {
				side.Finding = &f
			}
			aSide = side
		}

		diff.Rules = append(diff.Rules, RuleDiff{
			RuleID: id,
			Before: bSide,
			After:  aSide,
			Change: classifyChange(bOk, aOk, bRule, aRule),
		})
	}

	diff.Summary = summarize(diff.Rules, before, after)
	return diff, nil
}
