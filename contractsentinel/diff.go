// Package contractsentinel diff: deterministic comparison of two stored reports.
package contractsentinel

import (
	"sort"
)

// Per-rule comparison outcomes.
const (
	ChangeNewDefect      = "新发现缺陷"
	ChangeResolvedDefect = "已消除缺陷"
	ChangeStatusChanged  = "检查状态变化"
	ChangeNoteChanged    = "检查说明变化"
	ChangeNoChange       = "无变化"
	ChangeRuleAdded      = "新增规则"
	ChangeRuleRemoved    = "移除规则"
	ChangeRuleChanged    = "规则变化"
)

// DiffReportRef identifies one side of a diff: the report id and the artifact
// name and content hash it audited.
type DiffReportRef struct {
	ReportID string         `json:"reportId"`
	Artifact ReportArtifact `json:"artifact"`
}

// DiffSide is one side of a per-rule comparison: the complete rule definition
// with its check status, and the defect evidence when the rule found a defect.
// The finding keeps the artifact hash and rule version recorded at audit time.
type DiffSide struct {
	Rule    ReportRule     `json:"rule"`
	Finding *ReportFinding `json:"finding"`
}

// RuleDiff is the comparison result for one rule id. Exactly one result is
// emitted per rule id present on either side; a side absent from that report
// is null.
type RuleDiff struct {
	RuleID string    `json:"ruleId"`
	Change string    `json:"change"`
	Before *DiffSide `json:"before"`
	After  *DiffSide `json:"after"`
}

// DiffSummary counts every result category plus the actual defect totals of
// both sides. Zero counts are always present.
type DiffSummary struct {
	NewDefects      int `json:"newDefects"`
	ResolvedDefects int `json:"resolvedDefects"`
	StatusChanges   int `json:"statusChanges"`
	NoteChanges     int `json:"noteChanges"`
	NoChange        int `json:"noChange"`
	AddedRules      int `json:"addedRules"`
	RemovedRules    int `json:"removedRules"`
	ChangedRules    int `json:"changedRules"`
	BeforeDefects   int `json:"beforeDefects"`
	AfterDefects    int `json:"afterDefects"`
}

// DiffResult is the full comparison of two reports. It contains no timestamps
// and no storage-order artifacts, so comparing the same pair of reports always
// renders byte-identical JSON.
type DiffResult struct {
	Before              DiffReportRef `json:"before"`
	After               DiffReportRef `json:"after"`
	ArtifactNameChanged bool          `json:"artifactNameChanged"`
	ArtifactHashChanged bool          `json:"artifactHashChanged"`
	Results             []RuleDiff    `json:"results"`
	Summary             DiffSummary   `json:"summary"`
}

// validReportID reports whether id is exactly 64 lowercase hex characters.
func validReportID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// LoadReportForDiff loads a stored report for comparison. The id must be 64
// lowercase hex characters; the archive is fully verified. The store is only
// read, never created or modified.
func LoadReportForDiff(dir, id string) (Report, error) {
	if !validReportID(id) {
		return Report{}, errInvalid("invalid report id " + id + ": want 64 lowercase hex characters")
	}
	return LoadReport(dir, id)
}

// DiffStore loads both reports from the store and compares them. Both reports
// are fully verified before any comparison happens; any failure yields an
// error and no partial result.
func DiffStore(dir, beforeID, afterID string) (DiffResult, error) {
	before, err := LoadReportForDiff(dir, beforeID)
	if err != nil {
		return DiffResult{}, err
	}
	after, err := LoadReportForDiff(dir, afterID)
	if err != nil {
		return DiffResult{}, err
	}
	return DiffReports(before, after), nil
}

// DiffStoreRule works exactly like DiffStore — both archives are loaded and
// fully verified first, the store is only read — but the returned comparison
// keeps only the result for ruleID. The rule id is matched against its
// complete text exactly: case and surrounding spaces are part of the id, so
// "R1" and " R1 " never match "r1". The output keeps the full comparison
// shape: the two report refs, artifact name/hash flags and the one selected
// result entry, which is classified by the same rules as the full diff. The
// summary counts only that entry, and beforeDefects/afterDefects are each
// zero or one — whether the selected rule has a real defect finding on that
// side, independently of defects other rules have in the same report.
//
// The filter never bypasses archive verification: a missing, corrupt or
// illegitimately bound archive fails with the usual error even when the
// problem is on another rule, and only after both archives have passed does
// the filter itself get validated. An explicitly empty rule id, or an id
// neither report contains, is then an input error and no result is returned.
func DiffStoreRule(dir, beforeID, afterID, ruleID string) (DiffResult, error) {
	before, err := LoadReportForDiff(dir, beforeID)
	if err != nil {
		return DiffResult{}, err
	}
	after, err := LoadReportForDiff(dir, afterID)
	if err != nil {
		return DiffResult{}, err
	}
	if ruleID == "" {
		return DiffResult{}, errInvalid("rule id filter must not be empty")
	}
	full := DiffReports(before, after)
	for i := range full.Results {
		if full.Results[i].RuleID != ruleID {
			continue
		}
		entry := full.Results[i]
		full.Results = []RuleDiff{entry}
		full.Summary = summaryForEntry(entry)
		return full, nil
	}
	return DiffResult{}, errInvalid("rule " + ruleID + " not found in either report")
}

// summaryForEntry builds the summary of a one-rule comparison: the single
// category the entry belongs to plus the per-side real-defect presence, each
// zero or one. A side carries a finding exactly when that report recorded a
// real defect for the rule; tool-missing, timeout and unchecked sides do not.
func summaryForEntry(entry RuleDiff) DiffSummary {
	s := DiffSummary{}
	switch entry.Change {
	case ChangeNewDefect:
		s.NewDefects = 1
	case ChangeResolvedDefect:
		s.ResolvedDefects = 1
	case ChangeStatusChanged:
		s.StatusChanges = 1
	case ChangeNoteChanged:
		s.NoteChanges = 1
	case ChangeNoChange:
		s.NoChange = 1
	case ChangeRuleAdded:
		s.AddedRules = 1
	case ChangeRuleRemoved:
		s.RemovedRules = 1
	case ChangeRuleChanged:
		s.ChangedRules = 1
	}
	if entry.Before != nil && entry.Before.Finding != nil {
		s.BeforeDefects = 1
	}
	if entry.After != nil && entry.After.Finding != nil {
		s.AfterDefects = 1
	}
	return s
}

// sameRuleDefinition reports whether two rules with the same id also agree on
// version, kind, severity, invariant and ABI requirement. Only then may their
// check statuses be compared.
func sameRuleDefinition(a, b ReportRule) bool {
	return a.Version == b.Version &&
		a.Kind == b.Kind &&
		a.Severity == b.Severity &&
		a.Invariant == b.Invariant &&
		a.RequiresABI == b.RequiresABI
}

// indexFindings maps rule id to finding. Reports are verified before diffing,
// so at most one finding exists per rule id.
func indexFindings(findings []ReportFinding) map[string]ReportFinding {
	out := make(map[string]ReportFinding, len(findings))
	for _, f := range findings {
		out[f.RuleID] = f
	}
	return out
}

// diffSide builds one side of a result: the rule and, when it found a defect,
// its evidence.
func diffSide(rule ReportRule, findings map[string]ReportFinding) *DiffSide {
	side := &DiffSide{Rule: rule}
	if f, ok := findings[rule.ID]; ok {
		finding := f
		side.Finding = &finding
	}
	return side
}

// DiffReports compares two verified reports. Rules are matched by id; statuses
// are only compared when the full rule definition is identical. Results are
// sorted by rule id and independent of the storage order of rules and
// findings.
func DiffReports(before, after Report) DiffResult {
	beforeRules := make(map[string]ReportRule, len(before.Rules))
	for _, r := range before.Rules {
		beforeRules[r.ID] = r
	}
	afterRules := make(map[string]ReportRule, len(after.Rules))
	for _, r := range after.Rules {
		afterRules[r.ID] = r
	}
	beforeFindings := indexFindings(before.Findings)
	afterFindings := indexFindings(after.Findings)

	ids := make([]string, 0, len(beforeRules)+len(afterRules))
	for id := range beforeRules {
		ids = append(ids, id)
	}
	for id := range afterRules {
		if _, ok := beforeRules[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	result := DiffResult{
		Before:              DiffReportRef{ReportID: before.ReportID, Artifact: before.Artifact},
		After:               DiffReportRef{ReportID: after.ReportID, Artifact: after.Artifact},
		ArtifactNameChanged: before.Artifact.Name != after.Artifact.Name,
		ArtifactHashChanged: before.Artifact.Hash != after.Artifact.Hash,
		Results:             []RuleDiff{},
		Summary: DiffSummary{
			BeforeDefects: len(before.Findings),
			AfterDefects:  len(after.Findings),
		},
	}
	for _, id := range ids {
		b, inBefore := beforeRules[id]
		a, inAfter := afterRules[id]
		entry := RuleDiff{RuleID: id}
		switch {
		case !inBefore:
			entry.Change = ChangeRuleAdded
			entry.After = diffSide(a, afterFindings)
			result.Summary.AddedRules++
		case !inAfter:
			entry.Change = ChangeRuleRemoved
			entry.Before = diffSide(b, beforeFindings)
			result.Summary.RemovedRules++
		case !sameRuleDefinition(b, a):
			entry.Change = ChangeRuleChanged
			entry.Before = diffSide(b, beforeFindings)
			entry.After = diffSide(a, afterFindings)
			result.Summary.ChangedRules++
		default:
			entry.Before = diffSide(b, beforeFindings)
			entry.After = diffSide(a, afterFindings)
			switch {
			case b.Status == a.Status && b.Note == a.Note:
				entry.Change = ChangeNoChange
				result.Summary.NoChange++
			case b.Status == a.Status:
				entry.Change = ChangeNoteChanged
				result.Summary.NoteChanges++
			case b.Status == StatusPass && a.Status == StatusDefect:
				entry.Change = ChangeNewDefect
				result.Summary.NewDefects++
			case b.Status == StatusDefect && a.Status == StatusPass:
				entry.Change = ChangeResolvedDefect
				result.Summary.ResolvedDefects++
			default:
				entry.Change = ChangeStatusChanged
				result.Summary.StatusChanges++
			}
		}
		result.Results = append(result.Results, entry)
	}
	return result
}
