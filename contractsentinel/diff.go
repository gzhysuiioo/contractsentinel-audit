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

// DiffStoreRule loads both reports from the store and compares only the rule
// with the given id. Both reports are fully verified before any comparison
// happens, exactly as in DiffStore; the rule id must match exactly, including
// case and surrounding spaces. The store is only read, never modified.
func DiffStoreRule(dir, beforeID, afterID, ruleID string) (DiffResult, error) {
	if ruleID == "" {
		return DiffResult{}, errInvalid("rule id must not be empty")
	}
	before, err := LoadReportForDiff(dir, beforeID)
	if err != nil {
		return DiffResult{}, err
	}
	after, err := LoadReportForDiff(dir, afterID)
	if err != nil {
		return DiffResult{}, err
	}
	return DiffReportsRule(before, after, ruleID)
}

// DiffReportsRule compares two verified reports restricted to one rule id.
// The classification of the selected rule is identical to the full diff; the
// summary counts only that rule, and the defect totals become 0 or 1 each,
// reflecting whether this rule has a real defect record in that report.
func DiffReportsRule(before, after Report, ruleID string) (DiffResult, error) {
	if ruleID == "" {
		return DiffResult{}, errInvalid("rule id must not be empty")
	}
	full := DiffReports(before, after)
	for _, entry := range full.Results {
		if entry.RuleID != ruleID {
			continue
		}
		filtered := DiffResult{
			Before:              full.Before,
			After:               full.After,
			ArtifactNameChanged: full.ArtifactNameChanged,
			ArtifactHashChanged: full.ArtifactHashChanged,
			Results:             []RuleDiff{entry},
		}
		switch entry.Change {
		case ChangeNewDefect:
			filtered.Summary.NewDefects = 1
		case ChangeResolvedDefect:
			filtered.Summary.ResolvedDefects = 1
		case ChangeStatusChanged:
			filtered.Summary.StatusChanges = 1
		case ChangeNoteChanged:
			filtered.Summary.NoteChanges = 1
		case ChangeNoChange:
			filtered.Summary.NoChange = 1
		case ChangeRuleAdded:
			filtered.Summary.AddedRules = 1
		case ChangeRuleRemoved:
			filtered.Summary.RemovedRules = 1
		case ChangeRuleChanged:
			filtered.Summary.ChangedRules = 1
		}
		if entry.Before != nil && entry.Before.Finding != nil {
			filtered.Summary.BeforeDefects = 1
		}
		if entry.After != nil && entry.After.Finding != nil {
			filtered.Summary.AfterDefects = 1
		}
		return filtered, nil
	}
	return DiffResult{}, errInvalid("rule " + ruleID + " not found in either report")
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
