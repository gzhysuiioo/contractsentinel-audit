package contractsentinel

import (
	"testing"
)

// defectEvidenceNote is the baseline counterexample: Chinese text, embedded
// newlines and surrounding whitespace. The diff must surface it verbatim; a
// definition change must not rewrite it or re-version it.
const defectEvidenceNote = "  反例：攻击合约的 receive 在 balances 扣减前重入 withdraw，\n" +
	"此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。\n"

// defectBaselineRule is the rule definition shared by every case in this
// file. Each mutation below changes exactly one definition field.
func defectBaselineRule() Rule {
	return Rule{
		ID:        "reentrancy-guard",
		Kind:      "static",
		Severity:  "high",
		Invariant: "no-reentrant-withdraw",
		Version:   "1.4.2",
	}
}

// saveDefectThenPassReports stores two check-based reports for the same
// artifact: the baseline records 发现缺陷 with the counterexample note, the
// new report records 通过. Both are saved to and read back from the store,
// so the comparison exercises the normal archive load path.
func saveDefectThenPassReports(t *testing.T, dir string, beforeRule, afterRule Rule) (Report, Report) {
	t.Helper()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	before := saveCheckReport(t, dir, artifact, []Rule{beforeRule},
		[]CheckRecord{{ArtifactHash: hash, RuleID: beforeRule.ID, Version: beforeRule.Version,
			Status: StatusDefect, Note: defectEvidenceNote}})
	after := saveCheckReport(t, dir, artifact, []Rule{afterRule},
		[]CheckRecord{{ArtifactHash: hash, RuleID: afterRule.ID, Version: afterRule.Version,
			Status: StatusPass}})
	return before, after
}

// TestDiffDefectToPassWithChangedDefinitionIsRuleChange pins the regression
// guarantee: 发现缺陷 -> 通过 only counts as 已消除缺陷 when the full rule
// definition is identical. Changing any single definition field — version,
// kind, severity, invariant or the ABI requirement — must instead yield
// 规则变化, even when the version string itself is unchanged.
func TestDiffDefectToPassWithChangedDefinitionIsRuleChange(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(before, after *Rule)
	}{
		{"version changed", func(before, after *Rule) {
			after.Version = "1.4.3"
		}},
		{"kind changed, version unchanged", func(before, after *Rule) {
			after.Kind = "symbolic"
		}},
		{"severity changed, version unchanged", func(before, after *Rule) {
			after.Severity = "critical"
		}},
		{"invariant changed, version unchanged", func(before, after *Rule) {
			after.Invariant = "no-reentrant-call"
		}},
		{"requiresABI changed, version unchanged", func(before, after *Rule) {
			after.RequiresABI = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			beforeRule := defectBaselineRule()
			afterRule := defectBaselineRule()
			tc.mutate(&beforeRule, &afterRule)

			before, after := saveDefectThenPassReports(t, dir, beforeRule, afterRule)
			// The defect totals count actual findings in each archive; they
			// are not a resolved-defect count.
			if len(before.Findings) != 1 || len(after.Findings) != 0 {
				t.Fatalf("findings = %d/%d, want 1/0", len(before.Findings), len(after.Findings))
			}

			diff, err := DiffStore(dir, before.ReportID, after.ReportID)
			if err != nil {
				t.Fatal(err)
			}
			if len(diff.Results) != 1 {
				t.Fatalf("results = %d, want 1", len(diff.Results))
			}
			entry := diff.Results[0]
			if entry.RuleID != beforeRule.ID {
				t.Errorf("ruleId = %q, want %q", entry.RuleID, beforeRule.ID)
			}
			if entry.Change != ChangeRuleChanged {
				t.Errorf("change = %q, want %q", entry.Change, ChangeRuleChanged)
			}

			s := diff.Summary
			if s.ChangedRules != 1 {
				t.Errorf("changedRules = %d, want 1", s.ChangedRules)
			}
			if s.ResolvedDefects != 0 || s.NewDefects != 0 || s.StatusChanges != 0 {
				t.Errorf("defect/status transitions must be zero: %+v", s)
			}
			if s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 || s.RemovedRules != 0 {
				t.Errorf("other categories must be zero: %+v", s)
			}
			if s.BeforeDefects != 1 || s.AfterDefects != 0 {
				t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
			}

			if entry.Before == nil || entry.After == nil {
				t.Fatal("both sides must be present")
			}
			// The baseline side keeps its complete original definition,
			// status and note.
			wantBeforeRule := ReportRule{
				ID:          beforeRule.ID,
				Kind:        beforeRule.Kind,
				Severity:    beforeRule.Severity,
				Invariant:   beforeRule.Invariant,
				RequiresABI: beforeRule.RequiresABI,
				Version:     beforeRule.Version,
				Status:      StatusDefect,
				Note:        defectEvidenceNote,
			}
			if entry.Before.Rule != wantBeforeRule {
				t.Errorf("before rule = %+v, want %+v", entry.Before.Rule, wantBeforeRule)
			}
			// The baseline finding keeps the original artifact hash, rule id,
			// version and verbatim evidence — a definition change on the new
			// side must not rewrite the old evidence or re-version it.
			if entry.Before.Finding == nil {
				t.Fatal("defect side must carry its finding")
			}
			wantFinding := ReportFinding{
				ArtifactHash: ArtifactHash(sampleArtifact()),
				RuleID:       beforeRule.ID,
				Version:      beforeRule.Version,
				Severity:     beforeRule.Severity,
				Invariant:    beforeRule.Invariant,
				Evidence:     defectEvidenceNote,
			}
			if *entry.Before.Finding != wantFinding {
				t.Errorf("before finding = %+v, want %+v", *entry.Before.Finding, wantFinding)
			}
			// The new side records 通过 with its own (changed) definition and
			// carries no finding.
			wantAfterRule := ReportRule{
				ID:          afterRule.ID,
				Kind:        afterRule.Kind,
				Severity:    afterRule.Severity,
				Invariant:   afterRule.Invariant,
				RequiresABI: afterRule.RequiresABI,
				Version:     afterRule.Version,
				Status:      StatusPass,
			}
			if entry.After.Rule != wantAfterRule {
				t.Errorf("after rule = %+v, want %+v", entry.After.Rule, wantAfterRule)
			}
			if entry.After.Finding != nil {
				t.Errorf("passing side must not carry a finding: %+v", entry.After.Finding)
			}
		})
	}
}

// TestDiffDefectToPassSameDefinitionIsResolved is the control case: with a
// fully identical rule definition, the same 发现缺陷 -> 通过 transition is
// classified as 已消除缺陷.
func TestDiffDefectToPassSameDefinitionIsResolved(t *testing.T) {
	dir := t.TempDir()
	rule := defectBaselineRule()
	before, after := saveDefectThenPassReports(t, dir, rule, rule)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(diff.Results))
	}
	entry := diff.Results[0]
	if entry.Change != ChangeResolvedDefect {
		t.Errorf("change = %q, want %q", entry.Change, ChangeResolvedDefect)
	}
	s := diff.Summary
	if s.ResolvedDefects != 1 || s.ChangedRules != 0 {
		t.Errorf("summary = %+v, want resolvedDefects 1 and changedRules 0", s)
	}
	if s.NewDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("summary = %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}
	if entry.Before == nil || entry.Before.Finding == nil {
		t.Fatal("baseline defect side must carry its finding")
	}
	if entry.Before.Finding.Evidence != defectEvidenceNote {
		t.Errorf("evidence = %q, want the verbatim counterexample", entry.Before.Finding.Evidence)
	}
	if entry.Before.Finding.Version != rule.Version {
		t.Errorf("finding version = %q, want %q", entry.Before.Finding.Version, rule.Version)
	}
	if entry.After == nil || entry.After.Rule.Status != StatusPass || entry.After.Finding != nil {
		t.Errorf("after side = %+v", entry.After)
	}
}
