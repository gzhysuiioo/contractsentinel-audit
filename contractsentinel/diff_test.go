package contractsentinel

import (
	"encoding/json"
	"strings"
	"testing"
)

func testArtifact(name, hash string) ReportArtifact {
	return ReportArtifact{Name: name, Hash: hash}
}

func testRule(id, kind, severity, invariant string, requiresABI bool, version, status string) ReportRule {
	return ReportRule{
		ID:          id,
		Kind:        kind,
		Severity:    severity,
		Invariant:   invariant,
		RequiresABI: requiresABI,
		Version:     version,
		Status:      status,
	}
}

// buildTestReport builds a report and auto-generates the findings that match
// its defect rules.
func buildTestReport(id string, artifact ReportArtifact, rules []ReportRule) Report {
	findings := []ReportFinding{}
	for _, rule := range rules {
		if rule.Status == StatusDefect {
			findings = append(findings, ReportFinding{
				ArtifactHash: artifact.Hash,
				RuleID:       rule.ID,
				Version:      rule.Version,
				Severity:     rule.Severity,
				Invariant:    rule.Invariant,
				Evidence:     "invariant " + rule.Invariant + " does not hold",
			})
		}
	}
	return Report{
		ReportID: id,
		Artifact: artifact,
		Rules:    rules,
		Findings: findings,
	}
}

const (
	testHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testID1   = "1111111111111111111111111111111111111111111111111111111111111111"
	testID2   = "2222222222222222222222222222222222222222222222222222222222222222"
)

// --- ValidReportID ---

func TestValidReportID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{testID1, true},
		{strings.Repeat("A", 64), false},
		{"", false},
		{"abc", false},
		{testID1[:63], false},
		{testID1 + "0", false},
		{strings.Repeat("g", 64), false},
		{strings.Repeat("0", 64), true},
	}
	for _, c := range cases {
		if got := ValidReportID(c.id); got != c.want {
			t.Errorf("ValidReportID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

// --- basic diff ---

func TestDiffReportsSameReport(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	rules := []ReportRule{
		testRule("r1", "static", "high", "inv1", false, "1.0.0", StatusDefect),
		testRule("r2", "static", "medium", "inv2", true, "2.0.0", StatusPass),
	}
	report := buildTestReport(testID1, artifact, rules)
	diff, err := DiffReports(report, report)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(diff.Rules))
	}
	for _, r := range diff.Rules {
		if r.Change != ChangeUnchanged {
			t.Errorf("rule %s change = %q, want %q", r.RuleID, r.Change, ChangeUnchanged)
		}
	}
	if diff.Summary.NewFindings != 0 || diff.Summary.ResolvedFindings != 0 ||
		diff.Summary.StatusChanges != 0 || diff.Summary.AddedRules != 0 ||
		diff.Summary.RemovedRules != 0 || diff.Summary.ChangedRules != 0 {
		t.Errorf("summary = %+v, want all defect/rule changes zero", diff.Summary)
	}
	if diff.Summary.BeforeDefectCount != 1 || diff.Summary.AfterDefectCount != 1 {
		t.Errorf("defect counts = %d/%d, want 1/1", diff.Summary.BeforeDefectCount, diff.Summary.AfterDefectCount)
	}
}

func TestDiffReportsEmpty(t *testing.T) {
	before := buildTestReport(testID1, testArtifact("A", testHashA), nil)
	after := buildTestReport(testID2, testArtifact("A", testHashA), nil)
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Rules) != 0 {
		t.Fatalf("rules = %d, want 0", len(diff.Rules))
	}
	if diff.Summary.BeforeDefectCount != 0 || diff.Summary.AfterDefectCount != 0 {
		t.Errorf("defect counts = %d/%d, want 0/0", diff.Summary.BeforeDefectCount, diff.Summary.AfterDefectCount)
	}
}

// --- status transitions ---

func TestDiffReportsNewFinding(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusDefect),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Rules) != 1 || diff.Rules[0].Change != ChangeNewFinding {
		t.Fatalf("change = %v, want %q", diff.Rules, ChangeNewFinding)
	}
	if diff.Summary.NewFindings != 1 {
		t.Errorf("newFindings = %d, want 1", diff.Summary.NewFindings)
	}
	if diff.Summary.BeforeDefectCount != 0 || diff.Summary.AfterDefectCount != 1 {
		t.Errorf("defect counts = %d/%d, want 0/1", diff.Summary.BeforeDefectCount, diff.Summary.AfterDefectCount)
	}
}

func TestDiffReportsResolved(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusDefect),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Rules) != 1 || diff.Rules[0].Change != ChangeResolved {
		t.Fatalf("change = %v, want %q", diff.Rules, ChangeResolved)
	}
	if diff.Summary.ResolvedFindings != 1 {
		t.Errorf("resolvedFindings = %d, want 1", diff.Summary.ResolvedFindings)
	}
}

func TestDiffReportsStatusChange(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	for _, tc := range []struct {
		from, to string
	}{
		{StatusUnchecked, StatusPass},
		{StatusPass, StatusUnchecked},
		{StatusUnchecked, StatusDefect},
		{StatusDefect, StatusUnchecked},
	} {
		before := buildTestReport(testID1, artifact, []ReportRule{
			testRule("r1", "static", "high", "inv", false, "1.0.0", tc.from),
		})
		after := buildTestReport(testID2, artifact, []ReportRule{
			testRule("r1", "static", "high", "inv", false, "1.0.0", tc.to),
		})
		diff, err := DiffReports(before, after)
		if err != nil {
			t.Fatal(err)
		}
		if len(diff.Rules) != 1 || diff.Rules[0].Change != ChangeStatusChange {
			t.Errorf("%s -> %s: change = %v, want %q", tc.from, tc.to, diff.Rules, ChangeStatusChange)
		}
	}
}

// --- rule set changes ---

func TestDiffReportsAddedRule(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, nil)
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(diff.Rules))
	}
	r := diff.Rules[0]
	if r.Change != ChangeAddedRule {
		t.Errorf("change = %q, want %q", r.Change, ChangeAddedRule)
	}
	if r.Before != nil {
		t.Errorf("before side = %v, want nil", r.Before)
	}
	if r.After == nil || r.After.Rule.ID != "r1" {
		t.Errorf("after side = %v, want rule r1", r.After)
	}
	if diff.Summary.AddedRules != 1 {
		t.Errorf("addedRules = %d, want 1", diff.Summary.AddedRules)
	}
}

func TestDiffReportsRemovedRule(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, nil)
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(diff.Rules))
	}
	r := diff.Rules[0]
	if r.Change != ChangeRemovedRule {
		t.Errorf("change = %q, want %q", r.Change, ChangeRemovedRule)
	}
	if r.Before == nil || r.Before.Rule.ID != "r1" {
		t.Errorf("before side = %v, want rule r1", r.Before)
	}
	if r.After != nil {
		t.Errorf("after side = %v, want nil", r.After)
	}
	if diff.Summary.RemovedRules != 1 {
		t.Errorf("removedRules = %d, want 1", diff.Summary.RemovedRules)
	}
}

func TestDiffReportsChangedRule(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r1", "static", "critical", "inv", false, "1.0.0", StatusPass),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Rules) != 1 || diff.Rules[0].Change != ChangeChangedRule {
		t.Fatalf("change = %v, want %q", diff.Rules, ChangeChangedRule)
	}
	if diff.Summary.ChangedRules != 1 {
		t.Errorf("changedRules = %d, want 1", diff.Summary.ChangedRules)
	}
}

func TestDiffReportsChangedRuleVersionOnly(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.1", StatusPass),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Rules) != 1 || diff.Rules[0].Change != ChangeChangedRule {
		t.Fatalf("change = %v, want %q (version change must be detected even when status is unchanged)", diff.Rules, ChangeChangedRule)
	}
}

func TestDiffReportsChangedRuleKindSeverityInvariantABI(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	base := testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass)
	for _, mutate := range []func(*ReportRule){
		func(r *ReportRule) { r.Kind = "symbolic" },
		func(r *ReportRule) { r.Severity = "critical" },
		func(r *ReportRule) { r.Invariant = "other" },
		func(r *ReportRule) { r.RequiresABI = true },
	} {
		before := buildTestReport(testID1, artifact, []ReportRule{base})
		afterRule := base
		mutate(&afterRule)
		after := buildTestReport(testID2, artifact, []ReportRule{afterRule})
		diff, err := DiffReports(before, after)
		if err != nil {
			t.Fatal(err)
		}
		if len(diff.Rules) != 1 || diff.Rules[0].Change != ChangeChangedRule {
			t.Errorf("mutated %+v: change = %v, want %q", afterRule, diff.Rules, ChangeChangedRule)
		}
	}
}

// --- artifact changes ---

func TestDiffReportsRenameOnly(t *testing.T) {
	artifactA := testArtifact("Vault", testHashA)
	artifactB := testArtifact("Other", testHashA)
	rules := []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	}
	before := buildTestReport(testID1, artifactA, rules)
	after := buildTestReport(testID2, artifactB, rules)
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.ArtifactDiff.NameChanged {
		t.Error("nameChanged = false, want true")
	}
	if diff.ArtifactDiff.HashChanged {
		t.Error("hashChanged = true, want false")
	}
	for _, r := range diff.Rules {
		if r.Change != ChangeUnchanged {
			t.Errorf("rename produced rule change %q for %s", r.Change, r.RuleID)
		}
	}
}

func TestDiffReportsHashChange(t *testing.T) {
	artifactA := testArtifact("Vault", testHashA)
	artifactB := testArtifact("Vault", testHashB)
	rules := []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	}
	before := buildTestReport(testID1, artifactA, rules)
	after := buildTestReport(testID2, artifactB, rules)
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if diff.ArtifactDiff.NameChanged {
		t.Error("nameChanged = true, want false")
	}
	if !diff.ArtifactDiff.HashChanged {
		t.Error("hashChanged = false, want true")
	}
}

func TestDiffReportsDifferentArtifactHashAllowed(t *testing.T) {
	// Comparing reports with different artifact hashes must succeed; the
	// hash difference is reported, not rejected.
	artifactA := testArtifact("Vault", testHashA)
	artifactB := testArtifact("Vault", testHashB)
	before := buildTestReport(testID1, artifactA, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusDefect),
	})
	after := buildTestReport(testID2, artifactB, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusDefect),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatalf("different artifact hash must be allowed: %v", err)
	}
	if diff.ArtifactDiff.HashChanged != true {
		t.Error("hashChanged = false, want true")
	}
}

// --- ordering and determinism ---

func TestDiffReportsSortedByRuleID(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("zebra", "static", "high", "inv", false, "1.0.0", StatusPass),
		testRule("alpha", "static", "high", "inv", false, "1.0.0", StatusPass),
		testRule("mid", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("mid", "static", "high", "inv", false, "1.0.0", StatusPass),
		testRule("alpha", "static", "high", "inv", false, "1.0.0", StatusPass),
		testRule("zebra", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "mid", "zebra"}
	for i, r := range diff.Rules {
		if r.RuleID != want[i] {
			t.Errorf("rules[%d] = %q, want %q", i, r.RuleID, want[i])
		}
	}
}

func TestDiffReportsDeterministic(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv1", false, "1.0.0", StatusDefect),
		testRule("r2", "static", "medium", "inv2", true, "2.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r2", "static", "medium", "inv2", true, "2.0.1", StatusDefect),
		testRule("r3", "static", "low", "inv3", false, "0.9.0", StatusUnchecked),
	})
	first, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := json.MarshalIndent(first, "", "  ")
	secondBytes, _ := json.MarshalIndent(second, "", "  ")
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("repeated diff produced different JSON")
	}
}

func TestDiffReportsStorageOrderIndependent(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	rules := []ReportRule{
		testRule("r1", "static", "high", "inv1", false, "1.0.0", StatusDefect),
		testRule("r2", "static", "medium", "inv2", true, "2.0.0", StatusPass),
	}
	before := buildTestReport(testID1, artifact, rules)
	after := buildTestReport(testID2, artifact, rules)
	// Shuffle the stored order; the diff must be identical.
	shuffled := buildTestReport(testID2, artifact, []ReportRule{rules[1], rules[0]})
	first, _ := DiffReports(before, after)
	second, _ := DiffReports(before, shuffled)
	firstBytes, _ := json.MarshalIndent(first, "", "  ")
	secondBytes, _ := json.MarshalIndent(second, "", "  ")
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("rule storage order leaked into the diff")
	}
}

// --- finding evidence ---

func TestDiffReportsFindingCarriesHashAndVersion(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusDefect),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusDefect),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	r := diff.Rules[0]
	if r.Before.Finding == nil {
		t.Fatal("before finding is nil")
	}
	if r.Before.Finding.ArtifactHash != testHashA {
		t.Errorf("before finding artifact hash = %q, want %q", r.Before.Finding.ArtifactHash, testHashA)
	}
	if r.Before.Finding.Version != "1.0.0" {
		t.Errorf("before finding version = %q, want 1.0.0", r.Before.Finding.Version)
	}
	if r.After.Finding == nil {
		t.Fatal("after finding is nil")
	}
	if r.After.Finding.ArtifactHash != testHashA {
		t.Errorf("after finding artifact hash = %q, want %q", r.After.Finding.ArtifactHash, testHashA)
	}
}

func TestDiffReportsFindingNullWhenNoDefect(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	r := diff.Rules[0]
	if r.Before.Finding != nil || r.After.Finding != nil {
		t.Errorf("passing rule produced findings: before=%v after=%v", r.Before.Finding, r.After.Finding)
	}
}

// --- validation rejection ---

func TestDiffReportsRejectsEmptyRuleID(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, nil)
	if _, err := DiffReports(before, after); err == nil {
		t.Fatal("expected error for empty rule id")
	}
}

func TestDiffReportsRejectsDuplicateRuleID(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
		testRule("r1", "static", "low", "inv2", false, "1.0.0", StatusPass),
	})
	if _, err := DiffReports(before, after); err == nil {
		t.Fatal("expected error for duplicate rule id")
	}
}

func TestDiffReportsRejectsEmptyVersion(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "", StatusPass),
	})
	after := buildTestReport(testID2, artifact, nil)
	if _, err := DiffReports(before, after); err == nil {
		t.Fatal("expected error for empty version")
	}
}

func TestDiffReportsRejectsUnknownStatus(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", "未知状态"),
	})
	after := buildTestReport(testID2, artifact, nil)
	if _, err := DiffReports(before, after); err == nil {
		t.Fatal("expected error for unknown status")
	}
}

func TestDiffReportsRejectsFindingVersionMismatch(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusDefect),
	})
	// Tamper with the finding version without changing the rule.
	before.Findings[0].Version = "9.9.9"
	after := buildTestReport(testID2, artifact, nil)
	if _, err := DiffReports(before, after); err == nil {
		t.Fatal("expected error for finding version mismatch")
	}
}

func TestDiffReportsRejectsFindingArtifactHashMismatch(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusDefect),
	})
	before.Findings[0].ArtifactHash = testHashB
	after := buildTestReport(testID2, artifact, nil)
	if _, err := DiffReports(before, after); err == nil {
		t.Fatal("expected error for finding artifact hash mismatch")
	}
}

// --- summary counts ---

func TestDiffReportsSummaryCounts(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("new-finding", "static", "high", "inv1", false, "1.0.0", StatusPass),
		testRule("resolved", "static", "high", "inv2", false, "1.0.0", StatusDefect),
		testRule("status-change", "static", "high", "inv3", false, "1.0.0", StatusUnchecked),
		testRule("unchanged", "static", "high", "inv4", false, "1.0.0", StatusPass),
		testRule("changed", "static", "high", "inv5", false, "1.0.0", StatusPass),
		testRule("removed", "static", "high", "inv6", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("new-finding", "static", "high", "inv1", false, "1.0.0", StatusDefect),
		testRule("resolved", "static", "high", "inv2", false, "1.0.0", StatusPass),
		testRule("status-change", "static", "high", "inv3", false, "1.0.0", StatusPass),
		testRule("unchanged", "static", "high", "inv4", false, "1.0.0", StatusPass),
		testRule("changed", "static", "critical", "inv5", false, "1.0.0", StatusPass),
		testRule("added", "static", "high", "inv7", false, "1.0.0", StatusPass),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	s := diff.Summary
	if s.NewFindings != 1 {
		t.Errorf("newFindings = %d, want 1", s.NewFindings)
	}
	if s.ResolvedFindings != 1 {
		t.Errorf("resolvedFindings = %d, want 1", s.ResolvedFindings)
	}
	if s.StatusChanges != 1 {
		t.Errorf("statusChanges = %d, want 1", s.StatusChanges)
	}
	if s.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", s.Unchanged)
	}
	if s.AddedRules != 1 {
		t.Errorf("addedRules = %d, want 1", s.AddedRules)
	}
	if s.RemovedRules != 1 {
		t.Errorf("removedRules = %d, want 1", s.RemovedRules)
	}
	if s.ChangedRules != 1 {
		t.Errorf("changedRules = %d, want 1", s.ChangedRules)
	}
	if s.BeforeDefectCount != 1 {
		t.Errorf("beforeDefectCount = %d, want 1", s.BeforeDefectCount)
	}
	if s.AfterDefectCount != 1 {
		t.Errorf("afterDefectCount = %d, want 1", s.AfterDefectCount)
	}
}

func TestDiffReportsSummaryZeroCountsPresent(t *testing.T) {
	artifact := testArtifact("Vault", testHashA)
	before := buildTestReport(testID1, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	after := buildTestReport(testID2, artifact, []ReportRule{
		testRule("r1", "static", "high", "inv", false, "1.0.0", StatusPass),
	})
	diff, err := DiffReports(before, after)
	if err != nil {
		t.Fatal(err)
	}
	s := diff.Summary
	// Every count must be present and zero.
	if s.NewFindings != 0 || s.ResolvedFindings != 0 || s.StatusChanges != 0 ||
		s.Unchanged != 1 || s.AddedRules != 0 || s.RemovedRules != 0 ||
		s.ChangedRules != 0 || s.BeforeDefectCount != 0 || s.AfterDefectCount != 0 {
		t.Errorf("summary = %+v, want all zero except unchanged=1", s)
	}
}
