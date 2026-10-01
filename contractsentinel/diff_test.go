package contractsentinel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// saveDiffReport builds, saves and returns a report for diff tests.
func saveDiffReport(t *testing.T, dir string, artifact Artifact, rules []Rule, invariants map[string]bool) Report {
	t.Helper()
	report, err := BuildReport(artifact, rules, invariants)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	return report
}

// storeFileNames lists the files currently in the store directory.
func storeFileNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestDiffAllCategories(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	beforeRules := []Rule{
		{ID: "added-later", Kind: "static", Severity: "low", Invariant: "inv-added", Version: "1"},
		{ID: "changed-def", Kind: "static", Severity: "high", Invariant: "inv-changed", Version: "1"},
		{ID: "new-defect", Kind: "static", Severity: "high", Invariant: "inv-new", Version: "1"},
		{ID: "removed-later", Kind: "static", Severity: "low", Invariant: "inv-removed", Version: "1"},
		{ID: "resolved", Kind: "static", Severity: "medium", Invariant: "inv-resolved", Version: "1"},
		{ID: "status-shift", Kind: "static", Severity: "low", Invariant: "inv-shift", Version: "1"},
		{ID: "stable", Kind: "static", Severity: "medium", Invariant: "inv-stable", Version: "1"},
	}
	beforeInv := map[string]bool{
		"inv-added": true, "inv-changed": true, "inv-new": true,
		"inv-removed": true, "inv-resolved": false, "inv-stable": true,
		// inv-shift absent => 未检查
	}
	before := saveDiffReport(t, dir, artifact, beforeRules, beforeInv)

	afterRules := []Rule{
		{ID: "added-later", Kind: "static", Severity: "low", Invariant: "inv-added", Version: "1"},
		{ID: "changed-def", Kind: "static", Severity: "critical", Invariant: "inv-changed", Version: "1"},
		{ID: "new-defect", Kind: "static", Severity: "high", Invariant: "inv-new", Version: "1"},
		{ID: "resolved", Kind: "static", Severity: "medium", Invariant: "inv-resolved", Version: "1"},
		{ID: "status-shift", Kind: "static", Severity: "low", Invariant: "inv-shift", Version: "1"},
		{ID: "stable", Kind: "static", Severity: "medium", Invariant: "inv-stable", Version: "1"},
		{ID: "brand-new", Kind: "static", Severity: "low", Invariant: "inv-brand", Version: "1"},
	}
	afterInv := map[string]bool{
		"inv-added": true, "inv-changed": true, "inv-new": false,
		"inv-resolved": true, "inv-shift": true, "inv-stable": true,
		"inv-brand": true,
	}
	after := saveDiffReport(t, dir, artifact, afterRules, afterInv)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Before.ReportID != before.ReportID || diff.After.ReportID != after.ReportID {
		t.Errorf("report refs = %+v / %+v", diff.Before, diff.After)
	}
	if diff.ArtifactNameChanged || diff.ArtifactHashChanged {
		t.Error("same artifact must not be flagged as changed")
	}

	changes := map[string]string{}
	for _, r := range diff.Results {
		changes[r.RuleID] = r.Change
	}
	want := map[string]string{
		"added-later":   ChangeNoChange,
		"brand-new":     ChangeRuleAdded,
		"changed-def":   ChangeRuleChanged,
		"new-defect":    ChangeNewDefect,
		"removed-later": ChangeRuleRemoved,
		"resolved":      ChangeResolvedDefect,
		"status-shift":  ChangeStatusChanged,
		"stable":        ChangeNoChange,
	}
	if len(diff.Results) != len(want) {
		t.Fatalf("results = %d, want %d", len(diff.Results), len(want))
	}
	for id, w := range want {
		if changes[id] != w {
			t.Errorf("rule %s change = %q, want %q", id, changes[id], w)
		}
	}
	// Results sorted by rule id.
	for i := 1; i < len(diff.Results); i++ {
		if diff.Results[i-1].RuleID >= diff.Results[i].RuleID {
			t.Fatalf("results not sorted: %q then %q", diff.Results[i-1].RuleID, diff.Results[i].RuleID)
		}
	}
	// Summary counts, including zeros.
	s := diff.Summary
	if s.NewDefects != 1 || s.ResolvedDefects != 1 || s.StatusChanges != 1 ||
		s.NoChange != 2 || s.AddedRules != 1 || s.RemovedRules != 1 || s.ChangedRules != 1 {
		t.Errorf("summary = %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}
}

func TestDiffResultSidesAndEvidence(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	before := saveDiffReport(t, dir, artifact,
		[]Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1.0.0"}},
		map[string]bool{"inv": false})
	after := saveDiffReport(t, dir, artifact,
		[]Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1.0.0"}},
		map[string]bool{"inv": true})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(diff.Results))
	}
	entry := diff.Results[0]
	if entry.Change != ChangeResolvedDefect {
		t.Fatalf("change = %q, want %q", entry.Change, ChangeResolvedDefect)
	}
	if entry.Before == nil || entry.After == nil {
		t.Fatal("both sides must be present")
	}
	if entry.Before.Rule.Status != StatusDefect || entry.After.Rule.Status != StatusPass {
		t.Errorf("statuses = %q/%q", entry.Before.Rule.Status, entry.After.Rule.Status)
	}
	if entry.Before.Finding == nil {
		t.Fatal("defect side must carry evidence")
	}
	if entry.Before.Finding.ArtifactHash != ArtifactHash(artifact) {
		t.Errorf("evidence artifact hash = %q", entry.Before.Finding.ArtifactHash)
	}
	if entry.Before.Finding.Version != "1.0.0" {
		t.Errorf("evidence version = %q", entry.Before.Finding.Version)
	}
	if entry.After.Finding != nil {
		t.Errorf("passing side must not carry evidence: %+v", entry.After.Finding)
	}
}

func TestDiffAbsentSideIsNull(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	before := saveDiffReport(t, dir, artifact, nil, nil)
	after := saveDiffReport(t, dir, artifact,
		[]Rule{{ID: "r1", Kind: "static", Severity: "low", Invariant: "inv", Version: "1"}},
		map[string]bool{"inv": false})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeRuleAdded {
		t.Fatalf("results = %+v", diff.Results)
	}
	if diff.Results[0].Before != nil {
		t.Error("absent before side must be null")
	}
	if diff.Results[0].After == nil || diff.Results[0].After.Finding == nil {
		t.Error("added defect rule must carry its evidence")
	}
}

func TestDiffAllowsDifferentArtifactHashes(t *testing.T) {
	dir := t.TempDir()
	a1 := sampleArtifact()
	a2 := sampleArtifact()
	a2.Source = "VaultV2.sol"
	rules := sampleRules()
	before := saveDiffReport(t, dir, a1, rules, sampleInvariants())
	after := saveDiffReport(t, dir, a2, rules, sampleInvariants())

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.ArtifactHashChanged {
		t.Error("hash change must be reported")
	}
	if diff.ArtifactNameChanged {
		t.Error("name did not change")
	}
	if diff.Before.Artifact.Hash != ArtifactHash(a1) || diff.After.Artifact.Hash != ArtifactHash(a2) {
		t.Errorf("artifact refs = %+v / %+v", diff.Before.Artifact, diff.After.Artifact)
	}
	for _, r := range diff.Results {
		if r.Change != ChangeNoChange {
			t.Errorf("rule %s change = %q, want %q", r.RuleID, r.Change, ChangeNoChange)
		}
	}
}

func TestDiffRenameDoesNotFabricateChanges(t *testing.T) {
	dir := t.TempDir()
	a1 := sampleArtifact()
	a2 := sampleArtifact()
	a2.Name = "VaultRenamed"
	rules := sampleRules()
	before := saveDiffReport(t, dir, a1, rules, sampleInvariants())
	after := saveDiffReport(t, dir, a2, rules, sampleInvariants())

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.ArtifactNameChanged || diff.ArtifactHashChanged {
		t.Errorf("rename flags = name:%v hash:%v", diff.ArtifactNameChanged, diff.ArtifactHashChanged)
	}
	if diff.Summary.NewDefects != 0 || diff.Summary.ResolvedDefects != 0 ||
		diff.Summary.ChangedRules != 0 || diff.Summary.AddedRules != 0 || diff.Summary.RemovedRules != 0 {
		t.Errorf("rename fabricated changes: %+v", diff.Summary)
	}
	if diff.Summary.NoChange != len(rules) {
		t.Errorf("no-change = %d, want %d", diff.Summary.NoChange, len(rules))
	}
}

func TestDiffRuleChangeIgnoresVersionString(t *testing.T) {
	// A definition change with an unchanged version string is still 规则变化.
	dir := t.TempDir()
	artifact := sampleArtifact()
	before := saveDiffReport(t, dir, artifact,
		[]Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}},
		map[string]bool{"inv": true})
	after := saveDiffReport(t, dir, artifact,
		[]Rule{{ID: "r1", Kind: "symbolic", Severity: "high", Invariant: "inv", Version: "1"}},
		map[string]bool{"inv": true})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeRuleChanged {
		t.Fatalf("results = %+v", diff.Results)
	}
	if diff.Summary.ChangedRules != 1 || diff.Summary.NoChange != 0 {
		t.Errorf("summary = %+v", diff.Summary)
	}
}

func TestDiffRuleChangedNotClassifiedAsDefectChange(t *testing.T) {
	// pass -> defect with a changed definition is 规则变化, not 新发现缺陷.
	dir := t.TempDir()
	artifact := sampleArtifact()
	before := saveDiffReport(t, dir, artifact,
		[]Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}},
		map[string]bool{"inv": true})
	after := saveDiffReport(t, dir, artifact,
		[]Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "2"}},
		map[string]bool{"inv": false})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Results[0].Change != ChangeRuleChanged {
		t.Fatalf("change = %q, want %q", diff.Results[0].Change, ChangeRuleChanged)
	}
	if diff.Summary.NewDefects != 0 || diff.Summary.ChangedRules != 1 {
		t.Errorf("summary = %+v", diff.Summary)
	}
}

func TestDiffSameReportBothSides(t *testing.T) {
	dir := t.TempDir()
	report := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	diff, err := DiffStore(dir, report.ReportID, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if diff.ArtifactNameChanged || diff.ArtifactHashChanged {
		t.Error("identical reports must not flag artifact changes")
	}
	if diff.Summary.NoChange != len(sampleRules()) {
		t.Errorf("no-change = %d, want %d", diff.Summary.NoChange, len(sampleRules()))
	}
	if diff.Summary.NewDefects != 0 || diff.Summary.ResolvedDefects != 0 || diff.Summary.StatusChanges != 0 {
		t.Errorf("summary = %+v", diff.Summary)
	}
	if diff.Summary.BeforeDefects != 2 || diff.Summary.AfterDefects != 2 {
		t.Errorf("defect totals = %d/%d, want 2/2", diff.Summary.BeforeDefects, diff.Summary.AfterDefects)
	}
}

func TestDiffBothSidesEmpty(t *testing.T) {
	dir := t.TempDir()
	before := saveDiffReport(t, dir, sampleArtifact(), nil, nil)
	after := saveDiffReport(t, dir, sampleArtifact(), nil, nil)
	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 0 {
		t.Fatalf("results = %+v, want empty", diff.Results)
	}
	if diff.Summary != (DiffSummary{}) {
		t.Errorf("summary = %+v, want all zero", diff.Summary)
	}
	// Empty results must render as [], not null.
	out, err := json.Marshal(diff)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"results":[]`) {
		t.Errorf("empty results must serialize as []: %s", out)
	}
}

func TestDiffDeterministicByteIdentical(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rules := sampleRules()
	before := saveDiffReport(t, dir, artifact, rules, sampleInvariants())
	// Same logical report, different rule storage order.
	reversed := []Rule{rules[2], rules[1], rules[0]}
	after := saveDiffReport(t, dir, artifact, reversed, sampleInvariants())
	if before.ReportID != after.ReportID {
		t.Fatal("rule order must not change the report id")
	}

	first, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.MarshalIndent(first, "", "  ")
	b2, _ := json.MarshalIndent(second, "", "  ")
	if string(b1) != string(b2) {
		t.Fatal("repeated diffs must be byte-identical")
	}
	if strings.Contains(string(b1), "time") || strings.Contains(string(b1), "date") {
		t.Error("diff output must not contain timestamps")
	}
}

func TestDiffStorageOrderIndependent(t *testing.T) {
	// Two reports with identical rule sets stored in different order must
	// produce the same per-rule results.
	dir := t.TempDir()
	artifact := sampleArtifact()
	rules := sampleRules()
	before := saveDiffReport(t, dir, artifact, rules, sampleInvariants())
	after := saveDiffReport(t, dir, artifact, []Rule{rules[1], rules[2], rules[0]}, sampleInvariants())
	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, r := range diff.Results {
		ids = append(ids, r.RuleID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}
}

func TestDiffInvalidReportID(t *testing.T) {
	dir := t.TempDir()
	report := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	for _, bad := range []string{"", "abc", strings.ToUpper(report.ReportID), report.ReportID + "0", "zz" + report.ReportID[2:]} {
		if _, err := DiffStore(dir, bad, report.ReportID); err == nil {
			t.Errorf("expected error for before id %q", bad)
		}
		if _, err := DiffStore(dir, report.ReportID, bad); err == nil {
			t.Errorf("expected error for after id %q", bad)
		}
	}
}

func TestDiffMissingReport(t *testing.T) {
	dir := t.TempDir()
	report := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	missing := strings.Repeat("0", 64)
	_, err := DiffStore(dir, missing, report.ReportID)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error must name the missing id: %v", err)
	}
}

func TestDiffMissingStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	id := strings.Repeat("a", 64)
	if _, err := DiffStore(dir, id, id); err == nil {
		t.Fatal("expected error for missing store")
	}
	// The failed diff must not create the store directory.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("diff created the store directory: %v", err)
	}
}

// saveRawReport writes a hand-built report with a self-consistent id directly
// into the store, bypassing BuildReport's input validation.
func saveRawReport(t *testing.T, dir string, r Report) Report {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, r.ReportID+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDiffRejectsDuplicateRuleIDs(t *testing.T) {
	dir := t.TempDir()
	good := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	bad := saveRawReport(t, dir, Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: ArtifactHash(sampleArtifact())},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusPass},
			{ID: "r1", Kind: "static", Severity: "low", Invariant: "inv", Version: "1", Status: StatusPass},
		},
		Findings: []ReportFinding{},
	})
	if _, err := DiffStore(dir, good.ReportID, bad.ReportID); err == nil {
		t.Fatal("expected error for duplicate rule ids")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error must mention the duplicate: %v", err)
	}
}

func TestDiffRejectsEmptyRuleID(t *testing.T) {
	dir := t.TempDir()
	good := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	bad := saveRawReport(t, dir, Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: ArtifactHash(sampleArtifact())},
		Rules: []ReportRule{
			{ID: "", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusPass},
		},
		Findings: []ReportFinding{},
	})
	if _, err := DiffStore(dir, good.ReportID, bad.ReportID); err == nil {
		t.Fatal("expected error for empty rule id")
	}
}

func TestDiffRejectsEmptyRuleVersion(t *testing.T) {
	dir := t.TempDir()
	good := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	bad := saveRawReport(t, dir, Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: ArtifactHash(sampleArtifact())},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "", Status: StatusPass},
		},
		Findings: []ReportFinding{},
	})
	if _, err := DiffStore(dir, good.ReportID, bad.ReportID); err == nil {
		t.Fatal("expected error for empty rule version")
	}
}

func TestDiffRejectsUnknownStatus(t *testing.T) {
	dir := t.TempDir()
	good := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	bad := saveRawReport(t, dir, Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: ArtifactHash(sampleArtifact())},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: "跳过"},
		},
		Findings: []ReportFinding{},
	})
	if _, err := DiffStore(dir, good.ReportID, bad.ReportID); err == nil {
		t.Fatal("expected error for unknown status")
	} else if !strings.Contains(err.Error(), "unknown status") {
		t.Fatalf("error must mention the unknown status: %v", err)
	}
}

func TestDiffRejectsCorruptedArchive(t *testing.T) {
	dir := t.TempDir()
	good := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	bad := saveDiffReport(t, dir, sampleArtifact(), nil, nil)
	path := filepath.Join(dir, bad.ReportID+".json")
	if err := os.WriteFile(path, []byte(`{broken`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DiffStore(dir, good.ReportID, bad.ReportID); err == nil {
		t.Fatal("expected error for corrupted archive")
	}
}

func TestDiffDoesNotModifyStore(t *testing.T) {
	dir := t.TempDir()
	before := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	after := saveDiffReport(t, dir, sampleArtifact(), nil, nil)
	filesBefore := storeFileNames(t, dir)
	contentsBefore := map[string]string{}
	for _, name := range filesBefore {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		contentsBefore[name] = string(data)
	}
	if _, err := DiffStore(dir, before.ReportID, after.ReportID); err != nil {
		t.Fatal(err)
	}
	filesAfter := storeFileNames(t, dir)
	if strings.Join(filesBefore, ",") != strings.Join(filesAfter, ",") {
		t.Fatalf("store files changed: %v -> %v", filesBefore, filesAfter)
	}
	for _, name := range filesAfter {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != contentsBefore[name] {
			t.Errorf("diff modified %s", name)
		}
	}
}
