package contractsentinel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// check builds a CheckRecord already bound to the sample artifact and a
// rule's current version.
func check(artifact Artifact, rule Rule, status, note string) CheckRecord {
	return CheckRecord{
		ArtifactHash: ArtifactHash(artifact),
		RuleID:       rule.ID,
		RuleVersion:  rule.Version,
		Status:       status,
		Note:         note,
	}
}

// saveCheckReport builds, saves and returns a report that imports checks.
func saveCheckReport(t *testing.T, dir string, artifact Artifact, rules []Rule, invariants map[string]bool, checks []CheckRecord) Report {
	t.Helper()
	report, err := BuildReportWithChecks(artifact, rules, invariants, checks)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	return report
}

func ruleStatuses(r Report) map[string]string {
	out := map[string]string{}
	for _, rr := range r.Rules {
		out[rr.ID] = rr.Status
	}
	return out
}

func ruleNotes(r Report) map[string]string {
	out := map[string]string{}
	for _, rr := range r.Rules {
		out[rr.ID] = rr.Note
	}
	return out
}

// --- Imported check statuses ---

func TestChecksAllStatuses(t *testing.T) {
	artifact := sampleArtifact()
	rules := []Rule{
		{ID: "p", Kind: "static", Severity: "low", Invariant: "inv-p", Version: "1"},
		{ID: "d", Kind: "static", Severity: "high", Invariant: "inv-d", Version: "1"},
		{ID: "m", Kind: "static", Severity: "medium", Invariant: "inv-m", RequiresABI: true, Version: "1"},
		{ID: "x", Kind: "symbolic", Severity: "critical", Invariant: "inv-x", Version: "1"},
	}
	checks := []CheckRecord{
		check(artifact, rules[0], StatusPass, ""),
		check(artifact, rules[1], StatusDefect, "counterexample: deposit(1) then withdraw(2)"),
		check(artifact, rules[2], StatusToolMissing, "static-analyzer binary not installed"),
		check(artifact, rules[3], StatusTimeout, "symbolic run exceeded 10m on withdraw"),
	}
	report, err := BuildReportWithChecks(artifact, rules, nil, checks)
	if err != nil {
		t.Fatal(err)
	}
	got := ruleStatuses(report)
	want := map[string]string{"p": StatusPass, "d": StatusDefect, "m": StatusToolMissing, "x": StatusTimeout}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("rule %s status = %q, want %q", id, got[id], w)
		}
	}
	// Only the defect produces a finding; tool missing and timeout never do.
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(report.Findings), report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "d" {
		t.Fatalf("finding rule = %q, want d", f.RuleID)
	}
	if f.Evidence != "counterexample: deposit(1) then withdraw(2)" {
		t.Errorf("defect must keep submitted evidence, got %q", f.Evidence)
	}
	if f.ArtifactHash != ArtifactHash(artifact) {
		t.Errorf("finding artifact hash = %q", f.ArtifactHash)
	}
	if f.Version != "1" {
		t.Errorf("finding version = %q, want 1", f.Version)
	}
	// Original notes are preserved on every rule.
	notes := ruleNotes(report)
	if notes["p"] != "" || notes["d"] == "" || notes["m"] == "" || notes["x"] == "" {
		t.Errorf("notes = %+v", notes)
	}
}

func TestChecksToolMissingDoesNotBlockOthers(t *testing.T) {
	// One rule's 工具缺失 must neither block other rules' normal results nor
	// count as a defect.
	artifact := sampleArtifact()
	rules := []Rule{
		{ID: "missing", Kind: "static", Severity: "high", Invariant: "inv-missing", Version: "1"},
		{ID: "passes", Kind: "static", Severity: "low", Invariant: "inv-pass", Version: "1"},
		{ID: "defective", Kind: "static", Severity: "high", Invariant: "inv-def", Version: "1"},
	}
	checks := []CheckRecord{
		check(artifact, rules[0], StatusToolMissing, "tool unavailable"),
		check(artifact, rules[2], StatusDefect, "reentrant call sequence"),
	}
	invariants := map[string]bool{"inv-pass": true}
	report, err := BuildReportWithChecks(artifact, rules, invariants, checks)
	if err != nil {
		t.Fatal(err)
	}
	got := ruleStatuses(report)
	if got["missing"] != StatusToolMissing || got["passes"] != StatusPass || got["defective"] != StatusDefect {
		t.Errorf("statuses = %+v", got)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "defective" {
		t.Fatalf("only the real defect counts, got %+v", report.Findings)
	}
}

func TestChecksSharedInvariantDifferentConclusions(t *testing.T) {
	// Two rules over the same invariant may disagree when both carry records.
	artifact := sampleArtifact()
	rules := []Rule{
		{ID: "a", Kind: "static", Severity: "high", Invariant: "shared-inv", Version: "1"},
		{ID: "b", Kind: "static", Severity: "high", Invariant: "shared-inv", Version: "1"},
	}
	checks := []CheckRecord{
		check(artifact, rules[0], StatusPass, ""),
		check(artifact, rules[1], StatusDefect, "counterexample via delegatecall"),
	}
	report, err := BuildReportWithChecks(artifact, rules, nil, checks)
	if err != nil {
		t.Fatal(err)
	}
	got := ruleStatuses(report)
	if got["a"] != StatusPass || got["b"] != StatusDefect {
		t.Errorf("shared invariant conclusions = %+v", got)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "b" {
		t.Fatalf("findings = %+v", report.Findings)
	}
}

func TestChecksFallBackToBoolAndUnchecked(t *testing.T) {
	// No record => original boolean; neither record nor boolean => unchecked.
	artifact := sampleArtifact()
	rules := []Rule{
		{ID: "checked", Kind: "static", Severity: "low", Invariant: "inv-c", Version: "1"},
		{ID: "booled", Kind: "static", Severity: "low", Invariant: "inv-b", Version: "1"},
		{ID: "neither", Kind: "static", Severity: "low", Invariant: "inv-n", Version: "1"},
	}
	checks := []CheckRecord{check(artifact, rules[0], StatusPass, "")}
	invariants := map[string]bool{"inv-b": false}
	report, err := BuildReportWithChecks(artifact, rules, invariants, checks)
	if err != nil {
		t.Fatal(err)
	}
	got := ruleStatuses(report)
	if got["checked"] != StatusPass || got["booled"] != StatusDefect || got["neither"] != StatusUnchecked {
		t.Errorf("statuses = %+v", got)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "booled" {
		t.Fatalf("boolean defect still produces its finding, got %+v", report.Findings)
	}
	if report.Findings[0].Evidence != "invariant inv-b does not hold" {
		t.Errorf("boolean evidence unchanged, got %q", report.Findings[0].Evidence)
	}
}

func TestChecksPassNoteMayBeEmptyOrWhitespace(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "p", Kind: "static", Severity: "low", Invariant: "inv", Version: "1"}
	for _, note := range []string{"", "   ", "\t\n"} {
		if _, err := BuildReportWithChecks(artifact, []Rule{rule}, nil,
			[]CheckRecord{check(artifact, rule, StatusPass, note)}); err != nil {
			t.Errorf("pass with note %q rejected: %v", note, err)
		}
	}
}

// --- Whole-submission rejections ---

func TestChecksRejectUnknownRule(t *testing.T) {
	artifact := sampleArtifact()
	rules := []Rule{{ID: "known", Kind: "static", Invariant: "inv", Version: "1"}}
	bad := check(artifact, Rule{ID: "known", Version: "1"}, StatusPass, "")
	bad.RuleID = "ghost"
	_, err := BuildReportWithChecks(artifact, rules, nil, []CheckRecord{bad})
	if err == nil || !strings.Contains(err.Error(), "ghost") || !strings.Contains(err.Error(), "unknown rule") {
		t.Fatalf("error must name rule and reason, got %v", err)
	}
}

func TestChecksRejectDuplicateRecord(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Invariant: "inv", Version: "1"}
	_, err := BuildReportWithChecks(artifact, []Rule{rule}, nil, []CheckRecord{
		check(artifact, rule, StatusPass, ""),
		check(artifact, rule, StatusDefect, "evidence"),
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "r") {
		t.Fatalf("error must name rule and duplicate, got %v", err)
	}
}

func TestChecksRejectUnknownStatus(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Invariant: "inv", Version: "1"}
	bad := check(artifact, rule, "跳过", "")
	_, err := BuildReportWithChecks(artifact, []Rule{rule}, nil, []CheckRecord{bad})
	if err == nil || !strings.Contains(err.Error(), "unknown status") || !strings.Contains(err.Error(), "r") {
		t.Fatalf("error must name rule and status, got %v", err)
	}
}

func TestChecksRejectEmptyRequiredNotes(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Invariant: "inv", Version: "1"}
	for _, status := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		for _, note := range []string{"", "   ", "\t\n "} {
			_, err := BuildReportWithChecks(artifact, []Rule{rule}, nil,
				[]CheckRecord{check(artifact, rule, status, note)})
			if err == nil || !strings.Contains(err.Error(), "non-empty note") {
				t.Fatalf("status %s note %q must be rejected, got %v", status, note, err)
			}
		}
	}
}

func TestChecksRejectArtifactHashMismatch(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Invariant: "inv", Version: "1"}
	bad := check(artifact, rule, StatusPass, "")
	bad.ArtifactHash = strings.Repeat("0", 64)
	_, err := BuildReportWithChecks(artifact, []Rule{rule}, nil, []CheckRecord{bad})
	if err == nil || !strings.Contains(err.Error(), "hash") || !strings.Contains(err.Error(), "r") {
		t.Fatalf("error must name rule and hash mismatch, got %v", err)
	}
}

func TestChecksRejectVersionMismatch(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Invariant: "inv", Version: "2.0.0"}
	bad := check(artifact, rule, StatusPass, "")
	bad.RuleVersion = "1.0.0"
	_, err := BuildReportWithChecks(artifact, []Rule{rule}, nil, []CheckRecord{bad})
	if err == nil || !strings.Contains(err.Error(), "version") || !strings.Contains(err.Error(), "r") {
		t.Fatalf("error must name rule and version mismatch, got %v", err)
	}
}

func TestChecksRejectCheckAndBoolForSameRule(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Invariant: "inv", Version: "1"}
	_, err := BuildReportWithChecks(artifact, []Rule{rule},
		map[string]bool{"inv": true},
		[]CheckRecord{check(artifact, rule, StatusPass, "")})
	if err == nil || !strings.Contains(err.Error(), "both") || !strings.Contains(err.Error(), "r") {
		t.Fatalf("error must reject check plus invariant bool, got %v", err)
	}
}

func TestChecksCannotBypassABIRequirement(t *testing.T) {
	rule := Rule{ID: "r", Kind: "static", Invariant: "inv", RequiresABI: true, Version: "1"}
	artifact := Artifact{Name: "A", ABI: "", Bytecode: "0x1"}
	for _, status := range []string{StatusToolMissing, StatusTimeout, StatusPass, StatusDefect} {
		c := CheckRecord{ArtifactHash: ArtifactHash(artifact), RuleID: "r", RuleVersion: "1", Status: status, Note: "x"}
		if _, err := BuildReportWithChecks(artifact, []Rule{rule}, nil, []CheckRecord{c}); err == nil {
			t.Fatalf("status %s bypassed missing-ABI rejection", status)
		}
	}
}

func TestChecksCannotBypassBytecodeRequirement(t *testing.T) {
	rule := Rule{ID: "r", Kind: "symbolic", Invariant: "inv", Version: "1"}
	artifact := Artifact{Name: "A", ABI: "abi", Bytecode: ""}
	for _, status := range []string{StatusToolMissing, StatusTimeout, StatusPass, StatusDefect} {
		c := CheckRecord{ArtifactHash: ArtifactHash(artifact), RuleID: "r", RuleVersion: "1", Status: status, Note: "x"}
		if _, err := BuildReportWithChecks(artifact, []Rule{rule}, nil, []CheckRecord{c}); err == nil {
			t.Fatalf("status %s bypassed missing-bytecode rejection", status)
		}
	}
}

func TestChecksRejectionLeavesNoArchive(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Invariant: "inv", Version: "1"}
	bad := check(artifact, rule, StatusDefect, "   ")
	_, err := BuildReportWithChecks(artifact, []Rule{rule}, nil, []CheckRecord{bad})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*")); len(matches) != 0 {
		t.Fatalf("rejected submission must not write archives: %v", matches)
	}
}

// --- Parsing ---

func TestParseAuditInputChecks(t *testing.T) {
	input := `{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}],
		"invariants": {},
		"checks": [{"artifactHash":"abc","ruleId":"r1","ruleVersion":"1.0.0","status":"超时","note":"took too long"}]
	}`
	_, _, _, checks, err := ParseAuditInput([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 {
		t.Fatalf("checks = %d, want 1", len(checks))
	}
	c := checks[0]
	if c.ArtifactHash != "abc" || c.RuleID != "r1" || c.RuleVersion != "1.0.0" ||
		c.Status != StatusTimeout || c.Note != "took too long" {
		t.Errorf("check = %+v", c)
	}
}

func TestParseAuditInputChecksWrongType(t *testing.T) {
	input := `{"artifact":{"name":"A"},"rules":[],"checks":{"r1":"通过"}}`
	if _, _, _, _, err := ParseAuditInput([]byte(input)); err == nil {
		t.Fatal("expected error when checks is not an array")
	}
}

func TestParseAuditInputNoChecks(t *testing.T) {
	input := `{"artifact":{"name":"A"},"rules":[]}`
	_, _, _, checks, err := ParseAuditInput([]byte(input))
	if err != nil || len(checks) != 0 {
		t.Fatalf("missing checks must parse empty, got %v %+v", err, checks)
	}
}

// --- Report ID determinism and binding ---

func TestChecksReportIDOrderIndependent(t *testing.T) {
	artifact := sampleArtifact()
	rules := []Rule{
		{ID: "a", Kind: "static", Severity: "low", Invariant: "ia", Version: "1"},
		{ID: "b", Kind: "static", Severity: "low", Invariant: "ib", Version: "1"},
		{ID: "c", Kind: "static", Severity: "low", Invariant: "ic", Version: "1"},
	}
	mk := func() []CheckRecord {
		return []CheckRecord{
			check(artifact, rules[0], StatusPass, ""),
			check(artifact, rules[1], StatusToolMissing, "no tool"),
			check(artifact, rules[2], StatusDefect, "evidence"),
		}
	}
	r1, err := BuildReportWithChecks(artifact, rules, nil, mk())
	if err != nil {
		t.Fatal(err)
	}
	reordered := []CheckRecord{mk()[2], mk()[0], mk()[1]}
	r2, err := BuildReportWithChecks(artifact, []Rule{rules[2], rules[0], rules[1]}, nil, reordered)
	if err != nil {
		t.Fatal(err)
	}
	if r1.ReportID != r2.ReportID {
		t.Fatal("record and rule order must not affect the id")
	}
}

func TestChecksReportIDChangesWithStatus(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "low", Invariant: "inv", Version: "1"}
	r1, _ := BuildReportWithChecks(artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusPass, "")})
	r2, _ := BuildReportWithChecks(artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusTimeout, "timed out")})
	if r1.ReportID == r2.ReportID {
		t.Fatal("status change must produce a new id")
	}
}

func TestChecksReportIDChangesWithNote(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "low", Invariant: "inv", Version: "1"}
	r1, _ := BuildReportWithChecks(artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusDefect, "counterexample v1")})
	r2, _ := BuildReportWithChecks(artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusDefect, "counterexample v2")})
	if r1.ReportID == r2.ReportID {
		t.Fatal("note change must produce a new id")
	}
}

func TestChecksEmptyPassNoteStable(t *testing.T) {
	// 通过 with no note must serialize without a note field, keeping old
	// boolean-pass reports byte-compatible in shape.
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "low", Invariant: "inv", Version: "1"}
	r1, _ := BuildReport(artifact, []Rule{rule}, map[string]bool{"inv": true})
	r2, _ := BuildReportWithChecks(artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusPass, "")})
	// Content differs in provenance only through identical fields: the two
	// reports describe the same statuses and no notes, so ids coincide.
	if r1.ReportID != r2.ReportID {
		t.Fatalf("empty-note pass check must equal boolean pass: %s vs %s", r1.ReportID, r2.ReportID)
	}
}

// --- Tamper detection on imported archives ---

func TestChecksTamperedNoteDetected(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}
	report := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusTimeout, "original note")})
	path := filepath.Join(dir, report.ReportID+".json")
	var stored Report
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	stored.Rules[0].Note = "changed note"
	tampered, _ := json.Marshal(stored)
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(dir, report.ReportID); err == nil {
		t.Fatal("changed note must be detected")
	}
}

func TestChecksTamperedStatusDetected(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}
	report := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusToolMissing, "missing tool")})
	path := filepath.Join(dir, report.ReportID+".json")
	var stored Report
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &stored)
	stored.Rules[0].Status = StatusTimeout
	tampered, _ := json.Marshal(stored)
	os.WriteFile(path, tampered, 0o644)
	if _, err := LoadReport(dir, report.ReportID); err == nil {
		t.Fatal("changed status must be detected")
	}
}

func TestChecksTamperedEvidenceDetected(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}
	report := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusDefect, "original counterexample")})
	path := filepath.Join(dir, report.ReportID+".json")
	var stored Report
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &stored)
	stored.Findings[0].Evidence = "forged counterexample"
	tampered, _ := json.Marshal(stored)
	os.WriteFile(path, tampered, 0o644)
	if _, err := LoadReport(dir, report.ReportID); err == nil {
		t.Fatal("forged evidence must be detected")
	}
}

// --- Idempotent persistence of identical check reports ---

func TestChecksConcurrentSameReportOneArchive(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rules := sampleRules()
	checks := []CheckRecord{
		check(artifact, rules[0], StatusDefect, "cex 1"),
		check(artifact, rules[1], StatusToolMissing, "missing"),
		check(artifact, rules[2], StatusTimeout, "timeout"),
	}
	report, err := BuildReportWithChecks(artifact, rules, nil, checks)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- SaveReport(dir, report)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent save: %v", err)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(matches) != 1 {
		t.Fatalf("expected 1 archive, got %d", len(matches))
	}
	loaded, err := LoadReport(dir, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ReportID != report.ReportID {
		t.Fatal("loaded id mismatch")
	}
}

// --- Diff with imported checks ---

func TestDiffNoteChangedSameStatus(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}
	before := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusDefect, "counterexample v1")})
	after := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusDefect, "counterexample v2")})
	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 {
		t.Fatalf("results = %+v", diff.Results)
	}
	e := diff.Results[0]
	if e.Change != ChangeNoteChanged {
		t.Fatalf("change = %q, want %q", e.Change, ChangeNoteChanged)
	}
	if e.Before.Rule.Note != "counterexample v1" || e.After.Rule.Note != "counterexample v2" {
		t.Errorf("notes = %q / %q", e.Before.Rule.Note, e.After.Rule.Note)
	}
	if e.Before.Finding == nil || e.After.Finding == nil {
		t.Error("both defect sides carry evidence")
	}
	if diff.Summary.NoteChanges != 1 {
		t.Errorf("noteChanges = %d, want 1", diff.Summary.NoteChanges)
	}
	if diff.Summary.NewDefects != 0 || diff.Summary.ResolvedDefects != 0 || diff.Summary.StatusChanges != 0 {
		t.Errorf("note change must not count as defect/status change: %+v", diff.Summary)
	}
	if diff.Summary.BeforeDefects != 1 || diff.Summary.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d", diff.Summary.BeforeDefects, diff.Summary.AfterDefects)
	}
}

func TestDiffPassNoteChanged(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "low", Invariant: "inv", Version: "1"}
	before := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusPass, "")})
	after := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusPass, "reviewed manually")})
	diff, _ := DiffStore(dir, before.ReportID, after.ReportID)
	if diff.Results[0].Change != ChangeNoteChanged {
		t.Fatalf("change = %q", diff.Results[0].Change)
	}
	if diff.Summary.NoteChanges != 1 || diff.Summary.NoChange != 0 {
		t.Errorf("summary = %+v", diff.Summary)
	}
}

func TestDiffTransitionsAroundToolMissingAndTimeout(t *testing.T) {
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}
	cases := []struct {
		name       string
		from       string
		to         string
		wantChange string
	}{
		{"pass to tool missing", StatusPass, StatusToolMissing, ChangeStatusChanged},
		{"tool missing to pass", StatusToolMissing, StatusPass, ChangeStatusChanged},
		{"defect to tool missing", StatusDefect, StatusToolMissing, ChangeStatusChanged},
		{"tool missing to defect", StatusToolMissing, StatusDefect, ChangeStatusChanged},
		{"timeout to defect", StatusTimeout, StatusDefect, ChangeStatusChanged},
		{"defect to timeout", StatusDefect, StatusTimeout, ChangeStatusChanged},
		{"timeout to tool missing", StatusTimeout, StatusToolMissing, ChangeStatusChanged},
		{"unchecked to tool missing", StatusUnchecked, StatusToolMissing, ChangeStatusChanged},
		{"tool missing to timeout", StatusToolMissing, StatusTimeout, ChangeStatusChanged},
		{"pass to defect", StatusPass, StatusDefect, ChangeNewDefect},
		{"defect to pass", StatusDefect, StatusPass, ChangeResolvedDefect},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rec := func(status string) []CheckRecord {
				if status == StatusUnchecked {
					return nil
				}
				return []CheckRecord{check(artifact, rule, status, "explanation for "+status)}
			}
			var before Report
			var err error
			if tc.from == StatusUnchecked {
				before = saveDiffReport(t, dir, artifact, []Rule{rule}, nil)
			} else {
				before, err = BuildReportWithChecks(artifact, []Rule{rule}, nil, rec(tc.from))
				if err != nil {
					t.Fatal(err)
				}
				if err := SaveReport(dir, before); err != nil {
					t.Fatal(err)
				}
			}
			after, err := BuildReportWithChecks(artifact, []Rule{rule}, nil, rec(tc.to))
			if err != nil {
				t.Fatal(err)
			}
			if err := SaveReport(dir, after); err != nil {
				t.Fatal(err)
			}
			diff, err := DiffStore(dir, before.ReportID, after.ReportID)
			if err != nil {
				t.Fatal(err)
			}
			if diff.Results[0].Change != tc.wantChange {
				t.Errorf("%s: change = %q, want %q", tc.name, diff.Results[0].Change, tc.wantChange)
			}
			if tc.wantChange == ChangeStatusChanged && diff.Summary.StatusChanges != 1 {
				t.Errorf("statusChanges = %d", diff.Summary.StatusChanges)
			}
		})
	}
}

func TestDiffToolMissingSideCarriesNote(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rule := Rule{ID: "r", Kind: "static", Severity: "medium", Invariant: "inv", Version: "1"}
	before := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusPass, "")})
	after := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusToolMissing, "mythril unavailable")})
	diff, _ := DiffStore(dir, before.ReportID, after.ReportID)
	e := diff.Results[0]
	if e.Change != ChangeStatusChanged {
		t.Fatalf("change = %q", e.Change)
	}
	if e.After.Rule.Status != StatusToolMissing || e.After.Rule.Note != "mythril unavailable" {
		t.Errorf("after side = %+v", e.After.Rule)
	}
	if e.After.Finding != nil {
		t.Error("tool missing must not carry a finding")
	}
}

func TestDiffDefectTotalsExcludeToolAndTimeout(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	rules := []Rule{
		{ID: "def", Kind: "static", Severity: "high", Invariant: "id", Version: "1"},
		{ID: "miss", Kind: "static", Severity: "high", Invariant: "im", Version: "1"},
		{ID: "time", Kind: "static", Severity: "high", Invariant: "it", Version: "1"},
		{ID: "ok", Kind: "static", Severity: "low", Invariant: "io", Version: "1"},
	}
	report := saveCheckReport(t, dir, artifact, rules, nil, []CheckRecord{
		check(artifact, rules[0], StatusDefect, "cex"),
		check(artifact, rules[1], StatusToolMissing, "missing"),
		check(artifact, rules[2], StatusTimeout, "timeout"),
		check(artifact, rules[3], StatusPass, ""),
	})
	diff, err := DiffStore(dir, report.ReportID, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Summary.BeforeDefects != 1 || diff.Summary.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", diff.Summary.BeforeDefects, diff.Summary.AfterDefects)
	}
	if diff.Summary.NoChange != 4 {
		t.Errorf("noChange = %d, want 4", diff.Summary.NoChange)
	}
}

func TestDiffAddedRulePriorityOverToolStatus(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	before := saveDiffReport(t, dir, artifact, nil, nil)
	rule := Rule{ID: "r", Kind: "static", Severity: "low", Invariant: "inv", Version: "1"}
	after := saveCheckReport(t, dir, artifact, []Rule{rule}, nil,
		[]CheckRecord{check(artifact, rule, StatusTimeout, "late")})
	diff, _ := DiffStore(dir, before.ReportID, after.ReportID)
	if diff.Results[0].Change != ChangeRuleAdded {
		t.Fatalf("change = %q, want %q", diff.Results[0].Change, ChangeRuleAdded)
	}
	if diff.Summary.AddedRules != 1 || diff.Summary.StatusChanges != 0 {
		t.Errorf("summary = %+v", diff.Summary)
	}
}

func TestDiffOldBooleanReportAgainstCheckReport(t *testing.T) {
	// A legacy boolean-only report diffs cleanly against a new check report.
	dir := t.TempDir()
	artifact := sampleArtifact()
	rules := sampleRules()
	old := saveDiffReport(t, dir, artifact, rules, sampleInvariants())
	checks := []CheckRecord{
		check(artifact, rules[0], StatusDefect, "reentrancy tx: A->B->A"),
		check(artifact, rules[1], StatusPass, ""),
		check(artifact, rules[2], StatusTimeout, "symbolic check unfinished after 10m"),
	}
	updated, err := BuildReportWithChecks(artifact, rules, nil, checks)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, updated); err != nil {
		t.Fatal(err)
	}
	diff, err := DiffStore(dir, old.ReportID, updated.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]string{}
	for _, r := range diff.Results {
		changes[r.RuleID] = r.Change
	}
	// r0 defect->defect note changed; r1 pass->pass identical; r2 defect->timeout status change.
	if changes["reentrancy-guard"] != ChangeNoteChanged {
		t.Errorf("reentrancy-guard = %q", changes["reentrancy-guard"])
	}
	if changes["access-control"] != ChangeNoChange {
		t.Errorf("access-control = %q", changes["access-control"])
	}
	if changes["invariant-preserved"] != ChangeStatusChanged {
		t.Errorf("invariant-preserved = %q", changes["invariant-preserved"])
	}
	// Defect->timeout is NOT a resolved defect.
	if diff.Summary.ResolvedDefects != 0 || diff.Summary.NewDefects != 0 {
		t.Errorf("defect counters = %+v", diff.Summary)
	}
	if diff.Summary.NoteChanges != 1 || diff.Summary.StatusChanges != 1 || diff.Summary.NoChange != 1 {
		t.Errorf("summary = %+v", diff.Summary)
	}
	if diff.Summary.BeforeDefects != 2 || diff.Summary.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 2/1", diff.Summary.BeforeDefects, diff.Summary.AfterDefects)
	}
}
