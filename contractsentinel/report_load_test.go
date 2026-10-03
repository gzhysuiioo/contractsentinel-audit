package contractsentinel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// loadTestReport builds a valid report with two defects of both evidence
// kinds: reentrancy-guard is a defect derived from an invariant boolean
// (auto-generated evidence, no note), access-control is a defect imported
// from a check record (evidence is the original checker note).
// invariant-preserved stays unchecked.
func loadTestReport(t *testing.T) Report {
	t.Helper()
	hash := ArtifactHash(sampleArtifact())
	checks := []CheckRecord{
		{ArtifactHash: hash, RuleID: "access-control", Version: "2.1.0", Status: StatusDefect, Note: "counterexample: caller is not owner"},
	}
	invariants := map[string]bool{"no-reentrant-withdraw": false}
	report, err := BuildReport(sampleArtifact(), sampleRules(), invariants, checks)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("test setup: findings = %d, want 2", len(report.Findings))
	}
	return report
}

// rewriteArchive stores a mutated copy of report in dir with the id
// recomputed to match the mutated content, and returns the new id. The
// archive it produces therefore has an id consistent with its bytes: any
// rejection of it comes from the business relations inside the report, never
// from an id mismatch.
func rewriteArchive(t *testing.T, dir string, report Report, mutate func(*Report)) string {
	t.Helper()
	mutated := report
	mutated.Rules = append([]ReportRule(nil), report.Rules...)
	mutated.Findings = append([]ReportFinding(nil), report.Findings...)
	mutate(&mutated)
	mutated.ReportID = ReportID(mutated)
	data, err := json.Marshal(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, mutated.ReportID+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return mutated.ReportID
}

// expectLoadCorrupt asserts that reading id from dir fails as a corrupt
// archive (never as not-found or invalid-request), that the error names
// wantRule, that no partial report is returned, and that the archive bytes
// on disk are left untouched.
func expectLoadCorrupt(t *testing.T, dir, id, wantRule string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatal("expected corrupt archive to be rejected")
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T: %v", err, err)
	}
	var ei errInvalid
	if errors.As(err, &ei) {
		t.Fatalf("corrupt archive must not be reported as errInvalid: %v", err)
	}
	var en errNotFound
	if errors.As(err, &en) {
		t.Fatalf("corrupt archive must not be reported as errNotFound: %v", err)
	}
	if wantRule != "" && !strings.Contains(err.Error(), wantRule) {
		t.Fatalf("error must name rule %q: %v", wantRule, err)
	}
	if !reflect.DeepEqual(got, Report{}) {
		t.Fatalf("a rejected read must not return a partial report, got %+v", got)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a failed read must not modify the archive")
	}
}

// --- Legal reports: the defect/finding correspondence survives a read ---

func TestLoadReportPreservesDefectBinding(t *testing.T) {
	dir := t.TempDir()
	report := loadTestReport(t)
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, report) {
		t.Fatalf("loaded report differs from the audited report:\nloaded: %+v\nwant:   %+v", loaded, report)
	}
	hash := ArtifactHash(sampleArtifact())
	ruleByID := map[string]ReportRule{}
	for _, r := range loaded.Rules {
		ruleByID[r.ID] = r
	}
	// Every 发现缺陷 rule corresponds to exactly one finding, and the finding
	// carries the artifact hash, rule version, severity and invariant of its
	// owning report and rule — preserved, not recomputed on read.
	defects := 0
	for _, r := range loaded.Rules {
		if r.Status == StatusDefect {
			defects++
		}
	}
	if defects != len(loaded.Findings) {
		t.Fatalf("defect rules = %d, findings = %d", defects, len(loaded.Findings))
	}
	seen := map[string]bool{}
	for _, f := range loaded.Findings {
		rule, ok := ruleByID[f.RuleID]
		if !ok {
			t.Fatalf("finding references unknown rule %q", f.RuleID)
		}
		if rule.Status != StatusDefect {
			t.Fatalf("finding attached to non-defect rule %q", f.RuleID)
		}
		if seen[f.RuleID] {
			t.Fatalf("rule %q has more than one finding", f.RuleID)
		}
		seen[f.RuleID] = true
		if f.ArtifactHash != hash || f.ArtifactHash != loaded.Artifact.Hash {
			t.Errorf("finding %s artifact hash = %q, want %q", f.RuleID, f.ArtifactHash, hash)
		}
		if f.Version != rule.Version {
			t.Errorf("finding %s version = %q, want %q", f.RuleID, f.Version, rule.Version)
		}
		if f.Severity != rule.Severity {
			t.Errorf("finding %s severity = %q, want %q", f.RuleID, f.Severity, rule.Severity)
		}
		if f.Invariant != rule.Invariant {
			t.Errorf("finding %s invariant = %q, want %q", f.RuleID, f.Invariant, rule.Invariant)
		}
	}
}

func TestLoadReportSharedInvariantKeepsSeparateAttribution(t *testing.T) {
	// Two rules check the same invariant; one passes, the other finds a
	// defect. The finding belongs to the defect rule only and must not be
	// merged or moved by invariant name, on build or on read.
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	rules := []Rule{
		{ID: "shared-pass", Kind: "static", Severity: "high", Invariant: "shared-inv", Version: "1.0.0"},
		{ID: "shared-defect", Kind: "static", Severity: "low", Invariant: "shared-inv", Version: "2.0.0"},
	}
	checks := []CheckRecord{
		{ArtifactHash: hash, RuleID: "shared-pass", Version: "1.0.0", Status: StatusPass, Note: ""},
		{ArtifactHash: hash, RuleID: "shared-defect", Version: "2.0.0", Status: StatusDefect, Note: "counterexample: shared-inv violated"},
	}
	report, err := BuildReport(sampleArtifact(), rules, nil, checks)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", loaded.Findings)
	}
	f := loaded.Findings[0]
	if f.RuleID != "shared-defect" {
		t.Fatalf("finding attached to rule %q, want shared-defect", f.RuleID)
	}
	if f.Version != "2.0.0" || f.Severity != "low" || f.Invariant != "shared-inv" {
		t.Errorf("finding binding = %+v", f)
	}
	if f.Evidence != "counterexample: shared-inv violated" {
		t.Errorf("finding evidence = %q", f.Evidence)
	}
	for _, r := range loaded.Rules {
		if r.ID == "shared-pass" && r.Status != StatusPass {
			t.Errorf("shared-pass status = %q, want %q", r.Status, StatusPass)
		}
	}
}

// --- Evidence compatibility of the two legal report shapes ---

func TestLoadReportEvidenceFromCheckNote(t *testing.T) {
	// A defect imported from a check record keeps the original checker note
	// as its evidence after a save/load round trip.
	dir := t.TempDir()
	report := loadTestReport(t)
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range loaded.Findings {
		if f.RuleID == "access-control" {
			if f.Evidence != "counterexample: caller is not owner" {
				t.Fatalf("evidence = %q, want the original check note", f.Evidence)
			}
			return
		}
	}
	t.Fatal("finding for access-control missing after load")
}

func TestLoadReportEvidenceAutoGenerated(t *testing.T) {
	// A defect derived from an invariant boolean has no check note; the
	// auto-generated evidence must survive the round trip unchanged.
	dir := t.TempDir()
	report := loadTestReport(t)
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range loaded.Findings {
		if f.RuleID == "reentrancy-guard" {
			want := "invariant no-reentrant-withdraw does not hold"
			if f.Evidence != want {
				t.Fatalf("evidence = %q, want %q", f.Evidence, want)
			}
			return
		}
	}
	t.Fatal("finding for reentrancy-guard missing after load")
}

// --- Corrupted archives: the correspondence is enforced on read ---
// Every archive below has an id that matches its content, so rejection can
// only come from the broken defect/finding relation itself.

func TestLoadReportRejectsDuplicateFinding(t *testing.T) {
	dir := t.TempDir()
	report := loadTestReport(t)
	id := rewriteArchive(t, dir, report, func(r *Report) {
		r.Findings = append(r.Findings, r.Findings[0])
	})
	if ReportID(mustLoadRaw(t, dir, id)) != id {
		t.Fatal("test setup: archive id must match its content")
	}
	expectLoadCorrupt(t, dir, id, "reentrancy-guard")
}

func TestLoadReportRejectsFindingForUnknownRule(t *testing.T) {
	dir := t.TempDir()
	report := loadTestReport(t)
	id := rewriteArchive(t, dir, report, func(r *Report) {
		r.Findings = append(r.Findings, ReportFinding{
			ArtifactHash: r.Artifact.Hash, RuleID: "ghost-rule",
			Version: "1.0.0", Severity: "high", Invariant: "inv", Evidence: "fabricated",
		})
	})
	expectLoadCorrupt(t, dir, id, "ghost-rule")
}

func TestLoadReportRejectsFindingForNonDefectRule(t *testing.T) {
	// A finding pointing at a rule that did not conclude 发现缺陷 is illegal,
	// even when both rules check the same invariant: the defect must not be
	// transferred to the passing rule by invariant name.
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	rules := []Rule{
		{ID: "shared-pass", Kind: "static", Severity: "high", Invariant: "shared-inv", Version: "1.0.0"},
		{ID: "shared-defect", Kind: "static", Severity: "low", Invariant: "shared-inv", Version: "2.0.0"},
	}
	checks := []CheckRecord{
		{ArtifactHash: hash, RuleID: "shared-pass", Version: "1.0.0", Status: StatusPass, Note: ""},
		{ArtifactHash: hash, RuleID: "shared-defect", Version: "2.0.0", Status: StatusDefect, Note: "counterexample"},
	}
	report, err := BuildReport(sampleArtifact(), rules, nil, checks)
	if err != nil {
		t.Fatal(err)
	}
	id := rewriteArchive(t, dir, report, func(r *Report) {
		for i := range r.Findings {
			if r.Findings[i].RuleID == "shared-defect" {
				r.Findings[i].RuleID = "shared-pass"
				r.Findings[i].Version = "1.0.0"
				r.Findings[i].Severity = "high"
			}
		}
	})
	expectLoadCorrupt(t, dir, id, "shared-pass")
}

func TestLoadReportRejectsDefectWithoutFinding(t *testing.T) {
	// A rule declaring 发现缺陷 with no corresponding finding must not read
	// back as an apparently complete report.
	dir := t.TempDir()
	report := loadTestReport(t)
	id := rewriteArchive(t, dir, report, func(r *Report) {
		r.Findings = r.Findings[1:]
	})
	expectLoadCorrupt(t, dir, id, "reentrancy-guard")
}

func TestLoadReportRejectsFindingBoundToOtherArtifact(t *testing.T) {
	dir := t.TempDir()
	report := loadTestReport(t)
	other := ArtifactHash(Artifact{Name: "Vault", ABI: "other-abi", Bytecode: "0x6080", Source: "Vault.sol"})
	if other == report.Artifact.Hash {
		t.Fatal("test setup: need a distinct artifact hash")
	}
	id := rewriteArchive(t, dir, report, func(r *Report) {
		r.Findings[0].ArtifactHash = other
	})
	expectLoadCorrupt(t, dir, id, "reentrancy-guard")
}

func TestLoadReportRejectsFindingFieldMismatch(t *testing.T) {
	// findings[0] is the invariant-boolean defect (auto-generated evidence),
	// findings[1] is the check-record defect (evidence is the check note).
	cases := []struct {
		name   string
		mutate func(*Report)
		rule   string
	}{
		{"version", func(r *Report) { r.Findings[0].Version = "9.9.9" }, "reentrancy-guard"},
		{"severity", func(r *Report) { r.Findings[0].Severity = "low" }, "reentrancy-guard"},
		{"invariant", func(r *Report) { r.Findings[0].Invariant = "other-inv" }, "reentrancy-guard"},
		{"auto evidence", func(r *Report) { r.Findings[0].Evidence = "fabricated evidence" }, "reentrancy-guard"},
		{"note evidence", func(r *Report) { r.Findings[1].Evidence = "invariant owner-only-withdraw does not hold" }, "access-control"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			report := loadTestReport(t)
			id := rewriteArchive(t, dir, report, tc.mutate)
			expectLoadCorrupt(t, dir, id, tc.rule)
		})
	}
}

// --- Reads never modify the store, and error classes stay distinct ---

func TestLoadReportDoesNotModifyArchiveOnSuccess(t *testing.T) {
	dir := t.TempDir()
	report := loadTestReport(t)
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, report.ReportID+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(dir, report.ReportID); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a successful read must not modify the archive")
	}
}

func TestLoadReportErrorClassification(t *testing.T) {
	dir := t.TempDir()
	report := loadTestReport(t)
	// A broken defect/finding relation with a content-matching id is a
	// corrupt archive, distinct from a missing report and from a malformed
	// request id.
	corruptID := rewriteArchive(t, dir, report, func(r *Report) {
		r.Findings = r.Findings[:1]
	})
	if _, err := LoadReport(dir, corruptID); err != nil {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("broken relation: expected errCorrupt, got %T: %v", err, err)
		}
	} else {
		t.Fatal("broken relation: expected an error")
	}
	if _, err := LoadReport(dir, strings.Repeat("1", 64)); err != nil {
		var en errNotFound
		if !errors.As(err, &en) {
			t.Fatalf("missing report: expected errNotFound, got %T: %v", err, err)
		}
	} else {
		t.Fatal("missing report: expected an error")
	}
	if _, err := LoadReport(dir, "not-a-hex-id"); err != nil {
		var ei errInvalid
		if !errors.As(err, &ei) {
			t.Fatalf("malformed id: expected errInvalid, got %T: %v", err, err)
		}
	} else {
		t.Fatal("malformed id: expected an error")
	}
}

// mustLoadRaw reads the stored archive for id without validation, for test
// setup assertions only.
func mustLoadRaw(t *testing.T, dir, id string) Report {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
