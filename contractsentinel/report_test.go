package contractsentinel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func sampleArtifact() Artifact {
	return Artifact{Name: "Vault", ABI: `[{"name":"withdraw"}]`, Bytecode: "0x6080", Source: "Vault.sol"}
}

func sampleRules() []Rule {
	return []Rule{
		{ID: "reentrancy-guard", Kind: "static", Severity: "high", Invariant: "no-reentrant-withdraw", Version: "1.0.0"},
		{ID: "access-control", Kind: "static", Severity: "medium", Invariant: "owner-only-withdraw", RequiresABI: true, Version: "2.1.0"},
		{ID: "invariant-preserved", Kind: "symbolic", Severity: "critical", Invariant: "balance-monotonic", Version: "0.9.0"},
	}
}

func sampleInvariants() map[string]bool {
	return map[string]bool{
		"no-reentrant-withdraw": false,
		"owner-only-withdraw":   true,
		"balance-monotonic":     false,
	}
}

// --- ArtifactHash ---

func TestArtifactHashDeterministic(t *testing.T) {
	a := sampleArtifact()
	if ArtifactHash(a) != ArtifactHash(a) {
		t.Fatal("artifact hash is not deterministic")
	}
}

func TestArtifactHashFieldBoundaries(t *testing.T) {
	// Different splits of the same concatenation must not collide.
	a := Artifact{ABI: "ab", Bytecode: "c", Source: ""}
	b := Artifact{ABI: "a", Bytecode: "bc", Source: ""}
	if ArtifactHash(a) == ArtifactHash(b) {
		t.Fatal("artifact hash collided across field boundaries")
	}
}

func TestArtifactHashNameExcluded(t *testing.T) {
	a := Artifact{Name: "Vault", ABI: "x", Bytecode: "y", Source: "z"}
	b := Artifact{Name: "Other", ABI: "x", Bytecode: "y", Source: "z"}
	if ArtifactHash(a) != ArtifactHash(b) {
		t.Fatal("name must not participate in the artifact hash")
	}
}

func TestArtifactHashSourceIsValue(t *testing.T) {
	// Source is hashed as a field value; a source string that looks like a
	// path must never be read from disk.
	a := Artifact{ABI: "x", Bytecode: "y", Source: "Vault.sol"}
	b := Artifact{ABI: "x", Bytecode: "y", Source: "other/Vault.sol"}
	if ArtifactHash(a) == ArtifactHash(b) {
		t.Fatal("different source values must hash differently")
	}
}

// --- BuildReport statuses ---

func TestBuildReportStatuses(t *testing.T) {
	report, err := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err != nil {
		t.Fatal(err)
	}
	statusByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["reentrancy-guard"] != StatusDefect {
		t.Errorf("reentrancy-guard = %q, want %q", statusByID["reentrancy-guard"], StatusDefect)
	}
	if statusByID["access-control"] != StatusPass {
		t.Errorf("access-control = %q, want %q", statusByID["access-control"], StatusPass)
	}
	if statusByID["invariant-preserved"] != StatusDefect {
		t.Errorf("invariant-preserved = %q, want %q", statusByID["invariant-preserved"], StatusDefect)
	}
}

func TestBuildReportUnchecked(t *testing.T) {
	// Missing invariant value => 未检查, not a defect.
	invariants := map[string]bool{"no-reentrant-withdraw": false}
	report, err := BuildReport(sampleArtifact(), sampleRules(), invariants)
	if err != nil {
		t.Fatal(err)
	}
	statusByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["access-control"] != StatusUnchecked {
		t.Errorf("access-control = %q, want %q", statusByID["access-control"], StatusUnchecked)
	}
	if statusByID["invariant-preserved"] != StatusUnchecked {
		t.Errorf("invariant-preserved = %q, want %q", statusByID["invariant-preserved"], StatusUnchecked)
	}
	for _, f := range report.Findings {
		if f.RuleID == "access-control" || f.RuleID == "invariant-preserved" {
			t.Errorf("unchecked rule produced a finding: %+v", f)
		}
	}
}

func TestBuildReportFindingsBind(t *testing.T) {
	report, err := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}
	hash := ArtifactHash(sampleArtifact())
	for _, f := range report.Findings {
		if f.ArtifactHash != hash {
			t.Errorf("finding %s artifact hash = %q, want %q", f.RuleID, f.ArtifactHash, hash)
		}
		if f.Version == "" {
			t.Errorf("finding %s has empty version", f.RuleID)
		}
		if f.Evidence == "" {
			t.Errorf("finding %s has empty evidence", f.RuleID)
		}
	}
}

func TestBuildReportEmptyRules(t *testing.T) {
	report, err := BuildReport(sampleArtifact(), nil, sampleInvariants())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Rules) != 0 || len(report.Findings) != 0 {
		t.Fatalf("empty rules should give empty report, got %+v", report)
	}
	if report.ReportID == "" {
		t.Fatal("empty rules report still needs an id")
	}
}

// --- BuildReport input refusal ---

func TestBuildReportRequiresABIMissing(t *testing.T) {
	rules := []Rule{{ID: "r1", Kind: "static", Invariant: "inv", RequiresABI: true, Version: "1"}}
	_, err := BuildReport(Artifact{Name: "A", ABI: "", Bytecode: "0x1"}, rules, map[string]bool{"inv": false})
	if err == nil {
		t.Fatal("expected error for missing ABI")
	}
}

func TestBuildReportSymbolicMissingBytecode(t *testing.T) {
	rules := []Rule{{ID: "r1", Kind: "symbolic", Invariant: "inv", Version: "1"}}
	_, err := BuildReport(Artifact{Name: "A", ABI: "abi", Bytecode: ""}, rules, map[string]bool{"inv": false})
	if err == nil {
		t.Fatal("expected error for missing bytecode")
	}
}

func TestBuildReportDuplicateRuleID(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Kind: "static", Invariant: "a", Version: "1"},
		{ID: "r1", Kind: "static", Invariant: "b", Version: "1"},
	}
	_, err := BuildReport(sampleArtifact(), rules, nil)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate rule id error, got %v", err)
	}
}

func TestBuildReportEmptyRuleID(t *testing.T) {
	rules := []Rule{{ID: "", Kind: "static", Invariant: "a", Version: "1"}}
	_, err := BuildReport(sampleArtifact(), rules, nil)
	if err == nil {
		t.Fatal("expected error for empty rule id")
	}
}

func TestBuildReportEmptyVersion(t *testing.T) {
	rules := []Rule{{ID: "r1", Kind: "static", Invariant: "a", Version: ""}}
	_, err := BuildReport(sampleArtifact(), rules, nil)
	if err == nil {
		t.Fatal("expected error for empty version")
	}
}

func TestBuildReportEmptyArtifactName(t *testing.T) {
	_, err := BuildReport(Artifact{ABI: "x", Bytecode: "y"}, sampleRules(), nil)
	if err == nil {
		t.Fatal("expected error for empty artifact name")
	}
}

// --- ParseAuditInput ---

func TestParseAuditInputValid(t *testing.T) {
	input := `{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":true,"version":"1.0.0"}],
		"invariants": {"inv": false}
	}`
	artifact, rules, invariants, err := ParseAuditInput([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Name != "Vault" || artifact.ABI != "abi" || artifact.Bytecode != "0x1" || artifact.Source != "Vault.sol" {
		t.Errorf("artifact = %+v", artifact)
	}
	if len(rules) != 1 || rules[0].ID != "r1" || rules[0].Version != "1.0.0" || !rules[0].RequiresABI {
		t.Errorf("rules = %+v", rules)
	}
	if len(invariants) != 1 || invariants["inv"] {
		t.Errorf("invariants = %+v", invariants)
	}
}

func TestParseAuditInputInvalidJSON(t *testing.T) {
	if _, _, _, err := ParseAuditInput([]byte(`{not json`)); err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func TestParseAuditInputBooleanTypeError(t *testing.T) {
	input := `{"artifact":{"name":"A"},"rules":[],"invariants":{"inv":"true"}}`
	_, _, _, err := ParseAuditInput([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("expected boolean type error, got %v", err)
	}
}

func TestParseAuditInputInvariantsNotObject(t *testing.T) {
	input := `{"artifact":{"name":"A"},"rules":[],"invariants":[1,2]}`
	if _, _, _, err := ParseAuditInput([]byte(input)); err == nil {
		t.Fatal("expected error when invariants is not an object")
	}
}

// --- ReportID binding ---

func TestReportIDDeterministicAndStable(t *testing.T) {
	r1, err := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err != nil {
		t.Fatal(err)
	}
	if r1.ReportID != r2.ReportID {
		t.Fatal("same input produced different ids")
	}
}

func TestReportIDRuleOrderIndependent(t *testing.T) {
	rules := sampleRules()
	r1, err := BuildReport(sampleArtifact(), rules, sampleInvariants())
	if err != nil {
		t.Fatal(err)
	}
	reversed := []Rule{rules[2], rules[1], rules[0]}
	r2, err := BuildReport(sampleArtifact(), reversed, sampleInvariants())
	if err != nil {
		t.Fatal(err)
	}
	if r1.ReportID != r2.ReportID {
		t.Fatal("rule order must not affect the id")
	}
}

func TestReportIDInvariantKeyOrderIndependent(t *testing.T) {
	// Go maps have no order; run repeatedly to be sure lookup-only access
	// never leaks iteration order into the id.
	ids := map[string]bool{}
	for i := 0; i < 20; i++ {
		r, err := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
		if err != nil {
			t.Fatal(err)
		}
		ids[r.ReportID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("invariant key order leaked into the id: %v", ids)
	}
}

func TestReportIDUnrelatedInvariantsIgnored(t *testing.T) {
	inv := sampleInvariants()
	r1, err := BuildReport(sampleArtifact(), sampleRules(), inv)
	if err != nil {
		t.Fatal(err)
	}
	inv["unrelated-key"] = true
	inv["another-unrelated"] = false
	r2, err := BuildReport(sampleArtifact(), sampleRules(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if r1.ReportID != r2.ReportID {
		t.Fatal("unrelated invariant keys must not affect the id")
	}
}

func TestReportIDBindsName(t *testing.T) {
	a1 := sampleArtifact()
	a2 := sampleArtifact()
	a2.Name = "Other"
	r1, _ := BuildReport(a1, sampleRules(), sampleInvariants())
	r2, _ := BuildReport(a2, sampleRules(), sampleInvariants())
	if r1.ReportID == r2.ReportID {
		t.Fatal("name change must produce a new id")
	}
}

func TestReportIDBindsRuleDefinition(t *testing.T) {
	r1, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	rules := sampleRules()
	rules[0].Severity = "critical"
	r2, _ := BuildReport(sampleArtifact(), rules, sampleInvariants())
	if r1.ReportID == r2.ReportID {
		t.Fatal("rule definition change must produce a new id")
	}
}

func TestReportIDBindsVersion(t *testing.T) {
	r1, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	rules := sampleRules()
	rules[0].Version = "1.0.1"
	r2, _ := BuildReport(sampleArtifact(), rules, sampleInvariants())
	if r1.ReportID == r2.ReportID {
		t.Fatal("version change must produce a new id")
	}
}

func TestReportIDBindsInvariantValue(t *testing.T) {
	// Changing an invariant value changes the id even when the findings list
	// stays the same (e.g. a passing rule becomes unchecked).
	inv := sampleInvariants()
	r1, _ := BuildReport(sampleArtifact(), sampleRules(), inv)
	inv["owner-only-withdraw"] = false
	r2, _ := BuildReport(sampleArtifact(), sampleRules(), inv)
	if r1.ReportID == r2.ReportID {
		t.Fatal("invariant value change must produce a new id")
	}
}

func TestReportIDUncheckedDistinctFromPass(t *testing.T) {
	// Explicit pass and unchecked must produce different ids.
	invPass := map[string]bool{"no-reentrant-withdraw": false, "owner-only-withdraw": true, "balance-monotonic": false}
	invUnchecked := map[string]bool{"no-reentrant-withdraw": false, "balance-monotonic": false}
	r1, _ := BuildReport(sampleArtifact(), sampleRules(), invPass)
	r2, _ := BuildReport(sampleArtifact(), sampleRules(), invUnchecked)
	if r1.ReportID == r2.ReportID {
		t.Fatal("unchecked and explicit pass must produce different ids")
	}
}

// --- Save / Load ---

func TestSaveAndLoadReport(t *testing.T) {
	dir := t.TempDir()
	report, err := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
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
	if loaded.ReportID != report.ReportID {
		t.Fatalf("loaded id = %q, want %q", loaded.ReportID, report.ReportID)
	}
	if len(loaded.Rules) != len(report.Rules) || len(loaded.Findings) != len(report.Findings) {
		t.Fatalf("loaded report = %+v", loaded)
	}
}

func TestSaveReportByteIdentical(t *testing.T) {
	dir := t.TempDir()
	report, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, report.ReportID+".json")
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Resubmitting the same report must leave byte-identical bytes.
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("resubmission changed the report bytes")
	}
}

func TestLoadReportNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadReport(dir, "deadbeef")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestLoadReportCorrupted(t *testing.T) {
	dir := t.TempDir()
	report, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, report.ReportID+".json")
	if err := os.WriteFile(path, []byte(`{broken`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadReport(dir, report.ReportID)
	if err == nil {
		t.Fatal("expected error for corrupted report")
	}
}

func TestLoadReportTamperedEvidence(t *testing.T) {
	dir := t.TempDir()
	report, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, report.ReportID+".json")
	var stored Report
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	stored.Findings[0].Evidence = "tampered evidence"
	tampered, _ := json.Marshal(stored)
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadReport(dir, report.ReportID)
	if err == nil {
		t.Fatal("expected error for tampered evidence")
	}
}

func TestLoadReportIDMismatch(t *testing.T) {
	dir := t.TempDir()
	report, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	_, err := LoadReport(dir, "0"+report.ReportID[1:])
	if err == nil {
		t.Fatal("expected error for id mismatch")
	}
}

func TestSaveReportCorruptedArchiveFails(t *testing.T) {
	// Resubmitting with the same id but a corrupted archive must fail and
	// keep the original file.
	dir := t.TempDir()
	report, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, report.ReportID+".json")
	original, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(`{broken`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := SaveReport(dir, report)
	if err == nil {
		t.Fatal("expected error when resubmitting against a corrupted archive")
	}
	kept, _ := os.ReadFile(path)
	if string(kept) != `{broken` {
		t.Fatal("original corrupted file was modified")
	}
	if string(original) == `{broken` {
		t.Fatal("test setup error: original was already corrupted")
	}
}

func TestSaveReportDifferentReportsDoNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	r1, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	a2 := sampleArtifact()
	a2.Name = "Other"
	r2, _ := BuildReport(a2, sampleRules(), sampleInvariants())
	if r1.ReportID == r2.ReportID {
		t.Fatal("different reports must have different ids")
	}
	if err := SaveReport(dir, r1); err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, r2); err != nil {
		t.Fatal(err)
	}
	loaded1, err := LoadReport(dir, r1.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	loaded2, err := LoadReport(dir, r2.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded1.ReportID != r1.ReportID || loaded2.ReportID != r2.ReportID {
		t.Fatal("reports were overwritten")
	}
}

func TestSaveReportConcurrentSameReport(t *testing.T) {
	dir := t.TempDir()
	report, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
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
			t.Fatalf("concurrent save failed: %v", err)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(matches) != 1 {
		t.Fatalf("expected 1 file, got %d", len(matches))
	}
	loaded, err := LoadReport(dir, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ReportID != report.ReportID {
		t.Fatal("loaded report id mismatch")
	}
}

func TestSaveReportConcurrentDifferentReports(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := sampleArtifact()
			a.Name = "Artifact-" + string(rune('A'+i))
			report, err := BuildReport(a, sampleRules(), sampleInvariants())
			if err != nil {
				errs <- err
				return
			}
			errs <- SaveReport(dir, report)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent save failed: %v", err)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(matches) != 16 {
		t.Fatalf("expected 16 files, got %d", len(matches))
	}
}

func TestSaveReportCreatesStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "store")
	report, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, report.ReportID+".json")); err != nil {
		t.Fatalf("report file missing: %v", err)
	}
}

// --- errInvalid type ---

func TestErrInvalidType(t *testing.T) {
	_, err := BuildReport(Artifact{Name: ""}, nil, nil)
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid, got %T %v", err, err)
	}
}
