package contractsentinel

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const testInput = `{
  "artifact": {"name": "Vault", "abi": "[{\"name\":\"withdraw\"}]", "bytecode": "0x6080", "source": "Vault.sol"},
  "rules": [
    {"id": "reentrancy-guard", "kind": "static", "severity": "high", "invariant": "no-reentrant-withdraw", "version": "1.0.0"},
    {"id": "access-control", "kind": "static", "severity": "medium", "invariant": "owner-only-withdraw", "requiresABI": true, "version": "2.1.0"},
    {"id": "invariant-preserved", "kind": "symbolic", "severity": "critical", "invariant": "balance-monotonic", "version": "0.9.0"}
  ],
  "invariants": {"no-reentrant-withdraw": false, "owner-only-withdraw": true, "balance-monotonic": false, "unrelated-key": true}
}`

func submit(t *testing.T, dir, input string) (*Report, []byte) {
	t.Helper()
	report, raw, err := Audit([]byte(input), dir)
	if err != nil {
		t.Fatalf("audit failed: %v", err)
	}
	return report, raw
}

func TestAuditDeterministicAndOrderIndependent(t *testing.T) {
	dir := t.TempDir()
	report, raw := submit(t, dir, testInput)
	if len(report.ID) != 64 {
		t.Fatalf("unexpected report id %q", report.ID)
	}
	if len(report.Checks) != 3 || len(report.Findings) != 2 {
		t.Fatalf("unexpected report shape: checks=%d findings=%d", len(report.Checks), len(report.Findings))
	}
	for _, f := range report.Findings {
		if f.ArtifactHash != report.ArtifactHash || f.Version == "" || f.Evidence == "" {
			t.Fatalf("finding not fully bound: %+v", f)
		}
	}

	// Resubmission returns the same id and byte-identical report.
	again, againRaw := submit(t, dir, testInput)
	if again.ID != report.ID || string(againRaw) != string(raw) {
		t.Fatal("resubmission changed the report")
	}

	// Rule order, invariant key order and unrelated invariant keys are irrelevant.
	reordered := `{
	  "invariants": {"balance-monotonic": false, "owner-only-withdraw": true, "no-reentrant-withdraw": false},
	  "rules": [
	    {"id": "invariant-preserved", "kind": "symbolic", "severity": "critical", "invariant": "balance-monotonic", "version": "0.9.0"},
	    {"id": "access-control", "kind": "static", "severity": "medium", "invariant": "owner-only-withdraw", "requiresABI": true, "version": "2.1.0"},
	    {"id": "reentrancy-guard", "kind": "static", "severity": "high", "invariant": "no-reentrant-withdraw", "version": "1.0.0"}
	  ],
	  "artifact": {"name": "Vault", "abi": "[{\"name\":\"withdraw\"}]", "bytecode": "0x6080", "source": "Vault.sol"}
	}`
	other, otherRaw := submit(t, dir, reordered)
	if other.ID != report.ID || string(otherRaw) != string(raw) {
		t.Fatal("rule or invariant order changed the report")
	}
}

func TestReportIDChanges(t *testing.T) {
	base := map[string]string{
		"name":       `"Vault"`,
		"version":    `"1.0.0"`,
		"invariants": `{"inv": true}`,
	}
	input := func(name, version, invariants string) string {
		return fmt.Sprintf(`{
		  "artifact": {"name": %s, "abi": "[]", "bytecode": "0x", "source": "A.sol"},
		  "rules": [{"id": "r1", "kind": "static", "severity": "low", "invariant": "inv", "version": %s}],
		  "invariants": %s
		}`, name, version, invariants)
	}
	dir := t.TempDir()
	ids := map[string]string{}
	put := func(key, name, version, invariants string) {
		t.Helper()
		report, _, err := Audit([]byte(input(name, version, invariants)), dir)
		if err != nil {
			t.Fatalf("audit %s failed: %v", key, err)
		}
		ids[key] = report.ID
	}
	put("base", base["name"], base["version"], base["invariants"])
	put("name", `"Vault2"`, base["version"], base["invariants"])
	put("version", base["name"], `"1.0.1"`, base["invariants"])
	put("unchecked", base["name"], base["version"], `{}`)
	put("failed", base["name"], base["version"], `{"inv": false}`)

	seen := map[string]string{}
	for key, id := range ids {
		if other, dup := seen[id]; dup {
			t.Fatalf("ids for %s and %s collide: %s", key, other, id)
		}
		seen[id] = key
	}
	// Unchecked and passed produce no findings, yet their ids must differ.
	unchecked, _, _ := Audit([]byte(input(base["name"], base["version"], `{}`)), dir)
	if len(unchecked.Findings) != 0 || unchecked.ID == ids["base"] {
		t.Fatal("unchecked must differ from passed even with identical findings")
	}
}

func TestCheckStatuses(t *testing.T) {
	dir := t.TempDir()
	report, _ := submit(t, dir, `{
	  "artifact": {"name": "Vault", "abi": "[]", "bytecode": "0x", "source": "A.sol"},
	  "rules": [
	    {"id": "a", "kind": "static", "severity": "low", "invariant": "missing", "version": "1"},
	    {"id": "b", "kind": "static", "severity": "low", "invariant": "ok", "version": "1"},
	    {"id": "c", "kind": "static", "severity": "low", "invariant": "bad", "version": "1"}
	  ],
	  "invariants": {"ok": true, "bad": false}
	}`)
	want := map[string]string{"a": StatusUnchecked, "b": StatusPassed, "c": StatusFailed}
	for _, check := range report.Checks {
		if check.Status != want[check.Rule.ID] {
			t.Fatalf("rule %s status %q, want %q", check.Rule.ID, check.Status, want[check.Rule.ID])
		}
	}
	if len(report.Findings) != 1 || report.Findings[0].Rule != "c" {
		t.Fatalf("only the violated invariant may produce findings: %+v", report.Findings)
	}
}

func TestAuditInputErrors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"malformed json":     `{`,
		"trailing data":      `{"artifact":{"name":"A"}} garbage`,
		"non-bool invariant": `{"artifact":{"name":"A"},"rules":[],"invariants":{"inv":"true"}}`,
		"duplicate rule id": `{"artifact":{"name":"A"},"rules":[
			{"id":"r","kind":"static","severity":"low","invariant":"i","version":"1"},
			{"id":"r","kind":"static","severity":"low","invariant":"i","version":"1"}]}`,
		"empty rule id":    `{"artifact":{"name":"A"},"rules":[{"id":"","kind":"static","severity":"low","invariant":"i","version":"1"}]}`,
		"empty version":    `{"artifact":{"name":"A"},"rules":[{"id":"r","kind":"static","severity":"low","invariant":"i","version":""}]}`,
		"missing name":     `{"rules":[]}`,
		"missing ABI":      `{"artifact":{"name":"A"},"rules":[{"id":"r","kind":"static","severity":"low","invariant":"i","requiresABI":true,"version":"1"}]}`,
		"missing bytecode": `{"artifact":{"name":"A"},"rules":[{"id":"r","kind":"symbolic","severity":"low","invariant":"i","version":"1"}]}`,
	}
	for name, input := range cases {
		if _, _, err := Audit([]byte(input), dir); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("failed submissions must not store reports, found %d entries", len(entries))
	}
}

func TestEmptyRulesAllowed(t *testing.T) {
	dir := t.TempDir()
	report, _ := submit(t, dir, `{"artifact":{"name":"A"},"rules":[],"invariants":{"x":false}}`)
	if len(report.Checks) != 0 || len(report.Findings) != 0 {
		t.Fatalf("expected empty report, got %+v", report)
	}
}

func TestArtifactHashFieldBoundaries(t *testing.T) {
	a := Artifact{Name: "A", ABI: "ab", Bytecode: "c", Source: ""}
	b := Artifact{Name: "A", ABI: "a", Bytecode: "bc", Source: ""}
	if ArtifactHash(a) == ArtifactHash(b) {
		t.Fatal("field boundaries must be distinguished")
	}
	c := Artifact{Name: "Other", ABI: "ab", Bytecode: "c", Source: ""}
	if ArtifactHash(a) != ArtifactHash(c) {
		t.Fatal("artifact name must not affect the content hash")
	}
}

func TestStoreIntegrity(t *testing.T) {
	dir := t.TempDir()
	report, raw := submit(t, dir, testInput)
	path := filepath.Join(dir, report.ID+".json")

	// Reading back yields the same bytes.
	loaded, loadedRaw, err := LoadReport(dir, report.ID)
	if err != nil || loaded.ID != report.ID || string(loadedRaw) != string(raw) {
		t.Fatalf("reload mismatch: %v", err)
	}

	// Missing id is a clear error.
	if _, _, err := LoadReport(dir, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected error for missing report")
	}
	if _, _, err := LoadReport(dir, "../etc/passwd"); err == nil {
		t.Fatal("expected error for invalid id")
	}

	// Tamper with finding evidence: reads must fail and resubmission must
	// fail too, leaving the original corrupted file untouched.
	tampered := []byte(string(raw[:len(raw)/2]) + `"evidence": "forged",` + string(raw[len(raw)/2:]))
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadReport(dir, report.ID); err == nil {
		t.Fatal("tampered evidence must be detected")
	}
	if _, _, err := Audit([]byte(testInput), dir); err == nil {
		t.Fatal("resubmission over a corrupted archive must fail")
	}
	current, _ := os.ReadFile(path)
	if string(current) != string(tampered) {
		t.Fatal("corrupted archive must be preserved")
	}

	// Invalid JSON in the archive is also detected.
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadReport(dir, report.ID); err == nil {
		t.Fatal("corrupted archive must be detected")
	}
}

func TestConcurrentSubmissions(t *testing.T) {
	dir := t.TempDir()
	inputs := []string{testInput}
	for i := 0; i < 4; i++ {
		inputs = append(inputs, fmt.Sprintf(`{
		  "artifact": {"name": "C%d", "abi": "[]", "bytecode": "0x", "source": "C.sol"},
		  "rules": [{"id": "r", "kind": "static", "severity": "low", "invariant": "inv", "version": "1"}],
		  "invariants": {"inv": %t}
		}`, i, i%2 == 0))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2*len(inputs))
	for round := 0; round < 2; round++ {
		for _, input := range inputs {
			wg.Add(1)
			go func(input string) {
				defer wg.Done()
				if _, _, err := Audit([]byte(input), dir); err != nil {
					errs <- err
				}
			}(input)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(inputs) {
		t.Fatalf("expected %d stored reports, found %d", len(inputs), len(entries))
	}
	for _, entry := range entries {
		id := entry.Name()[:len(entry.Name())-len(".json")]
		if _, _, err := LoadReport(dir, id); err != nil {
			t.Fatalf("stored report %s unreadable: %v", id, err)
		}
	}
}
