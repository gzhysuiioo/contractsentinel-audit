package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// auditBinary builds the CLI into a temp file once and returns its path. The
// tests exercise the real process boundary: exit status, stdout and stderr are
// observed exactly as an operator would see them.
func auditBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "contractsentinel")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out.String())
	}
	return bin
}

// writeInput stores a JSON submission and returns its path.
func writeInput(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const nullInvariantInput = `{
	"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
	"rules": [{"id":"invariant-preserved","kind":"symbolic","severity":"critical","invariant":"balance-monotonic","version":"0.9.0"}],
	"invariants": {"balance-monotonic": null}
}`

const validInvariantInput = `{
	"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
	"rules": [{"id":"invariant-preserved","kind":"symbolic","severity":"critical","invariant":"balance-monotonic","version":"0.9.0"}],
	"invariants": {"balance-monotonic": false}
}`

// null 不变式：非零退出、原因进 stderr、stdout 不得出现成功报告。
func TestCLIAuditNullInvariantFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", nullInvariantInput)
	store := filepath.Join(work, "reports")

	cmd := exec.Command(bin, "audit", "--input", input, "--store", store)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err == nil {
		t.Fatal("audit must exit non-zero for a null invariant value")
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if strings.Contains(stdout.String(), "reportId") || strings.Contains(stdout.String(), "发现缺陷") {
		t.Fatalf("stdout must not contain a success report:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "balance-monotonic") {
		t.Fatalf("stderr must name the invariant:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "boolean") {
		t.Fatalf("stderr must say the value must be a boolean:\n%s", stderr.String())
	}
}

// 解析失败时不得创建尚不存在的报告目录或任何文件。
func TestCLIAuditNullInvariantCreatesNoStore(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", nullInvariantInput)
	store := filepath.Join(work, "nested", "reports")

	cmd := exec.Command(bin, "audit", "--input", input, "--store", store)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("audit must fail, output:\n%s", out)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("failure must not create the report store: %v", err)
	}
}

// 目录中已有报告时，一次失败的提交必须保持原有内容原样不变。
func TestCLIAuditNullInvariantKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	validInput := writeInput(t, work, "valid.json", validInvariantInput)
	store := filepath.Join(work, "reports")

	// Produce one real report first.
	setup := exec.Command(bin, "audit", "--input", validInput, "--store", store)
	if out, err := setup.CombinedOutput(); err != nil {
		t.Fatalf("valid audit setup failed: %v\n%s", err, out)
	}
	before, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("setup expected 1 report, got %d: %v", len(before), before)
	}
	existingPath := filepath.Join(store, before[0])
	existingBytes, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}

	// The invalid submission must fail and change nothing.
	badInput := writeInput(t, work, "bad.json", nullInvariantInput)
	fail := exec.Command(bin, "audit", "--input", badInput, "--store", store)
	if out, err := fail.CombinedOutput(); err == nil {
		t.Fatalf("invalid audit must fail, output:\n%s", out)
	}
	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("failure changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("failure modified the existing report")
	}
}

// 合法的 false 输入仍然产生缺陷报告（回归保护）。
func TestCLIAuditExplicitFalseStillReportsDefect(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", validInvariantInput)
	store := filepath.Join(work, "reports")

	cmd := exec.Command(bin, "audit", "--input", input, "--store", store)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("explicit false must be a valid defect report: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "发现缺陷") {
		t.Fatalf("stdout must contain the defect report:\n%s", stdout.String())
	}
}

func listFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
