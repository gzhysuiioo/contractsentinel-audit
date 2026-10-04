package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件在真实命令行进程边界上回归保护：规则对象里的正式 requiresABI 成员
// 一旦写成 null（或任何非布尔值），整份提交必须失败——非零退出、原因进
// stderr 并点名规则、stdout 没有报告、尚不存在的报告目录不被创建、已有
// 归档保持原样。省略 requiresABI 与显式 false 的既有行为不变。

const nullRequiresABIInput = `{
	"artifact": {"name":"Vault","abi":"","bytecode":"0x1","source":"Vault.sol"},
	"rules": [{"id":"reentrancy-guard","kind":"static","severity":"high","invariant":"no-reentrant-withdraw","requiresABI":null,"version":"1.0.0"}],
	"invariants": {"no-reentrant-withdraw": false}
}`

const falseRequiresABIInput = `{
	"artifact": {"name":"Vault","abi":"","bytecode":"0x1","source":"Vault.sol"},
	"rules": [{"id":"reentrancy-guard","kind":"static","severity":"high","invariant":"no-reentrant-withdraw","requiresABI":false,"version":"1.0.0"}],
	"invariants": {"no-reentrant-withdraw": false}
}`

// null requiresABI：非零退出、原因进 stderr 并点名规则、stdout 不出现报告。
func TestCLIAuditNullRequiresABIFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", nullRequiresABIInput)
	store := filepath.Join(work, "reports")

	cmd := exec.Command(bin, "audit", "--input", input, "--store", store)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err == nil {
		t.Fatal("audit must exit non-zero for a null requiresABI value")
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if stdout.String() != "" {
		t.Fatalf("stdout must not contain any report fragment:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "reentrancy-guard") {
		t.Fatalf("stderr must name the rule:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "requiresABI") || !strings.Contains(stderr.String(), "boolean") {
		t.Fatalf("stderr must say requiresABI must be a boolean:\n%s", stderr.String())
	}
}

// 失败时不得创建尚不存在的报告目录。
func TestCLIAuditNullRequiresABICreatesNoStore(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", nullRequiresABIInput)
	store := filepath.Join(work, "nested", "reports")

	cmd := exec.Command(bin, "audit", "--input", input, "--store", store)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("audit must fail, output:\n%s", out)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("failure must not create the report store: %v", err)
	}
}

// 目录中已有报告时，一次 null requiresABI 提交必须保持原有内容原样不变。
func TestCLIAuditNullRequiresABIKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	validInput := writeInput(t, work, "valid.json", falseRequiresABIInput)
	store := filepath.Join(work, "reports")

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

	badInput := writeInput(t, work, "bad.json", nullRequiresABIInput)
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

// 显式 false 在无 ABI 时仍然合法并产生缺陷报告（回归保护：与省略等价）。
func TestCLIAuditExplicitFalseRequiresABIStillWorks(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", falseRequiresABIInput)
	store := filepath.Join(work, "reports")

	cmd := exec.Command(bin, "audit", "--input", input, "--store", store)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("explicit false requiresABI without an ABI must stay legal: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "发现缺陷") {
		t.Fatalf("stdout must contain the defect report:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"requiresABI": false`) {
		t.Fatalf("report must record requiresABI as false:\n%s", stdout.String())
	}
}
