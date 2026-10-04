package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件在真实命令行进程边界上回归保护 audit 的 requiresABI 布尔规则：规则
// 对象出现正式 requiresABI 成员时，值必须是 JSON true/false；null 或其他类型
// 让整份提交失败，原因进 stderr 并点名规则，stdout 不出现报告，尚不存在的报告
// 目录不被创建，已有归档保持原样。省略成员与显式 false 的合法行为不受影响。

// requiresABIInput 拼一份提交，requiresABI 片段由调用方原样给出（空串表示省略
// 该成员）；withABI 决定产物是否携带非空 ABI。
func requiresABIInput(requiresABIPart string, withABI bool) string {
	artifact := `{"name":"Vault","bytecode":"0x1","source":"Vault.sol"}`
	if withABI {
		artifact = `{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`
	}
	return `{"artifact":` + artifact + `,"rules":[{"id":"r1","kind":"static","severity":"high","invariant":"inv",` +
		requiresABIPart + `"version":"1.0.0"}],"invariants":{"inv":true}}`
}

// null requiresABI：非零退出、stderr 点名规则与布尔要求、stdout 无报告。
func TestCLIAuditNullRequiresABIFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", requiresABIInput(`"requiresABI":null,`, false))
	store := filepath.Join(work, "nested", "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("audit must exit non-zero for a null requiresABI value")
	}
	assertNoPartialReport(t, stdout)
	if !strings.Contains(stderr, "r1") {
		t.Fatalf("stderr must name the rule:\n%s", stderr)
	}
	if !strings.Contains(stderr, "requiresABI") || !strings.Contains(stderr, "boolean") {
		t.Fatalf("stderr must say requiresABI must be a boolean:\n%s", stderr)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// 非布尔类型（字符串、数字、对象、数组）即使产物已有 ABI 也整份拒绝。
func TestCLIAuditNonBooleanRequiresABIRejectedEvenWithABI(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	for _, val := range []string{`"yes"`, `1`, `{"v":true}`, `[true]`} {
		input := writeInput(t, work, "in.json", requiresABIInput(`"requiresABI":`+val+`,`, true))
		store := filepath.Join(work, "reports")
		stdout, stderr, code := runCLIAudit(t, bin, input, store)
		if code == 0 {
			t.Fatalf("requiresABI=%s must exit non-zero", val)
		}
		assertNoPartialReport(t, stdout)
		if !strings.Contains(stderr, "r1") || !strings.Contains(stderr, "boolean") {
			t.Fatalf("requiresABI=%s: stderr must name the rule and the boolean requirement:\n%s", val, stderr)
		}
		if _, err := os.Stat(store); !os.IsNotExist(err) {
			t.Fatalf("requiresABI=%s: rejected submission must not create the store: %v", val, err)
		}
	}
}

// 已有归档时一次非法提交不得新增或改写任何报告。
func TestCLIAuditNullRequiresABIKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	good := writeInput(t, work, "good.json", requiresABIInput(`"requiresABI":false,`, false))
	if _, stderr, code := runCLIAudit(t, bin, good, store); code != 0 {
		t.Fatalf("valid setup audit must succeed: %s", stderr)
	}
	before, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("setup expected 1 report, got %v", before)
	}
	existingPath := filepath.Join(store, before[0])
	existingBytes, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}

	bad := writeInput(t, work, "bad.json", requiresABIInput(`"requiresABI":null,`, false))
	if _, _, code := runCLIAudit(t, bin, bad, store); code == 0 {
		t.Fatal("null requiresABI must exit non-zero")
	}
	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("rejected submission changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("rejected submission modified the existing report")
	}
}

// 省略成员与显式 false 在没有 ABI 时都合法，且报告标识一致；显式 true 在
// 缺少 ABI 时继续整份拒绝。
func TestCLIAuditRequiresABILegalFormsUnchanged(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	omitted := writeInput(t, work, "omitted.json", requiresABIInput("", false))
	stdoutOmitted, stderr, code := runCLIAudit(t, bin, omitted, filepath.Join(work, "s1"))
	if code != 0 {
		t.Fatalf("omitted requiresABI must succeed without an ABI: %s", stderr)
	}
	explicitFalse := writeInput(t, work, "false.json", requiresABIInput(`"requiresABI":false,`, false))
	stdoutFalse, stderr, code := runCLIAudit(t, bin, explicitFalse, filepath.Join(work, "s2"))
	if code != 0 {
		t.Fatalf("explicit false must succeed without an ABI: %s", stderr)
	}
	if decodeReport(t, stdoutOmitted).ReportID != decodeReport(t, stdoutFalse).ReportID {
		t.Fatal("omitted and explicit-false requiresABI must keep the same report id")
	}

	explicitTrue := writeInput(t, work, "true.json", requiresABIInput(`"requiresABI":true,`, false))
	stdout, stderr, code := runCLIAudit(t, bin, explicitTrue, filepath.Join(work, "s3"))
	if code == 0 {
		t.Fatal("explicit true without an ABI must keep refusing the submission")
	}
	assertNoPartialReport(t, stdout)
	if !strings.Contains(stderr, "r1") || !strings.Contains(stderr, "ABI") {
		t.Fatalf("stderr must name the rule and the ABI requirement:\n%s", stderr)
	}
}
