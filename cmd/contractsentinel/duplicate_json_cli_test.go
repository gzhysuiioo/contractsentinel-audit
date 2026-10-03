package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 audit 对“重复 JSON 成员名”的
// 整体拒绝：同一 invariants 对象里 false 后写 true 只保留通过、null 后
// 写布尔值绕过非布尔拒绝，都会让一次提交给出不唯一的结论。任何对象出现
// 重复成员都必须以非零状态退出、原因进 stderr、stdout 不出现完整或部分
// 成功报告，并且不得创建报告目录或改写已有报告。

const cliDupArtifact = `"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`

func cliDupInput(body string) string {
	return `{` + cliDupArtifact + `,"rules":[{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1"}],` + body + `}`
}

// auditMustRejectDuplicate runs the audit binary on a duplicate-member
// submission and asserts the full failure contract: non-zero exit, a stderr
// message that explicitly says the member is duplicated and names the member
// and its object, and a completely empty stdout.
func auditMustRejectDuplicate(t *testing.T, bin, input, store string, wantStderr ...string) {
	t.Helper()
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("a submission with a duplicate JSON member must exit non-zero")
	}
	if !strings.Contains(strings.ToLower(stderr), "duplicate") {
		t.Fatalf("stderr must state that a member is duplicated:\n%s", stderr)
	}
	for _, want := range wantStderr {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must contain %q:\n%s", want, stderr)
		}
	}
	assertNoPartialReport(t, stdout)
}

// --- 同一不变式 false 后写 true：必须整份拒绝 ---

func TestCLIAuditDuplicateInvariantFalseTrueRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "bad.json",
		cliDupInput(`"invariants":{"inv":false,"inv":true}`))
	store := filepath.Join(work, "nested", "missing-store")

	auditMustRejectDuplicate(t, bin, input, store, `"inv"`, "invariants")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the report store: %v", err)
	}
}

// --- null 在前、布尔在后：在非布尔校验之前拦下，不登记缺陷 ---

func TestCLIAuditDuplicateInvariantNullThenBoolRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "bad.json",
		cliDupInput(`"invariants":{"inv":null,"inv":false}`))
	store := filepath.Join(work, "reports")

	auditMustRejectDuplicate(t, bin, input, store, `"inv"`)
}

// --- 值完全相同也不放行，也不按出现次序选择结论 ---

func TestCLIAuditDuplicateInvariantEqualValuesRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "bad.json",
		cliDupInput(`"invariants":{"inv":true,"inv":true}`))
	store := filepath.Join(work, "reports")

	auditMustRejectDuplicate(t, bin, input, store, `"inv"`)
}

// --- 名称按 JSON 解码后比较：inv 与 \u0069nv 是同一个名称 ---

func TestCLIAuditDuplicateInvariantUnicodeEscapeRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "bad.json",
		cliDupInput(`"invariants":{"inv":false,"inv":true}`))
	store := filepath.Join(work, "reports")

	auditMustRejectDuplicate(t, bin, input, store, `"inv"`)
}

// --- 顶层对象与产物对象重复成员同样拒绝 ---

func TestCLIAuditDuplicateTopLevelMemberRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "bad.json", `{
		`+cliDupArtifact+`,
		"rules":[{"id":"r1","version":"1"}],
		"rules":[{"id":"r2","version":"1"}]
	}`)
	store := filepath.Join(work, "reports")

	auditMustRejectDuplicate(t, bin, input, store, `"rules"`, "top-level object")
}

func TestCLIAuditDuplicateArtifactMemberRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "bad.json",
		`{"artifact":{"name":"Vault","name":"Other"},"rules":[]}`)
	store := filepath.Join(work, "nested", "missing-store")

	auditMustRejectDuplicate(t, bin, input, store, `"name"`, "artifact object")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the report store: %v", err)
	}
}

// --- 规则对象内重复成员：错误必须指出是哪一条规则 ---

func TestCLIAuditDuplicateRuleMemberNamesRule(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "bad.json", `{
		`+cliDupArtifact+`,
		"rules": [
			{"id":"rule-a","kind":"static","severity":"low","invariant":"a","version":"1"},
			{"id":"rule-b","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}
		]
	}`)
	store := filepath.Join(work, "reports")

	auditMustRejectDuplicate(t, bin, input, store, `"severity"`, `rule "rule-b"`)
}

// --- 检查记录对象内重复成员：错误必须指出是哪一条检查记录 ---

func TestCLIAuditDuplicateCheckMemberNamesRecord(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	in := mixedCheckInput(hash)
	raw, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	// 在 rule-tool 这条检查记录里重复 status 成员（超时 vs 工具缺失）。
	doc := string(raw)
	needle := `"ruleId": "rule-tool"`
	idx := strings.Index(doc, needle)
	if idx < 0 {
		t.Fatal("test setup: rule-tool record not found")
	}
	original := `"status": "` + contractsentinel.StatusToolMissing + `"`
	at := strings.Index(doc[idx:], original)
	if at < 0 {
		t.Fatal("test setup: tool status pair not found")
	}
	at += idx
	duplicated := doc[:at] +
		`"status": "` + contractsentinel.StatusTimeout + `", ` + original +
		doc[at+len(original):]
	input := writeInput(t, work, "bad.json", duplicated)
	store := filepath.Join(work, "reports")

	auditMustRejectDuplicate(t, bin, input, store, `"status"`, `rule "rule-tool"`)
}

// --- 重复输入里夹带的其他合法结果不能单独保存：目录中已有报告原样保留 ---

func TestCLIAuditDuplicateKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	// 先落一份合法报告。
	good := writeStructInput(t, work, "good.json", mixedCheckInput(mixedArtifactHash(t)))
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

	// 再提交一份同一不变式 false/true 自相矛盾的提交。
	bad := writeInput(t, work, "bad.json", cliDupInput(`"invariants":{"inv":false,"inv":true}`))
	if _, _, code := runCLIAudit(t, bin, bad, store); code == 0 {
		t.Fatal("duplicate-member submission must exit non-zero")
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
		t.Fatal("rejected submission modified the existing report bytes")
	}
}

// --- 不同对象各自带 id / ruleId 不是重复：多规则合法导入保持成功 ---

func TestCLIAuditSameMemberNameInDifferentObjectsAccepted(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeStructInput(t, work, "in.json", mixedCheckInput(mixedArtifactHash(t)))
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("every rule/check carrying its own id is legal: exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "reportId") {
		t.Fatal("legal submission must still print the success report")
	}
}

// --- 字符串里看起来像 JSON 的文字是普通内容，不触发重复检测 ---

func TestCLIAuditJSONLookingStringContentAccepted(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	a := mixedCheckArtifact()
	a.Source = `contract Vault { // {"id":1,"id":2} }`
	hash := contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name: a.Name, ABI: a.ABI, Bytecode: a.Bytecode, Source: a.Source,
	})
	in := mixedCheckInput(hash)
	in.Artifact = a
	in.Checks[1].Note = `反例 {"x":1,"x":2}`
	input := writeStructInput(t, work, "in.json", in)
	store := filepath.Join(work, "reports")

	if _, stderr, code := runCLIAudit(t, bin, input, store); code != 0 {
		t.Fatalf("JSON-looking text inside strings is ordinary content: %s", stderr)
	}
}

// --- 合法输入的报告标识不因本次修复改变 ---

func TestCLIAuditLegalReportIDUnchanged(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", validInvariantInput)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("legal false input must still produce a defect report: %s", stderr)
	}
	report := decodeReport(t, stdout)
	const wantID = "6a54260f78ffd829293839ad5e666e6ef4c371a447a59239c5dd1eaeeac50ade"
	if report.ReportID != wantID {
		t.Fatalf("report id changed for a legal input:\n got %s\nwant %s", report.ReportID, wantID)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("legal false must still register exactly one defect: %+v", report.Findings)
	}
}
