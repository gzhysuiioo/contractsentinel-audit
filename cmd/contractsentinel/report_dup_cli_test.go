package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 report / diff 读取已保存报告时对
// “重复 JSON 成员”的拒绝：归档任何对象（规则、缺陷记录、产物信息、顶层
// 对象及未知嵌套对象）重复同名成员，即使最后一个值使报告标识与缺陷归属
// 校验成立，也必须把整份报告判为归档损坏——非零退出、原因进 stderr（含
// 报告标识、成员名、所在对象；在规则/缺陷数组中给出位置与规则标识），
// stdout 不出现完整或部分报告，且原文件原样保留。

// auditOneReport 通过真实 audit 命令落盘一份合法的混合状态报告，返回其标识。
func auditOneReport(t *testing.T, bin, work, store string) string {
	t.Helper()
	input := writeStructInput(t, work, "in.json", mixedCheckInput(mixedArtifactHash(t)))
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit must succeed: %s", stderr)
	}
	return decodeReport(t, stdout).ReportID
}

// injectArchiveDuplicate reads the archive named by id, applies the textual
// replacement once, and writes it back. All replacements repeat a member
// while leaving the last value identical to the legal one.
func injectArchiveDuplicate(t *testing.T, store, id, old, new string) {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	if !strings.Contains(doc, old) {
		t.Fatalf("test setup: archive does not contain %q", old)
	}
	doc = strings.Replace(doc, old, new, 1)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runCLIDiff-like helpers already exist; assert the full failure contract here.
func assertDupFailure(t *testing.T, stdout, stderr string, code int, id string, want ...string) {
	t.Helper()
	if code == 0 {
		t.Fatal("an archive with a duplicate JSON member must exit non-zero")
	}
	if !strings.Contains(strings.ToLower(stderr), "duplicate") {
		t.Fatalf("stderr must state that a member is duplicated:\n%s", stderr)
	}
	if !strings.Contains(stderr, "corrupt") {
		t.Fatalf("stderr must classify the archive as corrupt:\n%s", stderr)
	}
	if !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the report id %q:\n%s", id, stderr)
	}
	for _, w := range want {
		if !strings.Contains(stderr, w) {
			t.Fatalf("stderr must contain %q:\n%s", w, stderr)
		}
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- report：规则中先“发现缺陷”再“通过”，最后一个值使标识仍一致，仍须拒绝 ---

func TestCLIReportDuplicateRuleStatusRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveDuplicate(t, store, id,
		`"status":"`+contractsentinel.StatusPass+`"`,
		`"status":"`+contractsentinel.StatusDefect+`","status":"`+contractsentinel.StatusPass+`"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertDupFailure(t, stdout, stderr, code, id, `"status"`, `rule "rule-pass"`, "rules[0]")

	// 原文件必须原样保留。
	data, err := os.ReadFile(filepath.Join(store, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"status":"`+contractsentinel.StatusDefect+`","status":"`+contractsentinel.StatusPass+`"`) {
		t.Fatal("failed report read must leave the corrupt archive untouched")
	}
}

// --- report：两个值完全相同也不接受 ---

func TestCLIReportDuplicateEqualValuesRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveDuplicate(t, store, id,
		`"id":"rule-defect"`,
		`"id":"rule-defect","id":"rule-defect"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertDupFailure(t, stdout, stderr, code, id, `"id"`, `rule "rule-defect"`, "rules[1]")
}

// --- report：缺陷记录数组中的重复成员，给出位置与涉及规则 ---

func TestCLIReportDuplicateFindingMemberRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveDuplicate(t, store, id,
		`"ruleId":"rule-defect"`,
		`"ruleId":"rule-defect","ruleId":"rule-defect"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertDupFailure(t, stdout, stderr, code, id, `"ruleId"`, `finding for rule "rule-defect"`, "findings[0]")
}

// --- report：产物对象与顶层对象重复成员 ---

func TestCLIReportDuplicateArtifactMemberRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveDuplicate(t, store, id,
		`"name":"Vault"`,
		`"name":"Other","name":"Vault"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertDupFailure(t, stdout, stderr, code, id, `"name"`, "the artifact object")
}

func TestCLIReportDuplicateTopLevelMemberRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveDuplicate(t, store, id,
		`"reportId":"`+id+`"`,
		`"reportId":"`+id+`","reportId":"`+id+`"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertDupFailure(t, stdout, stderr, code, id, `"reportId"`, "the top-level object")
}

// --- report：未知字段的嵌套对象重复成员同样拒绝 ---

func TestCLIReportDuplicateNestedUnknownFieldRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveDuplicate(t, store, id,
		`{"reportId"`,
		`{"mystery":{"a":1,"a":2},"reportId"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertDupFailure(t, stdout, stderr, code, id, `"a"`, ".mystery")
}

// --- 错误分类不变：重复成员是损坏；不存在与标识不合法仍是各自的含义 ---

func TestCLIReportDuplicateDoesNotMaskOtherErrors(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveDuplicate(t, store, id,
		`"status":"`+contractsentinel.StatusPass+`"`,
		`"status":"`+contractsentinel.StatusPass+`","status":"`+contractsentinel.StatusPass+`"`)

	if _, stderr, code := runCLIReport(t, bin, store, id); code == 0 {
		t.Fatal("duplicate archive must fail")
	} else if !strings.Contains(stderr, "corrupt") {
		t.Fatalf("duplicate archive is corrupt, got: %s", stderr)
	}
	if _, stderr, code := runCLIReport(t, bin, store, strings.Repeat("0", 64)); code == 0 {
		t.Fatal("missing report must fail")
	} else if !strings.Contains(stderr, "not found") {
		t.Fatalf("missing report keeps its not-found meaning, got: %s", stderr)
	}
	if _, stderr, code := runCLIReport(t, bin, store, "xyz"); code == 0 {
		t.Fatal("invalid id must fail")
	} else if !strings.Contains(stderr, "invalid report id") {
		t.Fatalf("invalid id keeps its meaning, got: %s", stderr)
	}
}

// --- diff：任一侧归档含重复成员，整体失败且不输出局部差异 ---

func TestCLIDiffDuplicateMemberEitherSideFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := mixedArtifactHash(t)
	artifact := mixedCheckArtifact()
	beforeReport := auditDiffReport(t, bin, work, store, "before.json", artifact, diffRules(), diffBeforeChecks(hash))
	afterReport := auditDiffReport(t, bin, work, store, "after.json", artifact, diffRules(), diffAfterChecks(hash))
	beforeID := beforeReport.ReportID
	afterID := afterReport.ReportID

	// Keep clean bytes of both sides in separate setup stores, so one side can
	// be restored while the other is corrupted (re-auditing into the same store
	// would itself fail against the corrupt existing archive).
	cleanBefore := mustMarshalStoreReport(t, bin, filepath.Join(work, "clean-b"), "before.json", artifact, hash, "before")
	cleanAfter := mustMarshalStoreReport(t, bin, filepath.Join(work, "clean-a"), "after.json", artifact, hash, "after")

	dupStatus := func(data []byte) []byte {
		old := `"status":"` + contractsentinel.StatusPass + `"`
		new := `"status":"` + contractsentinel.StatusDefect + `","status":"` + contractsentinel.StatusPass + `"`
		out := bytes.Replace(data, []byte(old), []byte(new), 1)
		if bytes.Equal(out, data) {
			t.Fatal("test setup: replacement did not change the archive")
		}
		return out
	}
	writeArchive := func(id string, data []byte) {
		if err := os.WriteFile(filepath.Join(store, id+".json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 第二份损坏。
	writeArchive(afterID, dupStatus(cleanAfter))
	stdout, stderr, code := runCLIDiff(t, bin, store, beforeID, afterID)
	assertDupFailure(t, stdout, stderr, code, afterID, `"status"`, "rules[")
	for _, marker := range []string{`"results"`, `"summary"`, contractsentinel.ChangeNewDefect, contractsentinel.StatusUnchecked} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a partial diff %q:\n%s", marker, stdout)
		}
	}

	// 第一份损坏、第二份恢复。
	writeArchive(afterID, cleanAfter)
	writeArchive(beforeID, dupStatus(cleanBefore))
	stdout, stderr, code = runCLIDiff(t, bin, store, beforeID, afterID)
	assertDupFailure(t, stdout, stderr, code, beforeID, `"status"`)
	if stdout != "" {
		t.Fatalf("stdout must stay empty on failure:\n%s", stdout)
	}

	// 失败的比较不修复、不覆盖任何一侧归档。
	if kept, err := os.ReadFile(filepath.Join(store, beforeID+".json")); err != nil || !bytes.Equal(kept, dupStatus(cleanBefore)) {
		t.Fatalf("failed diff must leave the corrupt first archive untouched: %v", err)
	}
	if kept, err := os.ReadFile(filepath.Join(store, afterID+".json")); err != nil || !bytes.Equal(kept, cleanAfter) {
		t.Fatalf("failed diff must leave the restored second archive untouched: %v", err)
	}
}

// mustMarshalStoreReport audits one side into a dedicated fresh store and
// returns the archived bytes, so tests can restore main-store archives.
func mustMarshalStoreReport(t *testing.T, bin, store, name string, artifact cliWireArtifact, hash, side string) []byte {
	t.Helper()
	checks := diffAfterChecks(hash)
	if side == "before" {
		checks = diffBeforeChecks(hash)
	}
	r := auditDiffReport(t, bin, t.TempDir(), store, name, artifact, diffRules(), checks)
	data, err := os.ReadFile(filepath.Join(store, r.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// --- audit 保存遇到同标识已有归档含重复成员：不能当成保存成功，原文件保留 ---

func TestCLIAuditDuplicateExistingArchiveFailsAndKeepsFile(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	path := filepath.Join(store, id+".json")
	injectArchiveDuplicate(t, store, id,
		`"status":"`+contractsentinel.StatusPass+`"`,
		`"status":"`+contractsentinel.StatusDefect+`","status":"`+contractsentinel.StatusPass+`"`)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 用完全相同的合法提交再审计一次：同标识归档已损坏，必须失败。
	input := writeStructInput(t, work, "again.json", mixedCheckInput(mixedArtifactHash(t)))
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("audit against a duplicate-member existing archive must exit non-zero")
	}
	if !strings.Contains(strings.ToLower(stderr), "duplicate") || !strings.Contains(stderr, "corrupt") {
		t.Fatalf("stderr must report duplicate-member corruption:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("failed audit must print nothing to stdout:\n%s", stdout)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must be kept: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed audit must leave the corrupt archive untouched")
	}
}

// --- report：合法大数扩展值不能使重复成员错误丢掉缺陷记录的规则归属 ---

func TestCLIReportDuplicateFindingBigNumberStillNamesRule(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveDuplicate(t, store, id,
		`"ruleId":"rule-defect"`,
		`"ruleId":"rule-defect","ruleId":"rule-defect"`)
	// 顶层扩展里的合法大数（超出 float64）不得改变归档损坏的归属信息。
	injectArchiveDuplicate(t, store, id,
		`{"reportId"`,
		`{"extra":{"tolerance":1e1000},"reportId"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertDupFailure(t, stdout, stderr, code, id, `"ruleId"`, `finding for rule "rule-defect"`, "findings[0]")

	// 原文件必须原样保留。
	data, err := os.ReadFile(filepath.Join(store, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"ruleId":"rule-defect","ruleId":"rule-defect"`) {
		t.Fatal("failed report read must leave the corrupt archive untouched")
	}
}
