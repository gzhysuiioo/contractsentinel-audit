package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护“归档读取拒绝重复 JSON 成员”：
// 在原本通过的规则里先写一个 "status":"发现缺陷"、再保留原来的
// "status":"通过"，解码只保留最后一个值，报告标识与缺陷归属校验都能对上，
// 但 report/diff/audit 任何一条读取路径都必须把这份归档当作损坏整份拒绝——
// 非零退出、原因进 stderr、stdout 不出现完整或部分报告，且原文件字节不动。

// injectDupStatusBefore 在归档 JSON 中 ruleID 这条规则的既有 status 成员前
// 插入一个额外的 status 成员。解码器只保留最后一个值，因此解码内容与报告
// 标识不变；重复成员本身就是损坏。
func injectDupStatusBefore(t *testing.T, path, ruleID, status string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	anchor := `"id":"` + ruleID + `"`
	idx := strings.Index(doc, anchor)
	if idx < 0 {
		t.Fatalf("test setup: rule %q not found in %s", ruleID, doc)
	}
	at := strings.Index(doc[idx:], `"status":"`)
	if at < 0 {
		t.Fatalf("test setup: status member not found after %q", anchor)
	}
	at += idx
	dup := doc[:at] + `"status":"` + status + `",` + doc[at:]
	if err := os.WriteFile(path, []byte(dup), 0o644); err != nil {
		t.Fatal(err)
	}
}

// auditOneReport 落盘一份合法混合报告并返回其标识与归档路径。
func auditOneReport(t *testing.T, bin, work, store string) (string, string) {
	t.Helper()
	input := writeStructInput(t, work, "in.json", mixedCheckInput(mixedArtifactHash(t)))
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit must succeed, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)
	return report.ReportID, filepath.Join(store, report.ReportID+".json")
}

// report 查询：归档任一对象内出现重复成员 => 非零退出、stderr 点名报告标识、
// 重复成员与所在规则，stdout 完全空白，归档字节保持不动。
func TestCLIReportDuplicateRuleStatusRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id, path := auditOneReport(t, bin, work, store)

	// 在 rule-pass（结论为通过）里先插入一个冲突的“发现缺陷”。
	injectDupStatusBefore(t, path, "rule-pass", contractsentinel.StatusDefect)
	corrupt, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code == 0 {
		t.Fatal("report with a duplicate member must exit non-zero")
	}
	if !strings.Contains(strings.ToLower(stderr), "duplicate") {
		t.Fatalf("stderr must state that a member is duplicated:\n%s", stderr)
	}
	for _, want := range []string{id, `"status"`, `rule "rule-pass"`, "rules[0]"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must contain %q:\n%s", want, stderr)
		}
	}
	assertNoPartialReport(t, stdout)

	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must not be deleted: %v", err)
	}
	if string(kept) != string(corrupt) {
		t.Fatal("failed report read must not rewrite or repair the archive")
	}
}

// 缺陷记录对象内的重复成员同样整份拒绝，并点名涉及哪条规则。
func TestCLIReportDuplicateFindingMemberRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id, path := auditOneReport(t, bin, work, store)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	at := strings.Index(doc, `"evidence":"`)
	if at < 0 {
		t.Fatal("test setup: evidence member not found")
	}
	dup := doc[:at] + `"evidence":"伪造的另一份证据",` + doc[at:]
	if err := os.WriteFile(path, []byte(dup), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code == 0 {
		t.Fatal("report with a duplicate finding member must exit non-zero")
	}
	for _, want := range []string{`"evidence"`, `rule "rule-defect"`, "findings[0]"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must contain %q:\n%s", want, stderr)
		}
	}
	assertNoPartialReport(t, stdout)
}

// diff 任一侧归档含重复成员：非零退出、原因进 stderr、stdout 不出现局部
// 差异，也不把读取失败降级成“未检查”。
func TestCLIDiffDuplicateMemberArchiveRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	good := auditDiffReport(t, bin, work, store, "good.json", artifact, rules, diffBeforeChecks(hash))
	bad := auditDiffReport(t, bin, work, store, "bad.json", artifact, rules, diffAfterChecks(hash))

	badPath := filepath.Join(store, bad.ReportID+".json")
	injectDupStatusBefore(t, badPath, "e-stable-pass", contractsentinel.StatusDefect)
	corrupt, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"duplicate on the after side", good.ReportID, bad.ReportID},
		{"duplicate on the before side", bad.ReportID, good.ReportID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCLIDiff(t, bin, store, tc.before, tc.after)
			if code == 0 {
				t.Fatal("diff with a duplicate-member archive must exit non-zero")
			}
			if !strings.Contains(strings.ToLower(stderr), "duplicate") {
				t.Fatalf("stderr must state that a member is duplicated:\n%s", stderr)
			}
			if !strings.Contains(stderr, bad.ReportID) {
				t.Fatalf("stderr must name the corrupt report id:\n%s", stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
			}
			for _, marker := range []string{`"results"`, `"summary"`, contractsentinel.StatusUnchecked} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak %q on failure:\n%s", marker, stdout)
				}
			}
		})
	}
	kept, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != string(corrupt) {
		t.Fatal("failed diff must not modify the corrupt archive")
	}
}

// audit 保存遇到同标识的既有归档含重复成员：不能当成保存成功，原文件保留。
func TestCLIAuditExistingDuplicateArchiveNotSuccess(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	input := writeStructInput(t, work, "in.json", mixedCheckInput(mixedArtifactHash(t)))

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit must succeed, exit=%d stderr=%s", code, stderr)
	}
	id := decodeReport(t, stdout).ReportID
	path := filepath.Join(store, id+".json")
	injectDupStatusBefore(t, path, "rule-pass", contractsentinel.StatusDefect)
	corrupt, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 同一提交的再次保存：既有归档虽解码一致，但含重复成员，必须失败。
	stdout, stderr, code = runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("save against an existing duplicate-member archive must exit non-zero")
	}
	if !strings.Contains(strings.ToLower(stderr), "duplicate") {
		t.Fatalf("stderr must state that a member is duplicated:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)

	names, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != id+".json" {
		t.Fatalf("failed save changed the store contents: %v", names)
	}
	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != string(corrupt) {
		t.Fatal("failed save must not delete, repair or overwrite the existing archive")
	}
}

// 合法归档不受新校验影响：report 查询照常输出完整报告。
func TestCLIReportLegalArchiveStillLoads(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id, _ := auditOneReport(t, bin, work, store)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("legal archive must still load, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)
	if report.ReportID != id {
		t.Fatalf("report id = %q, want %q", report.ReportID, id)
	}
}
