package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 report 读取已保存报告时的固定字段
// 大小写规则：归档中名为 "StAtus" 这类大小写变体只是扩展字段，既不覆盖
// 原有 status 的结论，也不能在原字段非法时提供合法状态顶替。合法归档按原
// 结论正常输出；确有损坏的归档非零退出、原因进 stderr、stdout 不输出完整
// 或部分报告，且归档原文保留。

// rewriteArchiveWithVariant rewrites the archive named by id so that the
// fixed status member of ruleID reads fixedStatus, injects a case-variant
// extension member carrying variantStatus right after it, and recomputes the
// report id so the archive id matches its (now illegal) content. It returns
// the new id. Rejection can then only come from report validation, never
// from the id check.
func rewriteArchiveWithVariant(t *testing.T, store, id, ruleID, fixedStatus, variantStatus string) string {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r contractsentinel.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	for i := range r.Rules {
		if r.Rules[i].ID == ruleID {
			r.Rules[i].Status = fixedStatus
		}
	}
	r.ReportID = contractsentinel.ReportID(r)
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	old := `"status":"` + fixedStatus + `"`
	doc := strings.Replace(string(out), old, old+`,"StAtus":"`+variantStatus+`"`, 1)
	if doc == string(out) {
		t.Fatalf("test setup: archive does not contain %q", old)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, r.ReportID+".json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return r.ReportID
}

// assertCorruptReadFailure 断言损坏归档的完整读取失败契约：非零退出、原因
// 进 stderr 且点名报告标识、stdout 不输出任何完整或部分报告。
func assertCorruptReadFailure(t *testing.T, stdout, stderr string, code int, id string) {
	t.Helper()
	if code == 0 {
		t.Fatal("a corrupt archive must exit non-zero")
	}
	if !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the report id %q:\n%s", id, stderr)
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- 合法缺陷报告加入 StAtus 扩展字段：两种成员顺序都读出原来的缺陷结论 ---

func TestCLIReportCaseVariantStatusKeepsOriginalConclusion(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  string
	}{
		{"variant after fixed field",
			`"status":"` + contractsentinel.StatusDefect + `","StAtus":"` + contractsentinel.StatusPass + `"`},
		{"variant before fixed field",
			`"StAtus":"` + contractsentinel.StatusPass + `","status":"` + contractsentinel.StatusDefect + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			injectArchiveDuplicate(t, store, id,
				`"status":"`+contractsentinel.StatusDefect+`"`, tc.new)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			if code != 0 {
				t.Fatalf("a case-variant extension member must not fail the read: %s", stderr)
			}
			report := decodeReport(t, stdout)
			if report.ReportID != id {
				t.Fatalf("report id not preserved: %q", report.ReportID)
			}
			statusByID := map[string]string{}
			noteByID := map[string]string{}
			for _, rule := range report.Rules {
				statusByID[rule.ID] = rule.Status
				noteByID[rule.ID] = rule.Note
			}
			if got := statusByID["rule-defect"]; got != contractsentinel.StatusDefect {
				t.Fatalf("rule-defect status = %q, want the original %q", got, contractsentinel.StatusDefect)
			}
			if got := statusByID["rule-pass"]; got != contractsentinel.StatusPass {
				t.Fatalf("rule-pass status = %q, want %q", got, contractsentinel.StatusPass)
			}
			if noteByID["rule-defect"] != defectNote {
				t.Fatalf("defect note not preserved verbatim: %q", noteByID["rule-defect"])
			}
			if len(report.Findings) != 1 || report.Findings[0].Evidence != defectNote {
				t.Fatalf("finding evidence not preserved: %+v", report.Findings)
			}
		})
	}
}

// --- 原有 status 非法：不能靠大小写变体提供合法状态让归档通过校验 ---

func TestCLIReportCaseVariantCannotLaunderInvalidStatus(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	// 原有 status 是不支持的状态，紧随的 StAtus 变体携带合法状态：归档标识
	// 与内容相符，唯一的非法之处就是原字段里的 bogus。
	id = rewriteArchiveWithVariant(t, store, id, "rule-pass", "bogus", contractsentinel.StatusPass)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCorruptReadFailure(t, stdout, stderr, code, id)

	// 归档原文保留。
	data, err := os.ReadFile(filepath.Join(store, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"status":"bogus","StAtus":"`+contractsentinel.StatusPass+`"`) {
		t.Fatal("failed report read must leave the archive untouched")
	}
}

// --- 缺少原本的 status 字段：仅提供大小写变体不能替代 ---

func TestCLIReportCaseVariantCannotReplaceMissingStatus(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	// 原字段写成空状态再提供变体：等同于缺失，变体不能顶替。
	id = rewriteArchiveWithVariant(t, store, id, "rule-pass", "", contractsentinel.StatusPass)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCorruptReadFailure(t, stdout, stderr, code, id)
}
