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

// 本文件在真实命令行进程边界上回归保护 audit 提交侧的固定字段大小写规则：
// 只有约定拼写的字段参与审计，检查记录里的 "StAtus" 这类大小写变体只是扩展
// 信息，出现在正式 status 之前或之后、携带任意合法 JSON 值都不能改写结论；
// 但扩展信息允许存在，合法提交照常落盘且报告标识不变。缺少正式 status、或
// 正式 status 为不支持的状态/错误类型时，即使旁边的 StAtus 写着“通过”，也
// 必须整份拒绝：非零退出、原因进 stderr 且点名对应规则，stdout 不输出完整或
// 部分报告，不创建存储目录、不新增或改写已有报告。

// compactMixedInput 序列化与 mixedCheckInput 相同的合法提交（紧凑 JSON），
// 返回的文本可被精确地做成员级改写。
func compactMixedInput(t *testing.T, hash string) []byte {
	t.Helper()
	data, err := json.Marshal(mixedCheckInput(hash))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// rewriteInputText 把提交文本中的 old 替换为 new（恰好一次），写入文件。
func rewriteInputText(t *testing.T, dir, name string, data []byte, old, new string) string {
	t.Helper()
	doc := string(data)
	if !strings.Contains(doc, old) {
		t.Fatalf("test setup: submission does not contain %q", old)
	}
	doc = strings.Replace(doc, old, new, 1)
	return writeInput(t, dir, name, doc)
}

// assertAuditRejected 断言一次提交被整份拒绝的完整契约：非零退出、stderr
// 包含所有要求片段、stdout 完全为空。
func assertAuditRejected(t *testing.T, bin, input, store string, wantStderr ...string) {
	t.Helper()
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("the submission must exit non-zero")
	}
	for _, want := range wantStderr {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must contain %q:\n%s", want, stderr)
		}
	}
	assertNoPartialReport(t, stdout)
}

// --- 正式 status=发现缺陷 + StAtus=通过：两种成员顺序都保留缺陷、标识不变 ---

func TestCLIAuditCaseVariantStatusKeepsDefect(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	clean := compactMixedInput(t, hash)
	cleanPath := writeInput(t, work, "clean.json", string(clean))
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, cleanPath, store)
	if code != 0 {
		t.Fatalf("clean submission must succeed: %s", stderr)
	}
	want := decodeReport(t, stdout)

	old := `"status":"` + contractsentinel.StatusDefect + `"`
	for _, tc := range []struct {
		name string
		new  string
	}{
		{"variant after formal status", old + `,"StAtus":"` + contractsentinel.StatusPass + `"`},
		{"variant before formal status", `"StAtus":"` + contractsentinel.StatusPass + `",` + old},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := rewriteInputText(t, t.TempDir(), "in.json", clean, old, tc.new)
			out, gotErr, gotCode := runCLIAudit(t, bin, in, store)
			if gotCode != 0 {
				t.Fatalf("an extension member must not reject a legal submission: %s", gotErr)
			}
			got := decodeReport(t, out)

			if got.ReportID != want.ReportID {
				t.Fatalf("extension member changed the report id:\n got %s\nwant %s", got.ReportID, want.ReportID)
			}
			statusByID := map[string]string{}
			for _, r := range got.Rules {
				statusByID[r.ID] = r.Status
			}
			if statusByID["rule-defect"] != contractsentinel.StatusDefect {
				t.Fatalf("rule-defect must stay 发现缺陷, got %q", statusByID["rule-defect"])
			}
			if statusByID["rule-pass"] != contractsentinel.StatusPass {
				t.Fatalf("rule-pass must stay 通过, got %q", statusByID["rule-pass"])
			}
			if len(got.Findings) != 1 {
				t.Fatalf("exactly one defect must survive, got %+v", got.Findings)
			}
			f := got.Findings[0]
			if f.RuleID != "rule-defect" || f.Evidence != defectNote ||
				f.ArtifactHash != hash || f.Version != "2.0.1" {
				t.Fatalf("finding binding/evidence not preserved: %+v", f)
			}
		})
	}
}

// --- 扩展成员携带不同类型的合法 JSON 值，前后位置都不改变结论 ---

func TestCLIAuditCaseVariantAnyTypeIgnored(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	clean := compactMixedInput(t, hash)
	old := `"status":"` + contractsentinel.StatusDefect + `"`
	for _, val := range []string{`"通过"`, `123`, `true`, `null`, `[1,2]`, `{"k":"v"}`} {
		for _, pos := range []string{"after", "before"} {
			var injected string
			if pos == "after" {
				injected = old + `,"StAtus":` + val
			} else {
				injected = `"StAtus":` + val + `,` + old
			}
			in := rewriteInputText(t, work, "in.json", clean, old, injected)
			out, stderr, code := runCLIAudit(t, bin, in, filepath.Join(work, "store-"+pos))
			if code != 0 {
				t.Fatalf("ext=%s pos=%s must be ignored, not rejected: %s", val, pos, stderr)
			}
			got := decodeReport(t, out)
			if len(got.Findings) != 1 || got.Findings[0].RuleID != "rule-defect" {
				t.Fatalf("ext=%s pos=%s changed the conclusion: %+v", val, pos, got.Findings)
			}
		}
	}
}

// --- 缺少正式 status，即使旁边的 StAtus=通过，也整份拒绝、不建目录 ---

func TestCLIAuditMissingFormalStatusRejectedNoStore(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	clean := compactMixedInput(t, hash)
	old := `"status":"` + contractsentinel.StatusDefect + `"`

	for _, tc := range []struct {
		name string
		new  string
	}{
		{"variant after missing formal", `"StAtus":"` + contractsentinel.StatusPass + `","note":"x"`},
		{"variant before missing formal", `"note":"x","StAtus":"` + contractsentinel.StatusPass + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 用 StAtus 顶替正式 status（连同 note 一起改写，避免悬空逗号）。
			oldFull := old + `,"note":` + jsonString(defectNote)
			in := rewriteInputText(t, work, "bad.json", clean, oldFull, tc.new)
			store := filepath.Join(work, "nested", "missing-store-"+tc.name)
			assertAuditRejected(t, bin, in, store, "rule-defect", "status")
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("rejected submission must not create the store directory: %v", err)
			}
		})
	}
}

// jsonString 编码一个 JSON 字符串字面量。
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// --- 正式 status 为不支持的值：StAtus 不能提供合法状态顶替 ---

func TestCLIAuditUnsupportedFormalStatusRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	clean := compactMixedInput(t, hash)
	old := `"status":"` + contractsentinel.StatusPass + `"` // 仅 rule-pass 为通过
	for _, tc := range []struct {
		name string
		new  string
	}{
		{"variant after bogus", `"status":"bogus","StAtus":"` + contractsentinel.StatusPass + `"`},
		{"variant before bogus", `"StAtus":"` + contractsentinel.StatusPass + `","status":"bogus"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := rewriteInputText(t, work, "bad.json", clean, old, tc.new)
			store := filepath.Join(work, "reports-"+tc.name)
			assertAuditRejected(t, bin, in, store, "rule-pass", "unknown status bogus")
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("rejected submission must not create the store: %v", err)
			}
		})
	}
}

// --- 正式 status 类型错误（数字）：不能被相邻 StAtus 掩盖 ---

func TestCLIAuditNonStringFormalStatusRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	clean := compactMixedInput(t, hash)
	old := `"status":"` + contractsentinel.StatusPass + `"`
	patched := `"StAtus":"` + contractsentinel.StatusPass + `","status":123`
	in := rewriteInputText(t, work, "bad.json", clean, old, patched)
	store := filepath.Join(work, "nested", "missing-store")
	assertAuditRejected(t, bin, in, store, "rule-pass", "string")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store: %v", err)
	}
}

// --- 名称两侧带空格的成员不能替代正式 status ---

func TestCLIAuditPaddedStatusNameRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	clean := compactMixedInput(t, hash)
	old := `"status":"` + contractsentinel.StatusPass + `"`
	patched := `" status ":"` + contractsentinel.StatusPass + `"`
	in := rewriteInputText(t, work, "bad.json", clean, old, patched)
	store := filepath.Join(work, "nested", "missing-store")
	assertAuditRejected(t, bin, in, store, "rule-pass", "status")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store: %v", err)
	}
}

// --- 转义写出的 status 仍是正式字段，合法提交照常成功 ---

func TestCLIAuditEscapedFormalStatusAccepted(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	clean := compactMixedInput(t, hash)
	old := `"status":"` + contractsentinel.StatusPass + `"`
	// 0x73 == 's'：解码后仍是 "status"。
	patched := `"` + `\u0073` + `tatus":"` + contractsentinel.StatusPass + `"`
	in := rewriteInputText(t, work, "in.json", clean, old, patched)
	store := filepath.Join(work, "reports")
	stdout, stderr, code := runCLIAudit(t, bin, in, store)
	if code != 0 {
		t.Fatalf("an escaped spelling of status must be the formal field: %s", stderr)
	}
	got := decodeReport(t, stdout)
	statusByID := map[string]string{}
	for _, r := range got.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["rule-pass"] != contractsentinel.StatusPass {
		t.Fatalf("rule-pass must read 通过 from the escaped formal field: %+v", statusByID)
	}
}

// --- 拒绝提交不得新增或改写存储目录里的已有报告 ---

func TestCLIAuditCaseVariantRejectionKeepsExistingReports(t *testing.T) {
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
	existing := filepath.Join(store, before[0])
	existingBytes, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}

	// 再提交一份正式 status 缺失、只带 StAtus 的提交。
	hash := mixedArtifactHash(t)
	clean := compactMixedInput(t, hash)
	oldFull := `"status":"` + contractsentinel.StatusDefect + `","note":` + jsonString(defectNote)
	bad := rewriteInputText(t, work, "bad.json", clean, oldFull,
		`"StAtus":"`+contractsentinel.StatusPass+`","note":"x"`)
	if _, _, code := runCLIAudit(t, bin, bad, store); code == 0 {
		t.Fatal("invalid submission must exit non-zero")
	}

	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("rejected submission changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("rejected submission modified the existing report bytes")
	}
}
