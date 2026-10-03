package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归“固定字段只认原有大小写写法”：归档里与
// 固定字段大小写不同（或两侧带空白）的成员只是未知扩展字段，report 读出的
// 可信内容必须只由原固定字段决定，不能随扩展成员出现的位置而变化；原字段
// 非法/缺失时，变体也不能顶替。diff 读取同一归档时使用一致含义。

// injectArchiveText reads the archive named by id, applies a textual
// replacement once (any mutation, not just a member duplication), and writes
// it back unchanged otherwise.
func injectArchiveText(t *testing.T, store, id, old, new string) {
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

// --- report：缺陷规则带扩展 StAtus=通过，读出的仍是原缺陷结论 ---

func TestCLIReportCaseVariantStatusKeepsDefect(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)

	// 在规则的固定 status 后追加一个仅大小写不同的扩展成员，取值“通过”。
	injectArchiveText(t, store, id,
		`"status":"`+contractsentinel.StatusDefect+`"`,
		`"status":"`+contractsentinel.StatusDefect+`","StAtus":"`+contractsentinel.StatusPass+`"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("a case-variant extension must keep the report legal: %s", stderr)
	}
	if stderr != "" {
		t.Fatalf("a legal read must be silent on stderr, got: %s", stderr)
	}
	report := decodeReport(t, stdout)
	if report.ReportID != id {
		t.Fatalf("report id must stay %q, got %q", id, report.ReportID)
	}
	found := false
	for _, raw := range jsonRuleStatuses(t, stdout) {
		if raw["id"] == "rule-defect" {
			found = true
			if raw["status"] != contractsentinel.StatusDefect {
				t.Fatalf("defect conclusion overridden by StAtus: status=%q", raw["status"])
			}
		}
	}
	if !found {
		t.Fatal("rule-defect missing from output")
	}
	// 缺陷记录必须原样保留，证据/哈希/版本不变。
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "rule-defect" {
		t.Fatalf("original defect finding must stay: %+v", report.Findings)
	}

	// 扩展写在固定成员之前，必须读出同一份报告（标识不变）。
	injectArchiveText(t, store, id,
		`"status":"`+contractsentinel.StatusDefect+`","StAtus":"`+contractsentinel.StatusPass+`"`,
		`"StAtus":"`+contractsentinel.StatusPass+`","status":"`+contractsentinel.StatusDefect+`"`)
	stdout2, stderr2, code2 := runCLIReport(t, bin, store, id)
	if code2 != 0 {
		t.Fatalf("extension position must not matter: %s", stderr2)
	}
	if stdout2 != stdout {
		t.Fatal("moving the extension member changed the printed report")
	}
}

// jsonRuleStatuses extracts the id/status pairs from a printed report without
// depending on internal structs.
func jsonRuleStatuses(t *testing.T, raw string) []map[string]string {
	t.Helper()
	var doc struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("output is not a report: %v\n%s", err, raw)
	}
	out := make([]map[string]string, 0, len(doc.Rules))
	for _, r := range doc.Rules {
		m := map[string]string{}
		for k, v := range r {
			if s, ok := v.(string); ok {
				m[k] = s
			}
		}
		out = append(out, m)
	}
	return out
}

// --- report：两侧带空白的成员名不顶替固定字段 ---

func TestCLIReportWhitespacePaddedVariantIgnored(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveText(t, store, id,
		`"status":"`+contractsentinel.StatusDefect+`"`,
		`" status ":"`+contractsentinel.StatusPass+`","status":"`+contractsentinel.StatusDefect+`"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("whitespace-padded variant must be ignored: %s", stderr)
	}
	report := decodeReport(t, stdout)
	var gotStatus string
	for _, rl := range report.Rules {
		if rl.ID == "rule-defect" {
			gotStatus = rl.Status
		}
	}
	if gotStatus != contractsentinel.StatusDefect {
		t.Fatalf("padded-name member overrode status: %q", gotStatus)
	}
}

// --- report：原固定状态非法时，扩展不能提供合法状态蒙混过关（非零退出）---

func TestCLIReportBadFixedStatusNotRescuedByVariant(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	origID := auditOneReport(t, bin, work, store)

	// 读出干净归档，把缺陷规则的固定 status 改成非法值后按严格内容重算标识，
	// 再文本注入一个取值“发现缺陷”的 StAtus 扩展。扩展不能提供合法状态：
	// 拒绝必须来自固定字段校验，而不是标识不匹配。
	origPath := filepath.Join(store, origID+".json")
	data, err := os.ReadFile(origPath)
	if err != nil {
		t.Fatal(err)
	}
	var stored contractsentinel.Report
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	for i := range stored.Rules {
		if stored.Rules[i].ID == "rule-defect" {
			stored.Rules[i].Status = "奇怪状态"
		}
	}
	stored.ReportID = contractsentinel.ReportID(stored)
	base, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(base),
		`"status":"奇怪状态"`,
		`"status":"奇怪状态","StAtus":"`+contractsentinel.StatusDefect+`"`, 1)
	freshID := stored.ReportID
	if err := os.Remove(origPath); err != nil {
		t.Fatal(err)
	}
	freshPath := filepath.Join(store, freshID+".json")
	if err := os.WriteFile(freshPath, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLIReport(t, bin, store, freshID)
	if code == 0 {
		t.Fatalf("archive with an illegal fixed status must not pass:\n%s", stdout)
	}
	if !strings.Contains(stderr, "unknown status") {
		t.Fatalf("illegal fixed status must be rejected by fixed-field validation: %s", stderr)
	}
	if !strings.Contains(stderr, "rule-defect") {
		t.Fatalf("error must name the offending rule: %s", stderr)
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout:\n%s", stdout)
	}
	kept, err := os.ReadFile(freshPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != doc {
		t.Fatal("failed read must leave the archive untouched")
	}
}

// --- diff：含扩展字段的合法归档参与比较时使用固定字段含义，结论无变化 ---

func TestCLIDiffCaseVariantArchiveUsesFixedFields(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveText(t, store, id,
		`"status":"`+contractsentinel.StatusDefect+`"`,
		`"StAtus":"`+contractsentinel.StatusPass+`","status":"`+contractsentinel.StatusDefect+`"`)

	stdout, stderr, code := runCLIDiff(t, bin, store, id, id)
	if code != 0 {
		t.Fatalf("diff of a legal variant archive must succeed: %s", stderr)
	}
	var diff struct {
		Summary struct {
			NewDefects      int `json:"newDefects"`
			ResolvedDefects int `json:"resolvedDefects"`
			StatusChanges   int `json:"statusChanges"`
			NoteChanges     int `json:"noteChanges"`
			NoChange        int `json:"noChange"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(stdout), &diff); err != nil {
		t.Fatalf("diff output invalid: %v\n%s", err, stdout)
	}
	if diff.Summary.NewDefects != 0 || diff.Summary.ResolvedDefects != 0 ||
		diff.Summary.StatusChanges != 0 || diff.Summary.NoteChanges != 0 {
		t.Fatalf("extension member must not create a change: %+v", diff.Summary)
	}
}
