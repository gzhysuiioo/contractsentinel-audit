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

// 本文件在真实命令行进程边界上回归保护 audit 对外部检查记录 note 的类型
// 校验：正式 note 一旦写出就必须是 JSON 字符串。产物、规则和记录绑定都
// 合法时，状态为“通过”的记录写 "note":null 也曾成功生成报告，与省略说明
// 的提交得到同一报告；修正后这类提交必须非零退出、stdout 为空、stderr
// 指出 note 必须是字符串并点名 checks 数组位置与规则，报告目录尚不存在时
// 不创建，已有归档保持原样。这是提交格式错误，不是任何检查结论。

// mixedCheckMapInput 把混合状态合法提交解成通用 map，便于把单个成员改成
// 类型镜像结构体无法表达的 null / 布尔 / 数字 / 对象等原始值。
func mixedCheckMapInput(t *testing.T, hash string) map[string]any {
	t.Helper()
	data, err := json.Marshal(mixedCheckInput(hash))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// mapCheckByRule 取出提交中 ruleId 等于 ruleID 的检查记录 map。
func mapCheckByRule(t *testing.T, doc map[string]any, ruleID string) map[string]any {
	t.Helper()
	for _, e := range doc["checks"].([]any) {
		rec := e.(map[string]any)
		if rec["ruleId"] == ruleID {
			return rec
		}
	}
	t.Fatalf("check for rule %s missing from fixture", ruleID)
	return nil
}

// writeMapInput 把通用提交对象编码为 JSON 写入临时目录并返回路径。
func writeMapInput(t *testing.T, dir, name string, doc map[string]any) string {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return writeInput(t, dir, name, string(data))
}

// assertNoteTypeFailure 断言一次 note 类型错误的进程表现：非零退出、
// stdout 完全为空、stderr 点名 checks 位置、规则与字符串要求。
func assertNoteTypeFailure(t *testing.T, stdout, stderr string, code int, position, ruleID string) {
	t.Helper()
	if code == 0 {
		t.Fatal("a non-string formal note must exit non-zero")
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty for a rejected submission, got:\n%s", stdout)
	}
	if !strings.Contains(stderr, position) {
		t.Fatalf("stderr must name the checks-array position %q:\n%s", position, stderr)
	}
	if ruleID != "" && !strings.Contains(stderr, ruleID) {
		t.Fatalf("stderr must name the rule %q:\n%s", ruleID, stderr)
	}
	if !strings.Contains(stderr, "note must be a string") {
		t.Fatalf("stderr must state note must be a string:\n%s", stderr)
	}
	for _, marker := range []string{contractsentinel.StatusDefect, contractsentinel.StatusToolMissing,
		contractsentinel.StatusTimeout, contractsentinel.StatusUnchecked} {
		if strings.Contains(stderr, marker) {
			t.Fatalf("a format error must not be reported as the conclusion %q:\n%s", marker, stderr)
		}
	}
}

// --- 核心回归：合法绑定的“通过”记录写 "note":null 必须失败，且不建目录 ---

func TestCLIAuditNullPassNoteRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	doc := mixedCheckMapInput(t, hash)
	// 通过记录在合法夹具中省略 note：显式写入 null。
	mapCheckByRule(t, doc, "rule-pass")["note"] = nil
	input := writeMapInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertNoteTypeFailure(t, stdout, stderr, code, "checks[0]", "rule-pass")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 四种状态写 null 都失败，错误位置随记录在 checks 数组中的下标变化 ---

func TestCLIAuditNullNoteRejectedForEveryStatus(t *testing.T) {
	cases := []struct {
		ruleID   string
		position string
	}{
		{"rule-pass", "checks[0]"},
		{"rule-defect", "checks[1]"},
		{"rule-tool", "checks[2]"},
		{"rule-timeout", "checks[3]"},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			hash := mixedArtifactHash(t)
			doc := mixedCheckMapInput(t, hash)
			mapCheckByRule(t, doc, tc.ruleID)["note"] = nil
			input := writeMapInput(t, work, "bad.json", doc)
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			assertNoteTypeFailure(t, stdout, stderr, code, tc.position, tc.ruleID)
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("rejected submission must not create the store directory: %v", err)
			}
		})
	}
}

// --- 布尔、数字、对象、数组都失败，不能转成空串、文字或跳过记录 ---

func TestCLIAuditNonStringNoteRejected(t *testing.T) {
	nonString := []struct {
		name string
		val  any
	}{
		{"bool-true", true}, {"bool-false", false}, {"number-zero", 0},
		{"number", 123}, {"object", map[string]any{}}, {"array-empty", []any{}},
		{"array", []any{"x"}},
	}
	for _, tc := range nonString {
		t.Run(tc.name, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			hash := mixedArtifactHash(t)
			doc := mixedCheckMapInput(t, hash)
			mapCheckByRule(t, doc, "rule-pass")["note"] = tc.val
			input := writeMapInput(t, work, "bad.json", doc)
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			assertNoteTypeFailure(t, stdout, stderr, code, "checks[0]", "rule-pass")
		})
	}
}

// --- 其他记录合法也不输出片段：stdout 不得泄漏报告 id、状态或 finding ---

func TestCLIAuditNullNoteHasNoReportFragments(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	doc := mixedCheckMapInput(t, hash)
	mapCheckByRule(t, doc, "rule-defect")["note"] = nil
	input := writeMapInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertNoteTypeFailure(t, stdout, stderr, code, "checks[1]", "rule-defect")
	for _, marker := range []string{"reportId", "artifactHash", "findings", "rules"} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a partial report fragment %q:\n%s", marker, stdout)
		}
	}
}

// --- 已有归档保持原样：失败提交不改文件列表，也不改已有字节 ---

func TestCLIAuditNullNoteKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	// 先落一份合法混合状态报告。
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

	// 再提交一份给通过记录写 null note 的提交。
	badDoc := mixedCheckMapInput(t, mixedArtifactHash(t))
	mapCheckByRule(t, badDoc, "rule-pass")["note"] = nil
	bad := writeMapInput(t, work, "bad.json", badDoc)
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
	kept, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("rejected submission modified the existing report bytes")
	}
}

// --- Unicode 转义写出、解码后恰为 note 的名称同样受约束 ---

func TestCLIAuditEscapedNoteNameRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	doc := mixedCheckMapInput(t, hash)
	mapCheckByRule(t, doc, "rule-pass")["note"] = nil
	raw := writeMapInput(t, work, "bad.json", doc)
	data, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	// 紧凑 JSON 中该记录恰有一处 "note":null，改用 n的转义写法，解码后仍是正式 note。
	escaped := strings.Replace(string(data), `"note":null`, `"\u006eote":null`, 1)
	if !strings.Contains(escaped, `\u006eote`) {
		t.Fatal("test setup must carry the escaped note name")
	}
	input := writeInput(t, work, "escaped.json", escaped)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertNoteTypeFailure(t, stdout, stderr, code, "checks[0]", "rule-pass")
}

// --- Note / 带空格名称是扩展信息：其非字符串值不触发类型错误，合法字符串
// 既不能补上缺失的正式说明，也不能挽救非法的正式 note ---

func TestCLIAuditNoteExtensionMembersDoNotRescue(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)

	// 正式 note 为 null，旁边的 "Note" 携带合法字符串，仍按类型错误拒绝。
	doc := mixedCheckMapInput(t, hash)
	pass := mapCheckByRule(t, doc, "rule-pass")
	pass["note"] = nil
	pass["Note"] = "passing remark"
	input := writeMapInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "reports")
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertNoteTypeFailure(t, stdout, stderr, code, "checks[0]", "rule-pass")

	// 正式 note 省略、缺陷状态，扩展成员给 null 或合法字符串都不能补上说明：
	// 沿用原有的业务失败，而不是 note 类型错误。
	doc2 := mixedCheckMapInput(t, hash)
	defect := mapCheckByRule(t, doc2, "rule-defect")
	delete(defect, "note")
	defect["Note"] = nil
	defect[" note "] = " 反例文本 "
	input2 := writeMapInput(t, work, "bad2.json", doc2)
	stdout2, stderr2, code2 := runCLIAudit(t, bin, input2, store)
	if code2 == 0 {
		t.Fatal("a defect record without a formal note must keep failing")
	}
	if stdout2 != "" {
		t.Fatalf("stdout must be empty:\n%s", stdout2)
	}
	if !strings.Contains(stderr2, "rule-defect") ||
		!strings.Contains(stderr2, "note is required for status "+contractsentinel.StatusDefect) {
		t.Fatalf("the original blank-note business failure must survive, got:\n%s", stderr2)
	}
	if strings.Contains(stderr2, "must be a string") {
		t.Fatalf("an extension null must not trigger the formal note type error:\n%s", stderr2)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submissions must not create the store directory: %v", err)
	}
}

// --- 合法提交行为不变：通过记录显式空串与省略等价；纯空白串逐字保留并改变
// 报告标识；合法提交的产物哈希、规则结论与说明保持原值 ---

func TestCLIAuditLegalNotesUnchanged(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	store := filepath.Join(work, "reports")

	// 基线：通过记录省略 note。
	baseInput := writeStructInput(t, work, "base.json", mixedCheckInput(hash))
	stdout, stderr, code := runCLIAudit(t, bin, baseInput, store)
	if code != 0 {
		t.Fatalf("legal baseline must succeed: %s", stderr)
	}
	base := decodeReport(t, stdout)

	// 显式空串：同一份报告（标识相同，归档复用同一文件）。
	emptyDoc := mixedCheckMapInput(t, hash)
	mapCheckByRule(t, emptyDoc, "rule-pass")["note"] = ""
	emptyInput := writeMapInput(t, work, "empty.json", emptyDoc)
	stdout, stderr, code = runCLIAudit(t, bin, emptyInput, store)
	if code != 0 {
		t.Fatalf("an explicit empty-string pass note must be legal: %s", stderr)
	}
	emptyReport := decodeReport(t, stdout)
	if emptyReport.ReportID != base.ReportID {
		t.Fatalf("omitted and explicit-empty note must share the report id:\n%s\n%s",
			emptyReport.ReportID, base.ReportID)
	}

	// 纯空白串（含中文/换行场景已在包测覆盖）：逐字保留，标识不同于基线，
	// 且其余结论与缺陷证据不变。
	wsDoc := mixedCheckMapInput(t, hash)
	mapCheckByRule(t, wsDoc, "rule-pass")["note"] = "  备注换行\n仍在  "
	wsInput := writeMapInput(t, work, "ws.json", wsDoc)
	stdout, stderr, code = runCLIAudit(t, bin, wsInput, store)
	if code != 0 {
		t.Fatalf("a whitespace pass note must be legal: %s", stderr)
	}
	wsReport := decodeReport(t, stdout)
	if wsReport.ReportID == base.ReportID {
		t.Fatal("a non-empty whitespace note must change the report id")
	}
	var wsNote string
	for _, r := range wsReport.Rules {
		if r.ID == "rule-pass" {
			wsNote = r.Note
		}
	}
	if wsNote != "  备注换行\n仍在  " {
		t.Fatalf("whitespace/CJK note must be preserved verbatim, got %q", wsNote)
	}
	if wsReport.Artifact.Hash != hash {
		t.Fatal("legal notes must keep the artifact hash")
	}
	if len(wsReport.Findings) != 1 || wsReport.Findings[0].Evidence != defectNote {
		t.Fatalf("defect attribution and evidence must be unchanged: %+v", wsReport.Findings)
	}

	// 归档文件数量：基线与空串共享一份，纯空白另一份。
	entries, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected two distinct archives (shared id + whitespace id), got %v", entries)
	}
}
