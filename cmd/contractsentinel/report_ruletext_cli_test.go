package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件在真实命令行进程边界上回归保护 report / diff 读取已保存报告时对规则
// 文本成员的类型要求：rules 中每条规则的 id、kind、severity、invariant、
// version、status、note，正式成员一旦写出就只能是 JSON 字符串。归档里把它
// 们写成 null（或布尔值、数字、对象、数组）时，整份归档必须判为损坏——非零
// 退出、原因进 stderr（含报告标识、规则数组位置、出错字段；规则有合法非空
// id 时同时点名该规则），stdout 不出现任何报告片段，原归档原样保留。省略
// 字段仍按既有默认值与必填校验处理；Note、" note " 这类大小写变体或带空格
// 名称只是扩展信息，其中的 null 既不触发错误，也不能挽救非法的正式成员。
// diff 的任一侧遇到同样的归档，也必须在输出比较结果前失败。

// injectRuleTextField reads the archive named by id, locates the rule object
// with ruleID and rewrites the formal field member with the raw fragment
// (e.g. `null`); a rule that does not carry the member gets it inserted right
// after the id member. The mutated bytes are written back and returned so
// tests can assert the failed read leaves them untouched.
func injectRuleTextField(t *testing.T, store, id, ruleID, field, fragment string) []byte {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	idMember := `"id":"` + ruleID + `"`
	idIdx := strings.Index(doc, idMember)
	if idIdx < 0 {
		t.Fatalf("test setup: rule %s not found in archive", ruleID)
	}
	ruleEnd := strings.IndexByte(doc[idIdx:], '}')
	if ruleEnd < 0 {
		t.Fatalf("test setup: rule %s object has no end", ruleID)
	}
	ruleEnd += idIdx
	marker := `"` + field + `":`
	at := strings.Index(doc[idIdx:ruleEnd], marker)
	var out string
	if at < 0 {
		idEnd := idIdx + len(idMember)
		out = doc[:idEnd] + `,"` + field + `":` + fragment + doc[idEnd:]
	} else {
		at += idIdx
		valueStart := at + len(marker)
		var valueEnd int
		if doc[valueStart] == '"' {
			closing := strings.IndexByte(doc[valueStart+1:], '"')
			if closing < 0 {
				t.Fatalf("test setup: rule %s %s value has no closing quote", ruleID, field)
			}
			valueEnd = valueStart + 1 + closing + 1
		} else {
			end := strings.IndexAny(doc[valueStart:], ",}")
			if end < 0 {
				t.Fatalf("test setup: rule %s %s value has no end", ruleID, field)
			}
			valueEnd = valueStart + end
		}
		out = doc[:at] + `"` + field + `":` + fragment + doc[valueEnd:]
	}
	if out == doc {
		t.Fatal("test setup: injection did not change the archive")
	}
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	return []byte(out)
}

// assertRuleTextCorruptFailure asserts the full CLI failure contract for a
// non-string formal rule text member.
func assertRuleTextCorruptFailure(t *testing.T, stdout, stderr string, code int, id, position, rule, field string) {
	t.Helper()
	if code == 0 {
		t.Fatal("an archive with a non-string rule text member must exit non-zero")
	}
	if !strings.Contains(stderr, "corrupt") {
		t.Fatalf("stderr must classify the archive as corrupt:\n%s", stderr)
	}
	if !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the report id %q:\n%s", id, stderr)
	}
	if !strings.Contains(stderr, position) {
		t.Fatalf("stderr must name the rule array position %q:\n%s", position, stderr)
	}
	if rule != "" && !strings.Contains(stderr, rule) {
		t.Fatalf("stderr must name the offending rule %q:\n%s", rule, stderr)
	}
	if !strings.Contains(stderr, field+" must be a string") {
		t.Fatalf("stderr must state %s must be a string:\n%s", field, stderr)
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- report：null 落在任何检查结论的规则上都失败，stdout 没有报告片段 ---

func TestCLIReportNullNoteFailsCleanly(t *testing.T) {
	positions := map[string]string{
		"rule-pass": "rules[0]", "rule-defect": "rules[1]", "rule-tool": "rules[2]",
		"rule-timeout": "rules[3]", "rule-unchecked": "rules[4]",
	}
	for _, rule := range []string{"rule-pass", "rule-defect", "rule-tool", "rule-timeout", "rule-unchecked"} {
		t.Run(rule, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			mutated := injectRuleTextField(t, store, id, rule, "note", `null`)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertRuleTextCorruptFailure(t, stdout, stderr, code, id, positions[rule], rule, "note")
			for _, marker := range []string{`"reportId"`, `"rules"`, `"findings"`, "发现缺陷"} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a report fragment %q:\n%s", marker, stdout)
				}
			}

			// 归档必须原样保留，不被自动修补。
			kept, err := os.ReadFile(filepath.Join(store, id+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(kept, mutated) {
				t.Fatalf("failed report read must leave the corrupt archive untouched:\n%s", kept)
			}
		})
	}
}

// --- report：其余文本成员（含 id 本身）写成 null 同样判为损坏 ---

func TestCLIReportNullRuleTextFieldsFailCleanly(t *testing.T) {
	for _, tc := range []struct {
		field string
		rule  string // id 本身非法时没有可点名的规则标识
	}{
		{"id", ""},
		{"kind", "rule-pass"},
		{"severity", "rule-pass"},
		{"invariant", "rule-pass"},
		{"version", "rule-pass"},
		{"status", "rule-pass"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			injectRuleTextField(t, store, id, "rule-pass", tc.field, `null`)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertRuleTextCorruptFailure(t, stdout, stderr, code, id, "rules[0]", tc.rule, tc.field)
		})
	}
}

// --- report：布尔值、数字、对象、数组都同样判为损坏，不能默认成空字符串 ---

func TestCLIReportNonStringRuleTextFailsCleanly(t *testing.T) {
	for _, val := range []string{`true`, `0`, `{}`, `[]`} {
		t.Run(val, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			injectRuleTextField(t, store, id, "rule-defect", "note", val)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertRuleTextCorruptFailure(t, stdout, stderr, code, id, "rules[1]", "rule-defect", "note")
		})
	}
}

// --- report：变体名称中的 null 是扩展信息，既不触发错误也不能挽救正式 null ---

func TestCLIReportRuleTextVariantRules(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)

	// 变体携带 null：仍是一份合法报告，note 读回空、状态保持通过。
	injectRuleTextField(t, store, id, "rule-pass", "Note", `null`)
	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("a case-variant extension member must not corrupt the report: %s", stderr)
	}
	decoded := decodeReport(t, stdout)
	for _, rl := range decoded.Rules {
		if rl.ID == "rule-pass" {
			if rl.Note != "" {
				t.Fatal("a variant member must not supply the formal note value")
			}
			if rl.Status != "通过" {
				t.Fatalf("rule-pass status = %q, want 通过", rl.Status)
			}
		}
	}

	// 正式成员为 null、旁边的变体写了合法字符串（位于其前或其后）都必须失败。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			sub := t.TempDir()
			subStore := filepath.Join(sub, "reports")
			subID := auditOneReport(t, bin, sub, subStore)
			if pos == "before" {
				// 两次插入都落在 id 成员之后：先插入正式 null，再插入变体，
				// 最终变体位于正式成员之前。
				injectRuleTextField(t, subStore, subID, "rule-pass", "note", `null`)
				injectRuleTextField(t, subStore, subID, "rule-pass", "Note", `"说明"`)
			} else {
				injectRuleTextField(t, subStore, subID, "rule-pass", "note", `null,"Note":"说明"`)
			}
			out, errText, exitCode := runCLIReport(t, bin, subStore, subID)
			assertRuleTextCorruptFailure(t, out, errText, exitCode, subID, "rules[0]", "rule-pass", "note")
		})
	}
}

// --- diff：任一侧归档含 null 文本成员，比较前失败且不输出局部结果，不能把
// 被默认成空字符串的内容判为“无变化” ---

func TestCLIDiffNullRuleTextEitherSideFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	beforeReport := auditDiffReport(t, bin, work, store, "before.json", artifact, diffRules(), diffBeforeChecks(hash))
	afterReport := auditDiffReport(t, bin, work, store, "after.json", artifact, diffRules(), diffAfterChecks(hash))
	beforeID, afterID := beforeReport.ReportID, afterReport.ReportID

	// 干净字节用于恢复与保留断言。
	cleanBefore, err := os.ReadFile(filepath.Join(store, beforeID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	cleanAfter, err := os.ReadFile(filepath.Join(store, afterID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	// e-stable-pass 原本没有 note：null 会被洗成 ""，归档标识保持不变，
	// 两侧该规则的状态与说明在解码后完全相同，拒绝只能来自类型关——否则
	// 这份损坏归档会被判为“无变化”。
	mutated := injectRuleTextField(t, store, afterID, "e-stable-pass", "note", `null`)

	// 第二份损坏。
	stdout, stderr, code := runCLIDiff(t, bin, store, beforeID, afterID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the second report carries a null note")
	}
	if !strings.Contains(stderr, "corrupt") || !strings.Contains(stderr, afterID) ||
		!strings.Contains(stderr, "e-stable-pass") || !strings.Contains(stderr, "note must be a string") {
		t.Fatalf("stderr must name the corrupt report, rule and string requirement:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
	}
	for _, marker := range []string{`"results"`, `"summary"`, "无变化", "规则变化"} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a partial diff %q:\n%s", marker, stdout)
		}
	}
	if kept, err := os.ReadFile(filepath.Join(store, afterID+".json")); err != nil || !bytes.Equal(kept, mutated) {
		t.Fatalf("failed diff must leave the corrupt archive untouched: %v", err)
	}

	// 第一份损坏、第二份恢复。
	if err := os.WriteFile(filepath.Join(store, afterID+".json"), cleanAfter, 0o644); err != nil {
		t.Fatal(err)
	}
	injectRuleTextField(t, store, beforeID, "e-stable-pass", "note", `null`)
	stdout, stderr, code = runCLIDiff(t, bin, store, beforeID, afterID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the first report carries a null note")
	}
	if !strings.Contains(stderr, beforeID) || !strings.Contains(stderr, "e-stable-pass") {
		t.Fatalf("stderr must name the corrupt first report and rule:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must stay empty on failure:\n%s", stdout)
	}

	// 两侧都恢复后比较成功，且成功的比较不重写归档。
	if err := os.WriteFile(filepath.Join(store, beforeID+".json"), cleanBefore, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLIDiff(t, bin, store, beforeID, afterID)
	if code != 0 {
		t.Fatalf("restored archives must diff successfully: %s", stderr)
	}
	if !strings.Contains(stdout, `"results"`) || !strings.Contains(stdout, `"summary"`) {
		t.Fatalf("restored diff must print the full comparison:\n%s", stdout)
	}
	keptBefore, err := os.ReadFile(filepath.Join(store, beforeID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	keptAfter, err := os.ReadFile(filepath.Join(store, afterID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keptBefore, cleanBefore) || !bytes.Equal(keptAfter, cleanAfter) {
		t.Fatal("successful diff must not rewrite either archive")
	}
}
