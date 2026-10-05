package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件在真实命令行进程边界上回归保护 report / diff 读取已保存报告时对规则
// 字符串成员类型的要求：规则的 id、kind、severity、invariant、version、
// status、note 这些正式成员一旦出现就只能是 JSON 字符串。归档里把任何一个
// 写成 null（或布尔值、数字、对象、数组）时，整份归档必须判为损坏——非零
// 退出、原因进 stderr（含报告标识、出错字段、规则数组位置与规则 id），
// stdout 不出现任何报告片段，原归档原样保留，不会被自动修补。省略该成员仍
// 按已有默认值读回；Note、" note " 这类大小写变体或带空格名称只是扩展信
// 息，其中的值既不能触发错误，也不能挽救非法的正式成员。diff 的任一侧遇到
// 同样的归档，也必须在输出比较结果前失败。

// injectRuleStringMember reads the archive named by id, locates the rule
// object with ruleID and rewrites its formal field member to fragment (a
// complete member such as `"note":null`). When the member is absent — note is
// omitted whenever it is empty — the fragment is appended to the rule object.
// The mutated bytes are written back and returned so tests can assert the
// failed read leaves them untouched.
func injectRuleStringMember(t *testing.T, store, id, ruleID, field, fragment string) []byte {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	anchor := `"id":"` + ruleID + `"`
	idx := strings.Index(doc, anchor)
	if idx < 0 {
		t.Fatalf("test setup: rule %s not found in archive", ruleID)
	}
	ruleEnd := strings.IndexByte(doc[idx:], '}')
	if ruleEnd < 0 {
		t.Fatalf("test setup: rule %s object is not closed", ruleID)
	}
	ruleEnd += idx
	marker := `"` + field + `":`
	rel := strings.Index(doc[idx:ruleEnd], marker)
	var out string
	if rel < 0 {
		out = doc[:ruleEnd] + "," + fragment + doc[ruleEnd:]
	} else {
		memberStart := idx + rel
		valueStart := memberStart + len(marker)
		valueEnd := valueStart
		if doc[valueEnd] == '"' {
			valueEnd++
			for valueEnd < len(doc) {
				if doc[valueEnd] == '\\' {
					valueEnd += 2
					continue
				}
				if doc[valueEnd] == '"' {
					valueEnd++
					break
				}
				valueEnd++
			}
		} else {
			for valueEnd < len(doc) && doc[valueEnd] != ',' && doc[valueEnd] != '}' {
				valueEnd++
			}
		}
		out = doc[:memberStart] + fragment + doc[valueEnd:]
	}
	if out == doc {
		t.Fatal("test setup: injection did not change the archive")
	}
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	return []byte(out)
}

// assertStringCorruptFailure asserts the full CLI failure contract for an
// illegal formal string member.
func assertStringCorruptFailure(t *testing.T, stdout, stderr string, code int, id, rule, field, pos string) {
	t.Helper()
	if code == 0 {
		t.Fatal("an archive with a non-string formal member must exit non-zero")
	}
	if !strings.Contains(stderr, "corrupt") {
		t.Fatalf("stderr must classify the archive as corrupt:\n%s", stderr)
	}
	if !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the report id %q:\n%s", id, stderr)
	}
	if !strings.Contains(stderr, rule) {
		t.Fatalf("stderr must name the offending rule %q:\n%s", rule, stderr)
	}
	if !strings.Contains(stderr, pos) {
		t.Fatalf("stderr must name the rule array position %q:\n%s", pos, stderr)
	}
	if !strings.Contains(stderr, field+" must be a string") {
		t.Fatalf("stderr must state %s must be a string:\n%s", field, stderr)
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- report：没有说明的“通过”规则加入 "note":null，标识不变仍须失败 ---

func TestCLIReportNullNoteOnPassRuleFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	mutated := injectRuleStringMember(t, store, id, "rule-pass", "note", `"note":null`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertStringCorruptFailure(t, stdout, stderr, code, id, "rule-pass", "note", "rules[0]")
	for _, marker := range []string{`"reportId"`, `"rules"`, `"findings"`, "通过"} {
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
}

// --- report：null 落在任何检查结论的规则上都失败，stdout 没有报告片段 ---

func TestCLIReportNullNoteFailsForEveryRuleStatus(t *testing.T) {
	for _, tc := range []struct {
		rule string
		pos  string
	}{
		{"rule-pass", "rules[0]"},      // 通过
		{"rule-defect", "rules[1]"},    // 发现缺陷
		{"rule-tool", "rules[2]"},      // 工具缺失
		{"rule-timeout", "rules[3]"},   // 超时
		{"rule-unchecked", "rules[4]"}, // 未检查
	} {
		t.Run(tc.rule, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			mutated := injectRuleStringMember(t, store, id, tc.rule, "note", `"note":null`)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertStringCorruptFailure(t, stdout, stderr, code, id, tc.rule, "note", tc.pos)

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

// --- report：布尔值、数字、对象、数组都同样判为损坏 ---

func TestCLIReportNonStringMembersFailCleanly(t *testing.T) {
	for _, val := range []string{`true`, `0`, `{}`, `["x"]`} {
		t.Run(val, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			injectRuleStringMember(t, store, id, "rule-defect", "note", `"note":`+val)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertStringCorruptFailure(t, stdout, stderr, code, id, "rule-defect", "note", "rules[1]")
		})
	}
}

// --- report：其余字符串成员写成 null 同样判为损坏 ---

func TestCLIReportNullOnOtherStringMembersFailsCleanly(t *testing.T) {
	for _, field := range []string{"kind", "severity", "invariant", "version", "status"} {
		t.Run(field, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			injectRuleStringMember(t, store, id, "rule-defect", field, `"`+field+`":null`)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertStringCorruptFailure(t, stdout, stderr, code, id, "rule-defect", field, "rules[1]")
		})
	}
}

// --- report：变体名称中的值是扩展信息，既不触发错误也不能挽救正式 null ---

func TestCLIReportStringVariantRules(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)

	// 正式成员省略、变体携带 null：仍是一份合法报告，note 读回为空。
	injectRuleStringMember(t, store, id, "rule-pass", "note", `"Note":null`)
	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("a case-variant extension member must not corrupt the report: %s", stderr)
	}
	decoded := decodeReport(t, stdout)
	for _, rl := range decoded.Rules {
		if rl.ID == "rule-pass" {
			if rl.Note != "" {
				t.Fatal("a variant member must not supply the formal note")
			}
			if rl.Status != "通过" {
				t.Fatalf("rule-pass status = %q, want 通过", rl.Status)
			}
		}
	}

	// 正式成员为 null、旁边的变体写了合法字符串（位于其前或其后）都必须失败，
	// 每次损坏用独立的存储，避免同一归档先后被注入两种片段。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			sub := t.TempDir()
			subStore := filepath.Join(sub, "reports")
			subID := auditOneReport(t, bin, sub, subStore)
			fragment := `"note":null,"Note":"x"`
			if pos == "before" {
				fragment = `"Note":"x","note":null`
			}
			injectRuleStringMember(t, subStore, subID, "rule-pass", "note", fragment)
			out, errText, exitCode := runCLIReport(t, bin, subStore, subID)
			assertStringCorruptFailure(t, out, errText, exitCode, subID, "rule-pass", "note", "rules[0]")
		})
	}
}

// --- diff：任一侧归档含 null 字符串成员，比较前失败且不输出局部结果 ---

func TestCLIDiffNullStringMemberEitherSideFailsCleanly(t *testing.T) {
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
	// a-resolved 原本没有说明：null 会被洗成空字符串，归档标识保持不变，
	// 因此拒绝只能来自类型关，而不是标识不匹配。
	mutated := injectRuleStringMember(t, store, afterID, "a-resolved", "note", `"note":null`)

	// 第二份损坏。
	stdout, stderr, code := runCLIDiff(t, bin, store, beforeID, afterID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the second report carries a null note")
	}
	if !strings.Contains(stderr, "corrupt") || !strings.Contains(stderr, afterID) ||
		!strings.Contains(stderr, "a-resolved") || !strings.Contains(stderr, "note must be a string") {
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
	// 失败不得把 null 洗成空字符串后拿去比较。
	if kept, err := os.ReadFile(filepath.Join(store, afterID+".json")); err != nil || !bytes.Equal(kept, mutated) {
		t.Fatalf("failed diff must leave the corrupt archive untouched: %v", err)
	}

	// 第一份损坏、第二份恢复。
	if err := os.WriteFile(filepath.Join(store, afterID+".json"), cleanAfter, 0o644); err != nil {
		t.Fatal(err)
	}
	injectRuleStringMember(t, store, beforeID, "a-resolved", "note", `"note":null`)
	stdout, stderr, code = runCLIDiff(t, bin, store, beforeID, afterID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the first report carries a null note")
	}
	if !strings.Contains(stderr, beforeID) || !strings.Contains(stderr, "a-resolved") {
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
