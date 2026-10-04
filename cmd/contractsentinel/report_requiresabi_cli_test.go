package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件在真实命令行进程边界上回归保护 report / diff 读取已保存报告时对
// requiresABI 类型的要求：正式 requiresABI 成员一旦出现就只能是 JSON 布尔
// 值。归档里把它写成 null（或字符串、数字、对象、数组）时，整份归档必须
// 判为损坏——非零退出、原因进 stderr（含报告标识、出错规则和 requiresABI
// 必须是布尔值），stdout 不出现任何报告片段，原归档原样保留，不会被自动
// 修补。省略该成员仍按 false 读回；RequiresABI、" requiresABI " 这类大小
// 写变体或带空格名称只是扩展信息，其中的值既不能触发错误，也不能挽救非
// 法的正式成员。diff 的任一侧遇到同样的归档，也必须在输出比较结果前失败。

// injectRuleRequiresABI reads the archive named by id, locates the rule
// object with ruleID and replaces its formal requiresABI member with
// fragment (e.g. `"requiresABI":null`). The mutated bytes are written back
// and returned so tests can assert the failed read leaves them untouched.
func injectRuleRequiresABI(t *testing.T, store, id, ruleID, fragment string) []byte {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	head := `"id":"` + ruleID + `"`
	idx := strings.Index(doc, head)
	if idx < 0 {
		t.Fatalf("test setup: rule %s not found in archive", ruleID)
	}
	rest := doc[idx:]
	marker := `"requiresABI":`
	at := strings.Index(rest, marker)
	if at < 0 {
		t.Fatalf("test setup: rule %s has no requiresABI member", ruleID)
	}
	valueStart := idx + at + len(marker)
	comma := strings.IndexByte(doc[valueStart:], ',')
	if comma < 0 {
		t.Fatalf("test setup: rule %s requiresABI value has no trailing comma", ruleID)
	}
	valueEnd := valueStart + comma
	out := doc[:idx+at] + fragment + doc[valueEnd:]
	if out == doc {
		t.Fatal("test setup: injection did not change the archive")
	}
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	return []byte(out)
}

// assertRequiresABICorruptFailure asserts the full CLI failure contract for
// an illegal formal requiresABI value.
func assertRequiresABICorruptFailure(t *testing.T, stdout, stderr string, code int, id, rule string) {
	t.Helper()
	if code == 0 {
		t.Fatal("an archive with a non-boolean requiresABI must exit non-zero")
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
	if !strings.Contains(stderr, "requiresABI must be a boolean") {
		t.Fatalf("stderr must state requiresABI must be a boolean:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- report：null 落在任何检查结论的规则上都失败，stdout 没有报告片段 ---

func TestCLIReportNullRequiresABIFailsCleanly(t *testing.T) {
	for _, tc := range []struct {
		rule string
	}{
		{"rule-pass"},      // 通过
		{"rule-defect"},    // 发现缺陷
		{"rule-tool"},      // 工具缺失
		{"rule-timeout"},   // 超时
		{"rule-unchecked"}, // 未检查
	} {
		t.Run(tc.rule, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			mutated := injectRuleRequiresABI(t, store, id, tc.rule, `"requiresABI":null`)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertRequiresABICorruptFailure(t, stdout, stderr, code, id, tc.rule)
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

// --- report：字符串、数字、对象、数组都同样判为损坏 ---

func TestCLIReportNonBooleanRequiresABIFailsCleanly(t *testing.T) {
	for _, val := range []string{`"false"`, `0`, `1`, `{}`, `[true]`} {
		t.Run(val, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			injectRuleRequiresABI(t, store, id, "rule-pass", `"requiresABI":`+val)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertRequiresABICorruptFailure(t, stdout, stderr, code, id, "rule-pass")
		})
	}
}

// --- report：变体名称中的值是扩展信息，既不触发错误也不能挽救正式 null ---

func TestCLIReportRequiresABIVariantRules(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)

	// 正式成员省略、变体携带 null：仍是一份合法报告，requiresABI 读回 false。
	injectRuleRequiresABI(t, store, id, "rule-pass", `"RequiresABI":null`)
	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("a case-variant extension member must not corrupt the report: %s", stderr)
	}
	decoded := decodeReport(t, stdout)
	var passStatus string
	for _, rl := range decoded.Rules {
		if rl.ID == "rule-pass" {
			passStatus = rl.Status
			if rl.RequiresABI {
				t.Fatal("a variant member must not supply the formal requiresABI value")
			}
		}
	}
	if passStatus != "通过" {
		t.Fatalf("rule-pass status = %q, want 通过", passStatus)
	}

	// 正式成员为 null、旁边的变体写了合法 false（位于其前或其后）都必须失败，
	// 每次损坏用独立的存储，避免同一归档先后被注入两种片段。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			sub := t.TempDir()
			subStore := filepath.Join(sub, "reports")
			subID := auditOneReport(t, bin, sub, subStore)
			fragment := `"requiresABI":null,"RequiresABI":false`
			if pos == "before" {
				fragment = `"RequiresABI":false,"requiresABI":null`
			}
			injectRuleRequiresABI(t, subStore, subID, "rule-pass", fragment)
			out, errText, exitCode := runCLIReport(t, bin, subStore, subID)
			assertRequiresABICorruptFailure(t, out, errText, exitCode, subID, "rule-pass")
		})
	}
}

// --- diff：任一侧归档含 null requiresABI，比较前失败且不输出局部结果 ---

func TestCLIDiffNullRequiresABIEitherSideFailsCleanly(t *testing.T) {
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
	// a-resolved 原本显式 false：null 会被洗成 false，归档标识保持不变，
	// 因此拒绝只能来自类型关，而不是标识不匹配。
	mutated := injectRuleRequiresABI(t, store, afterID, "a-resolved", `"requiresABI":null`)

	// 第二份损坏。
	stdout, stderr, code := runCLIDiff(t, bin, store, beforeID, afterID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the second report carries a null requiresABI")
	}
	if !strings.Contains(stderr, "corrupt") || !strings.Contains(stderr, afterID) ||
		!strings.Contains(stderr, "a-resolved") || !strings.Contains(stderr, "requiresABI must be a boolean") {
		t.Fatalf("stderr must name the corrupt report, rule and boolean requirement:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
	}
	for _, marker := range []string{`"results"`, `"summary"`, "无变化", "规则变化"} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a partial diff %q:\n%s", marker, stdout)
		}
	}
	// 失败不得把 null 洗成 false 后拿去比较。
	if kept, err := os.ReadFile(filepath.Join(store, afterID+".json")); err != nil || !bytes.Equal(kept, mutated) {
		t.Fatalf("failed diff must leave the corrupt archive untouched: %v", err)
	}

	// 第一份损坏、第二份恢复。
	if err := os.WriteFile(filepath.Join(store, afterID+".json"), cleanAfter, 0o644); err != nil {
		t.Fatal(err)
	}
	injectRuleRequiresABI(t, store, beforeID, "a-resolved", `"requiresABI":null`)
	stdout, stderr, code = runCLIDiff(t, bin, store, beforeID, afterID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the first report carries a null requiresABI")
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
