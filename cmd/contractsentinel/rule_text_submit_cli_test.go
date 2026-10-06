package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护：audit 提交中每条规则的五个正式文本
// 成员 id、kind、severity、invariant、version 一旦写出就必须是 JSON 字符串。
// 写成 null（或布尔值、数字、对象、数组）时整份提交必须失败——非零退出、
// 原因进 stderr 并点名 rules 数组中从零开始的位置、出错成员与“必须是字符串”
// （规则有合法非空 id 时同时点名），stdout 为空，尚不存在的报告目录不被
// 创建，已有归档保持原样。省略成员与显式空字符串的既有行为不变，合法
// 字符串中的中文、换行与前后空格逐字保留。这是提交格式错误，不得表现为
// 缺陷、工具缺失或超时。

// ruleTextCLIInput 是一个规则数组内容（不含外层方括号）由调用者给出的提交。
func ruleTextCLIInput(rulesInner string) string {
	return `{"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},` +
		`"rules":[` + rulesInner + `]}`
}

// validRuleWithID 是一条不要求 ABI 的完整合法静态规则。
func validRuleWithID(id string) string {
	return `{"id":"` + id + `","kind":"static","severity":"high","invariant":"inv-` + id +
		`","requiresABI":false,"version":"1.0.0"}`
}

// ruleCLIWithValue 构造一条五个文本成员齐全的规则，仅把 field 的值换成
// 原始片段 val（其余成员保持合法字符串）。
func ruleCLIWithValue(field, val string) string {
	values := map[string]string{
		"id": `"r1"`, "kind": `"static"`, "severity": `"high"`,
		"invariant": `"inv"`, "version": `"1.0.0"`,
	}
	values[field] = val
	return `{"id":` + values["id"] + `,"kind":` + values["kind"] + `,"severity":` + values["severity"] +
		`,"invariant":` + values["invariant"] + `,"requiresABI":false,"version":` + values["version"] + `}`
}

// assertRuleTextSubmitFailure 断言非字符串正式规则文本成员的完整失败契约。
func assertRuleTextSubmitFailure(t *testing.T, stdout, stderr string, code int, position, rule, field string) {
	t.Helper()
	if code == 0 {
		t.Fatalf("audit must exit non-zero when rule member %s is not a string", field)
	}
	if stdout != "" {
		t.Fatalf("stdout must stay empty on a rejected submission:\n%s", stdout)
	}
	if !strings.Contains(stderr, position) {
		t.Fatalf("stderr must name the rules-array position %q:\n%s", position, stderr)
	}
	if !strings.Contains(stderr, field+" must be a string") {
		t.Fatalf("stderr must state %s must be a string:\n%s", field, stderr)
	}
	if rule != "" {
		if !strings.Contains(stderr, rule) {
			t.Fatalf("stderr must name the legal rule id %q:\n%s", rule, stderr)
		}
	} else if strings.Contains(stderr, "(rule ") {
		t.Fatalf("an illegal id must leave the rule locatable by position alone:\n%s", stderr)
	}
	// 规则定义的提交格式错误：stderr 不能把它描述成任何检查结论。
	for _, marker := range []string{contractsentinel.StatusDefect, contractsentinel.StatusToolMissing,
		contractsentinel.StatusTimeout} {
		if strings.Contains(stderr, marker) {
			t.Fatalf("a format error must not be classified as the conclusion %q:\n%s", marker, stderr)
		}
	}
}

// --- 五个成员的 null：非零退出、stderr 点名位置/字段/字符串要求，目录不创建 ---

func TestCLIAuditNullRuleTextFieldFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	for _, tc := range []struct {
		field string
		rule  string // id 自身非法时没有可点名的规则标识
	}{
		{"id", ""},
		{"kind", "r1"},
		{"severity", "r1"},
		{"invariant", "r1"},
		{"version", "r1"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			work := t.TempDir()
			// id 自身为 null 时没有可点名的合法规则标识，其余字段仍可定位规则。
			in := ruleTextCLIInput(ruleCLIWithValue(tc.field, "null"))
			input := writeInput(t, work, "in.json", in)
			store := filepath.Join(work, "nested", "missing-store")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			assertRuleTextSubmitFailure(t, stdout, stderr, code, "rules[0]", tc.rule, tc.field)
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("failure must not create the report store: %v", err)
			}
		})
	}
}

// --- 布尔值、数字、对象、数组同样失败，stdout 不泄露任何报告片段 ---

func TestCLIAuditNonStringRuleTextFieldFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	for _, val := range []string{"true", "false", "42", "{}", `["inv"]`} {
		t.Run(val, func(t *testing.T) {
			work := t.TempDir()
			in := ruleTextCLIInput(`{"id":"r1","kind":"static","severity":"high",` +
				`"invariant":` + val + `,"requiresABI":false,"version":"1.0.0"}`)
			input := writeInput(t, work, "in.json", in)
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			assertRuleTextSubmitFailure(t, stdout, stderr, code, "rules[0]", "r1", "invariant")
			for _, marker := range []string{`"reportId"`, `"rules"`, `"findings"`} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a report fragment %q", marker)
				}
			}
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("failure must not create the report store: %v", err)
			}
		})
	}
}

// --- 其他规则与检查记录合法也不能挽救：错误点名出错规则的数组位置与 id ---

func TestCLIAuditNullRuleTextNamesPositionAmongRules(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	rules := validRuleWithID("r1") + "," +
		`{"id":"r2","kind":"static","severity":null,"invariant":"inv-r2","version":"2.0.0"}`
	input := writeInput(t, work, "in.json", ruleTextCLIInput(rules))
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertRuleTextSubmitFailure(t, stdout, stderr, code, "rules[1]", "r2", "severity")
}

// --- 目录中已有归档时，一次类型错误提交必须保持原有归档原样不变 ---

func TestCLIAuditNullRuleTextFieldKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	validInput := writeInput(t, work, "valid.json", ruleTextCLIInput(validRuleWithID("r1")))
	store := filepath.Join(work, "reports")
	if out, err := exec.Command(bin, "audit", "--input", validInput, "--store", store).CombinedOutput(); err != nil {
		t.Fatalf("valid audit setup failed: %v\n%s", err, out)
	}
	before, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("setup expected 1 report, got %d: %v", len(before), before)
	}
	existingPath := filepath.Join(store, before[0])
	existingBytes, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}

	badInput := writeInput(t, work, "bad.json",
		ruleTextCLIInput(`{"id":"r1","kind":null,"severity":"high","invariant":"inv","version":"1.0.0"}`))
	var stdout bytes.Buffer
	cmd := exec.Command(bin, "audit", "--input", badInput, "--store", store)
	cmd.Stdout = &stdout
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("invalid audit must fail, output:\n%s", out)
	}
	if stdout.String() != "" {
		t.Fatalf("rejected submission must print nothing to stdout:\n%s", stdout.String())
	}
	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("failure changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("failure modified the existing report")
	}
}

// --- 大小写变体与带空格名称：其中的 null 是扩展信息，合法字符串也不能挽救
// 正式 null（无论写在其前还是后） ---

func TestCLIAuditRuleTextVariantsCannotRescueNull(t *testing.T) {
	bin := auditBinary(t)

	// 正式 kind 省略、变体 Kind=null：合法提交，kind 读回空。
	work := t.TempDir()
	in := ruleTextCLIInput(`{"id":"r1","Kind":null,"severity":"high","invariant":"inv","version":"1.0.0"}`)
	input := writeInput(t, work, "in.json", in)
	store := filepath.Join(work, "reports")
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("a null under a case-variant name is extension data: %s", stderr)
	}
	report := decodeReport(t, stdout)
	if report.Rules[0].Kind != "" {
		t.Fatalf("a variant member must not supply the formal kind: %+v", report.Rules[0])
	}

	for _, tc := range []struct {
		name  string
		rules string
	}{
		{"variant before", `{"id":"r1","Kind":"static","kind":null,"severity":"high","invariant":"inv","version":"1.0.0"}`},
		{"variant after", `{"id":"r1","kind":null," kind ":"static","severity":"high","invariant":"inv","version":"1.0.0"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub := t.TempDir()
			badInput := writeInput(t, sub, "in.json", ruleTextCLIInput(tc.rules))
			out, errText, exitCode := runCLIAudit(t, bin, badInput, filepath.Join(sub, "reports"))
			assertRuleTextSubmitFailure(t, out, errText, exitCode, "rules[0]", "r1", "kind")
		})
	}
}

// --- 显式空字符串与 null 形成对照：显式空 kind 仍成功出报告且可读回 ---

func TestCLIAuditExplicitEmptyRuleTextStillSucceeds(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	in := ruleTextCLIInput(`{"id":"r1","kind":"","severity":"high","invariant":"inv","version":"1.0.0"}`)
	input := writeInput(t, work, "in.json", in)
	store := filepath.Join(work, "nested", "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("an explicit empty-string kind is legal, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)
	if report.Rules[0].Kind != "" || report.Rules[0].ID != "r1" {
		t.Fatalf("explicit empty kind must read back empty: %+v", report.Rules[0])
	}
	readStdout, _, readCode := runCLIReport(t, bin, store, report.ReportID)
	if readCode != 0 {
		t.Fatalf("the saved report must read back by id, exit=%d", readCode)
	}
	if decodeReport(t, readStdout).ReportID != report.ReportID {
		t.Fatal("read-back must keep the report id")
	}
}

// --- 合法字符串中的中文、换行与前后空格逐字保留，报告可按标识原样读回 ---

func TestCLIAuditLegalRuleTextPreservedVerbatim(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	id := " 规则 一 \n"
	severity := " 高 "
	invariant := "不变式\nx"
	rule := `{"id":` + jsonCLIString(id) + `,"kind":"static","severity":` + jsonCLIString(severity) +
		`,"invariant":` + jsonCLIString(invariant) + `,"requiresABI":false,"version":" v1\n "}`
	input := writeInput(t, work, "in.json", ruleTextCLIInput(rule))
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("a legal multilingual submission must succeed: %s", stderr)
	}
	report := decodeReport(t, stdout)
	got := report.Rules[0]
	if got.ID != id || got.Severity != severity || got.Invariant != invariant || got.Version != " v1\n " {
		t.Fatalf("rule text must be preserved verbatim:\n%+v", got)
	}
	readStdout, _, readCode := runCLIReport(t, bin, store, report.ReportID)
	if readCode != 0 {
		t.Fatal("the saved report must read back by id")
	}
	loaded := decodeReport(t, readStdout)
	if loaded.ReportID != report.ReportID || loaded.Rules[0] != report.Rules[0] {
		t.Fatalf("read-back changed the rule text:\n%+v\n%+v", loaded.Rules[0], report.Rules[0])
	}
}

// jsonCLIString quotes a Go string as a JSON string literal for hand-built input.
func jsonCLIString(s string) string {
	b := strings.Builder{}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
