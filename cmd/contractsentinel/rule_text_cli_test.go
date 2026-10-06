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

// 本文件在真实命令行进程边界上回归保护 audit 提交对规则定义文本成员的类型
// 要求：rules 中每条规则的 id、kind、severity、invariant、version 五个正式
// 成员一旦写出就只能是 JSON 字符串。写成 null（或布尔值、数字、对象、数组）
// 时整份提交必须失败——非零退出、原因进 stderr（含 rules 数组中从零开始的
// 位置、出错成员与“必须是字符串”；规则有合法非空 id 时同时点名该规则），
// stdout 不出现任何报告片段，尚不存在的报告目录不被创建，已有归档保持原样。
// 这是规则定义的提交格式错误，不能记成缺陷、工具缺失或超时。省略成员与显式
// 空字符串的既有行为不变；Kind、" kind " 这类大小写变体或带空格名称只是
// 扩展信息，其中的 null 既不触发错误，合法字符串也不能挽救非法正式成员。

// ruleTextAuditInput renders an audit submission whose single rule carries the
// given raw "member":fragment pairs in order; artifact and invariants are
// fixed and legal.
func ruleTextAuditInput(rulePairs string) string {
	return `{
	"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
	"rules": [{` + rulePairs + `}],
	"invariants": {"inv1": true}
}`
}

// legalRuleTextPairs is a fully legal single rule.
const legalRuleTextPairs = `"id":"r1","kind":"static","severity":"high","invariant":"inv1","requiresABI":false,"version":"1.0.0"`

// ruleTextFailure runs one bad audit and asserts the full failure contract.
func ruleTextFailure(t *testing.T, bin, work, store, input, position, rule, field string) {
	t.Helper()
	inputPath := writeInput(t, work, "in.json", input)
	stdout, stderr, code := runCLIAudit(t, bin, inputPath, store)
	if code == 0 {
		t.Fatalf("audit must exit non-zero when %s is not a string", field)
	}
	if stdout != "" {
		t.Fatalf("stdout must not contain any report fragment:\n%s", stdout)
	}
	if !strings.Contains(stderr, position) {
		t.Fatalf("stderr must name the rules-array position %q:\n%s", position, stderr)
	}
	if rule != "" && !strings.Contains(stderr, rule) {
		t.Fatalf("stderr must name the offending rule %q:\n%s", rule, stderr)
	}
	if !strings.Contains(stderr, field+" must be a string") {
		t.Fatalf("stderr must state %s must be a string:\n%s", field, stderr)
	}
	// 这是规则定义的提交格式错误：stderr 不能把它描述成缺陷、工具缺失或超时。
	for _, marker := range []string{contractsentinel.StatusDefect, contractsentinel.StatusToolMissing,
		contractsentinel.StatusTimeout} {
		if strings.Contains(stderr, marker) {
			t.Fatalf("a format error must not be classified as %q:\n%s", marker, stderr)
		}
	}
}

// --- 核心场景：合法 id 和 version，kind/severity/invariant 为 null 也必须失败，
// stdout 没有报告 ---

func TestCLIAuditNullCoreRuleTextFailsCleanly(t *testing.T) {
	legal := map[string]string{
		"kind":      `"static"`,
		"severity":  `"high"`,
		"invariant": `"inv1"`,
	}
	for _, field := range []string{"kind", "severity", "invariant"} {
		t.Run(field, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			pairs := strings.Replace(legalRuleTextPairs,
				`"`+field+`":`+legal[field], `"`+field+`":null`, 1)
			ruleTextFailure(t, bin, work, store, ruleTextAuditInput(pairs), "rules[0]", "r1", field)
		})
	}
}

// --- 五个文本成员的 null 都失败；id 自身非法时凭位置定位、不点名规则 ---

func TestCLIAuditNullRuleTextFieldsFailCleanly(t *testing.T) {
	legal := map[string]string{
		"id":        `"r1"`,
		"kind":      `"static"`,
		"severity":  `"high"`,
		"invariant": `"inv1"`,
		"version":   `"1.0.0"`,
	}
	for _, field := range []string{"id", "kind", "severity", "invariant", "version"} {
		t.Run(field, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			pairs := `"id":"r1","kind":"static","severity":"high","invariant":"inv1","requiresABI":false,"version":"1.0.0"`
			pairs = strings.Replace(pairs, `"`+field+`":`+legal[field], `"`+field+`":null`, 1)
			rule := "r1"
			if field == "id" {
				rule = ""
			}
			ruleTextFailure(t, bin, work, store, ruleTextAuditInput(pairs), "rules[0]", rule, field)
		})
	}
}

// --- 布尔值、数字、对象、数组写在正式 invariant 上同样整份失败 ---

func TestCLIAuditNonStringRuleTextFailsCleanly(t *testing.T) {
	for _, val := range []string{"true", "false", "0", "1", "{}", `["x"]`} {
		t.Run(val, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			pairs := strings.Replace(legalRuleTextPairs, `"invariant":"inv1"`, `"invariant":`+val, 1)
			ruleTextFailure(t, bin, work, store, ruleTextAuditInput(pairs), "rules[0]", "r1", "invariant")
		})
	}
}

// --- 失败时不得创建尚不存在的报告目录，也不留归档 ---

func TestCLIAuditNullRuleTextCreatesNoStore(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	in := ruleTextAuditInput(strings.Replace(legalRuleTextPairs, `"kind":"static"`, `"kind":null`, 1))
	input := writeInput(t, work, "in.json", in)
	store := filepath.Join(work, "nested", "missing-store")

	if out, err := exec.Command(bin, "audit", "--input", input, "--store", store).CombinedOutput(); err == nil {
		t.Fatalf("audit must fail, output:\n%s", out)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("failure must not create the report store: %v", err)
	}
}

// --- 目录中已有报告时，一次非法提交必须保持原有内容原样不变 ---

func TestCLIAuditNullRuleTextKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	validInput := writeInput(t, work, "valid.json", ruleTextAuditInput(legalRuleTextPairs))
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

	badDoc := ruleTextAuditInput(strings.Replace(legalRuleTextPairs, `"severity":"high"`, `"severity":null`, 1))
	badInput := writeInput(t, work, "bad.json", badDoc)
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

// --- 显式空字符串与 null 形成对照：没有相关要求时合法空文本仍成功出报告，
// 且与省略该成员的提交报告标识一致 ---

func TestCLIAuditExplicitEmptyRuleTextStillSucceeds(t *testing.T) {
	bin := auditBinary(t)

	// 显式空 kind/severity/invariant：合法并出报告。
	emptyPairs := `"id":"r1","kind":"","severity":"","invariant":"","requiresABI":false,"version":"1.0.0"`
	work := t.TempDir()
	emptyInput := writeInput(t, work, "empty.json", ruleTextAuditInput(emptyPairs))
	store := filepath.Join(work, "reports")
	stdout, stderr, code := runCLIAudit(t, bin, emptyInput, store)
	if code != 0 {
		t.Fatalf("explicit empty rule text must stay legal, exit=%d stderr=%s", code, stderr)
	}
	emptyReport := decodeReport(t, stdout)

	// 省略这三个成员的提交得到同一份报告标识。
	omittedPairs := `"id":"r1","requiresABI":false,"version":"1.0.0"`
	work2 := t.TempDir()
	omittedInput := writeInput(t, work2, "omitted.json", ruleTextAuditInput(omittedPairs))
	store2 := filepath.Join(work2, "reports")
	stdout2, stderr2, code2 := runCLIAudit(t, bin, omittedInput, store2)
	if code2 != 0 {
		t.Fatalf("omitted rule text must stay legal, exit=%d stderr=%s", code2, stderr2)
	}
	omittedReport := decodeReport(t, stdout2)
	if emptyReport.ReportID != omittedReport.ReportID {
		t.Fatalf("explicit-empty and omitted text must share the report id:\n%s\n%s",
			emptyReport.ReportID, omittedReport.ReportID)
	}
	// 成功的提交必须落盘且可按标识读回。
	savedPath := filepath.Join(store, emptyReport.ReportID+".json")
	if _, err := os.Stat(savedPath); err != nil {
		t.Fatalf("a successful submission must archive the report: %v", err)
	}
}

// --- 大小写变体或带空格名称中的值是扩展信息：不触发错误，也不能挽救正式 null ---

func TestCLIAuditRuleTextVariantRules(t *testing.T) {
	bin := auditBinary(t)

	// 正式 kind 省略、变体携带 null：仍是一份合法提交，kind 读回空，报告标识
	// 与完全省略时一致。
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	variantNull := ruleTextAuditInput(
		`"id":"r1","Kind":null,"severity":"high","invariant":"inv1","requiresABI":false,"version":"1.0.0"`)
	input := writeInput(t, work, "in.json", variantNull)
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("a case-variant null member must not reject the submission: %s", stderr)
	}
	report := decodeReport(t, stdout)
	if report.Rules[0].Kind != "" {
		t.Fatalf("a variant member must not supply the formal kind: %q", report.Rules[0].Kind)
	}

	// 正式 kind 为 null，旁边的变体写了合法字符串（位于其前或其后）都必须失败。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			sub := t.TempDir()
			subStore := filepath.Join(sub, "reports")
			var pairs string
			if pos == "before" {
				pairs = `"id":"r1","Kind":"static","kind":null,"severity":"high","invariant":"inv1","requiresABI":false,"version":"1.0.0"`
			} else {
				pairs = `"id":"r1","kind":null,"Kind":"static","severity":"high","invariant":"inv1","requiresABI":false,"version":"1.0.0"`
			}
			subInput := writeInput(t, sub, "in.json", ruleTextAuditInput(pairs))
			out, errText, exitCode := runCLIAudit(t, bin, subInput, subStore)
			if exitCode == 0 {
				t.Fatal("a variant member must not rescue a null formal kind")
			}
			if out != "" {
				t.Fatalf("stdout must stay empty:\n%s", out)
			}
			if !strings.Contains(errText, "rules[0]") || !strings.Contains(errText, "r1") ||
				!strings.Contains(errText, "kind must be a string") {
				t.Fatalf("stderr must name the position, rule and string requirement:\n%s", errText)
			}
			if _, err := os.Stat(subStore); !os.IsNotExist(err) {
				t.Fatalf("failure must not create the report store: %v", err)
			}
		})
	}

	// 带前后空格的名称同样不能挽救正式 null。
	padded := t.TempDir()
	paddedStore := filepath.Join(padded, "reports")
	pairs := `"id":"r1"," kind ":"static","kind":null,"severity":"high","invariant":"inv1","requiresABI":false,"version":"1.0.0"`
	paddedInput := writeInput(t, padded, "in.json", ruleTextAuditInput(pairs))
	out, errText, exitCode := runCLIAudit(t, bin, paddedInput, paddedStore)
	if exitCode == 0 || out != "" ||
		!strings.Contains(errText, "kind must be a string") {
		t.Fatalf("a whitespace-padded variant must not rescue the formal null: code=%d out=%s err=%s",
			exitCode, out, errText)
	}
}
