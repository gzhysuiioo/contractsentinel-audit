package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 report / diff 读取已保存报告时对缺陷
// 记录文本成员的类型要求：findings 中每条记录的 artifactHash、ruleId、
// version、severity、invariant、evidence，正式成员一旦写出就只能是 JSON
// 字符串。当规则与缺陷记录原本都把严重级别保存为空字符串时，归档里把它改
// 写成 null 仍会得到同标识、同归属的“成功读回”，把没有保存合法文本的事实
// 洗成合法空文本，diff 还可能判为“无变化”。修正后这类归档必须判为损坏——
// 非零退出、原因进 stderr（含报告标识、记录在 findings 数组中从零开始的
// 位置、成员名及“必须是字符串”；ruleId 是合法非空字符串时同时点名所属
// 规则），stdout 不出现任何报告片段，原归档原样保留。省略成员仍按既有
// 默认值与必填/绑定校验处理；Severity、" ruleId " 这类大小写变体或带空格
// 名称只是扩展信息，其中的 null 既不触发错误，也不能挽救非法的正式成员。
// diff 任一侧遇到同样的归档，也必须在输出比较结果前整体失败。

// cliEscapedS 是解码后等于字母 s 的六字符 JSON unicode 转义，用拼接写出，
// 避免源码里直接出现转义形态的字面量。
const cliEscapedS = `\` + `u0073`

// emptySeverityInput 构造一份合法提交：唯一的缺陷规则与检查记录都把严重
// 级别留空（severity 没有非空限制），因此落盘报告的 finding 写着
// "severity":""——把它改成 null 后普通解码无法区分二者，正是漏洞场景。
func emptySeverityInput(hash string, withExtraPass bool) cliWireInput {
	rules := []cliWireRule{
		{ID: "rule-empty", Kind: "static", Severity: "", Invariant: "inv-empty", Version: "1.0.0"},
	}
	checks := []cliWireCheck{
		{ArtifactHash: hash, RuleID: "rule-empty", Version: "1.0.0", Status: contractsentinel.StatusDefect, Note: "空级别反例证据"},
	}
	if withExtraPass {
		rules = append(rules,
			cliWireRule{ID: "rule-extra", Kind: "static", Severity: "info", Invariant: "inv-extra", Version: "2.0.0"})
		checks = append(checks,
			cliWireCheck{ArtifactHash: hash, RuleID: "rule-extra", Version: "2.0.0", Status: contractsentinel.StatusPass})
	}
	return cliWireInput{Artifact: mixedCheckArtifact(), Rules: rules, Checks: checks}
}

// auditEmptySeverityReport 通过真实 audit 命令落盘一份（可带额外通过规则的）
// 空严重级别缺陷报告并返回其报告标识。
func auditEmptySeverityReport(t *testing.T, bin, work, store, name string, withExtraPass bool) string {
	t.Helper()
	input := writeStructInput(t, work, name+".json", emptySeverityInput(mixedArtifactHash(t), withExtraPass))
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit %s must succeed: %s", name, stderr)
	}
	return decodeReport(t, stdout).ReportID
}

// injectFindingField reads the archive named by id, locates the finding whose
// ruleId matches and rewrites the formal field member with the raw fragment;
// when the finding does not carry the member it is inserted right after the
// ruleId member. The search spans the whole finding object so a member that
// precedes ruleId (artifactHash) is replaced in place rather than duplicated.
// The mutated bytes are written back and returned so tests can assert the
// failed read leaves them untouched.
func injectFindingField(t *testing.T, store, id, ruleID, field, fragment string) []byte {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	idMember := `"ruleId":"` + ruleID + `"`
	idIdx := strings.Index(doc, idMember)
	if idIdx < 0 {
		t.Fatalf("test setup: finding for rule %s not found in archive", ruleID)
	}
	objStart := strings.LastIndexByte(doc[:idIdx], '{')
	if objStart < 0 {
		t.Fatalf("test setup: finding for rule %s object has no start", ruleID)
	}
	objEnd := strings.IndexByte(doc[idIdx:], '}')
	if objEnd < 0 {
		t.Fatalf("test setup: finding for rule %s object has no end", ruleID)
	}
	objEnd += idIdx
	marker := `"` + field + `":`
	at := strings.Index(doc[objStart:objEnd], marker)
	var out string
	if at < 0 {
		idEnd := idIdx + len(idMember)
		out = doc[:idEnd] + `,"` + field + `":` + fragment + doc[idEnd:]
	} else {
		at += objStart
		valueStart := at + len(marker)
		var valueEnd int
		if doc[valueStart] == '"' {
			closing := strings.IndexByte(doc[valueStart+1:], '"')
			if closing < 0 {
				t.Fatalf("test setup: finding for rule %s %s value has no closing quote", ruleID, field)
			}
			valueEnd = valueStart + 1 + closing + 1
		} else {
			end := strings.IndexAny(doc[valueStart:], ",}")
			if end < 0 {
				t.Fatalf("test setup: finding for rule %s %s value has no end", ruleID, field)
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

// assertFindingTextCorruptFailure asserts the full CLI failure contract for a
// non-string formal finding member.
func assertFindingTextCorruptFailure(t *testing.T, stdout, stderr string, code int, id, position, rule, field string) {
	t.Helper()
	if code == 0 {
		t.Fatal("an archive with a non-string finding member must exit non-zero")
	}
	if !strings.Contains(stderr, "corrupt") {
		t.Fatalf("stderr must classify the archive as corrupt:\n%s", stderr)
	}
	if !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the report id %q:\n%s", id, stderr)
	}
	if !strings.Contains(stderr, position) {
		t.Fatalf("stderr must name the findings array position %q:\n%s", position, stderr)
	}
	if rule != "" && !strings.Contains(stderr, "(rule "+rule+")") {
		t.Fatalf("stderr must name the owning rule %q:\n%s", rule, stderr)
	}
	if !strings.Contains(stderr, field+" must be a string") {
		t.Fatalf("stderr must state %s must be a string:\n%s", field, stderr)
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- report：核心场景，空严重级别改成 null，标识与归属仍吻合也必须失败 ---

func TestCLIReportNullEmptySeverityFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditEmptySeverityReport(t, bin, work, store, "empty-sev", false)
	mutated := injectFindingField(t, store, id, "rule-empty", "severity", `null`)

	// null 被洗成 ""：归档文件名、归档内 reportId 与按解码内容重算的标识
	// 全部保持不变，证据与归属也吻合，拒绝只能来自类型关。
	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertFindingTextCorruptFailure(t, stdout, stderr, code, id, "findings[0]", "rule-empty", "severity")
	for _, marker := range []string{`"reportId"`, `"rules"`, `"findings"`, `"artifactHash"`, "发现缺陷", "空级别反例证据"} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a report fragment %q:\n%s", marker, stdout)
		}
	}

	// 原归档必须原样保留，不被自动修补；重复读取始终失败。
	for i := 0; i < 2; i++ {
		if _, _, again := runCLIReport(t, bin, store, id); again == 0 {
			t.Fatal("repeated report reads must keep failing")
		}
	}
	if kept, err := os.ReadFile(filepath.Join(store, id+".json")); err != nil || !bytes.Equal(kept, mutated) {
		t.Fatalf("failed report read must leave the corrupt archive untouched: %v", err)
	}
}

// --- report：六个文本成员写成 null 都判为损坏，位置、字段与所属规则齐全 ---

func TestCLIReportNullFindingFieldsFailCleanly(t *testing.T) {
	for _, tc := range []struct {
		field string
		rule  string // ruleId 本身非法时没有可点名的所属规则
	}{
		{"artifactHash", "rule-empty"},
		{"ruleId", ""},
		{"version", "rule-empty"},
		{"severity", "rule-empty"},
		{"invariant", "rule-empty"},
		{"evidence", "rule-empty"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditEmptySeverityReport(t, bin, work, store, "empty-sev-"+tc.field, false)
			injectFindingField(t, store, id, "rule-empty", tc.field, `null`)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertFindingTextCorruptFailure(t, stdout, stderr, code, id, "findings[0]", tc.rule, tc.field)
		})
	}
}

// --- report：布尔值、数字、对象、数组都同样判为损坏，不能默认成空字符串 ---

func TestCLIReportNonStringFindingFailsCleanly(t *testing.T) {
	for _, val := range []string{`true`, `false`, `0`, `1`, `{}`, `[]`, `["x"]`} {
		t.Run(val, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditEmptySeverityReport(t, bin, work, store, "empty-sev", false)
			injectFindingField(t, store, id, "rule-empty", "evidence", val)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertFindingTextCorruptFailure(t, stdout, stderr, code, id, "findings[0]", "rule-empty", "evidence")
		})
	}
}

// --- report：变体名称中的 null 是扩展信息，既不触发错误也不能挽救正式 null ---

func TestCLIReportFindingTextVariantRules(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditEmptySeverityReport(t, bin, work, store, "empty-sev", false)

	// 变体携带 null：仍是一份合法报告，finding 的 severity 读回空字符串、
	// 证据与归属保持原值。
	injectFindingField(t, store, id, "rule-empty", "Severity", `null`)
	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("a case-variant extension member must not corrupt the report: %s", stderr)
	}
	decoded := decodeReport(t, stdout)
	if len(decoded.Findings) != 1 {
		t.Fatalf("legal report must keep its finding: %+v", decoded.Findings)
	}
	f := decoded.Findings[0]
	if f.Severity != "" || f.RuleID != "rule-empty" || f.Evidence != "空级别反例证据" {
		t.Fatalf("a variant member must not supply formal finding values: %+v", f)
	}

	// 正式成员为 null、旁边的变体写了合法字符串（位于其前或其后）都必须失败。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			sub := t.TempDir()
			subStore := filepath.Join(sub, "reports")
			subID := auditEmptySeverityReport(t, bin, sub, subStore, "sub", false)
			if pos == "before" {
				injectFindingField(t, subStore, subID, "rule-empty", "severity", `null`)
				injectFindingField(t, subStore, subID, "rule-empty", "Severity", `"high"`)
			} else {
				injectFindingField(t, subStore, subID, "rule-empty", "severity", `null,"Severity":"high"`)
			}
			out, errText, exitCode := runCLIReport(t, bin, subStore, subID)
			assertFindingTextCorruptFailure(t, out, errText, exitCode, subID, "findings[0]", "rule-empty", "severity")
		})
	}
}

// --- report：Unicode 转义拼出的正式名称遵守同一字符串规则 ---

func TestCLIReportEscapedFindingNameFollowsSameRule(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditEmptySeverityReport(t, bin, work, store, "empty-sev", false)

	// 把 finding 的正式 severity 名称整体改写成转义拼写并携带 null：名称
	// 解码后仍是 severity，必须判为损坏。
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := `"version":"1.0.0","severity":""`
	doc := strings.Replace(string(data), old, `"version":"1.0.0","`+cliEscapedS+`everity":null`, 1)
	if doc == string(data) {
		t.Fatal("test setup: escaped-name rewrite did not change the archive")
	}
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertFindingTextCorruptFailure(t, stdout, stderr, code, id, "findings[0]", "rule-empty", "severity")
}

// --- diff：任一侧归档 finding 含 null 文本成员，比较前整体失败，不输出局部
// 结果，不能把被默认成空字符串的错误值拿去分类或统计（否则会是“无变化”） ---

func TestCLIDiffNullFindingEitherSideFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := mixedArtifactHash(t)

	// 基准侧：只有空级别缺陷；新侧：同一缺陷再加一条无说明的通过规则。
	beforeID := auditEmptySeverityReport(t, bin, work, store, "before", false)
	afterID := auditEmptySeverityReport(t, bin, work, store, "after", true)
	cleanAfter, err := os.ReadFile(filepath.Join(store, afterID+".json"))
	if err != nil {
		t.Fatal(err)
	}

	// 新侧 finding 的空 severity 改成 null：null 被洗成 ""，归档标识保持
	// 不变，该规则两侧在解码后完全相同——若没有类型关，会被判成“无变化”。
	mutated := injectFindingField(t, store, afterID, "rule-empty", "severity", `null`)

	// 第二份损坏。
	stdout, stderr, code := runCLIDiff(t, bin, store, beforeID, afterID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the second report finding carries null")
	}
	if !strings.Contains(stderr, "corrupt") || !strings.Contains(stderr, afterID) ||
		!strings.Contains(stderr, "rule-empty") || !strings.Contains(stderr, "findings[0]") ||
		!strings.Contains(stderr, "severity must be a string") {
		t.Fatalf("stderr must name the corrupt report, position, rule and string requirement:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
	}
	for _, marker := range []string{`"results"`, `"summary"`, "无变化", "新增规则", `"findings"`} {
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
	injectFindingField(t, store, beforeID, "rule-empty", "invariant", `null`)
	stdout, stderr, code = runCLIDiff(t, bin, store, beforeID, afterID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the first report finding carries null")
	}
	if !strings.Contains(stderr, beforeID) || !strings.Contains(stderr, "rule-empty") ||
		!strings.Contains(stderr, "invariant must be a string") {
		t.Fatalf("stderr must name the corrupt first report, rule and field:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must stay empty on failure:\n%s", stdout)
	}

	// 两侧都恢复后比较成功：空级别缺陷为“无变化”，额外通过规则为“新增规则”，
	// 且成功的比较不重写任何一侧归档。第一侧已被改成 invariant:null，把相同
	// 合法提交审计进独立存储取回干净字节，再恢复主存储。
	cleanBeforeInput := writeStructInput(t, work, "before-clean.json", emptySeverityInput(hash, false))
	if _, _, code := runCLIAudit(t, bin, cleanBeforeInput, filepath.Join(work, "clean-b")); code != 0 {
		t.Fatal("setup clean-b audit must succeed")
	}
	cleanBefore, err := os.ReadFile(filepath.Join(work, "clean-b", beforeID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, beforeID+".json"), cleanBefore, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLIDiff(t, bin, store, beforeID, afterID)
	if code != 0 {
		t.Fatalf("restored archives must diff successfully: %s", stderr)
	}
	d := decodeDiff(t, stdout)
	if d.Summary.NoChange != 1 || d.Summary.AddedRules != 1 {
		t.Fatalf("legal comparison must classify from legal findings only: %+v", d.Summary)
	}
	if d.Summary.BeforeDefects != 1 || d.Summary.AfterDefects != 1 {
		t.Fatalf("defect totals must stay 1/1: %+v", d.Summary)
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

// --- audit 保存遇到同标识已有损坏归档：不能当成保存成功，原文件保留 ---

func TestCLIAuditFindingTextCorruptExistingArchiveFailsAndKeepsFile(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditEmptySeverityReport(t, bin, work, store, "empty-sev", false)
	path := filepath.Join(store, id+".json")
	injectFindingField(t, store, id, "rule-empty", "evidence", `null`)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 用完全相同的合法提交再审计一次：同标识归档已损坏，必须失败。
	input := writeStructInput(t, work, "again.json", emptySeverityInput(mixedArtifactHash(t), false))
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("audit against a corrupt existing archive must exit non-zero")
	}
	if !strings.Contains(stderr, "corrupt") || !strings.Contains(stderr, id) ||
		!strings.Contains(stderr, "rule-empty") || !strings.Contains(stderr, "evidence must be a string") {
		t.Fatalf("stderr must report the finding text corruption:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("failed audit must print nothing to stdout:\n%s", stdout)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must be kept: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed audit must leave the corrupt archive untouched")
	}
}
