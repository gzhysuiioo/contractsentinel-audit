package contractsentinel

import (
	"strings"
	"testing"
)

// 本文件锁定重复成员错误定位对“合法大数扩展值”的免疫力：1e1000 这类
// 超出 float64 的 JSON 数字是合法的扩展内容（不参与任何固定字段），
// 它出现在顶层、其他记录或出错记录自身的嵌套扩展里时，重复成员错误
// 仍必须点名出错记录的正式标识（rules 用 id，checks/findings 用
// ruleId）与从零开始的数组位置，不能退化成只剩位置。标识只取自出错
// 记录自己的正式成员：按 JSON 解码后的名称与字符串值识别，等价
// Unicode 转义写法有效，大小写变体、带空格的成员名、其他记录的标识
// 都不能补位；标识缺失、为空或非字符串时保留记录类型与位置，不编造
// 规则名。没有重复成员时，大数扩展值继续作为扩展信息忽略。

// bigNumberTopLevel 在顶层扩展成员里放一个超出 float64 的合法大数。
const bigNumberTopLevel = `"extension": {"tolerance": 1e1000, "nested": [[2E+999]]}`

func TestParseAuditInputDuplicateRuleBigNumberTopLevel(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":"rule-a","kind":"static","severity":"low","invariant":"a","version":"1"},
			{"id":"rule-b","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}
		],
		` + bigNumberTopLevel + `
	}`)
	// 大数在顶层扩展里：规则归属不能丢。
	expectDupRejection(t, data, `"severity"`, `rule "rule-b"`, "rules[1]")
}

func TestParseAuditInputDuplicateRuleBigNumberInOtherRecord(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":"rule-a","kind":"static","severity":"low","invariant":"a","version":"1","extra":{"limit":1e1000}},
			{"id":"rule-b","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}
		]
	}`)
	// 大数在另一条规则的扩展里：仍点名出错的那一条。
	expectDupRejection(t, data, `"severity"`, `rule "rule-b"`, "rules[1]")
}

func TestParseAuditInputDuplicateRuleBigNumberInOffendingRecord(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":"rule-b","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1","extra":{"deep":[{"limit":1e1000}]}}
		]
	}`)
	// 大数就在出错记录自己的嵌套扩展内容里：归属同样保留。
	expectDupRejection(t, data, `"severity"`, `rule "rule-b"`, "rules[0]")
}

func TestParseAuditInputDuplicateCheckBigNumberNamesRule(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":"rule-a","kind":"static","severity":"high","invariant":"a","version":"1"},
			{"id":"rule-b","kind":"static","severity":"high","invariant":"b","version":"1"}
		],
		"checks": [
			{"ruleId":"rule-a","version":"1","status":"通过"},
			{"ruleId":"rule-b","version":"1","status":"发现缺陷","status":"通过","note":"x"}
		],
		` + bigNumberTopLevel + `
	}`)
	expectDupRejection(t, data, `"status"`, `rule "rule-b"`, "checks[1]")
}

func TestParseAuditInputDuplicateNestedInRecordKeepsPath(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":"规则 α","kind":"static","severity":"low","invariant":"a","version":"1","extra":{"a":1,"a":2}}
		],
		` + bigNumberTopLevel + `
	}`)
	// 重复发生在记录内的嵌套对象：保留通向该对象的路径，且规则名中的
	// 中文与空格原样保留，不被修剪。
	expectDupRejection(t, data, `"a"`, `rule "规则 α"`, "rules[0].extra")
}

// --- 标识纪律：只认出错了记录自己的正式成员 ---

func TestParseAuditInputDuplicateRuleIDCaseVariantNotUsed(t *testing.T) {
	// "Id" 与 " id " 只是扩展数据，不能冒充正式标识；错误退到记录类型与位置。
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"Id":"fake","kind":"static","severity":"high","severity":"low","version":"1"},
			{" id ":"padded","kind":"static","severity":"high","severity":"low","version":"1"}
		]
	}`)
	expectDupRejection(t, data, `"severity"`, "rule entry rules[0]")
	msg := duplicateMemberMessage(data, findDuplicateJSONMember(data))
	if strings.Contains(msg, "fake") || strings.Contains(msg, "padded") {
		t.Fatalf("case/whitespace variants must not pose as the formal id: %s", msg)
	}
}

func TestParseAuditInputDuplicateRuleIDEscapedSpellingUsed(t *testing.T) {
	// "id"（0x69 == 'i'）解码后就是正式成员名，转义写法同样有效。
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":"rule-escaped","kind":"static","severity":"high","severity":"low","version":"1"}
		]
	}`)
	expectDupRejection(t, data, `"severity"`, `rule "rule-escaped"`, "rules[0]")
}

func TestParseAuditInputDuplicateRuleIDNonStringNotUsed(t *testing.T) {
	// 正式 id 不是字符串（这里写成数字）时不能当标识用，仍保留类型与位置。
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":7,"kind":"static","severity":"high","severity":"low","version":"1"}
		]
	}`)
	expectDupRejection(t, data, `"severity"`, "rule entry rules[0]")
}

func TestParseAuditInputDuplicateRuleIDEmptyNotUsed(t *testing.T) {
	// 空标识不点名，但记录类型与数组位置仍在。
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":"","kind":"static","severity":"high","severity":"low","version":"1"}
		]
	}`)
	expectDupRejection(t, data, `"severity"`, "rule entry rules[0]")
}

func TestParseAuditInputDuplicateCheckOtherRecordIDNotUsed(t *testing.T) {
	// 出错记录自己没有 ruleId 时，不能拿另一条记录的标识补位。
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [{"id":"rule-a","kind":"static","severity":"high","invariant":"a","version":"1"}],
		"checks": [
			{"ruleId":"rule-a","version":"1","status":"通过"},
			{"version":"1","status":"发现缺陷","status":"通过","note":"x"}
		]
	}`)
	expectDupRejection(t, data, `"status"`, "check record checks[1]")
	msg := duplicateMemberMessage(data, findDuplicateJSONMember(data))
	if strings.Contains(msg, "rule-a") {
		t.Fatalf("another record's ruleId must not stand in: %s", msg)
	}
}

// --- 没有重复成员时：大数扩展值继续作为扩展信息忽略，不新增数值限制 ---

func TestParseAuditInputLegalBigNumberExtensionIgnored(t *testing.T) {
	base := `{"artifact":{"name":"A"},"rules":[{"id":"r1","kind":"static","severity":"low","invariant":"inv","version":"1"}],"invariants":{"inv":true}}`
	withBig := `{"artifact":{"name":"A"},"rules":[{"id":"r1","kind":"static","severity":"low","invariant":"inv","version":"1","extra":{"deep":[1e1000,{"x":2E+999}]}}],"invariants":{"inv":true},"tolerance":1e1000}`
	a1, r1, i1, c1, err := ParseAuditInput([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	a2, r2, i2, c2, err := ParseAuditInput([]byte(withBig))
	if err != nil {
		t.Fatalf("a legal oversized exponent is extension data, not an error: %v", err)
	}
	rep1, err := BuildReport(a1, r1, i1, c1)
	if err != nil {
		t.Fatal(err)
	}
	rep2, err := BuildReport(a2, r2, i2, c2)
	if err != nil {
		t.Fatal(err)
	}
	if ReportID(rep1) != ReportID(rep2) {
		t.Fatal("extension content must not change the report id")
	}
	if len(rep2.Rules) != 1 || rep2.Rules[0].Status != StatusPass {
		t.Fatalf("rule conclusion must be unchanged: %+v", rep2.Rules)
	}
}

// --- 归档读取侧：同样的归属规则 ---

func TestLoadReportDuplicateFindingBigNumberNamesRule(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(), func(doc string) string {
		doc = dupOnce(`"ruleId":"r-bad"`, `"ruleId":"r-bad","ruleId":"r-bad"`)(doc)
		// 顶层扩展里的大数不能使缺陷记录的规则归属消失。
		return dupOnce(`{"reportId"`, `{"extra":{"tolerance":1e1000},"reportId"`)(doc)
	})
	expectCorruptDupLoad(t, dir, id, `"ruleId"`, `finding for rule "r-bad"`, "findings[0]")
}

func TestLoadReportDuplicateRuleBigNumberInOffendingRule(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(), func(doc string) string {
		// 大数就在出错规则自己的嵌套扩展里，且该规则的 status 成员重复。
		return dupOnce(`{"id":"r-none"`,
			`{"id":"r-none","extra":[{"limit":1e1000}],"status":"`+StatusUnchecked+`","status":"`+StatusUnchecked+`"`)(doc)
	})
	expectCorruptDupLoad(t, dir, id, `"status"`, `rule "r-none"`, "rules[2]")
}

func TestLoadReportLegalBigNumberExtensionStillLoads(t *testing.T) {
	dir := t.TempDir()
	r := oneDefectFixture()
	id := writeDupArchiveText(t, dir, r,
		dupOnce(`{"reportId"`, `{"extra":{"tolerance":1e1000,"deep":[[2E+999]]},"reportId"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal oversized exponent in extension data must stay ignored: %v", err)
	}
	if loaded.ReportID != id {
		t.Fatalf("legal report id not preserved: %q", loaded.ReportID)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].Evidence != "counterexample: x" {
		t.Fatalf("findings and evidence must be unchanged: %+v", loaded.Findings)
	}
}
