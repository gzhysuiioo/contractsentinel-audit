package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 本文件锁定“重复成员错误定位不受无关大数扩展值干扰”的修复：同一份 JSON
// 里任何位置出现合法的大数扩展值（如 1e1000）时，重复成员仍被整份拒绝，
// 且错误信息继续点名出错记录的正式标识（规则 id / 记录 ruleId）、数组位置
// 与嵌套路径。标识只取自出错记录自己的正式成员：按 JSON 解码后的名称与
// 字符串值识别，等价 Unicode 转义有效，大小写变体与带空白的名字不算数，
// 也不拿其他记录的标识补位。

const dupBigArtifact = `{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`

// --- 大数扩展值在顶层：规则对象的重复成员仍点名规则 id ---

func TestDuplicateRuleIDKeptWithTopLevelBigNumber(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupBigArtifact + `,
		"rules": [
			{"id":"rule-a","kind":"static","severity":"low","invariant":"a","version":"1"},
			{"id":"rule-b","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}
		],
		"mystery": 1e1000
	}`)
	expectDupRejection(t, data, `"severity"`, `rule "rule-b"`, "rules[1]")
}

// --- 大数扩展值在其他记录里：检查记录的重复成员仍点名 ruleId ---

func TestDuplicateCheckRuleIDKeptWithBigNumberInOtherRecord(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupBigArtifact + `,
		"rules": [
			{"id":"rule-a","kind":"static","severity":"high","invariant":"a","version":"1","ext":1e1000},
			{"id":"rule-b","kind":"static","severity":"high","invariant":"b","version":"1"}
		],
		"checks": [
			{"ruleId":"rule-a","version":"1","status":"通过"},
			{"ruleId":"rule-b","version":"1","status":"发现缺陷","status":"通过"}
		]
	}`)
	expectDupRejection(t, data, `"status"`, `rule "rule-b"`, "checks[1]")
}

// --- 大数扩展值在出错记录自己的嵌套扩展内容里：标识与嵌套路径都保留 ---

func TestDuplicateNestedPathKeptWithBigNumberInsideOffendingRecord(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupBigArtifact + `,
		"rules": [
			{"id":"rule-a","kind":"static","severity":"low","invariant":"a","version":"1"},
			{"id":"rule-b","kind":"static","severity":"high","invariant":"b","version":"1",
				"ext":{"deep":1e1000,"again":{"x":1,"x":2}}}
		]
	}`)
	expectDupRejection(t, data, `"x"`, `rule "rule-b"`, "rules[1].ext.again")
}

// --- 标识识别：等价 Unicode 转义的正式成员名仍作数 ---

func TestDuplicateRuleIDUnicodeEscapedNameStillIdentifies(t *testing.T) {
	// "id" 与 "id"（0x69 == 'i'）解码后是同一个正式成员名。
	data := []byte(`{
		"artifact": ` + dupBigArtifact + `,
		"rules": [
			{"id":"rule-b","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}
		],
		"mystery": 1e1000
	}`)
	expectDupRejection(t, data, `"severity"`, `rule "rule-b"`, "rules[0]")
}

// --- 标识识别：大小写变体与带空白的成员名不能冒充正式标识 ---

func TestDuplicateRuleIDCaseAndWhitespaceVariantsNotUsed(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupBigArtifact + `,
		"rules": [
			{"Id":"fake","id ":"also-fake","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}
		],
		"mystery": 1e1000
	}`)
	msg := dupErrorMessage(t, data)
	if strings.Contains(msg, "fake") {
		t.Fatalf("case/whitespace variants must not pose as the formal id: %q", msg)
	}
	if !strings.Contains(msg, "rule entry rules[0]") {
		t.Fatalf("without a formal id the record type and index must remain: %q", msg)
	}
}

// --- 标识识别：不能拿其他记录的标识补位 ---

func TestDuplicateCheckRuleIDNotBorrowedFromSibling(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupBigArtifact + `,
		"rules": [{"id":"rule-a","kind":"static","severity":"high","invariant":"a","version":"1"}],
		"checks": [
			{"ruleId":"rule-a","version":"1","status":"通过"},
			{"version":"1","status":"发现缺陷","status":"通过"}
		],
		"mystery": 1e1000
	}`)
	msg := dupErrorMessage(t, data)
	if strings.Contains(msg, "rule-a") {
		t.Fatalf("the sibling record's ruleId must not be borrowed: %q", msg)
	}
	if !strings.Contains(msg, "check record checks[1]") {
		t.Fatalf("record type and array position must remain: %q", msg)
	}
}

// --- 标识缺失、为空或不是字符串：保留记录类型、数组位置与嵌套路径 ---

func TestDuplicateRuleIDMissingEmptyOrNonString(t *testing.T) {
	cases := map[string]string{
		"missing":     `{"kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}`,
		"empty":       `{"id":"","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}`,
		"non-string":  `{"id":7,"kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}`,
		"nested path": `{"id":"","kind":"static","severity":"high","invariant":"b","version":"1","ext":{"x":1,"x":2}}`,
	}
	for name, entry := range cases {
		data := []byte(`{
			"artifact": ` + dupBigArtifact + `,
			"rules": [` + entry + `],
			"mystery": 1e1000
		}`)
		msg := dupErrorMessage(t, data)
		if !strings.Contains(msg, "rule entry rules[0]") {
			t.Fatalf("%s: record type and array position must remain: %q", name, msg)
		}
		if name == "nested path" && !strings.Contains(msg, "rules[0].ext") {
			t.Fatalf("%s: the nested path must remain: %q", name, msg)
		}
	}
}

// --- 规则名称中的中文和空格保持原意 ---

func TestDuplicateRuleIDChineseAndSpacesPreserved(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupBigArtifact + `,
		"rules": [
			{"id":"规则 一","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}
		],
		"mystery": 1e1000
	}`)
	expectDupRejection(t, data, `"severity"`, `rule "规则 一"`, "rules[0]")
}

// --- 没有重复成员且其他内容合法：大数扩展值继续作为扩展信息忽略 ---

func TestBigNumberExtensionStillIgnoredWhenLegal(t *testing.T) {
	baseline := []byte(`{
		"artifact": ` + dupBigArtifact + `,
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1"}],
		"invariants": {"inv": false}
	}`)
	big := []byte(`{
		"artifact": ` + dupBigArtifact + `,
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1","ext":1e1000}],
		"invariants": {"inv": false},
		"mystery": [1e1000, {"deep": 1e1000}]
	}`)
	a0, r0, i0, c0, err := ParseAuditInput(baseline)
	if err != nil {
		t.Fatalf("baseline must parse: %v", err)
	}
	a1, r1, i1, c1, err := ParseAuditInput(big)
	if err != nil {
		t.Fatalf("legal big-number extension must stay ignored, not gain a range limit: %v", err)
	}
	rep0, err := BuildReport(a0, r0, i0, c0)
	if err != nil {
		t.Fatal(err)
	}
	rep1, err := BuildReport(a1, r1, i1, c1)
	if err != nil {
		t.Fatal(err)
	}
	if rep1.ReportID != rep0.ReportID {
		t.Fatalf("big-number extension must not change the report id: %s vs %s", rep0.ReportID, rep1.ReportID)
	}
	if len(rep1.Findings) != 1 || rep1.Findings[0].Evidence != "invariant inv does not hold" {
		t.Fatalf("defect and evidence must be preserved: %+v", rep1.Findings)
	}
}

// --- 归档读取侧：findings 重复成员 + 大数扩展值仍点名 ruleId 与报告标识 ---

func TestLoadReportDuplicateFindingRuleIDKeptWithBigNumber(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"ruleId":"r-bad"`, `"ruleId":"r-bad","ruleId":"r-bad","ext":1e1000`))
	expectCorruptDupLoad(t, dir, id, `"ruleId"`, `finding for rule "r-bad"`, "findings[0]")
}

// --- 归档读取侧：合法归档夹带大数扩展值仍按原样读出 ---

func TestLoadReportBigNumberExtensionStillIgnored(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`{"reportId"`, `{"mystery":1e1000,"reportId"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal big-number extension must stay ignored: %v", err)
	}
	if loaded.ReportID != id {
		t.Fatalf("legal report id not preserved: %q", loaded.ReportID)
	}
}

// dupErrorMessage returns the ParseAuditInput error text for a duplicate
// submission, failing the test if the submission is not rejected as errInvalid.
func dupErrorMessage(t *testing.T, data []byte) string {
	t.Helper()
	_, _, _, _, err := ParseAuditInput(data)
	if err == nil {
		t.Fatalf("submission with a duplicate member must be rejected: %s", data)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid, got %T: %v", err, err)
	}
	return err.Error()
}
