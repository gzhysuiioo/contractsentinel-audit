package contractsentinel

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交侧规则定义五个文本成员 id、kind、severity、
// invariant、version 的类型规则。它们在 wireRule 中都是 Go 字符串，
// json.Unmarshal 会把正式成员的 null 静默解码成零值 ""：一条 id 与 version
// 合法的规则，即使 kind、severity 或 invariant 写成 null，也可能通过全部
// 业务检查并生成报告，空掉的定义与用户明确提交空字符串得到的规则定义、
// 报告标识和缺陷绑定完全相同，格式错误被洗成了合法提交。
//
// 修正后，五个正式成员（约定拼写，含 Unicode 转义写法）一旦写出，其值就
// 必须是 JSON 字符串；null、布尔值、数字、对象、数组都使整份提交失败
// （errInvalid），与该规则是否被检查、是否产生缺陷无关，其他规则和检查
// 记录合法也不能挽救。错误点名 rules 数组中从零开始的位置与出错成员并
// 说明必须为字符串，规则有合法非空 id 时同时点名该 id；id 自身非法时凭
// 位置定位。省略成员与显式空字符串仍按既有默认值与业务要求判断；
// Kind、带前后空格的名称及未知成员只是扩展信息，其中的 null 不触发错误，
// 合法字符串也不能补上缺失字段或挽救非法正式字段。

// ruleTextSubmission 拼装一份 audit 提交：rulesJSON 是 rules 数组的完整
// JSON（含方括号），extra 是追加的顶层片段（invariants、checks 等）。
func ruleTextSubmission(rulesJSON string, extra ...string) string {
	sections := append([]string{`"artifact":` + strictArtifactJSON, `"rules":` + rulesJSON}, extra...)
	return strictDoc(sections...)
}

// ruleObject 用给出的原始成员片段拼出一个规则对象。
func ruleObject(members ...string) string {
	return "{" + strings.Join(members, ",") + "}"
}

// expectInvalidRuleText 断言整份提交被拒绝：errInvalid、错误点名 rules
// 数组位置、字段与字符串要求；id 参数为""时错误不得携带规则标识。
func expectInvalidRuleText(t *testing.T, in, position, id, field string) {
	t.Helper()
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err == nil {
		t.Fatalf("a non-string formal %s must reject the whole submission\ninput: %s", field, in)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("a rule text type error is a submission format error (errInvalid), got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, position) {
		t.Fatalf("error must name the rules-array position %q: %v", position, err)
	}
	if !strings.Contains(msg, field+" must be a string") {
		t.Fatalf("error must state %s must be a string: %v", field, err)
	}
	if id != "" {
		if !strings.Contains(msg, "(rule "+id+")") {
			t.Fatalf("error must name the legal rule id %q: %v", id, err)
		}
	} else if strings.Contains(msg, "(rule ") {
		t.Fatalf("an illegal id must leave the rule locatable by position alone: %v", err)
	}
	// 这是规则定义的提交格式错误，不得记成任何检查结论。
	for _, marker := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		if strings.Contains(msg, marker) {
			t.Fatalf("a format error must not be reported as the conclusion %q: %v", marker, err)
		}
	}
	if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
		t.Fatalf("rejection must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
	}
}

// --- 核心场景：id 与 version 合法，kind/severity/invariant 为 null 也必须拒绝 ---

func TestParseAuditNullRuleDefinitionTextRejected(t *testing.T) {
	for _, field := range []string{"kind", "severity", "invariant"} {
		t.Run(field, func(t *testing.T) {
			// 没有检查记录：规则只会依据 invariant 布尔值得出结论，与类型关无关。
			rule := ruleObject(`"id":"r1"`, `"`+field+`":null`,
				`"requiresABI":false`, `"version":"1.0.0"`)
			in := ruleTextSubmission("["+rule+"]", `"invariants":{"inv":true}`)
			expectInvalidRuleText(t, in, "rules[0]", "r1", field)
		})
	}
}

// --- 五个文本成员写成 null 都整份拒绝；id 自身非法时只凭位置定位 ---

func TestParseAuditNullRuleTextFieldsRejected(t *testing.T) {
	for _, field := range submissionRuleTextFields {
		t.Run(field, func(t *testing.T) {
			// id 自身为 null 时没有可点名的合法规则标识，其余字段仍可定位规则。
			id := "r1"
			if field == "id" {
				id = ""
			}
			expectInvalidRuleText(t, ruleTextSubmission("["+ruleTextWithValue(field, "null")+"]"),
				"rules[0]", id, field)
		})
	}
}

// --- 布尔值、数字、对象、数组同样整份拒绝，不能被当成空字符串 ---

// ruleTextWithValue 构造一条五个文本成员齐全的规则，仅把 field 的值换成
// 原始片段 val（其余成员保持合法字符串）。
func ruleTextWithValue(field, val string) string {
	values := map[string]string{
		"id": `"r1"`, "kind": `"static"`, "severity": `"high"`,
		"invariant": `"inv"`, "version": `"1.0.0"`,
	}
	values[field] = val
	members := make([]string, 0, len(submissionRuleTextFields))
	for _, f := range submissionRuleTextFields {
		members = append(members, `"`+f+`":`+values[f])
	}
	return ruleObject(members...)
}

func TestParseAuditNonStringRuleTextFieldsRejected(t *testing.T) {
	values := []string{"true", "false", "0", "123", "{}", "[]", `["x"]`}
	for _, field := range submissionRuleTextFields {
		for _, val := range values {
			t.Run(field+"/"+val, func(t *testing.T) {
				in := ruleTextSubmission("[" + ruleTextWithValue(field, val) + "]")
				artifact, _, _, _, err := ParseAuditInput([]byte(in))
				if err == nil {
					t.Fatalf("%s=%s must reject the whole submission", field, val)
				}
				if !strings.Contains(err.Error(), "rules[0]") ||
					!strings.Contains(err.Error(), field+" must be a string") {
					t.Fatalf("error must name the position, field and string requirement: %v", err)
				}
				if artifact != (Artifact{}) {
					t.Fatalf("rejection must return no partial artifact: %+v", artifact)
				}
			})
		}
	}
}

// --- 位置与点名：出错规则按数组下标定位，规则内按正式字段顺序报第一个 ---

func TestParseAuditRuleTextErrorNamesPositionAndID(t *testing.T) {
	// 第二条规则非法：错误必须点名 rules[1] 与它的合法 id，而不是第一条。
	rules := "[" +
		ruleObject(`"id":"r0"`, `"kind":"static"`, `"severity":"low"`, `"invariant":"i0"`, `"version":"1"`) + "," +
		ruleObject(`"id":"r2"`, `"kind":null`, `"severity":"high"`, `"invariant":"i2"`, `"version":"2"`) +
		"]"
	expectInvalidRuleText(t, ruleTextSubmission(rules), "rules[1]", "r2", "kind")

	// 同一规则内多个字段非法且书写顺序任意：按 id、kind、severity、
	// invariant、version 的正式顺序报第一个，这里是 kind 而不是 severity。
	rule := `{"severity":null,"invariant":null,"id":"r9","kind":null,"version":"9"}`
	expectInvalidRuleText(t, ruleTextSubmission("["+rule+"]"), "rules[0]", "r9", "kind")

	// 多条规则非法：报数组中最靠前的一条。
	twoBad := "[" +
		ruleObject(`"id":"a"`, `"version":"1"`, `"severity":null`) + "," +
		ruleObject(`"id":"b"`, `"version":"2"`, `"kind":null`) +
		"]"
	_, _, _, _, err := ParseAuditInput([]byte(ruleTextSubmission(twoBad)))
	if err == nil || !strings.Contains(err.Error(), "rules[0]") ||
		!strings.Contains(err.Error(), "severity must be a string") {
		t.Fatalf("the first offending rule must be reported by its array index: %v", err)
	}
}

// --- 与检查记录无关：该规则有合法检查结论，或其他规则、检查记录全部合法，
// 都不能使提交成功；格式错误不被记成缺陷、工具缺失或超时 ---

func TestParseAuditNullRuleTextRejectedRegardlessOfChecks(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	// 非法规则本身带着一条完全合法的“发现缺陷”检查记录：仍在构建报告前拒绝。
	badRule := ruleObject(`"id":"r1"`, `"kind":null`, `"severity":"high"`,
		`"invariant":"inv"`, `"version":"1.0.0"`)
	defectCheck := fmt.Sprintf(
		`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","status":"发现缺陷","note":"ce"}`, hash)
	in := ruleTextSubmission("["+badRule+"]", `"checks":[`+defectCheck+`]`)
	expectInvalidRuleText(t, in, "rules[0]", "r1", "kind")

	// 另一条规则及其“通过”检查记录完全合法，也不能挽救第二条规则的 null。
	goodRule := ruleObject(`"id":"r1"`, `"kind":"static"`, `"severity":"low"`,
		`"invariant":"i1"`, `"version":"1.0.0"`)
	otherBad := ruleObject(`"id":"r2"`, `"kind":"static"`, `"severity":null`,
		`"invariant":"i2"`, `"version":"2.0.0"`)
	passCheck := fmt.Sprintf(
		`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","status":"通过"}`, hash)
	in = ruleTextSubmission("["+goodRule+","+otherBad+"]", `"checks":[`+passCheck+`]`)
	expectInvalidRuleText(t, in, "rules[1]", "r2", "severity")
}

// --- 省略成员仍取默认值；显式空字符串是合法字符串，业务判断保持原样 ---

func TestParseAuditRuleTextOmittedAndExplicitEmpty(t *testing.T) {
	// 省略 kind/severity/invariant：解析合法，三者取零值 ""。
	omitted := ruleTextSubmission("[" + ruleObject(`"id":"r1"`, `"version":"1.0.0"`) + "]")
	aOmit, rulesOmit, _, _, err := ParseAuditInput([]byte(omitted))
	if err != nil {
		t.Fatalf("omitted text members must keep their defaults: %v", err)
	}
	if rulesOmit[0].Kind != "" || rulesOmit[0].Severity != "" || rulesOmit[0].Invariant != "" {
		t.Fatalf("omitted members must decode to empty strings: %+v", rulesOmit[0])
	}

	// 显式空字符串：同样解析合法，规则定义与省略写法逐字段相同，报告标识一致。
	explicitEmpty := ruleTextSubmission("[" + ruleObject(
		`"id":"r1"`, `"kind":""`, `"severity":""`, `"invariant":""`, `"version":"1.0.0"`) + "]")
	aEmpty, rulesEmpty, _, _, err := ParseAuditInput([]byte(explicitEmpty))
	if err != nil {
		t.Fatalf("explicit empty strings must be legal strings: %v", err)
	}
	if aEmpty != aOmit || len(rulesEmpty) != 1 || rulesEmpty[0] != rulesOmit[0] {
		t.Fatalf("omitted and explicit-empty must decode to the same values")
	}
	if strictParsedReport(t, omitted).ReportID != strictParsedReport(t, explicitEmpty).ReportID {
		t.Fatal("omitted and explicit-empty text must share the report id")
	}

	// 显式空 id：通过类型关，但仍被既有“rule id is required”业务规则拒绝。
	emptyID := ruleTextSubmission("[" + ruleObject(`"id":""`, `"version":"1.0.0"`) + "]")
	a, rules, _, _, err := ParseAuditInput([]byte(emptyID))
	if err != nil {
		t.Fatalf("an explicit empty id is a legal string and must parse: %v", err)
	}
	if _, err := BuildReport(a, rules, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "rule id is required") ||
		strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an empty id must keep the required-id business error, got: %v", err)
	}

	// 显式空 version：仍是既有必填版本业务错误，不是类型错误。
	emptyVersion := ruleTextSubmission("[" + ruleObject(`"id":"r1"`, `"version":""`) + "]")
	a, rules, _, _, err = ParseAuditInput([]byte(emptyVersion))
	if err != nil {
		t.Fatalf("an explicit empty version is a legal string and must parse: %v", err)
	}
	if _, err := BuildReport(a, rules, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "version is required") ||
		strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an empty version must keep the required-version business error, got: %v", err)
	}
}

// --- 合法字符串逐字保留：中文、换行与前后空格，且产物哈希与报告标识保持原值 ---

func TestParseAuditLegalRuleTextPreservedVerbatim(t *testing.T) {
	id := " 规则 1\n "
	kind := " 静态\n类型 "
	severity := " 高 "
	invariant := "不变式\nx"
	version := " v1\n "
	rule := ruleObject(
		`"id":`+jsonString(id),
		`"kind":`+jsonString(kind),
		`"severity":`+jsonString(severity),
		`"invariant":`+jsonString(invariant),
		`"requiresABI":false`,
		`"version":`+jsonString(version),
	)
	in := ruleTextSubmission("["+rule+"]", `"invariants":{`+jsonString(invariant)+`:false}`)

	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err != nil {
		t.Fatalf("a legal submission with CJK/newline/whitespace text must parse: %v", err)
	}
	got := rules[0]
	if got.ID != id || got.Kind != kind || got.Severity != severity ||
		got.Invariant != invariant || got.Version != version {
		t.Fatalf("rule text must be preserved verbatim:\n%+v", got)
	}
	if invariants[invariant] != false {
		t.Fatalf("the invariant conclusion must bind to the verbatim name: %+v", invariants)
	}
	if ArtifactHash(artifact) != ArtifactHash(strictTestArtifact()) {
		t.Fatal("legal text must keep the original artifact hash")
	}

	// 与同样字段直接构造的 Go 值构建出的报告共享标识，缺陷证据逐字保留。
	directArtifact := strictTestArtifact()
	directRules := []Rule{{ID: id, Kind: kind, Severity: severity, Invariant: invariant, Version: version}}
	want, err := BuildReport(directArtifact, directRules, map[string]bool{invariant: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(artifact, rules, invariants, checks)
	if err != nil {
		t.Fatalf("a legal submission must build a report: %v", err)
	}
	if report.ReportID != want.ReportID {
		t.Fatalf("report id must keep its existing value:\n got %s\nwant %s", report.ReportID, want.ReportID)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("inv=false must produce exactly one finding, got %+v", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != id || f.Severity != severity || f.Invariant != invariant || f.Version != version {
		t.Fatalf("finding must bind the verbatim rule text: %+v", f)
	}
	if f.Evidence != invariantEvidence(invariant) {
		t.Fatalf("evidence must be the verbatim invariant text, got %q", f.Evidence)
	}
}

// --- 大小写变体、带空格名称与未知成员是扩展信息：其中的 null 不触发错误，
// 合法字符串也不能补上缺失字段或挽救非法正式字段（无论写在前还是后） ---

func TestParseAuditRuleTextVariantsIgnored(t *testing.T) {
	// 正式 kind 省略，变体携带 null 或字符串：只是扩展信息，kind 仍取零值，
	// 报告标识与不含任何变体的提交一致。
	plain := ruleTextSubmission("[" + ruleObject(`"id":"r1"`, `"version":"1.0.0"`) + "]")
	for _, ext := range []string{
		`"Kind":null`,
		`" kind ":null`,
		`"mystery":null`,
		`"Kind":"symbolic"`,
		`" kind ":" static "`,
	} {
		rule := ruleObject(`"id":"r1"`, `"version":"1.0.0"`, ext)
		got := strictParsedReport(t, ruleTextSubmission("["+rule+"]"))
		if got.Rules[0].Kind != "" {
			t.Fatalf("extension member %s must not supply a missing formal kind: %+v", ext, got.Rules[0])
		}
		if got.ReportID != strictParsedReport(t, plain).ReportID {
			t.Fatalf("extension member %s changed the report id", ext)
		}
	}

	// 正式 kind 为 null，旁边的变体携带合法字符串（位于其前或其后）都不能挽救。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			var members []string
			if pos == "before" {
				members = []string{`"id":"r1"`, `"Kind":"static"`, `"kind":null`, `"version":"1.0.0"`}
			} else {
				members = []string{`"id":"r1"`, `"kind":null`, `" kind ":"static"`, `"version":"1.0.0"`}
			}
			expectInvalidRuleText(t, ruleTextSubmission("["+ruleObject(members...)+"]"),
				"rules[0]", "r1", "kind")
		})
	}
}

// --- Unicode 转义写出的正式名称遵守同一字符串规则 ---

func TestParseAuditEscapedRuleTextNameFollowsSameRule(t *testing.T) {
	// "kind" 的首字母 k 的码位是 0x6b：转义写出后解码仍是正式 kind，null 拒绝。
	escName := "\\" + "u006b" + "ind"
	rule := ruleObject(`"id":"r1"`, `"`+escName+`":null`, `"version":"1.0.0"`)
	in := ruleTextSubmission("[" + rule + "]")
	if !strings.Contains(in, `\`+"u006bind") {
		t.Fatalf("test setup must carry the JSON escape, got %s", in)
	}
	expectInvalidRuleText(t, in, "rules[0]", "r1", "kind")

	// 转义写法携带合法字符串时，与直接书写解析到同一规则、同一报告标识。
	escaped := ruleTextSubmission("[" + ruleObject(
		`"id":"r1"`, `"`+escName+`":"static"`, `"severity":"high"`,
		`"invariant":"inv"`, `"requiresABI":false`, `"version":"1.0.0"`) + "]")
	plainLegal := ruleTextSubmission("[" + artifactTextRule + "]")
	if strictParsedReport(t, escaped).ReportID != strictParsedReport(t, plainLegal).ReportID {
		t.Fatal("escaped and plain spellings of a legal string must share the report id")
	}
}
