package contractsentinel

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交侧规则定义五个文本成员的类型规则。wireRule 的 id、
// kind、severity、invariant、version 都是 Go 字符串，严格重写后的 JSON 再经
// json.Unmarshal 时，正式成员的 null 会被静默解码成零值 ""：一条规则有合法
// 的 id 和 version，只把 kind、severity 或 invariant 写成 null，就可能成功
// 生成报告，而且规则定义与报告标识和用户显式提交空字符串完全相同，原始格式
// 错误在保存前被悄悄改写。
//
// 修正后，五个正式成员（约定拼写，含 Unicode 转义写法）一旦写出，值就必须是
// JSON 字符串；null、布尔值、数字、对象、数组都使整份提交失败（errInvalid），
// 与该规则是否被检查、是否产生缺陷无关，其他规则和检查记录合法也不能挽救。
// 错误指出 rules 数组中从零开始的位置、出错成员及必须为字符串；规则有合法
// 非空 id 时同时给出该标识，id 自身非法时仍凭位置定位。省略成员与显式空
// 字符串继续按原来的默认值和业务要求判断，不新增必填、非空或取值范围限制；
// Kind、带前后空格的名称及其他未知成员仍是扩展信息，其中的 null 不触发本
// 错误，合法字符串也不能补上缺失字段或挽救非法正式字段。

// ruleTextRule 渲染一条提交规则：fields 给出正式成员名与其后原始 JSON 片段
// （如 `"static"`、`null`、`true`），未列出的成员即省略；extra 是按书写
// 顺序插入的额外 "name":raw 片段（用于扩展成员出现在正式成员前后）。
func ruleTextRule(fields map[string]string, extra ...ruleTextExtra) string {
	parts := textFormalPairs(fields)
	for _, e := range extra {
		pair := `"` + e.name + `":` + e.raw
		if e.at == 0 {
			parts = append([]string{pair}, parts...)
		} else {
			parts = append(parts, pair)
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ruleTextExtra places one extension pair before (at == 0) or after (at == 1)
// the formal pairs.
type ruleTextExtra struct {
	name string
	raw  string
	at   int
}

// textFormalPairs renders the ordered formal members as "name":raw pairs.
func textFormalPairs(fields map[string]string) []string {
	order := []string{"id", "kind", "severity", "invariant", "requiresABI", "version"}
	parts := make([]string, 0, len(order))
	for _, name := range order {
		if raw, ok := fields[name]; ok {
			parts = append(parts, `"`+name+`":`+raw)
		}
	}
	return parts
}

// ruleTextDefaultFields 是一条完全合法的静态规则。
func ruleTextDefaultFields() map[string]string {
	return map[string]string{
		"id":          `"r1"`,
		"kind":        `"static"`,
		"severity":    `"high"`,
		"invariant":   `"inv1"`,
		"requiresABI": `false`,
		"version":     `"1.0.0"`,
	}
}

// ruleTextDoc 拼装一份提交，rules 是完整的 rules 数组 JSON，sections 给出
// 其余顶层段落（如 invariants、checks）。
func ruleTextDoc(rules string, sections ...string) string {
	all := append([]string{`"artifact":` + strictArtifactJSON, rules}, sections...)
	return strictDoc(all...)
}

// ruleTextArrayDoc 是多条规则时的便捷封装。
func ruleTextArrayDoc(rules ...string) string {
	return `"rules":[` + strings.Join(rules, ",") + `]`
}

// expectInvalidRuleText asserts the full submission contract for a non-string
// formal rule text member: errInvalid naming the rules-array position, the
// field and the string requirement (plus the rule id when one is given), and
// no partial data.
func expectInvalidRuleText(t *testing.T, in, position, rule, field string) {
	t.Helper()
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err == nil {
		t.Fatalf("a non-string formal %s must reject the whole submission", field)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("a rule text type error is a submission format error (errInvalid), got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, position) {
		t.Fatalf("error must name the rules-array position %q: %v", position, err)
	}
	if rule != "" && !strings.Contains(msg, rule) {
		t.Fatalf("error must name the offending rule %q: %v", rule, err)
	}
	if !strings.Contains(msg, field+" must be a string") {
		t.Fatalf("error must state %s must be a string: %v", field, err)
	}
	// 这是规则定义的提交格式错误，不得记成缺陷、工具缺失或超时。
	for _, marker := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		if strings.Contains(msg, marker) {
			t.Fatalf("a format error must not be reported as the conclusion %q: %v", marker, err)
		}
	}
	if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
		t.Fatalf("rejection must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
	}
}

// --- 核心场景：合法 id 和 version，kind/severity/invariant 为 null 也必须拒绝，
// 即便这样的规则在旧行为下能成功出报告 ---

func TestParseAuditNullCoreRuleTextRejected(t *testing.T) {
	for _, field := range []string{"kind", "severity", "invariant"} {
		t.Run(field, func(t *testing.T) {
			fields := ruleTextDefaultFields()
			fields[field] = `null`
			in := ruleTextDoc(ruleTextArrayDoc(ruleTextRule(fields)), `"invariants":{"inv1":true}`)
			expectInvalidRuleText(t, in, "rules[0]", "r1", field)
		})
	}
}

// --- 五个文本成员写成 null 都拒绝；id 自身非法时凭位置定位，不点名规则 ---

func TestParseAuditNullRuleTextFieldRejected(t *testing.T) {
	for _, field := range []string{"id", "kind", "severity", "invariant", "version"} {
		t.Run(field, func(t *testing.T) {
			fields := ruleTextDefaultFields()
			fields[field] = `null`
			in := ruleTextDoc(ruleTextArrayDoc(ruleTextRule(fields)), `"invariants":{"inv1":true}`)
			rule := "r1"
			if field == "id" {
				rule = ""
			}
			expectInvalidRuleText(t, in, "rules[0]", rule, field)
		})
	}
}

// --- 与该规则是否被检查、是否产生缺陷无关：缺陷、通过、未检查、带检查记录都拒绝 ---

func TestParseAuditNullRuleTextRejectedForEveryConclusion(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	// 缺陷规则：不变式为 false，原本会产生 finding；invariant 写成 null 后
	// 旧行为把它洗成 ""（未检查），整份提交仍然成功。
	defect := ruleTextDefaultFields()
	defect["invariant"] = `null`
	in := ruleTextDoc(ruleTextArrayDoc(ruleTextRule(defect)), `"invariants":{"inv1":false}`)
	expectInvalidRuleText(t, in, "rules[0]", "r1", "invariant")

	// 带合法检查记录（发现缺陷）的规则，其 severity 写成 null：检查记录合法
	// 也不能挽救提交，且这不是缺陷结论。
	checked := ruleTextDefaultFields()
	checked["id"] = `"r-checked"`
	checked["invariant"] = `"inv-checked"`
	checked["severity"] = `null`
	check := fmt.Sprintf(
		`{"artifactHash":%q,"ruleId":"r-checked","version":"1.0.0","status":"发现缺陷","note":"counterexample: x"}`,
		hash)
	in = ruleTextDoc(ruleTextArrayDoc(ruleTextRule(checked)), `"checks":[`+check+`]`)
	expectInvalidRuleText(t, in, "rules[0]", "r-checked", "severity")

	// 通过检查记录同样不改变结果。
	pass := ruleTextDefaultFields()
	pass["id"] = `"r-pass"`
	pass["invariant"] = `"inv-pass"`
	pass["kind"] = `null`
	passCheck := fmt.Sprintf(
		`{"artifactHash":%q,"ruleId":"r-pass","version":"1.0.0","status":"通过","note":""}`,
		hash)
	in = ruleTextDoc(ruleTextArrayDoc(ruleTextRule(pass)), `"checks":[`+passCheck+`]`)
	expectInvalidRuleText(t, in, "rules[0]", "r-pass", "kind")
}

// --- 其他规则与检查记录合法也不能使提交成功；位置按从零开始的下标点名 ---

func TestParseAuditNullRuleTextAmongLegalRulesRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	legal1 := ruleTextDefaultFields()
	legal2 := ruleTextDefaultFields()
	legal2["id"] = `"r2"`
	legal2["invariant"] = `"inv2"`
	legal3 := ruleTextDefaultFields()
	legal3["id"] = `"r3"`
	legal3["invariant"] = `"inv3"`

	// r1 带一条合法的“通过”检查记录；非法的是第三条规则，位置必须是从零
	// 开始的 rules[2]，且同时点名其合法 id。
	badLast := fieldsWith(legal3, "version", `null`)
	checks := "[" +
		fmt.Sprintf(`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","status":"通过","note":""}`, hash) +
		"]"
	in := ruleTextDoc(
		ruleTextArrayDoc(ruleTextRule(legal1), ruleTextRule(legal2), ruleTextRule(badLast)),
		`"invariants":{"inv2":true}`,
		`"checks":`+checks)
	expectInvalidRuleText(t, in, "rules[2]", "r3", "version")

	// 非法规则位于中间时，同样点名 rules[1] 与规则标识。
	badMiddle := fieldsWith(legal2, "severity", `null`)
	in = ruleTextDoc(
		ruleTextArrayDoc(ruleTextRule(legal1), ruleTextRule(badMiddle), ruleTextRule(legal3)),
		`"invariants":{"inv3":true}`,
		`"checks":`+checks)
	expectInvalidRuleText(t, in, "rules[1]", "r2", "severity")

	// 非法规则自身 id 非法（null）时仍凭位置 rules[1] 定位，且不点名规则。
	badID := fieldsWith(legal2, "id", `null`)
	in = ruleTextDoc(
		ruleTextArrayDoc(ruleTextRule(legal1), ruleTextRule(badID), ruleTextRule(legal3)),
		`"invariants":{"inv3":true}`)
	expectInvalidRuleText(t, in, "rules[1]", "", "id")
}

// --- 布尔值、数字、对象、数组同样整份拒绝，不能被当成空字符串 ---

func TestParseAuditNonStringRuleTextRejected(t *testing.T) {
	for _, val := range []string{`true`, `false`, `0`, `1`, `{}`, `[]`, `["x"]`} {
		t.Run(val, func(t *testing.T) {
			fields := ruleTextDefaultFields()
			fields["invariant"] = val
			in := ruleTextDoc(ruleTextArrayDoc(ruleTextRule(fields)), `"invariants":{"inv1":true}`)
			expectInvalidRuleText(t, in, "rules[0]", "r1", "invariant")
		})
	}
}

// --- 省略成员仍取默认值；显式空字符串按既有业务规则判断，不触发类型错误 ---

func TestParseAuditRuleTextOmittedAndEmptyStringSemantics(t *testing.T) {
	defaults := ruleTextDefaultFields()

	// 省略 kind/severity/invariant 与显式空字符串解析到同一条规则，报告标识
	// 也相同：类型关不改变默认值与空文本的既有含义。
	omitted := map[string]string{
		"id":          defaults["id"],
		"requiresABI": defaults["requiresABI"],
		"version":     defaults["version"],
	}
	empty := map[string]string{}
	for k, v := range omitted {
		empty[k] = v
	}
	empty["kind"] = `""`
	empty["severity"] = `""`
	empty["invariant"] = `""`

	reportOmitted := strictParsedReport(t, ruleTextDoc(ruleTextArrayDoc(ruleTextRule(omitted))))
	reportEmpty := strictParsedReport(t, ruleTextDoc(ruleTextArrayDoc(ruleTextRule(empty))))
	if reportOmitted.ReportID != reportEmpty.ReportID {
		t.Fatalf("omitted and explicit-empty text must share the report id:\n%s\n%s",
			reportOmitted.ReportID, reportEmpty.ReportID)
	}
	if reportEmpty.Rules[0].Kind != "" || reportEmpty.Rules[0].Severity != "" ||
		reportEmpty.Rules[0].Invariant != "" {
		t.Fatalf("explicit empty strings must read back as empty: %+v", reportEmpty.Rules[0])
	}

	// 显式空字符串 id 仍由既有“rule id is required”业务校验拒绝，不是类型错误。
	emptyID := ruleTextDefaultFields()
	emptyID["id"] = `""`
	a, rules, inv, checks, err := ParseAuditInput([]byte(ruleTextDoc(ruleTextArrayDoc(ruleTextRule(emptyID)))))
	if err != nil {
		t.Fatalf("an explicit empty-string id is a legal string and must parse: %v", err)
	}
	_, err = BuildReport(a, rules, inv, checks)
	if err == nil || !strings.Contains(err.Error(), "rule id is required") {
		t.Fatalf("an empty id must keep the business-rule error: %v", err)
	}
	if strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an explicit empty string is not a type error: %v", err)
	}

	// 显式空字符串 version 同理。
	emptyVersion := ruleTextDefaultFields()
	emptyVersion["version"] = `""`
	a, rules, inv, checks, err = ParseAuditInput([]byte(ruleTextDoc(ruleTextArrayDoc(ruleTextRule(emptyVersion)))))
	if err != nil {
		t.Fatalf("an explicit empty-string version is a legal string and must parse: %v", err)
	}
	_, err = BuildReport(a, rules, inv, checks)
	if err == nil || !strings.Contains(err.Error(), "version is required") {
		t.Fatalf("an empty version must keep the business-rule error: %v", err)
	}
	if strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an explicit empty string is not a type error: %v", err)
	}
}

// --- 合法字符串逐字保留：中文、换行与前后空格，哈希与报告标识保持原有结果 ---

func TestParseAuditLegalRuleTextPreserved(t *testing.T) {
	kind := "  静态 检查\n第二行 "
	severity := " 高 危 "
	invariant := " 不变式：余额单调\n "
	fields := map[string]string{
		"id":          `"r-中文"`,
		"kind":        jsonString(kind),
		"severity":    jsonString(severity),
		"invariant":   jsonString(invariant),
		"requiresABI": `false`,
		"version":     `"v 1.0 "`,
	}
	in := ruleTextDoc(ruleTextArrayDoc(ruleTextRule(fields)))
	artifact, rules, _, _, err := ParseAuditInput([]byte(in))
	if err != nil {
		t.Fatalf("a legal submission with multilingual/whitespace text must parse: %v", err)
	}
	if rules[0].Kind != kind || rules[0].Severity != severity ||
		rules[0].Invariant != invariant || rules[0].Version != "v 1.0 " ||
		rules[0].ID != "r-中文" {
		t.Fatalf("rule text must be preserved verbatim: %+v", rules[0])
	}

	// 与直接构造的 Go 值产生同一份报告（标识、规则结论、缺陷证据一致）。
	directRules := []Rule{{ID: "r-中文", Kind: kind, Severity: severity, Invariant: invariant, Version: "v 1.0 "}}
	directReport, err := BuildReport(artifact, directRules, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gotReport := strictParsedReport(t, in)
	if gotReport.ReportID != directReport.ReportID {
		t.Fatalf("parsed and directly built reports must share the id:\n%s\n%s",
			gotReport.ReportID, directReport.ReportID)
	}
}

// --- 大小写变体或带空格名称中的值是扩展信息：不触发错误，也不能挽救正式 null ---

func TestParseAuditRuleTextVariantNullIgnored(t *testing.T) {
	defaults := ruleTextDefaultFields()

	// 正式 kind 省略，变体携带 null 或合法字符串：只是扩展信息，规则仍取
	// 默认空值，与完全省略的提交报告标识一致。
	noKind := ruleTextRule(map[string]string{
		"id":          defaults["id"],
		"severity":    defaults["severity"],
		"invariant":   defaults["invariant"],
		"requiresABI": defaults["requiresABI"],
		"version":     defaults["version"],
	})
	plain := strictParsedReport(t, ruleTextDoc(ruleTextArrayDoc(noKind)))

	for _, variant := range []string{`"Kind":null`, `" kind ":"symbolic"`, `"KIND":null`} {
		t.Run(variant, func(t *testing.T) {
			rule := strings.TrimSuffix(noKind, "}") + "," + variant + "}"
			got := strictParsedReport(t, ruleTextDoc(ruleTextArrayDoc(rule)))
			if got.ReportID != plain.ReportID {
				t.Fatalf("extension member %s must not supply a formal field:\n got %s\nwant %s",
					variant, got.ReportID, plain.ReportID)
			}
		})
	}
}

func TestParseAuditRuleTextVariantCannotRescueFormalNull(t *testing.T) {
	defaults := ruleTextDefaultFields()
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			// 变体携带合法字符串，写在正式 null 之前或之后，都不能挽救。
			var rule string
			if pos == "before" {
				rule = ruleTextRule(fieldsWith(defaults, "kind", `null`),
					ruleTextExtra{name: "Kind", raw: `"static"`, at: 0})
			} else {
				rule = ruleTextRule(fieldsWith(defaults, "kind", `null`),
					ruleTextExtra{name: "Kind", raw: `"static"`, at: 1})
			}
			in := ruleTextDoc(ruleTextArrayDoc(rule))
			expectInvalidRuleText(t, in, "rules[0]", "r1", "kind")
		})
	}
}

// fieldsWith returns a copy of fields with one member replaced.
func fieldsWith(fields map[string]string, key, raw string) map[string]string {
	out := make(map[string]string, len(fields)+1)
	for k, v := range fields {
		out[k] = v
	}
	out[key] = raw
	return out
}

// --- Unicode 转义写出的正式名称遵守同一字符串规则 ---

func TestParseAuditEscapedRuleTextNameFollowsSameRule(t *testing.T) {
	// "invariant" 用 Unicode 转义写出（i 的码位是 0x69），解码后仍是
	// invariant：null 同样整份拒绝。
	escName := "\\" + "u0069" + "nvariant"
	fields := ruleTextDefaultFields()
	fields["invariant"] = `null`
	nullDoc := ruleTextDoc(ruleTextArrayDoc(ruleTextRule(fields)))
	nullDoc = strings.Replace(nullDoc, `"invariant":null`, `"`+escName+`":null`, 1)
	if !strings.Contains(nullDoc, `\`+"u0069nvariant") {
		t.Fatalf("test setup must carry the JSON escape, got %s", nullDoc)
	}
	expectInvalidRuleText(t, nullDoc, "rules[0]", "r1", "invariant")

	// 转义写法携带合法字符串时，与直接书写的报告标识一致并按原值读回。
	legal := ruleTextDoc(ruleTextArrayDoc(ruleTextRule(ruleTextDefaultFields())),
		`"invariants":{"inv1":true}`)
	escaped := strings.Replace(legal, `"invariant":"inv1"`, `"`+escName+`":"inv1"`, 1)
	gotEscaped := strictParsedReport(t, escaped)
	gotPlain := strictParsedReport(t, legal)
	if gotEscaped.ReportID != gotPlain.ReportID {
		t.Fatalf("escaped and plain spellings must share the report id:\n%s\n%s",
			gotEscaped.ReportID, gotPlain.ReportID)
	}
	if gotEscaped.Rules[0].Invariant != "inv1" {
		t.Fatalf("escaped invariant must read back verbatim, got %q", gotEscaped.Rules[0].Invariant)
	}
}
