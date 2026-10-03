package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交对“JSON 对象内重复成员名”的整体拒绝：
// Go 的 encoding/json 对同名成员静默保留最后一个值，因此 invariants 中
// false 后再写 true 会只剩通过、null 后写布尔值会绕过非布尔拒绝。
// 这类输入没有唯一可信结论，任何一个对象出现重复成员都必须整份拒绝，
// 且错误要点名重复成员与所在对象（具体到哪条规则/哪条检查记录）。

const dupRulesArtifact = `{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`

// --- 扫描器本身：在解码后的成员名上判重 ---

func TestFindDuplicateInvariantsFalseThenTrue(t *testing.T) {
	data := []byte(`{"invariants":{"inv":false,"inv":true}}`)
	dup := findDuplicateJSONMember(data)
	if dup == nil {
		t.Fatal("false then true for the same invariant must be detected")
	}
	if dup.member != "inv" {
		t.Fatalf("duplicate member = %q, want inv", dup.member)
	}
}

func TestFindDuplicateRejectsEqualValues(t *testing.T) {
	// 重复值相同也不放行：问题在于成员出现两次，而不是值冲突。
	data := []byte(`{"invariants":{"inv":true,"inv":true}}`)
	if findDuplicateJSONMember(data) == nil {
		t.Fatal("identical repeated values must still be a duplicate")
	}
}

func TestFindDuplicateNullThenBool(t *testing.T) {
	// null 在前、布尔在后：必须在非布尔校验“看到”最后一个值之前拦下。
	data := []byte(`{"invariants":{"inv":null,"inv":false}}`)
	if findDuplicateJSONMember(data) == nil {
		t.Fatal("null then bool must be detected before type validation")
	}
}

func TestFindDuplicateUnicodeEscapedName(t *testing.T) {
	// "inv" 解码后就是 "inv"（0x69 == 'i'）：按解码后的字符串判重。
	data := []byte(`{"invariants":{"inv":false,"inv":true}}`)
	dup := findDuplicateJSONMember(data)
	if dup == nil {
		t.Fatal("literal name and the same Unicode-escaped name must collide")
	}
	if dup.member != "inv" {
		t.Fatalf("duplicate member must be reported using the decoded name, got %q", dup.member)
	}
}

func TestFindDuplicateCaseSensitiveNoTrim(t *testing.T) {
	// 名称区分大小写：Inv 与 inv 是两个成员。
	if dup := findDuplicateJSONMember([]byte(`{"invariants":{"Inv":false,"inv":true}}`)); dup != nil {
		t.Fatalf("Inv and inv are distinct members, got %+v", dup)
	}
	// 不修剪空白：" inv " 与 "inv" 是两个成员。
	if dup := findDuplicateJSONMember([]byte(`{"invariants":{" inv ":false,"inv":true}}`)); dup != nil {
		t.Fatalf("whitespace-padded names must not be trimmed, got %+v", dup)
	}
	// 反过来，完全一致的名称（仅 JSON 外围空白不同）当然算重复。
	if dup := findDuplicateJSONMember([]byte(`{"invariants":{ "inv" : false, "inv" : true}}`)); dup == nil {
		t.Fatal("identical names separated by whitespace must collide")
	}
}

func TestFindDuplicateEveryObjectKind(t *testing.T) {
	cases := map[string]string{
		"top-level":   `{"artifact":{"name":"A"},"artifact":{"name":"B"}}`,
		"artifact":    `{"artifact":{"name":"A","name":"B"}}`,
		"invariants":  `{"invariants":{"inv":false,"inv":true}}`,
		"rule":        `{"rules":[{"id":"r1","version":"1","id":"r1"}]}`,
		"check":       `{"checks":[{"ruleId":"r1","ruleId":"r1"}]}`,
		"nested":      `{"invariants":{"inv":{"a":1,"a":2}}}`,
		"unknown":     `{"mystery":{"a":1,"a":2}}`,
		"top-unknown": `{"extra":1,"extra":2}`,
	}
	for name, input := range cases {
		if findDuplicateJSONMember([]byte(input)) == nil {
			t.Errorf("%s: duplicate member not detected in %s", name, input)
		}
	}
}

func TestFindDuplicateSameNameInDifferentObjectsOK(t *testing.T) {
	// 多条规则各自带 id、多条检查各自带 ruleId，是正常输入，不能误判。
	input := `{
		"artifact": {"name":"A"},
		"rules": [
			{"id":"r1","version":"1"},
			{"id":"r2","version":"1"}
		],
		"checks": [
			{"ruleId":"r1","status":"通过"},
			{"ruleId":"r2","status":"通过"}
		]
	}`
	if dup := findDuplicateJSONMember([]byte(input)); dup != nil {
		t.Fatalf("equal member names in separate objects are legal: %+v", dup)
	}
}

func TestFindDuplicateIgnoresJSONLookingStrings(t *testing.T) {
	// 源码与说明字符串里看起来再像 JSON 的文字也只是普通内容。
	input := `{
		"artifact": {"name":"A","source":"{\"id\":1, \"id\":2, \"id\":3}"},
		"checks": [{"ruleId":"r1","status":"发现缺陷","note":"{\"x\":1, \"x\":2}"}]
	}`
	if dup := findDuplicateJSONMember([]byte(input)); dup != nil {
		t.Fatalf("string contents must never be scanned as JSON: %+v", dup)
	}
}

func TestFindDuplicateMalformedJSONDefersToUnmarshal(t *testing.T) {
	// 语法错误交给 json.Unmarshal 统一报错；扫描器不臆造重复。
	for _, input := range []string{``, `{`, `{"a":1 "b":2}`, `{"a":`} {
		if dup := findDuplicateJSONMember([]byte(input)); dup != nil {
			t.Errorf("malformed input %q must not yield a duplicate finding, got %+v", input, dup)
		}
	}
}

// --- ParseAuditInput：任何对象重复成员 => errInvalid，且无部分数据 ---

func parseDupSubmission(extra string) []byte {
	return []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1"}],
		` + extra + `
	}`)
}

func expectDupRejection(t *testing.T, data []byte, wantSubstrings ...string) {
	t.Helper()
	artifact, rules, invariants, checks, err := ParseAuditInput(data)
	if err == nil {
		t.Fatalf("submission with a duplicate member must be rejected: %s", data)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid (input error), got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(strings.ToLower(msg), "duplicate") {
		t.Fatalf("error must state the member is duplicated: %v", err)
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
	if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
		t.Fatalf("failure must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
	}
}

func TestParseAuditInputDuplicateInvariantFalseTrue(t *testing.T) {
	expectDupRejection(t, parseDupSubmission(`"invariants": {"inv": false, "inv": true}`),
		`"inv"`, "invariants object")
}

func TestParseAuditInputDuplicateInvariantNullThenBool(t *testing.T) {
	expectDupRejection(t, parseDupSubmission(`"invariants": {"inv": null, "inv": false}`),
		`"inv"`, "invariants object")
}

func TestParseAuditInputDuplicateInvariantEqualValues(t *testing.T) {
	expectDupRejection(t, parseDupSubmission(`"invariants": {"inv": false, "inv": false}`),
		`"inv"`)
}

func TestParseAuditInputDuplicateUnicodeEscapedInvariant(t *testing.T) {
	expectDupRejection(t, parseDupSubmission(`"invariants": {"inv": false, "inv": true}`),
		`"inv"`)
}

func TestParseAuditInputDuplicateTopLevelMember(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [{"id":"r1","version":"1"}],
		"rules": [{"id":"r2","version":"1"}]
	}`)
	expectDupRejection(t, data, `"rules"`, "top-level object")
}

func TestParseAuditInputDuplicateArtifactMember(t *testing.T) {
	data := []byte(`{"artifact": {"name":"A","name":"B"},"rules":[]}`)
	expectDupRejection(t, data, `"name"`, "artifact object")
}

func TestParseAuditInputDuplicateRuleMemberNamesRule(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":"rule-a","kind":"static","severity":"low","invariant":"a","version":"1"},
			{"id":"rule-b","kind":"static","severity":"high","severity":"low","invariant":"b","version":"1"}
		]
	}`)
	// 必须能区分是哪条规则：点名 rule-b 及其数组位置。
	expectDupRejection(t, data, `"severity"`, `rule "rule-b"`, "rules[1]")
}

func TestParseAuditInputDuplicateRuleIDMember(t *testing.T) {
	// 连 id 成员本身重复也要拒绝，并给出数组位置便于定位。
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [{"id":"rule-a","id":"rule-b","version":"1"}]
	}`)
	expectDupRejection(t, data, `"id"`, "rules[0]")
}

func TestParseAuditInputDuplicateCheckMemberNamesRecord(t *testing.T) {
	data := []byte(`{
		"artifact": ` + dupRulesArtifact + `,
		"rules": [
			{"id":"rule-a","kind":"static","severity":"high","invariant":"a","version":"1"},
			{"id":"rule-b","kind":"static","severity":"high","invariant":"b","version":"1"}
		],
		"checks": [
			{"ruleId":"rule-a","version":"1","status":"通过"},
			{"ruleId":"rule-b","version":"1","status":"发现缺陷","status":"通过","note":"x"}
		]
	}`)
	// 必须能区分是哪条检查记录：点名 rule-b 及其数组位置。
	expectDupRejection(t, data, `"status"`, "rule \"rule-b\"", "checks[1]")
}

func TestParseAuditInputDuplicateUnknownMemberStillRejected(t *testing.T) {
	// 未知字段按现有方式放行，但未知字段自身重复仍是重复成员。
	data := []byte(`{"artifact":{"name":"A"},"rules":[],"mystery":1,"mystery":2}`)
	expectDupRejection(t, data, `"mystery"`)
}

func TestParseAuditInputDuplicateNestedUnderInvariant(t *testing.T) {
	// 即使重复出现在不变式值内部的对象里，也整份拒绝（且先于类型校验）。
	data := []byte(`{"artifact":{"name":"A"},"rules":[],"invariants":{"inv":{"a":1,"a":2}}}`)
	expectDupRejection(t, data, `"a"`)
}

// --- 合法输入行为完全不变 ---

func TestParseAuditInputDistinctCaseKeysAreSeparate(t *testing.T) {
	data := []byte(`{"artifact":{"name":"A"},"rules":[],"invariants":{"Inv":false,"inv":true}}`)
	_, _, invariants, _, err := ParseAuditInput(data)
	if err != nil {
		t.Fatalf("case-distinct keys are two invariants: %v", err)
	}
	if len(invariants) != 2 || invariants["Inv"] != false || invariants["inv"] != true {
		t.Fatalf("both case-distinct invariants must be kept, got %+v", invariants)
	}
}

func TestParseAuditInputUnknownFieldSingleAccepted(t *testing.T) {
	// 未知字段只出现一次时维持现有行为（放行）。
	data := []byte(`{"artifact":{"name":"A"},"rules":[],"mystery":{"nested":true}}`)
	if _, _, _, _, err := ParseAuditInput(data); err != nil {
		t.Fatalf("a single unknown field must stay accepted: %v", err)
	}
}

func TestParseAuditInputLegalFalseTrueUnchanged(t *testing.T) {
	// 合法 false 仍是缺陷、合法 true 仍是通过：端到端报告状态不变。
	artifact := Artifact{Name: "Vault", ABI: "abi", Bytecode: "0x1", Source: "Vault.sol"}
	rules := []Rule{
		{ID: "r-fail", Kind: "static", Severity: "high", Invariant: "inv-fail", Version: "1"},
		{ID: "r-pass", Kind: "static", Severity: "low", Invariant: "inv-pass", Version: "1"},
	}
	invariants := map[string]bool{"inv-fail": false, "inv-pass": true}
	report, err := BuildReport(artifact, rules, invariants, nil)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, r := range report.Rules {
		status[r.ID] = r.Status
	}
	if status["r-fail"] != StatusDefect || status["r-pass"] != StatusPass {
		t.Fatalf("legal false/true conclusions changed: %+v", status)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "r-fail" {
		t.Fatalf("exactly the false invariant must produce one defect: %+v", report.Findings)
	}
}
