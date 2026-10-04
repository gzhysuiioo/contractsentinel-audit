package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交中规则定义 requiresABI 成员的类型规则：正式成员
// （约定拼写，含 Unicode 转义写法）一旦出现，值必须是 JSON 布尔值 true 或
// false。null、字符串、数字、对象或数组都使整份提交失败，而不是被解码成
// 零值 false 后按“不需要 ABI”继续——否则一处写错的输入会与显式 false
// 得到相同的报告标识，用户无法区分。省略 requiresABI 仍按 false 处理；
// 大小写变体或两侧带空格的名称是扩展信息，其中的 null 不触发本错误，也
// 不能挽救正式成员的非法值。

// requiresABIDoc 拼装一份只含单条规则的提交，ruleJSON 是规则对象的完整
// JSON；artifact 默认不带 ABI，便于验证“无 ABI 时显式 false 仍合法”。
func requiresABIDoc(ruleJSON, abi string) string {
	return `{"artifact":{"name":"Vault","abi":"` + abi + `","bytecode":"0x1","source":"Vault.sol"},` +
		`"rules":[` + ruleJSON + `],` +
		`"invariants":{"inv":true}}`
}

// requiresABIRule 给出一条合法规则，requiresABI 片段由调用者原样插入
// （可以是 "requiresABI":null 这类非法值，或空串表示省略该成员）。
func requiresABIRule(requiresABIFragment string) string {
	rule := `{"id":"r1","kind":"static","severity":"high","invariant":"inv",`
	if requiresABIFragment != "" {
		rule += requiresABIFragment + ","
	}
	return rule + `"version":"1.0.0"}`
}

// --- 正式 requiresABI 为 null：无论产物是否带 ABI、规则是否有结论，都整份拒绝 ---

func TestParseAuditNullRequiresABIRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule string
		abi  string
	}{
		{"no ABI on artifact", requiresABIRule(`"requiresABI":null`), ""},
		{"ABI present on artifact", requiresABIRule(`"requiresABI":null`), "abi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := requiresABIDoc(tc.rule, tc.abi)
			artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
			if err == nil {
				t.Fatal("a null formal requiresABI must reject the whole submission")
			}
			var ei errInvalid
			if !errors.As(err, &ei) {
				t.Fatalf("rejection must be errInvalid, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), "r1") {
				t.Fatalf("error must identify rule r1: %v", err)
			}
			if !strings.Contains(err.Error(), "requiresABI") || !strings.Contains(err.Error(), "boolean") {
				t.Fatalf("error must state requiresABI must be a boolean: %v", err)
			}
			if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
				t.Fatalf("rejection must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
			}
		})
	}
}

// --- 字符串、数字、对象、数组同样整份拒绝，不能改成默认值 ---

func TestParseAuditNonBooleanRequiresABIRejected(t *testing.T) {
	values := []string{`"false"`, `"true"`, `0`, `1`, `{}`, `[true]`}
	for _, val := range values {
		t.Run(val, func(t *testing.T) {
			in := requiresABIDoc(requiresABIRule(`"requiresABI":`+val), "abi")
			_, _, _, _, err := ParseAuditInput([]byte(in))
			if err == nil {
				t.Fatalf("requiresABI=%s must reject the whole submission", val)
			}
			if !strings.Contains(err.Error(), "r1") || !strings.Contains(err.Error(), "requiresABI must be a boolean") {
				t.Fatalf("error must name the rule and the boolean requirement: %v", err)
			}
		})
	}
}

// --- 省略仍按 false；显式 false 无 ABI 合法；显式 true 无 ABI 仍整份拒绝 ---

func TestParseAuditRequiresABIOmittedAndExplicitStillWork(t *testing.T) {
	// 省略：无 ABI 也合法，报告中记为 false。
	omitted := requiresABIDoc(requiresABIRule(""), "")
	_, rules, _, _, err := ParseAuditInput([]byte(omitted))
	if err != nil {
		t.Fatalf("omitted requiresABI must still parse: %v", err)
	}
	if rules[0].RequiresABI {
		t.Fatal("omitted requiresABI must keep meaning false")
	}

	// 显式 false：无 ABI 合法。
	explicitFalse := requiresABIDoc(requiresABIRule(`"requiresABI":false`), "")
	if _, _, _, _, err := ParseAuditInput([]byte(explicitFalse)); err != nil {
		t.Fatalf("explicit false without an ABI must stay legal: %v", err)
	}

	// 省略与显式 false 的报告标识一致（既有行为不变）。
	reportOmitted := strictParsedReport(t, omitted)
	reportFalse := strictParsedReport(t, explicitFalse)
	if reportOmitted.ReportID != reportFalse.ReportID {
		t.Fatalf("omitted and explicit false must share the report id:\n%s\n%s",
			reportOmitted.ReportID, reportFalse.ReportID)
	}

	// 显式 true：产物没有 ABI 时继续整份拒绝（既有 ABI 检查不变）。
	explicitTrue := requiresABIDoc(requiresABIRule(`"requiresABI":true`), "")
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(explicitTrue))
	if err != nil {
		t.Fatalf("explicit true must parse: %v", err)
	}
	if _, err := BuildReport(artifact, rules, invariants, checks); err == nil ||
		!strings.Contains(err.Error(), "requires an ABI") {
		t.Fatalf("explicit true without an ABI must still be rejected by the ABI check: %v", err)
	}
}

// --- 大小写变体与带空格名称中的 null 是扩展信息：不触发错误，也不能挽救正式 null ---

func TestParseAuditRequiresABIVariantNullIgnored(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra string
	}{
		{"case variant", `"RequiresABI":null`},
		{"whitespace padded", `" requiresABI ":null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 正式成员省略，变体携带 null：只是扩展信息，提交合法。
			rule := `{"id":"r1","kind":"static","severity":"high","invariant":"inv",` +
				tc.extra + `,"version":"1.0.0"}`
			in := requiresABIDoc(rule, "")
			got := strictParsedReport(t, in)
			if got.Rules[0].RequiresABI {
				t.Fatal("a variant requiresABI member must not supply the formal value")
			}
			// 与完全没有该成员的提交报告标识一致。
			plain := strictParsedReport(t, requiresABIDoc(requiresABIRule(""), ""))
			if got.ReportID != plain.ReportID {
				t.Fatalf("extension member changed the report id:\n got %s\nwant %s",
					got.ReportID, plain.ReportID)
			}
		})
	}
}

// 变体成员（false，位于正式成员前或后）不能挽救正式成员的 null。
func TestParseAuditRequiresABIVariantCannotRescueFormalNull(t *testing.T) {
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			var rule string
			if pos == "before" {
				rule = `{"id":"r1","kind":"static","severity":"high","invariant":"inv",` +
					`"RequiresABI":false,"requiresABI":null,"version":"1.0.0"}`
			} else {
				rule = `{"id":"r1","kind":"static","severity":"high","invariant":"inv",` +
					`"requiresABI":null,"RequiresABI":false,"version":"1.0.0"}`
			}
			in := requiresABIDoc(rule, "abi")
			_, _, _, _, err := ParseAuditInput([]byte(in))
			if err == nil || !strings.Contains(err.Error(), "requiresABI must be a boolean") {
				t.Fatalf("a variant member must not rescue a null formal requiresABI: %v", err)
			}
		})
	}
}

// --- Unicode 转义写出的正式名称遵守同一布尔规则 ---

func TestParseAuditEscapedRequiresABINameFollowsSameRule(t *testing.T) {
	// "\u0072equiresABI" 解码后就是 requiresABI：null 同样整份拒绝。
	escapedNull := requiresABIDoc(requiresABIRule(`"\u0072equiresABI":null`), "abi")
	if _, _, _, _, err := ParseAuditInput([]byte(escapedNull)); err == nil ||
		!strings.Contains(err.Error(), "requiresABI must be a boolean") {
		t.Fatalf("escaped formal name with null must reject like the plain spelling: %v", err)
	}

	// 转义写法携带合法布尔值时，与直接书写的报告标识一致。
	escapedTrue := requiresABIDoc(requiresABIRule(`"\u0072equiresABI":true`), "abi")
	plainTrue := requiresABIDoc(requiresABIRule(`"requiresABI":true`), "abi")
	gotEscaped := strictParsedReport(t, escapedTrue)
	gotPlain := strictParsedReport(t, plainTrue)
	if gotEscaped.ReportID != gotPlain.ReportID {
		t.Fatalf("escaped and plain spellings must share the report id:\n%s\n%s",
			gotEscaped.ReportID, gotPlain.ReportID)
	}
}
