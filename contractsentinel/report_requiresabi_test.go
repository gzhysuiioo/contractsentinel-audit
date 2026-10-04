package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交侧规则定义里正式 requiresABI 成员的布尔规则：成员出现
// 时值必须是 JSON true/false，null、字符串、数字、对象、数组都整份拒绝，不能
// 悄悄当成 false（否则输入写错与显式 false 在报告与报告标识上无法区分）。省略
// 成员仍按 false 处理；大小写变体与名称两侧带空格的成员只是扩展信息，其中的
// null 不触发本错误，也不能替代或挽救正式成员的非法值；用 Unicode 转义写出的
// 相同名称仍是正式成员。

// abiRuleJSON 拼一条规则对象，requiresABI 部分由调用方原样给出（可为空串表示
// 省略该成员）。
func abiRuleJSON(requiresABIPart string) string {
	return `{"id":"r1","kind":"static","severity":"high","invariant":"inv",` +
		requiresABIPart + `"version":"1.0.0"}`
}

// abiSubmission 拼一份以 requiresABI 写法为变量的提交；withABI 决定产物是否
// 携带非空 ABI。
func abiSubmission(requiresABIPart string, withABI bool) string {
	artifact := `{"name":"Vault","bytecode":"0x1","source":"Vault.sol"}`
	if withABI {
		artifact = `{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`
	}
	return strictDoc(
		`"artifact":`+artifact,
		`"rules":[`+abiRuleJSON(requiresABIPart)+`]`,
		`"invariants":{"inv":true}`,
	)
}

// --- 正式 requiresABI 为 null 或非布尔类型：整份拒绝并点名规则 ---

func TestParseAuditRequiresABIRejectsNonBoolean(t *testing.T) {
	values := []string{`null`, `"yes"`, `1`, `0`, `{"v":true}`, `[true]`}
	for _, val := range values {
		for _, withABI := range []bool{false, true} {
			in := abiSubmission(`"requiresABI":`+val+`,`, withABI)
			artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
			if err == nil {
				t.Fatalf("requiresABI=%s (abi=%v) must reject the submission", val, withABI)
			}
			var ei errInvalid
			if !errors.As(err, &ei) {
				t.Fatalf("requiresABI=%s: rejection must be errInvalid, got %T: %v", val, err, err)
			}
			if !strings.Contains(err.Error(), "r1") {
				t.Fatalf("requiresABI=%s: error must identify rule r1: %v", val, err)
			}
			if !strings.Contains(err.Error(), "requiresABI") || !strings.Contains(err.Error(), "boolean") {
				t.Fatalf("requiresABI=%s: error must say requiresABI must be a boolean: %v", val, err)
			}
			if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
				t.Fatalf("requiresABI=%s: rejection must return no partial data: %+v %+v %+v %+v",
					val, artifact, rules, invariants, checks)
			}
		}
	}
}

// 没有收到任何检查结论（无 invariants、无 checks）时，非法 requiresABI 同样拒绝。
func TestParseAuditRequiresABIRejectsNullWithoutAnyConclusion(t *testing.T) {
	in := strictDoc(
		`"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`,
		`"rules":[`+abiRuleJSON(`"requiresABI":null,`)+`]`,
	)
	if _, _, _, _, err := ParseAuditInput([]byte(in)); err == nil {
		t.Fatal("null requiresABI must reject even when the rule gets no check conclusion")
	} else if !strings.Contains(err.Error(), "r1") || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("error must name the rule and the boolean requirement: %v", err)
	}
}

// --- 省略与显式布尔：原有行为不变 ---

func TestParseAuditRequiresABIOmittedMeansFalse(t *testing.T) {
	// 产物没有 ABI、成员省略：按 false 处理，提交合法。
	got := strictParsedReport(t, abiSubmission("", false))
	if got.Rules[0].RequiresABI != false {
		t.Fatalf("omitted requiresABI must decode as false, got %+v", got.Rules[0])
	}

	// 显式 false 同样允许规则在没有 ABI 时使用，且报告标识与省略时一致。
	explicit := strictParsedReport(t, abiSubmission(`"requiresABI":false,`, false))
	if explicit.ReportID != got.ReportID {
		t.Fatalf("explicit false must match the omitted-member report id:\n got %s\nwant %s",
			explicit.ReportID, got.ReportID)
	}
}

func TestParseAuditRequiresABIExplicitTrueStillRequiresABI(t *testing.T) {
	// 产物有 ABI：显式 true 合法。
	got := strictParsedReport(t, abiSubmission(`"requiresABI":true,`, true))
	if got.Rules[0].RequiresABI != true {
		t.Fatalf("explicit true must be preserved, got %+v", got.Rules[0])
	}

	// 产物没有 ABI：显式 true 继续整份拒绝。
	in := abiSubmission(`"requiresABI":true,`, false)
	if _, _, _, _, err := ParseAuditInput([]byte(in)); err != nil {
		t.Fatalf("parse must succeed; the ABI requirement is a build-time refusal: %v", err)
	}
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildReport(artifact, rules, invariants, checks); err == nil ||
		!strings.Contains(err.Error(), "r1") || !strings.Contains(err.Error(), "ABI") {
		t.Fatalf("explicit true without an ABI must refuse the whole submission: %v", err)
	}
}

// --- 大小写变体与带空格名称中的 null 只是扩展信息，不触发本错误 ---

func TestParseAuditRequiresABIVariantNullIgnored(t *testing.T) {
	variants := []string{`"RequiresABI"`, `"requiresabi"`, `" requiresABI "`, `"requiresABI "`}
	for _, name := range variants {
		for _, pos := range []string{"before", "after"} {
			var part string
			if pos == "before" {
				part = name + `:null,"requiresABI":false,`
			} else {
				part = `"requiresABI":false,` + name + `:null,`
			}
			got := strictParsedReport(t, abiSubmission(part, false))
			if got.Rules[0].RequiresABI != false {
				t.Fatalf("%s null (%s) must be ignored as extension data: %+v", name, pos, got.Rules[0])
			}
		}
	}
}

// 变体成员携带合法布尔值，也不能挽救正式成员的非法值（两种顺序）。
func TestParseAuditRequiresABIVariantCannotRescueIllegalFormal(t *testing.T) {
	for _, tc := range []struct {
		name string
		part string
	}{
		{"variant after formal", `"requiresABI":null,"RequiresABI":false,`},
		{"variant before formal", `"RequiresABI":false,"requiresABI":null,`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := ParseAuditInput([]byte(abiSubmission(tc.part, true)))
			if err == nil || !strings.Contains(err.Error(), "boolean") {
				t.Fatalf("a variant member must not rescue an illegal formal requiresABI: %v", err)
			}
		})
	}
}

// 变体成员也不能在正式成员缺失时顶替：省略正式成员时按 false 处理，变体的
// true 不生效。
func TestParseAuditRequiresABIVariantCannotSubstitute(t *testing.T) {
	got := strictParsedReport(t, abiSubmission(`"RequiresABI":true,`, false))
	if got.Rules[0].RequiresABI != false {
		t.Fatalf("a case variant must not supply requiresABI: %+v", got.Rules[0])
	}
}

// --- 用 Unicode 转义写出的相同正式名称遵守同一布尔规则 ---

func TestParseAuditRequiresABIEscapedNameIsFormal(t *testing.T) {
	// "requiresABI" 解码后就是 "requiresABI"：null 必须拒绝。
	in := abiSubmission(`"\u0072equiresABI":null,`, true)
	if _, _, _, _, err := ParseAuditInput([]byte(in)); err == nil {
		t.Fatal("escaped spelling of requiresABI must denote the formal member")
	} else if !strings.Contains(err.Error(), "r1") || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("error must name the rule and the boolean requirement: %v", err)
	}

	// 转义写出的合法 true 仍是正式成员：产物无 ABI 时按 true 拒绝。
	artifact, rules, invariants, checks, err := ParseAuditInput(
		[]byte(abiSubmission(`"\u0072equiresABI":true,`, false)))
	if err != nil {
		t.Fatal(err)
	}
	if !rules[0].RequiresABI {
		t.Fatal("escaped formal requiresABI:true must decode as true")
	}
	if _, err := BuildReport(artifact, rules, invariants, checks); err == nil {
		t.Fatal("escaped formal requiresABI:true must still require an ABI")
	}
}

// --- 合法提交的报告标识不因相邻扩展成员而改变 ---

func TestParseAuditRequiresABIExtensionDoesNotChangeReportID(t *testing.T) {
	plain := strictParsedReport(t, abiSubmission(`"requiresABI":true,`, true))
	withExt := strictParsedReport(t, abiSubmission(`"RequiresABI":null,"requiresABI":true,`, true))
	if withExt.ReportID != plain.ReportID {
		t.Fatalf("extension member changed the report id:\n got %s\nwant %s",
			withExt.ReportID, plain.ReportID)
	}
}
