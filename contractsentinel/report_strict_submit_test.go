package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 本文件锁定 audit “提交”侧固定字段的大小写规则：提交最外层、合约产物、
// 每条规则及每条检查记录中已经定义的字段，只认提交 JSON 中原有的大小写写
// 法。encoding/json 在精确匹配失败后会退化为大小写不敏感匹配，因此检查记录
// 里先写正式 status=发现缺陷、再写扩展成员 StAtus=通过 时，解码只会留下最
// 后一个值，缺陷被当成通过保存；把两个成员的次序调换又得到相反结论——同一
// 份提交仅因成员位置不同就得到不同审计结果。修正后，这些大小写变体、两侧
// 带空白的名字以及其他未知名称都只是被忽略的扩展信息：既不能覆盖正式字段，
// 也不能在正式字段缺失或非法时顶替；不变式名称由用户定义，不属于固定字
// 段，Inv 与 inv 仍是两个独立不变式，名称空白也不修剪。

// strictCheckSubmission 构造一条带单个产物、单条规则和一条检查记录的提交，
// middle 原样插入该检查记录（用于放置正式 status 与各种扩展成员）。
func strictCheckSubmission(hash string, middle string) []byte {
	return []byte(`{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1"}],
		"checks": [{"artifactHash":"` + hash + `","ruleId":"r1","version":"1",` + middle + `}]
	}`)
}

func strictSubmissionArtifact() Artifact {
	return Artifact{Name: "Vault", ABI: "abi", Bytecode: "0x1", Source: "Vault.sol"}
}

func strictSubmissionRules() []Rule {
	return []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}}
}

// --- 核心场景：正式 status=发现缺陷 与 StAtus=通过 同现，两种成员顺序与各种
// 合法 JSON 类型的扩展值，都必须保留原来的缺陷结论与报告标识 ---

func TestParseAuditInputCaseVariantStatusKeepsDefect(t *testing.T) {
	art := strictSubmissionArtifact()
	rules := strictSubmissionRules()
	hash := ArtifactHash(art)
	// 不含任何扩展成员时的基准报告：扩展信息不得改变报告标识。
	base, err := BuildReport(art, rules, nil, []CheckRecord{
		{ArtifactHash: hash, RuleID: "r1", Version: "1", Status: StatusDefect, Note: "cex"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		middle string
	}{
		{"variant after formal", `"status":"` + StatusDefect + `","StAtus":"` + StatusPass + `","note":"cex"`},
		{"variant before formal", `"StAtus":"` + StatusPass + `","status":"` + StatusDefect + `","note":"cex"`},
		{"variant carries a string", `"status":"` + StatusDefect + `","StAtus":"其他写法","note":"cex"`},
		{"variant carries a number", `"status":"` + StatusDefect + `","StAtus":123,"note":"cex"`},
		{"variant carries an object", `"status":"` + StatusDefect + `","StAtus":{"x":1},"note":"cex"`},
		{"variant carries an array", `"status":"` + StatusDefect + `","StAtus":[1,2],"note":"cex"`},
		{"variant carries null", `"status":"` + StatusDefect + `","StAtus":null,"note":"cex"`},
		{"variant carries a boolean", `"status":"` + StatusDefect + `","StAtus":true,"note":"cex"`},
		{"whitespace-padded name", `" status ":"` + StatusPass + `","status":"` + StatusDefect + `","note":"cex"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, checks, err := ParseAuditInput(strictCheckSubmission(hash, tc.middle))
			if err != nil {
				t.Fatalf("extension members must be ignored, got %v", err)
			}
			report, err := BuildReport(art, rules, nil, checks)
			if err != nil {
				t.Fatalf("formal defect must survive, got %v", err)
			}
			if checks[0].Status != StatusDefect {
				t.Fatalf("check status = %q, want the formal %q", checks[0].Status, StatusDefect)
			}
			if report.Rules[0].Status != StatusDefect {
				t.Fatalf("rule status = %q, want %q", report.Rules[0].Status, StatusDefect)
			}
			if report.ReportID != base.ReportID {
				t.Fatalf("extension members changed the report id:\n got %s\nwant %s", report.ReportID, base.ReportID)
			}
			if len(report.Findings) != 1 {
				t.Fatalf("findings = %d, want exactly the one defect", len(report.Findings))
			}
			f := report.Findings[0]
			if f.ArtifactHash != hash || f.RuleID != "r1" || f.Version != "1" || f.Evidence != "cex" {
				t.Fatalf("defect binding altered by extension data: %+v", f)
			}
		})
	}
}

// --- 缺少正式 status：即使旁边的 StAtus 写着“通过”，也必须整份拒绝且点名规则 ---

func TestParseAuditInputMissingFormalStatusRejected(t *testing.T) {
	art := strictSubmissionArtifact()
	rules := strictSubmissionRules()
	hash := ArtifactHash(art)
	for _, tc := range []struct {
		name   string
		middle string
	}{
		{"only a case variant", `"StAtus":"` + StatusPass + `"`},
		{"only a whitespace-padded name", `" status ":"` + StatusPass + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, checks, perr := ParseAuditInput(strictCheckSubmission(hash, tc.middle))
			if perr != nil {
				t.Fatalf("parsing with an absent formal status should succeed, got %v", perr)
			}
			report, berr := BuildReport(art, rules, nil, checks)
			if berr == nil {
				t.Fatalf("a check without a formal status must be rejected, got %+v", report)
			}
			var ei errInvalid
			if !errors.As(berr, &ei) {
				t.Fatalf("expected errInvalid, got %T: %v", berr, berr)
			}
			if !strings.Contains(berr.Error(), "r1") {
				t.Fatalf("error must identify the rule: %v", berr)
			}
			if !strings.Contains(berr.Error(), "status") {
				t.Fatalf("error must point at the formal status field: %v", berr)
			}
		})
	}
}

// --- 正式 status 写成不支持的状态：旁边的 StAtus=通过 不能将其洗白 ---

func TestParseAuditInputInvalidFormalStatusRejected(t *testing.T) {
	art := strictSubmissionArtifact()
	rules := strictSubmissionRules()
	hash := ArtifactHash(art)
	middle := `"status":"bogus","StAtus":"` + StatusPass + `","note":"x"`
	_, _, _, checks, perr := ParseAuditInput(strictCheckSubmission(hash, middle))
	if perr != nil {
		t.Fatalf("parse must accept the formal (invalid) value, got %v", perr)
	}
	_, berr := BuildReport(art, rules, nil, checks)
	if berr == nil {
		t.Fatal("an unsupported formal status must be rejected despite the variant")
	}
	if !strings.Contains(berr.Error(), "r1") || !strings.Contains(berr.Error(), "bogus") {
		t.Fatalf("error must name the rule and the invalid status: %v", berr)
	}
}

// --- 产物、规则与最外层的固定字段同样只认原有写法 ---

func TestParseAuditInputCaseVariantsIgnoredAcrossAllLevels(t *testing.T) {
	input := `{
		"RULES": [{"id":"evil","version":"1"}],
		"extraTop": {"any": "json"},
		"artifact": {"Name":"Other","ABI":"fake","abi":"real-abi","bytecode":"0x1","source":"s"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","Version":"9.9.9","version":"1","STATUS":"x"}],
		"invariants": {"inv": false}
	}`
	art, rules, invs, checks, err := ParseAuditInput([]byte(input))
	if err != nil {
		t.Fatalf("extension members must be accepted: %v", err)
	}
	// 正式 name 缺失时保持零值，绝不能取 Name 变体；ABI 必须取正式值。
	if art.Name != "" {
		t.Fatalf("absent formal name must stay empty, variant Name must not fill it: %q", art.Name)
	}
	if art.ABI != "real-abi" {
		t.Fatalf("artifact ABI laundered by variant: %+v", art)
	}
	if len(rules) != 1 || rules[0].ID != "r1" || rules[0].Version != "1" {
		t.Fatalf("formal rules altered by top-level/rule variants: %+v", rules)
	}
	if _, ok := invs["RULES"]; ok {
		t.Fatal("top-level RULES extension must not be imported as an invariant")
	}
	if len(checks) != 0 {
		t.Fatalf("no formal checks were given: %+v", checks)
	}
}

// --- 不变式名称由用户定义：Inv 与 inv 独立，名称空白不修剪，值只接受布尔 ---

func TestParseAuditInputInvariantNamesAreUserDefined(t *testing.T) {
	input := `{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"s"},
		"rules": [],
		"invariants": {"Inv": true, "inv": false, " Inv ": false}
	}`
	_, _, invs, _, err := ParseAuditInput([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(invs) != 3 {
		t.Fatalf("Inv, inv and the padded name are three invariants, got %+v", invs)
	}
	if invs["Inv"] != true || invs["inv"] != false {
		t.Fatalf("Inv and inv must stay distinct: %+v", invs)
	}
	if got, ok := invs[" Inv "]; !ok || got != false {
		t.Fatalf("surrounding whitespace in an invariant name must be preserved: %+v", invs)
	}

	// 即使名称碰巧与某个固定字段同名（如 rules），它仍是一个用户定义不变式，
	// 值仍只接受布尔值。
	bad := `{"artifact":{"name":"Vault"},"rules":[],"invariants":{"RULES":7}}`
	if _, _, _, _, err := ParseAuditInput([]byte(bad)); err == nil {
		t.Fatal("a user-defined invariant named RULES with a non-boolean value must be rejected")
	} else if !strings.Contains(err.Error(), "RULES") || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("error must name the invariant and require a boolean: %v", err)
	}
}

// --- 用 JSON 转义写出的固定字段名仍按解码后的名称识别为正式字段 ---

func TestParseAuditInputEscapedFixedNameDecodesAsFormal(t *testing.T) {
	// 正式字段名 status 中的 s 用 JSON 转义 写出，解码后仍是 status：
	// 给出的“通过”必须按正式字段识别，而不是被当作未知扩展成员。
	input := `{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"s"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1"}],
		"checks": [{"ruleId":"r1","version":"1","\u0073tatus":"` + StatusPass + `"}]
	}`
	_, _, _, checks, err := ParseAuditInput([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].Status != StatusPass {
		t.Fatalf("escaped fixed name must decode as the formal field: %+v", checks)
	}
}

// --- 扩展对象内部的重复成员仍整份拒绝，不能因忽略扩展信息而放行 ---

func TestParseAuditInputDuplicateInsideExtensionStillRejected(t *testing.T) {
	input := `{
		"mystery": {"a": 1, "a": 2},
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"s"},
		"rules": []
	}`
	_, _, _, _, err := ParseAuditInput([]byte(input))
	if err == nil {
		t.Fatal("a duplicate member inside an extension object must still reject the submission")
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid, got %T: %v", err, err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		t.Fatalf("error must state the duplicate member: %v", err)
	}
}

// --- 扩展信息不改变合法提交的报告标识：有无扩展成员、成员顺序如何都一致 ---

func TestParseAuditInputExtensionsDoNotChangeReportID(t *testing.T) {
	art := strictSubmissionArtifact()
	rules := strictSubmissionRules()
	hash := ArtifactHash(art)
	plain := strictCheckSubmission(hash, `"status":"`+StatusPass+`"`)
	extended := strictCheckSubmission(hash,
		`"StAtus":"`+StatusDefect+`","status":"`+StatusPass+`","Note":"ignored"`)
	build := func(data []byte) Report {
		_, rs, _, cs, err := ParseAuditInput(data)
		if err != nil {
			t.Fatal(err)
		}
		r, err := BuildReport(art, rs, nil, cs)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if build(plain).ReportID != build(extended).ReportID {
		t.Fatal("extension members must not change the report id of a legal submission")
	}
	_ = rules
}
