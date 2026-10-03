package contractsentinel

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交侧的固定字段大小写规则，与 report 读取侧
// (report_strict_load_test.go) 保持一致：只有约定拼写的字段参与审计，
// StAtus、Version、RULES 这类大小写变体以及名称两侧带空格的成员都只是扩展
// 信息，出现在正式成员之前或之后、携带任意合法 JSON 类型都不能改写结论；
// 但扩展信息本身仍被允许，不能一遇未知名称就拒绝。不变式名称是用户定义的，
// Inv 与 inv 是两个独立不变式，名称空格也不修剪。字段名的 JSON 转义按解码
// 后的名称识别；重复成员（含扩展对象内部）仍整份拒绝。

// strictTestArtifact 是本文件提交用例共享的产物，其 JSON 形态与字段值固定。
func strictTestArtifact() Artifact {
	return Artifact{Name: "Vault", ABI: "abi", Bytecode: "0x1", Source: "Vault.sol"}
}

const strictArtifactJSON = `{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`
const strictRulesJSON = `[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}]`

// strictDoc 用顶层段落拼装一份提交，括号由本函数统一负责，避免手写时漏掉
// 外层大括号。
func strictDoc(sections ...string) string {
	return "{" + strings.Join(sections, ",") + "}"
}

// strictDefectCheck 是一条绑定正确产物哈希、正式结论为“发现缺陷”的检查
// 记录；formalPrefix 会被放在正式 status 之前（用于在正式字段前放扩展成员），
// formalSuffix 放在其后。
func strictDefectCheck(hash, formalPrefix, formalSuffix string) string {
	return fmt.Sprintf(
		`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0",%s"status":"发现缺陷"%s,"note":"counterexample: x"}`,
		hash, formalPrefix, formalSuffix)
}

// strictParsedReport 解析并构建一份提交，返回报告；任一环节失败即终止。
func strictParsedReport(t *testing.T, in string) Report {
	t.Helper()
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err != nil {
		t.Fatalf("legal submission must parse: %v\ninput: %s", err, in)
	}
	report, err := BuildReport(artifact, rules, invariants, checks)
	if err != nil {
		t.Fatalf("legal submission must build a report: %v\ninput: %s", err, in)
	}
	return report
}

// --- 核心场景：正式 status=发现缺陷 + StAtus=通过，两种成员顺序结论一致 ---

func TestParseAuditCaseVariantStatusKeepsDefect(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	plain := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"checks":[`+strictDefectCheck(hash, "", "")+`]`,
	)
	want := strictParsedReport(t, plain)

	for _, tc := range []struct {
		name   string
		prefix string
		suffix string
	}{
		{"variant after formal field", "", `,"StAtus":"通过"`},
		{"variant before formal field", `"StAtus":"通过",`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := strictDoc(
				`"artifact":`+strictArtifactJSON,
				`"rules":`+strictRulesJSON,
				`"checks":[`+strictDefectCheck(hash, tc.prefix, tc.suffix)+`]`,
			)
			got := strictParsedReport(t, in)

			// 正式缺陷仍生成该规则的缺陷。
			if len(got.Findings) != 1 {
				t.Fatalf("findings = %d, want 1 (formal 发现缺陷)", len(got.Findings))
			}
			f := got.Findings[0]
			if f.RuleID != "r1" || f.Version != "1.0.0" || f.ArtifactHash != hash {
				t.Fatalf("finding binding changed: %+v", f)
			}
			if f.Evidence != "counterexample: x" {
				t.Fatalf("formal note evidence must be preserved, got %q", f.Evidence)
			}
			if got.Rules[0].Status != StatusDefect {
				t.Fatalf("rule status = %q, want %q", got.Rules[0].Status, StatusDefect)
			}
			// 仅增加扩展信息不得改变报告标识、产物哈希与规则版本绑定。
			if got.ReportID != want.ReportID {
				t.Fatalf("extension member changed the report id:\n got %s\nwant %s", got.ReportID, want.ReportID)
			}
			if got.Artifact.Hash != hash {
				t.Fatalf("artifact hash changed: %q", got.Artifact.Hash)
			}
		})
	}
}

// --- 扩展成员携带任意合法 JSON 类型、位于正式字段前后，都不改变合法结果 ---

func TestParseAuditExtensionMembersOfAnyTypeIgnored(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	values := []string{`"通过"`, `123`, `true`, `null`, `[1,2,3]`, `{"a":1}`}
	for _, val := range values {
		for _, pos := range []string{"before", "after"} {
			ext := `"StAtus":` + val
			var middle string
			var suffix string
			if pos == "before" {
				middle = ext + ","
			} else {
				suffix = "," + ext
			}
			check := fmt.Sprintf(
				`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0",%s"status":"发现缺陷"%s,"note":"ce"}`,
				hash, middle, suffix)
			in := strictDoc(
				`"artifact":`+strictArtifactJSON,
				`"rules":`+strictRulesJSON,
				`"checks":[`+check+`]`,
			)
			got := strictParsedReport(t, in)
			if len(got.Findings) != 1 || got.Rules[0].Status != StatusDefect {
				t.Fatalf("ext=%s pos=%s changed the conclusion: %+v", val, pos, got)
			}
		}
	}
}

// --- 顶层、产物、规则、检查记录的大小写变体都不能替代正式字段 ---

func TestParseAuditCaseVariantsIgnoredAtEveryLevel(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	// 正式输入：规则 r1 版本 1.0.0、不变式 inv=false，应产生一个缺陷；检查
	// 记录给 r1 一条正式“通过”会与不变式冲突，所以这里只在顶层放变体检查。
	in := strictDoc(
		// 产物：大小写变体给出不同名字与字段，正式产物不受影响。
		`"artifact":{`+
			`"Name":"Other","ABI":"other-abi","BYTECODE":"0xffff","Source":"Other.sol",`+
			`"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`,
		// 规则：变体 RULES 用 9.9.9 版本，正式 rules 仍是 1.0.0；规则内
		// Version/ID 变体也被忽略。
		`"RULES":[{"id":"r1","version":"9.9.9"}]`,
		`"rules":[{"ID":"x","Version":"9.9.9","id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}]`,
		// 顶层变体检查记录携带别的结论，正式 checks 为空，不影响。
		`"CHECKS":[{"ruleId":"r1","StAtus":"通过"}]`,
		`"invariants":{"inv":false}`,
	)
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err != nil {
		t.Fatalf("legal submission must parse: %v", err)
	}
	// 正式产物的四个字段都必须来自约定拼写，变体里的 other-* 一律忽略。
	if artifact != strictTestArtifact() {
		t.Fatalf("artifact fields came from case variants: %+v", artifact)
	}
	got, err := BuildReport(artifact, rules, invariants, checks)
	if err != nil {
		t.Fatalf("legal submission must build a report: %v", err)
	}
	if got.Artifact.Name != "Vault" {
		t.Fatalf("artifact name came from a case variant: %+v", got.Artifact)
	}
	if got.Artifact.Hash != hash {
		t.Fatalf("artifact hash changed via variants: %q want %q", got.Artifact.Hash, hash)
	}
	if got.Rules[0].Version != "1.0.0" || got.Rules[0].ID != "r1" {
		t.Fatalf("rule fields came from case variants: %+v", got.Rules[0])
	}
	if len(got.Findings) != 1 || got.Findings[0].Version != "1.0.0" {
		t.Fatalf("formal inv=false must bind rule version 1.0.0: %+v", got.Findings)
	}

	// 与不含任何扩展成员的同一提交报告标识一致。
	plain := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"invariants":{"inv":false}`,
	)
	want := strictParsedReport(t, plain)
	if got.ReportID != want.ReportID {
		t.Fatalf("extensions changed the report id:\n got %s\nwant %s", got.ReportID, want.ReportID)
	}
}

// --- 名称两侧带空格的成员不能替代正式字段；正式字段在场时被忽略 ---

func TestParseAuditWhitespacePaddedNameIgnoredOrRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	// 正式 status 在场时，" status " 只是扩展信息，结论仍是正式缺陷。
	withFormal := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"checks":[`+fmt.Sprintf(
			`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0"," status ":"通过","status":"发现缺陷","note":"ce"}]`,
			hash),
	)
	got := strictParsedReport(t, withFormal)
	if got.Rules[0].Status != StatusDefect || len(got.Findings) != 1 {
		t.Fatalf("padded-name extension must be ignored when formal status exists: %+v", got)
	}

	// 缺少正式 status，只有带空格的名字，必须整份拒绝。
	missingFormal := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"checks":[`+fmt.Sprintf(
			`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0"," status ":"通过"}]`,
			hash),
	)
	_, _, _, _, err := ParseAuditInput([]byte(missingFormal))
	if err == nil {
		t.Fatal("a whitespace-padded status name must not substitute for the formal status")
	}
	if !strings.Contains(err.Error(), "r1") || !strings.Contains(err.Error(), "status") {
		t.Fatalf("error must name the rule and the status field: %v", err)
	}
}

// --- 用 JSON 转义写出的字段名按解码后名称识别，仍是正式字段 ---

func TestParseAuditEscapedFixedNameDecodesAsFormal(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	// "status" 解码后就是 "status"，必须被当作正式结论。
	check := fmt.Sprintf(
		`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","status":"发现缺陷","note":"ce"}`,
		hash)
	in := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"checks":[`+check+`]`,
	)
	got := strictParsedReport(t, in)
	if got.Rules[0].Status != StatusDefect || len(got.Findings) != 1 {
		t.Fatalf("escaped spelling of status must denote the formal field: %+v", got)
	}
}

// --- 缺少正式 status：即使旁边的 StAtus=通过，也必须整份拒绝并点名规则 ---

func TestParseAuditMissingFormalStatusRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	for _, pos := range []string{"after", "before"} {
		name := pos
		t.Run(name, func(t *testing.T) {
			var check string
			if pos == "after" {
				check = fmt.Sprintf(
					`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","StAtus":"通过"}`,
					hash)
			} else {
				check = fmt.Sprintf(
					`{"artifactHash":%q,"StAtus":"通过","ruleId":"r1","version":"1.0.0"}`,
					hash)
			}
			in := strictDoc(
				`"artifact":`+strictArtifactJSON,
				`"rules":`+strictRulesJSON,
				`"checks":[`+check+`]`,
			)
			artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
			if err == nil {
				t.Fatal("missing formal status must reject even with a StAtus pass next to it")
			}
			var ei errInvalid
			if !errors.As(err, &ei) {
				t.Fatalf("rejection must be errInvalid, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), "r1") {
				t.Fatalf("error must identify rule r1: %v", err)
			}
			if !strings.Contains(err.Error(), "status") {
				t.Fatalf("error must state the formal status problem: %v", err)
			}
			if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
				t.Fatalf("rejection must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
			}
		})
	}
}

// --- 正式 status 写成不支持的值：StAtus 不能提供合法状态顶替 ---

func TestParseAuditUnsupportedFormalStatusRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	for _, tc := range []struct {
		name  string
		patch string
	}{
		{"variant after bogus", `"status":"bogus","StAtus":"通过"`},
		{"variant before bogus", `"StAtus":"通过","status":"bogus"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := fmt.Sprintf(
				`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0",%s,"note":"ce"}`,
				hash, tc.patch)
			in := strictDoc(
				`"artifact":`+strictArtifactJSON,
				`"rules":`+strictRulesJSON,
				`"checks":[`+check+`]`,
			)
			_, _, _, _, err := ParseAuditInput([]byte(in))
			if err == nil {
				t.Fatal("an unsupported formal status must reject")
			}
			if !strings.Contains(err.Error(), "r1") {
				t.Fatalf("error must identify rule r1: %v", err)
			}
			if !strings.Contains(err.Error(), "unknown status bogus") {
				t.Fatalf("error must name the unsupported formal status: %v", err)
			}
		})
	}
}

// --- 正式 status 类型不是字符串：不能被扩展成员掩盖 ---

func TestParseAuditNonStringFormalStatusRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	check := fmt.Sprintf(
		`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","StAtus":"通过","status":123}`,
		hash)
	in := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"checks":[`+check+`]`,
	)
	_, _, _, _, err := ParseAuditInput([]byte(in))
	if err == nil {
		t.Fatal("a non-string formal status must reject")
	}
	if !strings.Contains(err.Error(), "r1") || !strings.Contains(err.Error(), "string") {
		t.Fatalf("error must name the rule and require a string status: %v", err)
	}
}

// --- 没有 ruleId 的记录，正式 status 缺失时仍被拒绝（不会 panic，位置可辨） ---

func TestParseAuditBadStatusWithoutRuleIDRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	check := fmt.Sprintf(`{"artifactHash":%q,"version":"1.0.0","StAtus":"通过"}`, hash)
	in := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"checks":[`+check+`]`,
	)
	_, _, _, _, err := ParseAuditInput([]byte(in))
	if err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("missing formal status must reject even without a ruleId: %v", err)
	}
}

// --- 不变式名称大小写敏感、空格不修剪；值仍只接受布尔 ---

func TestParseAuditInvariantNamesAreUserDefined(t *testing.T) {
	in := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"invariants":{"Inv":true,"inv":false," inv ":true}`,
	)
	_, _, invariants, _, err := ParseAuditInput([]byte(in))
	if err != nil {
		t.Fatalf("Inv, inv and \" inv \" are three distinct invariants: %v", err)
	}
	if len(invariants) != 3 {
		t.Fatalf("want 3 distinct invariant names, got %+v", invariants)
	}
	if invariants["Inv"] != true || invariants["inv"] != false || invariants[" inv "] != true {
		t.Fatalf("invariant names/values not preserved exactly: %+v", invariants)
	}

	// 规则引用小写 inv：取 false，产生缺陷，与 Inv / " inv " 无关。
	got := strictParsedReport(t, in)
	if len(got.Findings) != 1 || got.Findings[0].Invariant != "inv" {
		t.Fatalf("rule must bind to lowercase inv=false: %+v", got.Findings)
	}

	// 用户定义名称下，非布尔值依旧整体拒绝。
	bad := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"invariants":{"Inv":"true","inv":false}`,
	)
	_, _, _, _, err = ParseAuditInput([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "Inv") || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("non-boolean invariant Inv must reject and be named: %v", err)
	}
}

// --- 扩展对象内部重复成员仍整份拒绝，不能因为忽略扩展信息而放行 ---

func TestParseAuditDuplicateMemberInsideExtensionRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	check := fmt.Sprintf(
		`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","status":"通过","ext":{"a":1,"a":2}}`,
		hash)
	in := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"checks":[`+check+`]`,
	)
	_, _, _, _, err := ParseAuditInput([]byte(in))
	if err == nil {
		t.Fatal("a duplicate member inside an extension object must still reject the submission")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		t.Fatalf("error must classify the problem as a duplicate member: %v", err)
	}

	// 顶层扩展对象重复成员同样拒绝。
	topExt := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"mystery":{"x":1,"x":2}`,
	)
	if _, _, _, _, err := ParseAuditInput([]byte(topExt)); err == nil {
		t.Fatal("a duplicate member inside a top-level extension object must reject")
	}
}

// --- 仅出现一次的未知成员继续放行，不因未知名称本身被拒绝 ---

func TestParseAuditSingleUnknownMemberAccepted(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	check := fmt.Sprintf(
		`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","status":"通过","mystery":{"nested":[true,null]}}`,
		hash)
	in := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"checks":[`+check+`]`,
		`"extraTop":"hello"`,
	)
	got := strictParsedReport(t, in)
	if got.Rules[0].Status != StatusPass || len(got.Findings) != 0 {
		t.Fatalf("unknown extension members must be allowed and ignored: %+v", got)
	}
}
