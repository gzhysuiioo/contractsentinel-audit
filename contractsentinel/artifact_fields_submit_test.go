package contractsentinel

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交中产物（artifact）四个正式成员的 JSON 类型规则：
// name、abi、bytecode、source 一旦写出，值必须是 JSON 字符串。null、布尔、
// 数字、对象或数组都使整份提交失败，并点名具体字段（例如 artifact.source）
// 必须是字符串；否则 null 会被解码成零值 ""，与用户明确提交的空文本混在
// 一起按空串参与产物哈希。省略成员仍沿用默认值，显式空字符串保留原有业务
// 判断（空名称不能出报告、需要 ABI 的规则仍要求非空 ABI、符号规则仍要求
// 非空字节码；没有这些要求时空文本合法）。大小写变体和带首尾空格的名称
// 仍是扩展信息，既不能补上缺失的正式字段，也不能挽救正式字段的非法值；
// 转义写法的正式名称按解码后名称识别。校验不依赖规则、检查记录是否存在。

// artifactJSONWith 构造一个产物对象，四个字段默认取合法字符串值，field
// 指定的字段改用 raw 原样写入（可以是 null、数字、对象等任意 JSON 值）。
func artifactJSONWith(field, raw string) string {
	vals := map[string]string{
		"name":     `"Vault"`,
		"abi":      `"abi"`,
		"bytecode": `"0x1"`,
		"source":   `"Vault.sol"`,
	}
	vals[field] = raw
	return fmt.Sprintf(`{"name":%s,"abi":%s,"bytecode":%s,"source":%s}`,
		vals["name"], vals["abi"], vals["bytecode"], vals["source"])
}

// artifactTypeDoc 用给定产物 JSON 拼装一份没有规则、没有不变式、没有检查
// 记录的提交：产物字段类型校验不得因为三者皆无而省略。
func artifactTypeDoc(artifactJSON string) string {
	return strictDoc(`"artifact":` + artifactJSON)
}

// artifactFields 是四个正式成员的固定检查顺序。
var artifactFields = []string{"name", "abi", "bytecode", "source"}

// --- 核心场景：合法名称、source 为 null、规则数组为空，也必须整份拒绝 ---

func TestParseAuditNullSourceWithEmptyRulesRejected(t *testing.T) {
	in := `{"artifact":{"name":"Vault","abi":"","bytecode":"","source":null},"rules":[]}`
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err == nil {
		t.Fatal("a legal name with source:null must reject even with an empty rules array")
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("rejection must be errInvalid, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "artifact.source") {
		t.Fatalf("error must name artifact.source: %v", err)
	}
	if !strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("error must state the field must be a string: %v", err)
	}
	if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
		t.Fatalf("rejection must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
	}
}

// --- 任一字段写成 null：点名该字段，且不依赖规则与检查记录 ---

func TestParseAuditNullArtifactFieldsRejected(t *testing.T) {
	for _, field := range artifactFields {
		t.Run(field, func(t *testing.T) {
			in := artifactTypeDoc(artifactJSONWith(field, "null"))
			_, _, _, _, err := ParseAuditInput([]byte(in))
			if err == nil {
				t.Fatalf("artifact.%s: null must reject the whole submission", field)
			}
			want := "artifact." + field + " must be a string"
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error must say %q, got: %v", want, err)
			}
		})
	}
}

// --- 布尔、数字、对象、数组同样整份拒绝 ---

func TestParseAuditNonStringArtifactFieldsRejected(t *testing.T) {
	values := []string{"true", "false", "0", "123", "{}", "[]", `["x"]`}
	for _, field := range artifactFields {
		for _, val := range values {
			t.Run(field+"/"+val, func(t *testing.T) {
				in := artifactTypeDoc(artifactJSONWith(field, val))
				_, _, _, _, err := ParseAuditInput([]byte(in))
				if err == nil {
					t.Fatalf("artifact.%s = %s must reject the whole submission", field, val)
				}
				want := "artifact." + field + " must be a string"
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error must say %q, got: %v", want, err)
				}
			})
		}
	}
}

// --- 即使存在规则与检查记录，产物字段类型错误仍在出报告前拒绝，且是格式错误 ---

func TestParseAuditArtifactFieldTypeErrorIndependentOfRulesAndChecks(t *testing.T) {
	artifact := Artifact{Name: "Vault", ABI: "", Bytecode: "0x1", Source: ""}
	hash := ArtifactHash(artifact)
	// 一条合法规则和一条绑定“被洗白哈希”的通过记录都在场；source:null 仍须
	// 作为提交格式错误拒绝，不能因为记录齐备而放行。
	in := strictDoc(
		`"artifact":{"name":"Vault","abi":"","bytecode":"0x1","source":null}`,
		`"rules":[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}]`,
		`"checks":[`+fmt.Sprintf(
			`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","status":"通过"}]`, hash),
	)
	_, _, _, _, err := ParseAuditInput([]byte(in))
	if err == nil {
		t.Fatal("source:null must reject even with rules and a matching check record present")
	}
	if !strings.Contains(err.Error(), "artifact.source must be a string") {
		t.Fatalf("error must be the artifact.source format error, got: %v", err)
	}
	// 类型错误先于 ABI/字节码业务校验：abi:null 不能被降级成“缺少 ABI”。
	abiNull := strictDoc(
		`"artifact":{"name":"Vault","abi":null,"bytecode":"0x1","source":"Vault.sol"}`,
		`"rules":[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":true,"version":"1.0.0"}]`,
	)
	if _, _, _, _, err := ParseAuditInput([]byte(abiNull)); err == nil ||
		!strings.Contains(err.Error(), "artifact.abi must be a string") {
		t.Fatalf("abi:null must be a format error naming artifact.abi, got: %v", err)
	}
}

// --- 省略字段沿用默认值；省略与显式空字符串报告标识一致 ---

func TestParseAuditOmittedAndExplicitEmptyArtifactFields(t *testing.T) {
	// 仅给出名称，其余三个字段省略。
	omitted := strictDoc(`"artifact":{"name":"Vault"}`, `"rules":[]`)
	a1, rules, _, checks, err := ParseAuditInput([]byte(omitted))
	if err != nil {
		t.Fatalf("omitted abi/bytecode/source must keep parsing: %v", err)
	}
	if a1 != (Artifact{Name: "Vault"}) {
		t.Fatalf("omitted fields must decode to their zero values, got %+v", a1)
	}
	r1, err := BuildReport(a1, rules, nil, checks)
	if err != nil {
		t.Fatalf("legal empty text without rules must build a report: %v", err)
	}

	// 显式空字符串：与省略在同一业务判断下合法，报告标识必须一致。
	explicit := strictDoc(
		`"artifact":{"name":"Vault","abi":"","bytecode":"","source":""}`, `"rules":[]`)
	a2, rules2, _, checks2, err := ParseAuditInput([]byte(explicit))
	if err != nil {
		t.Fatalf("explicit empty strings must parse: %v", err)
	}
	r2, err := BuildReport(a2, rules2, nil, checks2)
	if err != nil {
		t.Fatalf("explicit empty text must build a report: %v", err)
	}
	if r1.ReportID != r2.ReportID || r1.Artifact.Hash != r2.Artifact.Hash {
		t.Fatalf("omitted and explicit-empty must share hash and report id:\n%s\n%s",
			r1.ReportID, r2.ReportID)
	}
}

// --- 显式空字符串保留原有业务判断：空名称、缺 ABI、缺字节码依旧不能出报告 ---

func TestParseAuditExplicitEmptyStringBusinessRulesUnchanged(t *testing.T) {
	// 空名称：解析通过，构建报告仍被拒绝。
	emptyName := strictDoc(
		`"artifact":{"name":"","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`,
		`"rules":[]`)
	a, rules, _, checks, err := ParseAuditInput([]byte(emptyName))
	if err != nil {
		t.Fatalf("an explicit empty name is still a string and must parse: %v", err)
	}
	if _, err := BuildReport(a, rules, nil, checks); err == nil ||
		!strings.Contains(err.Error(), "artifact name is required") {
		t.Fatalf("empty name must still fail the name business rule, got: %v", err)
	}

	// 需要 ABI 的规则遇到显式空 ABI：仍是既有的 ABI 业务错误。
	emptyABI := strictDoc(
		`"artifact":{"name":"Vault","abi":"","bytecode":"0x1","source":"Vault.sol"}`,
		`"rules":[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":true,"version":"1.0.0"}]`)
	a, rules, _, checks, err = ParseAuditInput([]byte(emptyABI))
	if err != nil {
		t.Fatalf("empty ABI must parse as a string: %v", err)
	}
	if _, err := BuildReport(a, rules, nil, checks); err == nil ||
		!strings.Contains(err.Error(), "requires an ABI") {
		t.Fatalf("empty ABI must still fail the ABI rule, got: %v", err)
	}

	// 符号规则遇到显式空字节码：仍是既有的字节码业务错误。
	emptyBytecode := strictDoc(
		`"artifact":{"name":"Vault","abi":"abi","bytecode":"","source":"Vault.sol"}`,
		`"rules":[{"id":"r1","kind":"symbolic","severity":"critical","invariant":"inv","requiresABI":false,"version":"1.0.0"}]`)
	a, rules, _, checks, err = ParseAuditInput([]byte(emptyBytecode))
	if err != nil {
		t.Fatalf("empty bytecode must parse as a string: %v", err)
	}
	if _, err := BuildReport(a, rules, nil, checks); err == nil ||
		!strings.Contains(err.Error(), "requires bytecode") {
		t.Fatalf("empty bytecode must still fail the symbolic rule, got: %v", err)
	}
}

// --- 大小写变体与带空格名称中的值是扩展信息：不触发错误，也不能挽救正式值 ---

func TestParseAuditArtifactFieldVariantsIgnoredOrRejected(t *testing.T) {
	// 正式 source 省略，变体 Source 携带 null：只是扩展信息，提交合法且与
	// 完全省略 source 的提交产物一致（source 取默认空串）。
	variantNull := strictDoc(
		`"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","Source":null}`)
	artifact, _, _, _, err := ParseAuditInput([]byte(variantNull))
	if err != nil {
		t.Fatalf("a null under a variant name is extension data and must parse: %v", err)
	}
	if artifact.Source != "" {
		t.Fatalf("a variant Source must not supply the formal source, got %q", artifact.Source)
	}
	got := strictParsedReport(t, variantNull)
	plainOmitted := strictParsedReport(t, strictDoc(
		`"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1"}`))
	if got.ReportID != plainOmitted.ReportID {
		t.Fatalf("ignored variant must not change the report id:\n got %s\nwant %s",
			got.ReportID, plainOmitted.ReportID)
	}

	// 带首尾空格的名称同样是扩展信息，不能补位缺失的正式字段。
	paddedNull := strictDoc(
		`"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1"," source ":null}`)
	if r := strictParsedReport(t, paddedNull); r.ReportID != plainOmitted.ReportID {
		t.Fatalf("padded-name member must be ignored: %s vs %s", r.ReportID, plainOmitted.ReportID)
	}

	// 变体成员（合法字符串）位于正式成员前或后，都不能挽救正式 null。
	for _, pos := range []string{"before", "after"} {
		t.Run("rescue/"+pos, func(t *testing.T) {
			var art string
			if pos == "before" {
				art = `{"name":"Vault","abi":"abi","bytecode":"0x1","Source":"Other.sol","source":null}`
			} else {
				art = `{"name":"Vault","abi":"abi","bytecode":"0x1","source":null,"Source":"Other.sol"}`
			}
			_, _, _, _, err := ParseAuditInput([]byte(strictDoc(`"artifact":` + art)))
			if err == nil || !strings.Contains(err.Error(), "artifact.source must be a string") {
				t.Fatalf("variant member must not rescue a null formal source: %v", err)
			}
		})
	}
}

// --- Unicode 转义写出的正式名称按解码后名称识别，遵守同一字符串规则 ---

func TestParseAuditEscapedArtifactFieldNameFollowsSameRule(t *testing.T) {
	// "source" 用 Unicode 转义（s = u0073）写出，解码后就是正式字段：null 同样拒绝。
	escapedNull := strictDoc(
		`"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","\u0073ource":null}`)
	if _, _, _, _, err := ParseAuditInput([]byte(escapedNull)); err == nil ||
		!strings.Contains(err.Error(), "artifact.source must be a string") {
		t.Fatalf("escaped formal name with null must reject like the plain spelling: %v", err)
	}

	// 转义写法携带合法字符串时，与直接书写的产物哈希、报告标识一致。
	escaped := strictDoc(
		`"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","\u0073ource":"Vault.sol"}`,
		`"rules":`+strictRulesJSON,
		`"invariants":{"inv":false}`)
	plain := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+strictRulesJSON,
		`"invariants":{"inv":false}`)
	if strictParsedReport(t, escaped).ReportID != strictParsedReport(t, plain).ReportID {
		t.Fatal("escaped and plain spellings of a legal string must share the report id")
	}
}

// --- 合法字符串逐字保留：中文、换行与前后空格；source 是文本而非文件名 ---

func TestParseAuditArtifactStringValuesPreservedVerbatim(t *testing.T) {
	const sourceText = "  合约源码\n第二行  "
	art := fmt.Sprintf(
		`{"name":"  金库  ","abi":"[{\"name\":\"withdraw\"}]","bytecode":"0x6080","source":%q}`,
		sourceText)
	in := strictDoc(`"artifact":`+art, `"rules":[]`)
	got := strictParsedReport(t, in)

	want := Artifact{
		Name:     "  金库  ",
		ABI:      `[{"name":"withdraw"}]`,
		Bytecode: "0x6080",
		Source:   sourceText,
	}
	if got.Artifact.Name != want.Name {
		t.Fatalf("artifact name must keep spaces and Chinese text, got %q", got.Artifact.Name)
	}
	wantHash := ArtifactHash(want)
	if got.Artifact.Hash != wantHash {
		t.Fatalf("artifact hash must cover the literal source text:\n got %s\nwant %s",
			got.Artifact.Hash, wantHash)
	}
	if f := got.Findings; len(f) != 0 {
		t.Fatalf("empty rules must produce no findings, got %+v", f)
	}
}
