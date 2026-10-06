package contractsentinel

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交中产物四个正式字段 name、abi、bytecode、source 的
// 类型规则：成员一旦写出，值必须是 JSON 字符串。null、布尔值、数字、对象
// 或数组都使整份提交失败（errInvalid），错误点名具体字段，例如
// artifact.source，并说明该字段必须是字符串，而不是被解码成零值 "" 后按
// 空文本继续——否则产物名称合法、规则为空、source 为 null 这样的畸形提交
// 会与用户明确提交空文本得到相同的产物哈希和成功报告，格式错误与合法
// 空文本混在一起。校验与规则数组、检查记录、规则是否引用该字段无关。
// 省略成员仍取默认零值，显式空字符串仍走原有业务判断（空名称不能出报告、
// 需要 ABI 的规则仍要求非空 ABI、符号规则仍要求非空字节码）；大小写变体
// 与带空格的名称只是扩展信息，不能补上缺失的正式字段或挽救非法值；
// Unicode 转义写出的正式名称解码后受同一检查。合法字符串逐字保留。

// jsonString quotes a Go string as a JSON string literal, so tests can embed
// text containing newlines, tabs and CJK characters without hand-escaping.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// artifactFieldsDoc 拼装一份提交：nameJSON 与 fieldsJSON 是 artifact 对象
// 的内部 JSON 片段（均可为空），rulesJSON 是单条规则的完整 JSON，空串表示
// 规则数组为空。
func artifactFieldsDoc(nameJSON, fieldsJSON, rulesJSON string) string {
	inner := nameJSON
	if fieldsJSON != "" {
		if inner != "" {
			inner += ","
		}
		inner += fieldsJSON
	}
	rules := "[]"
	if rulesJSON != "" {
		rules = "[" + rulesJSON + "]"
	}
	return `{"artifact":{` + inner + `},"rules":` + rules + `}`
}

// artifactTextRule 是一条不要求 ABI 的普通静态规则，供“有规则时类型检查
// 也不省略”的用例使用。
const artifactTextRule = `{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}`

// --- 核心场景：名称合法、source 为 null、规则为空也必须整份拒绝 ---

func TestParseAuditNullSourceWithEmptyRulesRejected(t *testing.T) {
	in := artifactFieldsDoc(`"name":"Vault"`, `"abi":"","bytecode":"","source":null`, "")
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err == nil {
		t.Fatal("a legal name with source null and no rules must still reject the submission")
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("a type error is a submission format error (errInvalid), got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "artifact.source") {
		t.Fatalf("error must name the exact field artifact.source: %v", err)
	}
	if !strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("error must state the field must be a string: %v", err)
	}
	if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
		t.Fatalf("rejection must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
	}
}

// --- 四个字段的 null 都整份拒绝，且与是否有规则、是否有检查记录无关 ---

func TestParseAuditNullArtifactFieldsRejected(t *testing.T) {
	for _, tc := range []struct {
		field string
		doc   string
	}{
		{"name", artifactFieldsDoc(`"name":null`, `"abi":"a","bytecode":"b","source":"s"`, "")},
		{"abi", artifactFieldsDoc(`"name":"Vault"`, `"abi":null,"bytecode":"b","source":"s"`, "")},
		{"bytecode", artifactFieldsDoc(`"name":"Vault"`, `"abi":"a","bytecode":null,"source":"s"`, "")},
		{"source", artifactFieldsDoc(`"name":"Vault"`, `"abi":"a","bytecode":"b","source":null`, "")},
	} {
		t.Run(tc.field, func(t *testing.T) {
			// 无规则、无检查记录：不能因此省略类型校验。
			if _, _, _, _, err := ParseAuditInput([]byte(tc.doc)); err == nil ||
				!strings.Contains(err.Error(), "artifact."+tc.field) ||
				!strings.Contains(err.Error(), "must be a string") {
				t.Fatalf("null %s must reject and name artifact.%s: %v", tc.field, tc.field, err)
			}
			// 有规则（且规则并不引用该字段）时同样拒绝。
			withRule := strings.Replace(tc.doc, `"rules":[]`, `"rules":[`+artifactTextRule+`]`, 1)
			if _, _, _, _, err := ParseAuditInput([]byte(withRule)); err == nil ||
				!strings.Contains(err.Error(), "artifact."+tc.field+" must be a string") {
				t.Fatalf("null %s must reject even with an unrelated rule present: %v", tc.field, err)
			}
		})
	}
}

// --- 布尔值、数字、对象、数组同样整份拒绝，不能被当成空字符串 ---

func TestParseAuditNonStringArtifactFieldsRejected(t *testing.T) {
	values := []string{"true", "false", "0", "123", "{}", `["x"]`}
	docs := map[string]func(string) string{
		"name":     func(val string) string { return `{"artifact":{"name":` + val + `},"rules":[]}` },
		"abi":      func(val string) string { return `{"artifact":{"name":"Vault","abi":` + val + `},"rules":[]}` },
		"bytecode": func(val string) string { return `{"artifact":{"name":"Vault","bytecode":` + val + `},"rules":[]}` },
		"source":   func(val string) string { return `{"artifact":{"name":"Vault","source":` + val + `},"rules":[]}` },
	}
	for _, field := range []string{"name", "abi", "bytecode", "source"} {
		for _, val := range values {
			t.Run(field+"/"+val, func(t *testing.T) {
				_, _, _, _, err := ParseAuditInput([]byte(docs[field](val)))
				if err == nil {
					t.Fatalf("artifact %s=%s must reject the whole submission", field, val)
				}
				if !strings.Contains(err.Error(), "artifact."+field+" must be a string") {
					t.Fatalf("error must name artifact.%s and the string requirement: %v", field, err)
				}
			})
		}
	}
}

// --- 省略成员仍取默认值；显式空字符串合法；两种写法的产物哈希一致 ---

func TestParseAuditArtifactFieldsOmittedAndExplicitEmpty(t *testing.T) {
	omitted := `{"artifact":{"name":"Vault"},"rules":[]}`
	aOmit, _, _, _, err := ParseAuditInput([]byte(omitted))
	if err != nil {
		t.Fatalf("omitted artifact fields must keep their defaults: %v", err)
	}
	if aOmit.ABI != "" || aOmit.Bytecode != "" || aOmit.Source != "" {
		t.Fatalf("omitted fields must decode to empty strings: %+v", aOmit)
	}

	explicitEmpty := artifactFieldsDoc(`"name":"Vault"`, `"abi":"","bytecode":"","source":""`, "")
	aEmpty, _, _, _, err := ParseAuditInput([]byte(explicitEmpty))
	if err != nil {
		t.Fatalf("explicit empty strings must stay legal: %v", err)
	}
	if aEmpty != aOmit {
		t.Fatalf("omitted and explicit-empty must decode to the same artifact:\n%+v\n%+v", aEmpty, aOmit)
	}
	if ArtifactHash(aEmpty) != ArtifactHash(aOmit) {
		t.Fatal("omitted and explicit-empty text must share the artifact hash")
	}

	// 合法空文本在没有相关要求时可以出报告，且两种写法报告标识一致。
	rOmit := strictParsedReport(t, omitted)
	rEmpty := strictParsedReport(t, explicitEmpty)
	if rOmit.ReportID != rEmpty.ReportID {
		t.Fatalf("omitted and explicit-empty must share the report id:\n%s\n%s", rOmit.ReportID, rEmpty.ReportID)
	}
}

// --- 显式空字符串保留原有业务判断 ---

func TestParseAuditExplicitEmptyKeepsBusinessJudgement(t *testing.T) {
	// 显式空名称：解析合法，但不能生成报告。
	emptyName := `{"artifact":{"name":"","abi":"","bytecode":"","source":""},"rules":[]}`
	a, rules, inv, checks, err := ParseAuditInput([]byte(emptyName))
	if err != nil {
		t.Fatalf("an explicit empty name is a legal string and must parse: %v", err)
	}
	if _, err := BuildReport(a, rules, inv, checks); err == nil ||
		!strings.Contains(err.Error(), "artifact name is required") {
		t.Fatalf("an empty name must still produce no report: %v", err)
	}

	// 需要 ABI 的规则 + 显式空 ABI：仍是既有 ABI 业务错误，不是类型错误。
	emptyABI := artifactFieldsDoc(`"name":"Vault"`, `"abi":"","bytecode":"b","source":"s"`,
		`{"id":"r-abi","kind":"static","severity":"high","invariant":"inv","requiresABI":true,"version":"1.0.0"}`)
	a, rules, inv, checks, err = ParseAuditInput([]byte(emptyABI))
	if err != nil {
		t.Fatalf("an explicit empty ABI is a legal string and must parse: %v", err)
	}
	if _, err := BuildReport(a, rules, inv, checks); err == nil ||
		!strings.Contains(err.Error(), "requires an ABI") {
		t.Fatalf("an empty ABI must still fail the ABI business rule: %v", err)
	}

	// 符号规则 + 显式空字节码：仍是既有字节码业务错误。
	emptyBytecode := artifactFieldsDoc(`"name":"Vault"`, `"abi":"a","bytecode":"","source":"s"`,
		`{"id":"r-sym","kind":"symbolic","severity":"high","invariant":"inv","version":"1.0.0"}`)
	a, rules, inv, checks, err = ParseAuditInput([]byte(emptyBytecode))
	if err != nil {
		t.Fatalf("an explicit empty bytecode is a legal string and must parse: %v", err)
	}
	if _, err := BuildReport(a, rules, inv, checks); err == nil ||
		!strings.Contains(err.Error(), "requires bytecode") {
		t.Fatalf("empty bytecode must still fail the symbolic business rule: %v", err)
	}
}

// --- 类型错误是提交格式错误：不能记成缺陷、工具缺失或超时 ---

func TestParseAuditNonStringArtifactFieldIsNotAConclusion(t *testing.T) {
	// 即使存在规则，产物字段类型错误也在构建报告之前拒绝，永远不会以任何
	// 检查结论落盘。
	in := artifactFieldsDoc(`"name":"Vault"`, `"abi":"","bytecode":"","source":null`, artifactTextRule)
	_, _, _, _, err := ParseAuditInput([]byte(in))
	if err == nil {
		t.Fatal("source null must be rejected before any conclusion is recorded")
	}
	for _, marker := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("a format error must not be reported as a check conclusion %q: %v", marker, err)
		}
	}
}

// --- 大小写变体与带空格名称中的值是扩展信息：不触发错误，也不能挽救正式 null ---

func TestParseAuditArtifactVariantNamesIgnored(t *testing.T) {
	// 正式成员省略，变体携带字符串：只是扩展信息，字段仍取默认空值。
	variantSupplies := `{"artifact":{"name":"Vault","Source":"file.sol"," ABI ":"a"},"rules":[]}`
	got := strictParsedReport(t, variantSupplies)
	plain := strictParsedReport(t, `{"artifact":{"name":"Vault"},"rules":[]}`)
	if got.ReportID != plain.ReportID {
		t.Fatalf("a variant-named member must not supply a formal field:\n got %s\nwant %s",
			got.ReportID, plain.ReportID)
	}

	// 变体携带 null：只是扩展信息，不触发类型错误。
	variantNull := `{"artifact":{"name":"Vault","Source":null," ABI ":null},"rules":[]}`
	if _, _, _, _, err := ParseAuditInput([]byte(variantNull)); err != nil {
		t.Fatalf("null under a variant name is extension data and must be ignored: %v", err)
	}

	// 正式 source 为 null，变体携带合法字符串（位于其前或其后）都不能挽救。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			var artifact string
			if pos == "before" {
				artifact = `{"Source":"file.sol","source":null}`
			} else {
				artifact = `{"source":null,"Source":"file.sol"}`
			}
			in := `{"artifact":` + artifact + `,"rules":[]}`
			_, _, _, _, err := ParseAuditInput([]byte(in))
			if err == nil || !strings.Contains(err.Error(), "artifact.source must be a string") {
				t.Fatalf("a variant member must not rescue a null formal source: %v", err)
			}
		})
	}

	// 带首尾空格的名称同样不能挽救。
	padded := `{"artifact":{"name":"Vault"," source ":"x","source":null},"rules":[]}`
	if _, _, _, _, err := ParseAuditInput([]byte(padded)); err == nil ||
		!strings.Contains(err.Error(), "artifact.source must be a string") {
		t.Fatalf("a whitespace-padded variant must not rescue the formal null: %v", err)
	}
}

// --- Unicode 转义写出的正式名称遵守同一字符串规则 ---

func TestParseAuditEscapedArtifactNameFollowsSameRule(t *testing.T) {
	// 字段名 "source" 用 Unicode 转义写出（s 的码位是 0x73）。转义在运行期
	// 拼接，使提交给解析器的字节确实携带 JSON 转义写法，解码后名称等于
	// source：null 同样整份拒绝。
	escName := "\\" + "u0073" + "ource"
	plainNull := artifactFieldsDoc(`"name":"Vault"`, `"abi":"","bytecode":"","source":null`, "")
	escapedNull := strings.Replace(plainNull, `"source":null`, `"`+escName+`":null`, 1)
	if !strings.Contains(escapedNull, `\`+"u0073ource") {
		t.Fatalf("test setup must carry the JSON escape, got %s", escapedNull)
	}
	if _, _, _, _, err := ParseAuditInput([]byte(escapedNull)); err == nil ||
		!strings.Contains(err.Error(), "artifact.source must be a string") {
		t.Fatalf("an escaped formal name with null must reject like the plain spelling: %v", err)
	}

	// 转义写法携带合法字符串时，与直接书写的产物哈希与报告标识一致。
	plainLegal := artifactFieldsDoc(`"name":"Vault"`, `"abi":"a","bytecode":"b","source":"s"`, artifactTextRule)
	escaped := strings.Replace(plainLegal, `"source":"s"`, `"`+escName+`":"s"`, 1)
	rEscaped := strictParsedReport(t, escaped)
	rPlain := strictParsedReport(t, plainLegal)
	if rEscaped.ReportID != rPlain.ReportID || rEscaped.Artifact.Hash != rPlain.Artifact.Hash {
		t.Fatalf("escaped and plain spellings must share report id and hash:\n%s\n%s",
			rEscaped.ReportID, rPlain.ReportID)
	}
}

// --- 合法字符串逐字保留：中文、换行与前后空格，source 是文本而非文件名 ---

func TestParseAuditLegalArtifactStringsPreserved(t *testing.T) {
	// source 即便长得像文件名，也只作为提交文本参与哈希，绝不按文件读取。
	source := "  contract 金库 {\n // 中文注释 \n}\t"
	abi := " [ { \"name\" : \"取款\" } ] "
	bytecode := "  0x6080\n6040  "
	in := artifactFieldsDoc(`"name":" 金库 Vault "`,
		`"abi":`+jsonString(abi)+`,"bytecode":`+jsonString(bytecode)+`,"source":`+jsonString(source),
		"")
	artifact, _, _, _, err := ParseAuditInput([]byte(in))
	if err != nil {
		t.Fatalf("a legal submission with multilingual/whitespace text must parse: %v", err)
	}
	if artifact.Name != " 金库 Vault " || artifact.ABI != abi ||
		artifact.Bytecode != bytecode || artifact.Source != source {
		t.Fatalf("artifact text must be preserved verbatim:\n%+v", artifact)
	}

	// 哈希与报告标识相对同样 Go 字段直接构造的结果保持原有值。
	direct := Artifact{Name: " 金库 Vault ", ABI: abi, Bytecode: bytecode, Source: source}
	if ArtifactHash(artifact) != ArtifactHash(direct) {
		t.Fatal("the parsed artifact must hash exactly like the directly constructed one")
	}
	report := strictParsedReport(t, in)
	if report.Artifact.Hash != ArtifactHash(direct) {
		t.Fatalf("report must bind the original hash: %q", report.Artifact.Hash)
	}
}

// --- 缺失或 null 的 artifact 对象沿用既有“artifact name is required”判断 ---

func TestParseAuditMissingArtifactObjectKeepsBusinessError(t *testing.T) {
	for _, in := range []string{
		`{"rules":[]}`,
		`{"artifact":null,"rules":[]}`,
	} {
		a, rules, inv, checks, err := ParseAuditInput([]byte(in))
		if err != nil {
			t.Fatalf("a missing/null artifact object parses with defaults as before: %v", err)
		}
		if _, err := BuildReport(a, rules, inv, checks); err == nil ||
			!strings.Contains(err.Error(), "artifact name is required") {
			t.Fatalf("missing artifact must keep the existing required-name error: %v", err)
		}
	}
}
