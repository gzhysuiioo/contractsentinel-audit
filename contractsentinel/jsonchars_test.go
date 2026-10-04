package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交对“字符合法性”的整体拒绝，堵住 encoding/json 的两处
// 静默改写：
//   - 字符串内的非法 UTF-8 字节被解码成 U+FFFD；
//   - JSON Unicode 转义里未配对的高/低代理项、低代理项在前的错误配对顺序也被
//     解码成 U+FFFD。
//
// 任何成员名称或字符串值（含未知扩展成员的嵌套内容）出现这两类问题都必须整份
// 拒绝，并指出字节偏移、行列与 JSON 路径；合法字符（中文、换行、前后空格、正确
// 成对的代理转义、直接书写的同一字符、原文中的 U+FFFD、转义反斜线后的 uD800
// 文本）行为完全不变。

// --- 扫描器：合法输入一律放行 ---

func TestValidateCharsLegalInputs(t *testing.T) {
	legal := []string{
		// 中文、换行、前后空格。
		`{"note":"  反例：攻击者可重入\n第二行  "}`,
		// 正确成对的代理转义（😀）与同一字符的直接 UTF-8 书写。
		`{"a":"\uD83D\uDE00"}`,
		`{"a":"😀"}`,
		// 成对转义前后还可以接普通字符与另一对。
		`{"a":"x\uD83D\uDE00y\uD83D\uDE00z"}`,
		`{"a":"\uD83D\uDE00A"}`,
		// 成员名称里使用成对转义。
		`{"\uD83D\uDE00":1}`,
		// 原文中合法存在的 U+FFFD 只是普通字符。
		`{"a":"含替换字符 � 结尾"}`,
		// 转义反斜线之后跟 uD800 只是普通文本：JSON 体为 \\uD800。
		`{"a":"\\uD800"}`,
		`{"a":"c:\\temp\\uD800\\uD83D\\uDE00"}`,
		// 非字符串标量、数组、深层嵌套都不受影响。
		`{"n":123,"t":true,"f":false,"z":null,"arr":[1,2,3]}`,
		`{"x":{"y":[{"z":[true,null,"深"]}]}}`,
		`["数组里的中文",1]`,
		`"顶层字符串"`,
		`123`,
	}
	for _, in := range legal {
		if e := validateJSONCharacters([]byte(in)); e != nil {
			t.Errorf("legal input rejected: %s\nerr=%v", in, e)
		}
	}
}

// --- 扫描器：未配对/错序代理转义一律拒绝 ---

func TestValidateCharsLoneSurrogatesRejected(t *testing.T) {
	cases := map[string]string{
		"lone high":        `{"a":"x\uD800y"}`,
		"lone low":         `{"a":"x\uDC00y"}`,
		"low before high":  `{"a":"\uDC00\uD800"}`,
		"high then bmp":    `{"a":"\uD800A"}`,
		"high then high":   `{"a":"\uD800\uD800"}`,
		"high at end":      `{"a":"end\uD800"}`,
		"low at start":     `{"a":"\uDE03x"}`,
		"high then plain":  `{"a":"\uD83Dx"}`,
		"pair then lone":   `{"a":"\uD83D\uDE00\uD800"}`,
		"lone in name":     `{"\uD800":1}`,
		"low in name":      `{"x\uDC00":1}`,
		"lone in array":    `["\uD800"]`,
		"nested in ext":    `{"mystery":{"deep":[{"note":"\uD800"}]}}`,
		"top-level string": `"\uDC00"`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			e := validateJSONCharacters([]byte(in))
			if e == nil {
				t.Fatalf("surrogate problem must be rejected: %s", in)
			}
			if e.kind != charKindEscape {
				t.Fatalf("kind = %q, want %q: %v", e.kind, charKindEscape, e)
			}
			if !strings.Contains(e.Error(), "surrogate escape") {
				t.Fatalf("error must name the surrogate escape: %v", e)
			}
		})
	}
}

// --- 扫描器：非法 UTF-8 字节一律拒绝，覆盖值、成员名和字符串外空白 ---

func TestValidateCharsInvalidUTF8Rejected(t *testing.T) {
	cases := []struct {
		name      string
		data      []byte
		wantWhere string
	}{
		{"byte in value", []byte("{\"a\":\"x\xFFy\"}"), "string value"},
		{"byte in member name", []byte("{\"a\xFF\":1}"), "member name"},
		{"overlong ed a0 80", []byte("{\"a\":\"\xED\xA0\x80\"}"), "string value"},
		{"byte outside strings", []byte("  \xFF  {}"), "input"},
		{"byte in array string", []byte("[\"\xFF\"]"), "string value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validateJSONCharacters(tc.data)
			if e == nil {
				t.Fatalf("invalid UTF-8 must be rejected: % x", tc.data)
			}
			if e.kind != charKindEncoding {
				t.Fatalf("kind = %q, want %q: %v", e.kind, charKindEncoding, e)
			}
			if e.where != tc.wantWhere {
				t.Fatalf("where = %q, want %q: %v", e.where, tc.wantWhere, e)
			}
			if !strings.Contains(e.Error(), "UTF-8") {
				t.Fatalf("error must state the UTF-8 problem: %v", e)
			}
		})
	}
}

// --- 位置信息：行列、字节偏移与 JSON 路径必须可用于修正原内容 ---

func TestValidateCharsSurrogatePosition(t *testing.T) {
	in := []byte("{\n  \"checks\": [\n    {\"note\": \"x\\uD800y\"}\n  ]\n}")
	e := validateJSONCharacters(in)
	if e == nil {
		t.Fatal("lone surrogate must be rejected")
	}
	if e.line != 3 || e.column != 16 {
		t.Fatalf("position = line %d col %d, want 3:16", e.line, e.column)
	}
	// 偏移必须正好指向逃逸的反斜线。
	if in[e.offset] != '\\' {
		t.Fatalf("offset %d must point at the escape backslash, got %q", e.offset, in[e.offset])
	}
	msg := e.Error()
	for _, want := range []string{"byte offset", "line 3", "column 16", ".checks[0].note", "string value"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
}

func TestValidateCharsMemberNamePathStopsAtParent(t *testing.T) {
	// 坏名称本身无法逐字渲染，路径定位到包含它的对象即可。
	e := validateJSONCharacters([]byte(`{"outer":{"x\uD800":1}}`))
	if e == nil {
		t.Fatal("lone surrogate in a nested member name must be rejected")
	}
	if !strings.Contains(e.Error(), "member name") || !strings.Contains(e.Error(), ".outer") {
		t.Fatalf("error must identify the member name and parent object: %v", e)
	}
}

// --- 语法错误交给 json.Unmarshal：扫描器不臆造字符错误 ---

func TestValidateCharsMalformedJSONDefers(t *testing.T) {
	for _, in := range []string{
		``, `{`, `{"a":1 "b":2}`, `{"a":`, `{"a":"\uZZZZ"}`, `{"a":"\q"}`,
		`{"a":"trailing backslash\}`,
	} {
		if e := validateJSONCharacters([]byte(in)); e != nil {
			t.Errorf("malformed JSON %q must defer to json.Unmarshal, got %v", in, e)
		}
	}
}

// --- ParseAuditInput：字符问题是提交输入错误，且无任何部分数据 ---

func charSubmission(noteJSON string) []byte {
	return []byte(`{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1.0.0"}],
		"checks": [{"ruleId":"r1","version":"1.0.0","status":"通过","note":` + noteJSON + `}]
	}`)
}

func expectCharRejection(t *testing.T, data []byte, wantSubstrings ...string) {
	t.Helper()
	artifact, rules, invariants, checks, err := ParseAuditInput(data)
	if err == nil {
		t.Fatalf("illegal characters must reject the submission: %s", data)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("rejection must be errInvalid (input error), got %T: %v", err, err)
	}
	msg := err.Error()
	for _, want := range wantSubstrings {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
	if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
		t.Fatalf("failure must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
	}
}

func TestParseAuditLoneSurrogateInNoteRejected(t *testing.T) {
	// 一条绑定正确哈希与版本、结论为“发现缺陷”的记录，仅 note 带孤立高代理项。
	good := Artifact{Name: "Vault", ABI: "abi", Bytecode: "0x1", Source: "Vault.sol"}
	hash := ArtifactHash(good)
	in := []byte(`{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1.0.0"}],
		"checks": [{"artifactHash":"` + hash + `","ruleId":"r1","version":"1.0.0","status":"发现缺陷","note":"反例\uD800重入"}]
	}`)
	expectCharRejection(t, in, "invalid Unicode escape", "surrogate", "note", "byte offset")
}

func TestParseAuditLoneSurrogateInUnknownExtensionRejected(t *testing.T) {
	// 异常只出现在不参与报告的未知扩展成员的深层嵌套内容里，也不能放行。
	in := []byte(`{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1.0.0"}],
		"mystery": {"nested": [{"deep": "x\uDC00y"}]}
	}`)
	expectCharRejection(t, in, "invalid Unicode escape", "surrogate", ".mystery.nested[0].deep")
}

func TestParseAuditInvalidUTF8InSourceRejected(t *testing.T) {
	// 源码字符串的字节被改写会改变产物哈希的计算内容，必须在哈希前拒绝。
	// 用双引号字符串拼入真正的 0xFF 字节，而非反引号文本里的 "\xFF"。
	in := []byte(`{"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","source":"x` + "\xFF" + `y"},"rules":[]}`)
	expectCharRejection(t, in, "invalid character encoding", "UTF-8", "source")
}

func TestParseAuditInvalidUTF8InMemberNameRejected(t *testing.T) {
	in := []byte(`{"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","source":"s"},"rules":[],"no` + "\xFF" + `te":1}`)
	expectCharRejection(t, in, "invalid character encoding", "member name")
}

func TestParseAuditLoneSurrogateInRuleIDRejected(t *testing.T) {
	// 正式字段的字符串值同样受检。
	in := []byte(`{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"s"},
		"rules": [{"id":"r\uD8001","kind":"static","severity":"high","invariant":"i","version":"1"}]
	}`)
	expectCharRejection(t, in, "invalid Unicode escape", "surrogate")
}

// 字符问题先于重复成员与字段校验：既有字符问题又有其他问题时，报的是字符问题。
func TestParseAuditCharErrorTakesPrecedence(t *testing.T) {
	in := []byte(`{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"s"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"i","version":"1"}],
		"checks": [{"ruleId":"r1","ruleId":"r1","status":"通过","note":"x\uD800y"}]
	}`)
	_, _, _, _, err := ParseAuditInput(in)
	if err == nil {
		t.Fatal("submission must be rejected")
	}
	if !strings.Contains(err.Error(), "Unicode") {
		t.Fatalf("character error must surface before the duplicate-member error: %v", err)
	}
}

// --- 兼容：合法字符的解码、保留与直接/转义等价 ---

func TestParseAuditLegalCharactersPreserved(t *testing.T) {
	const note = "  反例：攻击者可在 withdraw 中重入\n第二行证据  "
	in := charSubmission(`"  反例：攻击者可在 withdraw 中重入\n第二行证据  "`)
	artifact, _, _, checks, err := ParseAuditInput(in)
	if err != nil {
		t.Fatalf("legal note must parse: %v", err)
	}
	if checks[0].Note != note {
		t.Fatalf("decoded note = %q, want %q", checks[0].Note, note)
	}
	if strings.ContainsRune(checks[0].Note, '\uFFFD') {
		t.Fatal("legal note must not acquire replacement characters")
	}
	_ = artifact
}

// 直接书写与合法代理转义表示相同字符串时，产物哈希与报告标识必须一致。
func TestParseAuditDirectAndEscapedSameStringSameIdentity(t *testing.T) {
	// 缺陷由不变式 false 产生，避免检查记录的哈希绑定干扰；这里要锁定的是
	// “同一逻辑字符串的两种写法解码后完全等价”。
	mk := func(sourceJSON string) []byte {
		return []byte(`{
			"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":` + sourceJSON + `},
			"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1.0.0"}],
			"invariants": {"inv": false}
		}`)
	}
	// 同一源码内容：一次直接写 😀，一次写成代理对转义。
	direct := mk(`"contract Vault {😀}"`)
	escaped := mk(`"contract Vault {\uD83D\uDE00}"`)

	a1, r1, i1, c1, err := ParseAuditInput(direct)
	if err != nil {
		t.Fatalf("direct form must parse: %v", err)
	}
	a2, r2, i2, c2, err := ParseAuditInput(escaped)
	if err != nil {
		t.Fatalf("escaped form must parse: %v", err)
	}
	if a1.Source != a2.Source {
		t.Fatalf("decoded sources differ: %q vs %q", a1.Source, a2.Source)
	}
	if ArtifactHash(a1) != ArtifactHash(a2) {
		t.Fatalf("artifact hash changed with the representation:\n%q\n%q", ArtifactHash(a1), ArtifactHash(a2))
	}
	rep1, err := BuildReport(a1, r1, i1, c1)
	if err != nil {
		t.Fatal(err)
	}
	rep2, err := BuildReport(a2, r2, i2, c2)
	if err != nil {
		t.Fatal(err)
	}
	if rep1.ReportID != rep2.ReportID {
		t.Fatalf("report id changed with the representation:\n%s\n%s", rep1.ReportID, rep2.ReportID)
	}
	if len(rep1.Findings) != 1 || rep1.Findings[0].ArtifactHash != ArtifactHash(a1) {
		t.Fatalf("finding must bind to the shared artifact hash: %+v", rep1.Findings)
	}
}

// 原文中合法的 U+FFFD 与“转义反斜线 + uD800 文本”都不得被误判。
func TestParseAuditLiteralReplacementAndEscapedBackslashAccepted(t *testing.T) {
	for _, noteJSON := range []string{
		`"原有替换字符 � 保留"`,        // 直接书写的 U+FFFD
		`"路径 C:\\uD800\\note"`, // JSON 体为 \\uD800，即反斜线加普通文本
	} {
		in := charSubmission(noteJSON)
		if _, _, _, _, err := ParseAuditInput(in); err != nil {
			t.Errorf("ordinary-U+FFFD/escaped-backslash input must stay legal: %v\ninput=%s", err, in)
		}
	}
}
