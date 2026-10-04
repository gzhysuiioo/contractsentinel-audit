package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交的“字符合法性”闸门：编码/解码会把非法 UTF-8 字节与
// 未配对的代理转义静默改写成 U+FFFD，因此整份提交必须在解码之前被拒绝，
// 不能删除坏字符、替换后继续，也不能把输入问题登记成合约缺陷。检查覆盖
// 成员名称和字符串值，异常只出现在未知扩展成员的嵌套内容里也不例外。
// 合法字符（中文、换行、前后空格、成对代理转义、直接书写的同一字符、原文
// 中的 U+FFFD、转义反斜线后的 uD800 文本）保持兼容。

// charArtifact 是本文件用例共享的产物；charDoc 以固定产物/规则/一条缺陷
// 检查拼装提交，noteJSON 是 note 字段值的原始 JSON 文本（可含转义）。
func charArtifact() Artifact {
	return Artifact{Name: "Vault", ABI: "abi", Bytecode: "0x1", Source: "Vault.sol"}
}

func charDoc(noteJSON string) string {
	return `{` +
		`"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},` +
		`"rules":[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}],` +
		`"invariants":{},` +
		`"checks":[{"artifactHash":"","ruleId":"r1","version":"1.0.0","status":"发现缺陷","note":` + noteJSON + `}]` +
		`}`
}

// charParsed 解析并构建一份 note 提交（哈希在构建时不参与解析，仅在
// BuildReport 校验，所以解析阶段用空占位哈希即可覆盖字符闸门）。
func charParsed(t *testing.T, doc string) (Artifact, []Rule, map[string]bool, []CheckRecord) {
	t.Helper()
	a, rules, inv, checks, err := ParseAuditInput([]byte(doc))
	if err != nil {
		t.Fatalf("legal submission must parse: %v\ninput: %s", err, doc)
	}
	return a, rules, inv, checks
}

func mustRejectChar(t *testing.T, doc string, wantFragment string) {
	t.Helper()
	_, _, _, _, err := ParseAuditInput([]byte(doc))
	if err == nil {
		t.Fatalf("illegal characters must reject the whole submission:\n%s", doc)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("rejection must be errInvalid, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), wantFragment) {
		t.Fatalf("error %q must classify/locate via %q", err.Error(), wantFragment)
	}
}

// --- 代理转义：孤立高、孤立低、反向成对、高后非低、高后另一个高、串尾高 ---

func TestValidateRejectsLoneHighSurrogate(t *testing.T) {
	mustRejectChar(t, charDoc(`"a\uD800b"`), "Unicode escape")
}

func TestValidateRejectsLoneLowSurrogate(t *testing.T) {
	mustRejectChar(t, charDoc(`"a\uDC00b"`), "lone low surrogate")
}

func TestValidateRejectsReversedSurrogatePair(t *testing.T) {
	mustRejectChar(t, charDoc(`"\uDC00\uD800"`), "lone low surrogate")
}

func TestValidateRejectsHighSurrogateFollowedByEscape(t *testing.T) {
	mustRejectChar(t, charDoc(`"\uD800\n"`), "lone high surrogate")
}

func TestValidateRejectsHighSurrogateFollowedByAnotherHigh(t *testing.T) {
	mustRejectChar(t, charDoc(`"\uD800\uD801"`), "lone high surrogate")
}

func TestValidateRejectsHighSurrogateAtStringEnd(t *testing.T) {
	mustRejectChar(t, charDoc(`"x\uD800"`), "lone high surrogate")
}

// --- 非法 UTF-8：字符串值、源码、成员名称 ---

func TestValidateRejectsInvalidUTF8InNote(t *testing.T) {
	doc := []byte(charDoc(`"a` + "\xFF" + `b"`))
	mustRejectChar(t, string(doc), "invalid UTF-8 encoding")
}

func TestValidateRejectsInvalidUTF8InSource(t *testing.T) {
	doc := []byte(strings.Replace(charDoc(`"ce"`), `"source":"Vault.sol"`,
		`"source":"a`+"\xFF"+`b"`, 1))
	mustRejectChar(t, string(doc), "invalid UTF-8 encoding")
}

func TestValidateRejectsSurrogateInMemberName(t *testing.T) {
	doc := charDoc(`"ce"`)
	doc = doc[:len(doc)-1] + `,"bad\uD800name":1}`
	mustRejectChar(t, doc, "Unicode escape")
}

func TestValidateRejectsInvalidUTF8InMemberName(t *testing.T) {
	doc := []byte(charDoc(`"ce"`))
	doc = append(doc[:len(doc)-1], []byte(`,"bad`+"\xFF"+`name":1}`)...)
	mustRejectChar(t, string(doc), "invalid UTF-8 encoding")
}

// --- 未知扩展成员及其嵌套内容：即使不参与报告也不放行 ---

func TestValidateRejectsSurrogateInsideExtension(t *testing.T) {
	doc := charDoc(`"ce"`)
	doc = doc[:len(doc)-1] + `,"mystery":{"nested":["x\uD800"]}}`
	mustRejectChar(t, doc, "Unicode escape")
}

func TestValidateRejectsInvalidUTF8InsideExtension(t *testing.T) {
	doc := []byte(charDoc(`"ce"`))
	doc = append(doc[:len(doc)-1], []byte(`,"mystery":{"nested":["x`+"\xFF"+`"]}}`)...)
	mustRejectChar(t, string(doc), "invalid UTF-8 encoding")
}

func TestValidateRejectsSurrogateInInvariantName(t *testing.T) {
	doc := `{"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},` +
		`"rules":[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}],` +
		`"invariants":{"inv\uD800":false}}`
	mustRejectChar(t, doc, "Unicode escape")
}

// --- 出错位置必须可辨：行、列、字节偏移都给出 ---

func TestValidateErrorGivesLocation(t *testing.T) {
	// 多行提交，第二行 note 中含孤立高代理；错误点名第二行、且给字节偏移。
	lines := []string{
		`{`,
		`  "artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},`,
		`  "rules":[{"id":"r1","version":"1.0.0","kind":"static","severity":"high","invariant":"inv","requiresABI":false}],`,
		`  "invariants":{},`,
		`  "checks":[{"ruleId":"r1","version":"1.0.0","status":"发现缺陷","note":"x\uD800"}]`,
		`}`,
	}
	doc := strings.Join(lines, "\n")
	_, _, _, _, err := ParseAuditInput([]byte(doc))
	if err == nil {
		t.Fatal("lone surrogate must reject")
	}
	msg := err.Error()
	for _, frag := range []string{"line 5", "column ", "byte offset ", "Unicode escape"} {
		if !strings.Contains(msg, frag) {
			t.Fatalf("error %q must contain %q", msg, frag)
		}
	}
}

// --- 整份失败：无任何部分数据返回，合法的其它记录不改变失败结论 ---

func TestValidateRejectionReturnsNoPartialData(t *testing.T) {
	doc := charDoc(`"a\uD800b"`)
	a, rules, inv, checks, err := ParseAuditInput([]byte(doc))
	if err == nil {
		t.Fatal("must reject")
	}
	if a != (Artifact{}) || rules != nil || inv != nil || checks != nil {
		t.Fatalf("rejection must return no partial data: %+v %+v %+v %+v", a, rules, inv, checks)
	}
}

// --- 语法错误仍按 JSON 语法问题报错，字符扫描不得 panic 或误分类 ---

func TestValidateDoesNotMaskSyntaxErrors(t *testing.T) {
	for _, bad := range []string{`{"a":}`, `{"a"`, `{"a":"x"`, `not json`, `{"a":"x",}`} {
		if _, _, _, _, err := ParseAuditInput([]byte(bad)); err == nil {
			t.Fatalf("malformed JSON must be rejected: %q", bad)
		}
	}
}

// --- 合法字符兼容：中文、换行、前后空格、成对代理、直接 U+FFFD、字面 uD800 ---

func TestValidateLegalCharactersAccepted(t *testing.T) {
	// 原文直接书写的 U+FFFD 是普通字符；"\\uD800" 是反斜线后跟 uD800 的
	// 普通文本，两者都不能被误判为孤立代理项。
	wantNotes := map[string]string{
		`"反例：攻击者重入\n第二行"`:           "反例：攻击者重入\n第二行",
		`"  前后空格  "`:                "  前后空格  ",
		`"普通替换字符 � 保留"`:             "普通替换字符 � 保留",
		`"路径 C:\\uD800 文本"`:         `路径 C:\uD800 文本`,
		`"成对代理 -> \uD83D\uDE00 结束"`: "成对代理 -> 😀 结束",
		`"直接字符 -> 😀 结束"`:            "直接字符 -> 😀 结束",
	}
	for noteJSON, wantNote := range wantNotes {
		_, _, _, checks := charParsed(t, charDoc(noteJSON))
		if len(checks) != 1 || checks[0].Note != wantNote {
			t.Fatalf("note %s decoded to %v, want %q", noteJSON, checks, wantNote)
		}
	}
}

// --- note/evidence 保留解码后的原文：成对代理与直接书写解码为同一字符 ---

func TestValidatePairedSurrogateDecodesAndIsPreserved(t *testing.T) {
	_, _, _, esc := charParsed(t, charDoc(`"证据 \uD83D\uDE00 结束"`))
	_, _, _, raw := charParsed(t, charDoc(`"证据 😀 结束"`))
	const want = "证据 😀 结束"
	if esc[0].Note != want {
		t.Fatalf("paired escape decoded note = %q, want %q", esc[0].Note, want)
	}
	if raw[0].Note != want {
		t.Fatalf("direct char note = %q, want %q", raw[0].Note, want)
	}
	if esc[0].Note != raw[0].Note {
		t.Fatalf("paired escape and direct char must decode to the same string: %q vs %q", esc[0].Note, raw[0].Note)
	}
}

// --- 直接书写与合法转义表示相同 source 时，产物哈希一致；报告标识一致 ---

func TestValidateEscapeAndDirectHaveSameHashAndReportID(t *testing.T) {
	artifact := charArtifact()
	hash := ArtifactHash(artifact)

	build := func(note string) Report {
		a := artifact
		rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", RequiresABI: false, Version: "1.0.0"}}
		checks := []CheckRecord{{ArtifactHash: hash, RuleID: "r1", Version: "1.0.0", Status: StatusDefect, Note: note}}
		r, err := BuildReport(a, rules, map[string]bool{}, checks)
		if err != nil {
			t.Fatalf("BuildReport: %v", err)
		}
		return r
	}
	viaEscape := build("证据 😀 结束") // 提交里写成 \uD83D\uDE00
	viaDirect := build("证据 😀 结束")
	if viaEscape.Artifact.Hash != viaDirect.Artifact.Hash {
		t.Fatal("artifact hash must be identical for equal decoded content")
	}
	if viaEscape.ReportID != viaDirect.ReportID {
		t.Fatalf("report id must be identical:\n esc=%s\n raw=%s", viaEscape.ReportID, viaDirect.ReportID)
	}
	if viaEscape.Findings[0].Evidence != viaDirect.Findings[0].Evidence {
		t.Fatal("evidence must be identical after decoding")
	}
}
