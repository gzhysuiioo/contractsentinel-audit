package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 audit 的“字符合法性”闸门：提交
// JSON 含有非法 UTF-8 字节，或字符串中的 Unicode 转义含有未配对/反向的
// 代理项时，命令必须以非零状态退出、原因（字符编码或 Unicode 转义问题）与
// 出错位置进 stderr、stdout 为空，且不创建报告目录、不留临时文件、不改写
// 已有报告。异常即使只出现在未知扩展成员的嵌套内容里也一样拒绝。合法字符
// （成对代理转义与直接书写的同一字符、原文中的 U+FFFD、字面 uD800 文本）
// 继续成功且报告标识一致。

// cliCharDoc 以固定产物/规则拼装一条绑定正确哈希的“发现缺陷”提交；
// noteToken 是 note 值的原始 JSON 文本（可含 \u 转义）。
func cliCharDoc(t *testing.T, noteToken string) string {
	t.Helper()
	a := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	check := "{" +
		`"artifactHash":"` + hash + `",` +
		`"ruleId":"r1","version":"1.0.0",` +
		`"status":"` + contractsentinel.StatusDefect + `",` +
		`"note":` + noteToken + "}"
	artifact := `{"name":"Vault","abi":` + jsonString(a.ABI) +
		`,"bytecode":` + jsonString(a.Bytecode) + `,"source":` + jsonString(a.Source) + `}`
	rule := `{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}`
	return `{"artifact":` + artifact + `,"rules":[` + rule + `],"invariants":{},"checks":[` + check + `]}`
}

// writeBytesInput stores raw submission bytes (used for illegal UTF-8).
func writeBytesInput(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// auditMustRejectBadChars asserts the full failure contract for a character
// problem and that no store directory or files appear.
func auditMustRejectBadChars(t *testing.T, bin, input, store string, wantStderr ...string) {
	t.Helper()
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("a submission with illegal characters must exit non-zero")
	}
	for _, want := range wantStderr {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must contain %q:\n%s", want, stderr)
		}
	}
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the report store: %v", err)
	}
}

// --- note 含孤立高代理转义：拒绝、定位、不落盘 ---

func TestCLIAuditLoneSurrogateInNoteRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "bad.json", cliCharDoc(t, `"反例 a\uD800b 结束"`))
	store := filepath.Join(work, "nested", "missing-store")

	auditMustRejectBadChars(t, bin, input, store,
		"invalid JSON", "Unicode escape", "lone high surrogate", "line ", "column ", "byte offset ")
}

// --- note 含孤立低代理/反向成对：拒绝 ---

func TestCLIAuditLoneLowAndReversedSurrogateRejected(t *testing.T) {
	bin := auditBinary(t)
	for _, tc := range []struct {
		name     string
		token    string
		fragment string
	}{
		{"lone low", `"a\uDC00b"`, "lone low surrogate"},
		{"reversed pair", `"\uDC00\uD800"`, "lone low surrogate"},
		{"high then high", `"\uD800\uD801"`, "lone high surrogate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			input := writeInput(t, work, "bad.json", cliCharDoc(t, tc.token))
			store := filepath.Join(work, "missing-store")
			auditMustRejectBadChars(t, bin, input, store, "Unicode escape", tc.fragment)
		})
	}
}

// --- 文件含非法 UTF-8 字节（note 与 source）：拒绝、按编码问题定位 ---

func TestCLIAuditInvalidUTF8Rejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	raw := []byte(cliCharDoc(t, `"a b"`))
	// 把 note 里的普通字节替换成非法 UTF-8 字节 0xFF。
	needle := []byte(`:"a b"`)
	idx := bytes.Index(raw, needle)
	if idx < 0 {
		t.Fatal("placeholder not found")
	}
	raw[idx+3] = 0xFF
	input := writeBytesInput(t, work, "bad.json", raw)
	store := filepath.Join(work, "missing-store")

	auditMustRejectBadChars(t, bin, input, store,
		"invalid JSON", "invalid UTF-8 encoding", "line ", "column ", "byte offset ", "0xFF")
}

func TestCLIAuditInvalidUTF8InSourceRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	// 直接构造：source 字符串里夹一个 0xFF；note 合法。
	artifact := []byte(`{"name":"Vault","abi":"abi","bytecode":"0x1","source":"s` + "\xFF" + `c"}`)
	rule := `{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}`
	doc := append([]byte(`{"artifact":`), artifact...)
	doc = append(doc, []byte(`,"rules":[`+rule+`],"invariants":{},"checks":[]}`)...)
	input := writeBytesInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "missing-store")

	auditMustRejectBadChars(t, bin, input, store, "invalid UTF-8 encoding", "byte offset ")
}

// --- 异常只出现在未知扩展成员的嵌套内容里：仍然拒绝 ---

func TestCLIAuditSurrogateInsideExtensionRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	doc := cliCharDoc(t, `"ce"`)
	doc = doc[:len(doc)-1] + `,"mystery":{"nested":["x\uD800"]}}`
	input := writeInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "missing-store")

	auditMustRejectBadChars(t, bin, input, store, "Unicode escape", "lone high surrogate")
}

// --- 成员名称含孤立代理：拒绝 ---

func TestCLIAuditSurrogateInMemberNameRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	doc := cliCharDoc(t, `"ce"`)
	doc = doc[:len(doc)-1] + `,"bad\uD800name":1}`
	input := writeInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "missing-store")

	auditMustRejectBadChars(t, bin, input, store, "Unicode escape", "lone high surrogate")
}

// --- 拒绝提交不改写已有报告、不留临时文件 ---

func TestCLIAuditBadCharsKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	// 先落一份完全合法的报告。
	good := writeStructInput(t, work, "good.json", mixedCheckInput(mixedArtifactHash(t)))
	if _, stderr, code := runCLIAudit(t, bin, good, store); code != 0 {
		t.Fatalf("valid setup audit must succeed: %s", stderr)
	}
	before, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("setup expected 1 report, got %v", before)
	}
	existing := filepath.Join(store, before[0])
	existingBytes, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}

	// 再提交一份带孤立代理的提交，必须失败。
	bad := writeInput(t, work, "bad.json", cliCharDoc(t, `"x\uD800"`))
	if _, _, code := runCLIAudit(t, bin, bad, store); code == 0 {
		t.Fatal("illegal-character submission must exit non-zero")
	}

	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0] != before[0] {
		t.Fatalf("rejected submission changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("rejected submission modified the existing report bytes")
	}
	if entries, err := os.ReadDir(store); err != nil || len(entries) != 1 {
		t.Fatalf("no temporary files may remain: %v %v", entries, err)
	}
}

// --- 合法兼容：成对代理转义与直接书写同一字符都成功，且报告标识一致 ---

func TestCLIAuditLegalSurrogateFormsSucceedAndAgree(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	escInput := writeInput(t, work, "esc.json", cliCharDoc(t, `"证据 \uD83D\uDE00 结束"`))
	rawInput := writeInput(t, work, "raw.json", cliCharDoc(t, `"证据 😀 结束"`))

	stdout1, stderr1, code1 := runCLIAudit(t, bin, escInput, filepath.Join(work, "store1"))
	if code1 != 0 {
		t.Fatalf("paired surrogate escapes must succeed: %s", stderr1)
	}
	stdout2, stderr2, code2 := runCLIAudit(t, bin, rawInput, filepath.Join(work, "store2"))
	if code2 != 0 {
		t.Fatalf("a directly written supplementary character must succeed: %s", stderr2)
	}

	r1 := decodeReport(t, stdout1)
	r2 := decodeReport(t, stdout2)
	if r1.ReportID != r2.ReportID {
		t.Fatalf("escaped and direct forms must share a report id:\n esc=%s\n raw=%s", r1.ReportID, r2.ReportID)
	}
	if r1.Findings[0].Evidence != "证据 😀 结束" {
		t.Fatalf("evidence must preserve the decoded original text: %q", r1.Findings[0].Evidence)
	}
}

// --- 合法兼容：原文直接书写 U+FFFD 与字面 \uD800 文本都成功并保留 ---

func TestCLIAuditLiteralReplacementAndEscapedBackslashSucceed(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	for _, tc := range []struct {
		name  string
		token string
		want  string
	}{
		{"direct replacement char", `"含 � 字符"`, "含 � 字符"},
		{"literal backslash uD800", `"路径 \\uD800 文本"`, `路径 \uD800 文本`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := writeInput(t, work, tc.name+".json", cliCharDoc(t, tc.token))
			stdout, stderr, code := runCLIAudit(t, bin, input, filepath.Join(work, "store-"+tc.name))
			if code != 0 {
				t.Fatalf("legal content must succeed: %s", stderr)
			}
			r := decodeReport(t, stdout)
			if r.Findings[0].Evidence != tc.want {
				t.Fatalf("evidence = %q, want %q", r.Findings[0].Evidence, tc.want)
			}
		})
	}
}
