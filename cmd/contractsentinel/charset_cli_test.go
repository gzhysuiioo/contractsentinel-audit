package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归 audit 提交的字符合法性拒绝：
// JSON 字符串里的非法 UTF-8 字节、未配对或错序的 Unicode 代理转义必须让
// audit 以非零状态退出、stderr 说明字符编码/Unicode 转义问题并指出位置、
// stdout 为空；尚不存在的报告目录不创建，已有报告原样保留。合法字符
// （含正确成对的代理转义与直接书写的同一字符）继续成功，且两种写法的
// 产物哈希与报告标识一致。

// charsetArtifactJSON / charsetRulesJSON 是结构合法的提交片段。
const charsetArtifactJSON = `{"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"}`
const charsetRulesJSON = `[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}]`

// charsetDefectDoc 用给定的原始 note JSON 片段拼出一份“发现缺陷”提交，
// 其检查记录绑定正确的产物哈希与规则版本。
func charsetDefectDoc(hash, noteJSON string) string {
	check := `{"artifactHash":"` + hash + `","ruleId":"r1","version":"1.0.0","status":"发现缺陷","note":` + noteJSON + `}`
	return `{"artifact":` + charsetArtifactJSON + `,"rules":` + charsetRulesJSON + `,"checks":[` + check + `]}`
}

// --- note 含孤立高代理项转义：整份拒绝，输出干净、无存储副作用 ---

func TestCLIAuditLoneSurrogateNoteRejectedCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := contractsentinelArtifactHashForCharset()
	input := writeInput(t, work, "bad.json",
		charsetDefectDoc(hash, `"反例：\uD800重入路径"`))
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("a lone surrogate escape in the note must exit non-zero")
	}
	if !strings.Contains(stderr, "Unicode escape") {
		t.Fatalf("stderr must classify the problem as a Unicode escape issue:\n%s", stderr)
	}
	if !strings.Contains(stderr, "surrogate") {
		t.Fatalf("stderr must name the unpaired surrogate:\n%s", stderr)
	}
	if !strings.Contains(stderr, "note") {
		t.Fatalf("stderr must locate the offending note field:\n%s", stderr)
	}
	for _, marker := range []string{"byte offset", "line ", "column"} {
		if !strings.Contains(stderr, marker) {
			t.Fatalf("stderr must point at the position (%q):\n%s", marker, stderr)
		}
	}
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 孤立代理项出现在未知扩展成员的嵌套内容里：同样整份拒绝 ---

func TestCLIAuditLoneSurrogateInExtensionRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	doc := `{"artifact":` + charsetArtifactJSON + `,"rules":` + charsetRulesJSON +
		`,"mystery":{"nested":[{"deep":"x\uDC00y"}]}}`
	input := writeInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("a lone surrogate inside an unknown extension must exit non-zero")
	}
	if !strings.Contains(stderr, "Unicode escape") || !strings.Contains(stderr, "surrogate") {
		t.Fatalf("stderr must classify and name the surrogate problem:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 源码字符串含非法 UTF-8 字节：在哈希计算前拒绝 ---

func TestCLIAuditInvalidUTF8SourceRejectedCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	// 真正拼入一个 0xFF 字节，而不是字面的反斜杠文本。
	doc := `{"artifact":{"name":"Vault","abi":"abi","bytecode":"0x1","source":"x` + "\xFF" + `y"},"rules":[]}`
	input := writeInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("an invalid UTF-8 byte in the source must exit non-zero")
	}
	if !strings.Contains(stderr, "character encoding") || !strings.Contains(stderr, "UTF-8") {
		t.Fatalf("stderr must classify the problem as a character encoding issue:\n%s", stderr)
	}
	if !strings.Contains(stderr, "source") {
		t.Fatalf("stderr must locate the offending source field:\n%s", stderr)
	}
	if !strings.Contains(stderr, "byte offset") {
		t.Fatalf("stderr must point at the byte offset:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 失败提交不得登记成合约缺陷/工具缺失/超时，也不得留下临时文件 ---

func TestCLIAuditBadCharsNoStatusFragmentsOrTempFiles(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := contractsentinelArtifactHashForCharset()
	input := writeInput(t, work, "bad.json",
		charsetDefectDoc(hash, `"ce\uD800"`))
	store := filepath.Join(work, "reports")

	stdout, _, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("bad characters must fail the submission")
	}
	for _, marker := range []string{"reportId", "findings", "发现缺陷", "工具缺失", "超时", "未检查", "通过"} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a partial report fragment %q:\n%s", marker, stdout)
		}
	}
	// 存储目录即便被创建（本例未创建），也不得残留临时文件。
	if entries, err := os.ReadDir(work); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".report-") && strings.HasSuffix(e.Name(), ".tmp") {
				t.Fatalf("rejected submission left a temporary file: %s", e.Name())
			}
		}
	}
}

// --- 已有报告时字符问题失败：原有报告保持原样，不新增文件 ---

func TestCLIAuditBadCharsKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	// 先落一份完全合法的报告（不变式 false 产生缺陷）。
	good := writeInput(t, work, "good.json", `{
		"artifact": `+charsetArtifactJSON+`,
		"rules": `+charsetRulesJSON+`,
		"invariants": {"inv": false}
	}`)
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
	existingPath := filepath.Join(store, before[0])
	existingBytes, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}

	// 再提交一份 note 含孤立代理项的提交（哈希与版本均正确，仅字符非法）。
	hash := contractsentinelArtifactHashForCharset()
	bad := writeInput(t, work, "bad.json", charsetDefectDoc(hash, `"ce\uD800"`))
	if _, _, code := runCLIAudit(t, bin, bad, store); code == 0 {
		t.Fatal("invalid submission must exit non-zero")
	}

	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("rejected submission changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("rejected submission modified the existing report bytes")
	}
}

// --- 合法成对代理转义与直接书写的同一字符：哈希、报告标识、证据一致 ---

func TestCLIAuditPairedEscapeEqualsLiteralIdentity(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	// 同一逻辑 note：一次用 ASCII 代理对转义书写，一次直接写 UTF-8 字符。
	hash := contractsentinelArtifactHashForCharset()
	escDoc := charsetDefectDoc(hash, `"证据：\uD83D\uDE00 重入\n第二行  "`)
	litDoc := charsetDefectDocLiteral(hash)

	escInput := writeInput(t, work, "esc.json", escDoc)
	litInput := writeInput(t, work, "lit.json", litDoc)

	escOut, escErr, code := runCLIAudit(t, bin, escInput, filepath.Join(work, "store-esc"))
	if code != 0 {
		t.Fatalf("paired surrogate escape must be legal: %s", escErr)
	}
	litOut, litErr, code := runCLIAudit(t, bin, litInput, filepath.Join(work, "store-lit"))
	if code != 0 {
		t.Fatalf("literal character must be legal: %s", litErr)
	}

	escReport := decodeReport(t, escOut)
	litReport := decodeReport(t, litOut)
	if escReport.Artifact.Hash != hash || litReport.Artifact.Hash != hash {
		t.Fatalf("artifact hash must be the correctly-bound value:\nesc=%q\nlit=%q\nwant=%q",
			escReport.Artifact.Hash, litReport.Artifact.Hash, hash)
	}
	if escReport.ReportID != litReport.ReportID {
		t.Fatalf("report id differs between escaped and literal same-string forms:\n%s\n%s",
			escReport.ReportID, litReport.ReportID)
	}
	wantNote := "证据：😀 重入\n第二行  "
	if escReport.Findings[0].Evidence != wantNote || litReport.Findings[0].Evidence != wantNote {
		t.Fatalf("evidence must preserve the decoded original text:\nesc=%q\nlit=%q\nwant=%q",
			escReport.Findings[0].Evidence, litReport.Findings[0].Evidence, wantNote)
	}
	if !strings.Contains(escOut, "证据") {
		t.Fatal("stdout report must carry the decoded CJK evidence text")
	}
}

// charsetDefectDocLiteral 与 charsetDefectDoc 内容相同，但 note 直接以
// UTF-8 书写 emoji 与换行转义。
func charsetDefectDocLiteral(hash string) string {
	check := `{"artifactHash":"` + hash +
		`","ruleId":"r1","version":"1.0.0","status":"发现缺陷","note":"证据：😀 重入\n第二行  "}`
	return `{"artifact":` + charsetArtifactJSON + `,"rules":` + charsetRulesJSON + `,"checks":[` + check + `]}`
}

// contractsentinelArtifactHashForCharset 计算 charsetArtifactJSON 对应产物
// 的内容哈希，避免测试手写哈希。
func contractsentinelArtifactHashForCharset() string {
	return contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name: "Vault", ABI: "abi", Bytecode: "0x1", Source: "Vault.sol",
	})
}
