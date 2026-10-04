package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 report / diff 读取已保存报告时的
// 字符合法性拒绝。audit 提交早已拒绝非法字符，但归档读取会先把非法 UTF-8
// 字节和未配对/错序的 Unicode 代理转义静默改写成 U+FFFD：一份说明与证据都
// 合法地含有 U+FFFD 的报告，把这两处换成孤立代理转义后，解码内容与原报告
// 完全相同（reportId 与证据校验都成立），仍必须被当作损坏归档拒绝。
//
// 损坏契约：非零退出、原因进 stderr（点名请求的报告标识，区分字符编码错误
// 与 Unicode 转义错误，给出原始文件字节偏移、行列与可定位的 JSON 路径，成员
// 名损坏指出所在对象）、stdout 不输出任何完整或部分报告，归档原字节保留。
// diff 任一侧损坏则整次比较失败；audit 遇到同标识既有字符损坏归档不能视为
// 保存成功。

// cliCharDefectNote 是一条合法地直接书写 U+FFFD 的缺陷说明。
const cliCharDefectNote = "  反例：攻击者可在 withdraw 中重入 �\n第二行证据  "

// cliReplacementBytes 是直接书写的 U+FFFD 的 UTF-8 编码。
var cliReplacementBytes = []byte{0xEF, 0xBF, 0xBD}

// auditCharReport 通过真实 audit 命令落盘一份缺陷说明含直接 U+FFFD 的合法
// 报告，返回其标识。归档中的说明与证据都带这三字节 U+FFFD。
func auditCharReport(t *testing.T, bin, work, store string) string {
	t.Helper()
	hash := mixedArtifactHash(t)
	in := cliWireInput{
		Artifact: mixedCheckArtifact(),
		Rules:    mixedCheckRules(),
		Checks: []cliWireCheck{
			{ArtifactHash: hash, RuleID: "rule-pass", Version: "1.4.0", Status: contractsentinel.StatusPass},
			{ArtifactHash: hash, RuleID: "rule-defect", Version: "2.0.1", Status: contractsentinel.StatusDefect, Note: cliCharDefectNote},
			{ArtifactHash: hash, RuleID: "rule-tool", Version: "3.0.0", Status: contractsentinel.StatusToolMissing, Note: "符号执行引擎未安装"},
		},
	}
	input := writeStructInput(t, work, "char.json", in)
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit with a literal U+FFFD note must succeed: %s", stderr)
	}
	return decodeReport(t, stdout).ReportID
}

// charReportInputPath 重写一份与 auditCharReport 相同的提交，用于再次审计。
func charReportInputPath(t *testing.T, work, name string) string {
	hash := mixedArtifactHash(t)
	in := cliWireInput{
		Artifact: mixedCheckArtifact(),
		Rules:    mixedCheckRules(),
		Checks: []cliWireCheck{
			{ArtifactHash: hash, RuleID: "rule-pass", Version: "1.4.0", Status: contractsentinel.StatusPass},
			{ArtifactHash: hash, RuleID: "rule-defect", Version: "2.0.1", Status: contractsentinel.StatusDefect, Note: cliCharDefectNote},
			{ArtifactHash: hash, RuleID: "rule-tool", Version: "3.0.0", Status: contractsentinel.StatusToolMissing, Note: "符号执行引擎未安装"},
		},
	}
	return writeStructInput(t, work, name, in)
}

// injectArchiveBytes 读取 id 命名的归档，把其中所有 old 字节替换为 new 后写回。
func injectArchiveBytes(t *testing.T, store, id string, old, new []byte) {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, old) {
		t.Fatalf("test setup: archive does not contain % x", old)
	}
	out := bytes.ReplaceAll(data, old, new)
	if bytes.Equal(out, data) {
		t.Fatal("test setup: byte replacement did not change the archive")
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// injectArchiveText 在归档中做一次纯文本替换。
func injectArchiveText(t *testing.T, store, id, old, new string) {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	if !strings.Contains(doc, old) {
		t.Fatalf("test setup: archive does not contain %q", old)
	}
	doc = strings.Replace(doc, old, new, 1)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

// assertCharReadFailure 断言字符损坏读取的完整失败契约。
func assertCharReadFailure(t *testing.T, stdout, stderr string, code int, id string, want ...string) {
	t.Helper()
	if code == 0 {
		t.Fatal("a character-illegal archive must exit non-zero")
	}
	if !strings.Contains(stderr, "corrupt") {
		t.Fatalf("stderr must classify the archive as corrupt:\n%s", stderr)
	}
	if !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the requested report id %q:\n%s", id, stderr)
	}
	for _, marker := range []string{"byte offset", "line ", "column"} {
		if !strings.Contains(stderr, marker) {
			t.Fatalf("stderr must point at the position (%q):\n%s", marker, stderr)
		}
	}
	for _, w := range want {
		if !strings.Contains(stderr, w) {
			t.Fatalf("stderr must contain %q:\n%s", w, stderr)
		}
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- 核心场景：说明与证据的合法 U+FFFD 都换成孤立高代理项，仍按损坏拒绝 ---

func TestCLIReportLoneSurrogateLaunderingRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditCharReport(t, bin, work, store)
	path := filepath.Join(store, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 说明与证据两处 U+FFFD 都换成 \uD800：解码后内容与原报告逐字节相同，
	// reportId 与证据校验都成立，唯一能拒绝它的就是字符关。
	injectArchiveBytes(t, store, id, cliReplacementBytes, []byte(`\uD800`))

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCharReadFailure(t, stdout, stderr, code, id,
		"invalid Unicode escape", "unpaired high surrogate escape",
		".rules[", ".note", "string value")

	// stdout 不得泄漏任何报告片段。
	for _, marker := range []string{"reportId", "findings", "rule-defect", contractsentinel.StatusDefect} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak the partial report %q:\n%s", marker, stdout)
		}
	}
	// 归档原字节保留：替换后的损坏文本仍在，没有被修复、替换或删除。
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(after, before) {
		t.Fatal("test setup: archive must have been corrupted")
	}
	if !bytes.Contains(after, []byte(`\uD800`)) {
		t.Fatal("failed report read must leave the corrupt archive untouched")
	}
}

// --- 孤立低代理项：Unicode 转义错误，定位到证据 ---

func TestCLIReportLoneLowSurrogateInEvidenceRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditCharReport(t, bin, work, store)
	// 只把证据一处 U+FFFD 换成孤立低代理项；说明仍是直接 U+FFFD。
	corruptEvidenceOnce(t, store, id, `\uDC00`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCharReadFailure(t, stdout, stderr, code, id,
		"invalid Unicode escape", "unpaired low surrogate escape",
		".findings[", ".evidence")
}

// corruptEvidenceOnce 仅替换证据字符串里的第一处 U+FFFD 三字节。
func corruptEvidenceOnce(t *testing.T, store, id, escape string) {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte(`"evidence":"`)
	ev := bytes.Index(data, marker)
	if ev < 0 {
		t.Fatal("test setup: evidence member not found")
	}
	head := append(append([]byte{}, data[:ev]...), marker...)
	tail := data[ev+len(marker):]
	tail = bytes.Replace(tail, cliReplacementBytes, []byte(escape), 1)
	out := append(head, tail...)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- 低代理项在前的错误配对顺序 ---

func TestCLIReportLowBeforeHighOrderingRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditCharReport(t, bin, work, store)
	// 说明里的 U+FFFD 三字节替换为“低后高”一对；扫描到的第一个逃逸即未配对
	// 低代理项。
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	noteMarker := []byte(`"note":"`)
	ni := bytes.Index(data, noteMarker)
	if ni < 0 {
		t.Fatal("test setup: note member not found")
	}
	head := append(append([]byte{}, data[:ni]...), noteMarker...)
	tail := data[ni+len(noteMarker):]
	tail = bytes.Replace(tail, cliReplacementBytes, []byte(`\uDC00\uD800`), 1)
	if err := os.WriteFile(path, append(head, tail...), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCharReadFailure(t, stdout, stderr, code, id,
		"invalid Unicode escape", "unpaired low surrogate escape", ".note")
}

// --- 非法 UTF-8 字节：字符编码错误，区别于转义错误 ---

func TestCLIReportInvalidUTF8Rejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditCharReport(t, bin, work, store)
	path := filepath.Join(store, id+".json")
	injectArchiveBytes(t, store, id, cliReplacementBytes, []byte{0xFF})

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCharReadFailure(t, stdout, stderr, code, id,
		"invalid character encoding", "invalid UTF-8 byte 0xff")
	if strings.Contains(stderr, "Unicode escape") {
		t.Fatalf("an encoding error must not be labelled a Unicode escape error:\n%s", stderr)
	}
	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(kept, []byte{0xFF}) {
		t.Fatal("failed report read must keep the invalid byte in the archive")
	}
}

// --- 未知扩展成员嵌套对象里的孤立代理项：不参与标识也不放行 ---

func TestCLIReportLoneSurrogateInUnknownExtensionRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveText(t, store, id,
		`{"reportId"`, `{"mystery":{"nested":[{"deep":"x\uD800y"}]},"reportId"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCharReadFailure(t, stdout, stderr, code, id,
		"invalid Unicode escape", "unpaired high surrogate escape",
		".mystery.nested[0].deep")
}

// --- 成员名称损坏：指出其所在对象（此处为顶层对象） ---

func TestCLIReportLoneSurrogateInMemberNameRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)
	injectArchiveText(t, store, id,
		`{"reportId"`, `{"x\uD800y":1,"reportId"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCharReadFailure(t, stdout, stderr, code, id,
		"invalid Unicode escape", "member name", "the top-level object")
}

// --- 兼容：直接书写的合法 U+FFFD 正常读取，说明证据保留解码原文 ---

func TestCLIReportLiteralReplacementCharStillReads(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditCharReport(t, bin, work, store)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("a literal U+FFFD is ordinary legal content and must read: %s", stderr)
	}
	report := decodeReport(t, stdout)
	if report.ReportID != id {
		t.Fatalf("report id not preserved: %q", report.ReportID)
	}
	if report.Rules[1].Note != cliCharDefectNote || report.Findings[0].Evidence != cliCharDefectNote {
		t.Fatalf("decoded U+FFFD text must be preserved:\n note=%q\n evidence=%q",
			report.Rules[1].Note, report.Findings[0].Evidence)
	}
}

// --- diff：任一侧归档字符损坏都整体失败，不输出已读成功一侧的局部结果 ---

func TestCLIDiffCharacterCorruptEitherSideFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	goodID := auditOneReport(t, bin, work, store)
	corruptID := auditCharReport(t, bin, work, store)
	if goodID == corruptID {
		t.Fatal("test setup: the two reports must have distinct ids")
	}
	// 损坏含 U+FFFD 的那份：两处都换成孤立高代理项。
	injectArchiveBytes(t, store, corruptID, cliReplacementBytes, []byte(`\uD800`))
	goodBytes, err := os.ReadFile(filepath.Join(store, goodID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	corruptBytes, err := os.ReadFile(filepath.Join(store, corruptID+".json"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"second report corrupt", goodID, corruptID},
		{"first report corrupt", corruptID, goodID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCLIDiff(t, bin, store, tc.before, tc.after)
			if code == 0 {
				t.Fatal("diff must exit non-zero when a side is character-corrupt")
			}
			if !strings.Contains(stderr, "corrupt") || !strings.Contains(stderr, corruptID) {
				t.Fatalf("stderr must classify corruption and name the corrupt side:\n%s", stderr)
			}
			if !strings.Contains(stderr, "Unicode escape") || !strings.Contains(stderr, "surrogate") {
				t.Fatalf("stderr must classify the character problem:\n%s", stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
			}
			for _, marker := range []string{goodID, corruptID, `"results"`, `"summary"`,
				contractsentinel.ChangeNewDefect, contractsentinel.StatusUnchecked} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a partial diff %q:\n%s", marker, stdout)
				}
			}
		})
	}

	// 失败的比较不修复、不覆盖任何一侧归档。
	if kept, err := os.ReadFile(filepath.Join(store, corruptID+".json")); err != nil || !bytes.Equal(kept, corruptBytes) {
		t.Fatalf("failed diff must leave the corrupt archive untouched: %v", err)
	}
	if kept, err := os.ReadFile(filepath.Join(store, goodID+".json")); err != nil || !bytes.Equal(kept, goodBytes) {
		t.Fatalf("failed diff must leave the clean side untouched: %v", err)
	}
}

// --- audit 保存遇到同标识既有字符损坏归档：不能当成保存成功，原文件保留 ---

func TestCLIAuditCharacterCorruptExistingArchiveFailsAndKeepsFile(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditCharReport(t, bin, work, store)
	path := filepath.Join(store, id+".json")
	injectArchiveBytes(t, store, id, cliReplacementBytes, []byte(`\uD800`))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 用内容标识相同的合法提交（直接书写 U+FFFD）再审计一次：已有归档字符
	// 损坏，必须失败而不是“同标识即成功”。
	input := charReportInputPath(t, work, "again.json")
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("audit against a character-corrupt existing archive must exit non-zero")
	}
	if !strings.Contains(stderr, "corrupt") || !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the corrupt archive and its report id:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Unicode escape") || !strings.Contains(stderr, "surrogate") {
		t.Fatalf("stderr must classify the character problem:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("failed audit must print nothing to stdout:\n%s", stdout)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must be kept: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed audit must leave the corrupt archive untouched")
	}
}
