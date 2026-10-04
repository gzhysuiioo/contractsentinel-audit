package contractsentinel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 本文件锁定“归档读取”侧对非法字符的拒绝，与 audit 提交侧同一标准：
// encoding/json 会把字符串里的非法 UTF-8 字节、未配对或错序的 Unicode 代理
// 转义静默改写成 U+FFFD。一份说明与证据本就含合法 U+FFFD 的报告，把这两处
// 换成孤立代理转义后，解码内容逐字回到原报告——重算的 reportId 与缺陷归属
// 校验都会在改写后的内容上通过。读取成功必须表示归档字节本身合法，因此
// loadStoredReport 在任何解码之前先做字符合法性扫描：命中即整份判损坏，
// 不输出部分报告，归档原字节保留。

// fffdFixture 是一份说明与证据都含合法 U+FFFD 的合法缺陷报告。
func fffdFixture() Report {
	hash := ArtifactHash(sampleArtifact())
	note := "反例：含替换字符 � 的说明"
	return Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect, Note: note},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: note},
		},
	}
}

// corruptArchiveText 对 id 的归档做纯文本改写并写回同一文件名。所有用例的
// 改写都不改变解码后的内容（非法字符会被解码器改写回原文），因此归档内
// reportId 与重算 id 依然一致，拒绝只能来自字符扫描。
func corruptArchiveText(t *testing.T, dir, id string, mutate func(string) string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := mutate(string(data))
	if doc == string(data) {
		t.Fatal("test setup: mutation did not change the archive")
	}
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

// decodeMatchesID 断言归档文本解码后的报告标识与请求 id 一致：排除“靠 id
// 不匹配才发现问题”，拒绝只能来自字符合法性扫描。
func decodeMatchesID(t *testing.T, dir, id string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportID != id || ReportID(decoded) != id {
		t.Fatalf("test setup: corrupt archive must still decode to id %q, got stored=%q recomputed=%q",
			id, decoded.ReportID, ReportID(decoded))
	}
}

// expectCorruptCharLoad 断言完整损坏契约：errCorrupt、点名报告标识、含全部
// 要求的定位片段、返回零值报告、归档原字节不动。
func expectCorruptCharLoad(t *testing.T, dir, id string, wantSubstrings ...string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("archive with illegal characters must be rejected, got %+v", got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("illegal characters classify as errCorrupt, got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, id) {
		t.Fatalf("error must name the report id %q: %v", id, err)
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
	if !reflect.DeepEqual(got, Report{}) {
		t.Fatalf("failed read must return the zero report, got %+v", got)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must not be deleted: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed read must not rewrite or repair the archive")
	}
}

// --- 核心场景：合法 U+FFFD 被换成孤立代理转义，解码后标识仍一致，仍须拒绝 ---

func TestLoadReportLoneHighSurrogateReplacingFFFDRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, fffdFixture())
	// 说明与证据两处 U+FFFD 都换成孤立高代理项转义：解码后逐字回到原文。
	corruptArchiveText(t, dir, id, func(doc string) string {
		return strings.ReplaceAll(doc, "�", `\uD800`)
	})
	decodeMatchesID(t, dir, id)
	expectCorruptCharLoad(t, dir, id,
		"Unicode escape", "surrogate", ".rules[0].note", "byte offset", "line ", "column")
}

func TestLoadReportLoneLowSurrogateReplacingFFFDRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, fffdFixture())
	corruptArchiveText(t, dir, id, func(doc string) string {
		return strings.ReplaceAll(doc, "�", `\uDC00`)
	})
	decodeMatchesID(t, dir, id)
	expectCorruptCharLoad(t, dir, id, "Unicode escape", "surrogate", ".rules[0].note")
}

// 配对顺序错误（低代理项在前）同样拒绝：两个连续 U+FFFD 换成 \uDC00\uD800，
// 解码后仍是两个 U+FFFD，标识一致。
func TestLoadReportMisorderedSurrogatePairRejected(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	note := "两个连续替换字符 �� 结尾"
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect, Note: note},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: note},
		},
	}
	id := writeReportWithFreshID(t, dir, report)
	corruptArchiveText(t, dir, id, func(doc string) string {
		return strings.ReplaceAll(doc, "��", `\uDC00\uD800`)
	})
	decodeMatchesID(t, dir, id)
	expectCorruptCharLoad(t, dir, id, "Unicode escape", "surrogate")
}

// --- 非法 UTF-8 字节：解码成 U+FFFD 后标识一致，仍按字符编码错误拒绝 ---

func TestLoadReportInvalidUTF8ReplacingFFFDRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, fffdFixture())
	corruptArchiveText(t, dir, id, func(doc string) string {
		return strings.ReplaceAll(doc, "�", "\xFF")
	})
	decodeMatchesID(t, dir, id)
	expectCorruptCharLoad(t, dir, id,
		"character encoding", "UTF-8", ".rules[0].note", "byte offset", "line ", "column")
}

// --- 未知扩展成员的嵌套内容、成员名称同样受检，不因不参与标识而放行 ---

func TestLoadReportLoneSurrogateInExtensionRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, oneDefectFixture())
	corruptArchiveText(t, dir, id, func(doc string) string {
		return strings.Replace(doc, `{"reportId"`, `{"mystery":{"nested":[{"deep":"x\uDC00y"}]},"reportId"`, 1)
	})
	expectCorruptCharLoad(t, dir, id, "Unicode escape", "surrogate", ".mystery.nested[0].deep")
}

func TestLoadReportLoneSurrogateInMemberNameRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, oneDefectFixture())
	corruptArchiveText(t, dir, id, func(doc string) string {
		return strings.Replace(doc, `{"reportId"`, `{"x\uD800":1,"reportId"`, 1)
	})
	// 成员名损坏时指出其所在对象（这里是顶层对象）。
	expectCorruptCharLoad(t, dir, id, "Unicode escape", "member name", "the top-level object")
}

func TestLoadReportInvalidUTF8InMemberNameRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, oneDefectFixture())
	corruptArchiveText(t, dir, id, func(doc string) string {
		return strings.Replace(doc, `{"reportId"`, `{"no`+"\xFF"+`te":1,"reportId"`, 1)
	})
	expectCorruptCharLoad(t, dir, id, "character encoding", "member name", "the top-level object")
}

// --- 合法字符继续正常读取：原文 U+FFFD、成对代理转义、转义反斜线文本 ---

func TestLoadReportLiteralFFFDArchiveStillLoads(t *testing.T) {
	dir := t.TempDir()
	report := fffdFixture()
	id := writeReportWithFreshID(t, dir, report)
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a literal U+FFFD in note and evidence is ordinary text: %v", err)
	}
	if loaded.Rules[0].Note != report.Rules[0].Note || loaded.Findings[0].Evidence != report.Findings[0].Evidence {
		t.Fatalf("decoded original text must be preserved: %+v", loaded)
	}
}

func TestLoadReportPairedSurrogateEscapeArchiveStillLoads(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	note := "证据：😀 重入"
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect, Note: note},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: note},
		},
	}
	id := writeReportWithFreshID(t, dir, report)
	// 把直接书写的 😀 改写成正确配对的代理转义：同一字符的合法另一种写法。
	corruptArchiveText(t, dir, id, func(doc string) string {
		return strings.ReplaceAll(doc, "😀", `\uD83D\uDE00`)
	})
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a correctly paired surrogate escape must stay legal: %v", err)
	}
	if loaded.Rules[0].Note != note || loaded.Findings[0].Evidence != note {
		t.Fatalf("paired escape must decode to the original character: %+v", loaded)
	}
}

func TestLoadReportEscapedBackslashBeforeUD800StillLoads(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	// 普通文本：反斜线后紧跟 uD800 字样。JSON 体写作 \\uD800，只是内容。
	note := `路径 C:\uD800 只是文本`
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect, Note: note},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: note},
		},
	}
	id := writeReportWithFreshID(t, dir, report)
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("an escaped backslash before uD800 text must not be misjudged: %v", err)
	}
	if loaded.Rules[0].Note != note {
		t.Fatalf("escaped-backslash text must be preserved verbatim: %q", loaded.Rules[0].Note)
	}
}

// --- diff：任一侧归档含非法字符，整次比较失败，无部分结果 ---

func TestDiffStoreRejectsBadCharsOnEitherSide(t *testing.T) {
	dir := t.TempDir()
	good := oneDefectFixture()
	goodID := writeReportWithFreshID(t, dir, good)
	bad := fffdFixture()
	badID := writeReportWithFreshID(t, dir, bad)
	corruptArchiveText(t, dir, badID, func(doc string) string {
		return strings.ReplaceAll(doc, "�", `\uD800`)
	})
	decodeMatchesID(t, dir, badID)

	for _, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"second report corrupt", goodID, badID},
		{"first report corrupt", badID, goodID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diff, err := DiffStore(dir, tc.before, tc.after)
			if err == nil {
				t.Fatalf("diff must fail when a side has illegal characters, got %+v", diff)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), badID) {
				t.Fatalf("error must name the corrupt report id: %v", err)
			}
			if !reflect.DeepEqual(diff, DiffResult{}) {
				t.Fatalf("failed diff must return the zero result, got %+v", diff)
			}
		})
	}
}

// --- audit 保存遇到同标识既有损坏归档：不能当成保存成功，原文件保留 ---

func TestSaveReportBadCharExistingArchiveNotTreatedAsSaved(t *testing.T) {
	dir := t.TempDir()
	r := fffdFixture()
	id := writeReportWithFreshID(t, dir, r)
	corruptArchiveText(t, dir, id, func(doc string) string {
		return strings.ReplaceAll(doc, "�", `\uD800`)
	})
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 提交内容标识相同的合法报告：既有归档已损坏，保存必须失败而非“同标识即成功”。
	r.ReportID = id
	if err := SaveReport(dir, r); err == nil {
		t.Fatal("a corrupt-character existing archive must not count as a successful save")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("expected errCorrupt, got %T: %v", err, err)
		}
		if !strings.Contains(err.Error(), "surrogate") {
			t.Fatalf("error must name the character problem: %v", err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must be kept: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed save must leave the corrupt archive untouched")
	}
}

// --- 错误三分类不变：字符损坏是 errCorrupt，不与不存在/标识不合法混淆 ---

func TestLoadReportBadCharErrorClassDistinct(t *testing.T) {
	dir := t.TempDir()
	corruptID := writeReportWithFreshID(t, dir, fffdFixture())
	corruptArchiveText(t, dir, corruptID, func(doc string) string {
		return strings.ReplaceAll(doc, "�", "\xFF")
	})
	if _, err := LoadReport(dir, corruptID); err == nil {
		t.Fatal("expected corrupt error")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("bad-character archive -> expected errCorrupt, got %T: %v", err, err)
		}
	}
	missing := strings.Repeat("0", 64)
	if _, err := LoadReport(dir, missing); err == nil {
		t.Fatal("expected not found error")
	} else {
		var enf errNotFound
		if !errors.As(err, &enf) {
			t.Fatalf("missing report -> expected errNotFound, got %T: %v", err, err)
		}
	}
	if _, err := LoadReport(dir, "xyz"); err == nil {
		t.Fatal("expected invalid id error")
	} else {
		var ei errInvalid
		if !errors.As(err, &ei) {
			t.Fatalf("invalid id -> expected errInvalid, got %T: %v", err, err)
		}
	}
}
