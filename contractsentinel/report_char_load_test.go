package contractsentinel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// 本文件锁定“归档读取”侧的字符合法性拒绝，与 audit 提交侧
// (jsonchars_test.go) 完全对齐。audit 提交早已拒绝非法字符，但读取已保存
// 报告时 json.Unmarshal 会静默把两类非法输入改写成 U+FFFD：
//   - JSON 字符串里的非法 UTF-8 字节；
//   - 未配对的高/低代理项、低代理项在前的错误配对顺序。
//
// 于是一份说明与证据都合法地含有 U+FFFD 的报告，把这两处换成孤立代理转义
// 后，解码内容与原报告逐字节相同——重算 reportId 一致、证据与说明也一致，
// 整份损坏归档就会被当成原报告读出。读取成功必须表示归档本身合法：任何成员
// 名称或字符串值（含成员名、规则说明、缺陷证据及未知扩展成员的嵌套对象和
// 数组，扩展成员不参与报告标识也不放行）出现字符问题，都必须把整份报告判为
// 归档损坏，即使改写后能算出相同 reportId。损坏归档原字节保留，不修复、替换
// 或删除；diff 任一侧损坏则整次比较失败；audit 遇到同标识既有损坏归档不能
// 视为保存成功。合法中文、前后空格、换行、正确成对的代理转义、直接书写的同
// 一字符、原文中的 U+FFFD 与“转义反斜线后接 uD800”文本继续正常读取。

// replacementCharBytes 是直接书写的 U+FFFD 的 UTF-8 编码。
var replacementCharBytes = []byte{0xEF, 0xBF, 0xBD}

// oneRuleCharReport 构造一份只有一条“发现缺陷”规则的合法报告，其说明与证据
// 都是 note（二者必须一致），用于按文本方式注入字符问题。
func oneRuleCharReport(note string) Report {
	hash := ArtifactHash(sampleArtifact())
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

// expectCorruptCharLoad 断言字符损坏归档的完整读取契约：errCorrupt 且点名
// 请求的报告标识与所有要求的定位片段，返回零值报告，归档原字节保留。
func expectCorruptCharLoad(t *testing.T, dir, id string, data []byte, wantSubstrings ...string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("character-illegal archive must be rejected, got %+v", got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("character problems classify as errCorrupt, got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, id) {
		t.Fatalf("error must name the requested report id %q: %v", id, err)
	}
	if !strings.Contains(msg, "archive is corrupt") {
		t.Fatalf("error must classify the archive as corrupt: %v", err)
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
	if string(after) != string(data) {
		t.Fatal("failed read must not rewrite, repair or replace the archive bytes")
	}
}

// --- 核心场景：说明与证据的合法 U+FFFD 都换成孤立高代理项，仍必须拒绝 ---

func TestLoadReportLoneSurrogateLaunderingRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("反例：�重入")
	legalID := ReportID(r)

	// 说明与证据两处的直接 U+FFFD 都换成 \uD800：解码器会把它们各自改写回
	// U+FFFD，所以除字符关外没有任何一关能拒绝这份归档。
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		return strings.ReplaceAll(doc, string(replacementCharBytes), `\uD800`)
	})
	if id != legalID {
		t.Fatalf("the rewritten content computes the same report id, got %s want %s", id, legalID)
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	// 偏移必须正好指向原始文件中说明处逃逸的反斜线。
	wantOffset := strings.Index(string(data), `"note":"反例：\uD800`)
	if wantOffset < 0 {
		t.Fatal("test setup: mutated note not found in archive")
	}
	escapeOffset := wantOffset + len(`"note":"反例：`)
	expectCorruptCharLoad(t, dir, id, data,
		"invalid Unicode escape", "unpaired high surrogate escape",
		".rules[0].note", "string value",
		"byte offset "+strconv.Itoa(escapeOffset), "line 1", "column ")
	if got := data[escapeOffset]; got != '\\' {
		t.Fatalf("reported offset %d must point at the escape backslash, got %q", escapeOffset, got)
	}
}

// --- 孤立低代理项 / 错误配对顺序出现在证据中：按证据路径拒绝 ---

func TestLoadReportLoneLowSurrogateInEvidenceRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("反例：�重入")
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		// 只替换证据一处；解码后证据仍是相同的 U+FFFD 文本，报告标识不变。
		return strings.Replace(doc, `"evidence":"反例：`+string(replacementCharBytes),
			`"evidence":"反例：\uDC00`, 1)
	})
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	expectCorruptCharLoad(t, dir, id, data,
		"invalid Unicode escape", "unpaired low surrogate escape",
		".findings[0].evidence")
}

func TestLoadReportLowBeforeHighOrderingRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("反例：�重入")
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		// 低代理项在前：扫描到的第一个逃逸就是未配对低代理项。
		return strings.Replace(doc, `"note":"反例：`+string(replacementCharBytes),
			`"note":"反例：\uDC00\uD800`, 1)
	})
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	expectCorruptCharLoad(t, dir, id, data,
		"invalid Unicode escape", "unpaired low surrogate escape", ".rules[0].note")
}

// --- 字符串值中的非法 UTF-8 字节：字符编码错误，区别于转义错误 ---

func TestLoadReportInvalidUTF8InEvidenceRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("反例：�重入")
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		// 证据里的 U+FFFD 三字节换成单个非法字节 0xFF；解码同样改写回一个
		// U+FFFD，报告标识仍一致。
		return strings.Replace(doc, `"evidence":"反例：`+string(replacementCharBytes),
			`"evidence":"反例：`+"\xFF", 1)
	})
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	expectCorruptCharLoad(t, dir, id, data,
		"invalid character encoding", "invalid UTF-8 byte 0xff",
		".findings[0].evidence", "string value")
}

// --- 文件任意位置的非法字节（字符串外的空白处）同样整份拒绝 ---

func TestLoadReportInvalidUTF8OutsideStringsRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, oneRuleCharReport("counterexample: x"))
	path := filepath.Join(dir, id+".json")
	legal, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := []byte(strings.Replace(string(legal), `{"reportId"`, `{`+" \xFF "+`"reportId"`, 1))
	if err := os.WriteFile(path, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("invalid UTF-8 outside string literals must reject the archive, got %+v", got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T: %v", err, err)
	}
	for _, want := range []string{id, "invalid character encoding", "invalid UTF-8 byte 0xff", "JSON input", "byte offset", "line 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must contain %q", err.Error(), want)
		}
	}
	if !reflect.DeepEqual(got, Report{}) {
		t.Fatalf("failed read must return the zero report, got %+v", got)
	}
}

// --- 成员名称损坏：指出其所在对象 ---

func TestLoadReportBadCharsInFixedMemberNameRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("counterexample: x")
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		// 产物对象里的固定成员名被写坏：坏名称无法逐字渲染，路径停在产物对象。
		return strings.Replace(doc, `"artifact":{"name":"Vault"`,
			`"artifact":{"nam\uD800":"Vault"`, 1)
	})
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	expectCorruptCharLoad(t, dir, id, data,
		"invalid Unicode escape", "member name", ".artifact")
}

func TestLoadReportBadCharsInTopLevelExtensionMemberNameRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("counterexample: x")
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		// 顶层未知扩展成员名损坏：所在对象是顶层对象。
		return strings.Replace(doc, `{"reportId"`,
			`{"x\uD800y":1,"reportId"`, 1)
	})
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	expectCorruptCharLoad(t, dir, id, data,
		"invalid Unicode escape", "member name", "the top-level object")
}

// --- 未知扩展成员的嵌套对象与数组：不参与标识也必须扫描 ---

func TestLoadReportBadCharsInsideUnknownExtensionRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("counterexample: x")
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		return strings.Replace(doc, `{"reportId"`,
			`{"mystery":{"nested":[{"deep":"x\uDC00y"}]},"reportId"`, 1)
	})
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	expectCorruptCharLoad(t, dir, id, data,
		"invalid Unicode escape", "unpaired low surrogate escape",
		".mystery.nested[0].deep")
}

func TestLoadReportInvalidUTF8InsideUnknownExtensionRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("counterexample: x")
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		return strings.Replace(doc, `{"reportId"`,
			`{"mystery":{"deep":"x`+"\xFF"+`y"},"reportId"`, 1)
	})
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	expectCorruptCharLoad(t, dir, id, data,
		"invalid character encoding", "UTF-8", ".mystery.deep")
}

// --- 反复读取始终拒绝，且不新增任何文件 ---

func TestLoadReportCharacterCorruptionRepeatedlyRejectedNoFiles(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("反例：�重入")
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		return strings.ReplaceAll(doc, string(replacementCharBytes), `\uD800`)
	})
	for i := 0; i < 2; i++ {
		if _, err := LoadReport(dir, id); err == nil {
			t.Fatal("repeated reads must keep rejecting the character-corrupt archive")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("failed reads must create no files, got %v", entries)
	}
}

// --- 错误三分类不变：字符损坏 ≠ 不存在 ≠ 请求标识不合法 ---

func TestLoadReportCharacterErrorClassDistinct(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("反例：�重入")
	corruptID := writeVariantArchiveText(t, dir, r, func(doc string) string {
		return strings.ReplaceAll(doc, string(replacementCharBytes), `\uD800`)
	})
	if _, err := LoadReport(dir, corruptID); err == nil {
		t.Fatal("expected corrupt error")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("character-corrupt archive -> expected errCorrupt, got %T: %v", err, err)
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

// --- diff：同一归档被用作任意一侧都拒绝整次比较，不输出已读成功一侧 ---

func TestDiffStoreRejectsCharacterCorruptionOnEitherSide(t *testing.T) {
	dir := t.TempDir()
	goodID := writeReportWithFreshID(t, dir, oneDefectFixture())
	// 另一侧是另一份合法报告（规则集合不同，标识不同），落盘文本再注入字符
	// 问题；改写后的标识与内容仍然相符。
	badID := writeVariantArchiveText(t, dir, oneRuleCharReport("反例：�重入"),
		func(doc string) string {
			return strings.ReplaceAll(doc, string(replacementCharBytes), `\uD800`)
		})
	if badID == goodID {
		t.Fatal("test setup: the two reports must have distinct ids")
	}

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
				t.Fatalf("diff must fail when a side is character-corrupt, got %+v", diff)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !reflect.DeepEqual(diff, DiffResult{}) {
				t.Fatalf("failed diff must return the zero result, got %+v", diff)
			}
			if !strings.Contains(err.Error(), badID) {
				t.Fatalf("error must name the corrupt side %q: %v", badID, err)
			}
			if !strings.Contains(err.Error(), "surrogate") {
				t.Fatalf("error must classify the character problem: %v", err)
			}
		})
	}
}

// --- audit 保存遇到同标识既有字符损坏归档：不能视为保存成功，原文件保留 ---

func TestSaveReportCharacterCorruptExistingArchiveNotTreatedAsSaved(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("反例：�重入")
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		return strings.ReplaceAll(doc, string(replacementCharBytes), `\uD800`)
	})
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 提交一份内容标识相同的合法报告（直接书写 U+FFFD）：已有归档字符损坏，
	// 保存必须失败，而不是把损坏文件当作“同标识已保存”。
	again := oneRuleCharReport("反例：�重入")
	again.ReportID = id
	if err := SaveReport(dir, again); err == nil {
		t.Fatal("a character-corrupt existing archive must not count as a successful save")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("expected errCorrupt, got %T: %v", err, err)
		}
		if !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "surrogate") {
			t.Fatalf("error must name the report id and the surrogate: %v", err)
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

// 并发落盘竞争中“抢先出现”的归档若字符损坏，同样按损坏失败并保留原文件。
func TestSaveReportRaceCharacterCorruptFileKept(t *testing.T) {
	dir := t.TempDir()
	legal := oneRuleCharReport("反例：�重入")
	legal.ReportID = ReportID(legal)
	data, err := json.Marshal(legal)
	if err != nil {
		t.Fatal(err)
	}
	corruptDoc := strings.ReplaceAll(string(data), string(replacementCharBytes), `\uD800`)
	finalPath := filepath.Join(dir, legal.ReportID+".json")
	saveReportHook = func(string) {
		os.WriteFile(finalPath, []byte(corruptDoc), 0o644)
	}
	defer func() { saveReportHook = nil }()

	if err := SaveReport(dir, legal); err == nil {
		t.Fatal("a racing character-corrupt archive must fail the save")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("expected errCorrupt, got %T: %v", err, err)
		}
	}
	kept, _ := os.ReadFile(finalPath)
	if string(kept) != corruptDoc {
		t.Fatal("the character-corrupt racing archive must be kept, not overwritten")
	}
}

// --- 合法字符继续正常读取，说明与证据保留解码后的原文 ---

func TestLoadReportLegalCharactersPreserved(t *testing.T) {
	const note = "  反例：攻击者可在 withdraw 中重入\n第二行证据  "
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, oneRuleCharReport(note))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("legal CJK/space/newline report must load: %v", err)
	}
	if loaded.Rules[0].Note != note || loaded.Findings[0].Evidence != note {
		t.Fatalf("decoded text must be preserved:\n note=%q\n evidence=%q\nwant %q",
			loaded.Rules[0].Note, loaded.Findings[0].Evidence, note)
	}
}

// 正确成对的代理转义与直接书写的同一字符读出后完全一致，标识也相同。
func TestLoadReportPairedEscapeEqualsLiteralCharacter(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("证据：😀 重入\n第二行  ")
	wantID := ReportID(r)
	emoji := []byte{0xF0, 0x9F, 0x98, 0x80}
	id := writeVariantArchiveText(t, dir, r, func(doc string) string {
		return strings.ReplaceAll(doc, string(emoji), `\uD83D\uDE00`)
	})
	if id != wantID {
		t.Fatalf("paired escapes decode to the same report id, got %s want %s", id, wantID)
	}
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("paired surrogate escapes are legal and must load: %v", err)
	}
	want := "证据：😀 重入\n第二行  "
	if loaded.Rules[0].Note != want || loaded.Findings[0].Evidence != want {
		t.Fatalf("decoded text = %q / %q, want %q", loaded.Rules[0].Note, loaded.Findings[0].Evidence, want)
	}
}

// 原文中合法存在的 U+FFFD 只是普通字符，读取时原样保留。
func TestLoadReportLiteralReplacementCharPreserved(t *testing.T) {
	dir := t.TempDir()
	note := "原有替换字符 � 保留"
	id := writeReportWithFreshID(t, dir, oneRuleCharReport(note))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a literal U+FFFD is ordinary legal content: %v", err)
	}
	if loaded.Rules[0].Note != note || loaded.Findings[0].Evidence != note {
		t.Fatalf("literal U+FFFD must be preserved: %q / %q", loaded.Rules[0].Note, loaded.Findings[0].Evidence)
	}
}

// “转义反斜线后接 uD800”只是普通文本，不得被误判成代理转义。
func TestLoadReportEscapedBackslashFollowedBySurrogateTextAccepted(t *testing.T) {
	dir := t.TempDir()
	note := `路径 C:\uD800\note`
	id := writeReportWithFreshID(t, dir, oneRuleCharReport(note))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("an escaped backslash before uD800 text is ordinary content: %v", err)
	}
	if loaded.Rules[0].Note != note || loaded.Findings[0].Evidence != note {
		t.Fatalf("ordinary text must be preserved verbatim: %q / %q",
			loaded.Rules[0].Note, loaded.Findings[0].Evidence)
	}
}
