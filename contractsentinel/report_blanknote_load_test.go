package contractsentinel

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 本文件锁定读取侧对“发现缺陷”规则说明的校验缺口：审计提交一直要求外部
// 检查器对缺陷给出非空白说明，但归档读取此前只核对 finding 证据是否与
// note 逐字一致——一条缺陷规则的 note 只有空格、制表符或换行、finding 的
// evidence 也保存同样的空白时，只要产物哈希、规则版本、其他绑定和重算的
// 报告标识吻合，整份报告仍会被接受。现在这种归档必须判为损坏。
//
// 与此同时，只由不变式布尔值生成的缺陷报告没有 note，证据为
// “invariant <不变式名> does not hold”，必须照常读回；省略 note 与显式
// 空字符串都不是“空白说明”。

// blankDefectNoteCases 覆盖“非空但完全由空白组成”的各种写法：判定空白的
// 口径与提交侧一致，即 strings.TrimSpace 为空。
var blankDefectNoteCases = map[string]string{
	"spaces":      "   ",
	"tab":         "\t",
	"newlines":    "\n\n",
	"carriage":    "\r\n",
	"mixed":       " \t\r\n ",
	"ideographic": "　", // U+3000 全角空格同样是空白
}

// blankNoteCorruptReport 构造一份“id 与内容完全相符”的损坏归档：先写出
// oneDefectFixture 的合法归档，再把唯一缺陷规则的 note 与对应 finding 的
// evidence 同时改成同一段空白并重算报告标识。这样读回时产物哈希、规则
// 版本、严重级别、不变式、证据逐字一致以及报告标识全部吻合，唯一的不合法
// 之处就是缺陷说明完全由空白组成。
func blankNoteCorruptReport(t *testing.T, dir, blank string) string {
	t.Helper()
	return storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		for i := range stored.Rules {
			if stored.Rules[i].ID == "r-bad" {
				stored.Rules[i].Note = blank
			}
		}
		stored.Findings[0].Evidence = blank
	})
}

// 各种纯空白说明：即使 evidence 与 note 逐字相同、报告标识与内容一致，
// 读取也必须把整份归档判为损坏，而不是当成未提供说明或补写自动证据。
func TestLoadReportRejectsBlankDefectNote(t *testing.T) {
	for name, blank := range blankDefectNoteCases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			id := blankNoteCorruptReport(t, dir, blank)

			loaded, err := LoadReport(dir, id)
			if err == nil {
				t.Fatalf("a whitespace-only defect note must corrupt the archive: %+v", loaded)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("blank defect note is archive corruption, got %T: %v", err, err)
			}
			msg := err.Error()
			for _, want := range []string{id, "r-bad", "blank defect note"} {
				if !strings.Contains(msg, want) {
					t.Fatalf("error must name %q, got: %v", want, err)
				}
			}
			if !reflect.DeepEqual(loaded, Report{}) {
				t.Fatalf("rejected read must return no partial report, got %+v", loaded)
			}
		})
	}
}

// 纯空白 note 的拒绝必须发生在证据比对之前：即使把 evidence 改写成与空白
// 不同的自动证据模板，错误仍然是“空白说明”，而不是证据不匹配。
func TestLoadReportBlankDefectNoteRejectedBeforeEvidence(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		for i := range stored.Rules {
			if stored.Rules[i].ID == "r-bad" {
				stored.Rules[i].Note = "   "
			}
		}
		stored.Findings[0].Evidence = "invariant inv-bad does not hold"
	})
	_, err := LoadReport(dir, id)
	if err == nil {
		t.Fatal("a whitespace-only defect note must be rejected even with auto-style evidence")
	}
	if !strings.Contains(err.Error(), "blank defect note") {
		t.Fatalf("rejection must be the blank-note rule, not an evidence mismatch: %v", err)
	}
}

// 一份报告里同时存在其他合法规则与合法缺陷时，坏记录不能被略过后返回
// 其余内容：整份归档都得判为损坏。
func TestLoadReportBlankNoteRejectsWholeArchive(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		// r-bad 的 note/evidence 都改成空白；r-pass 与 r-none 仍完全合法。
		for i := range stored.Rules {
			if stored.Rules[i].ID == "r-bad" {
				stored.Rules[i].Note = "\t\n "
			}
		}
		stored.Findings[0].Evidence = "\t\n "
	})
	loaded, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("the whole archive must be rejected, got %+v", loaded)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T: %v", err, err)
	}
	if !reflect.DeepEqual(loaded, Report{}) {
		t.Fatalf("no partial report may be returned, got %+v", loaded)
	}
}

// 拒绝只针对读取：归档字节保持原样，重复读取行为一致，也不产生额外文件。
func TestLoadReportBlankNoteKeepsArchiveUntouched(t *testing.T) {
	dir := t.TempDir()
	id := blankNoteCorruptReport(t, dir, " \n\t ")
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := LoadReport(dir, id); err == nil {
			t.Fatal("repeated reads must keep rejecting the archive")
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("a failed read must not rewrite or repair the archive")
	}
}

// 含非空白内容的外部说明（中文、换行、前后空格）逐字保留，不能被本次校验
// 误拒；证据与报告标识保持原值。
func TestLoadReportAcceptsNonBlankNoteWithWhitespace(t *testing.T) {
	dir := t.TempDir()
	note := "  反例：调用 withdraw 后重入\n第二行说明  "
	id := writeReportWithFreshID(t, dir, oneDefectFixtureWithNote(note))

	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal note containing non-whitespace text must load: %v", err)
	}
	if got := loaded.Rules[1].Note; got != note {
		t.Fatalf("note must survive verbatim: got %q want %q", got, note)
	}
	if got := loaded.Findings[0].Evidence; got != note {
		t.Fatalf("evidence must stay the verbatim note: got %q want %q", got, note)
	}
}

// oneDefectFixtureWithNote returns oneDefectFixture with the defect note and
// the matching finding evidence replaced by note.
func oneDefectFixtureWithNote(note string) Report {
	r := oneDefectFixture()
	for i := range r.Rules {
		if r.Rules[i].ID == "r-bad" {
			r.Rules[i].Note = note
		}
	}
	r.Findings[0].Evidence = note
	return r
}

// 布尔不变式报告：规则完全没有 note，证据为自动模板，照常读回（写盘时
// omitempty 会省略 note 成员）。
func TestLoadReportBlankNoteCheckKeepsOmittedNoteForm(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: "invariant inv does not hold"},
		},
	}
	id := writeReportWithFreshID(t, dir, report)
	if _, err := LoadReport(dir, id); err != nil {
		t.Fatalf("a note-less boolean defect report must load: %v", err)
	}
}

// 显式写成 "note":"" 的缺陷规则与省略 note 等价：配合自动证据时是合法
// 报告，不能被当成“空白说明”。这里手工写 JSON，因为 ReportRule 的
// omitempty 会让编组结果省略空 note。
func TestLoadReportExplicitEmptyNoteKeepsAutogenEvidence(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: "invariant inv does not hold"},
		},
	}
	id := writeReportWithFreshID(t, dir, report)
	path := filepath.Join(dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	old := `"status":"发现缺陷"`
	withEmptyNote := strings.Replace(doc, old, old+`,"note":""`, 1)
	if withEmptyNote == doc {
		t.Fatal("test setup: status field not found to inject the empty note")
	}
	if err := os.WriteFile(path, []byte(withEmptyNote), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("an explicit empty defect note with auto evidence must load: %v", err)
	}
	if loaded.Rules[0].Note != "" {
		t.Fatalf("empty note must read back as empty, got %q", loaded.Rules[0].Note)
	}
	if loaded.Findings[0].Evidence != "invariant inv does not hold" {
		t.Fatalf("auto evidence must be preserved: %q", loaded.Findings[0].Evidence)
	}
}

// 直接构造的 Go 报告带纯空白缺陷说明时，SaveReport 必须把它作为输入错误
// （errInvalid，而非归档损坏）拒绝，且不创建任何归档文件。
func TestSaveReportRejectsBlankDefectNoteAsInputError(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	r := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r-bad", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect, Note: "  \n\t "},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r-bad", Version: "1", Severity: "high", Invariant: "inv", Evidence: "  \n\t "},
		},
	}
	r.ReportID = ReportID(r)
	err := SaveReport(dir, r)
	if err == nil {
		t.Fatal("SaveReport must reject a whitespace-only defect note")
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("a direct-constructed blank note is an input error, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "blank defect note") {
		t.Fatalf("error must describe the blank note: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a rejected save must create no archive, got %v", entries)
	}
}

// diff 任一侧归档含纯空白缺陷说明时，比较必须整体失败：不返回任何分类或
// 统计，合法一侧的内容也不能作为局部结果露出。
func TestDiffStoreRejectsBlankDefectNoteEitherSide(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}}

	good := saveCheckReport(t, dir, artifact, rules, []CheckRecord{
		{ArtifactHash: hash, RuleID: "r1", Version: "1", Status: StatusDefect, Note: "真实反例"},
	})
	corruptID := blankNoteCorruptReport(t, dir, " \t\n")

	for _, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"after corrupt", good.ReportID, corruptID},
		{"before corrupt", corruptID, good.ReportID},
		{"both corrupt", corruptID, corruptID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DiffStore(dir, tc.before, tc.after)
			if err == nil {
				t.Fatalf("diff must fail against a blank-note archive: %+v", got)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("blank-note archive is corruption, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), corruptID) || !strings.Contains(err.Error(), "r-bad") {
				t.Fatalf("error must name the corrupt report and rule: %v", err)
			}
			if !reflect.DeepEqual(got, DiffResult{}) {
				t.Fatalf("a failed diff must return no partial result, got %+v", got)
			}
		})
	}
}

// 合法侧的说明含中文、换行和前后空格时，既有比较分类与统计保持原值。
func TestDiffStoreLegalWhitespaceNoteUnchanged(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}}
	note := "  反例：第一行\n第二行  "
	before := saveCheckReport(t, dir, artifact, rules, []CheckRecord{
		{ArtifactHash: hash, RuleID: "r1", Version: "1", Status: StatusDefect, Note: note},
	})
	after := saveCheckReport(t, dir, artifact, rules, []CheckRecord{
		{ArtifactHash: hash, RuleID: "r1", Version: "1", Status: StatusDefect, Note: note},
	})
	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("identical legal notes must diff cleanly: %v", err)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeNoChange || diff.Summary.NoChange != 1 {
		t.Fatalf("legal verbatim notes must stay 无变化: %+v", diff)
	}
	if diff.Results[0].Before.Finding.Evidence != note ||
		diff.Results[0].After.Finding.Evidence != note {
		t.Fatal("evidence must remain the verbatim note on both sides")
	}
}
