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

// 本文件锁定“归档读取”侧对缺陷说明的空白校验。审计提交早已要求“发现缺陷”
// 结论带非空白说明（BuildReport 对非通过状态拒绝 TrimSpace 后为空的 note），
// 但归档读取曾经存在缺口：把一条缺陷规则的 note 改成只有空格、制表符或换行
// 的字符串，同时把对应 finding 的 evidence 保存为同一段空白，产物哈希、规则
// 版本、其余绑定和重新计算的报告标识全部吻合，这样的报告会被当成合法读回。
//
// 修正后，凡“发现缺陷”规则的 note 是非空字符串却完全由空白组成（空白范围沿
// 用提交侧的 strings.TrimSpace 判断），整份归档判为损坏：错误点名请求的报告
// 标识、所属规则并指出缺陷说明为空白；evidence 与 note 逐字相同、报告标识与
// 内容一致都不能让它通过；同一份报告里的其他合法规则与缺陷也不能略过坏记录
// 后部分返回。布尔不变式报告原有的证据形式保留：只提交不变式值 false 时缺陷
// 规则没有 note，证据是 invariant <名> does not hold，这种报告仍正常读回；
// 省略 note 与显式空字符串按既有规则处理，不一律要求缺陷规则带外部说明。

// blankDefectNoteFixture 返回一份三规则合法报告：一条通过、一条带外部说明的
// 缺陷、一条未检查，外加一条独立的合法缺陷规则，用来证明坏记录不能被略过后
// 部分返回。
func blankDefectNoteFixture() Report {
	hash := ArtifactHash(sampleArtifact())
	return Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r-pass", Kind: "static", Severity: "medium", Invariant: "inv-pass", Version: "1", Status: StatusPass},
			{ID: "r-bad", Kind: "static", Severity: "high", Invariant: "inv-bad", Version: "2", Status: StatusDefect, Note: "counterexample: x"},
			{ID: "r-none", Kind: "symbolic", Severity: "low", Invariant: "inv-none", Version: "3", Status: StatusUnchecked},
			{ID: "r-good-defect", Kind: "static", Severity: "low", Invariant: "inv-good", Version: "4", Status: StatusDefect, Note: "counterexample: y"},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r-bad", Version: "2", Severity: "high", Invariant: "inv-bad", Evidence: "counterexample: x"},
			{ArtifactHash: hash, RuleID: "r-good-defect", Version: "4", Severity: "low", Invariant: "inv-good", Evidence: "counterexample: y"},
		},
	}
}

// blankOutDefectNote 把 r-bad 的 note 改成纯空白串，并把对应 finding 的
// evidence 改成同一段空白：归档其余部分（产物哈希、版本、绑定、重算标识）
// 全部自洽，拒绝只能来自空白说明校验。
func blankOutDefectNote(blank string) func(*Report) {
	return func(stored *Report) {
		for i := range stored.Rules {
			if stored.Rules[i].ID == "r-bad" {
				stored.Rules[i].Note = blank
			}
		}
		for i := range stored.Findings {
			if stored.Findings[i].RuleID == "r-bad" {
				stored.Findings[i].Evidence = blank
			}
		}
	}
}

// expectCorruptBlankNoteLoad 断言空白缺陷说明的完整读取契约：errCorrupt，
// 错误点名请求的报告标识、所属规则并指出说明为空白；不返回部分报告；原归档
// 逐字保留。
func expectCorruptBlankNoteLoad(t *testing.T, dir, id, rule string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("a whitespace-only defect note must reject the whole archive, got %+v", got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("blank defect note classifies as errCorrupt, got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, id) {
		t.Fatalf("error must name the requested report id %q: %v", id, err)
	}
	if !strings.Contains(msg, rule) {
		t.Fatalf("error must name the owning rule %q: %v", rule, err)
	}
	if !strings.Contains(msg, "blank") {
		t.Fatalf("error must state the defect note is blank: %v", err)
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

// --- 核心场景：note 与 evidence 同为纯空白、标识与内容吻合，也必须整份拒绝 ---

func TestLoadReportRejectsBlankDefectNote(t *testing.T) {
	for _, blank := range []string{" ", "\t", "\n", "   ", " \t\n ", "\t\t\n\n"} {
		t.Run("note="+strings.NewReplacer(" ", "␣", "\t", `\t`, "\n", `\n`).Replace(blank), func(t *testing.T) {
			dir := t.TempDir()
			id := storeAndCorrupt(t, dir, blankDefectNoteFixture(), blankOutDefectNote(blank))

			// 归档内 reportId、请求 id 与按内容重算的 id 三者一致，且 evidence
			// 与 note 逐字相同：拒绝只能来自空白说明校验。
			data, err := os.ReadFile(filepath.Join(dir, id+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var onDisk Report
			if err := json.Unmarshal(data, &onDisk); err != nil {
				t.Fatal(err)
			}
			if onDisk.ReportID != id || ReportID(onDisk) != id {
				t.Fatalf("test setup: id must match corrupt content, onDisk=%q recomputed=%q requested=%q",
					onDisk.ReportID, ReportID(onDisk), id)
			}
			expectCorruptBlankNoteLoad(t, dir, id, "r-bad")
		})
	}
}

// 同一份报告中的其他合法规则与合法缺陷不能挽救坏记录：整份拒绝，不部分返回。
func TestLoadReportBlankDefectNoteRejectsWholeReport(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, blankDefectNoteFixture(), blankOutDefectNote("  \t "))
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("other legal rules and findings must not rescue a blank defect note, got %+v", got)
	}
	if !reflect.DeepEqual(got, Report{}) {
		t.Fatalf("the bad record must not be skipped to return the rest, got %+v", got)
	}
	if !strings.Contains(err.Error(), "r-bad") {
		t.Fatalf("error must name the blank-note rule, got: %v", err)
	}
}

// 重复读取始终拒绝，且不创建任何额外文件。
func TestLoadReportBlankDefectNoteRepeatedRejectionCreatesNoFiles(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, blankDefectNoteFixture(), blankOutDefectNote("\n\n"))
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := LoadReport(dir, id); err == nil {
			t.Fatal("repeated reads must keep rejecting the archive")
		}
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("failed reads must create no files, got %v", after)
	}
}

// --- 保留布尔不变式报告的证据形式：无 note 与显式空串都正常读回 ---

// 只提交不变式值 false 生成的缺陷规则没有 note，证据是自动生成形式；显式把
// note 写成空字符串（规范形式与省略相同，标识不变）也必须按既有规则读回，
// 不能被当成“空白说明”拒绝，也不能被要求补写外部说明。
func TestLoadReportEmptyNoteDefectKeepsAutogenEvidence(t *testing.T) {
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

	// 把规则对象的 note 显式写成空字符串；omitempty 使规范形式不变，标识保持。
	path := filepath.Join(dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(data), `"status":"发现缺陷"}`, `"status":"发现缺陷","note":""}`, 1)
	if doc == string(data) {
		t.Fatal("test setup: explicit empty note injection did not change the archive")
	}
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("an explicit empty-string defect note keeps the existing rules and must load: %v", err)
	}
	if loaded.Rules[0].Note != "" {
		t.Fatalf("explicit empty note must read back empty, got %q", loaded.Rules[0].Note)
	}
	if got := loaded.Findings[0].Evidence; got != "invariant inv does not hold" {
		t.Fatalf("evidence must stay the invariant form, got %q", got)
	}
}

// 合法的含空白外部说明（中文、换行、前后空格，含非空白内容）逐字保留，
// 不因空白校验被拒绝；标识与证据保持原值。
func TestLoadReportDefectNoteWithWhitespaceContentPreserved(t *testing.T) {
	dir := t.TempDir()
	note := "  反例：重入路径仍可达\n\t第二行证据  "
	r := blankDefectNoteFixture()
	for i := range r.Rules {
		if r.Rules[i].ID == "r-bad" {
			r.Rules[i].Note = note
		}
	}
	for i := range r.Findings {
		if r.Findings[i].RuleID == "r-bad" {
			r.Findings[i].Evidence = note
		}
	}
	id := writeReportWithFreshID(t, dir, r)
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal note with non-blank content must load: %v", err)
	}
	if loaded.ReportID != id {
		t.Fatalf("report id must be preserved: %q vs %q", loaded.ReportID, id)
	}
	for _, rule := range loaded.Rules {
		if rule.ID == "r-bad" && rule.Note != note {
			t.Fatalf("note must read back verbatim:\n got %q\nwant %q", rule.Note, note)
		}
	}
	if got := loaded.Findings[0].Evidence; got != note {
		t.Fatalf("evidence must read back verbatim:\n got %q\nwant %q", got, note)
	}
}

// --- diff：任一侧归档带空白缺陷说明都整体失败，不输出比较分类或统计 ---

func TestDiffStoreRejectsBlankDefectNoteEitherSide(t *testing.T) {
	dir := t.TempDir()
	goodID := writeReportWithFreshID(t, dir, oneDefectFixture())
	badID := storeAndCorrupt(t, dir, blankDefectNoteFixture(), blankOutDefectNote(" \t\n"))
	badPath := filepath.Join(dir, badID+".json")
	badBytes, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
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
				t.Fatalf("diff must fail when a side carries a blank defect note, got %+v", diff)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), badID) || !strings.Contains(err.Error(), "r-bad") ||
				!strings.Contains(err.Error(), "blank") {
				t.Fatalf("error must name the corrupt report, the rule and the blank note: %v", err)
			}
			if !reflect.DeepEqual(diff, DiffResult{}) {
				t.Fatalf("failed diff must return the zero result, got %+v", diff)
			}
		})
	}

	// 失败的比较不得修复、覆盖损坏侧归档。
	kept, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != string(badBytes) {
		t.Fatal("failed diff must leave the corrupt archive untouched")
	}
}

// --- 保存路径：直接构造的空白说明报告在落盘前作为提交无效拒绝 ---
//
// 空白说明校验与归档读取共用同一份合法性定义（validateReport），因此一份
// 手工构造、缺陷规则带纯空白说明的报告在任何存储操作前被 errInvalid 拒绝，
// 且不创建存储目录；不存在“先落盘、读取时才被发现”的窗口。
func TestSaveReportRejectsBlankDefectNoteReport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	r := blankDefectNoteFixture()
	blankOutDefectNote(" \t ")(&r)
	r.ReportID = ReportID(r)
	err := SaveReport(dir, r)
	if err == nil {
		t.Fatal("a hand-built report with a blank defect note must be rejected before saving")
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "r-bad") || !strings.Contains(err.Error(), "blank") {
		t.Fatalf("error must name the rule and the blank note: %v", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("rejected submission must not create the store: %v", statErr)
	}
}
