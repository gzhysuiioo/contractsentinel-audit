package contractsentinel

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// 本文件锁定 Go 调用方“直接构造报告对象”保存时的字符合法性拒绝。
// JSON 提交侧（ParseAuditInput）与归档读取侧（loadStoredReport）的字符关只
// 作用于字节流：调用方手工构造 Report、绕过 JSON 解码直接交给 SaveReport 时，
// 字符串里的非法 UTF-8 字节一路畅通，而 json.Marshal 会先把坏字节静默替换成
// U+FFFD——无论是重算 reportId 还是写出归档。于是调用方即使预先算好了与替换
// 后内容相符的 reportId，也可能拿到“保存成功”，归档文字却已不是交来的原文。
//
// 因此保存前必须对内存对象逐字段做 UTF-8 检查：reportId、产物名称与哈希、
// 每条规则的完整定义和状态说明（不能只查正在产生缺陷的规则，通过/未检查/
// 没有缺陷记录的规则同样要查）、每条缺陷的全部绑定字段与证据。任何一处含
// 非法字节，整份报告按输入错误（errInvalid，而非工具缺失、超时或归档损坏）
// 拒绝，错误点名非法 UTF-8 与具体字段（数组字段带元素下标）；不创建原本不
// 存在的报告目录，已有目录不新增报告或临时文件，调用方对象与既有归档都保持
// 原样。合法中文、表情、原文中的 U+FFFD、前后空格与换行继续允许，保存与读
// 回逐字保留，不修剪、不替换。

// expectInvalidUTF8Save 断言坏字节报告的完整保存契约：errInvalid 且错误明确
// 指出非法 UTF-8 与字段位置；返回 nil 错误以外不产生任何副作用。
func expectInvalidUTF8Save(t *testing.T, dir string, r Report, wantSubstrings ...string) {
	t.Helper()
	before := deepCopyReport(r)
	err := SaveReport(dir, r)
	if err == nil {
		t.Fatalf("a report containing invalid UTF-8 must be rejected as an input error, object: %+v", r)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("invalid UTF-8 in the submitted object must classify as errInvalid, got %T: %v", err, err)
	}
	var ec errCorrupt
	if errors.As(err, &ec) {
		t.Fatalf("encoding of the new submission must not be reported as a corrupt archive: %v", err)
	}
	msg := err.Error()
	for _, want := range append([]string{"invalid UTF-8"}, wantSubstrings...) {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
	// Rejection must not mutate the caller's object.
	if !reflect.DeepEqual(r, before) {
		t.Fatalf("rejected save must leave the caller's report untouched:\nbefore=%+v\nafter =%+v", before, r)
	}
}

func deepCopyReport(r Report) Report {
	cp := r
	if r.Rules != nil {
		cp.Rules = make([]ReportRule, len(r.Rules))
		copy(cp.Rules, r.Rules)
	}
	if r.Findings != nil {
		cp.Findings = make([]ReportFinding, len(r.Findings))
		copy(cp.Findings, r.Findings)
	}
	return cp
}

// --- 核心场景：note 与 evidence 在“反例：”后都夹单个 0xff，reportId 已算好 ---

func TestSaveReportInvalidUTF8InNoteAndEvidenceRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "store")
	bad := "反例：\xff重入"
	r := oneRuleCharReport(bad)
	// 调用方可以预先算出 reportId：ReportID 内部的 json.Marshal 会把 0xff
	// 替换成 U+FFFD，所以该 id 与“替换后内容”相符——保存仍必须失败，且
	// 归档中绝不能出现 U+FFFD 版本。
	r.ReportID = ReportID(r)
	if strings.ContainsRune(r.ReportID, '\xff') {
		t.Fatal("test setup: the computed id must be hex, not raw content")
	}
	expectInvalidUTF8Save(t, dir, r,
		"invalid byte 0xff", "rules[0].note")
	// 规则说明先于缺陷证据被检查，证据字段同样非法时错误应先点到规则位置。
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("a rejected save must not create the store directory: %v", statErr)
	}
}

// 即便错误先点到规则说明，证据中的同一坏字节也必须独立可定位。
func TestSaveReportInvalidUTF8InEvidenceOnlyRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneRuleCharReport("counterexample: x")
	r.Findings[0].Evidence = "反例：\xff重入"
	r.ReportID = ReportID(r)
	expectInvalidUTF8Save(t, dir, r,
		"invalid byte 0xff", "findings[0].evidence")
}

// --- 顶层与产物字段 ---

func TestSaveReportInvalidUTF8TopAndArtifactFieldsRejected(t *testing.T) {
	base := func() Report {
		r := oneRuleCharReport("counterexample: x")
		r.ReportID = ReportID(r)
		return r
	}
	for _, tc := range []struct {
		name   string
		field  string
		mutate func(*Report)
	}{
		{"report id", "reportId", func(r *Report) { r.ReportID = strings.Repeat("f", 63) + "\xff" }},
		{"artifact name", "artifact.name", func(r *Report) { r.Artifact.Name = "Vault\xff" }},
		{"artifact hash", "artifact.hash", func(r *Report) { r.Artifact.Hash = strings.Repeat("a", 63) + "\xff" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			r := base()
			tc.mutate(&r)
			expectInvalidUTF8Save(t, dir, r, tc.field, "invalid byte 0xff")
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("rejected save must add no files, got %v", entries)
			}
		})
	}
}

// --- 规则数组：元素位置必须准确，且通过/未检查/无缺陷记录的规则也要查 ---

func TestSaveReportInvalidUTF8InRuleFieldsRejected(t *testing.T) {
	// 三条规则：通过、发现缺陷、未检查。坏字节放进任何一条、任何字段都必须
	// 整份拒绝；放在第二条时错误下标为 rules[1]。
	legalRule := func(id, status, note string) ReportRule {
		return ReportRule{ID: id, Kind: "static", Severity: "high", Invariant: "inv-" + id,
			Version: "1", Status: status, Note: note}
	}
	hash := ArtifactHash(sampleArtifact())
	build := func() Report {
		return Report{
			Artifact: ReportArtifact{Name: "Vault", Hash: hash},
			Rules: []ReportRule{
				legalRule("r-pass", StatusPass, "备注通过"),
				legalRule("r-bad", StatusDefect, "反例 x"),
				legalRule("r-none", StatusUnchecked, ""),
			},
			Findings: []ReportFinding{
				{ArtifactHash: hash, RuleID: "r-bad", Version: "1", Severity: "high",
					Invariant: "inv-r-bad", Evidence: "反例 x"},
			},
		}
	}
	cases := []struct {
		name   string
		field  string
		index  int
		mutate func(*ReportRule)
	}{
		{"rule id", "id", 1, func(r *ReportRule) { r.ID = "r-bad\xff" }},
		{"rule kind", "kind", 1, func(r *ReportRule) { r.Kind = "static\xff" }},
		{"rule severity", "severity", 0, func(r *ReportRule) { r.Severity = "high\xff" }},
		{"rule invariant", "invariant", 2, func(r *ReportRule) { r.Invariant = "inv-r-none\xff" }},
		{"rule version", "version", 0, func(r *ReportRule) { r.Version = "1\xff" }},
		{"rule status", "status", 2, func(r *ReportRule) { r.Status = "未检查\xff" }},
		{"passing rule note", "note", 0, func(r *ReportRule) { r.Note = "备注通过\xff" }},
		{"unchecked rule note", "note", 2, func(r *ReportRule) { r.Note = "稍后补查\xff" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			r := build()
			tc.mutate(&r.Rules[tc.index])
			// 让其余结构与改写后内容自洽（id 一并重算），证明拒绝只来自字符关。
			r.ReportID = ReportID(r)
			expectInvalidUTF8Save(t, dir, r,
				"invalid byte 0xff",
				"rules["+strconv.Itoa(tc.index)+"]."+tc.field)
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("rejected save must leave the empty store empty, got %v", entries)
			}
		})
	}
}

// --- 缺陷数组：全部绑定字段与证据都要查，元素位置准确 ---

func TestSaveReportInvalidUTF8InFindingFieldsRejected(t *testing.T) {
	build := func() Report {
		r := oneRuleCharReport("反例 x")
		r.ReportID = ReportID(r)
		return r
	}
	cases := []struct {
		name   string
		field  string
		mutate func(*ReportFinding)
	}{
		{"finding artifact hash", "artifactHash", func(f *ReportFinding) { f.ArtifactHash = strings.Repeat("b", 63) + "\xff" }},
		{"finding rule id", "ruleId", func(f *ReportFinding) { f.RuleID = "r1\xff" }},
		{"finding version", "version", func(f *ReportFinding) { f.Version = "1\xff" }},
		{"finding severity", "severity", func(f *ReportFinding) { f.Severity = "high\xff" }},
		{"finding invariant", "invariant", func(f *ReportFinding) { f.Invariant = "inv\xff" }},
		{"finding evidence", "evidence", func(f *ReportFinding) { f.Evidence = "反例 x\xff" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			r := build()
			tc.mutate(&r.Findings[0])
			expectInvalidUTF8Save(t, dir, r,
				"invalid byte 0xff", "findings[0]."+tc.field)
		})
	}
}

// --- 没有规则、没有缺陷记录的报告也逃不过检查（reportId/产物字段已在前面覆盖）---

func TestSaveReportInvalidUTF8CheckedWithoutRulesOrFindings(t *testing.T) {
	dir := t.TempDir()
	r := Report{
		Artifact: ReportArtifact{Name: "Vault\xff", Hash: ArtifactHash(sampleArtifact())},
		Rules:    []ReportRule{},
		Findings: []ReportFinding{},
	}
	r.ReportID = ReportID(r)
	expectInvalidUTF8Save(t, dir, r, "artifact.name")
}

// --- 已有归档保持原样，已有目录不新增任何文件（含临时文件）---

func TestSaveReportInvalidUTF8KeepsExistingArchiveAndAddsNoFiles(t *testing.T) {
	dir := t.TempDir()
	good := oneDefectFixture()
	goodID := writeReportWithFreshID(t, dir, good)
	goodPath := filepath.Join(dir, goodID+".json")
	before, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatal(err)
	}
	entriesBefore, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	bad := oneRuleCharReport("反例：\xff重入")
	bad.ReportID = ReportID(bad)
	// 与既有归档标识不同，证明拒绝不是撞车而是编码问题。
	if bad.ReportID == goodID {
		t.Fatal("test setup: bad report must have a distinct id")
	}
	if err := SaveReport(dir, bad); err == nil {
		t.Fatal("invalid UTF-8 submission must fail against an existing store")
	} else {
		var ei errInvalid
		if !errors.As(err, &ei) {
			t.Fatalf("expected errInvalid, got %T: %v", err, err)
		}
		if strings.Contains(err.Error(), StatusToolMissing) ||
			strings.Contains(err.Error(), StatusTimeout) ||
			strings.Contains(err.Error(), StatusDefect) {
			t.Fatalf("an encoding input error must not be reported as a check conclusion: %v", err)
		}
	}
	after, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatalf("existing archive must remain readable: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("existing archive bytes must be untouched")
	}
	entriesAfter, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entriesAfter) != len(entriesBefore) {
		t.Fatalf("failed save must add neither report nor temp file: before %d entries, after %d",
			len(entriesBefore), len(entriesAfter))
	}
	for _, e := range entriesAfter {
		if strings.HasPrefix(e.Name(), ".report-") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("a temp file must not be left behind: %s", e.Name())
		}
	}
}

// --- 合法文字：保存后读回逐字保留，不修剪、不替换 ---

func TestSaveReportLegalCharactersRoundTripVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name string
		note string
	}{
		{"cjk and surrounding whitespace and newline", "  反例：攻击者可在 withdraw 中重入\n第二行证据  "},
		{"emoji", "证据：😀 重入\n第二行  "},
		{"literal replacement character", "原有替换字符 � 原样保留"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			r := oneRuleCharReport(tc.note)
			r.ReportID = ReportID(r)
			if err := SaveReport(dir, r); err != nil {
				t.Fatalf("legal text must save: %v", err)
			}
			loaded, err := LoadReport(dir, r.ReportID)
			if err != nil {
				t.Fatalf("saved legal report must load: %v", err)
			}
			if loaded.Artifact.Name != r.Artifact.Name {
				t.Fatalf("artifact name changed: %q want %q", loaded.Artifact.Name, r.Artifact.Name)
			}
			if loaded.Rules[0].Note != tc.note || loaded.Findings[0].Evidence != tc.note {
				t.Fatalf("text must round-trip verbatim:\n note=%q\n evidence=%q\nwant %q",
					loaded.Rules[0].Note, loaded.Findings[0].Evidence, tc.note)
			}
			// U+FFFD may only appear where the caller literally put it.
			if strings.Count(tc.note, "�") != strings.Count(loaded.Rules[0].Note, "�") {
				t.Fatal("no character may be replaced with U+FFFD")
			}
		})
	}
}
