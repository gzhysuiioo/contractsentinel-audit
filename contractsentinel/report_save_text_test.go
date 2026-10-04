package contractsentinel

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 本文件锁定 Go 调用方“直接构造报告对象并交给 SaveReport”这一路径的文本
// 合法性。JSON 提交 (ParseAuditInput) 与归档读取 (loadStoredReport) 早已在
// JSON 字节上拒绝非法字符，但直接构造的 Report 从未经过 JSON 解码：其字符串
// 可以携带任意字节，而 encoding/json 编组时不报错、会把非法 UTF-8 字节悄悄
// 换成 U+FFFD；ReportID 又从同一份被改写的规范形式算出，于是报告标识与
// 规则/缺陷归属全部对得上，保存返回成功，归档里的文字却已不是调用方交来的
// 文字。保存成功必须表示归档文字与调用方的合法文字逐字一致，因此 SaveReport
// 在任何文件系统操作之前先对原始对象的每个字符串做 UTF-8 检查：
//   - 非法字节一律按输入错误 (errInvalid) 拒绝，错误说明非法 UTF-8 并点名字段；
//   - 规则与缺陷数组中的字段带元素位置，区分具体记录；
//   - 不只检查产生缺陷的规则：通过、未检查、没有缺陷记录的报告同样适用；
//   - 调用方即使已自行算出 reportId、note 与 evidence 带有完全相同的坏字节，
//     也不能获得成功；
//   - 拒绝不改调用方对象；报告目录原本不存在时不创建，已有目录不新增报告或
//     临时文件，已有归档保持原样；
//   - 合法中文、表情、原文中的 U+FFFD、前后空格与换行保存与读回均保留原文。

// saveTextBaseReport 构造一份结构合法的报告：r1 为“发现缺陷”（带说明与
// 证据），r2 为“通过”（带说明），r3 为“未检查”（无说明）。各字段均为
// 合法 UTF-8，供用例按字段注入坏字节。
func saveTextBaseReport() Report {
	hash := ArtifactHash(sampleArtifact())
	return Report{
		Artifact: ReportArtifact{Name: "Vault 金库", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv-1", Version: "1.0.0", Status: StatusDefect, Note: "反例：重入路径"},
			{ID: "r2", Kind: "static", Severity: "low", Invariant: "inv-2", Version: "2.0.0", Status: StatusPass, Note: "检查通过说明"},
			{ID: "r3", Kind: "symbolic", Severity: "medium", Invariant: "inv-3", RequiresABI: true, Version: "3.0.0", Status: StatusUnchecked},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1.0.0", Severity: "high", Invariant: "inv-1", Evidence: "反例：重入路径"},
		},
	}
}

// withFreshID 补算报告标识（对含坏字节的报告，标识是按 U+FFFD 改写后的规范
// 形式算出的——这正是只靠标识与归属检查无法发现编码问题的原因）。
func withFreshID(r Report) Report {
	r.ReportID = ReportID(r)
	return r
}

// expectInvalidUTF8Rejection 断言一次保存因非法 UTF-8 被干净拒绝：
// errInvalid、错误点名非法 UTF-8 与具体字段路径，且不产生任何副作用。
func expectInvalidUTF8Rejection(t *testing.T, dir string, r Report, wantField string) {
	t.Helper()
	before := r
	err := SaveReport(dir, r)
	if err == nil {
		t.Fatalf("invalid UTF-8 in %s must reject the whole report", wantField)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("%s: rejection must be an input error (errInvalid), got %T: %v", wantField, err, err)
	}
	var ec errCorrupt
	if errors.As(err, &ec) {
		t.Fatalf("%s: encoding input must not be misreported as archive corruption: %v", wantField, err)
	}
	msg := err.Error()
	for _, want := range []string{"invalid UTF-8 byte 0xff", wantField} {
		if !strings.Contains(msg, want) {
			t.Fatalf("%s: error %q must contain %q", wantField, msg, want)
		}
	}
	// 不得误报成工具缺失、检查超时或合约缺陷语义。
	if !reflect.DeepEqual(r, before) {
		t.Fatalf("%s: rejected save must not modify the caller's report object", wantField)
	}
}

// --- 核心场景：说明与证据在“反例：”后均夹有单个 0xff，reportId 已由调用方 ---
// --- 算好且与归属对应，保存仍须失败，目录原本不存在时不创建，无 U+FFFD 归档 ---

func TestSaveReportInvalidUTF8InNoteAndEvidenceRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "missing-store")
	hash := ArtifactHash(sampleArtifact())
	badText := "反例：\xff重入"
	r := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect, Note: badText},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: badText},
		},
	}
	r.ReportID = ReportID(r) // 调用方已自行算出标识；两处文本被同样改写，标识仍对应。

	expectInvalidUTF8Rejection(t, dir, r, "rules[0].note")

	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("rejected save must not create the report directory: %v", statErr)
	}
	// 对象中的坏字节必须原样保留，不能被就地换成 U+FFFD 的三字节编码。
	if r.Rules[0].Note != badText || r.Findings[0].Evidence != badText {
		t.Fatalf("caller strings must be untouched:\n note=%q\n evidence=%q", r.Rules[0].Note, r.Findings[0].Evidence)
	}
	if bytes.IndexByte([]byte(r.Rules[0].Note), 0xFF) < 0 || bytes.IndexByte([]byte(r.Findings[0].Evidence), 0xFF) < 0 {
		t.Fatal("the caller's raw 0xff byte must survive untouched in the object")
	}
	if bytes.Contains([]byte(r.Rules[0].Note), replacementCharBytes) || bytes.Contains([]byte(r.Findings[0].Evidence), replacementCharBytes) {
		t.Fatal("the bad byte must not have been rewritten to a U+FFFD encoding")
	}
}

// --- 每个字段都被检查：顶层、产物、规则数组各字段、缺陷数组各字段 ---

func TestSaveReportInvalidUTF8RejectedInEveryField(t *testing.T) {
	hash := ArtifactHash(sampleArtifact())

	type fieldCase struct {
		name      string
		wantField string
		mutate    func(Report) Report
	}
	cases := []fieldCase{
		{"reportId", "reportId", func(r Report) Report {
			r.ReportID = "deadbeef\xff"
			return r
		}},
		{"artifact name", "artifact.name", func(r Report) Report {
			r.Artifact.Name = "Vault\xff"
			return r
		}},
		{"artifact hash", "artifact.hash", func(r Report) Report {
			r.Artifact.Hash = hash[:10] + "\xff" + hash[11:]
			return r
		}},
		{"rule id", "rules[0].id", func(r Report) Report {
			r.Rules[0].ID = "r1\xff"
			return r
		}},
		{"rule kind", "rules[0].kind", func(r Report) Report {
			r.Rules[0].Kind = "static\xff"
			return r
		}},
		{"rule severity", "rules[0].severity", func(r Report) Report {
			r.Rules[0].Severity = "high\xff"
			return r
		}},
		{"rule invariant", "rules[0].invariant", func(r Report) Report {
			r.Rules[0].Invariant = "inv-1\xff"
			return r
		}},
		{"rule version", "rules[0].version", func(r Report) Report {
			r.Rules[0].Version = "1.0.0\xff"
			return r
		}},
		{"rule status", "rules[0].status", func(r Report) Report {
			r.Rules[0].Status = StatusDefect + "\xff"
			return r
		}},
		{"rule note", "rules[0].note", func(r Report) Report {
			r.Rules[0].Note = "反例：\xff"
			return r
		}},
		{"finding artifactHash", "findings[0].artifactHash", func(r Report) Report {
			r.Findings[0].ArtifactHash = hash[:10] + "\xff" + hash[11:]
			return r
		}},
		{"finding ruleId", "findings[0].ruleId", func(r Report) Report {
			r.Findings[0].RuleID = "r1\xff"
			return r
		}},
		{"finding version", "findings[0].version", func(r Report) Report {
			r.Findings[0].Version = "1.0.0\xff"
			return r
		}},
		{"finding severity", "findings[0].severity", func(r Report) Report {
			r.Findings[0].Severity = "high\xff"
			return r
		}},
		{"finding invariant", "findings[0].invariant", func(r Report) Report {
			r.Findings[0].Invariant = "inv-1\xff"
			return r
		}},
		{"finding evidence", "findings[0].evidence", func(r Report) Report {
			r.Findings[0].Evidence = "反例：\xff"
			return r
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			r := tc.mutate(withFreshID(saveTextBaseReport()))
			expectInvalidUTF8Rejection(t, dir, r, tc.wantField)
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Fatalf("rejected save must not create a previously absent store directory: %v", statErr)
			}
		})
	}
}

// --- 元素位置：第二条规则、第二条缺陷记录的坏字节要带各自下标 ---

func TestSaveReportInvalidUTF8NamesArrayPosition(t *testing.T) {
	dir := filepath.Join(t.TempDir())

	ruleTwo := withFreshID(saveTextBaseReport())
	ruleTwo.Rules[1].Note = "通过说明\xff"
	expectInvalidUTF8Rejection(t, dir, ruleTwo, "rules[1].note")

	findingTwo := withFreshID(saveTextBaseReport())
	findingTwo.Rules = append(findingTwo.Rules, ReportRule{
		ID: "r4", Kind: "static", Severity: "low", Invariant: "inv-4", Version: "4", Status: StatusDefect, Note: "另一反例",
	})
	findingTwo.Findings = append(findingTwo.Findings, ReportFinding{
		ArtifactHash: findingTwo.Artifact.Hash, RuleID: "r4", Version: "4", Severity: "low", Invariant: "inv-4", Evidence: "另一反例\xff",
	})
	findingTwo = withFreshID(findingTwo)
	expectInvalidUTF8Rejection(t, dir, findingTwo, "findings[1].evidence")
}

// --- 不只检查产生缺陷的规则：通过规则的说明、未检查规则的定义字段同样拒绝 ---

func TestSaveReportInvalidUTF8InNonDefectRulesRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir())

	// 通过规则的说明带坏字节：该规则不产生缺陷记录，仍必须拒绝。
	pass := withFreshID(saveTextBaseReport())
	pass.Rules[1].Note = "通过说明\xff"
	expectInvalidUTF8Rejection(t, dir, pass, "rules[1].note")

	// 未检查规则没有说明，其不变式定义带坏字节仍必须拒绝。
	unchecked := withFreshID(saveTextBaseReport())
	unchecked.Rules[2].Invariant = "inv-3\xff"
	expectInvalidUTF8Rejection(t, dir, unchecked, "rules[2].invariant")
}

// --- 没有任何缺陷记录的报告：通过规则与空规则集报告仍逐字符串检查 ---

func TestSaveReportInvalidUTF8WithoutFindingsRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir())

	onlyPass := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: ArtifactHash(sampleArtifact())},
		Rules: []ReportRule{
			{ID: "r2", Kind: "static", Severity: "low", Invariant: "inv-2", Version: "2", Status: StatusPass, Note: "ok\xff"},
		},
		Findings: []ReportFinding{},
	}
	expectInvalidUTF8Rejection(t, dir, withFreshID(onlyPass), "rules[0].note")

	emptyRules := Report{
		Artifact: ReportArtifact{Name: "Vault\xff", Hash: ArtifactHash(sampleArtifact())},
		Rules:    []ReportRule{},
		Findings: []ReportFinding{},
	}
	expectInvalidUTF8Rejection(t, dir, withFreshID(emptyRules), "artifact.name")
}

// --- 已有目录：拒绝时不新增报告或临时文件，已有归档逐字节保持原样 ---

func TestSaveReportInvalidUTF8LeavesExistingStoreUntouched(t *testing.T) {
	dir := t.TempDir()
	good := withFreshID(saveTextBaseReport())
	if err := SaveReport(dir, good); err != nil {
		t.Fatal(err)
	}
	goodPath := filepath.Join(dir, good.ReportID+".json")
	before, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatal(err)
	}
	entriesBefore, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 另一份标识不同的报告，仅在说明处带坏字节。
	other := saveTextBaseReport()
	other.Artifact.Name = "Other 金库"
	other.Rules[0].Note = "反例：\xff"
	other.Findings[0].Evidence = "反例：\xff"
	other = withFreshID(other)
	if other.ReportID == good.ReportID {
		t.Fatal("test setup: reports must have distinct ids")
	}
	if err := SaveReport(dir, other); err == nil {
		t.Fatal("the bad-UTF-8 report must not be saved")
	}

	entriesAfter, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entriesAfter) != len(entriesBefore) {
		t.Fatalf("rejected save must add no files:\nbefore=%v\nafter=%v", entriesBefore, entriesAfter)
	}
	for _, e := range entriesAfter {
		if strings.HasPrefix(e.Name(), ".report-") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("rejected save left a temporary file: %s", e.Name())
		}
	}
	after, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("the existing archive must be left byte-identical")
	}
}

// --- 合法文本：中文、表情、原文 U+FFFD、前后空格与换行保存/读回逐字保留 ---

func TestSaveReportLegalUTF8PreservedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	note := "  反例：攻击者可在 withdraw 中重入 😀\n原文中的替换字符 � 保留\n第二行  "
	hash := ArtifactHash(sampleArtifact())
	r := Report{
		Artifact: ReportArtifact{Name: "金库 Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "不变式-重入", Version: "1", Status: StatusDefect, Note: note},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "不变式-重入", Evidence: note},
		},
	}
	r = withFreshID(r)
	if err := SaveReport(dir, r); err != nil {
		t.Fatalf("legal multilingual text must save: %v", err)
	}
	loaded, err := LoadReport(dir, r.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Rules[0].Note != note || loaded.Findings[0].Evidence != note {
		t.Fatalf("text must round-trip verbatim, no trimming or replacement:\n note=%q\n evidence=%q\nwant %q",
			loaded.Rules[0].Note, loaded.Findings[0].Evidence, note)
	}
	if loaded.Artifact.Name != "金库 Vault" || loaded.Rules[0].Invariant != "不变式-重入" {
		t.Fatalf("legal CJK fields must be preserved: %+v", loaded)
	}
	archive, err := os.ReadFile(filepath.Join(dir, r.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(archive), "�") {
		t.Fatal("a literal U+FFFD in the original text must remain U+FFFD in the archive")
	}
}
