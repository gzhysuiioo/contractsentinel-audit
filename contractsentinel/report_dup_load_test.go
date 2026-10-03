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

// 本文件锁定“归档读取”侧对重复 JSON 成员的拒绝。audit 提交早已拒绝这类
// 数据，但读取已保存报告时 json.Unmarshal 会静默保留同名成员的最后一个
// 值：在原本“通过”的规则前再写一个“发现缺陷”status，只要后一个值让报告
// 标识与缺陷归属校验成立，整份自相矛盾的归档就会被当成可信结果读出。
// 任何对象（规则、缺陷记录、产物信息、顶层对象及未知字段的嵌套对象）出现
// 重复成员时，读取必须把整份报告归类为归档损坏，且不输出任何部分结果。

// writeDupArchiveText marshals a legal report with a fresh matching id, then
// applies a purely textual mutation. Most mutations repeat a member while
// keeping the last value equal to the original legal one, so the recomputed
// id and the rule/finding correspondence would all pass: rejection can only
// come from the duplicate-member scan, never from ordinary validation. A
// couple of tests use it for benign textual edits instead.
func writeDupArchiveText(t *testing.T, dir string, r Report, mutate func(string) string) string {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	doc := mutate(string(data))
	if doc == string(data) {
		t.Fatal("test setup: mutation did not change the archive")
	}
	if err := os.WriteFile(filepath.Join(dir, r.ReportID+".json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return r.ReportID
}

// dupOnce replaces the first occurrence of old with new in the archive text.
func dupOnce(old, new string) func(string) string {
	return func(doc string) string {
		return strings.Replace(doc, old, new, 1)
	}
}

// expectCorruptDupLoad loads id and asserts the full corruption contract:
// errCorrupt naming the report id, the duplicate member and every required
// location fragment, with the zero report and an untouched archive.
func expectCorruptDupLoad(t *testing.T, dir, id string, wantSubstrings ...string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("archive with a duplicate JSON member must be rejected, got %+v", got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("duplicate members classify as errCorrupt, got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(strings.ToLower(msg), "duplicate") {
		t.Fatalf("error must state the member is duplicated: %v", err)
	}
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
	// The corrupt archive is left exactly as it was.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must not be deleted: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed read must not rewrite or repair the archive")
	}
}

// --- 问题中的核心场景：先写“发现缺陷”再保留“通过”，最后一个值仍使标识与归属成立 ---

func TestLoadReportDuplicateRuleStatusDefectThenPassRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"`+StatusDefect+`","status":"`+StatusPass+`"`))
	// 最后一个值是“通过”，解码后的报告与合法归档逐字段相同：除重复扫描外
	// 没有任何一关能拒绝它。
	expectCorruptDupLoad(t, dir, id, `"status"`, `rule "r-pass"`, "rules[0]")
}

// --- 两个值完全相同也不接受 ---

func TestLoadReportDuplicateRuleStatusEqualValuesRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"`+StatusPass+`","status":"`+StatusPass+`"`))
	expectCorruptDupLoad(t, dir, id, `"status"`, `rule "r-pass"`, "rules[0]")
}

// --- 等价 Unicode 转义写法与直接书写的名字视为同名 ---

func TestLoadReportDuplicateRuleStatusUnicodeEscapeRejected(t *testing.T) {
	dir := t.TempDir()
	// 直接书写的 "status" 与等价转义 "status"（0x73 == 's'）必须视为同名。
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"`+StatusDefect+`", "\u0073tatus":"`+StatusPass+`"`))
	expectCorruptDupLoad(t, dir, id, `"status"`, `rule "r-pass"`)
}

// --- 缺陷记录数组中的重复成员：给出数组位置并点名涉及哪条规则 ---

func TestLoadReportDuplicateFindingMemberRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"ruleId":"r-bad"`, `"ruleId":"r-bad","ruleId":"r-bad"`))
	expectCorruptDupLoad(t, dir, id, `"ruleId"`, `finding for rule "r-bad"`, "findings[0]")
}

// 缺陷记录没有可辨认规则标识时，仍要给出数组位置。
func TestLoadReportDuplicateFindingMemberWithoutIDRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		func(doc string) string {
			// 移除 ruleId 并重复 version：该记录不再有可辨认的规则标识。
			return strings.Replace(doc, `"ruleId":"r-bad","version":"2"`, `"version":"2","version":"2"`, 1)
		})
	expectCorruptDupLoad(t, dir, id, `"version"`, "finding entry", "findings[0]")
}

// --- 规则数组中的重复成员：数组位置与规则标识 ---

func TestLoadReportDuplicateRuleMemberNamesRuleAndPosition(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"id":"r-none"`, `"id":"r-none","id":"r-none"`))
	expectCorruptDupLoad(t, dir, id, `"id"`, `rule "r-none"`, "rules[2]")
}

// --- 产物对象与顶层对象的重复成员 ---

func TestLoadReportDuplicateArtifactMemberRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"artifact":{"name":"Vault"`,
			`"artifact":{"name":"Other","name":"Vault"`))
	expectCorruptDupLoad(t, dir, id, `"name"`, "the artifact object")
}

func TestLoadReportDuplicateTopLevelMemberRejected(t *testing.T) {
	dir := t.TempDir()
	r := oneDefectFixture()
	r.ReportID = ReportID(r)
	id := writeDupArchiveText(t, dir, r, func(doc string) string {
		old := `"reportId":"` + r.ReportID + `"`
		return strings.Replace(doc, old, old+","+old, 1)
	})
	expectCorruptDupLoad(t, dir, id, `"reportId"`, "the top-level object")
}

// --- 未知字段中的嵌套对象同样扫描；位置按实际结构描述 ---

func TestLoadReportDuplicateNestedUnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`{"reportId"`, `{"mystery":{"a":1,"a":2},"reportId"`))
	expectCorruptDupLoad(t, dir, id, `"a"`, ".mystery")
}

// --- 大小写不同、带空白的名字不合并；字符串里像 JSON 的文字只是内容 ---

func TestLoadReportCaseAndWhitespaceDistinctKeysStillLoad(t *testing.T) {
	dir := t.TempDir()
	// 未知成员只出现一次时按既有方式放行；与已知成员名大小写不同或两侧带
	// 空白的未知键也不是重复。
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`,
			`"StAtus":"x"," status ":"y","status":"`+StatusPass+`"`))
	if _, err := LoadReport(dir, id); err != nil {
		t.Fatalf("case/whitespace-distinct unknown keys must not collide: %v", err)
	}
}

func TestLoadReportJSONLookingStringContentStillLoads(t *testing.T) {
	dir := t.TempDir()
	r := oneDefectFixture()
	// 证据字符串内的 “JSON” 只是普通内容，不参与成员判重。
	r.Rules[1].Note = `反例 {"x":1,"x":2}`
	r.Findings[0].Evidence = r.Rules[1].Note
	id := writeReportWithFreshID(t, dir, r)
	if _, err := LoadReport(dir, id); err != nil {
		t.Fatalf("JSON-looking text inside evidence is ordinary content: %v", err)
	}
}

// --- 未知字段只出现一次：既有接受方式保持兼容 ---

func TestLoadReportSingleUnknownFieldStillAccepted(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`{"reportId"`, `{"mystery":{"nested":true},"reportId"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a single unknown field must stay accepted: %v", err)
	}
	if loaded.ReportID != id {
		t.Fatalf("legal report id not preserved: %q", loaded.ReportID)
	}
}

// --- 重复读取始终拒绝，且不创建任何额外文件 ---

func TestLoadReportDuplicateMemberRepeatedlyRejectedNoFiles(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"`+StatusPass+`","status":"`+StatusPass+`"`))
	for i := 0; i < 2; i++ {
		if _, err := LoadReport(dir, id); err == nil {
			t.Fatal("repeated reads must keep rejecting the duplicate archive")
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

// --- 错误三分类不变：重复成员是损坏，不与“不存在/标识不合法”混淆 ---

func TestLoadReportDuplicateMemberErrorClassDistinct(t *testing.T) {
	dir := t.TempDir()
	corruptID := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"`+StatusPass+`","status":"`+StatusPass+`"`))
	if _, err := LoadReport(dir, corruptID); err == nil {
		t.Fatal("expected corrupt error")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("duplicate archive -> expected errCorrupt, got %T: %v", err, err)
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

// --- diff：任一侧归档含重复成员都整体失败，不输出局部差异，不变成“未检查” ---

func TestDiffStoreRejectsDuplicateMemberOnEitherSide(t *testing.T) {
	dir := t.TempDir()
	good := oneDefectFixture()
	goodID := writeReportWithFreshID(t, dir, good)
	// 另一侧是另一份合法报告，存档时再注入重复成员。
	other := oneDefectFixture()
	other.Rules = append(other.Rules,
		ReportRule{ID: "r-extra", Kind: "static", Severity: "info", Invariant: "inv-extra", Version: "9", Status: StatusPass})
	badID := writeDupArchiveText(t, dir, other,
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"`+StatusDefect+`","status":"`+StatusPass+`"`))

	for _, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"second report duplicate", goodID, badID},
		{"first report duplicate", badID, goodID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diff, err := DiffStore(dir, tc.before, tc.after)
			if err == nil {
				t.Fatalf("diff must fail when a side repeats a member, got %+v", diff)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !reflect.DeepEqual(diff, DiffResult{}) {
				t.Fatalf("failed diff must return the zero result, got %+v", diff)
			}
			if !strings.Contains(err.Error(), `"status"`) {
				t.Fatalf("error must name the duplicate member: %v", err)
			}
		})
	}
}

// --- 审计保存遇到同标识已有归档：重复成员归档不能被当成保存成功 ---

func TestSaveReportDuplicateExistingArchiveNotTreatedAsSaved(t *testing.T) {
	dir := t.TempDir()
	r := oneDefectFixture()
	id := writeDupArchiveText(t, dir, r,
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"`+StatusDefect+`","status":"`+StatusPass+`"`))
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 提交一份内容标识相同的合法报告：已有归档损坏，保存必须失败而不是
	// 静默地“同标识即成功”，且原文件原样保留。
	r.ReportID = id
	if err := SaveReport(dir, r); err == nil {
		t.Fatal("a duplicate-member existing archive must not count as a successful save")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("expected errCorrupt, got %T: %v", err, err)
		}
		if !strings.Contains(err.Error(), `"status"`) {
			t.Fatalf("error must name the duplicate member: %v", err)
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

// 并发落盘竞争中“抢先出现”的归档若含重复成员，同样按损坏失败并保留原文件。
func TestSaveReportRaceDuplicateFileKept(t *testing.T) {
	dir := t.TempDir()
	r := oneDefectFixture()
	r.ReportID = ReportID(r)
	finalPath := filepath.Join(dir, r.ReportID+".json")
	legal, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	dupDoc := strings.Replace(string(legal),
		`"status":"`+StatusPass+`"`,
		`"status":"`+StatusDefect+`","status":"`+StatusPass+`"`, 1)
	saveReportHook = func(string) {
		os.WriteFile(finalPath, []byte(dupDoc), 0o644)
	}
	defer func() { saveReportHook = nil }()

	err = SaveReport(dir, r)
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T: %v", err, err)
	}
	kept, _ := os.ReadFile(finalPath)
	if string(kept) != dupDoc {
		t.Fatal("the duplicate-member racing archive must be kept, not overwritten")
	}
}
