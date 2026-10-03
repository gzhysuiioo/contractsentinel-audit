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

// 本文件锁定报告归档读取对“JSON 对象内重复成员名”的整体拒绝：encoding/json
// 对同名成员静默保留最后一个值，因此在一条原本通过的规则里先写
// "status":"发现缺陷" 再保留原来的 "status":"通过"，解码后的内容仍是通过，
// 重算的报告标识与缺陷归属校验都能对上——但这份归档没有唯一可信结论。
// 读取（report 查询、diff 两侧、保存时的同标识既有归档）必须把任何对象内
// 的重复成员当作归档损坏整份拒绝，错误点名报告标识、重复成员与所在对象，
// 且原文件字节保持不动。

// injectBeforeMember 在 data 中 anchor 之后第一个 member 成员前插入 extra
// （一个完整的 "name":value, 片段）。解码器对重复成员只保留最后一个值，
// 因此在既有成员前插入同名成员不会改变解码结果与重算标识。
func injectBeforeMember(t *testing.T, data []byte, anchor, member, extra string) []byte {
	t.Helper()
	doc := string(data)
	idx := strings.Index(doc, anchor)
	if idx < 0 {
		t.Fatalf("test setup: anchor %q not found in %s", anchor, doc)
	}
	at := strings.Index(doc[idx:], member)
	if at < 0 {
		t.Fatalf("test setup: member %q not found after %q in %s", member, anchor, doc)
	}
	at += idx
	return []byte(doc[:at] + extra + doc[at:])
}

// writeDupArchive 把 content 写入 dir/<id>.json 并返回文件路径。调用方负责
// 保证 content 解码后的报告标识就是 id（重复成员插入在既有成员之前即可）。
func writeDupArchive(t *testing.T, dir, id string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// marshalFreshReport 返回一份标识与内容相符的合法报告的归档字节与标识。
func marshalFreshReport(t *testing.T, r Report) (string, []byte) {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return r.ReportID, data
}

// expectCorruptDupLoad 断言按 id 读取被当作归档损坏拒绝：errCorrupt、错误
// 同时点名报告标识与重复成员、不返回部分报告、归档字节保持不动。
func expectCorruptDupLoad(t *testing.T, dir, id string, wantSubstrings ...string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("archive with a duplicate member must be rejected, loaded: %+v", got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("duplicate member archive -> expected errCorrupt, got %T: %v", err, err)
	}
	if !reflect.DeepEqual(got, Report{}) {
		t.Fatalf("failed read must return the zero report, got %+v", got)
	}
	msg := err.Error()
	if !strings.Contains(strings.ToLower(msg), "duplicate") {
		t.Fatalf("error must state that a member is duplicated: %v", err)
	}
	if !strings.Contains(msg, id) {
		t.Fatalf("error must name the report id %q: %v", id, err)
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must not be deleted: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed read must not rewrite or repair the archive")
	}
}

// --- 头号场景：先写“发现缺陷”再保留“通过”，标识与归属校验都对得上 ---

func TestLoadReportRejectsDuplicateRuleStatusConflictingConclusion(t *testing.T) {
	dir := t.TempDir()
	id, data := marshalFreshReport(t, oneDefectFixture())
	// 在 r-pass（rules[0]，结论为通过）的 status 前插入一个冲突的“发现缺陷”。
	// 解码只保留最后的“通过”，因此归档标识、缺陷归属全部吻合；重复成员本身
	// 就是损坏，必须凭重复成员而不是凭内容矛盾被拒绝。
	dup := injectBeforeMember(t, data, `"id":"r-pass"`, `"status":"`,
		`"\u0073tatus":"`+StatusDefect+`",`)
	writeDupArchive(t, dir, id, dup)

	// 确认前提：解码后的内容标识与归档标识一致，排除“靠标识不匹配发现”。
	var decoded Report
	if err := json.Unmarshal(dup, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportID != id || ReportID(decoded) != id {
		t.Fatalf("test setup: decoded content id must match the archive id, decoded=%q recomputed=%q id=%q",
			decoded.ReportID, ReportID(decoded), id)
	}
	expectCorruptDupLoad(t, dir, id, `"status"`, `rule "r-pass"`, "rules[0]")
}

// 两个值完全相同也不放行：问题在于成员出现两次，而不是值冲突。
func TestLoadReportRejectsDuplicateRuleStatusEqualValues(t *testing.T) {
	dir := t.TempDir()
	id, data := marshalFreshReport(t, oneDefectFixture())
	dup := injectBeforeMember(t, data, `"id":"r-pass"`, `"status":"`,
		`"status":"`+StatusPass+`",`)
	writeDupArchive(t, dir, id, dup)
	expectCorruptDupLoad(t, dir, id, `"status"`, `rule "r-pass"`, "rules[0]")
}

// 名称按 JSON 字符串解码后比较：直接书写的 status 与 \u0073tatus 是同一个成员。
func TestLoadReportRejectsDuplicateUnicodeEscapedMember(t *testing.T) {
	dir := t.TempDir()
	id, data := marshalFreshReport(t, oneDefectFixture())
	// 插入的原始 JSON 文本是 "\u0073tatus"（即 s 的转义写法），解码后即 "status"。
	dup := injectBeforeMember(t, data, `"id":"r-pass"`, `"status":"`,
		`"\u0073tatus":"`+StatusDefect+`",`)
	writeDupArchive(t, dir, id, dup)
	expectCorruptDupLoad(t, dir, id, `"status"`, `rule "r-pass"`)
}

// --- 顶层对象、产物对象、缺陷记录、未知字段中的嵌套对象都遵守同一规则 ---

func TestLoadReportRejectsDuplicateTopLevelMember(t *testing.T) {
	dir := t.TempDir()
	id, data := marshalFreshReport(t, oneDefectFixture())
	// 顶层重复 "findings"：第二个值与第一个完全相同（解码结果不变）。
	doc := string(data)
	at := strings.Index(doc, `"findings"`)
	if at < 0 {
		t.Fatal("test setup: findings member not found")
	}
	end := strings.Index(doc[at:], `]}`)
	if end < 0 {
		t.Fatal("test setup: findings array end not found")
	}
	end += at + 1 // 指向 ']' 之后
	dup := doc[:end] + `,"findings":` + doc[at+len(`"findings":`):end] + doc[end:]
	writeDupArchive(t, dir, id, []byte(dup))
	expectCorruptDupLoad(t, dir, id, `"findings"`, "top-level object")
}

func TestLoadReportRejectsDuplicateArtifactMember(t *testing.T) {
	dir := t.TempDir()
	id, data := marshalFreshReport(t, oneDefectFixture())
	dup := injectBeforeMember(t, data, `"artifact":{`, `"hash":"`,
		`"hash":"`+strings.Repeat("0", 64)+`",`)
	writeDupArchive(t, dir, id, dup)
	expectCorruptDupLoad(t, dir, id, `"hash"`, "artifact object")
}

func TestLoadReportRejectsDuplicateFindingMember(t *testing.T) {
	dir := t.TempDir()
	id, data := marshalFreshReport(t, oneDefectFixture())
	// 缺陷记录里重复 evidence：错误必须给出数组位置并点名涉及哪条规则。
	dup := injectBeforeMember(t, data, `"findings":[{`, `"evidence":"`,
		`"evidence":"伪造的另一份证据",`)
	writeDupArchive(t, dir, id, dup)
	expectCorruptDupLoad(t, dir, id, `"evidence"`, `finding for rule "r-bad"`, "findings[0]")
}

func TestLoadReportRejectsDuplicateInsideUnknownField(t *testing.T) {
	dir := t.TempDir()
	id, data := marshalFreshReport(t, oneDefectFixture())
	// 未知字段整体被忽略（解码结果不变），但其内部对象的重复成员仍是重复。
	doc := string(data)
	dup := doc[:len(doc)-1] + `,"meta":{"note":1,"note":2}}`
	writeDupArchive(t, dir, id, []byte(dup))
	expectCorruptDupLoad(t, dir, id, `"note"`)
}

func TestLoadReportRejectsDuplicateUnknownTopLevelMember(t *testing.T) {
	dir := t.TempDir()
	id, data := marshalFreshReport(t, oneDefectFixture())
	doc := string(data)
	dup := doc[:len(doc)-1] + `,"mystery":1,"mystery":2}`
	writeDupArchive(t, dir, id, []byte(dup))
	expectCorruptDupLoad(t, dir, id, `"mystery"`, "top-level object")
}

// --- 边界：同名不同对象、大小写不同、字符串里的类 JSON 文字都合法 ---

func TestLoadReportAcceptsCaseDistinctAndJSONLookingStrings(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	note := `反例 {"x":1,"x":2}`
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect, Note: note},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: note},
		},
	}
	id, data := marshalFreshReport(t, report)
// 名称按 JSON 字符串解码后比较：直接书写的 status 与 \u0073tatus 是同一个成员。
	doc := string(data)
	doc = doc[:len(doc)-1] + `,"Status":"通过"}`
	writeDupArchive(t, dir, id, []byte(doc))

	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("case-distinct names and JSON-looking strings are legal: %v", err)
	}
	if loaded.Findings[0].Evidence != note {
		t.Fatalf("evidence not preserved: %+v", loaded.Findings[0])
	}
}

// --- diff 两侧遵守同一拒绝规则：不输出局部差异，不降级为“未检查” ---

func TestDiffStoreRejectsDuplicateMemberOnEitherSide(t *testing.T) {
	dir := t.TempDir()
	goodReport := oneDefectFixture()
	goodID, goodData := marshalFreshReport(t, goodReport)
	writeDupArchive(t, dir, goodID, goodData)

	other := oneDefectFixture()
	other.Rules[0].Status = StatusUnchecked
	badID, badData := marshalFreshReport(t, other)
	dup := injectBeforeMember(t, badData, `"id":"r-pass"`, `"status":"`,
		`"\u0073tatus":"`+StatusDefect+`",`)
	badPath := writeDupArchive(t, dir, badID, dup)
	badBytes, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"duplicate on the after side", goodID, badID},
		{"duplicate on the before side", badID, goodID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DiffStore(dir, tc.before, tc.after)
			if err == nil {
				t.Fatalf("diff with a duplicate-member archive must fail, got %+v", got)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), badID) {
				t.Fatalf("error must name the corrupt report id %q: %v", badID, err)
			}
			if !reflect.DeepEqual(got, DiffResult{}) {
				t.Fatalf("failed diff must return no partial result, got %+v", got)
			}
		})
	}
	kept, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != string(badBytes) {
		t.Fatal("failed diff must not modify the corrupt archive")
	}
}

// --- 保存遇到同标识既有归档：含重复成员的文件不能当成保存成功 ---

func TestSaveReportRejectsExistingDuplicateArchive(t *testing.T) {
	dir := t.TempDir()
	report, err := BuildReport(sampleArtifact(), []Rule{
		{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"},
	}, map[string]bool{"inv": true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	// 把既有归档改成含重复成员的版本（解码内容不变，标识仍相符）。
	path := filepath.Join(dir, report.ReportID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dup := injectBeforeMember(t, data, `"id":"r1"`, `"status":"`,
		`"\u0073tatus":"`+StatusDefect+`",`)
	if err := os.WriteFile(path, dup, 0o644); err != nil {
		t.Fatal(err)
	}

	// 同一报告的再次保存必须失败，不能凭“最后一个值与提交一致”当成成功。
	err = SaveReport(dir, report)
	if err == nil {
		t.Fatal("save against an existing duplicate-member archive must fail")
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T: %v", err, err)
	}
	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("existing archive must be kept: %v", err)
	}
	if string(kept) != string(dup) {
		t.Fatal("failed save must not delete, repair or overwrite the existing archive")
	}
}

// --- 既有合法行为不变：无重复成员的归档正常读取，标识计算不变 ---

func TestLoadReportLegalArchiveUnchangedByDuplicateScan(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, oneDefectFixture())
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("legal archive must still load: %v", err)
	}
	if loaded.ReportID != id || len(loaded.Rules) != 3 || len(loaded.Findings) != 1 {
		t.Fatalf("legal archive content changed: %+v", loaded)
	}
}
