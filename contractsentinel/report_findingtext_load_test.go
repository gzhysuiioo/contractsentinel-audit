package contractsentinel

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 本文件锁定“归档读取”侧缺陷记录文本成员的类型规则。ReportFinding 的
// artifactHash、ruleId、version、severity、invariant、evidence 都是 Go 字符串，
// json.Unmarshal 会把正式成员的 null 静默解码成零值 ""：当规则与缺陷记录
// 原本就把严重级别（或不变式）保存为空字符串时，把 findings 中对应记录的
// severity 改成 null，读出的内容与原合法报告逐字节相同——重算的报告标识、
// 产物哈希与规则/缺陷归属全部吻合，归档没有保存合法文本的事实被完全掩盖，
// diff 甚至可能把该记录判成“无变化”。
//
// 修正后，正式成员（约定拼写，含 Unicode 转义写法）一旦写出，其值就必须是
// JSON 字符串；null、布尔值、数字、对象、数组都使整份归档判为损坏，即使
// 产物哈希、报告标识以及规则与缺陷的对应关系仍吻合也不能返回报告。错误点名
// 请求的报告标识、出错记录在 findings 数组中从零开始的位置和成员名，明确
// 该成员必须是字符串；记录的 ruleId 本身是合法非空字符串时还要指出所属
// 规则。省略成员仍沿用默认值与必填/绑定校验，显式空字符串仍按既有业务
// 规则判断，不新增所有文本必须非空的限制；大小写变体、带空格名称与未知
// 扩展成员继续被忽略，其中的 null 不触发本错误，也不能替代或挽救非法的
// 正式成员。合法报告的标识、缺陷归属与证据原文（含中文、换行与前后空格）
// 保持不变。

// jsonEscapedS is the six-character JSON unicode escape that decodes to the
// letter s; it is built by concatenation so the source never carries the
// escape-looking literal as one piece.
const jsonEscapedS = `\` + `u0073`

// mutateFindingField 把归档中指定缺陷记录（按 ruleId 定位）的某个成员替换为
// raw 片段（如 null）；该成员不存在时把它插入到 ruleId 成员之后。fragment
// 为空串表示删除整个成员。搜索区间从该记录对象的起始花括号开始，因此排在
// ruleId 之前的 artifactHash 也能被原地替换而不是重复插入。
func mutateFindingField(t *testing.T, doc, ruleID, field, fragment string) string {
	t.Helper()
	idMember := `"ruleId":"` + ruleID + `"`
	idIdx := strings.Index(doc, idMember)
	if idIdx < 0 {
		t.Fatalf("test setup: finding for rule %s not found in archive", ruleID)
	}
	objStart := strings.LastIndexByte(doc[:idIdx], '{')
	if objStart < 0 {
		t.Fatalf("test setup: finding for rule %s object has no start", ruleID)
	}
	findEnd := strings.IndexByte(doc[idIdx:], '}')
	if findEnd < 0 {
		t.Fatalf("test setup: finding for rule %s object has no end", ruleID)
	}
	findEnd += idIdx
	marker := `"` + field + `":`
	at := strings.Index(doc[objStart:findEnd], marker)
	if at < 0 {
		if fragment == "" {
			t.Fatalf("test setup: finding for rule %s has no %s member to remove", ruleID, field)
		}
		idEnd := idIdx + len(idMember)
		return doc[:idEnd] + `,"` + field + `":` + fragment + doc[idEnd:]
	}
	at += objStart
	valueStart := at + len(marker)
	var valueEnd int
	if doc[valueStart] == '"' {
		// 测试夹具中的字符串值不含转义引号，下一个引号即结束。
		closing := strings.IndexByte(doc[valueStart+1:], '"')
		if closing < 0 {
			t.Fatalf("test setup: finding for rule %s %s value has no closing quote", ruleID, field)
		}
		valueEnd = valueStart + 1 + closing + 1
	} else {
		end := strings.IndexAny(doc[valueStart:], ",}")
		if end < 0 {
			t.Fatalf("test setup: finding for rule %s %s value has no end", ruleID, field)
		}
		valueEnd = valueStart + end
	}
	if fragment == "" {
		// 删除整个成员：优先连同后随逗号，否则连同前导逗号。
		if valueEnd < len(doc) && doc[valueEnd] == ',' {
			return doc[:at] + doc[valueEnd+1:]
		}
		return doc[:at-1] + doc[valueEnd:]
	}
	return doc[:at] + `"` + field + `":` + fragment + doc[valueEnd:]
}

// writeArchiveWithFindingText marshals a legal report, rewrites one finding
// member with a raw fragment, recomputes the report id from the decoded
// content and writes the archive under that id. A null fragment launders
// through the plain decoder (null decodes into the string zero value), so the
// recomputed id keeps the archive self-consistent and rejection can only come
// from the type gate. Other non-string JSON types never unmarshal into a Go
// string, so the original id is kept: it may mismatch, but the type gate runs
// before the id comparison and rejects with the same corruption error.
func writeArchiveWithFindingText(t *testing.T, dir string, r Report, ruleID, field, fragment string) string {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	doc := mutateFindingField(t, string(data), ruleID, field, fragment)
	if doc == string(data) {
		t.Fatal("test setup: mutation did not change the archive")
	}
	id := r.ReportID
	if strict, err := strictReportJSON([]byte(doc)); err == nil {
		var decoded Report
		if err := json.Unmarshal(strict, &decoded); err == nil {
			newID := ReportID(decoded)
			doc = strings.Replace(doc, `"reportId":"`+id+`"`, `"reportId":"`+newID+`"`, 1)
			id = newID
		}
	}
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return id
}

// expectCorruptFindingTextLoad asserts the full read-side contract for a
// non-string formal finding member: errCorrupt naming the report id, the
// findings array position, the field and the string requirement (plus the
// rule id when the finding carries a legal one), a zero report and an
// untouched archive.
func expectCorruptFindingTextLoad(t *testing.T, dir, id, position, rule, field string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("a non-string formal finding member %s must reject the whole archive, got %+v", field, got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("illegal finding member %s classifies as errCorrupt, got %T: %v", field, err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, id) {
		t.Fatalf("error must name the report id %q: %v", id, err)
	}
	if !strings.Contains(msg, position) {
		t.Fatalf("error must name the findings array position %q: %v", position, err)
	}
	if rule != "" && !strings.Contains(msg, "(rule "+rule+")") {
		t.Fatalf("error must name the owning rule %q: %v", rule, err)
	}
	if !strings.Contains(msg, field+" must be a string") {
		t.Fatalf("error must state %s must be a string: %v", field, err)
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

// emptyTextFixture 是一份合法报告：唯一的缺陷规则与它的缺陷记录都把严重
// 级别和不变式保存为空字符串，证据取自带换行与前后空格的检查说明。它正是
// “合法文本是空字符串”的场景：把记录里的空字符串改成 null 后，普通解码
// 无法区分二者。
func emptyTextFixture() Report {
	hash := ArtifactHash(sampleArtifact())
	note := "  反例：空级别路径仍可达\n第二行证据  "
	return Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r-pass", Kind: "static", Severity: "low", Invariant: "inv-pass", Version: "1", Status: StatusPass},
			{ID: "r-empty", Kind: "static", Severity: "", Invariant: "", Version: "2", Status: StatusDefect, Note: note},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r-empty", Version: "2", Severity: "", Invariant: "", Evidence: note},
		},
	}
}

// twoDefectFixture 是一份带两条缺陷记录的合法报告，用于定位非首条记录。
func twoDefectFixture() Report {
	hash := ArtifactHash(sampleArtifact())
	return Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r-one", Kind: "static", Severity: "high", Invariant: "inv-one", Version: "1", Status: StatusDefect, Note: "counterexample: one"},
			{ID: "r-two", Kind: "static", Severity: "low", Invariant: "inv-two", Version: "2", Status: StatusDefect, Note: "counterexample: two"},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r-one", Version: "1", Severity: "high", Invariant: "inv-one", Evidence: "counterexample: one"},
			{ArtifactHash: hash, RuleID: "r-two", Version: "2", Severity: "low", Invariant: "inv-two", Evidence: "counterexample: two"},
		},
	}
}

// --- 核心场景：合法空严重级别被改成 null，标识仍一致也必须拒绝 ---

func TestLoadReportNullSeverityOnEmptySeverityFindingRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, emptyTextFixture(), "r-empty", "severity", `null`)

	// null 被洗成 ""：归档内 reportId、请求 id 与按解码内容重算的 id 三者
	// 一致，且与保存了合法空字符串的报告标识相同，除类型关外没有任何一关
	// 能拒绝它。
	if want := ReportID(emptyTextFixture()); id != want {
		t.Fatalf("test setup: null severity must launder to the legal empty-severity report id %q, got %q", want, id)
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"severity":null`)) {
		t.Fatalf("test setup: archive must carry the null severity:\n%s", data)
	}
	expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-empty", "severity")
}

// --- 合法空不变式被改成 null 时同样拒绝 ---

func TestLoadReportNullInvariantOnEmptyInvariantFindingRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, emptyTextFixture(), "r-empty", "invariant", `null`)
	if want := ReportID(emptyTextFixture()); id != want {
		t.Fatalf("test setup: null invariant must launder to the legal empty-invariant report id %q, got %q", want, id)
	}
	expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-empty", "invariant")
}

// --- 六个文本成员写成 null 都判为损坏，错误点名位置、字段与所属规则 ---

func TestLoadReportNullFindingFieldRejected(t *testing.T) {
	for _, field := range archiveFindingTextFields {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", field, `null`)
			rule := "r-bad"
			if field == "ruleId" {
				// ruleId 本身非法时没有可点名的所属规则。
				rule = ""
			}
			expectCorruptFindingTextLoad(t, dir, id, "findings[0]", rule, field)
		})
	}
}

// --- 拒绝不依赖标识或归属不匹配：null 洗成空串后，业务校验全部通过 ---

func TestLoadReportNullSeverityCorruptDespiteMatchingIDAndBinding(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, emptyTextFixture(), "r-empty", "severity", `null`)

	data, _ := os.ReadFile(filepath.Join(dir, id+".json"))
	strict, err := strictReportJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(strict, &decoded); err != nil {
		t.Fatal(err)
	}
	// 产物哈希、报告标识以及规则与缺陷的对应关系在洗成空串后全部吻合。
	if decoded.ReportID != id || ReportID(decoded) != id {
		t.Fatalf("test setup: id must match the laundered content, archive=%q recomputed=%q requested=%q",
			decoded.ReportID, ReportID(decoded), id)
	}
	if err := validateReport(decoded, func(msg string) error { return errCorrupt(msg) }); err != nil {
		t.Fatalf("test setup: rule/finding correspondence must otherwise be legal: %v", err)
	}
	if decoded.Findings[0].Severity != "" {
		t.Fatal("test setup: null must launder to the empty string under the plain decoder")
	}
	expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-empty", "severity")
}

// --- 布尔值、数字、对象、数组同样判为损坏，不能默认成空字符串 ---

func TestLoadReportNonStringFindingFieldRejected(t *testing.T) {
	for _, val := range []string{`true`, `false`, `0`, `1`, `{}`, `[]`, `["x"]`} {
		t.Run(val, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "evidence", val)
			expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-bad", "evidence")
		})
	}
	for _, tc := range []struct {
		field  string
		fixt   func() Report
		ruleID string
	}{
		{"artifactHash", oneDefectFixture, "r-bad"},
		{"version", oneDefectFixture, "r-bad"},
		{"severity", emptyTextFixture, "r-empty"},
		{"invariant", emptyTextFixture, "r-empty"},
	} {
		for _, val := range []string{`true`, `0`, `{}`, `[]`} {
			t.Run(tc.field+" "+val, func(t *testing.T) {
				dir := t.TempDir()
				id := writeArchiveWithFindingText(t, dir, tc.fixt(), tc.ruleID, tc.field, val)
				expectCorruptFindingTextLoad(t, dir, id, "findings[0]", tc.ruleID, tc.field)
			})
		}
	}
}

// --- 多条缺陷记录时，错误给出从零开始的正确位置并先报第一条坏记录 ---

func TestLoadReportFindingPositionLocator(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, twoDefectFixture(), "r-two", "severity", `null`)
	expectCorruptFindingTextLoad(t, dir, id, "findings[1]", "r-two", "severity")
}

// --- 兼容行为：省略成员与显式空字符串仍按既有规则处理，合法文本原样读回 ---

func TestLoadReportFindingTextOmittedAndEmptyStringSemantics(t *testing.T) {
	dir := t.TempDir()

	// 显式空字符串 severity 合法（规则本身就是空级别）：夹具落盘的归档本来就
	// 写着 "severity":""，直接读回为空且标识稳定。
	emptySevID := writeReportWithFreshID(t, dir, emptyTextFixture())
	loaded, err := LoadReport(dir, emptySevID)
	if err != nil {
		t.Fatalf("an explicit empty-string severity must still load: %v", err)
	}
	if loaded.Findings[0].Severity != "" {
		t.Fatalf("empty severity must read back empty, got %q", loaded.Findings[0].Severity)
	}
	if want := ReportID(emptyTextFixture()); emptySevID != want {
		t.Fatalf("explicit empty severity report must keep its id:\n%s\n%s", emptySevID, want)
	}

	// 省略 severity：同样解码成 ""，与合法空级别报告同标识并成功读回。
	omittedID := writeArchiveWithFindingText(t, dir, emptyTextFixture(), "r-empty", "severity", ``)
	if _, err := LoadReport(dir, omittedID); err != nil {
		t.Fatalf("an omitted finding member must keep its default-value handling: %v", err)
	}
	if want := ReportID(emptyTextFixture()); omittedID != want {
		t.Fatalf("omitted severity must share the legal empty-string report id:\n%s\n%s", omittedID, want)
	}

	// 显式空字符串 evidence 不被类型关拒绝，但仍由既有绑定校验判为损坏
	// （证据必须等于检查说明），而不是类型错误。
	emptyEvidenceID := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "evidence", `""`)
	_, err = LoadReport(dir, emptyEvidenceID)
	if err == nil {
		t.Fatal("an empty evidence must still be rejected by the binding rule")
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("binding failure stays errCorrupt, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "has evidence") {
		t.Fatalf("empty evidence must keep the binding-rule error, got: %v", err)
	}
	if strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an explicit empty string is not a type error: %v", err)
	}

	// 显式空字符串 ruleId 同样落在既有必填校验上，而不是类型错误。
	emptyRuleID := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "ruleId", `""`)
	_, err = LoadReport(dir, emptyRuleID)
	if err == nil {
		t.Fatal("an empty finding rule id must still be rejected by the required rule")
	}
	if !strings.Contains(err.Error(), "empty rule id") {
		t.Fatalf("empty rule id must keep the business-rule error, got: %v", err)
	}
	if strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an explicit empty string is not a type error: %v", err)
	}
}

// --- 合法报告读回后标识、缺陷归属与证据原文保持不变，中文、换行和前后
// 空格不得被修剪或改写 ---

func TestLoadReportFindingTextPreservedVerbatim(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, emptyTextFixture())
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal report must load: %v", err)
	}
	if loaded.ReportID != id || ReportID(loaded) != id {
		t.Fatalf("report id must be preserved: %q vs %q", loaded.ReportID, id)
	}
	want := emptyTextFixture()
	if loaded.Findings[0] != want.Findings[0] {
		t.Fatalf("finding must read back verbatim:\n got %+v\nwant %+v", loaded.Findings[0], want.Findings[0])
	}
	if loaded.Findings[0].Evidence != want.Findings[0].Evidence {
		t.Fatalf("evidence must read back verbatim, got %q", loaded.Findings[0].Evidence)
	}
}

// --- 大小写变体或带空格名称中的 null 是扩展信息：不触发错误，也不能挽救
// 非法的正式成员 ---

func TestLoadReportFindingTextVariantNullIgnored(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"case variant", "Severity"},
		{"whitespace padded", " evidence "},
		{"case variant ruleId", "RuleId"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", tc.field, `null`)
			loaded, err := LoadReport(dir, id)
			if err != nil {
				t.Fatalf("a variant-named member is extension data and must be ignored: %v", err)
			}
			if loaded.Findings[0].Severity != "high" || loaded.Findings[0].RuleID != "r-bad" ||
				loaded.Findings[0].Evidence != "counterexample: x" {
				t.Fatalf("a variant member must not supply formal finding values: %+v", loaded.Findings[0])
			}
			if want := ReportID(oneDefectFixture()); id != want {
				t.Fatalf("extension data must not change the report id:\n got %s\nwant %s", id, want)
			}
		})
	}
}

func TestLoadReportFindingTextVariantCannotRescueFormalNull(t *testing.T) {
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			dir := t.TempDir()
			if pos == "before" {
				// 变体在正式成员之前：先插入正式 null，再在同位置插入变体，
				// 最终变体位于正式成员之前。
				id := writeArchiveWithFindingText(t, dir, emptyTextFixture(), "r-empty", "severity", `null`)
				path := filepath.Join(dir, id+".json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				doc := strings.Replace(string(data), `"severity":null`, `"Severity":"high","severity":null`, 1)
				if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
					t.Fatal(err)
				}
				expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-empty", "severity")
				return
			}
			id := writeArchiveWithFindingText(t, dir, emptyTextFixture(), "r-empty", "severity", `null,"Severity":"high"`)
			expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-empty", "severity")
		})
	}
}

// --- Unicode 转义写出的正式名称遵守同一字符串规则 ---

func TestLoadReportEscapedFindingNameFollowsSameRule(t *testing.T) {
	dir := t.TempDir()
	// 缺陷记录里的 severity 总随其他成员一起写出，因此把正式名称整体改写成
	// 转义拼写（而不是再插入一个同名成员）："severity" 解码后就是 severity，
	// 携带 null 时同样判为损坏。定位时带上 finding 内独有的 version 前缀，
	// 避免误改规则对象里的同名成员。
	nullID := writeVariantArchiveText(t, dir, oneDefectFixture(), func(doc string) string {
		old := `"version":"2","severity":"high"`
		mutated := strings.Replace(doc, old, `"version":"2","`+jsonEscapedS+`everity":null`, 1)
		if mutated == doc {
			t.Fatal("test setup: escaped-name rewrite did not change the archive")
		}
		if strings.Count(mutated, jsonEscapedS+`everity`) != 1 {
			t.Fatalf("test setup: expected exactly one escaped severity name:\n%s", mutated)
		}
		return mutated
	})
	expectCorruptFindingTextLoad(t, dir, nullID, "findings[0]", "r-bad", "severity")

	// 转义写法携带合法字符串时，与直接书写的报告标识一致并按原值读回。
	dir2 := t.TempDir()
	escapedID := writeVariantArchiveText(t, dir2, oneDefectFixture(), func(doc string) string {
		old := `"version":"2","severity":"high"`
		return strings.Replace(doc, old, `"version":"2","`+jsonEscapedS+`everity":"high"`, 1)
	})
	loaded, err := LoadReport(dir2, escapedID)
	if err != nil {
		t.Fatalf("escaped spelling with a legal string must load: %v", err)
	}
	if loaded.Findings[0].Severity != "high" {
		t.Fatalf("escaped severity must read back verbatim, got %q", loaded.Findings[0].Severity)
	}
	if want := ReportID(oneDefectFixture()); escapedID != want {
		t.Fatalf("escaped and plain spellings must share the report id:\n%s\n%s", escapedID, want)
	}
}

// --- 拒绝时不创建任何额外文件，重复读取始终拒绝 ---

func TestLoadReportNullFindingNoFilesAndRepeatedRejection(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "evidence", `null`)
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

// --- diff：任一侧归档含非法缺陷记录成员都整体失败，不输出局部差异，不能把
// 被默认成空字符串的错误值拿去分类或统计 ---

func TestDiffStoreRejectsBadFindingTextEitherSide(t *testing.T) {
	dir := t.TempDir()
	good := oneDefectFixture()
	goodID := writeReportWithFreshID(t, dir, good)

	// 另一侧是另一份合法报告：多一条空严重级别的缺陷规则及其缺陷记录。
	// 损坏其 finding 的 severity 为 null：null 会被洗成 ""，损坏归档与合法
	// 归档共用同一标识，先留一份干净字节。
	hash := ArtifactHash(sampleArtifact())
	other := oneDefectFixture()
	other.Rules = append(other.Rules,
		ReportRule{ID: "r-extra", Kind: "static", Severity: "", Invariant: "inv-extra", Version: "9", Status: StatusDefect, Note: "extra note"})
	other.Findings = append(other.Findings,
		ReportFinding{ArtifactHash: hash, RuleID: "r-extra", Version: "9", Severity: "", Invariant: "inv-extra", Evidence: "extra note"})
	otherID := writeReportWithFreshID(t, dir, other)
	cleanOther, err := os.ReadFile(filepath.Join(dir, otherID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	badID := writeArchiveWithFindingText(t, dir, other, "r-extra", "severity", `null`)
	if badID != otherID {
		t.Fatalf("test setup: null launders to the empty string, so the id must stay %q, got %q", otherID, badID)
	}
	badBytes, err := os.ReadFile(filepath.Join(dir, badID+".json"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		before string
		after  string
		named  string
	}{
		{"second report corrupt", goodID, badID, badID},
		{"first report corrupt", badID, goodID, badID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if data, _ := os.ReadFile(filepath.Join(dir, badID+".json")); !bytes.Contains(data, []byte(`"severity":null`)) {
				t.Fatalf("subtest start: archive already repaired:\n%s", data)
			}
			diff, err := DiffStore(dir, tc.before, tc.after)
			if data, _ := os.ReadFile(filepath.Join(dir, badID+".json")); !bytes.Contains(data, []byte(`"severity":null`)) {
				t.Fatalf("subtest end: DiffStore rewrote the archive:\n%s", data)
			}
			if err == nil {
				t.Fatalf("diff must fail when a side carries a non-string finding member, got %+v", diff)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), "r-extra") ||
				!strings.Contains(err.Error(), "severity must be a string") ||
				!strings.Contains(err.Error(), "findings[1]") ||
				!strings.Contains(err.Error(), tc.named) {
				t.Fatalf("error must name the report, position, rule and string requirement: %v", err)
			}
			if !reflect.DeepEqual(diff, DiffResult{}) {
				t.Fatalf("failed diff must return the zero result, got %+v", diff)
			}
		})
	}

	// 失败的比较不得修复、覆盖损坏侧归档：重复失败后损坏字节原样保留。
	for i := 0; i < 2; i++ {
		if _, err := DiffStore(dir, goodID, badID); err == nil {
			t.Fatal("diff against the corrupt side must keep failing")
		}
		kept, err := os.ReadFile(filepath.Join(dir, badID+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(kept, []byte(`"severity":null`)) {
			t.Fatalf("failed diff must leave the corrupt archive untouched:\n%s", kept)
		}
	}

	// 恢复另一侧后比较成功：证明失败只来自类型关，且成功的比较同样不重写
	// 归档，既有合法报告的比较分类与统计保持不变。
	if err := os.WriteFile(filepath.Join(dir, otherID+".json"), cleanOther, 0o644); err != nil {
		t.Fatal(err)
	}
	diff, err := DiffStore(dir, goodID, otherID)
	if err != nil {
		t.Fatalf("restored archive must diff successfully: %v", err)
	}
	if diff.Summary.AddedRules != 1 || diff.Summary.NoChange != 3 {
		t.Fatalf("legal comparison categories must be unchanged: %+v", diff.Summary)
	}
	if diff.Summary.BeforeDefects != 1 || diff.Summary.AfterDefects != 2 {
		t.Fatalf("defect totals must come from legal findings only: %+v", diff.Summary)
	}
	afterRestore, err := os.ReadFile(filepath.Join(dir, otherID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterRestore, cleanOther) {
		t.Fatal("successful diff must not rewrite the archive")
	}
	if bytes.Equal(badBytes, cleanOther) {
		t.Fatal("test setup: the mutated archive must differ from the clean one")
	}
}

// --- audit 保存遇到同标识已有损坏归档：不能被当成保存成功，原文件保留 ---

func TestSaveReportBadFindingTextExistingArchiveFails(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, emptyTextFixture(), "r-empty", "severity", `null`)
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	r := emptyTextFixture()
	r.ReportID = id
	err = SaveReport(dir, r)
	if err == nil {
		t.Fatal("a corrupt existing archive must not count as a successful save")
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "r-empty") ||
		!strings.Contains(err.Error(), "findings[0]") ||
		!strings.Contains(err.Error(), "severity must be a string") {
		t.Fatalf("error must name the report, position, rule and string requirement: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must be kept: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed save must leave the corrupt archive untouched")
	}
}

// --- 合法归档中常规（非空）文本不受影响：严格重写后解码与读回一致 ---

func TestLoadReportFindingLegalTextUnaffected(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, oneDefectFixture())
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal archive must load: %v", err)
	}
	if !reflect.DeepEqual(loaded.Findings, oneDefectFixture().Findings) {
		t.Fatalf("findings must read back unchanged:\n%+v\n%+v", loaded.Findings, oneDefectFixture().Findings)
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	strict, err := strictReportJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(strict, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, loaded) {
		t.Fatal("strict decode must match the loaded report")
	}
}
