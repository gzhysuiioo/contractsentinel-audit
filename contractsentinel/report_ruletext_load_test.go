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

// 本文件锁定“归档读取”侧规则文本成员的类型规则。ReportRule 的 id、kind、
// severity、invariant、version、status、note 都是 Go 字符串，json.Unmarshal
// 会把正式成员的 null 静默解码成零值 ""：给归档中一条没有说明的“通过”规则
// 加入 "note":null，读出的内容与省略该成员时逐字节相同，重算的报告标识、
// 规则状态与缺陷绑定全部吻合，归档没有按格式保存文本的事实被完全掩盖，
// diff 甚至可能把它判成“无变化”。
//
// 修正后，正式成员（约定拼写，含 Unicode 转义写法）一旦写出，其值就必须是
// JSON 字符串；null、布尔值、数字、对象、数组都使整份归档判为损坏，适用于
// 所有检查状态及没有 finding 的报告。错误点名报告标识、出错字段与规则数组
// 位置，规则有合法非空 id 时同时点名该规则。省略字段仍沿用默认值与必填校验，
// 显式空字符串仍按既有业务规则判断；大小写变体、带空格名称与未知扩展成员
// 继续被忽略，其中的 null 不触发本错误，也不能替代或挽救非法的正式成员。

// jsonEscapedN is the six-character JSON unicode escape that decodes to the
// letter n; it is built by concatenation so the source never carries the
// escape-looking literal as one piece.
const jsonEscapedN = `\` + `u006e`

// mutateRuleTextField 把归档中指定规则的某个文本成员替换为 raw 片段
// （如 null）；该成员不存在时把它插入到 id 成员之后。fragment 为空串表示
// 删除整个成员。
func mutateRuleTextField(t *testing.T, doc, ruleID, field, fragment string) string {
	t.Helper()
	idMember := `"id":"` + ruleID + `"`
	idIdx := strings.Index(doc, idMember)
	if idIdx < 0 {
		t.Fatalf("test setup: rule %s not found in archive", ruleID)
	}
	ruleEnd := strings.IndexByte(doc[idIdx:], '}')
	if ruleEnd < 0 {
		t.Fatalf("test setup: rule %s object has no end", ruleID)
	}
	ruleEnd += idIdx
	marker := `"` + field + `":`
	at := strings.Index(doc[idIdx:ruleEnd], marker)
	if at < 0 {
		if fragment == "" {
			t.Fatalf("test setup: rule %s has no %s member to remove", ruleID, field)
		}
		idEnd := idIdx + len(idMember)
		return doc[:idEnd] + `,"` + field + `":` + fragment + doc[idEnd:]
	}
	at += idIdx
	valueStart := at + len(marker)
	var valueEnd int
	if doc[valueStart] == '"' {
		// 测试夹具中的字符串值不含转义引号，下一个引号即结束。
		closing := strings.IndexByte(doc[valueStart+1:], '"')
		if closing < 0 {
			t.Fatalf("test setup: rule %s %s value has no closing quote", ruleID, field)
		}
		valueEnd = valueStart + 1 + closing + 1
	} else {
		end := strings.IndexAny(doc[valueStart:], ",}")
		if end < 0 {
			t.Fatalf("test setup: rule %s %s value has no end", ruleID, field)
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

// writeArchiveWithRuleText marshals a legal report, rewrites one rule text
// member with a raw fragment, recomputes the report id from the decoded
// content and writes the archive under that id. A null fragment launders
// through the plain decoder (null decodes into the string zero value), so the
// recomputed id keeps the archive self-consistent and rejection can only come
// from the type gate. Other non-string JSON types never unmarshal into a Go
// string, so the original id is kept: it may mismatch, but the type gate runs
// before the id comparison and rejects with the same corruption error.
func writeArchiveWithRuleText(t *testing.T, dir string, r Report, ruleID, field, fragment string) string {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	doc := mutateRuleTextField(t, string(data), ruleID, field, fragment)
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

// expectCorruptRuleTextLoad asserts the full read-side contract for a
// non-string formal rule text member: errCorrupt naming the report id, the
// array position, the field and the string requirement (plus the rule id when
// the rule carries a legal one), a zero report and an untouched archive.
func expectCorruptRuleTextLoad(t *testing.T, dir, id, position, rule, field string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("a non-string formal %s must reject the whole archive, got %+v", field, got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("illegal %s classifies as errCorrupt, got %T: %v", field, err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, id) {
		t.Fatalf("error must name the report id %q: %v", id, err)
	}
	if !strings.Contains(msg, position) {
		t.Fatalf("error must name the rule array position %q: %v", position, err)
	}
	if rule != "" && !strings.Contains(msg, rule) {
		t.Fatalf("error must name the offending rule %q: %v", rule, err)
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

// --- 核心场景：给没有说明的“通过”规则加入 "note":null，标识仍一致也必须拒绝 ---

func TestLoadReportNullNoteOnPassingRuleRejected(t *testing.T) {
	dir := t.TempDir()
	legal := oneDefectFixture()
	id := writeArchiveWithRuleText(t, dir, legal, "r-pass", "note", `null`)

	// null 被洗成 ""：归档内 reportId、请求 id 与按解码内容重算的 id 三者
	// 一致，且与合法报告的标识相同，除类型关外没有任何一关能拒绝它。
	if want := ReportID(legal); id != want {
		t.Fatalf("test setup: null note must launder to the legal report id %q, got %q", want, id)
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"note":null`)) {
		t.Fatalf("test setup: archive must carry the null note:\n%s", data)
	}
	expectCorruptRuleTextLoad(t, dir, id, "rules[0]", "r-pass", "note")
}

// --- 每个文本成员写成 null 都判为损坏，错误点名位置、字段与规则 ---

func TestLoadReportNullRuleTextFieldRejected(t *testing.T) {
	// r-bad 是带说明的缺陷规则，七个文本成员全部写出。
	for _, field := range archiveRuleTextFields {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-bad", field, `null`)
			rule := "r-bad"
			if field == "id" {
				// id 本身非法时没有可点名的规则标识。
				rule = ""
			}
			expectCorruptRuleTextLoad(t, dir, id, "rules[1]", rule, field)
		})
	}
}

// --- null 落在任何检查结论的规则上都使整份归档损坏，包括没有 finding 的报告 ---

func TestLoadReportNullNoteRejectedForEveryRuleStatus(t *testing.T) {
	positions := map[string]string{
		"r-pass": "rules[0]", "r-defect": "rules[1]", "r-unchecked": "rules[2]",
		"r-tool": "rules[3]", "r-timeout": "rules[4]",
	}
	for _, ruleID := range []string{"r-pass", "r-defect", "r-unchecked", "r-tool", "r-timeout"} {
		t.Run(ruleID, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleText(t, dir, allStatusFixture(), ruleID, "note", `null`)
			expectCorruptRuleTextLoad(t, dir, id, positions[ruleID], ruleID, "note")
		})
	}
}

func TestLoadReportNullStatusRejectedForEveryRuleStatus(t *testing.T) {
	positions := map[string]string{
		"r-pass": "rules[0]", "r-defect": "rules[1]", "r-unchecked": "rules[2]",
		"r-tool": "rules[3]", "r-timeout": "rules[4]",
	}
	for _, ruleID := range []string{"r-pass", "r-defect", "r-unchecked", "r-tool", "r-timeout"} {
		t.Run(ruleID, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleText(t, dir, allStatusFixture(), ruleID, "status", `null`)
			expectCorruptRuleTextLoad(t, dir, id, positions[ruleID], ruleID, "status")
		})
	}
}

// noFindingFixture 是一份没有任何 finding 的合法报告：全部规则通过或未检查。
func noFindingFixture() Report {
	hash := ArtifactHash(sampleArtifact())
	return Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r-pass", Kind: "static", Severity: "low", Invariant: "inv-pass", Version: "1", Status: StatusPass},
			{ID: "r-none", Kind: "symbolic", Severity: "info", Invariant: "inv-none", Version: "2", Status: StatusUnchecked},
		},
		Findings: []ReportFinding{},
	}
}

func TestLoadReportNullTextFieldRejectedWithoutFindings(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleText(t, dir, noFindingFixture(), "r-pass", "note", `null`)
	if want := ReportID(noFindingFixture()); id != want {
		t.Fatalf("test setup: null note must launder to the legal report id %q, got %q", want, id)
	}
	expectCorruptRuleTextLoad(t, dir, id, "rules[0]", "r-pass", "note")
}

// --- 布尔值、数字、对象、数组同样判为损坏，不能默认成空字符串 ---

func TestLoadReportNonStringRuleTextFieldRejected(t *testing.T) {
	for _, val := range []string{`true`, `false`, `0`, `1`, `{}`, `[]`, `["x"]`} {
		t.Run(val, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-bad", "note", val)
			expectCorruptRuleTextLoad(t, dir, id, "rules[1]", "r-bad", "note")
		})
	}
	for _, val := range []string{`true`, `0`, `{}`, `[]`} {
		t.Run("status "+val, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-pass", "status", val)
			expectCorruptRuleTextLoad(t, dir, id, "rules[0]", "r-pass", "status")
		})
	}
}

// --- 兼容行为：省略成员与显式空字符串仍按既有规则处理，合法文本原样读回 ---

func TestLoadReportRuleTextOmittedAndEmptyStringSemantics(t *testing.T) {
	dir := t.TempDir()

	// 显式空字符串 note 与省略一样合法（通过可以没有说明），标识不变。
	emptyNoteID := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-pass", "note", `""`)
	loaded, err := LoadReport(dir, emptyNoteID)
	if err != nil {
		t.Fatalf("an explicit empty-string note must still load: %v", err)
	}
	if loaded.Rules[0].Note != "" {
		t.Fatalf("empty note must read back empty, got %q", loaded.Rules[0].Note)
	}
	if want := ReportID(oneDefectFixture()); emptyNoteID != want {
		t.Fatalf("explicit empty note and omitted note must share the report id:\n%s\n%s", emptyNoteID, want)
	}

	// 显式空字符串 kind 不被类型关拒绝（kind 没有非空要求）。
	emptyKindID := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-pass", "kind", `""`)
	if _, err := LoadReport(dir, emptyKindID); err != nil {
		t.Fatalf("an explicit empty-string kind must not hit the type gate: %v", err)
	}

	// 显式空字符串 version 仍由既有必填校验拒绝，而不是类型错误。
	emptyVersionID := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-pass", "version", `""`)
	_, err = LoadReport(dir, emptyVersionID)
	if err == nil {
		t.Fatal("an empty version must still be rejected by the business rule")
	}
	if !strings.Contains(err.Error(), "has an empty version") {
		t.Fatalf("empty version must keep the business-rule error, got: %v", err)
	}
	if strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an explicit empty string is not a type error: %v", err)
	}
}

// --- 合法报告读回后标识、结论、说明与缺陷证据保持原值，中文、换行和前后
// 空格不得被修剪或改写 ---

func TestLoadReportRuleTextPreservedVerbatim(t *testing.T) {
	dir := t.TempDir()
	note := "  反例：重入路径仍可达\n第二行证据  "
	r := oneDefectFixture()
	r.Rules[1].Note = note
	r.Findings[0].Evidence = note
	id := writeReportWithFreshID(t, dir, r)
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal report must load: %v", err)
	}
	if loaded.ReportID != id || ReportID(loaded) != id {
		t.Fatalf("report id must be preserved: %q vs %q", loaded.ReportID, id)
	}
	if loaded.Rules[1].Note != note {
		t.Fatalf("note must read back verbatim, got %q", loaded.Rules[1].Note)
	}
	if loaded.Findings[0].Evidence != note {
		t.Fatalf("evidence must read back verbatim, got %q", loaded.Findings[0].Evidence)
	}
	if loaded.Rules[1].Status != StatusDefect {
		t.Fatalf("status must be preserved, got %q", loaded.Rules[1].Status)
	}
}

// --- 大小写变体或带空格名称中的 null 是扩展信息：不触发错误，也不能挽救
// 非法的正式成员 ---

func TestLoadReportRuleTextVariantNullIgnored(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"case variant", "Note"},
		{"whitespace padded", " note "},
		{"case variant status", "Status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-pass", tc.field, `null`)
			loaded, err := LoadReport(dir, id)
			if err != nil {
				t.Fatalf("a variant-named member is extension data and must be ignored: %v", err)
			}
			if loaded.Rules[0].Note != "" || loaded.Rules[0].Status != StatusPass {
				t.Fatalf("a variant member must not supply formal values: %+v", loaded.Rules[0])
			}
			if want := ReportID(oneDefectFixture()); id != want {
				t.Fatalf("extension data must not change the report id:\n got %s\nwant %s", id, want)
			}
		})
	}
}

func TestLoadReportRuleTextVariantCannotRescueFormalNull(t *testing.T) {
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			dir := t.TempDir()
			fragment := `null,"Note":"x"`
			if pos == "before" {
				// 变体在正式成员之前：先插入变体，再把正式成员改成 null。
				id := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-bad", "note", `null`)
				path := filepath.Join(dir, id+".json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				doc := strings.Replace(string(data), `"note":null`, `"Note":"x","note":null`, 1)
				if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
					t.Fatal(err)
				}
				expectCorruptRuleTextLoad(t, dir, id, "rules[1]", "r-bad", "note")
				return
			}
			id := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-bad", "note", fragment)
			expectCorruptRuleTextLoad(t, dir, id, "rules[1]", "r-bad", "note")
		})
	}
}

// --- Unicode 转义写出的正式名称遵守同一字符串规则 ---

func TestLoadReportEscapedRuleTextNameFollowsSameRule(t *testing.T) {
	// "note" 解码后就是 note：null 同样判为损坏。
	dir := t.TempDir()
	nullID := writeVariantArchiveText(t, dir, oneDefectFixture(), func(doc string) string {
		mutated := strings.Replace(doc, `"id":"r-pass"`, `"id":"r-pass","`+jsonEscapedN+`ote":null`, 1)
		if mutated == doc {
			t.Fatal("test setup: escaped-name insertion did not change the archive")
		}
		return mutated
	})
	expectCorruptRuleTextLoad(t, dir, nullID, "rules[0]", "r-pass", "note")

	// 转义写法携带合法字符串时，与直接书写的报告标识一致并按原值读回。
	withNote := oneDefectFixture()
	withNote.Rules[0].Note = "说明"
	escapedID := writeVariantArchiveText(t, dir, oneDefectFixture(), func(doc string) string {
		return strings.Replace(doc, `"id":"r-pass"`, `"id":"r-pass","`+jsonEscapedN+`ote":"说明"`, 1)
	})
	loaded, err := LoadReport(dir, escapedID)
	if err != nil {
		t.Fatalf("escaped spelling with a legal string must load: %v", err)
	}
	if loaded.Rules[0].Note != "说明" {
		t.Fatalf("escaped note must read back verbatim, got %q", loaded.Rules[0].Note)
	}
	if want := ReportID(withNote); escapedID != want {
		t.Fatalf("escaped and plain spellings must share the report id:\n%s\n%s", escapedID, want)
	}
}

// --- 拒绝时不创建任何额外文件，重复读取始终拒绝 ---

func TestLoadReportNullRuleTextNoFilesAndRepeatedRejection(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-none", "note", `null`)
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

// --- diff：任一侧归档含非法文本成员都整体失败，不输出局部差异，不能把被
// 默认成空字符串的内容判为“无变化” ---

func TestDiffStoreRejectsBadRuleTextEitherSide(t *testing.T) {
	dir := t.TempDir()
	good := oneDefectFixture()
	goodID := writeReportWithFreshID(t, dir, good)

	// 另一侧是另一份合法报告（多一条无说明的通过规则），损坏后落盘；null
	// 会被洗成 ""，所以损坏归档与合法归档共用同一标识，先留一份干净字节。
	other := oneDefectFixture()
	other.Rules = append(other.Rules,
		ReportRule{ID: "r-extra", Kind: "static", Severity: "info", Invariant: "inv-extra", Version: "9", Status: StatusPass})
	otherID := writeReportWithFreshID(t, dir, other)
	cleanOther, err := os.ReadFile(filepath.Join(dir, otherID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	badID := writeArchiveWithRuleText(t, dir, other, "r-extra", "note", `null`)
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
			if data, _ := os.ReadFile(filepath.Join(dir, badID+".json")); !bytes.Contains(data, []byte(`"note":null`)) {
				t.Fatalf("subtest start: archive already repaired:\n%s", data)
			}
			diff, err := DiffStore(dir, tc.before, tc.after)
			if data, _ := os.ReadFile(filepath.Join(dir, badID+".json")); !bytes.Contains(data, []byte(`"note":null`)) {
				t.Fatalf("subtest end: DiffStore rewrote the archive:\n%s", data)
			}
			if err == nil {
				t.Fatalf("diff must fail when a side carries a non-string rule text member, got %+v", diff)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), "r-extra") ||
				!strings.Contains(err.Error(), "note must be a string") ||
				!strings.Contains(err.Error(), "rules[3]") ||
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
		if !bytes.Contains(kept, []byte(`"note":null`)) {
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

func TestSaveReportBadRuleTextExistingArchiveFails(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleText(t, dir, oneDefectFixture(), "r-pass", "note", `null`)
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	r := oneDefectFixture()
	r.ReportID = id
	err = SaveReport(dir, r)
	if err == nil {
		t.Fatal("a corrupt existing archive must not count as a successful save")
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "r-pass") ||
		!strings.Contains(err.Error(), "note must be a string") {
		t.Fatalf("error must name the report, rule and string requirement: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must be kept: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed save must leave the corrupt archive untouched")
	}
}

// --- 合法 JSON 文本中的字符串值不受影响：显式字符串的 Unicode 转义写法与
// 直接书写读回同一内容 ---

func TestLoadReportRuleTextLegalStringUnaffected(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, oneDefectFixture())
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal archive must load: %v", err)
	}
	if !reflect.DeepEqual(loaded.Rules, oneDefectFixture().Rules) {
		t.Fatalf("rules must read back unchanged:\n%+v\n%+v", loaded.Rules, oneDefectFixture().Rules)
	}
	// 严格重写后的归档再解码必须与直接解码一致（正式成员全部保留）。
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
