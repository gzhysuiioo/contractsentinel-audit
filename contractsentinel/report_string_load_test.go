package contractsentinel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// jsonEscapedN is the six-character JSON unicode escape that decodes to the
// letter n; it is built by concatenation so the source never carries the
// escape-looking literal as one piece.
const jsonEscapedN = `\` + `u006e`

// 本文件锁定“归档读取”侧规则定义中字符串成员的类型规则。ReportRule 的
// id、kind、severity、invariant、version、status、note 都是 Go 字符串，
// json.Unmarshal 会把正式成员的 null 静默解码成零值 ""：给一条没有说明的
// “通过”规则加入 "note":null，重算的报告标识、规则状态与缺陷绑定仍全部
// 成立，读出的说明也显示为空，归档内容不合法的事实被完全掩盖。
//
// 修正后，正式成员（约定拼写，含 Unicode 转义写法）一旦出现就只允许 JSON
// 字符串；null、布尔值、数字、对象、数组都使整份归档判为损坏，与规则是否
// 已检查、是否发现缺陷、报告是否携带 finding 无关，也不能只跳过该规则返回
// 其余部分。省略该成员仍沿用已有默认值，显式空字符串仍按已有业务规则判断；
// Note、" note " 这类大小写变体或带空格名称只是扩展信息，其中的 null 不触
// 发本错误，也不能替代或挽救非法的正式成员。错误点名报告标识、出错字段与
// 规则数组位置，规则有合法非空 id 时同时点名该规则。

// mutateRuleStringMember rewrites one formal string member of a rule inside
// the archive text. fragment is the complete replacement member (for example
// `"note":null`); an empty fragment removes the member. When the member is
// absent — note is omitted from the archive whenever it is empty — a
// non-empty fragment is appended to the rule object.
func mutateRuleStringMember(t *testing.T, doc, ruleID, field, fragment string) string {
	t.Helper()
	anchor := `"id":"` + ruleID + `"`
	idx := strings.Index(doc, anchor)
	if idx < 0 {
		t.Fatalf("test setup: rule %s not found in archive", ruleID)
	}
	// Rule objects carry no nested objects, so the next closing brace ends
	// the rule; fixture values never contain a brace inside a string.
	ruleEnd := strings.IndexByte(doc[idx:], '}')
	if ruleEnd < 0 {
		t.Fatalf("test setup: rule %s object is not closed", ruleID)
	}
	ruleEnd += idx
	marker := `"` + field + `":`
	rel := strings.Index(doc[idx:ruleEnd], marker)
	if rel < 0 {
		if fragment == "" {
			t.Fatalf("test setup: rule %s has no %s member to remove", ruleID, field)
		}
		return doc[:ruleEnd] + "," + fragment + doc[ruleEnd:]
	}
	memberStart := idx + rel
	valueStart := memberStart + len(marker)
	valueEnd := valueStart
	if doc[valueEnd] == '"' {
		valueEnd++
		for valueEnd < len(doc) {
			if doc[valueEnd] == '\\' {
				valueEnd += 2
				continue
			}
			if doc[valueEnd] == '"' {
				valueEnd++
				break
			}
			valueEnd++
		}
	} else {
		for valueEnd < len(doc) && doc[valueEnd] != ',' && doc[valueEnd] != '}' {
			valueEnd++
		}
	}
	if fragment == "" {
		// Remove the member together with one adjacent comma.
		if valueEnd < len(doc) && doc[valueEnd] == ',' {
			return doc[:memberStart] + doc[valueEnd+1:]
		}
		return doc[:memberStart-1] + doc[valueEnd:]
	}
	return doc[:memberStart] + fragment + doc[valueEnd:]
}

// writeArchiveWithRuleStringMember marshals a legal report and rewrites one
// string member of one rule to a raw fragment. When the fragment launders
// through the plain decoder (null decodes into the string zero value), the
// reportId is recomputed so the archive is self-consistent and rejection can
// only come from the type gate. Other non-string JSON types never unmarshal
// into a Go string, so the original id is kept: it may mismatch, but the type
// gate runs before the id comparison and rejects with the same corruption
// error.
func writeArchiveWithRuleStringMember(t *testing.T, dir string, r Report, ruleID, field, fragment string) string {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	doc := mutateRuleStringMember(t, string(data), ruleID, field, fragment)
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

// expectCorruptStringLoad asserts the full read-side contract for an illegal
// formal string member: errCorrupt naming the report id, the offending field,
// the rule's position in the rules array and — when rule is non-empty — the
// rule itself, a zero report and an untouched archive.
func expectCorruptStringLoad(t *testing.T, dir, id, rule, field string, pos int) {
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
	if !strings.Contains(msg, fmt.Sprintf("rules[%d]", pos)) {
		t.Fatalf("error must name the rule array position rules[%d]: %v", pos, err)
	}
	if !strings.Contains(msg, field+" must be a string") {
		t.Fatalf("error must state %s must be a string: %v", field, err)
	}
	if rule != "" && !strings.Contains(msg, rule) {
		t.Fatalf("error must name the offending rule %q: %v", rule, err)
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

// --- 七个字符串成员逐一写成 null 都使整份归档损坏 ---

func TestLoadReportNullStringMemberRejectedForEveryField(t *testing.T) {
	for _, tc := range []struct {
		field string
		rule  string
		pos   int
		named string // 错误中应点名的规则 id；id 成员本身非法时无法点名
	}{
		{"id", "r-pass", 0, ""},
		{"kind", "r-bad", 1, "r-bad"},
		{"severity", "r-bad", 1, "r-bad"},
		{"invariant", "r-bad", 1, "r-bad"},
		{"version", "r-bad", 1, "r-bad"},
		{"status", "r-bad", 1, "r-bad"},
		{"note", "r-bad", 1, "r-bad"},   // 替换已有的说明
		{"note", "r-pass", 0, "r-pass"}, // 给没有说明的通过规则加入 "note":null
	} {
		t.Run(tc.field+"/"+tc.rule, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), tc.rule, tc.field,
				`"`+tc.field+`":null`)
			expectCorruptStringLoad(t, dir, id, tc.named, tc.field, tc.pos)
		})
	}
}

// --- 核心场景：没有说明的“通过”规则加入 "note":null，标识保持一致仍须拒绝 ---

func TestLoadReportNullNoteOnPassRuleCorruptDespiteMatchingID(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-pass", "note", `"note":null`)

	// null 被洗成 "" 后按省略处理：归档内 reportId、请求 id 与按解码内容
	// 重算的 id 三者一致，除类型关外没有任何一关能拒绝它。
	if want := ReportID(oneDefectFixture()); id != want {
		t.Fatalf("test setup: null note must launder to the omitted note, id %q want %q", id, want)
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"note":null`) {
		t.Fatalf("test setup: archive must carry the null note:\n%s", data)
	}
	strict, err := strictReportJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(strict, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportID != id || ReportID(decoded) != id {
		t.Fatalf("test setup: id must match the laundered content, archive=%q recomputed=%q requested=%q",
			decoded.ReportID, ReportID(decoded), id)
	}
	if decoded.Rules[0].Note != "" {
		t.Fatal("test setup: null must launder to the empty string under the plain decoder")
	}
	expectCorruptStringLoad(t, dir, id, "r-pass", "note", 0)
}

// --- 布尔值、数字、对象、数组同样判为损坏，不能默认成空字符串 ---

func TestLoadReportNonStringMembersRejected(t *testing.T) {
	for _, val := range []string{`true`, `false`, `0`, `1.5`, `{}`, `["x"]`} {
		t.Run(val, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-bad", "note",
				`"note":`+val)
			expectCorruptStringLoad(t, dir, id, "r-bad", "note", 1)
		})
	}
}

// --- null 落在任何检查结论的规则上都使整份归档损坏，不能跳过该规则 ---

func TestLoadReportNullNoteRejectedForEveryRuleStatus(t *testing.T) {
	for pos, ruleID := range []string{"r-pass", "r-defect", "r-unchecked", "r-tool", "r-timeout"} {
		t.Run(ruleID, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleStringMember(t, dir, allStatusFixture(), ruleID, "note", `"note":null`)
			expectCorruptStringLoad(t, dir, id, ruleID, "note", pos)
		})
	}
}

// --- 没有 finding 的报告同样适用：null 不能洗成空字符串 ---

func TestLoadReportNullStringMemberRejectedWithoutFindings(t *testing.T) {
	dir := t.TempDir()
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: ArtifactHash(sampleArtifact())},
		Rules: []ReportRule{
			{ID: "r-pass", Kind: "static", Severity: "medium", Invariant: "inv-pass", Version: "1", Status: StatusPass},
			{ID: "r-none", Kind: "symbolic", Severity: "low", Invariant: "inv-none", Version: "3", Status: StatusUnchecked},
		},
		Findings: []ReportFinding{},
	}
	id := writeArchiveWithRuleStringMember(t, dir, report, "r-none", "kind", `"kind":null`)

	// kind 没有任何业务非空要求：null 洗成 "" 后除类型关外全部合法。
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
	if err := validateReport(decoded, func(msg string) error { return errCorrupt(msg) }); err != nil {
		t.Fatalf("test setup: report must otherwise be legal: %v", err)
	}
	expectCorruptStringLoad(t, dir, id, "r-none", "kind", 1)
}

// --- 兼容行为：省略仍沿用默认值，显式空字符串仍按已有业务规则判断 ---

func TestLoadReportOmittedAndEmptyStringMembersKeepExistingMeaning(t *testing.T) {
	dir := t.TempDir()

	// 省略 kind：读回空字符串，业务规则不要求 kind 非空。
	omittedID := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-pass", "kind", ``)
	omitted, err := LoadReport(dir, omittedID)
	if err != nil {
		t.Fatalf("an omitted kind must still load: %v", err)
	}
	if omitted.Rules[0].Kind != "" {
		t.Fatalf("omitted kind must keep the zero value, got %q", omitted.Rules[0].Kind)
	}

	// 显式空说明与省略说明等价：标识一致，读回为空。
	emptyNoteID := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-pass", "note", `"note":""`)
	if want := ReportID(oneDefectFixture()); emptyNoteID != want {
		t.Fatalf("an explicit empty note must share the id of an omitted note:\n%s\n%s", emptyNoteID, want)
	}
	loaded, err := LoadReport(dir, emptyNoteID)
	if err != nil {
		t.Fatalf("an explicit empty note on a passing rule must load: %v", err)
	}
	if loaded.Rules[0].Note != "" {
		t.Fatalf("empty note must read back empty, got %q", loaded.Rules[0].Note)
	}

	// 显式空状态是字符串，类型关放行，仍由已有业务规则拒绝。
	emptyStatusID := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-pass", "status", `"status":""`)
	_, err = LoadReport(dir, emptyStatusID)
	if err == nil {
		t.Fatal("an explicit empty status must still be rejected by the business rules")
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("empty status classifies as errCorrupt, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "unknown status") {
		t.Fatalf("empty status must be judged by the existing status rule: %v", err)
	}
	if strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an explicit empty string must not trip the type gate: %v", err)
	}
}

// --- 合法报告读回：中文、换行和前后空格原样保留，标识不变 ---

func TestLoadReportPreservesNoteTextExactly(t *testing.T) {
	dir := t.TempDir()
	note := "  反例：攻击者可在 withdraw 中重入\n  第二行证据  "
	report := oneDefectFixture()
	report.Rules[1].Note = note
	report.Findings[0].Evidence = note
	id := writeReportWithFreshID(t, dir, report)

	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal report with multiline padded Chinese text must load: %v", err)
	}
	if loaded.ReportID != id {
		t.Fatalf("report id not preserved: %q", loaded.ReportID)
	}
	if got := loaded.Rules[1].Note; got != note {
		t.Fatalf("note must not be trimmed or rewritten:\n got %q\nwant %q", got, note)
	}
	if got := loaded.Findings[0].Evidence; got != note {
		t.Fatalf("evidence must not be trimmed or rewritten:\n got %q\nwant %q", got, note)
	}
	if got := loaded.Rules[1].Status; got != StatusDefect {
		t.Fatalf("status = %q, want %q", got, StatusDefect)
	}
}

// --- 大小写变体或带空格名称中的 null 是扩展信息：不触发错误 ---

func TestLoadReportStringVariantNullIgnored(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fragment string
	}{
		{"case variant", `"Note":null`},
		{"whitespace padded", `" note ":null`},
		{"case variant string", `"NOTE":"fake"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-pass", "note", tc.fragment)
			loaded, err := LoadReport(dir, id)
			if err != nil {
				t.Fatalf("a variant-named member is extension data and must be ignored: %v", err)
			}
			if loaded.Rules[0].Note != "" {
				t.Fatal("a variant member must not supply the formal note")
			}
			if want := ReportID(oneDefectFixture()); id != want {
				t.Fatalf("extension data must not change the report id:\n got %s\nwant %s", id, want)
			}
		})
	}
}

// --- 正式成员非法时，旁边的大小写变体即使写了合法字符串也不能挽救 ---

func TestLoadReportStringVariantCannotRescueFormalNull(t *testing.T) {
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			dir := t.TempDir()
			fragment := `"note":null,"Note":"x"`
			if pos == "before" {
				fragment = `"Note":"x","note":null`
			}
			id := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-pass", "note", fragment)
			expectCorruptStringLoad(t, dir, id, "r-pass", "note", 0)
		})
	}
}

// --- Unicode 转义写出的正式名称遵守同一字符串规则 ---

func TestLoadReportEscapedStringNameFollowsSameRule(t *testing.T) {
	// "note" 解码后就是 note：null 同样判为损坏。
	dir := t.TempDir()
	nullID := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-pass", "note",
		`"`+jsonEscapedN+`ote":null`)
	expectCorruptStringLoad(t, dir, nullID, "r-pass", "note", 0)

	// 转义写法携带合法字符串时，与直接书写的报告标识一致并按原值读回。
	withNote := oneDefectFixture()
	withNote.Rules[0].Note = "备注"
	escapedID := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-pass", "note",
		`"`+jsonEscapedN+`ote":"备注"`)
	loaded, err := LoadReport(dir, escapedID)
	if err != nil {
		t.Fatalf("escaped spelling with a legal string must load: %v", err)
	}
	if loaded.Rules[0].Note != "备注" {
		t.Fatalf("escaped note must read back verbatim, got %q", loaded.Rules[0].Note)
	}
	if want := ReportID(withNote); escapedID != want {
		t.Fatalf("escaped and plain spellings must share the report id:\n%s\n%s", escapedID, want)
	}
}

// --- 拒绝时不创建任何额外文件，重复读取始终拒绝 ---

func TestLoadReportNullNoteNoFilesAndRepeatedRejection(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-none", "note", `"note":null`)
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

// --- diff：任一侧归档含非法字符串成员都整体失败，不输出局部差异，不把被洗成
// 空字符串的内容判为“无变化” ---

func TestDiffStoreRejectsBadStringMemberEitherSide(t *testing.T) {
	dir := t.TempDir()
	good := oneDefectFixture()
	goodID := writeReportWithFreshID(t, dir, good)

	// 另一侧是另一份合法报告（多一条规则），损坏后落盘；null 会被洗成
	// ""，所以损坏归档与合法归档共用同一标识，先留一份干净字节便于恢复。
	other := oneDefectFixture()
	other.Rules = append(other.Rules,
		ReportRule{ID: "r-extra", Kind: "static", Severity: "info", Invariant: "inv-extra", Version: "9", Status: StatusPass})
	otherID := writeReportWithFreshID(t, dir, other)
	cleanOther, err := os.ReadFile(filepath.Join(dir, otherID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	badID := writeArchiveWithRuleStringMember(t, dir, other, "r-extra", "note", `"note":null`)
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
				t.Fatalf("diff must fail when a side carries a non-string note, got %+v", diff)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), "r-extra") ||
				!strings.Contains(err.Error(), "note must be a string") ||
				!strings.Contains(err.Error(), "rules[3]") ||
				!strings.Contains(err.Error(), tc.named) {
				t.Fatalf("error must name the report, rule, position and string requirement: %v", err)
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

	// 恢复另一侧后比较成功：证明失败只来自类型关，而非报告对本身有问题，
	// 且成功的比较同样不重写归档。
	if err := os.WriteFile(filepath.Join(dir, otherID+".json"), cleanOther, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DiffStore(dir, goodID, otherID); err != nil {
		t.Fatalf("restored archive must diff successfully: %v", err)
	}
	afterRestore, err := os.ReadFile(filepath.Join(dir, otherID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterRestore, cleanOther) {
		t.Fatal("successful diff must not rewrite the archive")
	}
	// 损坏阶段的字节与干净字节确实不同，保证前面的保留断言有效。
	if bytes.Equal(badBytes, cleanOther) {
		t.Fatal("test setup: the mutated archive must differ from the clean one")
	}
}

// --- audit 保存遇到同标识已有损坏归档：不能被当成保存成功，原文件保留 ---

func TestSaveReportBadStringMemberExistingArchiveFails(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleStringMember(t, dir, oneDefectFixture(), "r-pass", "note", `"note":null`)
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
