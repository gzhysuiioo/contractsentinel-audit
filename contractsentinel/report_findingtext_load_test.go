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
// artifactHash、ruleId、version、severity、invariant、evidence 全是 Go 字符串，
// json.Unmarshal 会把正式成员的 null 静默解码成零值 ""：当一份合法报告的
// 规则与缺陷记录都把 severity（或 invariant）保存为空字符串时，只把 findings
// 中对应记录的该成员改成 null，产物哈希、报告标识与规则/缺陷归属仍然全部
// 吻合，归档没有保存合法文本却被当成合法空文本读回，diff 甚至可能把它判成
// “无变化”。
//
// 修正后，正式成员（约定拼写，含 Unicode 转义写法）一旦写出，其值就必须是
// JSON 字符串；null、布尔值、数字、对象、数组都使整份归档判为损坏，即使产物
// 哈希、报告标识以及规则与缺陷的对应关系仍吻合也不例外。错误点名请求的报告
// 标识、出错记录在 findings 数组中从零开始的位置和成员名，明确该成员必须是
// 字符串；记录的 ruleId 本身是合法非空字符串时，还要指出所属规则。成员省略
// 或显式写成空字符串时，继续按原有必填和绑定要求判断，不新增所有文本必须
// 非空的限制。大小写变体、两侧带空格的名称和未知成员仍作为扩展信息忽略，
// 不能替代缺失字段或挽救非法正式值。

// jsonEscapedS is the six-character JSON unicode escape that decodes to the
// letter s; it is built by concatenation so the source never carries the
// escape-looking literal as one piece.
const jsonEscapedS = `\` + `u0073`

// mutateFindingField 把归档 findings 中指定记录（按其当前 ruleId 定位）的某个
// 文本成员替换为 raw 片段（如 null）；该成员不存在时把它插入到记录对象开头。
// fragment 为空串表示删除整个成员。
func mutateFindingField(t *testing.T, doc, ruleID, field, fragment string) string {
	t.Helper()
	findingsAt := strings.Index(doc, `"findings"`)
	if findingsAt < 0 {
		t.Fatal("test setup: archive has no findings member")
	}
	idMember := `"ruleId":"` + ruleID + `"`
	idIdx := strings.Index(doc[findingsAt:], idMember)
	if idIdx < 0 {
		t.Fatalf("test setup: finding for rule %s not found in archive", ruleID)
	}
	idIdx += findingsAt
	recStart := strings.LastIndexByte(doc[findingsAt:idIdx], '{')
	if recStart < 0 {
		t.Fatalf("test setup: finding for rule %s object has no start", ruleID)
	}
	recStart += findingsAt
	recEnd := strings.IndexByte(doc[idIdx:], '}')
	if recEnd < 0 {
		t.Fatalf("test setup: finding for rule %s object has no end", ruleID)
	}
	recEnd += idIdx
	marker := `"` + field + `":`
	at := strings.Index(doc[recStart:recEnd], marker)
	if at < 0 {
		if fragment == "" {
			t.Fatalf("test setup: finding for rule %s has no %s member to remove", ruleID, field)
		}
		// 成员不存在：插到记录对象的开括号之后。
		insertAt := recStart + 1
		return doc[:insertAt] + `"` + field + `":` + fragment + `,` + doc[insertAt:]
	}
	at += recStart
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
// text member with a raw fragment, recomputes the report id from the decoded
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
// non-string formal finding text member: errCorrupt naming the report id, the
// findings array position, the field and the string requirement (plus the rule
// id when the record carries a legal one), a zero report and an untouched
// archive.
func expectCorruptFindingTextLoad(t *testing.T, dir, id, position, rule, field string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("a non-string formal finding %s must reject the whole archive, got %+v", field, got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("illegal finding %s classifies as errCorrupt, got %T: %v", field, err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, id) {
		t.Fatalf("error must name the report id %q: %v", id, err)
	}
	if !strings.Contains(msg, position) {
		t.Fatalf("error must name the findings array position %q: %v", position, err)
	}
	if rule != "" && !strings.Contains(msg, rule) {
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

// emptySeverityFixture 是一份规则与缺陷记录都把 severity 与 invariant 保存为
// 空字符串的合法报告：这正是 null 能洗成合法空文本的关键形态。
func emptySeverityFixture() Report {
	hash := ArtifactHash(sampleArtifact())
	return Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r-pass", Kind: "static", Severity: "low", Invariant: "inv-pass", Version: "1", Status: StatusPass},
			{ID: "r-empty", Kind: "static", Severity: "", Invariant: "", Version: "2", Status: StatusDefect, Note: "counterexample: empty-text"},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r-empty", Version: "2", Severity: "", Invariant: "", Evidence: "counterexample: empty-text"},
		},
	}
}

// --- 核心场景：合法空文本报告，把缺陷记录的 severity 改成 null，标识不变也
// 必须拒绝 ---

func TestLoadReportNullFindingSeverityOnEmptyTextRejected(t *testing.T) {
	dir := t.TempDir()
	legal := emptySeverityFixture()
	id := writeArchiveWithFindingText(t, dir, legal, "r-empty", "severity", `null`)

	// null 被洗成 ""：归档内 reportId、请求 id 与按解码内容重算的 id 三者
	// 一致，且与合法空文本报告的标识完全相同；除类型关外没有任何一关能拒绝。
	if want := ReportID(legal); id != want {
		t.Fatalf("test setup: null severity must launder to the legal report id %q, got %q", want, id)
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"severity":null`)) {
		t.Fatalf("test setup: archive must carry the null finding severity:\n%s", data)
	}
	expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-empty", "severity")
}

// --- invariant 原本为空字符串时存在同样问题 ---

func TestLoadReportNullFindingInvariantOnEmptyTextRejected(t *testing.T) {
	dir := t.TempDir()
	legal := emptySeverityFixture()
	id := writeArchiveWithFindingText(t, dir, legal, "r-empty", "invariant", `null`)
	if want := ReportID(legal); id != want {
		t.Fatalf("test setup: null invariant must launder to the legal report id %q, got %q", want, id)
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"invariant":null`)) {
		t.Fatalf("test setup: archive must carry the null finding invariant:\n%s", data)
	}
	expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-empty", "invariant")
}

// --- 六个文本成员写成 null 都判为损坏，错误点名位置、字段与规则 ---

func TestLoadReportNullFindingFieldRejected(t *testing.T) {
	for _, field := range archiveFindingTextFields {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", field, `null`)
			rule := "r-bad"
			if field == "ruleId" {
				// ruleId 本身非法时没有可点名的规则标识。
				rule = ""
			}
			expectCorruptFindingTextLoad(t, dir, id, "findings[0]", rule, field)
		})
	}
}

// --- 即使产物哈希、报告标识与归属全部吻合，非字符串值也不能被接受 ---

func TestLoadReportNonStringFindingFieldRejected(t *testing.T) {
	for _, val := range []string{`true`, `false`, `0`, `1`, `{}`, `[]`, `["x"]`} {
		t.Run(val, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithFindingText(t, dir, emptySeverityFixture(), "r-empty", "severity", val)
			expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-empty", "severity")
		})
	}
	for _, val := range []string{`true`, `0`, `{}`, `[]`} {
		t.Run("evidence "+val, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "evidence", val)
			expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-bad", "evidence")
		})
	}
}

// --- 多条缺陷记录时，错误给出从零开始的正确位置 ---

func twoDefectFindingFixture() Report {
	hash := ArtifactHash(sampleArtifact())
	return Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r-one", Kind: "static", Severity: "high", Invariant: "inv-one", Version: "1", Status: StatusDefect, Note: "counterexample one"},
			{ID: "r-two", Kind: "static", Severity: "low", Invariant: "inv-two", Version: "2", Status: StatusDefect, Note: "counterexample two"},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r-one", Version: "1", Severity: "high", Invariant: "inv-one", Evidence: "counterexample one"},
			{ArtifactHash: hash, RuleID: "r-two", Version: "2", Severity: "low", Invariant: "inv-two", Evidence: "counterexample two"},
		},
	}
}

func TestLoadReportNullFindingNamesZeroBasedPosition(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, twoDefectFindingFixture(), "r-two", "artifactHash", `null`)
	expectCorruptFindingTextLoad(t, dir, id, "findings[1]", "r-two", "artifactHash")
}

// --- 兼容行为：省略成员与显式空字符串仍按既有规则处理 ---

func TestLoadReportFindingTextOmittedAndEmptyStringSemantics(t *testing.T) {
	dir := t.TempDir()

	// 显式空字符串 severity：合法空文本报告本来就把它写成 ""，必须正常读回且
	// 标识不变，不新增“所有文本必须非空”的限制。
	emptySeverityID := writeReportWithFreshID(t, dir, emptySeverityFixture())
	loaded, err := LoadReport(dir, emptySeverityID)
	if err != nil {
		t.Fatalf("an explicit empty-string finding severity must still load: %v", err)
	}
	if loaded.Findings[0].Severity != "" {
		t.Fatalf("empty severity must read back empty, got %q", loaded.Findings[0].Severity)
	}
	if want := ReportID(emptySeverityFixture()); emptySeverityID != want {
		t.Fatalf("explicit empty severity must keep the legal report id:\n%s\n%s", emptySeverityID, want)
	}

	// 省略 severity 同样解码成 ""，在空文本报告中仍与规则吻合、合法读回，
	// 而不是触发类型错误。
	omittedID := writeArchiveWithFindingText(t, dir, emptySeverityFixture(), "r-empty", "severity", ``)
	loaded, err = LoadReport(dir, omittedID)
	if err != nil {
		t.Fatalf("an omitted finding severity keeps the zero value and the existing binding rules: %v", err)
	}
	if loaded.Findings[0].Severity != "" {
		t.Fatalf("omitted severity must read back empty, got %q", loaded.Findings[0].Severity)
	}

	// 省略 ruleId 仍由既有必填校验拒绝（空 rule id），而不是类型错误。
	omittedRuleID := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "ruleId", ``)
	_, err = LoadReport(dir, omittedRuleID)
	if err == nil {
		t.Fatal("an omitted ruleId must still be rejected by the business rule")
	}
	if !strings.Contains(err.Error(), "empty rule id") {
		t.Fatalf("omitted ruleId must keep the business-rule error, got: %v", err)
	}
	if strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an omitted member is not a type error: %v", err)
	}

	// 省略 evidence 仍由既有绑定校验拒绝（证据与规则说明不符），不是类型错误。
	omittedEvidenceID := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "evidence", ``)
	_, err = LoadReport(dir, omittedEvidenceID)
	if err == nil {
		t.Fatal("an omitted evidence must still be rejected by the binding rule")
	}
	if !strings.Contains(err.Error(), "has evidence ") {
		t.Fatalf("omitted evidence must keep the binding-mismatch error, got: %v", err)
	}
	if strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("an omitted member is not a type error: %v", err)
	}
}

// --- 合法报告读回后标识、缺陷归属和证据原文保持不变，中文、换行和前后空格
// 不得被修剪或改写 ---

func TestLoadReportFindingTextPreservedVerbatim(t *testing.T) {
	dir := t.TempDir()
	evidence := "  反例：重入路径仍可达\n第二行证据  "
	r := oneDefectFixture()
	r.Rules[1].Note = evidence
	r.Findings[0].Evidence = evidence
	id := writeReportWithFreshID(t, dir, r)
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a legal report must load: %v", err)
	}
	if loaded.ReportID != id || ReportID(loaded) != id {
		t.Fatalf("report id must be preserved: %q vs %q", loaded.ReportID, id)
	}
	if loaded.Findings[0] != r.Findings[0] {
		t.Fatalf("finding must read back verbatim:\n got %+v\nwant %+v", loaded.Findings[0], r.Findings[0])
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
		{"whitespace padded", " severity "},
		{"case variant evidence", "Evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", tc.field, `null`)
			loaded, err := LoadReport(dir, id)
			if err != nil {
				t.Fatalf("a variant-named member is extension data and must be ignored: %v", err)
			}
			if loaded.Findings[0] != oneDefectFixture().Findings[0] {
				t.Fatalf("a variant member must not supply finding values: %+v", loaded.Findings[0])
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
				// 先插入正式 null，再插入位于其前的变体合法值。
				id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "severity", `null`)
				path := filepath.Join(dir, id+".json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				doc := strings.Replace(string(data), `"severity":null`, `"Severity":"critical","severity":null`, 1)
				if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
					t.Fatal(err)
				}
				expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-bad", "severity")
				return
			}
			id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "severity",
				`null,"Severity":"critical"`)
			expectCorruptFindingTextLoad(t, dir, id, "findings[0]", "r-bad", "severity")
		})
	}
}

// 变体同样不能替代缺失的正式成员：只写 "Severity" 而省略 severity 时，空文本
// 报告仍按默认 "" 走绑定判断（此处合法），变体值不得顶替正式值。
func TestLoadReportFindingTextVariantCannotReplaceMissing(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "severity", ``)
	// 此时记录没有正式 severity；再插入一个携带其他值的变体成员。
	path := filepath.Join(dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(data), `"ruleId":"r-bad"`, `"ruleId":"r-bad","Severity":"critical"`, 1)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadReport(dir, id)
	if err == nil {
		t.Fatal("a variant severity must not fill the missing formal severity, which mismatches the high rule")
	}
	if !strings.Contains(err.Error(), "has severity ") {
		t.Fatalf("the missing formal severity keeps its binding-mismatch judgement, got: %v", err)
	}
	if strings.Contains(err.Error(), "must be a string") {
		t.Fatalf("extension data must not turn omission into a type error: %v", err)
	}
}

// --- Unicode 转义写出的正式名称遵守同一字符串规则 ---

func TestLoadReportEscapedFindingNameFollowsSameRule(t *testing.T) {
	dir := t.TempDir()

	// "severity" 首字符写作转义（0x73 == 's'）仍是正式字段本身：把缺陷记录已有
	// 的正式 severity 替换为转义名 + null，必须按类型关判坏而不是被当成未知成员。
	nullID := writeVariantArchiveText(t, dir, oneDefectFixture(), func(doc string) string {
		findingsAt := strings.Index(doc, `"findings"`)
		if findingsAt < 0 {
			t.Fatal("test setup: archive has no findings")
		}
		head, tail := doc[:findingsAt], doc[findingsAt:]
		if !strings.Contains(tail, `"severity":"high"`) {
			t.Fatal("test setup: finding severity not found")
		}
		tail = strings.Replace(tail, `"severity":"high"`,
			`"`+jsonEscapedS+`everity":null`, 1)
		return head + tail
	})
	expectCorruptFindingTextLoad(t, dir, nullID, "findings[0]", "r-bad", "severity")

	// 转义写法携带合法字符串时，与直接书写读回同一内容。把 r-bad 规则及其缺陷
	// 记录的严重级别同时改为 critical（记录一侧用 Unicode 转义拼出成员名），
	// 重算标识后归档自洽，必须成功读回且严重级别逐字保留。
	escapedID := writeVariantArchiveText(t, dir, oneDefectFixture(), func(doc string) string {
		findingsAt := strings.Index(doc, `"findings"`)
		if findingsAt < 0 {
			t.Fatal("test setup: archive has no findings")
		}
		// 第一次命中是 r-bad 规则（rules 在 findings 之前，r-pass 是 medium）。
		mutated := strings.Replace(doc, `"severity":"high"`, `"severity":"critical"`, 1)
		// 剩余的那处就是缺陷记录；用转义名写正式成员。
		head, tail := mutated[:findingsAt], mutated[findingsAt:]
		if !strings.Contains(tail, `"severity":"high"`) {
			t.Fatal("test setup: finding severity not found")
		}
		tail = strings.Replace(tail, `"severity":"high"`, `"`+jsonEscapedS+`everity":"critical"`, 1)
		return head + tail
	})
	loaded, err := LoadReport(dir, escapedID)
	if err != nil {
		t.Fatalf("escaped spelling with a legal string must load: %v", err)
	}
	if loaded.Findings[0].Severity != "critical" {
		t.Fatalf("escaped finding severity must read back verbatim, got %q", loaded.Findings[0].Severity)
	}
	if loaded.Rules[1].Severity != "critical" {
		t.Fatalf("rule severity must read back as critical, got %q", loaded.Rules[1].Severity)
	}
}

// --- 拒绝时不创建任何额外文件，重复读取始终拒绝 ---

func TestLoadReportNullFindingNoFilesAndRepeatedRejection(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, oneDefectFixture(), "r-bad", "invariant", `null`)
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

// --- diff：任一侧归档含非法缺陷记录文本成员都整体失败，不输出局部比较，
// 不能把被默认成空字符串的错误值算进分类或统计 ---

func TestDiffStoreRejectsBadFindingTextEitherSide(t *testing.T) {
	dir := t.TempDir()
	good := oneDefectFixture()
	goodID := writeReportWithFreshID(t, dir, good)

	// 另一侧使用空文本合法报告：null severity 会被洗成 ""，损坏归档与合法归档
	// 共用同一标识；两侧该缺陷记录在解码后完全相同，拒绝只能来自类型关，
	// 否则这份损坏归档会与自身判成“无变化”。
	other := emptySeverityFixture()
	otherID := writeReportWithFreshID(t, dir, other)
	cleanOther, err := os.ReadFile(filepath.Join(dir, otherID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	badID := writeArchiveWithFindingText(t, dir, other, "r-empty", "severity", `null`)
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
			if !strings.Contains(err.Error(), "r-empty") ||
				!strings.Contains(err.Error(), "severity must be a string") ||
				!strings.Contains(err.Error(), "findings[0]") ||
				!strings.Contains(err.Error(), tc.named) {
				t.Fatalf("error must name the report, position, rule and string requirement: %v", err)
			}
			if !reflect.DeepEqual(diff, DiffResult{}) {
				t.Fatalf("failed diff must return the zero result, got %+v", diff)
			}
		})
	}

	// 失败的比较不得修复、覆盖损坏侧归档。
	for i := 0; i < 2; i++ {
		if _, err := DiffStore(dir, goodID, badID); err == nil {
			t.Fatal("diff against the corrupt side must keep failing")
		}
		kept, err := os.ReadFile(filepath.Join(dir, badID+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kept, badBytes) {
			t.Fatalf("failed diff must leave the corrupt archive untouched")
		}
	}

	// 恢复另一侧后比较成功：证明失败只来自类型关，成功的比较不重写归档。
	if err := os.WriteFile(filepath.Join(dir, otherID+".json"), cleanOther, 0o644); err != nil {
		t.Fatal(err)
	}
	diff, err := DiffStore(dir, goodID, otherID)
	if err != nil {
		t.Fatalf("restored archive must diff successfully: %v", err)
	}
	if diff.Summary.AddedRules+diff.Summary.RemovedRules+diff.Summary.ChangedRules == 0 {
		t.Fatalf("expected rule-set differences between the two legal reports, got %+v", diff.Summary)
	}
	afterRestore, err := os.ReadFile(filepath.Join(dir, otherID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterRestore, cleanOther) {
		t.Fatal("successful diff must not rewrite the archive")
	}
}

// --- audit 保存遇到同标识已有损坏归档：不能被当成保存成功，原文件保留 ---

func TestSaveReportBadFindingTextExistingArchiveFails(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithFindingText(t, dir, emptySeverityFixture(), "r-empty", "severity", `null`)
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	r := emptySeverityFixture()
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
