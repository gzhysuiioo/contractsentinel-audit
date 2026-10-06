package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 report / diff 读取已保存报告时对缺陷
// 记录文本成员的类型要求：findings 中每条记录已写出的 artifactHash、ruleId、
// version、severity、invariant、evidence 都必须是 JSON 字符串。把它们写成 null
// （或布尔值、数字、对象、数组）时，即使产物哈希、报告标识以及规则与缺陷的
// 对应关系仍吻合，整份归档也必须判为损坏——非零退出、原因进 stderr（含请求
// 的报告标识、记录在 findings 数组中从零开始的位置、出错成员名；记录的
// ruleId 本身是合法非空字符串时同时指出所属规则，并明确该成员必须是字符
// 串），stdout 不出现任何报告片段，原归档原样保留，不自动改写、删除或补齐。
// 成员省略或显式写成空字符串仍按既有必填与绑定要求判断；"Severity"、
// " evidence " 这类大小写变体或带空格名称只是扩展信息，其中的 null 既不触发
// 错误，也不能挽救非法的正式成员。diff 任一侧遇到同样的归档，也必须在输出
// 比较结果前整体失败，不能依据被当成空字符串的错误值计算分类或统计。

// injectFindingField reads the archive named by id, locates the finding record
// with ruleID inside the findings array and rewrites the formal field member
// with the raw fragment (e.g. `null`); a record that does not carry the member
// gets it inserted right after the record's opening brace. The mutated bytes
// are written back and returned so tests can assert the failed read leaves
// them untouched.
func injectFindingField(t *testing.T, store, id, ruleID, field, fragment string) []byte {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
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
	var out string
	if at < 0 {
		insertAt := recStart + 1
		out = doc[:insertAt] + `"` + field + `":` + fragment + `,` + doc[insertAt:]
	} else {
		at += recStart
		valueStart := at + len(marker)
		var valueEnd int
		if doc[valueStart] == '"' {
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
		out = doc[:at] + `"` + field + `":` + fragment + doc[valueEnd:]
	}
	if out == doc {
		t.Fatal("test setup: injection did not change the archive")
	}
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	return []byte(out)
}

// assertFindingTextCorruptFailure asserts the full CLI failure contract for a
// non-string formal finding text member.
func assertFindingTextCorruptFailure(t *testing.T, stdout, stderr string, code int, id, position, rule, field string) {
	t.Helper()
	if code == 0 {
		t.Fatal("an archive with a non-string finding text member must exit non-zero")
	}
	if !strings.Contains(stderr, "corrupt") {
		t.Fatalf("stderr must classify the archive as corrupt:\n%s", stderr)
	}
	if !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the requested report id %q:\n%s", id, stderr)
	}
	if !strings.Contains(stderr, position) {
		t.Fatalf("stderr must name the findings array position %q:\n%s", position, stderr)
	}
	if rule != "" && !strings.Contains(stderr, rule) {
		t.Fatalf("stderr must name the owning rule %q:\n%s", rule, stderr)
	}
	if !strings.Contains(stderr, field+" must be a string") {
		t.Fatalf("stderr must state %s must be a string:\n%s", field, stderr)
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- report：六个正式成员写成 null 都失败；ruleId 本身非法时只按位置定位 ---

func TestCLIReportNullFindingFieldsFailCleanly(t *testing.T) {
	for _, tc := range []struct {
		field string
		rule  string // ruleId 本身非法时没有可点名的规则标识
	}{
		{"artifactHash", "rule-defect"},
		{"ruleId", ""},
		{"version", "rule-defect"},
		{"severity", "rule-defect"},
		{"invariant", "rule-defect"},
		{"evidence", "rule-defect"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			mutated := injectFindingField(t, store, id, "rule-defect", tc.field, `null`)

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertFindingTextCorruptFailure(t, stdout, stderr, code, id, "findings[0]", tc.rule, tc.field)
			for _, marker := range []string{`"reportId"`, `"rules"`, `"findings"`, contractsentinel.StatusDefect} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a report fragment %q:\n%s", marker, stdout)
				}
			}

			// 归档必须原样保留，不被自动修补或补齐。
			kept, err := os.ReadFile(filepath.Join(store, id+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(kept, mutated) {
				t.Fatalf("failed report read must leave the corrupt archive untouched:\n%s", kept)
			}
		})
	}
}

// --- report：布尔值、数字、对象、数组都同样判为损坏，不能默认成空字符串 ---

func TestCLIReportNonStringFindingFieldsFailCleanly(t *testing.T) {
	for _, field := range []string{"severity", "invariant", "evidence"} {
		for _, val := range []string{`true`, `0`, `{}`, `[]`} {
			t.Run(field+" "+val, func(t *testing.T) {
				bin := auditBinary(t)
				work := t.TempDir()
				store := filepath.Join(work, "reports")
				id := auditOneReport(t, bin, work, store)
				injectFindingField(t, store, id, "rule-defect", field, val)

				stdout, stderr, code := runCLIReport(t, bin, store, id)
				assertFindingTextCorruptFailure(t, stdout, stderr, code, id, "findings[0]", "rule-defect", field)
			})
		}
	}
}

// --- 核心场景：规则与缺陷记录都把 severity 保存为空字符串的合法报告，只把
// finding 的 severity 改成 null，标识不变也必须失败；diff 不能判成“无变化” ---

func emptySeverityCLIInput(hash string) cliWireInput {
	return cliWireInput{
		Artifact: mixedCheckArtifact(),
		Rules: []cliWireRule{
			{ID: "g-empty", Kind: "static", Severity: "", Invariant: "", Version: "1"},
		},
		Checks: []cliWireCheck{
			{ArtifactHash: hash, RuleID: "g-empty", Version: "1", Status: contractsentinel.StatusDefect, Note: "empty-text counterexample"},
		},
	}
}

func auditEmptySeverityReport(t *testing.T, bin, work, store string) string {
	t.Helper()
	input := writeStructInput(t, work, "empty.json", emptySeverityCLIInput(mixedArtifactHash(t)))
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit of empty-text report must succeed: %s", stderr)
	}
	return decodeReport(t, stdout).ReportID
}

func TestCLIReportNullEmptyTextFindingSeverityFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditEmptySeverityReport(t, bin, work, store)
	path := filepath.Join(store, id+".json")
	clean, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := injectFindingField(t, store, id, "g-empty", "severity", `null`)

	// null 被洗成 ""：归档标识必须保持与合法空文本报告一致，拒绝只能来自
	// 类型关，而不是 id 不匹配。
	if !bytes.Contains(mutated, []byte(`"severity":null`)) {
		t.Fatalf("test setup: archive must carry the null finding severity:\n%s", mutated)
	}
	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertFindingTextCorruptFailure(t, stdout, stderr, code, id, "findings[0]", "g-empty", "severity")

	// 即使把这份归档与它自身比较，也必须整体失败，而不是读出“无变化”。
	diffOut, diffErr, diffCode := runCLIDiff(t, bin, store, id, id)
	if diffCode == 0 {
		t.Fatal("diff must not read 无变化 from a null severity laundered into empty text")
	}
	if !strings.Contains(diffErr, "corrupt") || !strings.Contains(diffErr, id) ||
		!strings.Contains(diffErr, "g-empty") || !strings.Contains(diffErr, "severity must be a string") {
		t.Fatalf("diff stderr must name the corrupt report, record, rule and string requirement:\n%s", diffErr)
	}
	if diffOut != "" || strings.Contains(diffOut, contractsentinel.ChangeNoChange) {
		t.Fatalf("diff stdout must stay empty and never render 无变化:\n%s", diffOut)
	}

	// 恢复为合法空文本归档后，report 与自比较都成功，且归档字节不被重写。
	if err := os.WriteFile(path, clean, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLIReport(t, bin, store, id); code != 0 {
		t.Fatal("the restored legal empty-text report must load")
	}
	if diffOut, _, code := runCLIDiff(t, bin, store, id, id); code != 0 {
		t.Fatalf("restored report must diff against itself: %s", diffOut)
	} else if !strings.Contains(diffOut, contractsentinel.ChangeNoChange) {
		t.Fatalf("a legal report compared with itself must show 无变化:\n%s", diffOut)
	}
	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, clean) {
		t.Fatal("reads must not rewrite the restored archive")
	}
}

// --- report：变体名称中的 null 是扩展信息，既不触发错误也不能挽救正式 null ---

func TestCLIReportFindingTextVariantRules(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)

	// 变体携带 null：仍是一份合法报告，缺陷记录按正式成员原样读回。
	injectFindingField(t, store, id, "rule-defect", "Severity", `null`)
	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("a case-variant extension member must not corrupt the report: %s", stderr)
	}
	decoded := decodeReport(t, stdout)
	if len(decoded.Findings) != 1 || decoded.Findings[0].Severity != "high" {
		t.Fatalf("a variant member must not supply the formal finding severity: %+v", decoded.Findings)
	}

	// 正式成员为 null、旁边的变体写了合法字符串（位于其前或其后）都必须失败。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			sub := t.TempDir()
			subStore := filepath.Join(sub, "reports")
			subID := auditOneReport(t, bin, sub, subStore)
			if pos == "before" {
				injectFindingField(t, subStore, subID, "rule-defect", "severity", `null`)
				injectFindingField(t, subStore, subID, "rule-defect", "Severity", `"critical"`)
			} else {
				injectFindingField(t, subStore, subID, "rule-defect", "severity",
					`null,"Severity":"critical"`)
			}
			out, errText, exitCode := runCLIReport(t, bin, subStore, subID)
			assertFindingTextCorruptFailure(t, out, errText, exitCode, subID, "findings[0]", "rule-defect", "severity")
		})
	}
}

// --- diff：任一侧归档含 null 缺陷记录文本成员，比较前失败且不输出局部结果 ---

func TestCLIDiffNullFindingTextEitherSideFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	// 一侧是常规混合状态报告；另一侧是 severity/invariant 均为空字符串的合法
	// 报告，损坏后 null 会被洗成 "" 且归档标识保持不变。
	goodID := auditOneReport(t, bin, work, store)
	emptyID := auditEmptySeverityReport(t, bin, work, store)
	cleanEmpty, err := os.ReadFile(filepath.Join(store, emptyID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	mutated := injectFindingField(t, store, emptyID, "g-empty", "severity", `null`)

	// 第二份损坏。
	stdout, stderr, code := runCLIDiff(t, bin, store, goodID, emptyID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the second report carries a null finding severity")
	}
	if !strings.Contains(stderr, "corrupt") || !strings.Contains(stderr, emptyID) ||
		!strings.Contains(stderr, "g-empty") || !strings.Contains(stderr, "findings[0]") ||
		!strings.Contains(stderr, "severity must be a string") {
		t.Fatalf("stderr must name the corrupt report, position, rule and string requirement:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
	}
	for _, marker := range []string{`"results"`, `"summary"`, contractsentinel.ChangeNoChange, contractsentinel.ChangeRuleAdded} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a partial diff %q:\n%s", marker, stdout)
		}
	}
	if kept, err := os.ReadFile(filepath.Join(store, emptyID+".json")); err != nil || !bytes.Equal(kept, mutated) {
		t.Fatalf("failed diff must leave the corrupt archive untouched: %v", err)
	}

	// 第一份损坏、第二份恢复。
	if err := os.WriteFile(filepath.Join(store, emptyID+".json"), cleanEmpty, 0o644); err != nil {
		t.Fatal(err)
	}
	injectFindingField(t, store, goodID, "rule-defect", "evidence", `null`)
	stdout, stderr, code = runCLIDiff(t, bin, store, goodID, emptyID)
	if code == 0 {
		t.Fatal("diff must exit non-zero when the first report carries a null finding evidence")
	}
	if !strings.Contains(stderr, goodID) || !strings.Contains(stderr, "rule-defect") ||
		!strings.Contains(stderr, "evidence must be a string") {
		t.Fatalf("stderr must name the corrupt first report, rule and string requirement:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must stay empty on failure:\n%s", stdout)
	}

	// 两侧都恢复后比较成功，且成功的比较不重写任何归档。
	goodClean := auditOneReportToCleanBytes(t, bin, work)
	if err := os.WriteFile(filepath.Join(store, goodID+".json"), goodClean, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, emptyID+".json"), cleanEmpty, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLIDiff(t, bin, store, goodID, emptyID)
	if code != 0 {
		t.Fatalf("restored archives must diff successfully: %s", stderr)
	}
	if !strings.Contains(stdout, `"results"`) || !strings.Contains(stdout, `"summary"`) {
		t.Fatalf("restored diff must print the full comparison:\n%s", stdout)
	}
	keptGood, err := os.ReadFile(filepath.Join(store, goodID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	keptEmpty, err := os.ReadFile(filepath.Join(store, emptyID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keptGood, goodClean) || !bytes.Equal(keptEmpty, cleanEmpty) {
		t.Fatal("successful diff must not rewrite either archive")
	}
}

// auditOneReportToCleanBytes audits the standard mixed report into a fresh
// store and returns its clean archive bytes, so a corrupted main-store copy can
// be restored to exactly what audit would have written.
func auditOneReportToCleanBytes(t *testing.T, bin, work string) []byte {
	t.Helper()
	cleanStore := filepath.Join(work, "clean-restore")
	cleanID := auditOneReport(t, bin, work, cleanStore)
	data, err := os.ReadFile(filepath.Join(cleanStore, cleanID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
