package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上为报告标识补充回归保障，锁定已有约定：
//
//   - 标识按报告内容确定：仅调整规则与缺陷（检查记录）的排列，两次提交
//     必须拿到同一个报告标识，且缺陷始终携带自己那条规则的产物哈希、
//     版本、严重级别与证据，证据不跟着位置交换；
//   - 取得标识不改变排列：audit 成功输出与 report 读回都保留提交/首次
//     归档时的顺序，只有 diff 的比较结果按规则标识排序——三者是不同
//     的行为，不能因为计算标识忽略顺序就把报告本身重排；
//   - 排列不同与内容真改变必须可区分：规则定义、检查结论、原始说明
//     （哪怕只多一个尾随空格）改变时，标识必须改变；
//   - 说明与证据中的中文、换行与前后空格逐字保留。
//
// 全程只使用既有的 audit / report / diff 命令与既有报告格式，不新增命令。

// 顺序夹具：三条规则、两条缺陷，id 字典序（a < b < pass）与提交顺序
// （b, pass, a）刻意不同。
func cliOrderRules() []cliWireRule {
	return []cliWireRule{
		{ID: "r-defect-b", Kind: "static", Severity: "critical", Invariant: "inv-b", Version: "2.0"},
		{ID: "r-pass", Kind: "static", Severity: "low", Invariant: "inv-p", Version: "1.5"},
		{ID: "r-defect-a", Kind: "static", Severity: "high", Invariant: "inv-a", Version: "1.0"},
	}
}

// 证据与说明刻意包含中文、换行、制表符与前后空格。
const (
	cliOrderEvidenceA = "  反例 A：重入路径可达\n  A 第二行证据  "
	cliOrderEvidenceB = "\t缺陷 B：换行后的尾行\n  B 的证据尾部保留 "
	cliOrderPassNote  = " 通过说明 首行 \n 次行 "
)

// cliOrderChecks 返回 r-pass 通过、r-defect-a/r-defect-b 两条缺陷的检查
// 记录，记录排列刻意与规则排列不同。
func cliOrderChecks(hash string) []cliWireCheck {
	return []cliWireCheck{
		{ArtifactHash: hash, RuleID: "r-defect-a", Version: "1.0", Status: contractsentinel.StatusDefect, Note: cliOrderEvidenceA},
		{ArtifactHash: hash, RuleID: "r-pass", Version: "1.5", Status: contractsentinel.StatusPass, Note: cliOrderPassNote},
		{ArtifactHash: hash, RuleID: "r-defect-b", Version: "2.0", Status: contractsentinel.StatusDefect, Note: cliOrderEvidenceB},
	}
}

func cliOrderInput(rules []cliWireRule, checks []cliWireCheck) cliWireInput {
	return cliWireInput{Artifact: mixedCheckArtifact(), Rules: rules, Checks: checks}
}

func auditOrderReport(t *testing.T, bin, work, store, name string, rules []cliWireRule, checks []cliWireCheck) contractsentinel.Report {
	t.Helper()
	input := writeStructInput(t, work, name, cliOrderInput(rules, checks))
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("audit %s must succeed, exit=%d stderr=%s", name, code, stderr)
	}
	return decodeReport(t, stdout)
}

func ruleIDSequence(r contractsentinel.Report) []string {
	ids := make([]string, len(r.Rules))
	for i, rule := range r.Rules {
		ids[i] = rule.ID
	}
	return ids
}

func findingRuleIDSequence(r contractsentinel.Report) []string {
	ids := make([]string, len(r.Findings))
	for i, f := range r.Findings {
		ids[i] = f.RuleID
	}
	return ids
}

// assertFindingsFollowRules 校验每条缺陷携带自己规则的版本、严重级别、
// 不变式、产物哈希与证据：交换排列只交换整条记录，绝不串位。
func assertFindingsFollowRules(t *testing.T, r contractsentinel.Report, hash string) {
	t.Helper()
	noteByID := map[string]string{
		"r-defect-a": cliOrderEvidenceA,
		"r-defect-b": cliOrderEvidenceB,
	}
	ruleByID := map[string]contractsentinel.ReportRule{}
	for _, rule := range r.Rules {
		ruleByID[rule.ID] = rule
	}
	if len(r.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(r.Findings))
	}
	for i, f := range r.Findings {
		rule, ok := ruleByID[f.RuleID]
		if !ok {
			t.Fatalf("findings[%d] references unknown rule %s", i, f.RuleID)
		}
		if f.ArtifactHash != hash {
			t.Errorf("finding %s artifact hash = %q, want %q", f.RuleID, f.ArtifactHash, hash)
		}
		if f.Version != rule.Version {
			t.Errorf("finding %s version = %q, want rule version %q", f.RuleID, f.Version, rule.Version)
		}
		if f.Severity != rule.Severity {
			t.Errorf("finding %s severity = %q, want rule severity %q", f.RuleID, f.Severity, rule.Severity)
		}
		if f.Invariant != rule.Invariant {
			t.Errorf("finding %s invariant = %q, want %q", f.RuleID, f.Invariant, rule.Invariant)
		}
		if want := noteByID[f.RuleID]; f.Evidence != want {
			t.Errorf("finding %s evidence = %q, want %q", f.RuleID, f.Evidence, want)
		}
	}
}

// --- 排列不同、内容相同：标识一致；两份成功报告各自保留自己的排列与归属 ---

func TestCLIAuditReportIDPermutationIndependent(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := mixedArtifactHash(t)
	rules := cliOrderRules()
	checks := cliOrderChecks(hash)

	// 甲：规则 [b, pass, a]，检查记录 [a, pass, b]。
	first := auditOrderReport(t, bin, work, store, "first.json",
		[]cliWireRule{rules[0], rules[1], rules[2]}, checks)
	// 乙：规则 [a, pass, b]，检查记录整体反转 [b, pass, a]。
	second := auditOrderReport(t, bin, work, store, "second.json",
		[]cliWireRule{rules[2], rules[1], rules[0]},
		[]cliWireCheck{checks[2], checks[1], checks[0]})

	if !hex64.MatchString(first.ReportID) {
		t.Fatalf("report id must be 64 lowercase hex chars, got %q", first.ReportID)
	}
	if first.ReportID != second.ReportID {
		t.Fatalf("content-only permutations must share the report id:\n first=%s\n second=%s", first.ReportID, second.ReportID)
	}

	// audit 的成功输出保留各自的提交顺序，不按标识排序。
	if got := ruleIDSequence(first); !reflect.DeepEqual(got, []string{"r-defect-b", "r-pass", "r-defect-a"}) {
		t.Errorf("first rule order = %v", got)
	}
	if got := ruleIDSequence(second); !reflect.DeepEqual(got, []string{"r-defect-a", "r-pass", "r-defect-b"}) {
		t.Errorf("second rule order = %v", got)
	}
	if got := findingRuleIDSequence(first); !reflect.DeepEqual(got, []string{"r-defect-b", "r-defect-a"}) {
		t.Errorf("first finding order = %v", got)
	}
	if got := findingRuleIDSequence(second); !reflect.DeepEqual(got, []string{"r-defect-a", "r-defect-b"}) {
		t.Errorf("second finding order = %v", got)
	}

	// 同一槽位在两份排列里属于不同规则：证据跟规则走，不跟槽位走。
	if first.Findings[0].RuleID != "r-defect-b" || first.Findings[0].Evidence != cliOrderEvidenceB {
		t.Errorf("first slot 0 = %+v, want r-defect-b with its own evidence", first.Findings[0])
	}
	if second.Findings[0].RuleID != "r-defect-a" || second.Findings[0].Evidence != cliOrderEvidenceA {
		t.Errorf("second slot 0 = %+v, want r-defect-a with its own evidence", second.Findings[0])
	}
	assertFindingsFollowRules(t, first, hash)
	assertFindingsFollowRules(t, second, hash)
}

// --- 首次保存后按标识读回：看到的是首次保存的顺序，且重算标识与归档相符；
// 后到的同标识排列提交不得改写归档 ---

func TestCLIReportReadbackKeepsFirstSavedOrder(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := mixedArtifactHash(t)
	rules := cliOrderRules()
	checks := cliOrderChecks(hash)

	first := auditOrderReport(t, bin, work, store, "first.json",
		[]cliWireRule{rules[0], rules[1], rules[2]}, checks)
	archivePath := filepath.Join(store, first.ReportID+".json")
	firstBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	// 按标识读回：规则与缺陷顺序必须是首次保存时的顺序，不是按标识排序。
	readStdout, readStderr, code := runCLIReport(t, bin, store, first.ReportID)
	if code != 0 {
		t.Fatalf("read-back must succeed, exit=%d stderr=%s", code, readStderr)
	}
	loaded := decodeReport(t, readStdout)
	if loaded.ReportID != first.ReportID {
		t.Fatalf("read-back id = %q, want %q", loaded.ReportID, first.ReportID)
	}
	if !reflect.DeepEqual(loaded, first) {
		t.Fatalf("read-back re-interpreted the first report:\nloaded=%+v\nfirst =%+v", loaded, first)
	}
	if got := ruleIDSequence(loaded); !reflect.DeepEqual(got, []string{"r-defect-b", "r-pass", "r-defect-a"}) {
		t.Errorf("loaded rule order = %v, want first-saved order", got)
	}
	if got := findingRuleIDSequence(loaded); !reflect.DeepEqual(got, []string{"r-defect-b", "r-defect-a"}) {
		t.Errorf("loaded finding order = %v, want first-saved order", got)
	}
	assertFindingsFollowRules(t, loaded, hash)

	// 再提交一份只是排列不同、标识相同的报告：必须成功但不得改写归档。
	second := auditOrderReport(t, bin, work, store, "second.json",
		[]cliWireRule{rules[2], rules[1], rules[0]},
		[]cliWireCheck{checks[2], checks[1], checks[0]})
	if second.ReportID != first.ReportID {
		t.Fatalf("permuted submission must resolve to the same id")
	}
	afterBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterBytes) != string(firstBytes) {
		t.Fatal("later permutation must not rewrite the first archived bytes")
	}

	// 再次读回仍是首次顺序；原始字节里证据按首次顺序排列且逐字保留。
	rereadStdout, _, code := runCLIReport(t, bin, store, first.ReportID)
	if code != 0 {
		t.Fatal("second read-back must succeed")
	}
	reread := decodeReport(t, rereadStdout)
	if got := ruleIDSequence(reread); !reflect.DeepEqual(got, []string{"r-defect-b", "r-pass", "r-defect-a"}) {
		t.Errorf("reread rule order = %v, want first-saved order", got)
	}
	if got := findingRuleIDSequence(reread); !reflect.DeepEqual(got, []string{"r-defect-b", "r-defect-a"}) {
		t.Errorf("reread finding order = %v, want first-saved order", got)
	}
	raw := string(firstBytes)
	ib, ia := strings.Index(raw, "缺陷 B"), strings.Index(raw, "反例 A")
	if ib < 0 || ia < 0 || ib > ia {
		t.Fatalf("archive must keep first-saved evidence order (B before A):\n%s", raw)
	}
	for _, want := range []string{
		`  反例 A：重入路径可达\n  A 第二行证据  `,
		`\t缺陷 B：换行后的尾行\n  B 的证据尾部保留 `,
		` 通过说明 首行 \n 次行 `,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("archive must preserve raw text verbatim, missing %q in:\n%s", want, raw)
		}
	}

	// 同目录下只有这一份归档：同标识即同一份报告。
	if matches, _ := filepath.Glob(filepath.Join(store, "*.json")); len(matches) != 1 {
		t.Fatalf("permutation must not add a second archive, got %v", matches)
	}
}

// --- 报告保持提交顺序，而 diff 的比较结果按规则标识排序：两种行为并存 ---

func TestCLIReportOrderAndDiffOrderingCoexist(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := mixedArtifactHash(t)
	rules := cliOrderRules()
	report := auditOrderReport(t, bin, work, store, "in.json",
		[]cliWireRule{rules[0], rules[1], rules[2]}, cliOrderChecks(hash))

	// 报告本身：未按标识排序。
	readStdout, _, code := runCLIReport(t, bin, store, report.ReportID)
	if code != 0 {
		t.Fatal("report must succeed")
	}
	loaded := decodeReport(t, readStdout)
	if got := ruleIDSequence(loaded); !reflect.DeepEqual(got, []string{"r-defect-b", "r-pass", "r-defect-a"}) {
		t.Fatalf("report must keep submission order, got %v", got)
	}

	// 同一份报告与自己比较：比较结果按规则标识排序，与报告排列无关。
	diffStdout, diffStderr, diffCode := runCLIDiff(t, bin, store, report.ReportID, report.ReportID)
	if diffCode != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", diffCode, diffStderr)
	}
	d := decodeDiff(t, diffStdout)
	ids := make([]string, 0, len(d.Results))
	for _, r := range d.Results {
		ids = append(ids, r.RuleID)
	}
	want := []string{"r-defect-a", "r-defect-b", "r-pass"}
	if !sort.StringsAreSorted(ids) || !reflect.DeepEqual(ids, want) {
		t.Fatalf("diff results must be sorted by rule id, got %v", ids)
	}
}

// --- 排列不同不是内容改变；规则定义、检查结论或原始说明改变必须换标识 ---

func TestCLIAuditReportIDDistinguishesPermutationFromContentChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := mixedArtifactHash(t)
	rules := cliOrderRules()
	checks := cliOrderChecks(hash)

	base := auditOrderReport(t, bin, work, store, "base.json",
		[]cliWireRule{rules[0], rules[1], rules[2]}, checks)

	// 对照组：仅排列不同，标识必须相同。
	permuted := auditOrderReport(t, bin, work, store, "permuted.json",
		[]cliWireRule{rules[2], rules[1], rules[0]},
		[]cliWireCheck{checks[2], checks[1], checks[0]})
	if permuted.ReportID != base.ReportID {
		t.Fatalf("pure permutation must keep the id %s, got %s", base.ReportID, permuted.ReportID)
	}

	// 实验组 1：已通过规则的说明只增加一个尾随空格，也是另一份报告。
	passSpaceInput := cliOrderInput(
		[]cliWireRule{rules[0], rules[1], rules[2]},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: "r-defect-a", Version: "1.0", Status: contractsentinel.StatusDefect, Note: cliOrderEvidenceA},
			{ArtifactHash: hash, RuleID: "r-pass", Version: "1.5", Status: contractsentinel.StatusPass, Note: cliOrderPassNote + " "},
			{ArtifactHash: hash, RuleID: "r-defect-b", Version: "2.0", Status: contractsentinel.StatusDefect, Note: cliOrderEvidenceB},
		})
	passSpace := auditOrderReport(t, bin, work, store, "pass-space.json",
		passSpaceInput.Rules, passSpaceInput.Checks)
	if passSpace.ReportID == base.ReportID {
		t.Fatal("a single trailing space added to a pass note must change the report id")
	}

	// 实验组 2：规则定义改变（严重级别）。
	severityRules := cliOrderRules()
	severityRules[1].Severity = "critical" // r-pass
	severityChanged := auditOrderReport(t, bin, work, store, "severity.json", severityRules, checks)
	if severityChanged.ReportID == base.ReportID {
		t.Fatal("a rule definition change must change the report id")
	}

	// 实验组 3：检查结论改变（通过 → 发现缺陷）。
	statusChecks := []cliWireCheck{
		{ArtifactHash: hash, RuleID: "r-defect-a", Version: "1.0", Status: contractsentinel.StatusDefect, Note: cliOrderEvidenceA},
		{ArtifactHash: hash, RuleID: "r-pass", Version: "1.5", Status: contractsentinel.StatusDefect, Note: "新发现缺陷：通过项反例"},
		{ArtifactHash: hash, RuleID: "r-defect-b", Version: "2.0", Status: contractsentinel.StatusDefect, Note: cliOrderEvidenceB},
	}
	statusChanged := auditOrderReport(t, bin, work, store, "status.json",
		[]cliWireRule{rules[0], rules[1], rules[2]}, statusChecks)
	if statusChanged.ReportID == base.ReportID {
		t.Fatal("a check conclusion change must change the report id")
	}
	if len(statusChanged.Findings) != 3 {
		t.Fatalf("pass-to-defect must add a finding, got %+v", statusChanged.Findings)
	}

	// 三份内容改变的报告各自独立归档，与排列对照组的归档互不覆盖。
	ids := map[string]bool{
		base.ReportID: true, passSpace.ReportID: true,
		severityChanged.ReportID: true, statusChanged.ReportID: true,
	}
	if len(ids) != 4 {
		t.Fatalf("content changes must yield distinct ids: %v", ids)
	}
}

// --- 空集合：没有规则/缺陷的合法报告照常取得标识；未提供集合与显式空
// 集合在标识上等价 ---

func TestCLIAuditReportIDMissingAndEmptyCollectionsEquivalent(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()

	artifactJSON := mustJSON(t, artifact)

	// 省略 rules / checks / invariants：未提供集合。
	missing := writeInput(t, work, "missing.json",
		`{"artifact":`+artifactJSON+`}`)
	missingStdout, missingStderr, missingCode := runCLIAudit(t, bin, missing, store)
	if missingCode != 0 {
		t.Fatalf("artifact-only submission must succeed: exit=%d stderr=%s", missingCode, missingStderr)
	}
	missingReport := decodeReport(t, missingStdout)

	// 显式提供空集合（null 与 [] 也一并覆盖）。
	for _, name := range []string{"empty-array.json", "null.json"} {
		collections := `[]`
		if name == "null.json" {
			collections = `null`
		}
		input := writeInput(t, work, name,
			`{"artifact":`+artifactJSON+
				`,"rules":`+collections+`,"checks":`+collections+`}`)
		stdout, stderr, code := runCLIAudit(t, bin, input, store)
		if code != 0 {
			t.Fatalf("%s: empty collection submission must succeed: exit=%d stderr=%s", name, code, stderr)
		}
		report := decodeReport(t, stdout)
		if report.ReportID != missingReport.ReportID {
			t.Fatalf("%s: explicit empty collection id %s must equal omitted-collection id %s",
				name, report.ReportID, missingReport.ReportID)
		}
		if len(report.Rules) != 0 || len(report.Findings) != 0 {
			t.Fatalf("%s: report must carry no rules or findings: %+v", name, report)
		}
	}

	if !hex64.MatchString(missingReport.ReportID) {
		t.Fatalf("empty report id must still be a valid id, got %q", missingReport.ReportID)
	}

	// 读回的空报告标识与归档相符。
	readStdout, _, code := runCLIReport(t, bin, store, missingReport.ReportID)
	if code != 0 {
		t.Fatal("empty report read-back must succeed")
	}
	if got := decodeReport(t, readStdout).ReportID; got != missingReport.ReportID {
		t.Fatalf("read-back empty report id = %q, want %q", got, missingReport.ReportID)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
