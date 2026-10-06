package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护报告标识与排列的约定（用户实际拿到
// 的 audit / report 行为）：
//
//   - 同一份合法报告（多条规则、至少两条缺陷）只调整 rules 与 checks 的
//     排列时，两次 audit 得到同一个报告标识；但每次 audit 成功输出仍保持
//     本次提交自己的顺序，比较结果按标识排序不等于把成功输出重排；
//   - 首次保存后按标识读回，看到的是首次保存时的规则与缺陷顺序，而不是
//     后一次同标识提交的顺序或按标识排序的内容；读回重算的标识与归档
//     标识相符；
//   - 排列无关只限排列：一条已通过规则的说明仅增加一个尾随空格就是另一份
//     报告（新标识、新归档），说明与证据中的中文、换行、制表符与前后空格
//     逐字保留；
//   - 没有规则或没有缺陷的合法提交保持原有结果；省略说明与显式空字符串
//     说明仍是同一个标识。
//
// 用例只使用既有的 audit / report 命令与既有报告 JSON 格式。

const (
	// 三条缺陷/通过说明刻意携带中文、换行、制表符与前后空格。
	cliOrderEvidenceZebra = "  反例 Z：重入 withdraw\n第二行证据  "
	cliOrderEvidenceApple = "\t缺陷 A：越权访问，下一行\n"
	cliOrderPassNote      = " 通过：首行 \n 次行 "
)

// cliOrderArtifact 同时满足 requiresABI 规则与 symbolic 规则的输入要求。
func cliOrderArtifact() cliWireArtifact {
	return cliWireArtifact{
		Name:     "OrderVault",
		ABI:      `[{"name":"withdraw","type":"function"}]`,
		Bytecode: "0x60806040",
		Source:   "contract OrderVault {\n}\n",
	}
}

func cliOrderHash(t *testing.T) string {
	t.Helper()
	a := cliOrderArtifact()
	return contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name: a.Name, ABI: a.ABI, Bytecode: a.Bytecode, Source: a.Source,
	})
}

// 规则标识的字典序为 rule-apple < rule-mango < rule-zebra；用例刻意以不同
// 顺序提交，使任何“偷偷按标识排序”的行为都能在成功输出里被看到。
func cliOrderRuleZebra() cliWireRule {
	return cliWireRule{ID: "rule-zebra", Kind: "static", Severity: "high", Invariant: "inv-zebra", Version: "1.0.0"}
}
func cliOrderRuleMango() cliWireRule {
	return cliWireRule{ID: "rule-mango", Kind: "static", Severity: "low", Invariant: "inv-mango", RequiresABI: true, Version: "2.0.0"}
}
func cliOrderRuleApple() cliWireRule {
	return cliWireRule{ID: "rule-apple", Kind: "symbolic", Severity: "critical", Invariant: "inv-apple", Version: "3.0.0"}
}

func cliOrderCheckZebra(hash string) cliWireCheck {
	return cliWireCheck{ArtifactHash: hash, RuleID: "rule-zebra", Version: "1.0.0", Status: contractsentinel.StatusDefect, Note: cliOrderEvidenceZebra}
}
func cliOrderCheckMango(hash, note string) cliWireCheck {
	return cliWireCheck{ArtifactHash: hash, RuleID: "rule-mango", Version: "2.0.0", Status: contractsentinel.StatusPass, Note: note}
}
func cliOrderCheckApple(hash string) cliWireCheck {
	return cliWireCheck{ArtifactHash: hash, RuleID: "rule-apple", Version: "3.0.0", Status: contractsentinel.StatusDefect, Note: cliOrderEvidenceApple}
}

func cliRuleIDs(r contractsentinel.Report) []string {
	ids := make([]string, len(r.Rules))
	for i, rule := range r.Rules {
		ids[i] = rule.ID
	}
	return ids
}

func cliFindingRuleIDs(r contractsentinel.Report) []string {
	ids := make([]string, len(r.Findings))
	for i, f := range r.Findings {
		ids[i] = f.RuleID
	}
	return ids
}

// assertOrderReportContent 钉住三条规则的状态、两条缺陷的归属与逐字证据：
// 证据只跟规则走，不随缺陷在数组中的位置交换。
func assertOrderReportContent(t *testing.T, r contractsentinel.Report, hash, mangoNote string) {
	t.Helper()
	if len(r.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(r.Rules))
	}
	if len(r.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 defects", len(r.Findings))
	}
	ruleByID := map[string]contractsentinel.ReportRule{}
	for _, rule := range r.Rules {
		ruleByID[rule.ID] = rule
	}
	wantRule := map[string]struct {
		version, status, note string
	}{
		"rule-zebra": {"1.0.0", contractsentinel.StatusDefect, cliOrderEvidenceZebra},
		"rule-mango": {"2.0.0", contractsentinel.StatusPass, mangoNote},
		"rule-apple": {"3.0.0", contractsentinel.StatusDefect, cliOrderEvidenceApple},
	}
	for id, want := range wantRule {
		got, ok := ruleByID[id]
		if !ok {
			t.Fatalf("missing rule %s", id)
		}
		if got.Version != want.version || got.Status != want.status {
			t.Errorf("rule %s = %q/%q, want %q/%q", id, got.Version, got.Status, want.version, want.status)
		}
		if got.Note != want.note {
			t.Errorf("rule %s note = %q, want verbatim %q", id, got.Note, want.note)
		}
	}
	wantFinding := map[string]struct {
		version, severity, invariant, evidence string
	}{
		"rule-zebra": {"1.0.0", "high", "inv-zebra", cliOrderEvidenceZebra},
		"rule-apple": {"3.0.0", "critical", "inv-apple", cliOrderEvidenceApple},
	}
	findingByID := map[string]contractsentinel.ReportFinding{}
	for _, f := range r.Findings {
		findingByID[f.RuleID] = f
		if f.ArtifactHash != hash {
			t.Errorf("finding %s artifact hash = %q, want %q", f.RuleID, f.ArtifactHash, hash)
		}
	}
	for id, want := range wantFinding {
		got, ok := findingByID[id]
		if !ok {
			t.Fatalf("missing finding for %s", id)
		}
		if got.Version != want.version || got.Severity != want.severity || got.Invariant != want.invariant {
			t.Errorf("finding %s binding = version %q severity %q invariant %q, want %q %q %q",
				id, got.Version, got.Severity, got.Invariant, want.version, want.severity, want.invariant)
		}
		if got.Evidence != want.evidence {
			t.Errorf("finding %s evidence = %q, want verbatim %q", id, got.Evidence, want.evidence)
		}
	}
}

// TestCLIReportIDPermutationKeepsSubmissionOrder 两种不同排列的合法提交
// 得到同一报告标识，且各自 audit 成功输出保持本提交的规则与缺陷顺序，
// 内容（含逐字证据）不被重排或改写。
func TestCLIReportIDPermutationKeepsSubmissionOrder(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := cliOrderHash(t)

	inputA := writeStructInput(t, work, "perm-a.json", cliWireInput{
		Artifact: cliOrderArtifact(),
		Rules:    []cliWireRule{cliOrderRuleZebra(), cliOrderRuleMango(), cliOrderRuleApple()},
		Checks:   []cliWireCheck{cliOrderCheckZebra(hash), cliOrderCheckMango(hash, cliOrderPassNote), cliOrderCheckApple(hash)},
	})
	// 第二种排列：规则顺序与 checks 顺序都独立打乱。
	inputB := writeStructInput(t, work, "perm-b.json", cliWireInput{
		Artifact: cliOrderArtifact(),
		Rules:    []cliWireRule{cliOrderRuleApple(), cliOrderRuleMango(), cliOrderRuleZebra()},
		Checks:   []cliWireCheck{cliOrderCheckMango(hash, cliOrderPassNote), cliOrderCheckApple(hash), cliOrderCheckZebra(hash)},
	})

	stdoutA, stderrA, codeA := runCLIAudit(t, bin, inputA, store)
	if codeA != 0 {
		t.Fatalf("perm A audit failed, exit=%d stderr=%s", codeA, stderrA)
	}
	reportA := decodeReport(t, stdoutA)

	stdoutB, stderrB, codeB := runCLIAudit(t, bin, inputB, store)
	if codeB != 0 {
		t.Fatalf("perm B audit failed, exit=%d stderr=%s", codeB, stderrB)
	}
	reportB := decodeReport(t, stdoutB)

	// 排列不同、内容相同：标识一致。
	if reportA.ReportID != reportB.ReportID {
		t.Fatalf("permutation changed the report id:\nA=%q\nB=%q", reportA.ReportID, reportB.ReportID)
	}

	// 两次成功输出各自保持本提交的顺序：比较排序是 diff 的行为，不能重排
	// audit 的成功报告。
	wantARules := []string{"rule-zebra", "rule-mango", "rule-apple"}
	wantBRules := []string{"rule-apple", "rule-mango", "rule-zebra"}
	if got := cliRuleIDs(reportA); !reflect.DeepEqual(got, wantARules) {
		t.Fatalf("audit A rule order = %v, want submission order %v", got, wantARules)
	}
	if got := cliRuleIDs(reportB); !reflect.DeepEqual(got, wantBRules) {
		t.Fatalf("audit B rule order = %v, want submission order %v", got, wantBRules)
	}
	if got := cliFindingRuleIDs(reportA); !reflect.DeepEqual(got, []string{"rule-zebra", "rule-apple"}) {
		t.Fatalf("audit A finding order = %v, want submission order [rule-zebra rule-apple]", got)
	}
	if got := cliFindingRuleIDs(reportB); !reflect.DeepEqual(got, []string{"rule-apple", "rule-zebra"}) {
		t.Fatalf("audit B finding order = %v, want submission order [rule-apple rule-zebra]", got)
	}
	assertOrderReportContent(t, reportA, hash, cliOrderPassNote)
	assertOrderReportContent(t, reportB, hash, cliOrderPassNote)

	// 成功输出中证据的中文、换行、制表符与前后空格必须逐字可见。
	for _, fragment := range []string{
		`"evidence": "  反例 Z：重入 withdraw\n第二行证据  "`,
		`"evidence": "\t缺陷 A：越权访问，下一行\n"`,
		`"note": " 通过：首行 \n 次行 "`,
	} {
		if !strings.Contains(stdoutA, fragment) {
			t.Fatalf("audit stdout must keep text verbatim, missing %s in:\n%s", fragment, stdoutA)
		}
	}
}

// TestCLIReadBackKeepsFirstSavedOrder 首次保存后按标识读回：看到的必须是
// 首次保存时的顺序（即使之后又提交了同标识、不同排列的报告），归档只有
// 一份；读回重算的标识与归档标识相符。
func TestCLIReadBackKeepsFirstSavedOrder(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := cliOrderHash(t)

	inputA := writeStructInput(t, work, "perm-a.json", cliWireInput{
		Artifact: cliOrderArtifact(),
		Rules:    []cliWireRule{cliOrderRuleZebra(), cliOrderRuleMango(), cliOrderRuleApple()},
		Checks:   []cliWireCheck{cliOrderCheckZebra(hash), cliOrderCheckMango(hash, cliOrderPassNote), cliOrderCheckApple(hash)},
	})
	inputB := writeStructInput(t, work, "perm-b.json", cliWireInput{
		Artifact: cliOrderArtifact(),
		Rules:    []cliWireRule{cliOrderRuleApple(), cliOrderRuleMango(), cliOrderRuleZebra()},
		Checks:   []cliWireCheck{cliOrderCheckZebra(hash), cliOrderCheckMango(hash, cliOrderPassNote), cliOrderCheckApple(hash)},
	})

	stdoutA, stderrA, codeA := runCLIAudit(t, bin, inputA, store)
	if codeA != 0 {
		t.Fatalf("first audit failed, exit=%d stderr=%s", codeA, stderrA)
	}
	reportA := decodeReport(t, stdoutA)
	_, stderrB, codeB := runCLIAudit(t, bin, inputB, store)
	if codeB != 0 {
		t.Fatalf("permuted audit of the same content must succeed, exit=%d stderr=%s", codeB, stderrB)
	}

	// 同标识只保留首次归档这一份文件。
	matches, err := filepath.Glob(filepath.Join(store, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("same-content resubmission must not add archives, got %d files: %v", len(matches), matches)
	}

	readStdout, readStderr, readCode := runCLIReport(t, bin, store, reportA.ReportID)
	if readCode != 0 {
		t.Fatalf("read-back must succeed, exit=%d stderr=%s", readCode, readStderr)
	}
	read := decodeReport(t, readStdout)
	if read.ReportID != reportA.ReportID {
		t.Fatalf("read-back id = %q, want %q", read.ReportID, reportA.ReportID)
	}
	// 读回顺序是首次保存顺序，而不是按标识排序（apple 在前）或后一次
	// 提交的顺序。
	if got := cliRuleIDs(read); !reflect.DeepEqual(got, []string{"rule-zebra", "rule-mango", "rule-apple"}) {
		t.Fatalf("read-back rule order = %v, want first-saved order", got)
	}
	if got := cliFindingRuleIDs(read); !reflect.DeepEqual(got, []string{"rule-zebra", "rule-apple"}) {
		t.Fatalf("read-back finding order = %v, want first-saved order", got)
	}
	if !reflect.DeepEqual(read, reportA) {
		t.Fatal("read-back report must equal the first successful submission field by field")
	}
	assertOrderReportContent(t, read, hash, cliOrderPassNote)

	// 归档字节本身也是首次顺序：直接读文件核对，防止读回路径临时排序。
	raw, err := os.ReadFile(filepath.Join(store, reportA.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	archived := decodeReport(t, string(raw))
	if got := cliRuleIDs(archived); !reflect.DeepEqual(got, cliRuleIDs(reportA)) {
		t.Fatalf("archived rule order = %v, want first-saved %v", got, cliRuleIDs(reportA))
	}
}

// TestCLITrailingSpaceInPassNoteChangesReportID 已通过规则的说明仅增加一个
// 尾随空格，必须被当成内容真的改变：新标识、独立归档，按各自标识读回时
// 说明（含那个尾随空格）逐字保留。
func TestCLITrailingSpaceInPassNoteChangesReportID(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := cliOrderHash(t)

	plain := writeStructInput(t, work, "plain.json", cliWireInput{
		Artifact: cliOrderArtifact(),
		Rules:    []cliWireRule{cliOrderRuleZebra(), cliOrderRuleMango(), cliOrderRuleApple()},
		Checks:   []cliWireCheck{cliOrderCheckZebra(hash), cliOrderCheckMango(hash, cliOrderPassNote), cliOrderCheckApple(hash)},
	})
	spacedNote := cliOrderPassNote + " "
	spaced := writeStructInput(t, work, "spaced.json", cliWireInput{
		Artifact: cliOrderArtifact(),
		Rules:    []cliWireRule{cliOrderRuleZebra(), cliOrderRuleMango(), cliOrderRuleApple()},
		Checks:   []cliWireCheck{cliOrderCheckZebra(hash), cliOrderCheckMango(hash, spacedNote), cliOrderCheckApple(hash)},
	})

	stdoutPlain, stderrPlain, codePlain := runCLIAudit(t, bin, plain, store)
	if codePlain != 0 {
		t.Fatalf("plain audit failed, exit=%d stderr=%s", codePlain, stderrPlain)
	}
	reportPlain := decodeReport(t, stdoutPlain)
	stdoutSpaced, stderrSpaced, codeSpaced := runCLIAudit(t, bin, spaced, store)
	if codeSpaced != 0 {
		t.Fatalf("spaced-note audit failed, exit=%d stderr=%s", codeSpaced, stderrSpaced)
	}
	reportSpaced := decodeReport(t, stdoutSpaced)

	if reportPlain.ReportID == reportSpaced.ReportID {
		t.Fatal("a single trailing space in a passing rule note must produce a new id")
	}
	matches, err := filepath.Glob(filepath.Join(store, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("a real content change must archive separately, got %d files", len(matches))
	}

	for _, want := range []struct {
		id, note string
	}{
		{reportPlain.ReportID, cliOrderPassNote},
		{reportSpaced.ReportID, spacedNote},
	} {
		readStdout, readStderr, readCode := runCLIReport(t, bin, store, want.id)
		if readCode != 0 {
			t.Fatalf("read-back by %s failed, exit=%d stderr=%s", want.id, readCode, readStderr)
		}
		read := decodeReport(t, readStdout)
		if read.ReportID != want.id {
			t.Fatalf("read-back id mismatch: %q vs %q", read.ReportID, want.id)
		}
		var gotNote string
		for _, rule := range read.Rules {
			if rule.ID == "rule-mango" {
				gotNote = rule.Note
			}
		}
		if gotNote != want.note {
			t.Fatalf("read-back note = %q, want verbatim %q (trailing whitespace must survive)", gotNote, want.note)
		}
		if !hex64.MatchString(read.ReportID) {
			t.Fatalf("report id must stay a 64 lowercase hex identifier: %q", read.ReportID)
		}
	}
}

// TestCLINoRulesAndNoFindingsReportsStayValid 没有规则（也就没有缺陷）的
// 合法提交仍然成功、取得标识并可原样读回；只有通过规则、没有缺陷的提交
// 读回时 findings 仍为空。
func TestCLINoRulesAndNoFindingsReportsStayValid(t *testing.T) {
	bin := auditBinary(t)

	t.Run("no rules", func(t *testing.T) {
		work := t.TempDir()
		store := filepath.Join(work, "reports")
		input := writeStructInput(t, work, "empty.json", cliWireInput{
			Artifact: cliOrderArtifact(),
			Rules:    []cliWireRule{},
			Checks:   []cliWireCheck{},
		})
		stdout, stderr, code := runCLIAudit(t, bin, input, store)
		if code != 0 {
			t.Fatalf("a submission without rules must be valid, exit=%d stderr=%s", code, stderr)
		}
		saved := decodeReport(t, stdout)
		if len(saved.Rules) != 0 || len(saved.Findings) != 0 {
			t.Fatalf("empty report must carry no rules or findings: %+v", saved)
		}
		readStdout, readStderr, readCode := runCLIReport(t, bin, store, saved.ReportID)
		if readCode != 0 {
			t.Fatalf("empty report read-back failed, exit=%d stderr=%s", readCode, readStderr)
		}
		if readStdout != stdout {
			t.Fatal("empty report read-back must be byte-identical to the success output")
		}
	})

	t.Run("pass only no findings", func(t *testing.T) {
		work := t.TempDir()
		store := filepath.Join(work, "reports")
		hash := cliOrderHash(t)
		input := writeStructInput(t, work, "pass.json", cliWireInput{
			Artifact: cliOrderArtifact(),
			Rules:    []cliWireRule{cliOrderRuleMango()},
			Checks:   []cliWireCheck{cliOrderCheckMango(hash, "")},
		})
		stdout, stderr, code := runCLIAudit(t, bin, input, store)
		if code != 0 {
			t.Fatalf("pass-only submission must be valid, exit=%d stderr=%s", code, stderr)
		}
		saved := decodeReport(t, stdout)
		if len(saved.Findings) != 0 || len(saved.Rules) != 1 || saved.Rules[0].Status != contractsentinel.StatusPass {
			t.Fatalf("pass-only report mismatch: %+v", saved)
		}
		readStdout, _, readCode := runCLIReport(t, bin, store, saved.ReportID)
		if readCode != 0 {
			t.Fatal("pass-only report must read back")
		}
		if readStdout != stdout {
			t.Fatal("pass-only read-back must be byte-identical to the success output")
		}
	})
}

// explicitNoteWire 与 cliWireCheck 的区别仅在 note 没有 omitempty：
// 显式写出 "note":"" 时它确实出现在提交字节里。
type explicitNoteWire struct {
	ArtifactHash string `json:"artifactHash"`
	RuleID       string `json:"ruleId"`
	Version      string `json:"version"`
	Status       string `json:"status"`
	Note         string `json:"note"`
}

type explicitNoteInput struct {
	Artifact cliWireArtifact    `json:"artifact"`
	Rules    []cliWireRule      `json:"rules"`
	Checks   []explicitNoteWire `json:"checks"`
}

// TestCLIOmittedAndEmptyNoteShareReportID 通过规则省略 note 与明确写成
// "note":"" 沿用既有同标识约定：两次提交同标识、归档只保留一份；但该约定
// 不推广到非空说明。
func TestCLIOmittedAndEmptyNoteShareReportID(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := cliOrderHash(t)

	omitted := writeStructInput(t, work, "omitted.json", cliWireInput{
		Artifact: cliOrderArtifact(),
		Rules:    []cliWireRule{cliOrderRuleMango()},
		Checks:   []cliWireCheck{{ArtifactHash: hash, RuleID: "rule-mango", Version: "2.0.0", Status: contractsentinel.StatusPass}},
	})
	empty := writeStructInput(t, work, "empty.json", explicitNoteInput{
		Artifact: cliOrderArtifact(),
		Rules:    []cliWireRule{cliOrderRuleMango()},
		Checks: []explicitNoteWire{{
			ArtifactHash: hash, RuleID: "rule-mango", Version: "2.0.0", Status: contractsentinel.StatusPass, Note: "",
		}},
	})
	nonEmpty := writeStructInput(t, work, "nonempty.json", explicitNoteInput{
		Artifact: cliOrderArtifact(),
		Rules:    []cliWireRule{cliOrderRuleMango()},
		Checks: []explicitNoteWire{{
			ArtifactHash: hash, RuleID: "rule-mango", Version: "2.0.0", Status: contractsentinel.StatusPass, Note: "x",
		}},
	})

	out1, stderr1, code1 := runCLIAudit(t, bin, omitted, store)
	if code1 != 0 {
		t.Fatalf("omitted-note submission must succeed, exit=%d stderr=%s", code1, stderr1)
	}
	out2, stderr2, code2 := runCLIAudit(t, bin, empty, store)
	if code2 != 0 {
		t.Fatalf("empty-note submission must succeed, exit=%d stderr=%s", code2, stderr2)
	}
	id1 := decodeReport(t, out1).ReportID
	id2 := decodeReport(t, out2).ReportID
	if id1 != id2 {
		t.Fatalf("omitted note (%q) and explicit \"\" (%q) must share the id", id1, id2)
	}
	out3, stderr3, code3 := runCLIAudit(t, bin, nonEmpty, store)
	if code3 != 0 {
		t.Fatalf("non-empty-note submission must succeed, exit=%d stderr=%s", code3, stderr3)
	}
	id3 := decodeReport(t, out3).ReportID
	if id3 == id1 {
		t.Fatal("a non-empty note must not be laundered into the omitted-note id")
	}
	matches, err := filepath.Glob(filepath.Join(store, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("omitted/empty note share one archive plus one non-empty archive, got %d files", len(matches))
	}
	// 按共享标识读回，说明仍是空。
	readStdout, _, readCode := runCLIReport(t, bin, store, id1)
	if readCode != 0 {
		t.Fatal("shared-id report must read back")
	}
	read := decodeReport(t, readStdout)
	if read.Rules[0].Note != "" {
		t.Fatalf("read-back note = %q, want empty", read.Rules[0].Note)
	}
}
