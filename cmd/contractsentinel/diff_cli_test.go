package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 diff 命令：用户用 audit 落盘两份
// 规则定义完全一致的报告后，diff 必须把每条规则的变化逐条归类——只有
// 通过→发现缺陷 才是新发现缺陷，发现缺陷→通过 才是已消除缺陷；超时、工具
// 缺失与未检查都证明不了合约安全，也证明不了旧缺陷已修复，一律归为检查
// 状态变化。成功时输出完整可解析的 JSON；任一报告缺失或损坏时非零退出、
// 原因进 stderr、stdout 不出现任何比较结果或局部片段，且归档保持原样。

// 缺陷证据刻意包含中文、换行和前后空格，任何修剪或模板替换都会被抓到。
const (
	oldDefectNote      = "旧缺陷证据：owner 校验缺失"
	resolvedDefectNote = "  旧缺陷：withdraw 可重入\n  修复前反例  "
	newDefectNote      = "  新缺陷：transfer 返回值未检查\n  第二行攻击路径  "
	timeoutDefectNote  = "超时后确认的反例：余额单调性被破坏"
)

// diffCLIRules 是前后两份报告共用的一批规则定义，逐字段完全一致。
func diffCLIRules() []cliWireRule {
	return []cliWireRule{
		{ID: "rule-defect-timeout", Kind: "static", Severity: "high", Invariant: "inv-dt", Version: "1.1.0"},
		{ID: "rule-new-defect", Kind: "static", Severity: "high", Invariant: "inv-nd", Version: "2.0.0"},
		{ID: "rule-resolved", Kind: "static", Severity: "medium", Invariant: "inv-rs", Version: "1.0.0"},
		{ID: "rule-stable", Kind: "static", Severity: "low", Invariant: "inv-st", Version: "3.0.0"},
		{ID: "rule-timeout-defect", Kind: "symbolic", Severity: "critical", Invariant: "inv-td", Version: "0.9.0"},
		{ID: "rule-tool-pass", Kind: "static", Severity: "medium", Invariant: "inv-tp", RequiresABI: true, Version: "4.2.0"},
	}
}

// diffBeforeInput 构造基准报告：两个真实缺陷、一个超时、一个工具缺失。
func diffBeforeInput(hash string) cliWireInput {
	return cliWireInput{
		Artifact: mixedCheckArtifact(),
		Rules:    diffCLIRules(),
		Checks: []cliWireCheck{
			{ArtifactHash: hash, RuleID: "rule-defect-timeout", Version: "1.1.0", Status: contractsentinel.StatusDefect, Note: oldDefectNote},
			{ArtifactHash: hash, RuleID: "rule-new-defect", Version: "2.0.0", Status: contractsentinel.StatusPass},
			{ArtifactHash: hash, RuleID: "rule-resolved", Version: "1.0.0", Status: contractsentinel.StatusDefect, Note: resolvedDefectNote},
			{ArtifactHash: hash, RuleID: "rule-stable", Version: "3.0.0", Status: contractsentinel.StatusPass},
			{ArtifactHash: hash, RuleID: "rule-timeout-defect", Version: "0.9.0", Status: contractsentinel.StatusTimeout, Note: "超过 60s 截止时间"},
			{ArtifactHash: hash, RuleID: "rule-tool-pass", Version: "4.2.0", Status: contractsentinel.StatusToolMissing, Note: "符号执行引擎未安装"},
		},
	}
}

// diffAfterInput 构造新报告：规则定义不变但故意颠倒排列顺序，检查结论
// 覆盖新发现缺陷、已消除缺陷与三种检查状态变化。
func diffAfterInput(hash string) cliWireInput {
	rules := diffCLIRules()
	shuffled := make([]cliWireRule, 0, len(rules))
	for i := len(rules) - 1; i >= 0; i-- {
		shuffled = append(shuffled, rules[i])
	}
	return cliWireInput{
		Artifact: mixedCheckArtifact(),
		Rules:    shuffled,
		Checks: []cliWireCheck{
			{ArtifactHash: hash, RuleID: "rule-defect-timeout", Version: "1.1.0", Status: contractsentinel.StatusTimeout, Note: "超过 90s 截止时间"},
			{ArtifactHash: hash, RuleID: "rule-new-defect", Version: "2.0.0", Status: contractsentinel.StatusDefect, Note: newDefectNote},
			{ArtifactHash: hash, RuleID: "rule-resolved", Version: "1.0.0", Status: contractsentinel.StatusPass},
			{ArtifactHash: hash, RuleID: "rule-stable", Version: "3.0.0", Status: contractsentinel.StatusPass},
			{ArtifactHash: hash, RuleID: "rule-timeout-defect", Version: "0.9.0", Status: contractsentinel.StatusDefect, Note: timeoutDefectNote},
			{ArtifactHash: hash, RuleID: "rule-tool-pass", Version: "4.2.0", Status: contractsentinel.StatusPass},
		},
	}
}

// submitDiffAudit 通过真实 audit 命令落盘一份报告并返回解码后的报告。
func submitDiffAudit(t *testing.T, bin, work, name string, in cliWireInput, store string) contractsentinel.Report {
	t.Helper()
	input := writeStructInput(t, work, name, in)
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit %s must succeed, exit=%d stderr=%s", name, code, stderr)
	}
	return decodeReport(t, stdout)
}

// setupDiffStore 落盘基准与新报告，返回两份报告与存储目录。
func setupDiffStore(t *testing.T, bin string) (contractsentinel.Report, contractsentinel.Report, string) {
	t.Helper()
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := mixedArtifactHash(t)
	before := submitDiffAudit(t, bin, work, "before.json", diffBeforeInput(hash), store)
	after := submitDiffAudit(t, bin, work, "after.json", diffAfterInput(hash), store)
	return before, after, store
}

// runCLIDiff 在真实进程上运行 diff，返回 stdout、stderr 与退出码。
func runCLIDiff(t *testing.T, bin, store, before, after string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, "diff", "--store", store, "--before", before, "--after", after)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return stdout.String(), stderr.String(), exitErr.ExitCode()
	}
	t.Fatalf("failed to start diff: %v", err)
	return "", "", 0
}

func decodeDiff(t *testing.T, raw string) contractsentinel.DiffResult {
	t.Helper()
	var diff contractsentinel.DiffResult
	if err := json.Unmarshal([]byte(raw), &diff); err != nil {
		t.Fatalf("diff output is not parseable JSON: %v\n%s", err, raw)
	}
	return diff
}

// snapshotStore 记录存储目录当前全部文件名与字节内容。
func snapshotStore(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap := make(map[string][]byte, len(entries))
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		snap[e.Name()] = data
	}
	return snap
}

// assertStoreUnchanged 断言存储目录与快照逐文件逐字节一致。
func assertStoreUnchanged(t *testing.T, dir string, snap map[string][]byte) {
	t.Helper()
	now := snapshotStore(t, dir)
	if len(now) != len(snap) {
		t.Fatalf("store file count changed: %d -> %d", len(snap), len(now))
	}
	for name, data := range snap {
		if !bytes.Equal(now[name], data) {
			t.Errorf("diff modified store file %s", name)
		}
	}
}

// assertNoDiffOutput 失败时 stdout 绝不能出现比较结果或局部成功片段：
// 已读到的第一份报告不能当作成功结果输出，读取失败也不能被降级成未检查。
func assertNoDiffOutput(t *testing.T, stdout string) {
	t.Helper()
	if stdout != "" {
		t.Fatalf("failed diff must print nothing to stdout, got:\n%s", stdout)
	}
	for _, marker := range []string{"reportId", "results", contractsentinel.StatusUnchecked} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a partial result fragment %q:\n%s", marker, stdout)
		}
	}
}

// --- 成功路径：完整 JSON、逐条归类、证据原文、汇总一致、按规则标识排序 ---

func TestCLIDiffMixedTransitionsFullResult(t *testing.T) {
	bin := auditBinary(t)
	before, after, store := setupDiffStore(t, bin)
	hash := mixedArtifactHash(t)

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff of two stored reports must succeed, exit=%d stderr=%s", code, stderr)
	}
	diff := decodeDiff(t, stdout)

	// 基准与新报告的位置、标识及产物信息与选择一致。
	if diff.Before.ReportID != before.ReportID || diff.After.ReportID != after.ReportID {
		t.Fatalf("report refs = %q / %q, want %q / %q",
			diff.Before.ReportID, diff.After.ReportID, before.ReportID, after.ReportID)
	}
	if diff.Before.Artifact != before.Artifact || diff.After.Artifact != after.Artifact {
		t.Fatalf("artifact refs = %+v / %+v, want %+v / %+v",
			diff.Before.Artifact, diff.After.Artifact, before.Artifact, after.Artifact)
	}
	if diff.ArtifactNameChanged || diff.ArtifactHashChanged {
		t.Error("same artifact must not be flagged as changed")
	}

	// 同一对报告里不同规则分别发生不同变化，必须逐条归属到对应规则。
	wantChanges := map[string]string{
		"rule-defect-timeout": contractsentinel.ChangeStatusChanged,
		"rule-new-defect":     contractsentinel.ChangeNewDefect,
		"rule-resolved":       contractsentinel.ChangeResolvedDefect,
		"rule-stable":         contractsentinel.ChangeNoChange,
		"rule-timeout-defect": contractsentinel.ChangeStatusChanged,
		"rule-tool-pass":      contractsentinel.ChangeStatusChanged,
	}
	if len(diff.Results) != len(wantChanges) {
		t.Fatalf("results = %d, want %d: %+v", len(diff.Results), len(wantChanges), diff.Results)
	}
	byID := map[string]contractsentinel.RuleDiff{}
	ids := []string{}
	for _, r := range diff.Results {
		byID[r.RuleID] = r
		ids = append(ids, r.RuleID)
		if r.Before == nil || r.After == nil {
			t.Errorf("rule %s must keep both sides: %+v", r.RuleID, r)
		}
	}
	for id, want := range wantChanges {
		if byID[id].Change != want {
			t.Errorf("rule %s change = %q, want %q", id, byID[id].Change, want)
		}
	}
	// 比较项按规则标识排序，输入报告中的排列顺序不影响对应关系。
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}

	// 每条比较项保留各自一侧的检查状态和说明。
	wantStatuses := map[string][2]string{
		"rule-defect-timeout": {contractsentinel.StatusDefect, contractsentinel.StatusTimeout},
		"rule-new-defect":     {contractsentinel.StatusPass, contractsentinel.StatusDefect},
		"rule-resolved":       {contractsentinel.StatusDefect, contractsentinel.StatusPass},
		"rule-stable":         {contractsentinel.StatusPass, contractsentinel.StatusPass},
		"rule-timeout-defect": {contractsentinel.StatusTimeout, contractsentinel.StatusDefect},
		"rule-tool-pass":      {contractsentinel.StatusToolMissing, contractsentinel.StatusPass},
	}
	for id, want := range wantStatuses {
		entry := byID[id]
		if entry.Before.Rule.Status != want[0] || entry.After.Rule.Status != want[1] {
			t.Errorf("rule %s statuses = %q/%q, want %q/%q",
				id, entry.Before.Rule.Status, entry.After.Rule.Status, want[0], want[1])
		}
	}
	if n := byID["rule-defect-timeout"].After.Rule.Note; n != "超过 90s 截止时间" {
		t.Errorf("timeout side note = %q", n)
	}
	if n := byID["rule-tool-pass"].Before.Rule.Note; n != "符号执行引擎未安装" {
		t.Errorf("tool-missing side note = %q", n)
	}

	// 发现缺陷的一侧携带当次归档中的产物哈希、规则版本及原始证据；
	// 没有缺陷的一侧不生成缺陷记录。
	wantFindings := map[string]struct {
		side     string // "before" 或 "after"
		version  string
		evidence string
	}{
		"rule-defect-timeout": {"before", "1.1.0", oldDefectNote},
		"rule-new-defect":     {"after", "2.0.0", newDefectNote},
		"rule-resolved":       {"before", "1.0.0", resolvedDefectNote},
		"rule-timeout-defect": {"after", "0.9.0", timeoutDefectNote},
	}
	for id, want := range wantFindings {
		entry := byID[id]
		var defectSide, cleanSide *contractsentinel.DiffSide
		if want.side == "before" {
			defectSide, cleanSide = entry.Before, entry.After
		} else {
			defectSide, cleanSide = entry.After, entry.Before
		}
		if defectSide.Finding == nil {
			t.Errorf("rule %s defect side (%s) must carry evidence", id, want.side)
			continue
		}
		f := defectSide.Finding
		if f.ArtifactHash != hash {
			t.Errorf("rule %s finding artifact hash = %q, want %q", id, f.ArtifactHash, hash)
		}
		if f.RuleID != id || f.Version != want.version {
			t.Errorf("rule %s finding binding = %q@%q, want %q@%q", id, f.RuleID, f.Version, id, want.version)
		}
		if f.Evidence != want.evidence {
			t.Errorf("rule %s evidence = %q, want %q", id, f.Evidence, want.evidence)
		}
		if cleanSide.Finding != nil {
			t.Errorf("rule %s non-defect side must not carry a finding: %+v", id, cleanSide.Finding)
		}
	}
	for _, id := range []string{"rule-stable", "rule-tool-pass"} {
		if byID[id].Before.Finding != nil || byID[id].After.Finding != nil {
			t.Errorf("rule %s has no defect on either side, want no findings: %+v", id, byID[id])
		}
	}

	// 证据中的中文、换行和前后空格在原始输出字节层面保持原文。
	if !strings.Contains(stdout, "  新缺陷：transfer 返回值未检查\\n  第二行攻击路径  ") {
		t.Errorf("diff output must preserve the defect evidence verbatim:\n%s", stdout)
	}
	if !strings.Contains(stdout, "  旧缺陷：withdraw 可重入\\n  修复前反例  ") {
		t.Errorf("diff output must preserve the resolved-defect evidence verbatim:\n%s", stdout)
	}

	// 汇总数量与逐条分类相符；前后缺陷总数只算真实缺陷，
	// 不把超时或工具缺失算进去。
	s := diff.Summary
	if s.NewDefects != 1 || s.ResolvedDefects != 1 || s.StatusChanges != 3 ||
		s.NoteChanges != 0 || s.NoChange != 1 || s.AddedRules != 0 ||
		s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("summary = %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 2 {
		t.Errorf("defect totals = %d/%d, want 2/2 (timeout and tool-missing are not defects)",
			s.BeforeDefects, s.AfterDefects)
	}
}

// 成功与失败都只读取归档：已有报告一个字节都不能变。
func TestCLIDiffKeepsStoreUntouched(t *testing.T) {
	bin := auditBinary(t)
	before, after, store := setupDiffStore(t, bin)
	snap := snapshotStore(t, store)

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	decodeDiff(t, stdout)
	assertStoreUnchanged(t, store, snap)

	// 失败的比较同样不写归档、不补报告。
	missing := strings.Repeat("0", 64)
	failStdout, _, failCode := runCLIDiff(t, bin, store, before.ReportID, missing)
	if failCode == 0 {
		t.Fatal("diff with a missing report must exit non-zero")
	}
	assertNoDiffOutput(t, failStdout)
	assertStoreUnchanged(t, store, snap)
}

// --- 失败路径：非零退出、原因进 stderr、stdout 无任何比较结果 ---

func TestCLIDiffMissingBeforeReport(t *testing.T) {
	bin := auditBinary(t)
	_, after, store := setupDiffStore(t, bin)
	missing := strings.Repeat("0", 64)

	stdout, stderr, code := runCLIDiff(t, bin, store, missing, after.ReportID)
	if code == 0 {
		t.Fatal("diff with a missing baseline report must exit non-zero")
	}
	if !strings.Contains(stderr, missing) || !strings.Contains(stderr, "not found") {
		t.Fatalf("stderr must name the missing report and reason:\n%s", stderr)
	}
	assertNoDiffOutput(t, stdout)
}

// 第二份报告出错时，已读到的第一份报告不能作为成功结果输出。
func TestCLIDiffMissingAfterReportNoPartialSuccess(t *testing.T) {
	bin := auditBinary(t)
	before, _, store := setupDiffStore(t, bin)
	missing := strings.Repeat("f", 64)

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, missing)
	if code == 0 {
		t.Fatal("diff with a missing new report must exit non-zero")
	}
	if !strings.Contains(stderr, missing) || !strings.Contains(stderr, "not found") {
		t.Fatalf("stderr must name the missing report and reason:\n%s", stderr)
	}
	assertNoDiffOutput(t, stdout)
	if strings.Contains(stdout, before.ReportID) {
		t.Fatalf("stdout must not present the readable first report as a success:\n%s", stdout)
	}
}

// 归档内容损坏：非零退出、说明原因，且损坏文件保持原样不被修复。
func TestCLIDiffCorruptedArchive(t *testing.T) {
	bin := auditBinary(t)
	before, after, store := setupDiffStore(t, bin)
	snap := snapshotStore(t, store)

	corruptPath := filepath.Join(store, after.ReportID+".json")
	corruptBytes := []byte(`{broken`)
	if err := os.WriteFile(corruptPath, corruptBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code == 0 {
		t.Fatal("diff with a corrupted archive must exit non-zero")
	}
	if !strings.Contains(stderr, "diff failed") {
		t.Fatalf("stderr must state the failure:\n%s", stderr)
	}
	assertNoDiffOutput(t, stdout)

	// 损坏内容保持原样，其余归档逐字节不变。
	kept, err := os.ReadFile(corruptPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, corruptBytes) {
		t.Fatal("diff must not repair or rewrite the corrupted archive")
	}
	snap[after.ReportID+".json"] = corruptBytes
	assertStoreUnchanged(t, store, snap)
}

// 非法报告标识同样非零退出，且不能当作未检查输出成功结果。
func TestCLIDiffInvalidReportID(t *testing.T) {
	bin := auditBinary(t)
	before, after, store := setupDiffStore(t, bin)

	for _, bad := range []string{"", "not-hex", strings.ToUpper(after.ReportID)} {
		stdout, stderr, code := runCLIDiff(t, bin, store, bad, after.ReportID)
		if code == 0 {
			t.Fatalf("diff with invalid before id %q must exit non-zero", bad)
		}
		if stderr == "" {
			t.Fatalf("stderr must explain the invalid id %q", bad)
		}
		assertNoDiffOutput(t, stdout)

		stdout, stderr, code = runCLIDiff(t, bin, store, before.ReportID, bad)
		if code == 0 {
			t.Fatalf("diff with invalid after id %q must exit non-zero", bad)
		}
		if stderr == "" {
			t.Fatalf("stderr must explain the invalid id %q", bad)
		}
		assertNoDiffOutput(t, stdout)
	}
}
