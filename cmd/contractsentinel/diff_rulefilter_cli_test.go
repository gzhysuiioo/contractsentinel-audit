package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 diff 的按规则筛选用法：调用 diff
// 时额外给出可选 --rule 参数。没有该参数时继续输出完整比较 JSON；给出
// 参数时沿用同一输出结构——顶层仍是实际比较的两份报告标识、产物名称与
// 哈希以及产物变化标记，results 只保留所选规则的一个条目，分类与计数只
// 统计这条规则，beforeDefects/afterDefects 各为零或一，其余分类为零。
//
// 规则标识按完整文字精确匹配，大小写与前后空格保留；规则只存在于一侧时
// 照常返回“新增规则”/“移除规则”，缺席侧为 null，存在侧保留完整规则、
// 状态、原始说明及缺陷记录的哈希、版本与逐字证据。明确给出空字符串，或
// 两份报告都没有该标识时，命令非零退出，stderr 说明参数为空或指出未找
// 到哪个规则，stdout 不输出比较片段。筛选不绕过整份归档校验：任一报告
// 缺失、损坏或绑定不合法仍按既有失败行为结束，即使问题在未选择的规则
// 上。比较全程只读。

// runCLIDiffRule 在真实进程上运行带 --rule 筛选的 diff。
func runCLIDiffRule(t *testing.T, bin, store, before, after, rule string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, "diff", "--store", store, "--before", before, "--after", after, "--rule", rule)
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

// ruleFilterRules 构造三条定义完全一致的规则，覆盖“新缺陷 + 对照”：
// selected 是被筛选规则，另两条在同份报告里带着真实缺陷或保持稳定，
// 用来证明筛选后的 summary 不被未选择规则污染。
func ruleFilterRules() []cliWireRule {
	return []cliWireRule{
		{ID: "a-other-defect", Kind: "static", Severity: "critical", Invariant: "inv-other", Version: "1"},
		{ID: "b-selected", Kind: "static", Severity: "high", Invariant: "inv-selected", Version: "2"},
		{ID: "c-stable-pass", Kind: "static", Severity: "low", Invariant: "inv-stable", Version: "3"},
	}
}

const ruleFilterEvidence = "  筛选反例：所选规则状态迁移\n  第二行证据  "
const ruleFilterOtherEvidence = "  未选择规则的缺陷证据\n第二行  "

func ruleFilterBeforeChecks(hash string) []cliWireCheck {
	return []cliWireCheck{
		{ArtifactHash: hash, RuleID: "b-selected", Version: "2", Status: contractsentinel.StatusPass},
		{ArtifactHash: hash, RuleID: "a-other-defect", Version: "1", Status: contractsentinel.StatusDefect, Note: ruleFilterOtherEvidence},
		{ArtifactHash: hash, RuleID: "c-stable-pass", Version: "3", Status: contractsentinel.StatusPass},
	}
}

func ruleFilterAfterChecks(hash string) []cliWireCheck {
	return []cliWireCheck{
		{ArtifactHash: hash, RuleID: "b-selected", Version: "2", Status: contractsentinel.StatusDefect, Note: ruleFilterEvidence},
		{ArtifactHash: hash, RuleID: "a-other-defect", Version: "1", Status: contractsentinel.StatusDefect, Note: ruleFilterOtherEvidence},
		{ArtifactHash: hash, RuleID: "c-stable-pass", Version: "3", Status: contractsentinel.StatusPass},
	}
}

// TestCLIDiffRuleFilterKeepsOnlySelectedEntry 成功路径：筛选后只有所选规则
// 一个条目；报告里另一条规则两侧都带着真实缺陷，summary 仍只计一条
// “新发现缺陷”，两侧缺陷数为零和一；顶层报告标识、产物与变化标记保留。
func TestCLIDiffRuleFilterKeepsOnlySelectedEntry(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, ruleFilterRules(), ruleFilterBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, ruleFilterRules(), ruleFilterAfterChecks(hash))

	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "b-selected")
	if code != 0 {
		t.Fatalf("filtered diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	// 顶层标识与产物信息保留，与完整比较一致。
	if d.Before.ReportID != before.ReportID || d.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", d.Before.ReportID, d.After.ReportID, before.ReportID, after.ReportID)
	}
	if d.Before.Artifact.Hash != hash || d.After.Artifact.Hash != hash ||
		d.Before.Artifact.Name != "Vault" || d.After.Artifact.Name != "Vault" {
		t.Errorf("artifact refs = %+v / %+v", d.Before.Artifact, d.After.Artifact)
	}
	if d.ArtifactNameChanged || d.ArtifactHashChanged {
		t.Errorf("same artifact must not be flagged changed: %v/%v", d.ArtifactNameChanged, d.ArtifactHashChanged)
	}

	// 只有所选规则一个条目，分类沿用既有口径。
	if len(d.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(d.Results), d.Results)
	}
	entry := d.Results[0]
	if entry.RuleID != "b-selected" || entry.Change != contractsentinel.ChangeNewDefect {
		t.Fatalf("entry = %q/%q, want b-selected/%q", entry.RuleID, entry.Change, contractsentinel.ChangeNewDefect)
	}
	if entry.Before == nil || entry.After == nil {
		t.Fatal("a rule present in both reports must keep both sides")
	}
	if entry.Before.Rule.Status != contractsentinel.StatusPass || entry.Before.Finding != nil {
		t.Errorf("passing before side = %+v", entry.Before)
	}
	if entry.After.Rule.Status != contractsentinel.StatusDefect || entry.After.Finding == nil {
		t.Fatalf("defect after side must keep its finding: %+v", entry.After)
	}
	f := entry.After.Finding
	if f.ArtifactHash != hash || f.RuleID != "b-selected" || f.Version != "2" {
		t.Errorf("finding binding = %+v, want hash=%q rule=b-selected version=2", f, hash)
	}
	if f.Evidence != ruleFilterEvidence {
		t.Errorf("evidence = %q, want verbatim %q", f.Evidence, ruleFilterEvidence)
	}

	// summary 与单一条目对应：新缺陷一条，其余分类全零；缺陷数 0/1，
	// 不被 a-other-defect 在两侧各自的真实缺陷污染。
	s := d.Summary
	if s.NewDefects != 1 {
		t.Errorf("newDefects = %d, want 1", s.NewDefects)
	}
	if s.ResolvedDefects != 0 || s.StatusChanges != 0 || s.NoteChanges != 0 || s.NoChange != 0 ||
		s.AddedRules != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other category must be zero: %+v", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("scoped defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}

	// 原始字节层面：所选证据逐字保留，未选择规则的证据与标识不出现。
	if !strings.Contains(stdout, "  筛选反例：所选规则状态迁移\\n  第二行证据  ") {
		t.Errorf("filtered output must preserve the selected evidence verbatim:\n%s", stdout)
	}
	if strings.Contains(stdout, ruleFilterOtherEvidence) || strings.Contains(stdout, "a-other-defect") ||
		strings.Contains(stdout, "c-stable-pass") {
		t.Errorf("filtered output must not carry unselected rules:\n%s", stdout)
	}
}

// TestCLIDiffWithoutRuleFlagIsUnchanged 不带 --rule 时仍是完整比较：结果
// 次序、分类与统计保持既有行为，不因为新增了可选参数而改变。
func TestCLIDiffWithoutRuleFlagIsUnchanged(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, ruleFilterRules(), ruleFilterBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, ruleFilterRules(), ruleFilterAfterChecks(hash))

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("full diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 3 {
		t.Fatalf("full results = %d, want 3: %+v", len(d.Results), d.Results)
	}
	changeByID := map[string]string{}
	for _, r := range d.Results {
		changeByID[r.RuleID] = r.Change
	}
	if changeByID["b-selected"] != contractsentinel.ChangeNewDefect ||
		changeByID["a-other-defect"] != contractsentinel.ChangeNoChange ||
		changeByID["c-stable-pass"] != contractsentinel.ChangeNoChange {
		t.Errorf("full-diff classifications = %+v", changeByID)
	}
	s := d.Summary
	if s.NewDefects != 1 || s.NoChange != 2 {
		t.Errorf("full summary = %+v, want newDefects=1 noChange=2", s)
	}
	// 完整比较的缺陷总数仍是两份报告各自的真实总数：1/2。
	if s.BeforeDefects != 1 || s.AfterDefects != 2 {
		t.Errorf("full defect totals = %d/%d, want 1/2", s.BeforeDefects, s.AfterDefects)
	}
}

// TestCLIDiffRuleExactTextMatching 标识按完整文字精确匹配：带前后空格的
// 标识必须用同样的完整文字选中，修剪或大小写不同都算未找到；原始证据中
// 的中文、空格与换行不被改写。
func TestCLIDiffRuleExactTextMatching(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	padded := cliWireRule{ID: " selected-rule ", Kind: "static", Severity: "high", Invariant: "inv-pad", Version: "1"}
	cased := cliWireRule{ID: "Selected-Rule", Kind: "static", Severity: "high", Invariant: "inv-case", Version: "1"}
	rules := []cliWireRule{padded, cased}
	mk := func(name string) contractsentinel.Report {
		return auditDiffReport(t, bin, work, store, name, artifact, rules, []cliWireCheck{
			{ArtifactHash: hash, RuleID: padded.ID, Version: "1", Status: contractsentinel.StatusDefect, Note: ruleFilterEvidence},
			{ArtifactHash: hash, RuleID: cased.ID, Version: "1", Status: contractsentinel.StatusPass},
		})
	}
	before := mk("before.json")
	after := mk("after.json")

	// 完整文字（含前后空格）精确选中；缺席与否都不存在，分类为无变化。
	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, " selected-rule ")
	if code != 0 {
		t.Fatalf("exact padded id must match, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 || d.Results[0].RuleID != " selected-rule " {
		t.Fatalf("filtered entry = %+v", d.Results)
	}
	if d.Results[0].Change != contractsentinel.ChangeNoChange || d.Summary.NoChange != 1 ||
		d.Summary.BeforeDefects != 1 || d.Summary.AfterDefects != 1 {
		t.Errorf("padded entry/summary = %+v / %+v", d.Results[0], d.Summary)
	}
	if !strings.Contains(stdout, "  筛选反例：所选规则状态迁移\\n  第二行证据  ") {
		t.Errorf("evidence verbatim must survive:\n%s", stdout)
	}

	// 修剪与大小写折叠都不得命中，命令非零退出、stderr 指出未找到的标识、
	// stdout 不出现比较片段。
	for _, bad := range []string{"selected-rule", " selected-rule", "Selected-Rule ", "SELECTED-RULE"} {
		stdout, stderr, code = runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, bad)
		if code == 0 {
			t.Errorf("filter %q must not match", bad)
			continue
		}
		if !strings.Contains(stderr, "not found") || !strings.Contains(stderr, bad) {
			t.Errorf("stderr must name the rule %q that was not found:\n%s", bad, stderr)
		}
		if stdout != "" {
			t.Errorf("stdout must be empty when the rule is not found, got:\n%s", stdout)
		}
	}
}

// TestCLIDiffRuleAddedRemovedAndNull 规则只存在于一侧：新增/移除分类沿用
// 既有口径，缺席侧渲染为 null，存在侧保留完整规则、状态、原始说明与缺陷
// 记录；交换比较方向后分类与缺陷数方向反转。
func TestCLIDiffRuleAddedRemovedAndNull(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rule := cliWireRule{ID: "b-selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "2"}

	// 基准侧完全没有这条规则；新侧首次出现即发现缺陷。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, nil, nil)
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, []cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
			Status: contractsentinel.StatusDefect, Note: ruleFilterEvidence}})

	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "b-selected")
	if code != 0 {
		t.Fatalf("added-rule filter must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 || d.Results[0].Change != contractsentinel.ChangeRuleAdded {
		t.Fatalf("entry = %+v, want 新增规则", d.Results)
	}
	if d.Results[0].Before != nil {
		t.Errorf("absent before side must be null: %+v", d.Results[0].Before)
	}
	if d.Results[0].After == nil || d.Results[0].After.Finding == nil ||
		d.Results[0].After.Finding.Evidence != ruleFilterEvidence {
		t.Errorf("added side must keep the full rule and verbatim finding: %+v", d.Results[0].After)
	}
	if d.Summary.AddedRules != 1 || d.Summary.NewDefects != 0 ||
		d.Summary.BeforeDefects != 0 || d.Summary.AfterDefects != 1 {
		t.Errorf("summary = %+v, want added=1 defects 0/1", d.Summary)
	}
	if !strings.Contains(stdout, `"before": null`) {
		t.Errorf("absent side must render as null:\n%s", stdout)
	}

	// 反方向：移除规则，after 为 null，缺陷数方向反转。
	stdout, stderr, code = runCLIDiffRule(t, bin, store, after.ReportID, before.ReportID, "b-selected")
	if code != 0 {
		t.Fatalf("removed-rule filter must succeed, exit=%d stderr=%s", code, stderr)
	}
	d = decodeDiff(t, stdout)
	if d.Results[0].Change != contractsentinel.ChangeRuleRemoved || d.Results[0].After != nil {
		t.Fatalf("entry = %+v, want 移除规则 with null after", d.Results[0])
	}
	if d.Results[0].Before == nil || d.Results[0].Before.Finding == nil {
		t.Errorf("removed side must keep its finding: %+v", d.Results[0].Before)
	}
	if d.Summary.RemovedRules != 1 || d.Summary.BeforeDefects != 1 || d.Summary.AfterDefects != 0 {
		t.Errorf("summary = %+v, want removed=1 defects 1/0", d.Summary)
	}
}

// TestCLIDiffRuleDefinitionChangeStillRuleChanged 所选规则版本变化且状态
// 通过 -> 发现缺陷：仍是“规则变化”，不是新缺陷；两侧缺陷数按真实记录为
// 0/1。
func TestCLIDiffRuleDefinitionChangeStillRuleChanged(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{{ID: "b-selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: "b-selected", Version: "1", Status: contractsentinel.StatusPass}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{{ID: "b-selected", Kind: "static", Severity: "critical", Invariant: "inv", Version: "1"}},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: "b-selected", Version: "1", Status: contractsentinel.StatusDefect, Note: ruleFilterEvidence}})

	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "b-selected")
	if code != 0 {
		t.Fatalf("rule-change filter must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 || d.Results[0].Change != contractsentinel.ChangeRuleChanged {
		t.Fatalf("entry = %+v, want 规则变化", d.Results)
	}
	s := d.Summary
	if s.ChangedRules != 1 || s.NewDefects != 0 {
		t.Errorf("summary = %+v, want changed=1 newDefects=0", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}

// TestCLIDiffRuleStatusTransitionsStayStatusChanges 工具缺失、超时、未检查
// 相关的迁移在筛选下仍归“检查状态变化”，不推断新增/消除缺陷；超时 ->
// 发现缺陷时新侧缺陷数为一，超时侧无缺陷记录。
func TestCLIDiffRuleStatusTransitionsStayStatusChanges(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rule := []cliWireRule{{ID: "b-selected", Kind: "symbolic", Severity: "critical", Invariant: "inv", Version: "7"}}
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rule,
		[]cliWireCheck{{ArtifactHash: hash, RuleID: "b-selected", Version: "7",
			Status: contractsentinel.StatusTimeout, Note: "超过 60s 截止时间"}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rule,
		[]cliWireCheck{{ArtifactHash: hash, RuleID: "b-selected", Version: "7",
			Status: contractsentinel.StatusDefect, Note: ruleFilterEvidence}})

	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "b-selected")
	if code != 0 {
		t.Fatalf("status-change filter must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if d.Results[0].Change != contractsentinel.ChangeStatusChanged {
		t.Fatalf("change = %q, want %q", d.Results[0].Change, contractsentinel.ChangeStatusChanged)
	}
	s := d.Summary
	if s.StatusChanges != 1 || s.NewDefects != 0 || s.ResolvedDefects != 0 {
		t.Errorf("summary = %+v, want only statusChanges=1", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
	if d.Results[0].Before.Finding != nil || d.Results[0].After.Finding == nil {
		t.Errorf("only the defect side carries a finding: %+v / %+v", d.Results[0].Before, d.Results[0].After)
	}
}

// TestCLIDiffRuleEmptyAndNotFoundFailCleanly 明确空字符串或两侧都没有该标
// 识：非零退出、stderr 说明参数为空或指出未找到哪个规则、stdout 无任何比
// 较片段。
func TestCLIDiffRuleEmptyAndNotFoundFailCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, ruleFilterRules(), ruleFilterBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, ruleFilterRules(), ruleFilterAfterChecks(hash))

	// 明确的空字符串：stderr 必须说明筛选参数为空。
	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "")
	if code == 0 {
		t.Fatal("empty --rule must exit non-zero")
	}
	if !strings.Contains(stderr, "empty") {
		t.Fatalf("stderr must say the rule filter is empty:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty for an empty filter, got:\n%s", stdout)
	}

	// 两份报告都没有的标识：stderr 指出未找到哪个规则。
	stdout, stderr, code = runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "no-such-rule")
	if code == 0 {
		t.Fatal("an unknown rule must exit non-zero")
	}
	if !strings.Contains(stderr, "no-such-rule") || !strings.Contains(stderr, "not found") {
		t.Fatalf("stderr must name the missing rule:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty when the rule is missing, got:\n%s", stdout)
	}
	for _, marker := range []string{`"results"`, `"summary"`, before.ReportID, contractsentinel.ChangeNewDefect} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak %q:\n%s", marker, stdout)
		}
	}
}

// TestCLIDiffRuleDoesNotBypassArchiveVerification 归档损坏即使发生在未选择
// 的规则上，带筛选的比较仍按既有失败行为结束：非零退出、原因进 stderr、
// stdout 无比较片段；报告缺失同理。
func TestCLIDiffRuleDoesNotBypassArchiveVerification(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	good := auditDiffReport(t, bin, work, store, "good.json", artifact,
		[]cliWireRule{{ID: "b-selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: "b-selected", Version: "1", Status: contractsentinel.StatusPass}})

	// 第二份归档整体损坏（JSON 无法解析）：即使筛选的是完好的 selected，
	// 整份校验仍先失败。这里刻意多带一条规则，使它的报告标识与 good 不同，
	// 避免内容相同的两份提交共享同一归档文件。
	broken := auditDiffReport(t, bin, work, store, "broken.json", artifact,
		[]cliWireRule{
			{ID: "b-selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"},
			{ID: "z-extra", Kind: "static", Severity: "low", Invariant: "inv-extra", Version: "1"},
		},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: "b-selected", Version: "1", Status: contractsentinel.StatusPass},
			{ArtifactHash: hash, RuleID: "z-extra", Version: "1", Status: contractsentinel.StatusPass},
		})
	if err := os.WriteFile(filepath.Join(store, broken.ReportID+".json"), []byte(`{broken`), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLIDiffRule(t, bin, store, good.ReportID, broken.ReportID, "b-selected")
	if code == 0 {
		t.Fatal("a corrupted second archive must fail even when the selected rule is intact elsewhere")
	}
	if !strings.Contains(stderr, "invalid JSON") {
		t.Fatalf("stderr must describe the corrupted archive:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty on corruption, got:\n%s", stdout)
	}

	// 第二份报告里 selected 完好，另一条未选择规则携带非法状态：整份归档
	// 绑定不合法，即使筛选的是 selected 也必须失败。
	badRulesReport := contractsentinel.Report{
		Artifact: contractsentinel.ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []contractsentinel.ReportRule{
			{ID: "b-selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: contractsentinel.StatusPass},
			{ID: "other", Kind: "static", Severity: "low", Invariant: "inv2", Version: "1", Status: "跳过"},
		},
		Findings: []contractsentinel.ReportFinding{},
	}
	badRulesReport.ReportID = contractsentinel.ReportID(badRulesReport)
	raw, err := json.Marshal(badRulesReport)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, badRulesReport.ReportID+".json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLIDiffRule(t, bin, store, good.ReportID, badRulesReport.ReportID, "b-selected")
	if code == 0 {
		t.Fatal("illegality on an unselected rule must still fail")
	}
	if !strings.Contains(stderr, "unknown status") {
		t.Fatalf("stderr must name the unknown status corruption:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty, got:\n%s", stdout)
	}

	// 报告缺失同样先于筛选失败。
	missing := strings.Repeat("0", 64)
	stdout, stderr, code = runCLIDiffRule(t, bin, store, missing, good.ReportID, "b-selected")
	if code == 0 {
		t.Fatal("a missing report must fail under a filter too")
	}
	if !strings.Contains(stderr, "not found") || stdout != "" {
		t.Fatalf("missing-report failure must stay clean: stdout=%q stderr=%s", stdout, stderr)
	}
}

// TestCLIDiffRuleIsReadOnly 带筛选的比较不改写任何归档，也不留临时文件。
func TestCLIDiffRuleIsReadOnly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, ruleFilterRules(), ruleFilterBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, ruleFilterRules(), ruleFilterAfterChecks(hash))

	names, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(store, name))
		if err != nil {
			t.Fatal(err)
		}
		contents[name] = string(data)
	}

	if _, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "b-selected"); code != 0 {
		t.Fatalf("filtered diff must succeed: %s", stderr)
	}
	gotNames, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotNames) != len(contents) {
		t.Fatalf("file set changed: %v vs %v", gotNames, names)
	}
	for _, name := range gotNames {
		data, err := os.ReadFile(filepath.Join(store, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != contents[name] {
			t.Errorf("filtered diff modified archive %s", name)
		}
	}
}
