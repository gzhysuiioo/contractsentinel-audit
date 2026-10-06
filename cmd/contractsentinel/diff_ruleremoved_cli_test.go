package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护“移除规则”口径：新报告缩小检查范围、
// 完全不再包含基准报告中某条带缺陷的规则时，diff 必须为该规则标识保留一个
// “移除规则”条目，旧侧仍是归档中的完整规则定义、检查状态和原始缺陷记录，新
// 侧为 null；这不同于同标准下复跑确认修复的“已消除缺陷”。两种变化放在同一
// 份比较结果中，必须各自进入对应分类与计数，不能仅凭缺陷总数下降就把移除算
// 成修复。两份报告都通过真实 audit 命令正常归档，再由 diff 命令读回比较，
// 既有报告格式、报告标识与基准/新比较方向保持兼容。

// 被移除规则的旧证据刻意包含中文、换行与前后空格，任何修剪或模板替换都会被
// 抓到；它与留下规则的证据不同，防止证据按不变式名串到另一条规则上。
const removedRuleEvidence = "  旧反例：检查范围已收缩\n  reentrancy 路径第二行  "
const keptRuleEvidence = "  保留规则：旧反例\n第二行  "

// removedCLI Rules 刻意引用同一个不变式名：归属只能按规则标识，不能按不变式。
func removedCLIRules() []cliWireRule {
	return []cliWireRule{
		{ID: "removed-reentrancy", Kind: "static", Severity: "high", Invariant: "shared-reentrancy-invariant", Version: "7.3.0"},
		{ID: "kept-reentrancy", Kind: "static", Severity: "medium", Invariant: "shared-reentrancy-invariant", Version: "2.0.4"},
	}
}

// TestCLIDiffRemovedDefectRuleIsNotResolved 在进程边界覆盖核心口径：带缺陷
// 旧规则在新报告完全缺席 -> “移除规则”（新侧 null、旧证据逐字保留）；同份
// 输出中定义一致的对照规则缺陷 -> 通过 -> “已消除缺陷”（通过侧无缺陷记录）。
func TestCLIDiffRemovedDefectRuleIsNotResolved(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := removedCLIRules()
	removedRule, keptRule := rules[0], rules[1]

	// 基准侧两条规则都为发现缺陷，各自带自己的证据；提交顺序刻意与标识排序
	// 不同，归属不得受归档排列影响。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{keptRule, removedRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: keptRule.ID, Version: keptRule.Version, Status: contractsentinel.StatusDefect, Note: keptRuleEvidence},
			{ArtifactHash: hash, RuleID: removedRule.ID, Version: removedRule.Version, Status: contractsentinel.StatusDefect, Note: removedRuleEvidence},
		})
	// 新报告只保留对照规则（定义完全一致）并复跑通过；被移除规则完全缺席。
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{keptRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: keptRule.ID, Version: keptRule.Version, Status: contractsentinel.StatusPass},
		})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	// 报告标识与比较方向按命令行参数保留，两侧为同一产物。
	if d.Before.ReportID != before.ReportID || d.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", d.Before.ReportID, d.After.ReportID, before.ReportID, after.ReportID)
	}
	if d.ArtifactNameChanged || d.ArtifactHashChanged {
		t.Error("same artifact must not be flagged changed")
	}

	// 每个标识恰好一个结果，共两条，按标识排序。
	if len(d.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(d.Results))
	}
	ids := make([]string, 0, len(d.Results))
	for _, r := range d.Results {
		ids = append(ids, r.RuleID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}

	// --- 被移除的缺陷规则 ---
	removed := diffEntry(t, d, removedRule.ID)
	if removed.Change != contractsentinel.ChangeRuleRemoved {
		t.Fatalf("removed change = %q, want %q", removed.Change, contractsentinel.ChangeRuleRemoved)
	}
	if removed.After != nil {
		t.Fatalf("absent new side must be null, got %+v", removed.After)
	}
	if removed.Before == nil {
		t.Fatal("removed rule must keep its old side")
	}
	if rb := removed.Before.Rule; rb.ID != removedRule.ID || rb.Kind != "static" ||
		rb.Severity != "high" || rb.Invariant != "shared-reentrancy-invariant" ||
		rb.RequiresABI != false || rb.Version != "7.3.0" {
		t.Errorf("removed old-side rule definition = %+v, want the archived definition", rb)
	}
	if removed.Before.Rule.Status != contractsentinel.StatusDefect {
		t.Errorf("removed old-side status = %q, want %q", removed.Before.Rule.Status, contractsentinel.StatusDefect)
	}
	if removed.Before.Rule.Note != removedRuleEvidence {
		t.Errorf("removed old-side note = %q, want %q verbatim", removed.Before.Rule.Note, removedRuleEvidence)
	}
	rf := removed.Before.Finding
	if rf == nil {
		t.Fatal("removed old side must keep the original defect finding")
	}
	if rf.ArtifactHash != hash || rf.RuleID != removedRule.ID || rf.Version != removedRule.Version ||
		rf.Severity != "high" || rf.Invariant != "shared-reentrancy-invariant" {
		t.Errorf("removed finding binding = %+v, want hash=%q rule=%q version=%q", rf, hash, removedRule.ID, removedRule.Version)
	}
	if rf.Evidence != removedRuleEvidence {
		t.Errorf("removed evidence = %q, want %q verbatim", rf.Evidence, removedRuleEvidence)
	}

	// --- 仍在检查的对照规则：定义一致、发现缺陷 -> 通过 ---
	kept := diffEntry(t, d, keptRule.ID)
	if kept.Change != contractsentinel.ChangeResolvedDefect {
		t.Fatalf("kept change = %q, want %q", kept.Change, contractsentinel.ChangeResolvedDefect)
	}
	if kept.Before == nil || kept.After == nil {
		t.Fatal("resolved rule must carry both sides")
	}
	if kb := kept.Before.Rule; kb.ID != keptRule.ID || kb.Severity != "medium" ||
		kb.Version != "2.0.4" || kb.Status != contractsentinel.StatusDefect ||
		kb.Note != keptRuleEvidence {
		t.Errorf("kept before = %+v", kb)
	}
	if ka := kept.After.Rule; ka.Status != contractsentinel.StatusPass || ka.Note != "" ||
		ka.ID != keptRule.ID || ka.Version != "2.0.4" {
		t.Errorf("kept after = %+v", ka)
	}
	if kept.Before.Finding == nil || kept.Before.Finding.Evidence != keptRuleEvidence ||
		kept.Before.Finding.RuleID != keptRule.ID || kept.Before.Finding.Version != keptRule.Version ||
		kept.Before.Finding.ArtifactHash != hash {
		t.Errorf("kept rule must keep its own finding: %+v", kept.Before.Finding)
	}
	if kept.After.Finding != nil {
		t.Errorf("passing side must carry no finding: %+v", kept.After.Finding)
	}
	// 留下的规则不能接收被移除规则的旧证据（两者引用同一不变式名）。
	if kept.Before.Finding.Evidence == removedRuleEvidence {
		t.Error("kept rule inherited the removed rule's evidence; findings must stay bound by rule id")
	}

	// --- 汇总：两类变化各计其一，缺陷总数只数各自归档的实际发现 ---
	s := d.Summary
	if s.RemovedRules != 1 {
		t.Errorf("removedRules = %d, want 1", s.RemovedRules)
	}
	if s.ResolvedDefects != 1 {
		t.Errorf("resolvedDefects = %d, want 1", s.ResolvedDefects)
	}
	if s.NewDefects != 0 || s.StatusChanges != 0 || s.NoteChanges != 0 ||
		s.NoChange != 0 || s.AddedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other count must be zero: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0 (actual archived findings)", s.BeforeDefects, s.AfterDefects)
	}

	// 原始输出字节层面：缺席新侧渲染为 null，旧证据中的中文、换行（JSON 转义
	// 为 \n）和前后空白逐字保留。
	if !strings.Contains(stdout, `"after": null`) {
		t.Errorf("removed entry must render the absent side as null:\n%s", stdout)
	}
	if !strings.Contains(stdout, "  旧反例：检查范围已收缩\\n  reentrancy 路径第二行  ") {
		t.Errorf("diff output must preserve the removed rule evidence verbatim:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"change": "`+contractsentinel.ChangeRuleRemoved+`"`) {
		t.Errorf("diff output must carry the %q category:\n%s", contractsentinel.ChangeRuleRemoved, stdout)
	}
}

// TestCLIDiffDefectRuleRemovedAgainstRuleLessReport 新报告没有任何规则也是
// 合法输入：diff 正常退出，旧缺陷规则按移除处理，新侧缺陷总数为零，不报错、
// 不推断为修复。
func TestCLIDiffDefectRuleRemovedAgainstRuleLessReport(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	removedRule := removedCLIRules()[0]

	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{removedRule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: removedRule.ID, Version: removedRule.Version,
			Status: contractsentinel.StatusDefect, Note: removedRuleEvidence}})
	// 新报告零规则零检查：合法的空范围报告。
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, nil, nil)

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff against a rule-less report must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(d.Results), d.Results)
	}
	entry := d.Results[0]
	if entry.RuleID != removedRule.ID || entry.Change != contractsentinel.ChangeRuleRemoved {
		t.Fatalf("entry = %q/%q, want %q/%q", entry.RuleID, entry.Change, removedRule.ID, contractsentinel.ChangeRuleRemoved)
	}
	if entry.After != nil {
		t.Errorf("absent new side must be null: %+v", entry.After)
	}
	if entry.Before == nil || entry.Before.Finding == nil ||
		entry.Before.Finding.Evidence != removedRuleEvidence ||
		entry.Before.Finding.ArtifactHash != hash || entry.Before.Finding.Version != removedRule.Version {
		t.Errorf("old side must keep the archived defect: %+v", entry.Before)
	}
	s := d.Summary
	if s.RemovedRules != 1 || s.ResolvedDefects != 0 {
		t.Errorf("summary = %+v, want removed=1 resolved=0", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}
	if !strings.Contains(stdout, `"after": null`) {
		t.Errorf("removed entry must render the absent side as null:\n%s", stdout)
	}
}
