package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护“新增规则”口径：新报告扩大检查范围、
// 首次包含某条带缺陷结论的规则时，diff 必须为该规则标识保留一个“新增规则”
// 条目，新侧仍是归档中的完整规则定义、检查状态、原始说明和缺陷记录，基准侧为
// null；这不同于两侧都存在、定义完全一致的规则由通过变为发现缺陷的“新发现缺
// 陷”。两种变化放在同一份比较结果中，必须各自进入对应分类与计数，不能仅凭新
// 侧缺陷总数上升就把扩大检查范围统计成已有规则的新缺陷；新侧缺陷总数仍包含
// 新增规则的真实缺陷。两份报告都通过真实 audit 命令正常归档，再由 diff 命令
// 读回比较，既有报告格式、报告标识、结果排序与基准/新比较方向保持兼容，比较
// 过程不改写归档。

// 新增规则与对照规则的证据刻意包含中文、换行与前后空格，且互不相同：任何修剪、
// 模板替换或按不变式名串证据都会被抓到。
const addedRuleEvidence = "  新反例：新增规则首次覆盖该路径\n  reentrancy 路径第二行  "
const keptNewDefectEvidence = "  既有规则的新反例：复跑发现缺陷\n第二行  "

// addedCLIRules 刻意让两条规则引用同一个不变式名：归属只能按规则标识，不能按
// 不变式名合并或互换证据。
func addedCLIRules() []cliWireRule {
	return []cliWireRule{
		{ID: "added-reentrancy", Kind: "static", Severity: "high", Invariant: "shared-reentrancy-invariant", Version: "7.3.0"},
		{ID: "kept-reentrancy", Kind: "static", Severity: "medium", Invariant: "shared-reentrancy-invariant", Version: "2.0.4"},
	}
}

// TestCLIDiffAddedDefectRuleIsNotNewDefect 在进程边界覆盖核心口径：带缺陷
// 新规则在基准报告完全缺席 -> “新增规则”（基准侧 null、新侧证据逐字保留）；
// 同份输出中定义一致的对照规则通过 -> 发现缺陷 -> “新发现缺陷”。新增规则与
// 新发现缺陷各计其一，缺陷总数为 0 和 2。
func TestCLIDiffAddedDefectRuleIsNotNewDefect(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := addedCLIRules()
	addedRule, keptRule := rules[0], rules[1]

	// 基准报告只包含对照规则（定义与新侧完全一致），结论为通过。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{keptRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: keptRule.ID, Version: keptRule.Version, Status: contractsentinel.StatusPass},
		})
	// 新报告扩大检查范围：新增规则首次出现即发现缺陷，对照规则由通过变为发现
	// 缺陷；提交顺序刻意与标识排序不同，归属不得受归档排列影响。
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{keptRule, addedRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: addedRule.ID, Version: addedRule.Version, Status: contractsentinel.StatusDefect, Note: addedRuleEvidence},
			{ArtifactHash: hash, RuleID: keptRule.ID, Version: keptRule.Version, Status: contractsentinel.StatusDefect, Note: keptNewDefectEvidence},
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

	// --- 仅在新侧出现的缺陷规则：新增规则，基准侧为 null ---
	added := diffEntry(t, d, addedRule.ID)
	if added.Change != contractsentinel.ChangeRuleAdded {
		t.Fatalf("added change = %q, want %q", added.Change, contractsentinel.ChangeRuleAdded)
	}
	if added.Before != nil {
		t.Fatalf("absent baseline side must be null, got %+v", added.Before)
	}
	if added.After == nil {
		t.Fatal("added rule must keep its new side")
	}
	if ar := added.After.Rule; ar.ID != addedRule.ID || ar.Kind != "static" ||
		ar.Severity != "high" || ar.Invariant != "shared-reentrancy-invariant" ||
		ar.RequiresABI != false || ar.Version != "7.3.0" {
		t.Errorf("added new-side rule definition = %+v, want the archived definition", ar)
	}
	if added.After.Rule.Status != contractsentinel.StatusDefect {
		t.Errorf("added new-side status = %q, want %q", added.After.Rule.Status, contractsentinel.StatusDefect)
	}
	if added.After.Rule.Note != addedRuleEvidence {
		t.Errorf("added new-side note = %q, want %q verbatim", added.After.Rule.Note, addedRuleEvidence)
	}
	af := added.After.Finding
	if af == nil {
		t.Fatal("added new side must keep its defect finding")
	}
	if af.ArtifactHash != hash || af.RuleID != addedRule.ID || af.Version != addedRule.Version ||
		af.Severity != "high" || af.Invariant != "shared-reentrancy-invariant" {
		t.Errorf("added finding binding = %+v, want hash=%q rule=%q version=%q", af, hash, addedRule.ID, addedRule.Version)
	}
	if af.Evidence != addedRuleEvidence {
		t.Errorf("added evidence = %q, want %q verbatim", af.Evidence, addedRuleEvidence)
	}

	// --- 两侧都在、定义一致的对照规则：通过 -> 发现缺陷 = 新发现缺陷 ---
	kept := diffEntry(t, d, keptRule.ID)
	if kept.Change != contractsentinel.ChangeNewDefect {
		t.Fatalf("kept change = %q, want %q", kept.Change, contractsentinel.ChangeNewDefect)
	}
	if kept.Before == nil || kept.After == nil {
		t.Fatal("new-defect rule must carry both sides")
	}
	if kb := kept.Before.Rule; kb.ID != keptRule.ID || kb.Severity != "medium" ||
		kb.Version != "2.0.4" || kb.Status != contractsentinel.StatusPass || kb.Note != "" {
		t.Errorf("kept before = %+v", kb)
	}
	if ka := kept.After.Rule; ka.Status != contractsentinel.StatusDefect ||
		ka.Note != keptNewDefectEvidence || ka.ID != keptRule.ID || ka.Version != "2.0.4" {
		t.Errorf("kept after = %+v", ka)
	}
	if kept.Before.Finding != nil {
		t.Errorf("passing baseline side must carry no finding: %+v", kept.Before.Finding)
	}
	if kept.After.Finding == nil || kept.After.Finding.Evidence != keptNewDefectEvidence ||
		kept.After.Finding.RuleID != keptRule.ID || kept.After.Finding.Version != keptRule.Version ||
		kept.After.Finding.ArtifactHash != hash {
		t.Errorf("kept rule must keep its own finding: %+v", kept.After.Finding)
	}
	// 两条规则引用同一不变式名，也各自保留自己的版本、严重级别与反例。
	if kept.After.Finding != nil && kept.After.Finding.Evidence == addedRuleEvidence {
		t.Error("kept rule inherited the added rule's evidence; findings must stay bound by rule id")
	}

	// --- 汇总：两类变化各计其一；新增规则的缺陷不计入新发现缺陷，但仍计入
	// 新侧缺陷总数（0 -> 2） ---
	s := d.Summary
	if s.AddedRules != 1 {
		t.Errorf("addedRules = %d, want 1", s.AddedRules)
	}
	if s.NewDefects != 1 {
		t.Errorf("newDefects = %d, want 1", s.NewDefects)
	}
	if s.ResolvedDefects != 0 || s.StatusChanges != 0 || s.NoteChanges != 0 ||
		s.NoChange != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other count must be zero: %+v", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 2 {
		t.Errorf("defect totals = %d/%d, want 0/2 (actual archived findings)", s.BeforeDefects, s.AfterDefects)
	}

	// 原始输出字节层面：缺席基准侧渲染为 null，新证据中的中文、换行（JSON 转
	// 义为 \n）和前后空白逐字保留。
	if !strings.Contains(stdout, `"before": null`) {
		t.Errorf("added entry must render the absent side as null:\n%s", stdout)
	}
	if !strings.Contains(stdout, "  新反例：新增规则首次覆盖该路径\\n  reentrancy 路径第二行  ") {
		t.Errorf("diff output must preserve the added rule evidence verbatim:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"change": "`+contractsentinel.ChangeRuleAdded+`"`) {
		t.Errorf("diff output must carry the %q category:\n%s", contractsentinel.ChangeRuleAdded, stdout)
	}
}

// TestCLIDiffUncheckedBaselineRuleLaterDefectIsStatusChange 在进程边界明确
// “新增”的判定依据：基准报告已有该规则、只是状态为“未检查”，新报告对同一定
// 义的规则得出发现缺陷时归为“检查状态变化”，不计入新增规则或新发现缺陷。
func TestCLIDiffUncheckedBaselineRuleLaterDefectIsStatusChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rule := addedCLIRules()[0]

	// 基准报告已有这条规则，但没有它的检查记录：状态为“未检查”。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{rule}, nil)
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version, Status: contractsentinel.StatusDefect, Note: addedRuleEvidence},
		})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(d.Results), d.Results)
	}
	entry := d.Results[0]
	if entry.RuleID != rule.ID || entry.Change != contractsentinel.ChangeStatusChanged {
		t.Fatalf("entry = %q/%q, want %q/%q", entry.RuleID, entry.Change, rule.ID, contractsentinel.ChangeStatusChanged)
	}
	if entry.Before == nil || entry.After == nil {
		t.Fatal("a rule present in both reports must keep both sides")
	}
	if entry.Before.Rule.Status != contractsentinel.StatusUnchecked || entry.Before.Finding != nil {
		t.Errorf("baseline side must be the unchecked rule without a finding: %+v", entry.Before)
	}
	if entry.After.Rule.Status != contractsentinel.StatusDefect ||
		entry.After.Finding == nil || entry.After.Finding.Evidence != addedRuleEvidence {
		t.Errorf("new side must keep the defect and its evidence: %+v", entry.After)
	}
	s := d.Summary
	if s.StatusChanges != 1 || s.AddedRules != 0 || s.NewDefects != 0 {
		t.Errorf("summary = %+v, want statusChanges=1 addedRules=0 newDefects=0", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}

// TestCLIDiffAddedDefectRuleAgainstRuleLessBaseline 基准报告没有任何规则也
// 是合法输入：diff 正常退出，新侧缺陷规则按“新增规则”呈现，基准侧保持 null
// 而不补成“通过”，新侧缺陷总数照常计入这条真实缺陷。
func TestCLIDiffAddedDefectRuleAgainstRuleLessBaseline(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	addedRule := addedCLIRules()[0]

	// 基准报告零规则零检查：合法的空范围报告。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, nil, nil)
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{addedRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: addedRule.ID, Version: addedRule.Version, Status: contractsentinel.StatusDefect, Note: addedRuleEvidence},
		})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff against a rule-less baseline must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(d.Results), d.Results)
	}
	entry := d.Results[0]
	if entry.RuleID != addedRule.ID || entry.Change != contractsentinel.ChangeRuleAdded {
		t.Fatalf("entry = %q/%q, want %q/%q", entry.RuleID, entry.Change, addedRule.ID, contractsentinel.ChangeRuleAdded)
	}
	if entry.Before != nil {
		t.Errorf("absent baseline side must be null, not a fabricated 通过: %+v", entry.Before)
	}
	if entry.After == nil || entry.After.Finding == nil ||
		entry.After.Finding.Evidence != addedRuleEvidence ||
		entry.After.Finding.ArtifactHash != hash || entry.After.Finding.Version != addedRule.Version {
		t.Errorf("new side must keep the archived defect: %+v", entry.After)
	}
	s := d.Summary
	if s.AddedRules != 1 || s.NewDefects != 0 {
		t.Errorf("summary = %+v, want added=1 newDefects=0", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
	if !strings.Contains(stdout, `"before": null`) {
		t.Errorf("added entry must render the absent side as null:\n%s", stdout)
	}
}
