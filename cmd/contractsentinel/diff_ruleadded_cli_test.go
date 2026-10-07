package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护“新增规则”口径：新报告扩大检查范围、
// 首次引入某条规则且该规则第一次接受检查就发现缺陷时，diff 必须为该规则标识
// 保留一个“新增规则”条目，基准侧为 null，新侧仍是归档中的完整规则定义、检查
// 状态和原始缺陷记录；这不同于两侧定义一致、通过 -> 发现缺陷的“新发现缺陷”。
// 两种变化放在同一份比较结果中，必须各自进入对应分类与计数：addedRules 计入
// 新增规则，newDefects 不因新增规则增加，而新侧缺陷总数仍如实包含这条真实缺
// 陷。两份报告都通过真实 audit 命令正常归档，再由 diff 命令读回比较，既有报
// 告格式、报告标识与基准/新比较方向保持兼容，比较过程不改写归档。

// 新增规则与已有规则的证据刻意包含中文、换行与前后空格，且互不相同，任何修
// 剪、模板替换或按不变式名互换证据都会被抓到。
const addedRuleEvidence = "  新反例：新增规则首次检出\n  reentrancy 路径第二行  "
const existingRuleEvidence = "  已有规则复跑反例\n第二行  "

// addedCLIRules 中的两条规则刻意引用同一个不变式名：归属只能按规则标识，
// 不能按不变式。
func addedCLIRules() []cliWireRule {
	return []cliWireRule{
		{ID: "added-reentrancy", Kind: "static", Severity: "critical", Invariant: "shared-reentrancy-invariant", Version: "8.1.0"},
		{ID: "existing-reentrancy", Kind: "static", Severity: "medium", Invariant: "shared-reentrancy-invariant", Version: "2.0.4"},
	}
}

// TestCLIDiffAddedDefectRuleIsNotNewDefect 在进程边界覆盖核心口径：带缺陷
// 新规则在基准报告完全缺席 -> “新增规则”（基准侧 null、新侧证据逐字保留）；
// 同份输出中定义一致的对照规则通过 -> 发现缺陷 -> “新发现缺陷”（通过侧无缺
// 陷记录）。addedRules 与 newDefects 各为一，两侧缺陷总数为零和二。
func TestCLIDiffAddedDefectRuleIsNotNewDefect(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := addedCLIRules()
	addedRule, existingRule := rules[0], rules[1]

	// 基准报告只包含已有规则，结论为通过；新增规则完全缺席。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{existingRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: existingRule.ID, Version: existingRule.Version, Status: contractsentinel.StatusPass},
		})
	// 新报告扩大检查范围：新增规则首次出现即发现缺陷，已有规则由通过变为
	// 发现缺陷；提交顺序刻意与标识排序不同，归属不得受归档排列影响。
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{existingRule, addedRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: existingRule.ID, Version: existingRule.Version, Status: contractsentinel.StatusDefect, Note: existingRuleEvidence},
			{ArtifactHash: hash, RuleID: addedRule.ID, Version: addedRule.Version, Status: contractsentinel.StatusDefect, Note: addedRuleEvidence},
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

	// --- 新增的缺陷规则 ---
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
	if ra := added.After.Rule; ra.ID != addedRule.ID || ra.Kind != "static" ||
		ra.Severity != "critical" || ra.Invariant != "shared-reentrancy-invariant" ||
		ra.RequiresABI != false || ra.Version != "8.1.0" {
		t.Errorf("added new-side rule definition = %+v, want the archived definition", ra)
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
		af.Severity != "critical" || af.Invariant != "shared-reentrancy-invariant" {
		t.Errorf("added finding binding = %+v, want hash=%q rule=%q version=%q", af, hash, addedRule.ID, addedRule.Version)
	}
	if af.Evidence != addedRuleEvidence {
		t.Errorf("added evidence = %q, want %q verbatim", af.Evidence, addedRuleEvidence)
	}

	// --- 两侧都在的对照规则：定义一致、通过 -> 发现缺陷 ---
	existing := diffEntry(t, d, existingRule.ID)
	if existing.Change != contractsentinel.ChangeNewDefect {
		t.Fatalf("existing change = %q, want %q", existing.Change, contractsentinel.ChangeNewDefect)
	}
	if existing.Before == nil || existing.After == nil {
		t.Fatal("new-defect rule must carry both sides")
	}
	if eb := existing.Before.Rule; eb.ID != existingRule.ID || eb.Severity != "medium" ||
		eb.Version != "2.0.4" || eb.Status != contractsentinel.StatusPass || eb.Note != "" {
		t.Errorf("existing before = %+v", eb)
	}
	if ea := existing.After.Rule; ea.Status != contractsentinel.StatusDefect ||
		ea.Note != existingRuleEvidence || ea.ID != existingRule.ID || ea.Version != "2.0.4" {
		t.Errorf("existing after = %+v", ea)
	}
	if existing.Before.Finding != nil {
		t.Errorf("passing baseline side must carry no finding: %+v", existing.Before.Finding)
	}
	if existing.After.Finding == nil || existing.After.Finding.Evidence != existingRuleEvidence ||
		existing.After.Finding.RuleID != existingRule.ID || existing.After.Finding.Version != existingRule.Version ||
		existing.After.Finding.ArtifactHash != hash {
		t.Errorf("existing rule must keep its own finding: %+v", existing.After.Finding)
	}
	// 两条规则引用同一不变式名，也必须各自保留自己的反例，不能互换证据。
	if existing.After.Finding.Evidence == addedRuleEvidence {
		t.Error("existing rule inherited the added rule's evidence; findings must stay bound by rule id")
	}

	// --- 汇总：两类变化各计其一，缺陷总数只数各自归档的实际发现 ---
	s := d.Summary
	if s.AddedRules != 1 {
		t.Errorf("addedRules = %d, want 1", s.AddedRules)
	}
	if s.NewDefects != 1 {
		t.Errorf("newDefects = %d, want 1 (the added rule must not inflate this)", s.NewDefects)
	}
	if s.ResolvedDefects != 0 || s.StatusChanges != 0 || s.NoteChanges != 0 ||
		s.NoChange != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other count must be zero: %+v", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 2 {
		t.Errorf("defect totals = %d/%d, want 0/2 (actual archived findings)", s.BeforeDefects, s.AfterDefects)
	}

	// 原始输出字节层面：缺席基准侧渲染为 null，新侧证据中的中文、换行
	// （JSON 转义为 \n）和前后空白逐字保留。
	if !strings.Contains(stdout, `"before": null`) {
		t.Errorf("added entry must render the absent side as null:\n%s", stdout)
	}
	if !strings.Contains(stdout, "  新反例：新增规则首次检出\\n  reentrancy 路径第二行  ") {
		t.Errorf("diff output must preserve the added rule evidence verbatim:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"change": "`+contractsentinel.ChangeRuleAdded+`"`) {
		t.Errorf("diff output must carry the %q category:\n%s", contractsentinel.ChangeRuleAdded, stdout)
	}
	if !strings.Contains(stdout, `"change": "`+contractsentinel.ChangeNewDefect+`"`) {
		t.Errorf("diff output must carry the %q category:\n%s", contractsentinel.ChangeNewDefect, stdout)
	}
}

// TestCLIDiffAddedDefectRuleAgainstRuleLessBaseline 基准报告没有任何规则也
// 是合法输入：diff 正常退出，新缺陷规则按新增处理，基准侧保持 null 而不是补
// 成“通过”，新侧缺陷总数如实计一。
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
		[]cliWireCheck{{ArtifactHash: hash, RuleID: addedRule.ID, Version: addedRule.Version,
			Status: contractsentinel.StatusDefect, Note: addedRuleEvidence}})

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
		t.Errorf("absent baseline side must be null, not a fabricated pass: %+v", entry.Before)
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

// TestCLIDiffUncheckedBaselineRuleIsNotAdded 明确“新增”的判定边界：基准报告
// 已有该规则、只是状态为“未检查”，新报告同一规则发现缺陷时，diff 正常退出并
// 按现有规则归为“检查状态变化”，不计入新增规则，也不计入新发现缺陷。
func TestCLIDiffUncheckedBaselineRuleIsNotAdded(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rule := addedCLIRules()[0]

	// 基准侧：规则在但没有任何检查记录 -> 未检查。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{rule}, nil)
	// 新侧：同一条规则定义完全一致，外部检查器发现缺陷。
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
			Status: contractsentinel.StatusDefect, Note: addedRuleEvidence}})

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
		t.Fatalf("entry = %q/%q, want %q/%q (a rule present in the baseline is not an added rule)",
			entry.RuleID, entry.Change, rule.ID, contractsentinel.ChangeStatusChanged)
	}
	if entry.Before == nil || entry.After == nil {
		t.Fatal("a rule present in both reports must keep both sides")
	}
	if entry.Before.Rule.Status != contractsentinel.StatusUnchecked || entry.Before.Finding != nil {
		t.Errorf("baseline side = %+v, want 未检查 without a finding", entry.Before)
	}
	if entry.After.Rule.Status != contractsentinel.StatusDefect ||
		entry.After.Finding == nil || entry.After.Finding.Evidence != addedRuleEvidence {
		t.Errorf("new side must keep the archived defect: %+v", entry.After)
	}
	s := d.Summary
	if s.StatusChanges != 1 || s.AddedRules != 0 || s.NewDefects != 0 {
		t.Errorf("summary = %+v, want statusChanges=1 added=0 newDefects=0", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}
