package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护“移除规则”与“已消除缺陷”的区分：
// 新报告缩小检查范围、不再包含基准报告中某条带缺陷的规则时，该规则必须记为
// “移除规则”——旧侧保留完整规则定义、检查状态与原始缺陷记录，新侧为 null；
// 同一份比较中定义完全一致、发现缺陷 -> 通过的对照规则才记为“已消除缺陷”。
// 缺陷总数减少本身不足以说明原因，不能凭总数差把全部减少都算成修复。两侧
// 报告都通过真实 audit 命令正常归档，再由 diff 命令读回比较，既有报告格式、
// 报告标识与基准/新比较方向保持兼容。

// cliRemovedRuleEvidence 与 cliKeptRuleEvidence 刻意包含中文、换行与前后空白，
// 且两条规则的证据互不相同：被移除规则的旧证据不得改写，也不得跑到留下的
// 规则上。
const cliRemovedRuleEvidence = "  被移除规则的旧反例：重入路径仍可达\n  第二行证据  "
const cliKeptRuleEvidence = "  保留规则的旧反例：owner 校验缺失  "

// cliRemovedRulePair 返回共用的两条规则定义：zz-removed-defect 将在新报告中
// 缺席，aa-kept-resolved 继续接受检查。两条规则刻意引用同一个不变式名，
// 归属必须按各自规则标识独立呈现；标识字典序与提交排列顺序相反。
func cliRemovedRulePair() (removed, kept cliWireRule) {
	removed = cliWireRule{
		ID:        "zz-removed-defect",
		Kind:      "static",
		Severity:  "high",
		Invariant: "shared-no-reentrant",
		Version:   "1.4.2",
	}
	kept = cliWireRule{
		ID:        "aa-kept-resolved",
		Kind:      "static",
		Severity:  "medium",
		Invariant: "shared-no-reentrant",
		Version:   "2.1.0",
	}
	return removed, kept
}

// TestCLIDiffRemovedDefectRuleAlongsideResolvedControl 在进程边界上覆盖：同一
// 份比较结果中，被移除的缺陷规则与定义不变的已消除缺陷各自进入对应分类和
// 计数，证据逐字保留，归档在比较前后保持原样。
func TestCLIDiffRemovedDefectRuleAlongsideResolvedControl(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	removed, kept := cliRemovedRulePair()

	// 基准报告：两条规则都发现缺陷，按与字典序相反的顺序提交；新报告只剩
	// 定义逐字相同的对照规则，结论为通过。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{removed, kept},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: removed.ID, Version: removed.Version,
				Status: contractsentinel.StatusDefect, Note: cliRemovedRuleEvidence},
			{ArtifactHash: hash, RuleID: kept.ID, Version: kept.Version,
				Status: contractsentinel.StatusDefect, Note: cliKeptRuleEvidence},
		})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{kept},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: kept.ID, Version: kept.Version,
			Status: contractsentinel.StatusPass}})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	// 报告标识与比较方向按命令行参数保留，同一产物不得被标记为变化。
	if d.Before.ReportID != before.ReportID || d.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", d.Before.ReportID, d.After.ReportID, before.ReportID, after.ReportID)
	}
	if d.ArtifactNameChanged || d.ArtifactHashChanged {
		t.Error("same artifact must not be flagged changed")
	}

	// 每个规则标识恰好一个结果，按标识排序，与提交排列顺序无关。
	if len(d.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(d.Results))
	}
	ids := []string{d.Results[0].RuleID, d.Results[1].RuleID}
	if !sort.StringsAreSorted(ids) || ids[0] == ids[1] {
		t.Fatalf("results must be sorted distinct rule ids, got %v", ids)
	}

	// 被移除的规则：change 为“移除规则”，旧侧完整保留，新侧为 null。
	removedEntry := diffEntry(t, d, removed.ID)
	if removedEntry.Change != contractsentinel.ChangeRuleRemoved {
		t.Fatalf("removed rule change = %q, want %q", removedEntry.Change, contractsentinel.ChangeRuleRemoved)
	}
	if removedEntry.After != nil {
		t.Fatalf("absent after side must be null, got %+v", removedEntry.After)
	}
	if removedEntry.Before == nil {
		t.Fatal("removed rule must keep its baseline side")
	}
	br := removedEntry.Before.Rule
	if br.ID != removed.ID || br.Kind != removed.Kind || br.Severity != removed.Severity ||
		br.Invariant != removed.Invariant || br.RequiresABI != removed.RequiresABI ||
		br.Version != removed.Version || br.Status != contractsentinel.StatusDefect ||
		br.Note != cliRemovedRuleEvidence {
		t.Errorf("removed baseline rule = %+v, want the full archived definition with 发现缺陷", br)
	}
	bf := removedEntry.Before.Finding
	if bf == nil {
		t.Fatal("removed rule must keep its baseline defect finding")
	}
	if bf.ArtifactHash != hash || bf.RuleID != removed.ID || bf.Version != removed.Version ||
		bf.Severity != removed.Severity || bf.Invariant != removed.Invariant {
		t.Errorf("removed finding binding = %+v, want the baseline hash/rule/version", bf)
	}
	if bf.Evidence != cliRemovedRuleEvidence {
		t.Errorf("removed evidence = %q, want %q verbatim", bf.Evidence, cliRemovedRuleEvidence)
	}

	// 对照规则：定义完全一致、发现缺陷 -> 通过，记为“已消除缺陷”；旧侧证据
	// 是它自己的，不是被移除规则的，通过侧没有缺陷记录。
	keptEntry := diffEntry(t, d, kept.ID)
	if keptEntry.Change != contractsentinel.ChangeResolvedDefect {
		t.Fatalf("kept rule change = %q, want %q", keptEntry.Change, contractsentinel.ChangeResolvedDefect)
	}
	if keptEntry.Before == nil || keptEntry.After == nil {
		t.Fatal("both sides must be present for the kept rule")
	}
	if keptEntry.Before.Rule.Status != contractsentinel.StatusDefect ||
		keptEntry.After.Rule.Status != contractsentinel.StatusPass {
		t.Errorf("kept statuses = %q/%q", keptEntry.Before.Rule.Status, keptEntry.After.Rule.Status)
	}
	if keptEntry.Before.Finding == nil || keptEntry.Before.Finding.Evidence != cliKeptRuleEvidence ||
		keptEntry.Before.Finding.RuleID != kept.ID || keptEntry.Before.Finding.Version != kept.Version {
		t.Errorf("kept rule must keep its own baseline finding: %+v", keptEntry.Before.Finding)
	}
	if keptEntry.After.Finding != nil {
		t.Errorf("passing side must carry no finding: %+v", keptEntry.After.Finding)
	}

	// 汇总：移除规则与已消除缺陷各计一条；缺陷总数 2 -> 0 中只有一条是修复。
	s := d.Summary
	if s.RemovedRules != 1 || s.ResolvedDefects != 1 {
		t.Errorf("summary = %+v, want one removed rule and one resolved defect", s)
	}
	if s.NewDefects != 0 || s.StatusChanges != 0 || s.NoteChanges != 0 ||
		s.NoChange != 0 || s.AddedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other change count must be zero: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0", s.BeforeDefects, s.AfterDefects)
	}

	// 原始输出字节层面：两条证据中的中文、换行（JSON 转义为 \n）和前后空白
	// 都逐字保留，各自留在自己的规则条目里。
	if !strings.Contains(stdout, "  被移除规则的旧反例：重入路径仍可达\\n  第二行证据  ") {
		t.Errorf("diff output must preserve the removed rule's evidence verbatim:\n%s", stdout)
	}
	if !strings.Contains(stdout, "  保留规则的旧反例：owner 校验缺失  ") {
		t.Errorf("diff output must preserve the kept rule's evidence verbatim:\n%s", stdout)
	}

	// 比较前后的报告内容与标识保持原样：两份报告仍可按原标识读回，被移除
	// 规则的缺陷记录与证据仍在基准报告中。
	reBefore, stderr, code := runCLIReport(t, bin, store, before.ReportID)
	if code != 0 {
		t.Fatalf("baseline report must still load after the diff: %s", stderr)
	}
	reloadedBefore := decodeReport(t, reBefore)
	if len(reloadedBefore.Rules) != 2 || len(reloadedBefore.Findings) != 2 {
		t.Errorf("baseline report changed by diff: rules=%d findings=%d",
			len(reloadedBefore.Rules), len(reloadedBefore.Findings))
	}
	reAfter, stderr, code := runCLIReport(t, bin, store, after.ReportID)
	if code != 0 {
		t.Fatalf("after report must still load after the diff: %s", stderr)
	}
	reloadedAfter := decodeReport(t, reAfter)
	if len(reloadedAfter.Rules) != 1 || reloadedAfter.Rules[0].ID != kept.ID ||
		reloadedAfter.Rules[0].Status != contractsentinel.StatusPass {
		t.Errorf("after report changed by diff: %+v", reloadedAfter.Rules)
	}
}

// TestCLIDiffRemovedRuleWhenAfterReportHasNoRules 在进程边界上覆盖：新报告
// 没有任何规则同样是合法输入，旧报告中的缺陷规则按“移除规则”处理，新侧
// 缺陷总数为零，命令成功退出且不推断修复。
func TestCLIDiffRemovedRuleWhenAfterReportHasNoRules(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	removed, _ := cliRemovedRulePair()

	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{removed},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: removed.ID, Version: removed.Version,
			Status: contractsentinel.StatusDefect, Note: cliRemovedRuleEvidence}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{}, nil)

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff against an empty after report must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	if len(d.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(d.Results))
	}
	entry := d.Results[0]
	if entry.RuleID != removed.ID || entry.Change != contractsentinel.ChangeRuleRemoved {
		t.Fatalf("entry = %+v, want the defect rule classified as %q", entry, contractsentinel.ChangeRuleRemoved)
	}
	if entry.Before == nil || entry.Before.Finding == nil ||
		entry.Before.Finding.Evidence != cliRemovedRuleEvidence ||
		entry.Before.Finding.ArtifactHash != hash || entry.Before.Finding.Version != removed.Version {
		t.Errorf("baseline side must keep the defect finding verbatim: %+v", entry.Before)
	}
	if entry.After != nil {
		t.Errorf("absent after side must be null, got %+v", entry.After)
	}
	s := d.Summary
	if s.RemovedRules != 1 || s.ResolvedDefects != 0 || s.NewDefects != 0 {
		t.Errorf("summary = %+v, want one removed rule and no defect transitions", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}
}
