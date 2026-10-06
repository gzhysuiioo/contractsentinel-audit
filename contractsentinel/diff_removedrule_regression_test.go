package contractsentinel

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 本文件围绕比较功能的一项业务回归口径：新报告缩小检查范围、不再包含基准
// 报告中的某条规则时，该规则必须记为“移除规则”——旧侧保留完整规则定义、
// 检查状态与原始缺陷记录，新侧为 null。旧报告有缺陷而新报告没有这条规则，
// 与后续检查确认缺陷已修复是两种不同的事实：缺陷总数减少本身不足以说明
// 原因，移除规则不能计入“已消除缺陷”，也不能为缺席的新侧补造“通过”结论
// 或缺陷记录。两侧缺陷总数仍分别反映各自归档中实际存在的缺陷。
//
// 所有用例都走 BuildReport -> SaveReport -> DiffStore 的正常归档与读回路径，
// 比较的是同一产物（同一名称、同一内容哈希）的两份合法报告。

// removedRuleEvidence 刻意包含中文、换行与前后空白；规则被移除不得改写旧证据。
const removedRuleEvidence = "  被移除规则的旧反例：调用序列如下\n  withdraw 重入 receive 再入 withdraw  "

// keptRuleEvidence 是留在新报告中的对照规则的旧证据，与被移除规则的证据
// 刻意不同：留下的规则不能接收被移除规则的旧证据。
const keptRuleEvidence = "  保留规则的旧反例：owner 校验缺失  "

// removedRuleDefs 返回本次回归共用的两条规则定义：一条将在新报告中缺席
// （zz-removed-defect），一条继续接受检查（aa-kept-resolved）。两条规则刻意
// 引用同一个不变式名：归属按各自规则标识独立呈现，共享不变式名不得合并。
// 标识的字典序与提交排列顺序相反，归档中的排列顺序不影响比较归属。
func removedRuleDefs() (removed Rule, kept Rule) {
	removed = Rule{
		ID:        "zz-removed-defect",
		Kind:      "static",
		Severity:  "high",
		Invariant: "shared-no-reentrant",
		Version:   "1.4.2",
	}
	kept = Rule{
		ID:        "aa-kept-resolved",
		Kind:      "static",
		Severity:  "medium",
		Invariant: "shared-no-reentrant",
		Version:   "2.1.0",
	}
	return removed, kept
}

// TestDiffRemovedDefectRuleAlongsideResolvedControl 把一条被移除的缺陷规则与
// 一条定义完全一致、结论从“发现缺陷”变成“通过”的对照规则放在同一份比较
// 结果中：前者记为“移除规则”，后者记为“已消除缺陷”，两种变化各自进入对应
// 分类和计数，不能仅凭缺陷总数差把全部减少都算成修复。
func TestDiffRemovedDefectRuleAlongsideResolvedControl(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	removed, kept := removedRuleDefs()

	// 基准报告：两条规则都发现缺陷，各自携带自己的原始证据。规则按与字典序
	// 相反的顺序提交，归档排列顺序不得影响比较归属。
	before := saveCheckReport(t, dir, artifact, []Rule{removed, kept}, []CheckRecord{
		{ArtifactHash: hash, RuleID: removed.ID, Version: removed.Version, Status: StatusDefect, Note: removedRuleEvidence},
		{ArtifactHash: hash, RuleID: kept.ID, Version: kept.Version, Status: StatusDefect, Note: keptRuleEvidence},
	})
	// 新报告：被移除的规则完全缺席（连规则定义都没有），留下的规则定义逐字
	// 相同、结论为通过。
	after := saveCheckReport(t, dir, artifact, []Rule{kept}, []CheckRecord{
		{ArtifactHash: hash, RuleID: kept.ID, Version: kept.Version, Status: StatusPass},
	})

	// 比较前两份报告都能正常读回；比较完成后内容必须与读回结果逐字段一致。
	loadedBefore, err := LoadReport(dir, before.ReportID)
	if err != nil {
		t.Fatalf("load before: %v", err)
	}
	loadedAfter, err := LoadReport(dir, after.ReportID)
	if err != nil {
		t.Fatalf("load after: %v", err)
	}
	if len(loadedBefore.Findings) != 2 || len(loadedAfter.Findings) != 0 {
		t.Fatalf("archived findings = %d/%d, want 2/0", len(loadedBefore.Findings), len(loadedAfter.Findings))
	}
	filesBefore := storeFileNames(t, dir)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("diff must succeed when a rule is removed: %v", err)
	}

	// 报告标识与比较方向按归档选择保留，同一产物不得被标记为变化。
	if diff.Before.ReportID != before.ReportID || diff.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", diff.Before.ReportID, diff.After.ReportID, before.ReportID, after.ReportID)
	}
	if diff.ArtifactHashChanged || diff.ArtifactNameChanged {
		t.Error("same artifact must not be flagged changed")
	}

	// 每个规则标识恰好出现一次，结果按标识排序，与归档中的排列顺序无关。
	if len(diff.Results) != 2 {
		t.Fatalf("results = %d, want 2: %+v", len(diff.Results), diff.Results)
	}
	seen := map[string]bool{}
	for _, r := range diff.Results {
		if seen[r.RuleID] {
			t.Fatalf("rule id %q appears more than once: %+v", r.RuleID, diff.Results)
		}
		seen[r.RuleID] = true
	}
	if diff.Results[0].RuleID != kept.ID || diff.Results[1].RuleID != removed.ID {
		t.Fatalf("results must be sorted by rule id: %q then %q", diff.Results[0].RuleID, diff.Results[1].RuleID)
	}
	byID := map[string]RuleDiff{}
	for _, r := range diff.Results {
		byID[r.RuleID] = r
	}

	// 被移除的规则：change 为“移除规则”，旧侧保留完整规则定义、检查状态与
	// 原始缺陷记录，新侧整体为 null——不能为缺席的新侧补造“通过”结论或缺陷
	// 记录。
	removedEntry := byID[removed.ID]
	if removedEntry.Change != ChangeRuleRemoved {
		t.Fatalf("removed rule change = %q, want %q", removedEntry.Change, ChangeRuleRemoved)
	}
	if removedEntry.Before == nil {
		t.Fatal("removed rule must keep its baseline side")
	}
	if removedEntry.After != nil {
		t.Fatalf("absent after side must be null, got %+v", removedEntry.After)
	}
	assertRuleFields(t, "removed before side", removedEntry.Before.Rule, removed, StatusDefect, removedRuleEvidence)
	removedFinding := removedEntry.Before.Finding
	if removedFinding == nil {
		t.Fatal("removed rule must keep its baseline defect finding")
	}
	// 产物哈希、规则标识和版本仍指向旧报告中的绑定，证据逐字保留。
	if removedFinding.ArtifactHash != hash {
		t.Errorf("removed finding artifact hash = %q, want %q", removedFinding.ArtifactHash, hash)
	}
	if removedFinding.RuleID != removed.ID {
		t.Errorf("removed finding rule id = %q, want %q", removedFinding.RuleID, removed.ID)
	}
	if removedFinding.Version != removed.Version {
		t.Errorf("removed finding version = %q, want baseline %q", removedFinding.Version, removed.Version)
	}
	if removedFinding.Severity != removed.Severity || removedFinding.Invariant != removed.Invariant {
		t.Errorf("removed finding binding = %+v, want severity %q invariant %q",
			removedFinding, removed.Severity, removed.Invariant)
	}
	if removedFinding.Evidence != removedRuleEvidence {
		t.Errorf("removed finding evidence = %q, want %q verbatim", removedFinding.Evidence, removedRuleEvidence)
	}

	// 对照规则：定义完全一致、发现缺陷 -> 通过，记为“已消除缺陷”。它引用与
	// 被移除规则相同的不变式名，但必须按自己的标识独立呈现：旧侧证据是它
	// 自己的，不是被移除规则的；通过侧没有缺陷记录。
	keptEntry := byID[kept.ID]
	if keptEntry.Change != ChangeResolvedDefect {
		t.Fatalf("kept rule change = %q, want %q", keptEntry.Change, ChangeResolvedDefect)
	}
	if keptEntry.Before == nil || keptEntry.After == nil {
		t.Fatal("both sides must be present for the kept rule")
	}
	assertRuleFields(t, "kept before side", keptEntry.Before.Rule, kept, StatusDefect, keptRuleEvidence)
	assertRuleFields(t, "kept after side", keptEntry.After.Rule, kept, StatusPass, "")
	if keptEntry.Before.Finding == nil {
		t.Fatal("kept rule must keep its own baseline finding")
	}
	if keptEntry.Before.Finding.Evidence != keptRuleEvidence {
		t.Errorf("kept rule evidence = %q, want its own %q (must not inherit the removed rule's evidence)",
			keptEntry.Before.Finding.Evidence, keptRuleEvidence)
	}
	if keptEntry.Before.Finding.RuleID != kept.ID || keptEntry.Before.Finding.Version != kept.Version ||
		keptEntry.Before.Finding.ArtifactHash != hash {
		t.Errorf("kept finding binding = %+v, want rule %q version %q hash %q",
			keptEntry.Before.Finding, kept.ID, kept.Version, hash)
	}
	if keptEntry.After.Finding != nil {
		t.Errorf("passing side must carry no finding: %+v", keptEntry.After.Finding)
	}

	// 汇总：移除规则与已消除缺陷各计一条；缺陷总数从 2 降到 0，但其中只有
	// 一条是“发现缺陷 -> 通过”的迁移，不能凭总数差把全部减少都算成修复。
	s := diff.Summary
	if s.RemovedRules != 1 {
		t.Errorf("removedRules = %d, want 1", s.RemovedRules)
	}
	if s.ResolvedDefects != 1 {
		t.Errorf("resolvedDefects = %d, want 1 (the removed rule is not a resolution)", s.ResolvedDefects)
	}
	if s.NewDefects != 0 || s.StatusChanges != 0 || s.NoteChanges != 0 ||
		s.NoChange != 0 || s.AddedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other change count must be zero: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0 (actual findings per archive)",
			s.BeforeDefects, s.AfterDefects)
	}

	// 归档字节层面：被移除规则证据中的中文、换行（JSON 中转义为 \n）和前后
	// 空白必须原样落盘，不能被修剪或替换。
	data, err := os.ReadFile(filepath.Join(dir, before.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	wantEscaped := `"evidence":"  被移除规则的旧反例：调用序列如下\n  withdraw 重入 receive 再入 withdraw  "`
	if !strings.Contains(string(data), wantEscaped) {
		t.Errorf("baseline archive must keep the removed rule's evidence verbatim:\n%s", string(data))
	}

	// 比较只是读取：两份报告的内容与标识保持原样，报告目录不增不减。
	reloadedBefore, err := LoadReport(dir, before.ReportID)
	if err != nil {
		t.Fatalf("reload before: %v", err)
	}
	reloadedAfter, err := LoadReport(dir, after.ReportID)
	if err != nil {
		t.Fatalf("reload after: %v", err)
	}
	if !reflect.DeepEqual(reloadedBefore, loadedBefore) || !reflect.DeepEqual(reloadedAfter, loadedAfter) {
		t.Error("diff must not change either archived report")
	}
	filesAfter := storeFileNames(t, dir)
	if !reflect.DeepEqual(filesBefore, filesAfter) {
		t.Errorf("store files changed by diff: %v -> %v", filesBefore, filesAfter)
	}
}

// TestDiffRemovedRuleWhenAfterReportHasNoRules 覆盖新报告没有任何规则的合法
// 输入：旧报告中的缺陷规则仍按“移除规则”处理，新侧缺陷总数为零，比较不得
// 报错，也不得把缺陷的消失推断成修复。
func TestDiffRemovedRuleWhenAfterReportHasNoRules(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	removed, _ := removedRuleDefs()

	before := saveCheckReport(t, dir, artifact, []Rule{removed}, []CheckRecord{
		{ArtifactHash: hash, RuleID: removed.ID, Version: removed.Version, Status: StatusDefect, Note: removedRuleEvidence},
	})
	// 新报告一条规则也没有：这是合法的归档（规则与缺陷列表均为空）。
	after := saveCheckReport(t, dir, artifact, nil, nil)
	if len(after.Rules) != 0 || len(after.Findings) != 0 {
		t.Fatalf("after report must be empty, got rules=%d findings=%d", len(after.Rules), len(after.Findings))
	}

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("diff against an empty after report must succeed: %v", err)
	}
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(diff.Results), diff.Results)
	}
	entry := diff.Results[0]
	if entry.RuleID != removed.ID || entry.Change != ChangeRuleRemoved {
		t.Fatalf("entry = %+v, want the defect rule classified as %q", entry, ChangeRuleRemoved)
	}
	if entry.Before == nil || entry.After != nil {
		t.Fatalf("removed rule must keep its baseline side and a null after side: %+v", entry)
	}
	assertRuleFields(t, "removed before side", entry.Before.Rule, removed, StatusDefect, removedRuleEvidence)
	if entry.Before.Finding == nil || entry.Before.Finding.Evidence != removedRuleEvidence ||
		entry.Before.Finding.ArtifactHash != hash || entry.Before.Finding.Version != removed.Version {
		t.Errorf("baseline finding must be preserved verbatim: %+v", entry.Before.Finding)
	}

	s := diff.Summary
	if s.RemovedRules != 1 {
		t.Errorf("removedRules = %d, want 1", s.RemovedRules)
	}
	if s.ResolvedDefects != 0 || s.NewDefects != 0 || s.StatusChanges != 0 ||
		s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("an empty after report must not fabricate any other change: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}
}
