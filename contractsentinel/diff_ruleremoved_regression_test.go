package contractsentinel

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 本文件围绕比较功能的一项业务回归口径：新报告缩小检查范围、完全移除某条
// 带缺陷的旧规则时，输出必须为该标识保留一个“移除规则”条目——而不是仅凭
// 缺陷总数下降就把这条旧缺陷记成“已消除缺陷”。规则不再接受检查，并不等于
// 后续检查确认缺陷已修复：移除条目只保留旧侧，旧侧必须仍是归档中的完整规则
// 定义、检查状态（发现缺陷）和原始缺陷记录；缺席的新侧为 null，不能补造
// “通过”结论或缺陷记录。汇总中移除规则数计入这一条，已消除缺陷数不能因此
// 增加；两侧缺陷总数只数各自归档中实际存在的缺陷，不抹掉旧侧缺陷。
//
// 同一份比较结果中保留一条仍在新报告接受检查的规则作为对照：定义完全一致、
// 发现缺陷 -> 通过归为“已消除缺陷”，通过侧 finding 为 null。两条规则即使引用
// 同一个不变式名，也按各自规则标识独立呈现，互不接收对方的旧证据。
//
// 所有用例都走 BuildReport -> SaveReport -> DiffStore 的正常归档与读回路径，
// 比较的是同一产物（同一名称、同一内容哈希）的两份可正常读取的归档报告。

// removedRuleEvidence 刻意包含中文、换行与前后空白；移除不得改写旧证据。
const removedRuleEvidence = "  旧反例：该检查已被移出范围\n  reentrancy 路径第二行  "

// removedPairRules 构造同一份产物上的两条规则：removed-id 将在新报告中完全
// 缺席，kept-id 仍接受检查。两者刻意引用同一个不变式名，回归保障必须按规则
// 标识、而非按不变式名归属证据与结论。
func removedPairRules() []Rule {
	return []Rule{
		{
			ID:        "removed-reentrancy",
			Kind:      "static",
			Severity:  "high",
			Invariant: "shared-reentrancy-invariant",
			Version:   "7.3.0",
		},
		{
			ID:        "kept-reentrancy",
			Kind:      "static",
			Severity:  "medium",
			Invariant: "shared-reentrancy-invariant",
			Version:   "2.0.4",
		},
	}
}

// assertFindingBinding 校验一条缺陷记录仍指向归档时的产物哈希、规则标识、版本
// 及原始证据（中文、换行与前后空白逐字保留），且严重级别与不变式名取自规则。
func assertFindingBinding(t *testing.T, where string, f *ReportFinding, hash string, rule Rule, evidence string) {
	t.Helper()
	if f == nil {
		t.Fatalf("%s: defect finding must be preserved", where)
	}
	if f.ArtifactHash != hash {
		t.Errorf("%s: artifact hash = %q, want %q", where, f.ArtifactHash, hash)
	}
	if f.RuleID != rule.ID {
		t.Errorf("%s: rule id = %q, want %q", where, f.RuleID, rule.ID)
	}
	if f.Version != rule.Version {
		t.Errorf("%s: version = %q, want %q (must stay the archived version)", where, f.Version, rule.Version)
	}
	if f.Severity != rule.Severity {
		t.Errorf("%s: severity = %q, want %q", where, f.Severity, rule.Severity)
	}
	if f.Invariant != rule.Invariant {
		t.Errorf("%s: invariant = %q, want %q", where, f.Invariant, rule.Invariant)
	}
	if f.Evidence != evidence {
		t.Errorf("%s: evidence = %q, want %q verbatim", where, f.Evidence, evidence)
	}
}

// saveRemovedBeforeReport 落盘基准报告：两条规则都为发现缺陷，各自带自己的
// 反例证据；证据中的中文、换行和前后空白随检查说明原样归档。
func saveRemovedBeforeReport(t *testing.T, dir string, artifact Artifact) (Report, []Rule) {
	t.Helper()
	hash := ArtifactHash(artifact)
	rules := removedPairRules()
	report := saveCheckReport(t, dir, artifact, rules, []CheckRecord{
		{ArtifactHash: hash, RuleID: rules[0].ID, Version: rules[0].Version, Status: StatusDefect, Note: removedRuleEvidence},
		{ArtifactHash: hash, RuleID: rules[1].ID, Version: rules[1].Version, Status: StatusDefect, Note: "  保留规则的旧反例\n第二行  "},
	})
	return report, rules
}

// TestDiffRemovedDefectRuleIsRemovedNotResolved 是核心回归用例：带缺陷的旧
// 规则在新报告规则列表中完全缺席，必须记为“移除规则”而非“已消除缺陷”，旧侧
// 完整保留、新侧为 null；同报告中定义一致的对照规则记为“已消除缺陷”。
func TestDiffRemovedDefectRuleIsRemovedNotResolved(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)

	before, rules := saveRemovedBeforeReport(t, dir, artifact)
	removedRule := rules[0]
	keptRule := rules[1]

	// 新报告只保留对照规则（定义完全一致）并复跑通过；被移除规则完全缺席。
	after := saveRuleChangeCheckReport(t, dir, artifact, keptRule, StatusPass, "")

	// 两份归档必须能独立读回：基准侧两条真实缺陷，新侧无缺陷。
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
	ruleIDsBefore := map[string]bool{}
	for _, r := range loadedBefore.Rules {
		ruleIDsBefore[r.ID] = true
	}
	if !ruleIDsBefore[removedRule.ID] {
		t.Fatalf("baseline must contain %s", removedRule.ID)
	}

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("diff must succeed when a defect rule is absent from the new report: %v", err)
	}

	// 比较方向与报告标识按归档选择保留；同一产物不标记为变化。
	if diff.Before.ReportID != before.ReportID || diff.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", diff.Before.ReportID, diff.After.ReportID, before.ReportID, after.ReportID)
	}
	if diff.ArtifactHashChanged || diff.ArtifactNameChanged {
		t.Error("same artifact must not be flagged changed")
	}

	// 每个标识只出现一次，共两条结果，且按规则标识排列。
	if len(diff.Results) != 2 {
		t.Fatalf("results = %d, want 2: %+v", len(diff.Results), diff.Results)
	}
	ids := []string{}
	for _, r := range diff.Results {
		ids = append(ids, r.RuleID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}
	seen := map[string]int{}
	for _, r := range diff.Results {
		seen[r.RuleID]++
	}
	if seen[removedRule.ID] != 1 || seen[keptRule.ID] != 1 {
		t.Fatalf("each id must appear exactly once: %v", seen)
	}

	// --- 被移除的缺陷规则 ---
	removed := entryByID(t, diff, removedRule.ID)
	if removed.Change != ChangeRuleRemoved {
		t.Fatalf("removed rule change = %q, want %q", removed.Change, ChangeRuleRemoved)
	}
	if removed.After != nil {
		t.Fatalf("absent new side must be null, got %+v", removed.After)
	}
	if removed.Before == nil {
		t.Fatal("removed rule must keep its old side")
	}
	assertRuleFields(t, "removed before side", removed.Before.Rule, removedRule, StatusDefect, removedRuleEvidence)
	assertFindingBinding(t, "removed before side", removed.Before.Finding, hash, removedRule, removedRuleEvidence)

	// --- 仍在检查的对照规则：定义一致、缺陷 -> 通过 ---
	kept := entryByID(t, diff, keptRule.ID)
	if kept.Change != ChangeResolvedDefect {
		t.Fatalf("kept rule change = %q, want %q", kept.Change, ChangeResolvedDefect)
	}
	if kept.Before == nil || kept.After == nil {
		t.Fatal("resolved rule must carry both sides")
	}
	assertRuleFields(t, "kept before side", kept.Before.Rule, keptRule, StatusDefect, "  保留规则的旧反例\n第二行  ")
	assertRuleFields(t, "kept after side", kept.After.Rule, keptRule, StatusPass, "")
	assertFindingBinding(t, "kept before side", kept.Before.Finding, hash, keptRule, "  保留规则的旧反例\n第二行  ")
	if kept.After.Finding != nil {
		t.Errorf("passing kept-rule side must carry no finding: %+v", kept.After.Finding)
	}

	// --- 留下的规则绝不能接收到被移除规则的旧证据 ---
	if kept.Before.Finding != nil && kept.Before.Finding.ArtifactHash != hash {
		t.Errorf("kept finding hash = %q, want %q", kept.Before.Finding.ArtifactHash, hash)
	}
	if removed.Before.Finding != nil && kept.Before.Finding != nil &&
		removed.Before.Finding.Evidence == kept.Before.Finding.Evidence {
		t.Error("each rule must keep its own evidence; kept rule inherited the removed rule's evidence")
	}

	// --- 汇总：移除计入一，消除计入一；不能把移除算成消除 ---
	s := diff.Summary
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
	// 两侧缺陷总数只数各自归档中实际存在的缺陷：旧侧 2、新侧 0。
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0 (actual archived findings)", s.BeforeDefects, s.AfterDefects)
	}

	// 比较是只读操作：两份归档内容与标识保持原样，证据逐字落盘（JSON 中
	// 换行转义为 \n），中文、前后空白不被修剪。
	for _, id := range []string{before.ReportID, after.ReportID} {
		data, err := os.ReadFile(filepath.Join(dir, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"reportId":"`+id+`"`) {
			t.Errorf("archive %s must keep its own id", id)
		}
	}
	beforeBytes, err := os.ReadFile(filepath.Join(dir, before.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	wantEscaped := `"evidence":"  旧反例：该检查已被移出范围\n  reentrancy 路径第二行  "`
	if !strings.Contains(string(beforeBytes), wantEscaped) {
		t.Errorf("baseline archive must keep the raw evidence verbatim:\n%s", string(beforeBytes))
	}
}

// TestDiffRemovedDefectRuleAgainstEmptyNewReport 新报告没有任何规则时同样是
// 合法输入：旧侧这条缺陷规则仍按移除处理，新侧缺陷总数为零，不报错也不推断
// 为修复。
func TestDiffRemovedDefectRuleAgainstEmptyNewReport(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)

	removedRule := removedPairRules()[0]
	before := saveRuleChangeCheckReport(t, dir, artifact, removedRule, StatusDefect, removedRuleEvidence)
	// 新报告零规则：合法归档，rules 与 findings 均为空。
	after := saveCheckReport(t, dir, artifact, nil, nil)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("diff against a rule-less new report must succeed: %v", err)
	}
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(diff.Results), diff.Results)
	}
	entry := diff.Results[0]
	if entry.RuleID != removedRule.ID || entry.Change != ChangeRuleRemoved {
		t.Fatalf("entry = %q/%q, want %q/%q", entry.RuleID, entry.Change, removedRule.ID, ChangeRuleRemoved)
	}
	if entry.After != nil {
		t.Errorf("absent new side must be null: %+v", entry.After)
	}
	assertRuleFields(t, "before side", entry.Before.Rule, removedRule, StatusDefect, removedRuleEvidence)
	assertFindingBinding(t, "before side", entry.Before.Finding, hash, removedRule, removedRuleEvidence)

	s := diff.Summary
	if s.RemovedRules != 1 {
		t.Errorf("removedRules = %d, want 1", s.RemovedRules)
	}
	if s.ResolvedDefects != 0 || s.NewDefects != 0 {
		t.Errorf("removal must not count as a defect transition: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}
}

// TestDiffRemovedAndResolvedIndependentOfArchiveOrder 归档中的排列顺序不影响
// 归属：无论基准侧两条规则以何种顺序存储、新报告对照规则放在哪里，被移除
// 规则与已消除规则都按标识独立分类。
func TestDiffRemovedAndResolvedIndependentOfArchiveOrder(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := removedPairRules()
	removedRule, keptRule := rules[0], rules[1]

	// 基准侧刻意把对照规则排在前面；新报告只留对照规则。
	before := saveCheckReport(t, dir, artifact, []Rule{keptRule, removedRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: keptRule.ID, Version: keptRule.Version, Status: StatusDefect, Note: "  保留规则的旧反例\n第二行  "},
		{ArtifactHash: hash, RuleID: removedRule.ID, Version: removedRule.Version, Status: StatusDefect, Note: removedRuleEvidence},
	})
	after := saveRuleChangeCheckReport(t, dir, artifact, keptRule, StatusPass, "")

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]RuleDiff{}
	for _, r := range diff.Results {
		byID[r.RuleID] = r
	}
	if byID[removedRule.ID].Change != ChangeRuleRemoved {
		t.Errorf("removed = %q, want %q", byID[removedRule.ID].Change, ChangeRuleRemoved)
	}
	if byID[keptRule.ID].Change != ChangeResolvedDefect {
		t.Errorf("kept = %q, want %q", byID[keptRule.ID].Change, ChangeResolvedDefect)
	}
	if s := diff.Summary; s.RemovedRules != 1 || s.ResolvedDefects != 1 ||
		s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("summary = %+v, want removed=1 resolved=1 defects=2/0", s)
	}
}

// entryByID 取出指定规则标识的比较条目。
func entryByID(t *testing.T, diff DiffResult, ruleID string) RuleDiff {
	t.Helper()
	for _, r := range diff.Results {
		if r.RuleID == ruleID {
			return r
		}
	}
	t.Fatalf("diff result for rule %s not found", ruleID)
	return RuleDiff{}
}
