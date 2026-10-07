package contractsentinel

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 本文件围绕比较功能的一项业务回归口径：新报告扩大检查范围、首次引入某条规则
// 且该规则第一次接受检查就发现缺陷时，输出必须为该标识保留一个“新增规则”条
// 目——而不是仅凭缺陷总数上升就把它记成已有规则的“新发现缺陷”。规则此前从未
// 出现在基准报告中，不存在可比较的基准侧结论：新增条目的基准侧为 null，不能
// 补造“通过”结论；新侧必须仍是归档中的完整规则定义、检查状态（发现缺陷）、原
// 始说明和缺陷记录。汇总中新增规则数计入这一条，新发现缺陷数不能因此增加；两
// 侧缺陷总数只数各自归档中实际存在的缺陷，新侧这条真实缺陷仍计入新侧总数，不
// 能为了分类而把它从总数或证据中抹掉。
//
// 同一份比较结果中保留一条两侧都存在的规则作为对照：定义完全一致、通过 ->
// 发现缺陷归为“新发现缺陷”，基准侧 finding 为 null。两条规则即使引用同一个
// 不变式名，也按各自规则标识独立呈现，各自保留自己的版本、严重级别与反例，
// 不按不变式名合并或互换证据。
//
// “新增”只依据规则是否出现在基准报告中判断：基准报告已有该规则、只是状态为
// “未检查”，后来发现缺陷时仍按现有规则归为“检查状态变化”。基准报告没有任何
// 规则也是合法比较条件：新增缺陷规则仍正常呈现，缺席侧保持 null。
//
// 所有用例都走 BuildReport -> SaveReport -> DiffStore 的正常归档与读回路径，
// 比较的是同一产物（同一名称、同一内容哈希）的两份可正常读取的归档报告。

// addedRuleEvidence 与 existingRuleEvidence 刻意包含中文、换行与前后空白，且
// 互不相同；新增不得改写证据，两条规则也不得互换证据。
const addedRuleEvidence = "  新反例：新增规则首次检出\n  reentrancy 路径第二行  "
const existingRuleEvidence = "  已有规则复跑反例\n第二行  "

// addedPairRules 构造同一份产物上的两条规则：added-reentrancy 在基准报告中
// 完全缺席，existing-reentrancy 两侧都在且定义完全一致。两者刻意引用同一个
// 不变式名，回归保障必须按规则标识、而非按不变式名归属证据与结论。
func addedPairRules() []Rule {
	return []Rule{
		{
			ID:        "added-reentrancy",
			Kind:      "static",
			Severity:  "critical",
			Invariant: "shared-reentrancy-invariant",
			Version:   "8.1.0",
		},
		{
			ID:        "existing-reentrancy",
			Kind:      "static",
			Severity:  "medium",
			Invariant: "shared-reentrancy-invariant",
			Version:   "2.0.4",
		},
	}
}

// TestDiffAddedDefectRuleIsAddedNotNewDefect 是核心回归用例：带缺陷的新规则
// 在基准报告规则列表中完全缺席，必须记为“新增规则”而非“新发现缺陷”，基准侧
// 为 null、新侧完整保留；同报告中定义一致的对照规则通过 -> 发现缺陷记为
// “新发现缺陷”。addedRules 与 newDefects 各为一，两侧缺陷总数为零和二。
func TestDiffAddedDefectRuleIsAddedNotNewDefect(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := addedPairRules()
	addedRule, existingRule := rules[0], rules[1]

	// 基准报告只包含已有规则，结论为通过；新增规则完全缺席，基准侧零缺陷。
	before := saveCheckReport(t, dir, artifact, []Rule{existingRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: existingRule.ID, Version: existingRule.Version, Status: StatusPass},
	})
	// 新报告扩大检查范围：新增规则首次出现即发现缺陷，已有规则由通过变为
	// 发现缺陷。规则与检查记录的排列顺序刻意与标识排序不同，归属不得受
	// 归档排列影响。
	after := saveCheckReport(t, dir, artifact, []Rule{existingRule, addedRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: existingRule.ID, Version: existingRule.Version, Status: StatusDefect, Note: existingRuleEvidence},
		{ArtifactHash: hash, RuleID: addedRule.ID, Version: addedRule.Version, Status: StatusDefect, Note: addedRuleEvidence},
	})

	// 两份归档必须能独立读回：基准侧零缺陷，新侧两条真实缺陷。
	loadedBefore, err := LoadReport(dir, before.ReportID)
	if err != nil {
		t.Fatalf("load before: %v", err)
	}
	loadedAfter, err := LoadReport(dir, after.ReportID)
	if err != nil {
		t.Fatalf("load after: %v", err)
	}
	if len(loadedBefore.Findings) != 0 || len(loadedAfter.Findings) != 2 {
		t.Fatalf("archived findings = %d/%d, want 0/2", len(loadedBefore.Findings), len(loadedAfter.Findings))
	}
	ruleIDsBefore := map[string]bool{}
	for _, r := range loadedBefore.Rules {
		ruleIDsBefore[r.ID] = true
	}
	if ruleIDsBefore[addedRule.ID] {
		t.Fatalf("baseline must not contain %s", addedRule.ID)
	}

	// 比较前留存归档快照：比较全程不得改动任何已保存报告。
	filesBefore := storeFileNames(t, dir)
	contentsBefore := map[string]string{}
	for _, name := range filesBefore {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		contentsBefore[name] = string(data)
	}

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("diff must succeed when the new report adds a defect rule: %v", err)
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
	if seen[addedRule.ID] != 1 || seen[existingRule.ID] != 1 {
		t.Fatalf("each id must appear exactly once: %v", seen)
	}

	// --- 新增的缺陷规则 ---
	added := entryByID(t, diff, addedRule.ID)
	if added.Change != ChangeRuleAdded {
		t.Fatalf("added rule change = %q, want %q", added.Change, ChangeRuleAdded)
	}
	if added.Before != nil {
		t.Fatalf("absent baseline side must be null, got %+v", added.Before)
	}
	if added.After == nil {
		t.Fatal("added rule must keep its new side")
	}
	assertRuleFields(t, "added after side", added.After.Rule, addedRule, StatusDefect, addedRuleEvidence)
	assertFindingBinding(t, "added after side", added.After.Finding, hash, addedRule, addedRuleEvidence)

	// --- 两侧都在的对照规则：定义一致、通过 -> 发现缺陷 ---
	existing := entryByID(t, diff, existingRule.ID)
	if existing.Change != ChangeNewDefect {
		t.Fatalf("existing rule change = %q, want %q", existing.Change, ChangeNewDefect)
	}
	if existing.Before == nil || existing.After == nil {
		t.Fatal("new-defect rule must carry both sides")
	}
	assertRuleFields(t, "existing before side", existing.Before.Rule, existingRule, StatusPass, "")
	assertRuleFields(t, "existing after side", existing.After.Rule, existingRule, StatusDefect, existingRuleEvidence)
	if existing.Before.Finding != nil {
		t.Errorf("passing baseline side must carry no finding: %+v", existing.Before.Finding)
	}
	assertFindingBinding(t, "existing after side", existing.After.Finding, hash, existingRule, existingRuleEvidence)

	// --- 两条规则引用同一不变式名，也必须各自保留自己的版本、严重级别与
	// 反例，不能按不变式名合并或互换证据 ---
	if added.After.Finding.Evidence == existingRuleEvidence ||
		existing.After.Finding.Evidence == addedRuleEvidence {
		t.Error("each rule must keep its own evidence; findings must not be merged or swapped by invariant name")
	}
	if added.After.Finding.RuleID == existing.After.Finding.RuleID {
		t.Error("findings must stay bound to their own rule ids")
	}
	if added.After.Rule.Version == existing.After.Rule.Version ||
		added.After.Rule.Severity == existing.After.Rule.Severity {
		t.Error("each rule must keep its own version and severity")
	}

	// --- 汇总：新增计入一，新发现缺陷计入一；不能把新增算成新缺陷 ---
	s := diff.Summary
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
	// 两侧缺陷总数只数各自归档中实际存在的缺陷：基准侧 0、新侧 2；新增
	// 规则的真实缺陷仍计入新侧总数，不能为了分类而排除。
	if s.BeforeDefects != 0 || s.AfterDefects != 2 {
		t.Errorf("defect totals = %d/%d, want 0/2 (actual archived findings)", s.BeforeDefects, s.AfterDefects)
	}

	// 比较是只读操作：归档文件集合与内容保持原样。
	filesAfter := storeFileNames(t, dir)
	if strings.Join(filesBefore, ",") != strings.Join(filesAfter, ",") {
		t.Fatalf("store files changed: %v -> %v", filesBefore, filesAfter)
	}
	for _, name := range filesAfter {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != contentsBefore[name] {
			t.Errorf("diff modified archive %s", name)
		}
	}
	// 新侧归档中的证据逐字落盘（JSON 中换行转义为 \n），中文、前后空白
	// 不被修剪。
	afterBytes, err := os.ReadFile(filepath.Join(dir, after.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	wantEscaped := `"evidence":"  新反例：新增规则首次检出\n  reentrancy 路径第二行  "`
	if !strings.Contains(string(afterBytes), wantEscaped) {
		t.Errorf("new report archive must keep the raw evidence verbatim:\n%s", string(afterBytes))
	}
}

// TestDiffAddedDefectRuleAgainstRuleLessBaseline 基准报告没有任何规则时同样
// 是合法输入：新侧这条缺陷规则仍按新增处理，基准侧保持 null 而不是补成
// “通过”，新侧缺陷总数如实计一，不报错也不把缺陷算成已有规则的新发现缺陷。
func TestDiffAddedDefectRuleAgainstRuleLessBaseline(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	addedRule := addedPairRules()[0]

	// 基准报告零规则：合法归档，rules 与 findings 均为空。
	before := saveCheckReport(t, dir, artifact, nil, nil)
	after := saveRuleChangeCheckReport(t, dir, artifact, addedRule, StatusDefect, addedRuleEvidence)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("diff against a rule-less baseline must succeed: %v", err)
	}
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(diff.Results), diff.Results)
	}
	entry := diff.Results[0]
	if entry.RuleID != addedRule.ID || entry.Change != ChangeRuleAdded {
		t.Fatalf("entry = %q/%q, want %q/%q", entry.RuleID, entry.Change, addedRule.ID, ChangeRuleAdded)
	}
	if entry.Before != nil {
		t.Errorf("absent baseline side must be null, not a fabricated pass: %+v", entry.Before)
	}
	assertRuleFields(t, "after side", entry.After.Rule, addedRule, StatusDefect, addedRuleEvidence)
	assertFindingBinding(t, "after side", entry.After.Finding, hash, addedRule, addedRuleEvidence)

	s := diff.Summary
	if s.AddedRules != 1 {
		t.Errorf("addedRules = %d, want 1", s.AddedRules)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 {
		t.Errorf("an added rule must not count as a defect transition: %+v", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}

// TestDiffUncheckedBaselineRuleDefectIsStatusChangeNotAdded 明确“新增”的判
// 定边界：基准报告已经包含该规则、只是状态为“未检查”（没有检查记录也没有不
// 变式值），新报告同一规则（定义完全一致）发现缺陷时，必须按现有规则归为
// “检查状态变化”，不能算新增规则，也不能算新发现缺陷。
func TestDiffUncheckedBaselineRuleDefectIsStatusChangeNotAdded(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rule := addedPairRules()[0]

	// 基准侧：规则在但没有外部检查记录、invariants 中也没有它引用的不变式，
	// 因此状态为“未检查”。
	before := saveMixedCheckReport(t, dir, artifact, []Rule{rule}, nil, nil)
	// 新侧：同一条规则定义完全一致，外部检查器发现缺陷。
	after := saveRuleChangeCheckReport(t, dir, artifact, rule, StatusDefect, addedRuleEvidence)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(diff.Results), diff.Results)
	}
	entry := diff.Results[0]
	if entry.RuleID != rule.ID || entry.Change != ChangeStatusChanged {
		t.Fatalf("entry = %q/%q, want %q/%q (a rule present in the baseline is not an added rule)",
			entry.RuleID, entry.Change, rule.ID, ChangeStatusChanged)
	}
	if entry.Before == nil || entry.After == nil {
		t.Fatal("a rule present in both reports must keep both sides")
	}
	if entry.Before.Rule.Status != StatusUnchecked {
		t.Errorf("before status = %q, want %q", entry.Before.Rule.Status, StatusUnchecked)
	}
	if entry.Before.Finding != nil {
		t.Errorf("unchecked baseline side must carry no finding: %+v", entry.Before.Finding)
	}
	assertRuleFields(t, "after side", entry.After.Rule, rule, StatusDefect, addedRuleEvidence)
	assertFindingBinding(t, "after side", entry.After.Finding, hash, rule, addedRuleEvidence)

	s := diff.Summary
	if s.StatusChanges != 1 {
		t.Errorf("statusChanges = %d, want 1", s.StatusChanges)
	}
	if s.AddedRules != 0 {
		t.Errorf("addedRules = %d, want 0: the rule already existed in the baseline", s.AddedRules)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 {
		t.Errorf("unchecked -> defect is not a defect transition: %+v", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}
