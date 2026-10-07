package contractsentinel

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 本文件围绕比较功能的一项业务回归口径：新报告扩大检查范围、首次引入某条
// 带缺陷结论的规则时，输出必须为该标识保留一个“新增规则”条目——而不是仅凭
// 新侧缺陷总数上升就把这条缺陷记成已有规则的“新发现缺陷”。新增条目只保留新
// 侧，新侧必须仍是归档中的完整规则定义、检查状态（发现缺陷）、原始说明与缺陷
// 记录；缺席的基准侧为 null，不能补造“通过”结论。汇总中新增规则数计入这一条，
// 新发现缺陷数不能因此增加；两侧缺陷总数只数各自归档中实际存在的缺陷，新侧
// 这条真实缺陷仍计入 afterDefects，不能为了分类把它从缺陷总数或证据中排除。
//
// 同一份比较结果中保留一条两侧都存在的规则作为对照：定义完全一致、通过 ->
// 发现缺陷归为“新发现缺陷”。两条规则即使引用同一个不变式名，也按各自规则标
// 识独立呈现，各自保留自己的版本、严重级别与反例，不按不变式名合并或互换证据。
//
// “新增”只依据规则标识是否出现在基准报告中判断：基准报告已有该规则、只是状
// 态为“未检查”，后来发现缺陷时仍按既有规则归为“检查状态变化”，不能算新增规
// 则。基准报告没有任何规则也是合法比较条件：新增缺陷规则仍正常呈现，缺席侧保
// 持 null。
//
// 所有用例都走 BuildReport -> SaveReport -> DiffStore 的正常归档与读回路径，
// 比较的是同一产物（同一名称、同一内容哈希）的两份可正常读取的归档报告，比较
// 全程不改写任何归档。

// addedRuleEvidence 与 keptNewDefectEvidence 刻意包含中文、换行与前后空白，
// 且互不相同：任何修剪、模板替换或按不变式名串证据都会被抓到。
const addedRuleEvidence = "  新反例：新增规则首次覆盖该路径\n  reentrancy 路径第二行  "
const keptNewDefectEvidence = "  既有规则的新反例：复跑发现缺陷\n第二行  "

// addedPairRules 构造同一份产物上的两条规则：added-id 只在新报告中出现，
// kept-id 两侧都在且定义完全一致。两者刻意引用同一个不变式名，回归保障必须按
// 规则标识、而非按不变式名归属证据与结论。
func addedPairRules() []Rule {
	return []Rule{
		{
			ID:        "added-reentrancy",
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

// snapshotStore 记录报告目录当前的文件名与字节内容，用于断言比较是只读操作。
func snapshotStore(t *testing.T, dir string) map[string]string {
	t.Helper()
	contents := map[string]string{}
	for _, name := range storeFileNames(t, dir) {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		contents[name] = string(data)
	}
	return contents
}

// assertStoreUnchanged 断言比较前后报告目录中的文件名与字节内容完全一致。
func assertStoreUnchanged(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	namesAfter := storeFileNames(t, dir)
	namesBefore := make([]string, 0, len(before))
	for name := range before {
		namesBefore = append(namesBefore, name)
	}
	sort.Strings(namesBefore)
	if strings.Join(namesBefore, ",") != strings.Join(namesAfter, ",") {
		t.Fatalf("store files changed: %v -> %v", namesBefore, namesAfter)
	}
	for _, name := range namesAfter {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != before[name] {
			t.Errorf("diff modified archive %s", name)
		}
	}
}

// TestDiffAddedDefectRuleIsAddedNotNewDefect 是核心回归用例：带缺陷的新规则
// 在基准报告规则列表中完全缺席，必须记为“新增规则”而非“新发现缺陷”，基准侧
// 为 null、新侧完整保留；同一份比较中定义一致的对照规则通过 -> 发现缺陷记为
// “新发现缺陷”。新增规则 1、新发现缺陷 1，两侧缺陷总数 0 和 2。
func TestDiffAddedDefectRuleIsAddedNotNewDefect(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := addedPairRules()
	addedRule := rules[0]
	keptRule := rules[1]

	// 基准报告只包含对照规则（定义与新侧完全一致），结论为通过。
	before := saveCheckReport(t, dir, artifact, []Rule{keptRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: keptRule.ID, Version: keptRule.Version, Status: StatusPass},
	})
	// 新报告扩大检查范围：新增规则首次出现即发现缺陷，对照规则由通过变为发现
	// 缺陷。规则与检查记录的提交顺序刻意与标识排序不同，归属不得受排列影响。
	after := saveCheckReport(t, dir, artifact, []Rule{keptRule, addedRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: addedRule.ID, Version: addedRule.Version, Status: StatusDefect, Note: addedRuleEvidence},
		{ArtifactHash: hash, RuleID: keptRule.ID, Version: keptRule.Version, Status: StatusDefect, Note: keptNewDefectEvidence},
	})

	// 检查范围不同，两份报告必然具有不同的报告标识。
	if before.ReportID == after.ReportID {
		t.Fatal("reports with different rule sets must have different report ids")
	}

	// 两份归档必须能独立读回：基准侧无缺陷，新侧两条真实缺陷。
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

	// 比较前留存归档快照：比较全程不得改动任何已保存报告。
	snapshot := snapshotStore(t, dir)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("diff must succeed when a defect rule first appears in the new report: %v", err)
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
	seen := map[string]int{}
	for _, r := range diff.Results {
		ids = append(ids, r.RuleID)
		seen[r.RuleID]++
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}
	if seen[addedRule.ID] != 1 || seen[keptRule.ID] != 1 {
		t.Fatalf("each id must appear exactly once: %v", seen)
	}

	// --- 仅在新侧出现的缺陷规则：新增规则，基准侧为 null ---
	added := entryByID(t, diff, addedRule.ID)
	if added.Change != ChangeRuleAdded {
		t.Fatalf("added rule change = %q, want %q (a widened check scope is not a new defect of an existing rule)",
			added.Change, ChangeRuleAdded)
	}
	if added.Before != nil {
		t.Fatalf("absent baseline side must be null, got %+v", added.Before)
	}
	if added.After == nil {
		t.Fatal("added rule must keep its new side")
	}
	assertRuleFields(t, "added after side", added.After.Rule, addedRule, StatusDefect, addedRuleEvidence)
	assertFindingBinding(t, "added after side", added.After.Finding, hash, addedRule, addedRuleEvidence)

	// --- 两侧都在、定义一致的对照规则：通过 -> 发现缺陷 = 新发现缺陷 ---
	kept := entryByID(t, diff, keptRule.ID)
	if kept.Change != ChangeNewDefect {
		t.Fatalf("kept rule change = %q, want %q", kept.Change, ChangeNewDefect)
	}
	if kept.Before == nil || kept.After == nil {
		t.Fatal("new-defect rule must carry both sides")
	}
	assertRuleFields(t, "kept before side", kept.Before.Rule, keptRule, StatusPass, "")
	assertRuleFields(t, "kept after side", kept.After.Rule, keptRule, StatusDefect, keptNewDefectEvidence)
	if kept.Before.Finding != nil {
		t.Errorf("passing baseline side must carry no finding: %+v", kept.Before.Finding)
	}
	assertFindingBinding(t, "kept after side", kept.After.Finding, hash, keptRule, keptNewDefectEvidence)

	// --- 两条规则引用同一个不变式名，也各自保留自己的版本、严重级别与反例 ---
	if added.After.Finding != nil && kept.After.Finding != nil {
		if added.After.Finding.Evidence == kept.After.Finding.Evidence {
			t.Error("each rule must keep its own evidence; findings must not merge by invariant name")
		}
		if added.After.Finding.RuleID == kept.After.Finding.RuleID {
			t.Error("findings must stay bound to their own rule ids")
		}
	}
	if added.After.Rule.Version == kept.After.Rule.Version ||
		added.After.Rule.Severity == kept.After.Rule.Severity {
		t.Error("rules sharing an invariant name must keep their own version and severity")
	}

	// --- 汇总：新增计入一、新发现缺陷计入一；新增规则的缺陷不能计入新发现缺陷 ---
	s := diff.Summary
	if s.AddedRules != 1 {
		t.Errorf("addedRules = %d, want 1", s.AddedRules)
	}
	if s.NewDefects != 1 {
		t.Errorf("newDefects = %d, want 1 (only the pre-existing rule's pass->defect transition)", s.NewDefects)
	}
	if s.ResolvedDefects != 0 || s.StatusChanges != 0 || s.NoteChanges != 0 ||
		s.NoChange != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other count must be zero: %+v", s)
	}
	// 两侧缺陷总数只数各自归档中实际存在的缺陷：基准侧 0、新侧 2——新增规则
	// 的真实缺陷仍计入 afterDefects，不能为了分类把它排除。
	if s.BeforeDefects != 0 || s.AfterDefects != 2 {
		t.Errorf("defect totals = %d/%d, want 0/2 (the added rule's real defect still counts)",
			s.BeforeDefects, s.AfterDefects)
	}

	// 比较是只读操作：两份归档内容与标识保持原样。
	assertStoreUnchanged(t, dir, snapshot)

	// 归档字节层面：新证据中的中文、换行（JSON 中转义为 \n）和前后空白必须
	// 原样落盘，不能被修剪或替换。
	afterBytes, err := os.ReadFile(filepath.Join(dir, after.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	wantEscaped := `"evidence":"  新反例：新增规则首次覆盖该路径\n  reentrancy 路径第二行  "`
	if !strings.Contains(string(afterBytes), wantEscaped) {
		t.Errorf("new report archive must keep the raw evidence verbatim:\n%s", string(afterBytes))
	}
}

// TestDiffUncheckedBaselineRuleLaterDefectIsStatusChange 明确“新增”的判定依
// 据：基准报告已经包含该规则、只是当时没有任何检查结论（未检查），新报告对同
// 一定义的规则得出发现缺陷时，必须归为“检查状态变化”，不能算“新增规则”，也
// 不能算“新发现缺陷”（后者只覆盖通过 -> 发现缺陷）。
func TestDiffUncheckedBaselineRuleLaterDefectIsStatusChange(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rule := addedPairRules()[0]

	// 基准报告已有这条规则，但既没有外部检查记录、也没有不变式布尔值：
	// 状态为“未检查”。
	before := saveCheckReport(t, dir, artifact, []Rule{rule}, nil)
	// 新报告对同一条定义完全一致的规则给出发现缺陷结论。
	after := saveCheckReport(t, dir, artifact, []Rule{rule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version, Status: StatusDefect, Note: addedRuleEvidence},
	})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("diff must succeed for an unchecked rule later found defective: %v", err)
	}
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(diff.Results), diff.Results)
	}
	entry := diff.Results[0]
	if entry.RuleID != rule.ID {
		t.Fatalf("rule id = %q, want %q", entry.RuleID, rule.ID)
	}
	if entry.Change != ChangeStatusChanged {
		t.Fatalf("change = %q, want %q (the rule already existed in the baseline, only unchecked)",
			entry.Change, ChangeStatusChanged)
	}

	// 规则两侧都在：基准侧是完整的未检查规则（不是 null），新侧保留缺陷结论。
	if entry.Before == nil || entry.After == nil {
		t.Fatal("a rule present in both reports must keep both sides")
	}
	assertRuleFields(t, "before side", entry.Before.Rule, rule, StatusUnchecked, "")
	if entry.Before.Finding != nil {
		t.Errorf("unchecked baseline side must carry no finding: %+v", entry.Before.Finding)
	}
	assertRuleFields(t, "after side", entry.After.Rule, rule, StatusDefect, addedRuleEvidence)
	assertFindingBinding(t, "after side", entry.After.Finding, hash, rule, addedRuleEvidence)

	// 汇总：检查状态变化一条；新增规则与新发现缺陷都不能因此增加。
	s := diff.Summary
	if s.StatusChanges != 1 {
		t.Errorf("statusChanges = %d, want 1", s.StatusChanges)
	}
	if s.AddedRules != 0 {
		t.Errorf("addedRules = %d, want 0: a rule already in the baseline is not an added rule", s.AddedRules)
	}
	if s.NewDefects != 0 {
		t.Errorf("newDefects = %d, want 0: 未检查 -> 发现缺陷 is not a pass->defect transition", s.NewDefects)
	}
	if s.ResolvedDefects != 0 || s.NoteChanges != 0 || s.NoChange != 0 ||
		s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other count must be zero: %+v", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}

// TestDiffAddedDefectRuleAgainstRuleLessBaseline 基准报告没有任何规则时同样
// 是合法输入：新侧的缺陷规则仍按“新增规则”正常呈现，基准侧保持 null，不能补
// 成“通过”；新侧缺陷总数照常计入这条真实缺陷。
func TestDiffAddedDefectRuleAgainstRuleLessBaseline(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	addedRule := addedPairRules()[0]

	// 基准报告零规则：合法归档，rules 与 findings 均为空。
	before := saveCheckReport(t, dir, artifact, nil, nil)
	after := saveCheckReport(t, dir, artifact, []Rule{addedRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: addedRule.ID, Version: addedRule.Version, Status: StatusDefect, Note: addedRuleEvidence},
	})

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
		t.Errorf("absent baseline side must be null, not a fabricated 通过: %+v", entry.Before)
	}
	if entry.After == nil {
		t.Fatal("added rule must keep its new side")
	}
	assertRuleFields(t, "after side", entry.After.Rule, addedRule, StatusDefect, addedRuleEvidence)
	assertFindingBinding(t, "after side", entry.After.Finding, hash, addedRule, addedRuleEvidence)

	s := diff.Summary
	if s.AddedRules != 1 {
		t.Errorf("addedRules = %d, want 1", s.AddedRules)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("an added rule is not a defect transition: %+v", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}

// TestDiffAddedAndNewDefectIndependentOfArchiveOrder 归档中的排列顺序不影响
// 归属：无论新报告把两条规则与检查记录按什么顺序落盘，新增规则与新发现缺陷
// 都按标识独立分类，结果仍按规则标识排序。
func TestDiffAddedAndNewDefectIndependentOfArchiveOrder(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := addedPairRules()
	addedRule, keptRule := rules[0], rules[1]

	before := saveCheckReport(t, dir, artifact, []Rule{keptRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: keptRule.ID, Version: keptRule.Version, Status: StatusPass},
	})
	// 新报告刻意把新增规则排在后面、检查记录顺序与规则顺序相反。
	after := saveCheckReport(t, dir, artifact, []Rule{keptRule, addedRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: addedRule.ID, Version: addedRule.Version, Status: StatusDefect, Note: addedRuleEvidence},
		{ArtifactHash: hash, RuleID: keptRule.ID, Version: keptRule.Version, Status: StatusDefect, Note: keptNewDefectEvidence},
	})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]RuleDiff{}
	ids := []string{}
	for _, r := range diff.Results {
		byID[r.RuleID] = r
		ids = append(ids, r.RuleID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}
	if byID[addedRule.ID].Change != ChangeRuleAdded {
		t.Errorf("added = %q, want %q", byID[addedRule.ID].Change, ChangeRuleAdded)
	}
	if byID[keptRule.ID].Change != ChangeNewDefect {
		t.Errorf("kept = %q, want %q", byID[keptRule.ID].Change, ChangeNewDefect)
	}
	if s := diff.Summary; s.AddedRules != 1 || s.NewDefects != 1 ||
		s.BeforeDefects != 0 || s.AfterDefects != 2 {
		t.Errorf("summary = %+v, want added=1 newDefects=1 defects=0/2", s)
	}
}
