package contractsentinel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件回归保护按规则筛选的比较：--rule 只改变结果视图，不改变分类口径。
// 筛选后的 summary 只统计所选规则，beforeDefects/afterDefects 退化为该规则
// 在对应报告中是否有真实缺陷记录（0 或 1）；整份归档校验不被筛选绕过，
// 找不到规则或规则标识为空都是错误，比较全程只读。

// filterFixture 落盘两份报告：before 中 resolved 有缺陷、stable 通过、
// removed-only 有缺陷；after 中 resolved 变通过、stable 变缺陷、removed-only
// 消失、added-only 新出现且有缺陷。另有多条其他缺陷，用于验证筛选后缺陷
// 总数不再反映整份报告。
func filterFixture(t *testing.T, dir string) (before, after Report) {
	t.Helper()
	artifact := sampleArtifact()
	beforeRules := []Rule{
		{ID: "noise-defect", Kind: "static", Severity: "high", Invariant: "inv-noise", Version: "1"},
		{ID: "removed-only", Kind: "static", Severity: "low", Invariant: "inv-removed", Version: "1"},
		{ID: "resolved", Kind: "static", Severity: "medium", Invariant: "inv-resolved", Version: "1"},
		{ID: "stable", Kind: "static", Severity: "medium", Invariant: "inv-stable", Version: "1"},
	}
	beforeInv := map[string]bool{
		"inv-noise": false, "inv-removed": false, "inv-resolved": false, "inv-stable": true,
	}
	before = saveDiffReport(t, dir, artifact, beforeRules, beforeInv)

	afterRules := []Rule{
		{ID: "added-only", Kind: "static", Severity: "low", Invariant: "inv-added", Version: "1"},
		{ID: "noise-defect", Kind: "static", Severity: "high", Invariant: "inv-noise", Version: "1"},
		{ID: "resolved", Kind: "static", Severity: "medium", Invariant: "inv-resolved", Version: "1"},
		{ID: "stable", Kind: "static", Severity: "medium", Invariant: "inv-stable", Version: "1"},
	}
	afterInv := map[string]bool{
		"inv-added": false, "inv-noise": false, "inv-resolved": true, "inv-stable": false,
	}
	after = saveDiffReport(t, dir, artifact, afterRules, afterInv)
	return before, after
}

// 通过→发现缺陷的规则被筛选时：只计一条新发现缺陷，缺陷数为 0 和 1，
// 其余分类全部为零；顶层引用与产物变化标记与完整比较一致。
func TestDiffRuleFilterNewDefect(t *testing.T) {
	dir := t.TempDir()
	before, after := filterFixture(t, dir)

	full, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "stable")
	if err != nil {
		t.Fatal(err)
	}

	if filtered.Before != full.Before || filtered.After != full.After {
		t.Errorf("top-level refs must match the full diff: %+v / %+v", filtered.Before, filtered.After)
	}
	if filtered.ArtifactNameChanged != full.ArtifactNameChanged ||
		filtered.ArtifactHashChanged != full.ArtifactHashChanged {
		t.Errorf("artifact change flags must match the full diff")
	}
	if len(filtered.Results) != 1 || filtered.Results[0].RuleID != "stable" {
		t.Fatalf("filtered results = %+v", filtered.Results)
	}
	entry := filtered.Results[0]
	if entry.Change != ChangeNewDefect {
		t.Errorf("change = %q, want %q", entry.Change, ChangeNewDefect)
	}
	if entry.Before == nil || entry.After == nil {
		t.Fatalf("both sides must be present: %+v", entry)
	}
	if entry.Before.Finding != nil || entry.After.Finding == nil {
		t.Errorf("findings = %+v / %+v", entry.Before.Finding, entry.After.Finding)
	}
	s := filtered.Summary
	if s.NewDefects != 1 || s.ResolvedDefects != 0 || s.StatusChanges != 0 ||
		s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 ||
		s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("filtered summary = %+v", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}

// 发现缺陷→通过的规则：只计一条已消除缺陷，缺陷数为 1 和 0，证据完整保留。
func TestDiffRuleFilterResolvedDefect(t *testing.T) {
	dir := t.TempDir()
	before, after := filterFixture(t, dir)

	filtered, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "resolved")
	if err != nil {
		t.Fatal(err)
	}
	entry := filtered.Results[0]
	if entry.Change != ChangeResolvedDefect {
		t.Errorf("change = %q, want %q", entry.Change, ChangeResolvedDefect)
	}
	if entry.Before.Finding == nil || entry.After.Finding != nil {
		t.Errorf("findings = %+v / %+v", entry.Before.Finding, entry.After.Finding)
	}
	s := filtered.Summary
	if s.ResolvedDefects != 1 || s.NewDefects != 0 {
		t.Errorf("filtered summary = %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}
}

// 只存在于一侧的规则照常归为新增/移除，缺失一侧为 null，存在一侧保留完整
// 规则与缺陷记录；缺陷数只反映存在的一侧。
func TestDiffRuleFilterAddedAndRemoved(t *testing.T) {
	dir := t.TempDir()
	before, after := filterFixture(t, dir)

	added, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "added-only")
	if err != nil {
		t.Fatal(err)
	}
	if len(added.Results) != 1 || added.Results[0].Change != ChangeRuleAdded {
		t.Fatalf("added entry = %+v", added.Results)
	}
	if added.Results[0].Before != nil || added.Results[0].After == nil {
		t.Errorf("added sides = %+v / %+v", added.Results[0].Before, added.Results[0].After)
	}
	if added.Results[0].After.Finding == nil {
		t.Error("added side must keep its defect finding")
	}
	if added.Summary.AddedRules != 1 || added.Summary.BeforeDefects != 0 || added.Summary.AfterDefects != 1 {
		t.Errorf("added summary = %+v", added.Summary)
	}

	removed, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "removed-only")
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.Results) != 1 || removed.Results[0].Change != ChangeRuleRemoved {
		t.Fatalf("removed entry = %+v", removed.Results)
	}
	if removed.Results[0].Before == nil || removed.Results[0].After != nil {
		t.Errorf("removed sides = %+v / %+v", removed.Results[0].Before, removed.Results[0].After)
	}
	if removed.Results[0].Before.Finding == nil {
		t.Error("removed side must keep its defect finding")
	}
	if removed.Summary.RemovedRules != 1 || removed.Summary.BeforeDefects != 1 || removed.Summary.AfterDefects != 0 {
		t.Errorf("removed summary = %+v", removed.Summary)
	}
}

// 规则定义变化（版本/kind/severity/invariant/ABI 任一）仍归为规则变化。
func TestDiffRuleFilterRuleChanged(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	mk := func(version string) Report {
		rules := []Rule{
			{ID: "evolving", Kind: "static", Severity: "high", Invariant: "inv-evolving", Version: version},
		}
		return saveDiffReport(t, dir, artifact, rules, map[string]bool{"inv-evolving": true})
	}
	before := mk("1")
	after := mk("2")

	filtered, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "evolving")
	if err != nil {
		t.Fatal(err)
	}
	if filtered.Results[0].Change != ChangeRuleChanged {
		t.Errorf("change = %q, want %q", filtered.Results[0].Change, ChangeRuleChanged)
	}
	if filtered.Summary.ChangedRules != 1 {
		t.Errorf("summary = %+v", filtered.Summary)
	}
	if filtered.Summary.BeforeDefects != 0 || filtered.Summary.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 0/0",
			filtered.Summary.BeforeDefects, filtered.Summary.AfterDefects)
	}
}

// 规则标识精确匹配：大小写与前后空格不同的标识视为未找到；两份报告都没
// 有的标识也是错误，错误必须指出该标识。
func TestDiffRuleFilterExactMatchAndNotFound(t *testing.T) {
	dir := t.TempDir()
	before, after := filterFixture(t, dir)

	for _, id := range []string{"Stable", " stable", "stable ", "no-such-rule"} {
		if _, err := DiffStoreRule(dir, before.ReportID, after.ReportID, id); err == nil {
			t.Errorf("rule id %q must not match", id)
		} else if !strings.Contains(err.Error(), id) {
			t.Errorf("error must name the missing rule id %q: %v", id, err)
		}
	}
}

// 空规则标识在读取任何归档之前就是错误。
func TestDiffRuleFilterEmptyIDFails(t *testing.T) {
	dir := t.TempDir()
	before, after := filterFixture(t, dir)
	if _, err := DiffStoreRule(dir, before.ReportID, after.ReportID, ""); err == nil {
		t.Fatal("empty rule id must be an error")
	}
	if _, err := DiffReportsRule(before, after, ""); err == nil {
		t.Fatal("empty rule id must be an error")
	}
}

// 筛选不能绕过整份归档校验：任一报告损坏仍按现有行为失败，即使损坏发生
// 在未选择的规则上；失败的比较不得改动归档。
func TestDiffRuleFilterCorruptArchiveStillFails(t *testing.T) {
	dir := t.TempDir()
	before, after := filterFixture(t, dir)
	badPath := filepath.Join(dir, after.ReportID+".json")
	corrupt := []byte(`{broken`)
	if err := os.WriteFile(badPath, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "stable"); err == nil {
		t.Fatal("corrupted archive must fail even when filtering")
	}
	kept, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != string(corrupt) {
		t.Fatal("failed filtered diff must not repair the corrupted archive")
	}
}

// 筛选比较是只读操作：归档文件集合与内容保持不变。
func TestDiffRuleFilterNeverModifiesStore(t *testing.T) {
	dir := t.TempDir()
	before, after := filterFixture(t, dir)
	namesBefore := storeFileNames(t, dir)
	contents := map[string]string{}
	for _, name := range namesBefore {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		contents[name] = string(data)
	}

	if _, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "stable"); err != nil {
		t.Fatal(err)
	}
	namesAfter := storeFileNames(t, dir)
	if strings.Join(namesBefore, ",") != strings.Join(namesAfter, ",") {
		t.Fatalf("store file set changed: %v vs %v", namesBefore, namesAfter)
	}
	for _, name := range namesAfter {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != contents[name] {
			t.Errorf("archive %s modified by filtered diff", name)
		}
	}
}
