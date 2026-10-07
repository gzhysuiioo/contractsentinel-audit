package contractsentinel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 本文件围绕比较功能的按规则筛选口径：调用比较时额外给出一个规则标识，
// 输出沿用完整比较的同一结构——顶层仍是实际比较的两份报告标识、产物名称
// 与哈希及产物变化标记，results 只保留所选标识的一个条目，分类沿用既有
// 八类规则。筛选后的 summary 只统计这一个条目，其余分类为零；
// beforeDefects/afterDefects 各为零或一，只表示这条规则在对应报告中是否
// 有真实缺陷记录，报告里其他规则的缺陷一律不计入。
//
// 规则标识按完整文字精确匹配：大小写与前后空格都是标识的一部分。规则只
// 存在于一侧时照常返回“新增规则”/“移除规则”，缺席一侧为 null，存在的
// 一侧保留完整规则、状态、原始说明及缺陷记录的产物哈希、版本与逐字证据。
// 明确给出空字符串，或两份报告都没有该标识，是参数错误：返回错误、没有
// 比较结果。筛选不绕过整份归档校验：任一报告缺失、损坏或绑定不合法，即
// 使问题出在未选择的规则上，仍按既有失败行为结束。比较全程只读。

// filteredEvidence 刻意包含中文、换行与前后空白，筛选输出必须逐字保留。
const filteredEvidence = "  筛选反例：所选规则重入可达\n第二行证据  "

// filteredOtherEvidence 是同一份报告里另一条规则的缺陷证据，用于证明
// summary 的缺陷计数不会被未选择规则的缺陷污染。
const filteredOtherEvidence = "  其他规则缺陷，不得计入筛选汇总\n第二行  "

// filteredCheckReport 通过检查记录路径归档一份报告。
func filteredCheckReport(t *testing.T, dir string, artifact Artifact, rules []Rule, checks []CheckRecord) Report {
	t.Helper()
	return saveCheckReport(t, dir, artifact, rules, checks)
}

// TestDiffStoreRuleNewDefectScopedToOneRule 是核心口径：所选规则定义一致、
// 通过 -> 发现缺陷，即使两份报告里另一条规则始终带着真实缺陷，筛选结果
// 也只计一条“新发现缺陷”，两侧缺陷数为零和一。
func TestDiffStoreRuleNewDefectScopedToOneRule(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := []Rule{
		{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv-selected", Version: "1"},
		{ID: "other", Kind: "static", Severity: "medium", Invariant: "inv-other", Version: "1"},
	}
	// 基准侧：selected 通过，other 真实缺陷（共 1 个缺陷）。
	before := filteredCheckReport(t, dir, artifact, rules, []CheckRecord{
		{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: StatusPass},
		{ArtifactHash: hash, RuleID: "other", Version: "1", Status: StatusDefect, Note: filteredOtherEvidence},
	})
	// 新侧：selected 发现缺陷，other 仍是缺陷（共 2 个缺陷）。
	after := filteredCheckReport(t, dir, artifact, rules, []CheckRecord{
		{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: StatusDefect, Note: filteredEvidence},
		{ArtifactHash: hash, RuleID: "other", Version: "1", Status: StatusDefect, Note: filteredOtherEvidence},
	})

	full, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	diff, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "selected")
	if err != nil {
		t.Fatalf("rule filter must succeed: %v", err)
	}

	// 顶层报告标识、产物与变化标记与完整比较完全一致。
	if diff.Before != full.Before || diff.After != full.After {
		t.Errorf("report refs must match the full diff: %+v / %+v", diff.Before, diff.After)
	}
	if diff.ArtifactNameChanged != full.ArtifactNameChanged || diff.ArtifactHashChanged != full.ArtifactHashChanged {
		t.Errorf("artifact flags must match the full diff: %v/%v", diff.ArtifactNameChanged, diff.ArtifactHashChanged)
	}

	// results 只有所选规则一个条目，且与完整比较中的同一条目逐字段相同。
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(diff.Results), diff.Results)
	}
	entry := diff.Results[0]
	if entry.RuleID != "selected" {
		t.Fatalf("entry ruleId = %q, want selected", entry.RuleID)
	}
	var fullEntry RuleDiff
	for _, r := range full.Results {
		if r.RuleID == "selected" {
			fullEntry = r
		}
	}
	if !reflect.DeepEqual(entry, fullEntry) {
		t.Fatalf("filtered entry must equal the full-diff entry:\nfiltered=%+v\nfull=%+v", entry, fullEntry)
	}
	if entry.Change != ChangeNewDefect {
		t.Fatalf("change = %q, want %q", entry.Change, ChangeNewDefect)
	}
	if entry.Before == nil || entry.After == nil {
		t.Fatal("a rule present in both reports must keep both sides")
	}
	if entry.Before.Rule.Status != StatusPass || entry.Before.Finding != nil {
		t.Errorf("passing before side = %+v", entry.Before)
	}
	if entry.After.Rule.Status != StatusDefect || entry.After.Finding == nil {
		t.Fatalf("defect after side must carry its finding: %+v", entry.After)
	}
	f := entry.After.Finding
	if f.ArtifactHash != hash || f.RuleID != "selected" || f.Version != "1" || f.Evidence != filteredEvidence {
		t.Errorf("finding binding = %+v, want hash=%q version=1 verbatim evidence", f, hash)
	}

	// summary 只统计所选条目：新缺陷一条，其余分类全零；缺陷数为零和一，
	// 不受 other 在两侧各自的真实缺陷影响。
	s := diff.Summary
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

	// 原始输出字节层面：证据中的中文、换行（JSON 转义为 \n）与前后空格
	// 逐字保留，且输出不携带未选择规则的证据。
	out, err := json.MarshalIndent(diff, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "  筛选反例：所选规则重入可达\\n第二行证据  ") {
		t.Errorf("filtered diff must preserve the selected evidence verbatim:\n%s", out)
	}
	if strings.Contains(string(out), filteredOtherEvidence) {
		t.Errorf("filtered diff must not carry the unselected rule's evidence:\n%s", out)
	}
}

// TestDiffStoreRuleExactTextMatching 规则标识按完整文字精确匹配：大小写与
// 前后空格都保留；带空格的标识只能用同样带空格的完整文字选中，任何修剪、
// 大小写折叠或子串匹配都算未找到。
func TestDiffStoreRuleExactTextMatching(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	padded := Rule{ID: " Rule ", Kind: "static", Severity: "low", Invariant: "inv-padded", Version: "1"}
	cased := Rule{ID: "R-One", Kind: "static", Severity: "low", Invariant: "inv-cased", Version: "1"}
	before := filteredCheckReport(t, dir, artifact, []Rule{padded, cased}, []CheckRecord{
		{ArtifactHash: hash, RuleID: padded.ID, Version: "1", Status: StatusPass},
		{ArtifactHash: hash, RuleID: cased.ID, Version: "1", Status: StatusPass},
	})
	after := filteredCheckReport(t, dir, artifact, []Rule{padded, cased}, []CheckRecord{
		{ArtifactHash: hash, RuleID: padded.ID, Version: "1", Status: StatusPass},
		{ArtifactHash: hash, RuleID: cased.ID, Version: "1", Status: StatusPass},
	})

	// 完整文字（含前后空格、原大小写）可以精确选中。
	diff, err := DiffStoreRule(dir, before.ReportID, after.ReportID, " Rule ")
	if err != nil {
		t.Fatalf("exact padded id must match: %v", err)
	}
	if len(diff.Results) != 1 || diff.Results[0].RuleID != " Rule " || diff.Results[0].Change != ChangeNoChange {
		t.Fatalf("filtered result = %+v", diff.Results)
	}
	if diff.Summary.NoChange != 1 {
		t.Errorf("summary = %+v, want noChange=1", diff.Summary)
	}

	// 修剪、大小写折叠、子串都不得匹配，错误需指出未找到的是哪个标识。
	for _, bad := range []string{"Rule", "rule", " Rule", "Rule ", "  Rule  ", "R-ONE", "r-one", "R-On", " R-One "} {
		_, err := DiffStoreRule(dir, before.ReportID, after.ReportID, bad)
		if err == nil {
			t.Errorf("filter %q must not match %q / %q", bad, padded.ID, cased.ID)
			continue
		}
		if !strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), bad) {
			t.Errorf("error must name the missing rule %q: %v", bad, err)
		}
	}

	// 明确的空字符串是参数错误，错误说明为空，而不是含糊的未找到。
	_, err = DiffStoreRule(dir, before.ReportID, after.ReportID, "")
	if err == nil {
		t.Fatal("empty rule filter must fail")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty-filter error must say the filter is empty: %v", err)
	}
}

// TestDiffStoreRuleAddedAndRemovedSides 规则只存在于一侧：新增/移除分类
// 沿用既有口径，缺席一侧为 null，存在的一侧保留完整规则、状态与缺陷记录。
func TestDiffStoreRuleAddedAndRemovedSides(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rule := Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}

	// 基准侧没有 selected；新侧首次出现即发现缺陷。
	before := filteredCheckReport(t, dir, artifact, nil, nil)
	after := filteredCheckReport(t, dir, artifact, []Rule{rule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: StatusDefect, Note: filteredEvidence},
	})

	added, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "selected")
	if err != nil {
		t.Fatal(err)
	}
	if len(added.Results) != 1 {
		t.Fatalf("results = %+v", added.Results)
	}
	a := added.Results[0]
	if a.Change != ChangeRuleAdded || a.RuleID != "selected" {
		t.Fatalf("entry = %q/%q, want %q", a.RuleID, a.Change, ChangeRuleAdded)
	}
	if a.Before != nil {
		t.Errorf("absent before side must be null: %+v", a.Before)
	}
	if a.After == nil || a.After.Rule.Status != StatusDefect || a.After.Finding == nil {
		t.Fatalf("added side must keep rule and finding: %+v", a.After)
	}
	if a.After.Finding.ArtifactHash != hash || a.After.Finding.Version != "1" ||
		a.After.Finding.Evidence != filteredEvidence {
		t.Errorf("added finding = %+v", a.After.Finding)
	}
	if added.Summary.AddedRules != 1 || added.Summary.NewDefects != 0 {
		t.Errorf("summary = %+v, want added=1 newDefects=0", added.Summary)
	}
	if added.Summary.BeforeDefects != 0 || added.Summary.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", added.Summary.BeforeDefects, added.Summary.AfterDefects)
	}

	// 交换基准/新报告：同一条规则变为“移除规则”，新侧（参数意义上的
	// after）为 null，缺陷数方向随之反转。
	removed, err := DiffStoreRule(dir, after.ReportID, before.ReportID, "selected")
	if err != nil {
		t.Fatal(err)
	}
	r := removed.Results[0]
	if r.Change != ChangeRuleRemoved || r.After != nil {
		t.Fatalf("removed entry = %q/%q after=%+v, want %q with null after", r.RuleID, r.Change, r.After, ChangeRuleRemoved)
	}
	if r.Before == nil || r.Before.Finding == nil || r.Before.Finding.Evidence != filteredEvidence {
		t.Errorf("removed side must keep its finding: %+v", r.Before)
	}
	if removed.Summary.RemovedRules != 1 || removed.Summary.AddedRules != 0 {
		t.Errorf("summary = %+v, want removed=1", removed.Summary)
	}
	if removed.Summary.BeforeDefects != 1 || removed.Summary.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", removed.Summary.BeforeDefects, removed.Summary.AfterDefects)
	}
}

// TestDiffStoreRuleDefinitionChangeWins 所选规则的版本、检查种类、严重级
// 别、不变式或 ABI 要求任一变化，即使状态通过 -> 发现缺陷也归为“规则变
// 化”，不能借筛选后的单条结果推断新缺陷；两侧缺陷数仍按真实 finding 计。
func TestDiffStoreRuleDefinitionChangeWins(t *testing.T) {
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)

	cases := []struct {
		name   string
		before Rule
		after  Rule
	}{
		{"version",
			Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"},
			Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "2"}},
		{"kind",
			Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"},
			Rule{ID: "selected", Kind: "symbolic", Severity: "high", Invariant: "inv", Version: "1"}},
		{"severity",
			Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"},
			Rule{ID: "selected", Kind: "static", Severity: "critical", Invariant: "inv", Version: "1"}},
		{"invariant",
			Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"},
			Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv2", Version: "1"}},
		{"requiresABI",
			Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", RequiresABI: false, Version: "1"},
			Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", RequiresABI: true, Version: "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub := t.TempDir()
			before := filteredCheckReport(t, sub, artifact, []Rule{tc.before}, []CheckRecord{
				{ArtifactHash: hash, RuleID: "selected", Version: tc.before.Version, Status: StatusPass},
			})
			after := filteredCheckReport(t, sub, artifact, []Rule{tc.after}, []CheckRecord{
				{ArtifactHash: hash, RuleID: "selected", Version: tc.after.Version, Status: StatusDefect, Note: filteredEvidence},
			})
			diff, err := DiffStoreRule(sub, before.ReportID, after.ReportID, "selected")
			if err != nil {
				t.Fatal(err)
			}
			if len(diff.Results) != 1 || diff.Results[0].Change != ChangeRuleChanged {
				t.Fatalf("results = %+v, want 规则变化", diff.Results)
			}
			s := diff.Summary
			if s.ChangedRules != 1 || s.NewDefects != 0 {
				t.Errorf("summary = %+v, want changed=1 newDefects=0", s)
			}
			// 新侧确有真实缺陷记录，afterDefects 仍如实为一。
			if s.BeforeDefects != 0 || s.AfterDefects != 1 {
				t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
			}
		})
	}
}

// TestDiffStoreRuleChangedDefinitionWithDefectOnBaseline 定义变化且基准侧
// 带缺陷、新侧通过：归为“规则变化”而不是“已消除缺陷”，基准缺陷数仍为一。
func TestDiffStoreRuleChangedDefinitionWithDefectOnBaseline(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	before := filteredCheckReport(t, dir, artifact,
		[]Rule{{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}},
		[]CheckRecord{{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: StatusDefect, Note: filteredEvidence}})
	after := filteredCheckReport(t, dir, artifact,
		[]Rule{{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "2"}},
		[]CheckRecord{{ArtifactHash: hash, RuleID: "selected", Version: "2", Status: StatusPass}})

	diff, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "selected")
	if err != nil {
		t.Fatal(err)
	}
	if diff.Results[0].Change != ChangeRuleChanged {
		t.Fatalf("change = %q, want %q", diff.Results[0].Change, ChangeRuleChanged)
	}
	s := diff.Summary
	if s.ChangedRules != 1 || s.ResolvedDefects != 0 || s.NewDefects != 0 {
		t.Errorf("summary = %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}
}

// TestDiffStoreRuleNonPassTransitionsAreStatusChanges 工具缺失、超时、未检
// 查相关的状态迁移一律仍是“检查状态变化”，筛选不能把它们推断成新增或消除
// 缺陷；两侧缺陷数只认真实 finding。
func TestDiffStoreRuleNonPassTransitionsAreStatusChanges(t *testing.T) {
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rule := Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}

	type transition struct {
		name        string
		before      string
		beforeNote  string
		after       string
		afterNote   string
		wantBeforeD int
		wantAfterD  int
	}
	cases := []transition{
		{"tool-missing to pass", StatusToolMissing, "符号执行引擎未安装", StatusPass, "", 0, 0},
		{"timeout to pass", StatusTimeout, "超过 60s 截止时间", StatusPass, "", 0, 0},
		{"unchecked to pass", StatusUnchecked, "", StatusPass, "", 0, 0},
		{"unchecked to defect", StatusUnchecked, "", StatusDefect, filteredEvidence, 0, 1},
		{"timeout to defect", StatusTimeout, "超过 60s 截止时间", StatusDefect, filteredEvidence, 0, 1},
		{"defect to timeout", StatusDefect, filteredEvidence, StatusTimeout, "复跑超过 60s 截止时间", 1, 0},
		{"tool-missing to timeout", StatusToolMissing, "符号执行引擎未安装", StatusTimeout, "超过 60s 截止时间", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub := t.TempDir()
			var beforeChecks, afterChecks []CheckRecord
			if tc.before != StatusUnchecked {
				beforeChecks = []CheckRecord{{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: tc.before, Note: tc.beforeNote}}
			}
			if tc.after != StatusUnchecked {
				afterChecks = []CheckRecord{{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: tc.after, Note: tc.afterNote}}
			}
			before := filteredCheckReport(t, sub, artifact, []Rule{rule}, beforeChecks)
			after := filteredCheckReport(t, sub, artifact, []Rule{rule}, afterChecks)

			diff, err := DiffStoreRule(sub, before.ReportID, after.ReportID, "selected")
			if err != nil {
				t.Fatal(err)
			}
			if len(diff.Results) != 1 || diff.Results[0].Change != ChangeStatusChanged {
				t.Fatalf("change = %+v, want %q", diff.Results, ChangeStatusChanged)
			}
			s := diff.Summary
			if s.StatusChanges != 1 || s.NewDefects != 0 || s.ResolvedDefects != 0 {
				t.Errorf("summary = %+v, want only statusChanges=1", s)
			}
			if s.BeforeDefects != tc.wantBeforeD || s.AfterDefects != tc.wantAfterD {
				t.Errorf("defect totals = %d/%d, want %d/%d",
					s.BeforeDefects, s.AfterDefects, tc.wantBeforeD, tc.wantAfterD)
			}
		})
	}
}

// TestDiffStoreRuleResolvedNoteAndNoChange 覆盖其余三种定义一致时的分类在
// 筛选口径下的计数：已消除缺陷、说明变化、无变化（两侧都是真实缺陷时
// 缺陷数各为一）。
func TestDiffStoreRuleResolvedNoteAndNoChange(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rule := Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}
	build := func(status, note string) Report {
		var checks []CheckRecord
		if status != StatusUnchecked {
			checks = []CheckRecord{{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: status, Note: note}}
		}
		return filteredCheckReport(t, dir, artifact, []Rule{rule}, checks)
	}

	// 发现缺陷 -> 通过：已消除缺陷，缺陷数 1/0。
	resolvedBefore := build(StatusDefect, filteredEvidence)
	resolvedAfter := build(StatusPass, "")
	d, err := DiffStoreRule(dir, resolvedBefore.ReportID, resolvedAfter.ReportID, "selected")
	if err != nil {
		t.Fatal(err)
	}
	if d.Results[0].Change != ChangeResolvedDefect || d.Summary.ResolvedDefects != 1 ||
		d.Summary.BeforeDefects != 1 || d.Summary.AfterDefects != 0 {
		t.Errorf("resolved case = %+v / %+v", d.Results[0], d.Summary)
	}

	// 通过且仅说明变化：说明变化，缺陷数 0/0。
	noteBefore := build(StatusPass, "旧说明")
	noteAfter := build(StatusPass, "新说明")
	d, err = DiffStoreRule(dir, noteBefore.ReportID, noteAfter.ReportID, "selected")
	if err != nil {
		t.Fatal(err)
	}
	if d.Results[0].Change != ChangeNoteChanged || d.Summary.NoteChanges != 1 ||
		d.Summary.BeforeDefects != 0 || d.Summary.AfterDefects != 0 {
		t.Errorf("note case = %+v / %+v", d.Results[0], d.Summary)
	}

	// 两侧都是同一缺陷结论与证据：无变化，但两侧缺陷数各为一。
	stableBefore := build(StatusDefect, filteredEvidence)
	stableAfter := build(StatusDefect, filteredEvidence)
	d, err = DiffStoreRule(dir, stableBefore.ReportID, stableAfter.ReportID, "selected")
	if err != nil {
		t.Fatal(err)
	}
	if d.Results[0].Change != ChangeNoChange || d.Summary.NoChange != 1 {
		t.Errorf("stable case = %+v / %+v", d.Results[0], d.Summary)
	}
	if d.Summary.BeforeDefects != 1 || d.Summary.AfterDefects != 1 {
		t.Errorf("stable defect totals = %d/%d, want 1/1", d.Summary.BeforeDefects, d.Summary.AfterDefects)
	}
}

// TestDiffStoreRuleRuleInNeitherReport 两份报告都没有该标识：参数错误，
// 错误指出未找到哪个规则，且不返回任何结果；即使另一个标识存在于单侧也
// 一样。
func TestDiffStoreRuleRuleInNeitherReport(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	before := filteredCheckReport(t, dir, artifact,
		[]Rule{{ID: "only-before", Kind: "static", Severity: "low", Invariant: "i1", Version: "1"}},
		[]CheckRecord{{ArtifactHash: hash, RuleID: "only-before", Version: "1", Status: StatusPass}})
	after := filteredCheckReport(t, dir, artifact,
		[]Rule{{ID: "only-after", Kind: "static", Severity: "low", Invariant: "i2", Version: "1"}},
		[]CheckRecord{{ArtifactHash: hash, RuleID: "only-after", Version: "1", Status: StatusPass}})

	_, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "missing-rule")
	if err == nil {
		t.Fatal("a rule in neither report must fail")
	}
	if !strings.Contains(err.Error(), "missing-rule") || !strings.Contains(err.Error(), "not found") {
		t.Errorf("error must name the rule that was not found: %v", err)
	}
}

// TestDiffStoreRuleVerificationIsNeverBypassed 筛选不绕过整份归档校验：
// 任一报告缺失、损坏或绑定不合法都按既有行为失败——即使问题出在未选择
// 的规则上，即使所选规则只存在于另一份完好的报告中。
func TestDiffStoreRuleVerificationIsNeverBypassed(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	good := filteredCheckReport(t, dir, artifact,
		[]Rule{{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}},
		[]CheckRecord{{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: StatusPass}})

	t.Run("corruption on an unselected rule in the second report", func(t *testing.T) {
		// selected 完好，另一条规则状态非法；整份归档损坏，必须失败。
		bad := saveRawReport(t, dir, Report{
			Artifact: ReportArtifact{Name: artifact.Name, Hash: hash},
			Rules: []ReportRule{
				{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusPass},
				{ID: "other", Kind: "static", Severity: "low", Invariant: "inv2", Version: "1", Status: "跳过"},
			},
			Findings: []ReportFinding{},
		})
		if _, err := DiffStoreRule(dir, good.ReportID, bad.ReportID, "selected"); err == nil {
			t.Fatal("corruption on an unselected rule must still fail")
		} else if !strings.Contains(err.Error(), "unknown status") {
			t.Errorf("error must describe the archive corruption: %v", err)
		}
	})

	t.Run("corrupt first report while the rule exists only in the second", func(t *testing.T) {
		bad := saveRawReport(t, dir, Report{
			Artifact: ReportArtifact{Name: artifact.Name, Hash: hash},
			Rules: []ReportRule{
				{ID: "unrelated", Kind: "static", Severity: "low", Invariant: "i", Version: "1", Status: "跳过"},
			},
			Findings: []ReportFinding{},
		})
		if _, err := DiffStoreRule(dir, bad.ReportID, good.ReportID, "selected"); err == nil {
			t.Fatal("the first report is fully verified before the filter is applied")
		}
	})

	t.Run("missing report", func(t *testing.T) {
		missing := strings.Repeat("0", 64)
		if _, err := DiffStoreRule(dir, missing, good.ReportID, "selected"); err == nil {
			t.Fatal("missing before report must fail")
		} else if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error must report the missing report: %v", err)
		}
		if _, err := DiffStoreRule(dir, good.ReportID, missing, "selected"); err == nil {
			t.Fatal("missing after report must fail")
		}
	})

	t.Run("invalid report id", func(t *testing.T) {
		if _, err := DiffStoreRule(dir, "xyz", good.ReportID, "selected"); err == nil {
			t.Fatal("invalid before id must fail")
		}
	})

	t.Run("missing store is not created", func(t *testing.T) {
		missingStore := filepath.Join(t.TempDir(), "never-created")
		id := strings.Repeat("a", 64)
		if _, err := DiffStoreRule(missingStore, id, id, "selected"); err == nil {
			t.Fatal("diff against a missing store must fail")
		}
		if _, err := os.Stat(missingStore); !os.IsNotExist(err) {
			t.Errorf("filtered diff must not create the store: %v", err)
		}
	})
}

// TestDiffStoreRuleIsReadOnlyAndDeterministic 筛选比较全程只读，且同一对
// 报告、同一筛选重复执行结果逐字节一致。
func TestDiffStoreRuleIsReadOnlyAndDeterministic(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rule := Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}
	before := filteredCheckReport(t, dir, artifact, []Rule{rule},
		[]CheckRecord{{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: StatusPass}})
	after := filteredCheckReport(t, dir, artifact, []Rule{rule},
		[]CheckRecord{{ArtifactHash: hash, RuleID: "selected", Version: "1", Status: StatusDefect, Note: filteredEvidence}})

	names := storeFileNames(t, dir)
	contents := map[string]string{}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		contents[name] = string(data)
	}

	first, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "selected")
	if err != nil {
		t.Fatal(err)
	}
	second, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "selected")
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(first)
	b2, _ := json.Marshal(second)
	if string(b1) != string(b2) {
		t.Fatal("repeated filtered diffs must be byte-identical")
	}

	gotNames := storeFileNames(t, dir)
	if strings.Join(names, ",") != strings.Join(gotNames, ",") {
		t.Fatalf("store files changed: %v -> %v", names, gotNames)
	}
	for _, name := range gotNames {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != contents[name] {
			t.Errorf("filtered diff modified %s", name)
		}
	}

	// 单条结果仍以数组形式呈现，而不是裸对象。
	if !strings.Contains(string(b1), `"results":[{`) {
		t.Errorf("results must stay a one-entry array: %s", b1)
	}
	// 输出不含时间戳。
	if strings.Contains(string(b1), "time") || strings.Contains(string(b1), "date") {
		t.Error("filtered diff must not contain timestamps")
	}
}

// TestDiffStoreRuleKeepsOtherSideArtifactChange 顶层产物变化标记属于整份
// 比较而非某条规则：即使筛选一条“无变化”的规则，两侧产物不同名/不同哈希
// 仍必须照实标记。
func TestDiffStoreRuleKeepsOtherSideArtifactChange(t *testing.T) {
	dir := t.TempDir()
	a1 := sampleArtifact()
	a2 := sampleArtifact()
	a2.Name = "VaultRenamed"
	a2.Source = "VaultV2.sol"
	rule := Rule{ID: "selected", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}
	before := saveDiffReport(t, dir, a1, []Rule{rule}, map[string]bool{"inv": true})
	after := saveDiffReport(t, dir, a2, []Rule{rule}, map[string]bool{"inv": true})

	diff, err := DiffStoreRule(dir, before.ReportID, after.ReportID, "selected")
	if err != nil {
		t.Fatal(err)
	}
	if !diff.ArtifactNameChanged || !diff.ArtifactHashChanged {
		t.Errorf("artifact flags = name:%v hash:%v, want both true", diff.ArtifactNameChanged, diff.ArtifactHashChanged)
	}
	if diff.Before.Artifact.Name != "Vault" || diff.After.Artifact.Name != "VaultRenamed" {
		t.Errorf("artifact refs = %+v / %+v", diff.Before.Artifact, diff.After.Artifact)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeNoChange || diff.Summary.NoChange != 1 {
		t.Errorf("entry/summary = %+v / %+v", diff.Results, diff.Summary)
	}
}
