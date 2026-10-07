package contractsentinel

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 本文件回归保护“基准报告发现缺陷，新报告规则仍在却没有任何检查结论”的比较
// 场景：同一份合约产物、同一条规则（标识、版本及其余定义完全一致），新报告既
// 没有该规则的外部检查记录，也没有它引用的不变式布尔值时，规则状态只能是
// “未检查”，比较必须归为“检查状态变化”，绝不能因为新侧没有缺陷就记成“已消除
// 缺陷”。基准侧的缺陷与证据原样保留（产物哈希、规则版本、严重级别、不变式名
// 称都不变），新侧保留完整规则但缺陷记录为空。基准缺陷的两种既有来源——外部
// 检查器的反例说明、不变式值为 false 时生成的证据——必须得到相同分类；说明中
// 的中文、换行与前后空格逐字保留，不因新侧缺少结论而被清空、缩短或替换。这里
// 的每一份报告都真正落盘，再经 DiffStore 完整校验读回后比较。

// uncheckedRegressionEvidence 刻意包含中文、换行与前后空格，任何修剪或模板
// 替换都会被抓到。
const uncheckedRegressionEvidence = "  旧反例：未复检不能当作修复\n第二行证据  "

// uncheckedRegressionRule 是两侧共用的同一条规则定义，标识、版本及其余字段
// 完全一致，只有这样两侧状态才允许直接比较。
func uncheckedRegressionRule() Rule {
	return Rule{ID: "reentrancy-guard", Kind: "static", Severity: "high", Invariant: "no-reentrant-withdraw", Version: "1.4.2"}
}

// saveMixedCheckReport 同时携带不变式布尔值与外部检查记录构建、保存并返回
// 报告：两类结论分属引用不同不变式的规则时这是合法输入。
func saveMixedCheckReport(t *testing.T, dir string, artifact Artifact, rules []Rule, invariants map[string]bool, checks []CheckRecord) Report {
	t.Helper()
	report, err := BuildReport(artifact, rules, invariants, checks)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	return report
}

// TestDiffDefectToUncheckedIsStatusChange 覆盖核心口径：基准侧“发现缺陷”，
// 新报告保留同一条规则但既无外部检查记录也无不变式值（状态为“未检查”），
// 必须归为“检查状态变化”，而不是“已消除缺陷”。基准缺陷的两种现有来源都要
// 得到相同分类，且各自的证据逐字保留。
func TestDiffDefectToUncheckedIsStatusChange(t *testing.T) {
	cases := []struct {
		name string
		// buildBefore 构造基准侧（带缺陷）报告。
		buildBefore    func(dir string, artifact Artifact, rule Rule, hash string) Report
		wantEvidence   string
		wantBeforeNote string
	}{
		{
			name: "external checker counterexample",
			buildBefore: func(dir string, artifact Artifact, rule Rule, hash string) Report {
				return saveMixedCheckReport(t, dir, artifact, []Rule{rule}, nil,
					[]CheckRecord{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
						Status: StatusDefect, Note: uncheckedRegressionEvidence}})
			},
			wantEvidence:   uncheckedRegressionEvidence,
			wantBeforeNote: uncheckedRegressionEvidence,
		},
		{
			name: "invariant false generated evidence",
			buildBefore: func(dir string, artifact Artifact, rule Rule, hash string) Report {
				return saveMixedCheckReport(t, dir, artifact, []Rule{rule},
					map[string]bool{rule.Invariant: false}, nil)
			},
			wantEvidence:   invariantEvidence("no-reentrant-withdraw"),
			wantBeforeNote: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := sampleArtifact()
			hash := ArtifactHash(artifact)
			rule := uncheckedRegressionRule()

			before := tc.buildBefore(dir, artifact, rule, hash)
			// 新报告：同一条规则仍在，但没有外部检查记录、invariants 中也没有
			// 它引用的不变式，因此规则状态为“未检查”，且没有缺陷记录。
			after := saveMixedCheckReport(t, dir, artifact, []Rule{rule}, nil, nil)

			// 状态不同，两份报告必然具有不同的报告标识。
			if before.ReportID == after.ReportID {
				t.Fatal("a defect report and an unchecked report must have different report ids")
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
				t.Fatal(err)
			}

			// 同一产物、同一引用方向。
			if diff.Before.ReportID != before.ReportID || diff.After.ReportID != after.ReportID {
				t.Errorf("refs = %q/%q, want %q/%q", diff.Before.ReportID, diff.After.ReportID, before.ReportID, after.ReportID)
			}
			if diff.ArtifactNameChanged || diff.ArtifactHashChanged {
				t.Error("same artifact must not be flagged as changed")
			}

			// 这条规则只出现一次，归为“检查状态变化”，两侧都保留完整规则。
			if len(diff.Results) != 1 {
				t.Fatalf("results = %d, want 1", len(diff.Results))
			}
			entry := diff.Results[0]
			if entry.RuleID != rule.ID {
				t.Fatalf("rule id = %q, want %q", entry.RuleID, rule.ID)
			}
			if entry.Change != ChangeStatusChanged {
				t.Fatalf("change = %q, want %q (a missing conclusion is not a fix)",
					entry.Change, ChangeStatusChanged)
			}
			if entry.Before == nil || entry.After == nil {
				t.Fatal("a rule still present in both reports must keep both sides")
			}

			// 两侧规则定义逐字段一致。
			b, a := entry.Before.Rule, entry.After.Rule
			if b.Kind != a.Kind || b.Severity != a.Severity || b.Invariant != a.Invariant ||
				b.RequiresABI != a.RequiresABI || b.Version != a.Version {
				t.Errorf("rule definitions must stay identical: before=%+v after=%+v", b, a)
			}

			// 基准侧仍带原来的缺陷记录：状态、说明与证据绑定都保持原值。
			if b.Status != StatusDefect {
				t.Errorf("before status = %q, want %q", b.Status, StatusDefect)
			}
			if b.Note != tc.wantBeforeNote {
				t.Errorf("before note = %q, want %q verbatim", b.Note, tc.wantBeforeNote)
			}
			if entry.Before.Finding == nil {
				t.Fatal("baseline side must keep its original defect finding")
			}
			bf := entry.Before.Finding
			if bf.ArtifactHash != hash || bf.RuleID != rule.ID || bf.Version != rule.Version ||
				bf.Severity != rule.Severity || bf.Invariant != rule.Invariant {
				t.Errorf("baseline finding binding = %+v, want hash=%q rule=%q version=%q severity=%q invariant=%q",
					*bf, hash, rule.ID, rule.Version, rule.Severity, rule.Invariant)
			}
			if bf.Evidence != tc.wantEvidence {
				t.Errorf("baseline evidence = %q, want %q verbatim", bf.Evidence, tc.wantEvidence)
			}

			// 新侧规则仍在但显示“未检查”，说明为空、缺陷记录为空——既不是“通过”，
			// 也没有继承基准侧的旧证据。
			if a.Status != StatusUnchecked {
				t.Errorf("after status = %q, want %q (no check record and no invariant value)",
					a.Status, StatusUnchecked)
			}
			if a.Note != "" {
				t.Errorf("unchecked after side must carry no note, got %q", a.Note)
			}
			if entry.After.Finding != nil {
				t.Errorf("unchecked after side must carry no finding, got %+v", entry.After.Finding)
			}

			// 汇总：检查状态变化一条；绝不能计成已消除缺陷或新发现缺陷；新侧
			// 缺陷总数为零，但逐规则分类仍是状态变化而不是修复。
			s := diff.Summary
			if s.StatusChanges != 1 {
				t.Errorf("statusChanges = %d, want 1", s.StatusChanges)
			}
			if s.ResolvedDefects != 0 {
				t.Errorf("resolvedDefects = %d, want 0: an unchecked rule is not a resolved defect", s.ResolvedDefects)
			}
			if s.NewDefects != 0 {
				t.Errorf("newDefects = %d, want 0", s.NewDefects)
			}
			if s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 ||
				s.RemovedRules != 0 || s.ChangedRules != 0 {
				t.Errorf("every other count must be zero: %+v", s)
			}
			if s.BeforeDefects != 1 || s.AfterDefects != 0 {
				t.Errorf("defect totals = %d/%d, want 1/0 (per-rule classification still applies)",
					s.BeforeDefects, s.AfterDefects)
			}

			// 比较后的归档内容保持原样，旧证据不被清空、缩短或替换。
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

			// 实际读回新报告：该规则确实以“未检查”落盘且没有缺陷记录；读回
			// 基准报告仍能看到原来的证据（外部说明时逐字保留）。
			reloadedAfter, err := LoadReport(dir, after.ReportID)
			if err != nil {
				t.Fatal(err)
			}
			if len(reloadedAfter.Rules) != 1 || reloadedAfter.Rules[0].Status != StatusUnchecked {
				t.Errorf("reloaded after rule = %+v, want 未检查", reloadedAfter.Rules)
			}
			if len(reloadedAfter.Findings) != 0 {
				t.Errorf("reloaded after report must carry no findings, got %+v", reloadedAfter.Findings)
			}
			reloadedBefore, err := LoadReport(dir, before.ReportID)
			if err != nil {
				t.Fatal(err)
			}
			if len(reloadedBefore.Findings) != 1 || reloadedBefore.Findings[0].Evidence != tc.wantEvidence {
				t.Errorf("reloaded baseline evidence = %+v, want %q", reloadedBefore.Findings, tc.wantEvidence)
			}
		})
	}
}

// TestDiffRealFixAndUncheckedCountedPerRule 保护“真实修复”与“未检查”同时
// 出现时的统计：两份报告都包含两条引用不同不变式、定义不变的规则；基准侧两
// 条都发现缺陷，新侧一条明确通过、另一条没有任何结论（未检查）。比较必须分
// 别给出“已消除缺陷”和“检查状态变化”，缺陷总数从 2 变成 0，但已消除缺陷只
// 计 1、检查状态变化只计 1，不出现新发现缺陷；每条结果携带各自所属规则的证
// 据，不能把通过规则的结论套到未检查规则上，也不能用总数下降代替逐规则判断。
func TestDiffRealFixAndUncheckedCountedPerRule(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	// fixed 走外部检查器：基准缺陷（带反例说明）-> 新侧明确通过。
	fixed := Rule{ID: "reentrancy-guard", Kind: "static", Severity: "high", Invariant: "no-reentrant-withdraw", Version: "1.4.2"}
	// skipped 走不变式布尔值：基准 invariant=false 缺陷 -> 新侧既无布尔值也无检查。
	skipped := Rule{ID: "balance-monotonic", Kind: "static", Severity: "critical", Invariant: "balance-monotonic", Version: "0.9.0"}
	rules := []Rule{fixed, skipped}
	skippedEvidence := invariantEvidence(skipped.Invariant)

	// 基准侧：fixed 由外部检查记录判定缺陷，skipped 由 invariant=false 判定缺陷。
	before := saveMixedCheckReport(t, dir, artifact, rules,
		map[string]bool{skipped.Invariant: false},
		[]CheckRecord{{ArtifactHash: hash, RuleID: fixed.ID, Version: fixed.Version,
			Status: StatusDefect, Note: uncheckedRegressionEvidence}})
	// 新侧：fixed 明确通过；skipped 规则仍在，但没有检查记录、invariants 中也
	// 没有它的不变式，因此为未检查。两条规则引用不同不变式，提交合法。
	after := saveMixedCheckReport(t, dir, artifact, rules,
		nil,
		[]CheckRecord{{ArtifactHash: hash, RuleID: fixed.ID, Version: fixed.Version,
			Status: StatusPass}})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}

	// 每条规则一个结果，按规则标识排序。
	if len(diff.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(diff.Results))
	}
	ids := make([]string, 0, len(diff.Results))
	byID := map[string]RuleDiff{}
	for _, r := range diff.Results {
		ids = append(ids, r.RuleID)
		byID[r.RuleID] = r
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}

	// 明确修复的规则：已消除缺陷，基准侧只带自己的缺陷证据，通过侧无缺陷记录。
	gotFixed, ok := byID[fixed.ID]
	if !ok {
		t.Fatalf("missing result for %s", fixed.ID)
	}
	if gotFixed.Change != ChangeResolvedDefect {
		t.Errorf("fixed rule change = %q, want %q", gotFixed.Change, ChangeResolvedDefect)
	}
	if gotFixed.Before == nil || gotFixed.After == nil {
		t.Fatal("fixed rule must keep both sides")
	}
	if gotFixed.Before.Rule.Status != StatusDefect || gotFixed.After.Rule.Status != StatusPass {
		t.Errorf("fixed statuses = %q/%q, want 发现缺陷/通过", gotFixed.Before.Rule.Status, gotFixed.After.Rule.Status)
	}
	if gotFixed.Before.Finding == nil || gotFixed.Before.Finding.Evidence != uncheckedRegressionEvidence ||
		gotFixed.Before.Finding.RuleID != fixed.ID || gotFixed.Before.Finding.Invariant != fixed.Invariant ||
		gotFixed.Before.Finding.ArtifactHash != hash || gotFixed.Before.Finding.Version != fixed.Version {
		t.Errorf("fixed baseline must keep its own finding: %+v", gotFixed.Before.Finding)
	}
	if gotFixed.After.Finding != nil {
		t.Errorf("passing side must carry no finding: %+v", gotFixed.After.Finding)
	}

	// 缺少结论的规则：检查状态变化，基准侧保留 invariant=false 生成的证据，
	// 新侧未检查、无说明、无缺陷记录。
	gotSkipped, ok := byID[skipped.ID]
	if !ok {
		t.Fatalf("missing result for %s", skipped.ID)
	}
	if gotSkipped.Change != ChangeStatusChanged {
		t.Errorf("skipped rule change = %q, want %q", gotSkipped.Change, ChangeStatusChanged)
	}
	if gotSkipped.Before == nil || gotSkipped.After == nil {
		t.Fatal("a still-present unchecked rule must keep both sides")
	}
	if gotSkipped.Before.Rule.Status != StatusDefect || gotSkipped.After.Rule.Status != StatusUnchecked {
		t.Errorf("skipped statuses = %q/%q, want 发现缺陷/未检查", gotSkipped.Before.Rule.Status, gotSkipped.After.Rule.Status)
	}
	if gotSkipped.Before.Rule.Note != "" {
		t.Errorf("invariant-form defect carries no rule note, got %q", gotSkipped.Before.Rule.Note)
	}
	if gotSkipped.Before.Finding == nil || gotSkipped.Before.Finding.Evidence != skippedEvidence ||
		gotSkipped.Before.Finding.RuleID != skipped.ID || gotSkipped.Before.Finding.Invariant != skipped.Invariant ||
		gotSkipped.Before.Finding.Severity != skipped.Severity ||
		gotSkipped.Before.Finding.ArtifactHash != hash || gotSkipped.Before.Finding.Version != skipped.Version {
		t.Errorf("skipped baseline must keep its invariant-form finding: %+v", gotSkipped.Before.Finding)
	}
	if gotSkipped.After.Rule.Note != "" {
		t.Errorf("unchecked side must carry no note, got %q", gotSkipped.After.Rule.Note)
	}
	if gotSkipped.After.Finding != nil {
		t.Errorf("unchecked side must carry no finding, got %+v", gotSkipped.After.Finding)
	}

	// 证据按规则标识各自归属，不能把通过规则的结论或另一条规则的证据串过来。
	if gotFixed.Before.Finding.RuleID == gotSkipped.Before.Finding.RuleID {
		t.Error("findings must stay bound to their own rule ids")
	}
	if gotFixed.Before.Finding.Evidence == skippedEvidence ||
		gotSkipped.Before.Finding.Evidence == uncheckedRegressionEvidence {
		t.Error("each result must carry its own rule's evidence, not the other rule's")
	}

	// 汇总：缺陷总数 2 -> 0，但逐规则计数仍是已消除 1、状态变化 1，没有新缺陷。
	s := diff.Summary
	if s.ResolvedDefects != 1 || s.StatusChanges != 1 {
		t.Errorf("resolved/statusChanges = %d/%d, want 1/1", s.ResolvedDefects, s.StatusChanges)
	}
	if s.NewDefects != 0 {
		t.Errorf("newDefects = %d, want 0", s.NewDefects)
	}
	if s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 ||
		s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other count must be zero: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0; the drop must not replace per-rule classification",
			s.BeforeDefects, s.AfterDefects)
	}
}

// TestDiffUncheckedPresentRuleIsNotRemovedRule 明确区分“规则仍在但未检查”与
// “规则被删除”：基准侧两条缺陷规则，新报告保留其中一条但没有结论（未检查），
// 另一条完全不再包含。前者必须是“检查状态变化”且新侧为完整的未检查规则，后
// 者才是“移除规则”且新侧整体为空，两者不能混在一起。
func TestDiffUncheckedPresentRuleIsNotRemovedRule(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	present := Rule{ID: "present-unchecked", Kind: "static", Severity: "high", Invariant: "inv-present", Version: "1.2.0"}
	removed := Rule{ID: "gone-removed", Kind: "static", Severity: "medium", Invariant: "inv-removed", Version: "2.3.0"}
	presentEvidence := "  保留规则的旧反例\n第二行  "
	removedEvidence := "  被移除规则的旧反例\n第二行  "

	// 基准侧两条规则都由外部检查器判定缺陷，各自携带不同证据。
	before := saveMixedCheckReport(t, dir, artifact, []Rule{present, removed}, nil,
		[]CheckRecord{
			{ArtifactHash: hash, RuleID: removed.ID, Version: removed.Version, Status: StatusDefect, Note: removedEvidence},
			{ArtifactHash: hash, RuleID: present.ID, Version: present.Version, Status: StatusDefect, Note: presentEvidence},
		})
	// 新报告只保留 present，且没有它的检查记录与不变式值 -> 未检查；removed 缺席。
	after := saveMixedCheckReport(t, dir, artifact, []Rule{present}, nil, nil)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(diff.Results))
	}
	byID := map[string]RuleDiff{}
	for _, r := range diff.Results {
		byID[r.RuleID] = r
	}

	// 仍在但未检查：检查状态变化，新侧是完整规则（状态未检查）而不是 null。
	gotPresent := byID[present.ID]
	if gotPresent.Change != ChangeStatusChanged {
		t.Errorf("present rule change = %q, want %q", gotPresent.Change, ChangeStatusChanged)
	}
	if gotPresent.Before == nil || gotPresent.After == nil {
		t.Fatal("present unchecked rule must keep both sides")
	}
	if gotPresent.After.Rule.ID != present.ID || gotPresent.After.Rule.Status != StatusUnchecked {
		t.Errorf("present after side = %+v, want the full rule with 未检查", gotPresent.After.Rule)
	}
	if gotPresent.After.Rule.Version != present.Version || gotPresent.After.Rule.Invariant != present.Invariant {
		t.Errorf("present after side must keep the identical definition: %+v", gotPresent.After.Rule)
	}
	if gotPresent.After.Finding != nil {
		t.Errorf("unchecked side must carry no finding, got %+v", gotPresent.After.Finding)
	}
	if gotPresent.Before.Finding == nil || gotPresent.Before.Finding.Evidence != presentEvidence {
		t.Errorf("present baseline must keep its own finding: %+v", gotPresent.Before.Finding)
	}

	// 完全缺席：移除规则，新侧整体为 null，基准侧保留原缺陷记录。
	gotRemoved := byID[removed.ID]
	if gotRemoved.Change != ChangeRuleRemoved {
		t.Errorf("removed rule change = %q, want %q", gotRemoved.Change, ChangeRuleRemoved)
	}
	if gotRemoved.After != nil {
		t.Errorf("an absent rule must render the new side null, got %+v", gotRemoved.After)
	}
	if gotRemoved.Before == nil || gotRemoved.Before.Finding == nil ||
		gotRemoved.Before.Finding.Evidence != removedEvidence {
		t.Errorf("removed baseline must keep the original defect: %+v", gotRemoved.Before)
	}

	// 两类计数各自独立：状态变化 1、移除规则 1，都不算已消除缺陷。
	s := diff.Summary
	if s.StatusChanges != 1 || s.RemovedRules != 1 {
		t.Errorf("statusChanges/removedRules = %d/%d, want 1/1", s.StatusChanges, s.RemovedRules)
	}
	if s.ResolvedDefects != 0 || s.NewDefects != 0 {
		t.Errorf("neither an unchecked rule nor a removed one is a resolved defect: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0", s.BeforeDefects, s.AfterDefects)
	}
}
