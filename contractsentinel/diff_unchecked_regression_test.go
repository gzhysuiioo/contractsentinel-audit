package contractsentinel

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 本文件围绕比较功能的一项业务回归口径：基准报告曾对某条规则发现缺陷，新报告
// 仍包含同一条规则——标识、版本、检查种类、严重级别、引用的不变式以及
// requiresABI 完全一致——但这次既没有该规则的外部检查记录，也没有它引用的
// 不变式布尔值。规则状态因此只能是“未检查”，不能当作“通过”，更不能仅凭
// 缺陷总数下降就把旧缺陷记成“已消除缺陷”：没有新结论不等于确认修复。该规则
// 在比较结果中必须归为“检查状态变化”，前后两侧都保留完整规则：基准侧仍带
// 原来的缺陷记录（产物哈希、规则版本、严重级别、不变式名称和证据保持归档原
// 值），新侧显示“未检查”且缺陷记录为空。
//
// 基准缺陷有两种既有来源，两种报告必须得到相同分类：其一是外部检查器导入的
// 反例说明（checks 中的“发现缺陷”记录，证据即说明原文）；其二是不变式值为
// false 时由报告生成的证据（没有外部说明，证据为 invariant ... does not
// hold）。外部说明中的中文、换行和前后空格必须逐字保留，不能因为新侧缺少结
// 论就清空、缩短或替换旧证据。
//
// 同一份比较结果中还要与真实修复并存：另一条定义不变的规则基准侧有缺陷、新
// 侧明确通过时归为“已消除缺陷”；两者各计其一，缺陷总数从 2 变成 0 也只能
// 有一条已消除缺陷。规则仍在但未检查与规则被完全删除也必须分清：后者仍按既
// 有行为归为“移除规则”，新侧整体为 null。
//
// 所有用例都走 BuildReport -> SaveReport -> LoadReport/DiffStore 的正常归档
// 与读回路径，比较的是同一产物（同一名称、同一内容哈希）的两份合法报告。

// uncheckedExternalEvidence 刻意包含中文、换行与前后空格；新侧没有结论不得
// 改写、清空或替换这条旧证据。
const uncheckedExternalEvidence = "  旧反例：该规则本次未复跑\n  callvalue 跨调用余额未清零  "

// uncheckedRule 是前后两份报告共用的规则定义；两个用例只改变基准缺陷的来源。
func uncheckedRule() Rule {
	return Rule{
		ID:        "unchecked-reentrancy",
		Kind:      "static",
		Severity:  "high",
		Invariant: "unchecked-reentrant-withdraw",
		Version:   "5.2.0",
	}
}

// saveUncheckedAfterReport 落盘新侧报告：同一条规则定义仍在，但没有任何外部
// 检查记录，提交的 invariants 中也没有该规则引用的不变式名，因此规则为“未
// 检查”，报告里没有该规则的缺陷记录。
func saveUncheckedAfterReport(t *testing.T, dir string, artifact Artifact, rule Rule) Report {
	t.Helper()
	// 刻意传入一个属于其他名字的不变式：它既不能给目标规则提供结论，也不能
	// 让目标规则因此变成“通过”。
	return saveDiffReport(t, dir, artifact, []Rule{rule}, map[string]bool{"some-other-invariant": true})
}

// assertUncheckedAfterSide 校验新侧：完整规则定义仍在、状态为未检查、说明为
// 空，且该侧没有缺陷记录。
func assertUncheckedAfterSide(t *testing.T, where string, side *DiffSide, rule Rule) {
	t.Helper()
	if side == nil {
		t.Fatalf("%s: rule still present must keep a full new side, not null", where)
	}
	assertRuleFields(t, where, side.Rule, rule, StatusUnchecked, "")
	if side.Finding != nil {
		t.Errorf("%s: unchecked side must carry no defect record, got %+v", where, side.Finding)
	}
}

// TestDiffDefectToUncheckedIsStatusChange 是核心回归用例，逐项覆盖基准缺陷
// 的两种既有来源：外部检查器反例说明，与不变式 false 生成的证据。两种基准报
// 告面对“规则仍在但本次未检查”的新报告时，都必须归为“检查状态变化”而非
// “已消除缺陷”。
func TestDiffDefectToUncheckedIsStatusChange(t *testing.T) {
	cases := []struct {
		name     string
		baseline func(t *testing.T, dir string, artifact Artifact, rule Rule) Report
		evidence string
	}{
		{
			name: "external checker counterexample",
			baseline: func(t *testing.T, dir string, artifact Artifact, rule Rule) Report {
				return saveCheckReport(t, dir, artifact, []Rule{rule}, []CheckRecord{{
					ArtifactHash: ArtifactHash(artifact),
					RuleID:       rule.ID,
					Version:      rule.Version,
					Status:       StatusDefect,
					Note:         uncheckedExternalEvidence,
				}})
			},
			evidence: uncheckedExternalEvidence,
		},
		{
			name: "invariant false generated evidence",
			baseline: func(t *testing.T, dir string, artifact Artifact, rule Rule) Report {
				// 没有外部检查记录，只有该规则引用的不变式值 false：缺陷证据由
				// 报告按不变式名生成，规则不携带外部说明。
				return saveDiffReport(t, dir, artifact, []Rule{rule},
					map[string]bool{rule.Invariant: false})
			},
			evidence: invariantEvidence("unchecked-reentrant-withdraw"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := sampleArtifact()
			hash := ArtifactHash(artifact)
			rule := uncheckedRule()

			before := tc.baseline(t, dir, artifact, rule)
			after := saveUncheckedAfterReport(t, dir, artifact, rule)

			// 两份报告必须能从归档独立读回：基准侧有一条真实缺陷，新侧没有任何
			// 缺陷记录，且目标规则在两侧规则列表中都存在。
			loadedBefore, err := LoadReport(dir, before.ReportID)
			if err != nil {
				t.Fatalf("load before: %v", err)
			}
			loadedAfter, err := LoadReport(dir, after.ReportID)
			if err != nil {
				t.Fatalf("load after: %v", err)
			}
			if len(loadedBefore.Findings) != 1 || loadedBefore.Findings[0].RuleID != rule.ID {
				t.Fatalf("baseline findings = %+v, want one finding for %s", loadedBefore.Findings, rule.ID)
			}
			if len(loadedAfter.Findings) != 0 {
				t.Fatalf("unchecked new report findings = %+v, want none", loadedAfter.Findings)
			}
			afterStatus := ""
			for _, r := range loadedAfter.Rules {
				if r.ID == rule.ID {
					afterStatus = r.Status
				}
			}
			if afterStatus != StatusUnchecked {
				t.Fatalf("archived new-side status = %q, want %q", afterStatus, StatusUnchecked)
			}

			diff, err := DiffStore(dir, before.ReportID, after.ReportID)
			if err != nil {
				t.Fatalf("diff must succeed: %v", err)
			}

			// 比较方向与报告标识按归档选择保留；同一产物不标记为变化。
			if diff.Before.ReportID != before.ReportID || diff.After.ReportID != after.ReportID {
				t.Errorf("refs = %q/%q, want %q/%q", diff.Before.ReportID, diff.After.ReportID, before.ReportID, after.ReportID)
			}
			if diff.ArtifactHashChanged || diff.ArtifactNameChanged {
				t.Error("same artifact must not be flagged changed")
			}

			// 恰好一条结果，归为“检查状态变化”，不能记成已消除缺陷。
			if len(diff.Results) != 1 {
				t.Fatalf("results = %d, want 1: %+v", len(diff.Results), diff.Results)
			}
			entry := diff.Results[0]
			if entry.RuleID != rule.ID {
				t.Errorf("rule id = %q, want %q", entry.RuleID, rule.ID)
			}
			if entry.Change != ChangeStatusChanged {
				t.Fatalf("change = %q, want %q (a missing new conclusion is not a fix)",
					entry.Change, ChangeStatusChanged)
			}

			// 计数：检查状态变化为一；已消除缺陷、新发现缺陷及其余类别均为零。
			s := diff.Summary
			if s.StatusChanges != 1 {
				t.Errorf("statusChanges = %d, want 1", s.StatusChanges)
			}
			if s.ResolvedDefects != 0 {
				t.Errorf("resolvedDefects = %d, want 0: unchecked must not read as resolved", s.ResolvedDefects)
			}
			if s.NewDefects != 0 || s.NoteChanges != 0 || s.NoChange != 0 ||
				s.AddedRules != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
				t.Errorf("every other count must be zero: %+v", s)
			}
			// 两侧缺陷总数只数各自归档中实际存在的缺陷：旧侧 1、新侧 0；总数
			// 下降不代表逐规则结论。
			if s.BeforeDefects != 1 || s.AfterDefects != 0 {
				t.Errorf("defect totals = %d/%d, want 1/0 (actual archived findings)",
					s.BeforeDefects, s.AfterDefects)
			}

			// 前后两侧都保留完整规则：基准侧仍为发现缺陷并携带原说明（外部反例
			// 用例）或不带说明（不变式用例）；新侧为未检查。
			if entry.Before == nil {
				t.Fatal("baseline side must be present")
			}
			assertRuleFields(t, "before side", entry.Before.Rule, rule, StatusDefect,
				loadedBefore.Rules[0].Note)
			assertUncheckedAfterSide(t, "after side", entry.After, rule)

			// 基准缺陷记录仍绑定归档时的产物哈希、规则标识、版本、严重级别、不
			// 变式名称与原始证据，逐字保留。
			assertFindingBinding(t, "before side", entry.Before.Finding, hash, rule, tc.evidence)

			// 归档字节层面：外部说明中的中文、换行（JSON 中转义为 \n）和前后空
			// 白必须原样落盘，不能因新侧缺少结论而被修剪或替换。
			data, err := os.ReadFile(filepath.Join(dir, before.ReportID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"ruleId":"`+rule.ID+`"`) {
				t.Errorf("baseline archive must keep the rule id:\n%s", string(data))
			}
			if tc.name == "external checker counterexample" {
				wantEscaped := `"evidence":"  旧反例：该规则本次未复跑\n  callvalue 跨调用余额未清零  "`
				if !strings.Contains(string(data), wantEscaped) {
					t.Errorf("baseline archive must keep the raw evidence verbatim:\n%s", string(data))
				}
			}
		})
	}
}

// TestDiffResolvedAndUncheckedCountedSeparately 保护未检查与真实修复同时出现
// 时的统计：两份报告都包含两条引用不同不变式、定义前后不变的规则；基准侧两
// 条都有缺陷（一条来自外部检查反例，一条来自不变式 false），新侧一条明确通
// 过、另一条未检查。比较必须分别给出“已消除缺陷”和“检查状态变化”，缺陷总
// 数从 2 变成 0 时已消除缺陷也只能计 1。
func TestDiffResolvedAndUncheckedCountedSeparately(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)

	fixedRule := Rule{
		ID:        "fixed-reentrancy",
		Kind:      "static",
		Severity:  "high",
		Invariant: "fixed-reentrant-withdraw",
		Version:   "1.4.0",
	}
	recheckRule := Rule{
		ID:        "rechecked-later",
		Kind:      "static",
		Severity:  "medium",
		Invariant: "rechecked-balance-monotonic",
		Version:   "2.0.0",
	}

	// 基准侧：fixed-reentrancy 由外部检查器给出带反例的缺陷；rechecked-later
	// 没有外部记录，但其不变式值为 false，同样是真实缺陷。
	before, err := BuildReport(artifact, []Rule{fixedRule, recheckRule},
		map[string]bool{recheckRule.Invariant: false},
		[]CheckRecord{{
			ArtifactHash: hash,
			RuleID:       fixedRule.ID,
			Version:      fixedRule.Version,
			Status:       StatusDefect,
			Note:         uncheckedExternalEvidence,
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, before); err != nil {
		t.Fatal(err)
	}
	// 新侧：fixed-reentrancy 有明确的通过记录；rechecked-later 既无检查记录，
	// invariants 中也没有它的不变式，只能是未检查。
	after := saveCheckReport(t, dir, artifact, []Rule{fixedRule, recheckRule},
		[]CheckRecord{{
			ArtifactHash: hash,
			RuleID:       fixedRule.ID,
			Version:      fixedRule.Version,
			Status:       StatusPass,
		}})

	loadedAfter, err := LoadReport(dir, after.ReportID)
	if err != nil {
		t.Fatalf("load after: %v", err)
	}
	if len(loadedAfter.Findings) != 0 {
		t.Fatalf("new report findings = %+v, want none", loadedAfter.Findings)
	}

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
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

	fixed := entryByID(t, diff, fixedRule.ID)
	recheck := entryByID(t, diff, recheckRule.ID)

	// 明确通过的一条：已消除缺陷，两侧完整，通过侧无缺陷记录。
	if fixed.Change != ChangeResolvedDefect {
		t.Fatalf("fixed rule change = %q, want %q", fixed.Change, ChangeResolvedDefect)
	}
	if fixed.Before == nil || fixed.After == nil {
		t.Fatal("resolved rule must carry both sides")
	}
	assertRuleFields(t, "fixed before", fixed.Before.Rule, fixedRule, StatusDefect, uncheckedExternalEvidence)
	assertRuleFields(t, "fixed after", fixed.After.Rule, fixedRule, StatusPass, "")
	assertFindingBinding(t, "fixed before", fixed.Before.Finding, hash, fixedRule, uncheckedExternalEvidence)
	if fixed.After.Finding != nil {
		t.Errorf("passing side must carry no finding: %+v", fixed.After.Finding)
	}

	// 未检查的一条：检查状态变化，基准缺陷保留，新侧未检查且无缺陷记录；通过
	// 规则的结论绝不能套到这条规则上。
	if recheck.Change != ChangeStatusChanged {
		t.Fatalf("rechecked rule change = %q, want %q", recheck.Change, ChangeStatusChanged)
	}
	if recheck.Before == nil {
		t.Fatal("baseline side must be present")
	}
	assertRuleFields(t, "recheck before", recheck.Before.Rule, recheckRule, StatusDefect, "")
	assertUncheckedAfterSide(t, "recheck after", recheck.After, recheckRule)
	generatedEvidence := invariantEvidence(recheckRule.Invariant)
	assertFindingBinding(t, "recheck before", recheck.Before.Finding, hash, recheckRule, generatedEvidence)

	// 每条结果只携带自己所属规则的证据：不能互换，也不能把通过当成未检查规则
	// 的新结论。
	if fixed.Before.Finding.RuleID != fixedRule.ID || recheck.Before.Finding.RuleID != recheckRule.ID {
		t.Errorf("evidence must stay bound by rule id: %+v / %+v", fixed.Before.Finding, recheck.Before.Finding)
	}
	if fixed.Before.Finding.Evidence == recheck.Before.Finding.Evidence {
		t.Error("the two rules must keep their own evidence, not share one text")
	}
	if recheck.After.Rule.Status != StatusUnchecked || fixed.After.Rule.Status != StatusPass {
		t.Errorf("the passing conclusion must not be applied to the unchecked rule: %q / %q",
			recheck.After.Rule.Status, fixed.After.Rule.Status)
	}

	// 汇总：缺陷总数 2 -> 0，但已消除缺陷只计 1，检查状态变化只计 1，没有新
	// 发现缺陷；逐规则判断而非用总数下降代替。
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
		t.Errorf("defect totals = %d/%d, want 2/0 (total drop is not per-rule resolution)",
			s.BeforeDefects, s.AfterDefects)
	}
}

// TestDiffUncheckedPresentDiffersFromRemovedRule 分清“规则仍在但未检查”和
// “规则被删除”：新报告完全不再包含的旧缺陷规则仍按既有行为归为“移除规则”，
// 该条目的新侧整体为 null；规则仍在但没有结论的一条归为“检查状态变化”，新
// 侧是完整的未检查规则。两者不能混在一起。
func TestDiffUncheckedPresentDiffersFromRemovedRule(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)

	presentRule := uncheckedRule()
	goneRule := Rule{
		ID:        "dropped-reentrancy",
		Kind:      "static",
		Severity:  "critical",
		Invariant: "dropped-reentrant-withdraw",
		Version:   "9.0.1",
	}
	goneEvidence := "  旧反例：规则随检查范围一并删除\n  delegatecall 路径  "

	// 基准侧两条都为外部检查器发现的缺陷，各自携带自己的证据。
	before := saveCheckReport(t, dir, artifact, []Rule{presentRule, goneRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: presentRule.ID, Version: presentRule.Version, Status: StatusDefect, Note: uncheckedExternalEvidence},
		{ArtifactHash: hash, RuleID: goneRule.ID, Version: goneRule.Version, Status: StatusDefect, Note: goneEvidence},
	})
	// 新报告只保留 presentRule，且没有任何检查记录或其不变式值 -> 未检查；
	// goneRule 在规则列表中完全缺席。
	after := saveUncheckedAfterReport(t, dir, artifact, presentRule)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}

	present := entryByID(t, diff, presentRule.ID)
	gone := entryByID(t, diff, goneRule.ID)

	// 仍在但未检查：检查状态变化，两侧完整。
	if present.Change != ChangeStatusChanged {
		t.Fatalf("present rule change = %q, want %q", present.Change, ChangeStatusChanged)
	}
	if present.Before == nil {
		t.Fatal("present rule must keep its baseline side")
	}
	assertUncheckedAfterSide(t, "present after", present.After, presentRule)
	assertFindingBinding(t, "present before", present.Before.Finding, hash, presentRule, uncheckedExternalEvidence)

	// 完全删除：移除规则，新侧整体为 null，旧侧完整保留。
	if gone.Change != ChangeRuleRemoved {
		t.Fatalf("gone rule change = %q, want %q", gone.Change, ChangeRuleRemoved)
	}
	if gone.After != nil {
		t.Fatalf("removed rule new side must be null, got %+v", gone.After)
	}
	if gone.Before == nil {
		t.Fatal("removed rule must keep its old side")
	}
	assertRuleFields(t, "gone before", gone.Before.Rule, goneRule, StatusDefect, goneEvidence)
	assertFindingBinding(t, "gone before", gone.Before.Finding, hash, goneRule, goneEvidence)

	s := diff.Summary
	if s.StatusChanges != 1 || s.RemovedRules != 1 {
		t.Errorf("statusChanges/removedRules = %d/%d, want 1/1", s.StatusChanges, s.RemovedRules)
	}
	if s.ResolvedDefects != 0 || s.NewDefects != 0 {
		t.Errorf("neither case is a defect transition: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0", s.BeforeDefects, s.AfterDefects)
	}
}
