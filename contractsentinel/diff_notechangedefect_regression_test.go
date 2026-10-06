package contractsentinel

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 本文件围绕比较功能的一项业务回归口径：同一份合约产物的两次检查都仍然
// “发现缺陷”，规则标识、版本及其他定义完全一致，只有检查说明（反例原文）
// 不同——检查器更新了反例说明，但缺陷仍然存在。此时该规则在比较结果中只能
// 出现一次并归为“检查说明变化”：缺陷没有被新增，也没有被消除，检查状态也
// 没有变化。汇总中说明变化计为一条，新增缺陷、已消除缺陷、检查状态变化均
// 为零，两侧缺陷总数各为一。两份报告是两次独立归档，必须具有不同的报告
// 标识，比较输出的基准侧与新侧分别引用各自的报告。
//
// 说明按原文比较：中文、换行和前后空格都属于内容，仅多一个尾随空格也是说明
// 变化；两侧文字逐字保留，旧侧证据不能换成新侧文字，两份说明也不能拼成一份
// 证据。原文完全相同时归为“无变化”，不增加说明变化计数。另保留一条影响
// 分类的边界：两侧都发现缺陷且说明不同，但规则版本（或其他定义）变化时沿用
// “规则变化”，不同时计为说明变化。
//
// 同一份比较还要能区分不同规则：一条更新反例、另一条保留原证据时，后者为
// “无变化”，两侧缺陷总数各为二，说明变化仍只有一条。规则与缺陷在两份归档
// 中的排列可以不同，输出必须按规则标识关联各自的证据。比较是只读操作，
// 归档内容保持原样，用户事后读回任一报告仍看到该次检查保存的反例。
//
// 所有用例都走 BuildReport -> SaveReport -> DiffStore 的正常归档与读回路径，
// 比较的是同一产物（同一名称、同一内容哈希）的两份合法报告。

// noteChangeOldEvidence / noteChangeNewEvidence 刻意包含中文、换行与前后
// 空白；说明变化不得修剪、归一化、交叉替换或拼接任何一侧的证据。
const noteChangeOldEvidence = "  旧反例：第一次检查的调用路径\nattacker.drain() 后余额归零  "
const noteChangeNewEvidence = "  新反例：复跑得到更短路径\nattacker.directTransfer() 直接转走  "

// noteChangeStableEvidence 是同份比较中另一条规则两侧共用的证据：该规则
// 两次检查都保留同一反例，必须归为“无变化”。
const noteChangeStableEvidence = "  稳定缺陷：两次检查都是这条反例\n第二行  "

// noteChangeRule 构造更新反例的那条规则；两次检查使用完全一致的定义。
func noteChangeRule() Rule {
	return Rule{
		ID:        "note-updated-reentrancy",
		Kind:      "static",
		Severity:  "high",
		Invariant: "no-reentrant-drain",
		Version:   "5.4.0",
	}
}

// noteChangeStableRule 构造保留原证据的对照规则，定义与更新规则不同。
func noteChangeStableRule() Rule {
	return Rule{
		ID:        "note-stable-access",
		Kind:      "static",
		Severity:  "medium",
		Invariant: "owner-only-settle",
		Version:   "2.7.1",
	}
}

// saveDefectNoteReport 通过外部检查记录落盘一份“发现缺陷”报告：状态固定为
// 发现缺陷，证据中的中文、换行和前后空白随检查说明原样归档。
func saveDefectNoteReport(t *testing.T, dir string, artifact Artifact, rule Rule, note string) Report {
	t.Helper()
	return saveRuleChangeCheckReport(t, dir, artifact, rule, StatusDefect, note)
}

// assertSideFinding 校验比较输出中一侧的缺陷记录仍绑定该侧归档时的产物
// 哈希、规则标识、版本，并逐字保留该侧自己的证据。
func assertSideFinding(t *testing.T, where string, side *DiffSide, hash string, rule Rule, evidence string) {
	t.Helper()
	if side == nil {
		t.Fatalf("%s: side must be present", where)
	}
	if side.Rule.Status != StatusDefect {
		t.Errorf("%s: status = %q, want %q", where, side.Rule.Status, StatusDefect)
	}
	if side.Rule.Note != evidence {
		t.Errorf("%s: rule note = %q, want %q verbatim", where, side.Rule.Note, evidence)
	}
	assertFindingBinding(t, where+" finding", side.Finding, hash, rule, evidence)
}

// TestDiffBothSidesDefectOnlyEvidenceRewordedIsNoteChange 是核心回归用例：
// 缺陷仍然存在、检查器只更新了反例说明时，只能记为“检查说明变化”，两侧缺陷
// 记录各自保留原反例，不能被误记为新增/消除缺陷或检查状态变化。
func TestDiffBothSidesDefectOnlyEvidenceRewordedIsNoteChange(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rule := noteChangeRule()

	before := saveDefectNoteReport(t, dir, artifact, rule, noteChangeOldEvidence)
	after := saveDefectNoteReport(t, dir, artifact, rule, noteChangeNewEvidence)

	// 两次独立归档必须具有不同的报告标识，且各自能独立读回一条真实缺陷。
	if before.ReportID == after.ReportID {
		t.Fatalf("two reports with different evidence must have distinct report ids, both %q", before.ReportID)
	}
	loadedBefore, err := LoadReport(dir, before.ReportID)
	if err != nil {
		t.Fatalf("load before: %v", err)
	}
	loadedAfter, err := LoadReport(dir, after.ReportID)
	if err != nil {
		t.Fatalf("load after: %v", err)
	}
	if len(loadedBefore.Findings) != 1 || len(loadedAfter.Findings) != 1 {
		t.Fatalf("archived findings = %d/%d, want 1/1", len(loadedBefore.Findings), len(loadedAfter.Findings))
	}

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatalf("diff must succeed when only the defect note changed: %v", err)
	}

	// 基准侧与新侧分别引用对应的报告标识；同一产物不标记为变化。
	if diff.Before.ReportID != before.ReportID || diff.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", diff.Before.ReportID, diff.After.ReportID, before.ReportID, after.ReportID)
	}
	if diff.ArtifactHashChanged || diff.ArtifactNameChanged {
		t.Error("same artifact must not be flagged changed")
	}

	// 这条规则恰好出现一次，归为“检查说明变化”。
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1: %+v", len(diff.Results), diff.Results)
	}
	entry := diff.Results[0]
	if entry.RuleID != rule.ID {
		t.Errorf("rule id = %q, want %q", entry.RuleID, rule.ID)
	}
	if entry.Change != ChangeNoteChanged {
		t.Fatalf("change = %q, want %q (defect still present, only the note was reworded)",
			entry.Change, ChangeNoteChanged)
	}

	// 汇总：说明变化为一；新增缺陷、已消除缺陷、检查状态变化（及其余类别）
	// 均为零；两侧缺陷总数各为一。
	s := diff.Summary
	if s.NoteChanges != 1 {
		t.Errorf("noteChanges = %d, want 1", s.NoteChanges)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("a reworded counterexample must not be read as a defect transition: %+v", s)
	}
	if s.NoChange != 0 || s.AddedRules != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every non-note-change count must be zero: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1 (the defect is present on both sides)",
			s.BeforeDefects, s.AfterDefects)
	}

	// 两侧规则定义一致、状态都是发现缺陷，各自的缺陷仍绑定原来的产物哈希、
	// 规则标识和版本。
	assertSideFinding(t, "before side", entry.Before, hash, rule, noteChangeOldEvidence)
	assertSideFinding(t, "after side", entry.After, hash, rule, noteChangeNewEvidence)

	// 不能把旧侧证据换成新侧文字，也不能把两份说明拼成一份证据。
	if entry.Before.Finding.Evidence == noteChangeNewEvidence {
		t.Error("baseline evidence must not be rewritten to the new counterexample")
	}
	if entry.After.Finding.Evidence == noteChangeOldEvidence {
		t.Error("new-side evidence must not keep the old counterexample")
	}
	if strings.Contains(entry.Before.Finding.Evidence, "directTransfer") ||
		strings.Contains(entry.After.Finding.Evidence, "drain()") {
		t.Errorf("each side must keep exactly its own evidence, not a merge: before=%q after=%q",
			entry.Before.Finding.Evidence, entry.After.Finding.Evidence)
	}

	// 归档字节层面：两份说明各自逐字落盘（JSON 中换行转义为 \n），中文和
	// 前后空白不被修剪，旧归档不含新文字、新归档不含旧文字。
	beforeBytes, err := os.ReadFile(filepath.Join(dir, before.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	afterBytes, err := os.ReadFile(filepath.Join(dir, after.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	oldEscaped := `"evidence":"  旧反例：第一次检查的调用路径\nattacker.drain() 后余额归零  "`
	newEscaped := `"evidence":"  新反例：复跑得到更短路径\nattacker.directTransfer() 直接转走  "`
	if !strings.Contains(string(beforeBytes), oldEscaped) || strings.Contains(string(beforeBytes), newEscaped) {
		t.Errorf("baseline archive must keep only the old evidence verbatim:\n%s", beforeBytes)
	}
	if !strings.Contains(string(afterBytes), newEscaped) || strings.Contains(string(afterBytes), oldEscaped) {
		t.Errorf("new archive must keep only the new evidence verbatim:\n%s", afterBytes)
	}
}

// TestDiffEvidenceRewordedByTrailingSpaceIsNoteChange 说明按原文比较：仅多
// 一个尾随空格也属于说明变化，两侧文字仍逐字保留，缺陷仍在两侧。
func TestDiffEvidenceRewordedByTrailingSpaceIsNoteChange(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rule := noteChangeRule()

	withTrailingSpace := noteChangeOldEvidence + " "
	before := saveDefectNoteReport(t, dir, artifact, rule, noteChangeOldEvidence)
	after := saveDefectNoteReport(t, dir, artifact, rule, withTrailingSpace)
	if before.ReportID == after.ReportID {
		t.Fatal("a trailing-space difference must produce a distinct report id")
	}

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeNoteChanged {
		t.Fatalf("results = %+v, want one %s", diff.Results, ChangeNoteChanged)
	}
	s := diff.Summary
	if s.NoteChanges != 1 || s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("a single trailing space is a note change, not a defect transition: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}
	entry := diff.Results[0]
	assertSideFinding(t, "before side", entry.Before, hash, rule, noteChangeOldEvidence)
	assertSideFinding(t, "after side", entry.After, hash, rule, withTrailingSpace)
}

// TestDiffIdenticalEvidenceOnBothDefectSidesIsNoChange 是原文完全相同的对照：
// 两侧都发现缺陷且说明逐字一致时归为“无变化”，不增加说明变化计数。
func TestDiffIdenticalEvidenceOnBothDefectSidesIsNoChange(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rule := noteChangeRule()

	before := saveDefectNoteReport(t, dir, artifact, rule, noteChangeOldEvidence)
	after := saveDefectNoteReport(t, dir, artifact, rule, noteChangeOldEvidence)
	// 内容一致（包括证据）的两次归档是同一份内容寻址报告。
	if before.ReportID != after.ReportID {
		t.Fatalf("identical content must share one report id, got %q vs %q", before.ReportID, after.ReportID)
	}

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeNoChange {
		t.Fatalf("results = %+v, want one %s", diff.Results, ChangeNoChange)
	}
	s := diff.Summary
	if s.NoteChanges != 0 {
		t.Errorf("noteChanges = %d, want 0 for verbatim-identical notes", s.NoteChanges)
	}
	if s.NoChange != 1 || s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("summary = %+v, want one no-change only", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}
	for _, side := range []*DiffSide{diff.Results[0].Before, diff.Results[0].After} {
		assertSideFinding(t, "identical side", side, hash, rule, noteChangeOldEvidence)
	}
}

// TestDiffBothSidesDefectWithVersionChangeIsRuleChange 保留分类优先级边界：
// 两侧都发现缺陷且说明不同，但规则版本变化时沿用“规则变化”，不能同时计为
// 说明变化；两侧证据仍各自保留。
func TestDiffBothSidesDefectWithVersionChangeIsRuleChange(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	beforeRule := noteChangeRule()
	afterRule := noteChangeRule()
	afterRule.Version = "5.5.0"

	before := saveDefectNoteReport(t, dir, artifact, beforeRule, noteChangeOldEvidence)
	after := saveDefectNoteReport(t, dir, artifact, afterRule, noteChangeNewEvidence)

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeRuleChanged {
		t.Fatalf("results = %+v, want one %s", diff.Results, ChangeRuleChanged)
	}
	s := diff.Summary
	if s.ChangedRules != 1 {
		t.Errorf("changedRules = %d, want 1", s.ChangedRules)
	}
	if s.NoteChanges != 0 {
		t.Errorf("noteChanges = %d, want 0: a rule change must not also be counted as a note change", s.NoteChanges)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("a rule-version change must not be read as a defect transition: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}
	entry := diff.Results[0]
	assertSideFinding(t, "before side", entry.Before, hash, beforeRule, noteChangeOldEvidence)
	assertSideFinding(t, "after side", entry.After, hash, afterRule, noteChangeNewEvidence)
}

// TestDiffRewordedEvidenceAndStableDefectMatchedByRuleID 在同一份比较中区分
// 两条规则：一条更新反例（检查说明变化），另一条两次检查保留同一反例
// （无变化）。两条规则与各自缺陷在两份归档中的排列刻意不同，输出必须按规则
// 标识关联证据，不能按数组位置串到另一条规则。
func TestDiffRewordedEvidenceAndStableDefectMatchedByRuleID(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	updatedRule := noteChangeRule()
	stableRule := noteChangeStableRule()

	// 基准侧刻意把稳定规则排在前面；新报告反转为更新规则在前，且规则与
	// 检查记录的排列都不同。更新规则换新反例，稳定规则保留原反例。
	before := saveCheckReport(t, dir, artifact, []Rule{stableRule, updatedRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: stableRule.ID, Version: stableRule.Version, Status: StatusDefect, Note: noteChangeStableEvidence},
		{ArtifactHash: hash, RuleID: updatedRule.ID, Version: updatedRule.Version, Status: StatusDefect, Note: noteChangeOldEvidence},
	})
	after := saveCheckReport(t, dir, artifact, []Rule{updatedRule, stableRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: updatedRule.ID, Version: updatedRule.Version, Status: StatusDefect, Note: noteChangeNewEvidence},
		{ArtifactHash: hash, RuleID: stableRule.ID, Version: stableRule.Version, Status: StatusDefect, Note: noteChangeStableEvidence},
	})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}

	// 每个标识恰好一个结果，共两条，按标识排序，与归档排列无关。
	if len(diff.Results) != 2 {
		t.Fatalf("results = %d, want 2: %+v", len(diff.Results), diff.Results)
	}
	ids := make([]string, 0, 2)
	for _, r := range diff.Results {
		ids = append(ids, r.RuleID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}

	updated := entryByID(t, diff, updatedRule.ID)
	if updated.Change != ChangeNoteChanged {
		t.Fatalf("updated rule change = %q, want %q", updated.Change, ChangeNoteChanged)
	}
	stable := entryByID(t, diff, stableRule.ID)
	if stable.Change != ChangeNoChange {
		t.Fatalf("stable rule change = %q, want %q", stable.Change, ChangeNoChange)
	}

	// 证据按规则标识归属：更新规则两侧分别是旧/新反例；稳定规则两侧都是
	// 原反例。任何一侧都不能拿到另一条规则的文字。
	assertSideFinding(t, "updated before", updated.Before, hash, updatedRule, noteChangeOldEvidence)
	assertSideFinding(t, "updated after", updated.After, hash, updatedRule, noteChangeNewEvidence)
	assertSideFinding(t, "stable before", stable.Before, hash, stableRule, noteChangeStableEvidence)
	assertSideFinding(t, "stable after", stable.After, hash, stableRule, noteChangeStableEvidence)
	for _, pair := range []struct {
		where string
		side  *DiffSide
	}{
		{"updated before", updated.Before}, {"updated after", updated.After},
		{"stable before", stable.Before}, {"stable after", stable.After},
	} {
		if pair.side.Finding.RuleID != pair.side.Rule.ID {
			t.Errorf("%s: finding rule id %q does not match its side rule %q",
				pair.where, pair.side.Finding.RuleID, pair.side.Rule.ID)
		}
	}
	if updated.Before.Finding.Evidence == noteChangeStableEvidence ||
		stable.Before.Finding.Evidence == noteChangeOldEvidence ||
		stable.After.Finding.Evidence == noteChangeNewEvidence {
		t.Error("evidence must be associated by rule id, not array position; a side inherited another rule's evidence")
	}

	// 汇总：说明变化只有一条，无变化一条，缺陷两侧总数各为二。
	s := diff.Summary
	if s.NoteChanges != 1 || s.NoChange != 1 {
		t.Errorf("summary = %+v, want noteChanges=1 noChange=1", s)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 ||
		s.AddedRules != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other count must be zero: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 2 {
		t.Errorf("defect totals = %d/%d, want 2/2 (each report kept both defects)",
			s.BeforeDefects, s.AfterDefects)
	}

	// 比较是只读操作：读回任一报告仍看到该次检查保存的反例，归档标识不变。
	for _, want := range []struct {
		id       string
		ruleID   string
		evidence string
	}{
		{before.ReportID, updatedRule.ID, noteChangeOldEvidence},
		{before.ReportID, stableRule.ID, noteChangeStableEvidence},
		{after.ReportID, updatedRule.ID, noteChangeNewEvidence},
		{after.ReportID, stableRule.ID, noteChangeStableEvidence},
	} {
		r, err := LoadReport(dir, want.id)
		if err != nil {
			t.Fatalf("reload %s: %v", want.id, err)
		}
		f, ok := indexFindings(r.Findings)[want.ruleID]
		if !ok {
			t.Fatalf("report %s no longer carries the finding for rule %s", want.id, want.ruleID)
		}
		if f.ArtifactHash != hash || f.Version != updatedOrStableVersion(want.ruleID, updatedRule, stableRule) {
			t.Errorf("reloaded finding binding changed: %+v", f)
		}
		if f.Evidence != want.evidence {
			t.Errorf("reloaded report %s rule %s evidence = %q, want %q verbatim",
				want.id, want.ruleID, f.Evidence, want.evidence)
		}
	}
}

// updatedOrStableVersion 按规则标识返回它在两份归档中一致的版本。
func updatedOrStableVersion(ruleID string, rules ...Rule) string {
	for _, r := range rules {
		if r.ID == ruleID {
			return r.Version
		}
	}
	return ""
}
