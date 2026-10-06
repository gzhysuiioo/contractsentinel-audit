package contractsentinel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件回归保护“缺陷仍然存在，但检查器更新了反例说明”的比较场景：两侧都是
// “发现缺陷”、规则定义（标识、版本及其余字段）完全一致、只有说明原文不同时，
// 必须归为“检查说明变化”，而不能把证据更新误解释成新增或消除缺陷。两侧的
// 缺陷证据各自保留当次归档的反例原文，仍绑定原产物哈希、规则标识与版本。
// 既有说明变化用例（TestDiffNoteChange）覆盖的是“通过”状态，这里保护缺陷状态。

// 两次检查各自的反例说明：中文、换行与前后空格都属于说明内容。
const (
	defectNoteBefore = "反例：攻击者先存入 1 ether 后调用 withdraw；\n  call 在 balances 扣减前交出控制权，receive 重入，同一笔余额被第二次转出。"
	defectNoteAfter  = "反例（更新）：攻击合约 receive 在 balances 扣减前重入 withdraw；\n  此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
)

// defectNoteRules 是两侧共用的一份规则定义，标识、版本及其余字段完全一致。
func defectNoteRules() []Rule {
	return []Rule{{ID: "reentrancy-guard", Kind: "static", Severity: "high", Invariant: "no-reentrant-withdraw", Version: "1.4.2"}}
}

func defectCheck(hash, note string) CheckRecord {
	return CheckRecord{ArtifactHash: hash, RuleID: "reentrancy-guard", Version: "1.4.2", Status: StatusDefect, Note: note}
}

// 核心场景：同一产物、同一条带版本规则，两侧都“发现缺陷”，仅反例说明不同。
// 该规则只出现一次并归为“检查说明变化”；新增/消除缺陷与状态变化均为零，
// 两侧缺陷总数各为一；两份原始证据分别留在各自一侧，不交换、不拼接。
func TestDiffDefectNoteUpdatedKeepsBothEvidences(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := defectNoteRules()
	before := saveCheckReport(t, dir, artifact, rules, []CheckRecord{defectCheck(hash, defectNoteBefore)})
	after := saveCheckReport(t, dir, artifact, rules, []CheckRecord{defectCheck(hash, defectNoteAfter)})

	// 说明不同则报告内容不同，两份报告必须具有不同的报告标识。
	if before.ReportID == after.ReportID {
		t.Fatal("reports with different notes must have different report ids")
	}

	// 比较全程不得改动归档：先记录目录内容快照。
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

	// 基准侧与新侧分别引用各自报告。
	if diff.Before.ReportID != before.ReportID || diff.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", diff.Before.ReportID, diff.After.ReportID, before.ReportID, after.ReportID)
	}
	if diff.ArtifactNameChanged || diff.ArtifactHashChanged {
		t.Error("same artifact must not be flagged as changed")
	}

	// 这条规则只出现一次，归为“检查说明变化”。
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(diff.Results))
	}
	entry := diff.Results[0]
	if entry.RuleID != "reentrancy-guard" {
		t.Fatalf("rule id = %q", entry.RuleID)
	}
	if entry.Change != ChangeNoteChanged {
		t.Fatalf("change = %q, want %q", entry.Change, ChangeNoteChanged)
	}

	// 汇总：说明变化一条；新增缺陷、已消除缺陷、检查状态变化均为零；
	// 两侧缺陷总数各为一（证据更新不是缺陷的增减）。
	s := diff.Summary
	if s.NoteChanges != 1 {
		t.Errorf("noteChanges = %d, want 1", s.NoteChanges)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("evidence update must not count as defect or status change: %+v", s)
	}
	if s.NoChange != 0 || s.AddedRules != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("unexpected counts: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}

	// 基准侧保留旧反例，新侧保留新反例；两侧缺陷仍绑定原来的产物哈希、
	// 规则标识与版本。旧侧证据不能换成新侧文字，两份说明也不能拼成一份证据。
	if entry.Before == nil || entry.After == nil {
		t.Fatal("both sides must be present")
	}
	if entry.Before.Rule.Status != StatusDefect || entry.After.Rule.Status != StatusDefect {
		t.Errorf("statuses = %q/%q, both must be %q", entry.Before.Rule.Status, entry.After.Rule.Status, StatusDefect)
	}
	if entry.Before.Rule.Note != defectNoteBefore {
		t.Errorf("before note = %q, want the old counterexample verbatim", entry.Before.Rule.Note)
	}
	if entry.After.Rule.Note != defectNoteAfter {
		t.Errorf("after note = %q, want the new counterexample verbatim", entry.After.Rule.Note)
	}
	if entry.Before.Finding == nil || entry.After.Finding == nil {
		t.Fatal("both defect sides must carry their findings")
	}
	bf, af := entry.Before.Finding, entry.After.Finding
	if bf.Evidence != defectNoteBefore {
		t.Errorf("before evidence = %q, want the old counterexample verbatim", bf.Evidence)
	}
	if af.Evidence != defectNoteAfter {
		t.Errorf("after evidence = %q, want the new counterexample verbatim", af.Evidence)
	}
	for side, f := range map[string]*ReportFinding{"before": bf, "after": af} {
		if f.ArtifactHash != hash || f.RuleID != "reentrancy-guard" || f.Version != "1.4.2" {
			t.Errorf("%s finding binding = %+v, want hash=%q rule=reentrancy-guard version=1.4.2", side, *f, hash)
		}
	}
	if strings.Contains(bf.Evidence, defectNoteAfter) || strings.Contains(af.Evidence, defectNoteBefore) {
		t.Error("evidences must not be swapped or merged into one")
	}

	// 比较后的归档内容保持原样。
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

	// 读回任一报告仍能看到该次检查保存的反例。
	reloadedBefore, err := LoadReport(dir, before.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	reloadedAfter, err := LoadReport(dir, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedBefore.Rules[0].Note != defectNoteBefore || reloadedBefore.Findings[0].Evidence != defectNoteBefore {
		t.Errorf("reloaded before report lost its counterexample: %+v / %+v", reloadedBefore.Rules[0], reloadedBefore.Findings[0])
	}
	if reloadedAfter.Rules[0].Note != defectNoteAfter || reloadedAfter.Findings[0].Evidence != defectNoteAfter {
		t.Errorf("reloaded after report lost its counterexample: %+v / %+v", reloadedAfter.Rules[0], reloadedAfter.Findings[0])
	}
}

// 说明按原文比较：仅增加一个尾随空格也属于说明变化，两侧文字逐字保留。
func TestDiffDefectNoteTrailingSpaceIsNoteChange(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := defectNoteRules()
	base := "反例：重入路径仍可达\n  第二行证据"
	before := saveCheckReport(t, dir, artifact, rules, []CheckRecord{defectCheck(hash, base)})
	after := saveCheckReport(t, dir, artifact, rules, []CheckRecord{defectCheck(hash, base+" ")})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeNoteChanged {
		t.Fatalf("a trailing space is a note change: %+v", diff.Results)
	}
	if diff.Summary.NoteChanges != 1 || diff.Summary.NoChange != 0 {
		t.Errorf("summary = %+v", diff.Summary)
	}
	if diff.Summary.BeforeDefects != 1 || diff.Summary.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", diff.Summary.BeforeDefects, diff.Summary.AfterDefects)
	}
	entry := diff.Results[0]
	if entry.Before.Rule.Note != base || entry.Before.Finding.Evidence != base {
		t.Errorf("before side must keep the note verbatim without trailing space: %q", entry.Before.Rule.Note)
	}
	if entry.After.Rule.Note != base+" " || entry.After.Finding.Evidence != base+" " {
		t.Errorf("after side must keep the trailing space verbatim: %q", entry.After.Rule.Note)
	}
}

// 原文完全相同（同一份报告在两侧）则归为“无变化”，不增加说明变化计数。
func TestDiffDefectIdenticalNoteIsNoChange(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	report := saveCheckReport(t, dir, artifact, defectNoteRules(), []CheckRecord{defectCheck(hash, defectNoteBefore)})

	diff, err := DiffStore(dir, report.ReportID, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeNoChange {
		t.Fatalf("identical notes must be no change: %+v", diff.Results)
	}
	s := diff.Summary
	if s.NoteChanges != 0 || s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("identical evidence must not fabricate changes: %+v", s)
	}
	if s.NoChange != 1 || s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("summary = %+v, want noChange=1 defects=1/1", s)
	}
	entry := diff.Results[0]
	if entry.Before.Finding == nil || entry.After.Finding == nil ||
		entry.Before.Finding.Evidence != defectNoteBefore || entry.After.Finding.Evidence != defectNoteBefore {
		t.Errorf("both sides must keep the same evidence: %+v / %+v", entry.Before.Finding, entry.After.Finding)
	}
}

// 分类边界：两侧都发现缺陷且说明不同，但规则版本已变化时仍归为“规则变化”，
// 不同时计为说明变化；两侧各自保留自己的反例证据与版本绑定。
func TestDiffDefectNoteChangeWithVersionBumpIsRuleChange(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	before := saveCheckReport(t, dir, artifact, defectNoteRules(),
		[]CheckRecord{defectCheck(hash, defectNoteBefore)})
	afterRules := []Rule{{ID: "reentrancy-guard", Kind: "static", Severity: "high", Invariant: "no-reentrant-withdraw", Version: "1.4.3"}}
	after := saveCheckReport(t, dir, artifact, afterRules,
		[]CheckRecord{{ArtifactHash: hash, RuleID: "reentrancy-guard", Version: "1.4.3", Status: StatusDefect, Note: defectNoteAfter}})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 || diff.Results[0].Change != ChangeRuleChanged {
		t.Fatalf("version bump must stay 规则变化: %+v", diff.Results)
	}
	s := diff.Summary
	if s.ChangedRules != 1 || s.NoteChanges != 0 {
		t.Errorf("changedRules = %d, noteChanges = %d, want 1/0", s.ChangedRules, s.NoteChanges)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("rule change must not count as defect or status change: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}
	entry := diff.Results[0]
	if entry.Before.Finding == nil || entry.Before.Finding.Evidence != defectNoteBefore ||
		entry.Before.Finding.Version != "1.4.2" {
		t.Errorf("before side must keep the old evidence at the old version: %+v", entry.Before.Finding)
	}
	if entry.After.Finding == nil || entry.After.Finding.Evidence != defectNoteAfter ||
		entry.After.Finding.Version != "1.4.3" {
		t.Errorf("after side must keep the new evidence at the new version: %+v", entry.After.Finding)
	}
}

// 同一份比较中的不同规则互不影响：一条规则更新反例，另一条保留原有缺陷
// 证据时后者保持“无变化”；两侧缺陷总数各为二，说明变化仍只有一条。两份
// 归档中规则与缺陷的排列刻意不同，输出必须按规则标识关联各自的证据。
func TestDiffDefectNoteChangeMatchesEvidenceByRuleID(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	stableNote := "反例：owner 校验缺失，任意账户可调用 withdraw。"
	updatedRule := Rule{ID: "reentrancy-guard", Kind: "static", Severity: "high", Invariant: "no-reentrant-withdraw", Version: "1.4.2"}
	stableRule := Rule{ID: "owner-only-withdraw", Kind: "static", Severity: "medium", Invariant: "withdraw-owner-only", Version: "2.1.0"}
	updatedCheck := func(note string) CheckRecord {
		return CheckRecord{ArtifactHash: hash, RuleID: updatedRule.ID, Version: updatedRule.Version, Status: StatusDefect, Note: note}
	}
	stableCheck := CheckRecord{ArtifactHash: hash, RuleID: stableRule.ID, Version: stableRule.Version, Status: StatusDefect, Note: stableNote}

	// 两侧规则与 checks 的提交排列刻意相反，归档中的数组顺序因此不同。
	before := saveCheckReport(t, dir, artifact,
		[]Rule{updatedRule, stableRule},
		[]CheckRecord{updatedCheck(defectNoteBefore), stableCheck})
	after := saveCheckReport(t, dir, artifact,
		[]Rule{stableRule, updatedRule},
		[]CheckRecord{stableCheck, updatedCheck(defectNoteAfter)})

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

	// 更新反例的规则归为“检查说明变化”，两侧证据各自保留。
	updated := byID[updatedRule.ID]
	if updated.Change != ChangeNoteChanged {
		t.Errorf("updated rule change = %q, want %q", updated.Change, ChangeNoteChanged)
	}
	if updated.Before.Finding == nil || updated.Before.Finding.Evidence != defectNoteBefore ||
		updated.After.Finding == nil || updated.After.Finding.Evidence != defectNoteAfter {
		t.Errorf("updated rule evidences = %+v / %+v", updated.Before.Finding, updated.After.Finding)
	}

	// 保留原有证据的规则保持“无变化”，其证据不能按数组位置串到另一条规则。
	stable := byID[stableRule.ID]
	if stable.Change != ChangeNoChange {
		t.Errorf("stable rule change = %q, want %q", stable.Change, ChangeNoChange)
	}
	if stable.Before.Finding == nil || stable.Before.Finding.Evidence != stableNote ||
		stable.After.Finding == nil || stable.After.Finding.Evidence != stableNote {
		t.Errorf("stable rule evidences = %+v / %+v, want %q on both sides",
			stable.Before.Finding, stable.After.Finding, stableNote)
	}
	if stable.Before.Rule.Note != stableNote || stable.After.Rule.Note != stableNote {
		t.Errorf("stable rule notes = %q / %q", stable.Before.Rule.Note, stable.After.Rule.Note)
	}
	for side, f := range map[string]*ReportFinding{"before": stable.Before.Finding, "after": stable.After.Finding} {
		if f.RuleID != stableRule.ID || f.Version != stableRule.Version || f.ArtifactHash != hash {
			t.Errorf("stable %s finding binding = %+v", side, *f)
		}
	}

	// 汇总：说明变化仍只有一条；两侧缺陷总数各为二。
	s := diff.Summary
	if s.NoteChanges != 1 || s.NoChange != 1 {
		t.Errorf("noteChanges/noChange = %d/%d, want 1/1", s.NoteChanges, s.NoChange)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 || s.ChangedRules != 0 {
		t.Errorf("unexpected counts: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 2 {
		t.Errorf("defect totals = %d/%d, want 2/2", s.BeforeDefects, s.AfterDefects)
	}

	// 比较后读回两份归档，各自仍能看到该次检查保存的两条反例。
	reloadedBefore, err := LoadReport(dir, before.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	reloadedAfter, err := LoadReport(dir, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	evidenceByRule := func(r Report) map[string]string {
		out := map[string]string{}
		for _, f := range r.Findings {
			out[f.RuleID] = f.Evidence
		}
		return out
	}
	beforeEvidence := evidenceByRule(reloadedBefore)
	if beforeEvidence[updatedRule.ID] != defectNoteBefore || beforeEvidence[stableRule.ID] != stableNote {
		t.Errorf("reloaded before evidences = %v", beforeEvidence)
	}
	afterEvidence := evidenceByRule(reloadedAfter)
	if afterEvidence[updatedRule.ID] != defectNoteAfter || afterEvidence[stableRule.ID] != stableNote {
		t.Errorf("reloaded after evidences = %v", afterEvidence)
	}
}
