package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护“缺陷仍然存在，但检查器更新了反例
// 说明”的口径：同一规则标识在基准报告与新报告中都是“发现缺陷”，规则定义
// 完全一致，只有说明原文不同。diff 必须把该规则归为“检查说明变化”且只出现
// 一次，不能把证据更新误解释为新增或消除缺陷：汇总中说明变化为一，新增
// 缺陷、已消除缺陷和检查状态变化均为零，两侧缺陷总数各为一。两份报告由真实
// audit 命令两次独立归档，具有不同的报告标识，diff 输出的基准侧与新侧分别
// 引用对应报告；旧侧规则说明与缺陷证据保留旧反例、新侧保留新反例，各自的
// 缺陷仍绑定原来的产物哈希、规则标识和版本。
//
// 说明按原文比较：中文、换行和前后空格都属于内容。仅多一个尾随空格也是说明
// 变化；原文完全相同则为“无变化”。两侧都发现缺陷且说明不同、但规则版本变化
// 时沿用“规则变化”，不同时计为说明变化。同一份比较中另一条保留原证据的
// 规则必须仍是“无变化”，证据按规则标识归属，与归档排列无关。既有报告格式、
// 报告标识与基准/新比较方向保持兼容。

// 旧反例与新反例刻意包含中文、换行与前后空格，任何修剪、替换或拼接都会被
// 抓到；对照规则的证据与两者都不同，防止证据按数组位置串规则。
const cliNoteOldEvidence = "  旧反例：第一次检查的调用路径\nattacker.drain() 后余额归零  "
const cliNoteNewEvidence = "  新反例：复跑得到更短路径\nattacker.directTransfer() 直接转走  "
const cliNoteStableEvidence = "  稳定缺陷：两次检查都是这条反例\n第二行  "

// cliNoteChangeRules 构造同一份产物上的两条规则：updated-id 两次检查都发现
// 缺陷但换新反例；stable-id 两次检查都发现缺陷且保留同一反例。
func cliNoteChangeRules() []cliWireRule {
	return []cliWireRule{
		{ID: "note-updated-reentrancy", Kind: "static", Severity: "high", Invariant: "no-reentrant-drain", RequiresABI: true, Version: "5.4.0"},
		{ID: "note-stable-access", Kind: "static", Severity: "medium", Invariant: "owner-only-settle", Version: "2.7.1"},
	}
}

// assertCLISideFinding 校验 diff 一侧的状态、说明及缺陷绑定（产物哈希、规则
// 标识、版本、逐字证据）。
func assertCLISideFinding(t *testing.T, where string, side *contractsentinel.DiffSide, hash, ruleID, version, evidence string) {
	t.Helper()
	if side == nil {
		t.Fatalf("%s: side must be present", where)
	}
	if side.Rule.ID != ruleID || side.Rule.Version != version {
		t.Errorf("%s: rule = id %q version %q, want %q/%q", where, side.Rule.ID, side.Rule.Version, ruleID, version)
	}
	if side.Rule.Status != contractsentinel.StatusDefect {
		t.Errorf("%s: status = %q, want %q", where, side.Rule.Status, contractsentinel.StatusDefect)
	}
	if side.Rule.Note != evidence {
		t.Errorf("%s: note = %q, want %q verbatim", where, side.Rule.Note, evidence)
	}
	if side.Finding == nil {
		t.Fatalf("%s: defect side must keep its finding", where)
	}
	if side.Finding.ArtifactHash != hash || side.Finding.RuleID != ruleID || side.Finding.Version != version {
		t.Errorf("%s: finding binding = %+v, want hash=%q rule=%q version=%q", where, side.Finding, hash, ruleID, version)
	}
	if side.Finding.Evidence != evidence {
		t.Errorf("%s: evidence = %q, want %q verbatim", where, side.Finding.Evidence, evidence)
	}
}

// TestCLIDiffBothSidesDefectRewordedEvidenceIsNoteChange 在进程边界覆盖核心
// 口径：两条规则两侧都是发现缺陷，一条换新反例（检查说明变化）、一条保留原
// 反例（无变化）。规则与检查记录在两份归档中的排列刻意不同。
func TestCLIDiffBothSidesDefectRewordedEvidenceIsNoteChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := cliNoteChangeRules()
	updatedRule, stableRule := rules[0], rules[1]

	// 两份归档的规则与检查记录排列刻意不同；更新规则旧/新反例不同，稳定
	// 规则两次都是同一反例。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{stableRule, updatedRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: stableRule.ID, Version: stableRule.Version, Status: contractsentinel.StatusDefect, Note: cliNoteStableEvidence},
			{ArtifactHash: hash, RuleID: updatedRule.ID, Version: updatedRule.Version, Status: contractsentinel.StatusDefect, Note: cliNoteOldEvidence},
		})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{updatedRule, stableRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: updatedRule.ID, Version: updatedRule.Version, Status: contractsentinel.StatusDefect, Note: cliNoteNewEvidence},
			{ArtifactHash: hash, RuleID: stableRule.ID, Version: stableRule.Version, Status: contractsentinel.StatusDefect, Note: cliNoteStableEvidence},
		})

	// 两次独立归档必须具有不同的报告标识。
	if before.ReportID == after.ReportID {
		t.Fatalf("two reports with different evidence must have distinct report ids, both %q", before.ReportID)
	}

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	// 报告标识与比较方向按命令行参数保留；两侧为同一产物。
	if d.Before.ReportID != before.ReportID || d.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", d.Before.ReportID, d.After.ReportID, before.ReportID, after.ReportID)
	}
	if d.ArtifactNameChanged || d.ArtifactHashChanged {
		t.Error("same artifact must not be flagged changed")
	}

	// 每个标识恰好一个结果，共两条，按标识排序。
	if len(d.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(d.Results))
	}
	ids := make([]string, 0, 2)
	for _, r := range d.Results {
		ids = append(ids, r.RuleID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}

	updated := diffEntry(t, d, updatedRule.ID)
	if updated.Change != contractsentinel.ChangeNoteChanged {
		t.Fatalf("updated rule change = %q, want %q", updated.Change, contractsentinel.ChangeNoteChanged)
	}
	stable := diffEntry(t, d, stableRule.ID)
	if stable.Change != contractsentinel.ChangeNoChange {
		t.Fatalf("stable rule change = %q, want %q", stable.Change, contractsentinel.ChangeNoChange)
	}

	// 两侧都是发现缺陷：更新规则旧侧保留旧反例、新侧保留新反例，绑定各自
	// 的产物哈希、规则标识和版本；不能交叉替换或拼接。
	assertCLISideFinding(t, "updated before", updated.Before, hash, updatedRule.ID, updatedRule.Version, cliNoteOldEvidence)
	assertCLISideFinding(t, "updated after", updated.After, hash, updatedRule.ID, updatedRule.Version, cliNoteNewEvidence)
	assertCLISideFinding(t, "stable before", stable.Before, hash, stableRule.ID, stableRule.Version, cliNoteStableEvidence)
	assertCLISideFinding(t, "stable after", stable.After, hash, stableRule.ID, stableRule.Version, cliNoteStableEvidence)
	if strings.Contains(updated.Before.Finding.Evidence, "directTransfer") ||
		strings.Contains(updated.After.Finding.Evidence, "drain()") {
		t.Errorf("updated sides must each keep their own evidence, not a merge: before=%q after=%q",
			updated.Before.Finding.Evidence, updated.After.Finding.Evidence)
	}

	// 汇总：说明变化只有一条、无变化一条；新增/已消除缺陷与检查状态变化均
	// 为零；两侧缺陷总数各为二。
	s := d.Summary
	if s.NoteChanges != 1 || s.NoChange != 1 {
		t.Errorf("summary = %+v, want noteChanges=1 noChange=1", s)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("reworded counterexamples must not be read as defect/status transitions: %+v", s)
	}
	if s.AddedRules != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("same rule definitions must not add/remove/change rules: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 2 {
		t.Errorf("defect totals = %d/%d, want 2/2", s.BeforeDefects, s.AfterDefects)
	}

	// 原始输出字节层面：旧反例与新反例各自逐字出现（JSON 中换行转义为
	// \n），中文、前后空格保留；两份说明不会拼成一段。
	if !strings.Contains(stdout, "  旧反例：第一次检查的调用路径\\nattacker.drain() 后余额归零  ") {
		t.Errorf("diff output must preserve the old evidence verbatim:\n%s", stdout)
	}
	if !strings.Contains(stdout, "  新反例：复跑得到更短路径\\nattacker.directTransfer() 直接转走  ") {
		t.Errorf("diff output must preserve the new evidence verbatim:\n%s", stdout)
	}

	// 比较是只读操作：用 report 命令读回任一报告，仍看到该次检查保存的反例。
	for _, tc := range []struct {
		id       string
		ruleID   string
		evidence string
	}{
		{before.ReportID, updatedRule.ID, cliNoteOldEvidence},
		{after.ReportID, updatedRule.ID, cliNoteNewEvidence},
	} {
		out, rerr, rcode := runCLIReport(t, bin, store, tc.id)
		if rcode != 0 {
			t.Fatalf("report %s must remain readable after diff: %s", tc.id, rerr)
		}
		r := decodeReport(t, out)
		var found *contractsentinel.ReportFinding
		for i := range r.Findings {
			if r.Findings[i].RuleID == tc.ruleID {
				found = &r.Findings[i]
			}
		}
		if found == nil {
			t.Fatalf("report %s must keep the finding for rule %s", tc.id, tc.ruleID)
		}
		if found.ArtifactHash != hash || found.Version != "5.4.0" {
			t.Errorf("reloaded finding binding = %+v", found)
		}
		if found.Evidence != tc.evidence {
			t.Errorf("reloaded evidence = %q, want %q verbatim", found.Evidence, tc.evidence)
		}
	}
}

// TestCLIDiffRewordedEvidenceTrailingSpaceIsNoteChange 仅多一个尾随空格也
// 必须归为检查说明变化，两侧文字逐字保留，缺陷两侧都在。
func TestCLIDiffRewordedEvidenceTrailingSpaceIsNoteChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rule := cliNoteChangeRules()[0]
	withTrailingSpace := cliNoteOldEvidence + " "

	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version, Status: contractsentinel.StatusDefect, Note: cliNoteOldEvidence}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version, Status: contractsentinel.StatusDefect, Note: withTrailingSpace}})
	if before.ReportID == after.ReportID {
		t.Fatal("a trailing-space difference must produce a distinct report id")
	}

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 || d.Results[0].Change != contractsentinel.ChangeNoteChanged {
		t.Fatalf("results = %+v, want one %s", d.Results, contractsentinel.ChangeNoteChanged)
	}
	s := d.Summary
	if s.NoteChanges != 1 || s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("a single trailing space is a note change, not a defect transition: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}
	entry := d.Results[0]
	assertCLISideFinding(t, "before side", entry.Before, hash, rule.ID, rule.Version, cliNoteOldEvidence)
	assertCLISideFinding(t, "after side", entry.After, hash, rule.ID, rule.Version, withTrailingSpace)
}

// TestCLIDiffIdenticalEvidenceOnBothSidesIsNoChange 原文完全相同的对照：两侧
// 都发现缺陷且说明逐字一致时归为“无变化”，不增加说明变化计数。
func TestCLIDiffIdenticalEvidenceOnBothSidesIsNoChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rule := cliNoteChangeRules()[0]

	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version, Status: contractsentinel.StatusDefect, Note: cliNoteOldEvidence}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version, Status: contractsentinel.StatusDefect, Note: cliNoteOldEvidence}})
	if before.ReportID != after.ReportID {
		t.Fatalf("identical content must share one report id, got %q vs %q", before.ReportID, after.ReportID)
	}

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 || d.Results[0].Change != contractsentinel.ChangeNoChange {
		t.Fatalf("results = %+v, want one %s", d.Results, contractsentinel.ChangeNoChange)
	}
	s := d.Summary
	if s.NoteChanges != 0 || s.NoChange != 1 {
		t.Errorf("summary = %+v, want noteChanges=0 noChange=1", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}
}

// TestCLIDiffBothSidesDefectVersionChangeWinsOverNoteChange 分类优先级边界：
// 两侧都发现缺陷且说明不同，但规则版本变化时沿用“规则变化”，不同时计为说明
// 变化；两侧证据仍各自保留。
func TestCLIDiffBothSidesDefectVersionChangeWinsOverNoteChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	beforeRule := cliNoteChangeRules()[0]
	afterRule := beforeRule
	afterRule.Version = "5.5.0"

	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{beforeRule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: beforeRule.ID, Version: beforeRule.Version, Status: contractsentinel.StatusDefect, Note: cliNoteOldEvidence}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{afterRule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: afterRule.ID, Version: afterRule.Version, Status: contractsentinel.StatusDefect, Note: cliNoteNewEvidence}})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 || d.Results[0].Change != contractsentinel.ChangeRuleChanged {
		t.Fatalf("results = %+v, want one %s", d.Results, contractsentinel.ChangeRuleChanged)
	}
	s := d.Summary
	if s.ChangedRules != 1 || s.NoteChanges != 0 {
		t.Errorf("summary = %+v, want changedRules=1 noteChanges=0", s)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("a version change must not be read as a defect transition: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}
	entry := d.Results[0]
	assertCLISideFinding(t, "before side", entry.Before, hash, beforeRule.ID, beforeRule.Version, cliNoteOldEvidence)
	assertCLISideFinding(t, "after side", entry.After, hash, afterRule.ID, afterRule.Version, cliNoteNewEvidence)
}
