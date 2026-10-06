package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护“缺陷仍然存在，但检查器更新了反例
// 说明”：同一合约产物、同一条标识/版本/定义完全一致的规则，两次检查状态均
// 为“发现缺陷”、只有说明原文不同。比较必须归为“检查说明变化”，新增/消除
// 缺陷与检查状态变化均为零，两侧缺陷总数各为一；基准侧与新侧各自保留当次
// 归档的反例证据，既不交换也不拼接。既有说明变化用例使用通过状态，这里保护
// 缺陷状态下的证据更新不被误解释为缺陷增减。

// 两次检查各自的反例说明：中文、换行与前后空格都属于说明内容。
const (
	cliDefectNoteBefore = "反例：攻击者先存入 1 ether 后调用 withdraw；\n  call 在 balances 扣减前交出控制权，receive 重入，同一笔余额被第二次转出。"
	cliDefectNoteAfter  = "反例（更新）：攻击合约 receive 在 balances 扣减前重入 withdraw；\n  此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
)

// cliDefectNoteRule 是两侧共用的同一条规则定义，标识、版本及其余字段一致。
func cliDefectNoteRule() cliWireRule {
	return cliWireRule{
		ID:        "reentrancy-guard",
		Kind:      "static",
		Severity:  "high",
		Invariant: "no-reentrant-withdraw",
		Version:   "1.4.2",
	}
}

// TestCLIDiffDefectNoteUpdatedKeepsBothEvidences 覆盖核心场景：两侧都发现
// 缺陷、仅反例说明更新时，比较分类、缺陷计数与两份原始证据的关系。
func TestCLIDiffDefectNoteUpdatedKeepsBothEvidences(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rule := cliDefectNoteRule()

	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
			Status: contractsentinel.StatusDefect, Note: cliDefectNoteBefore}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
			Status: contractsentinel.StatusDefect, Note: cliDefectNoteAfter}})

	// 说明不同则两份报告必须具有不同的报告标识。
	if before.ReportID == after.ReportID {
		t.Fatal("reports with different notes must have different report ids")
	}

	// 归档快照：比较全程不得改动任何已保存的报告。
	snapshot := func(t *testing.T) map[string]string {
		t.Helper()
		names, err := listFiles(store)
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(names)
		out := map[string]string{}
		for _, name := range names {
			data, err := os.ReadFile(filepath.Join(store, name))
			if err != nil {
				t.Fatal(err)
			}
			out[name] = string(data)
		}
		return out
	}
	original := snapshot(t)

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	// 基准侧与新侧分别引用对应报告，产物为同一份。
	if d.Before.ReportID != before.ReportID || d.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", d.Before.ReportID, d.After.ReportID, before.ReportID, after.ReportID)
	}
	if d.ArtifactNameChanged || d.ArtifactHashChanged {
		t.Error("same artifact must not be flagged changed")
	}

	// 这条规则只出现一次，归为“检查说明变化”。
	if len(d.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(d.Results))
	}
	entry := d.Results[0]
	if entry.RuleID != rule.ID {
		t.Fatalf("rule id = %q, want %q", entry.RuleID, rule.ID)
	}
	if entry.Change != contractsentinel.ChangeNoteChanged {
		t.Fatalf("change = %q, want %q", entry.Change, contractsentinel.ChangeNoteChanged)
	}

	// 汇总：说明变化一条；新增缺陷、已消除缺陷、检查状态变化均为零；
	// 两侧缺陷总数各为一。
	s := d.Summary
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
	// 规则标识与版本，旧侧证据不能换成新侧文字，两份说明不能拼成一份证据。
	if entry.Before == nil || entry.After == nil {
		t.Fatal("both sides must be present")
	}
	if entry.Before.Rule.Status != contractsentinel.StatusDefect ||
		entry.After.Rule.Status != contractsentinel.StatusDefect {
		t.Errorf("statuses = %q/%q, both must be 发现缺陷", entry.Before.Rule.Status, entry.After.Rule.Status)
	}
	if entry.Before.Rule.Note != cliDefectNoteBefore || entry.After.Rule.Note != cliDefectNoteAfter {
		t.Errorf("notes = %q / %q, each side must keep its own counterexample",
			entry.Before.Rule.Note, entry.After.Rule.Note)
	}
	if entry.Before.Finding == nil || entry.After.Finding == nil {
		t.Fatal("both defect sides must carry their findings")
	}
	bf, af := entry.Before.Finding, entry.After.Finding
	if bf.Evidence != cliDefectNoteBefore || af.Evidence != cliDefectNoteAfter {
		t.Errorf("evidences = %q / %q, each side must keep its own counterexample verbatim",
			bf.Evidence, af.Evidence)
	}
	for side, f := range map[string]*contractsentinel.ReportFinding{"before": bf, "after": af} {
		if f.ArtifactHash != hash || f.RuleID != rule.ID || f.Version != rule.Version {
			t.Errorf("%s finding binding = %+v, want hash=%q rule=%q version=%q",
				side, *f, hash, rule.ID, rule.Version)
		}
	}
	if strings.Contains(bf.Evidence, cliDefectNoteAfter) || strings.Contains(af.Evidence, cliDefectNoteBefore) {
		t.Error("evidences must not be swapped or merged into one")
	}

	// 原始输出字节层面：两份反例的中文、换行（JSON 转义为 \n）与前后空格
	// 都逐字保留，各自完整出现。
	for _, evidence := range []string{cliDefectNoteBefore, cliDefectNoteAfter} {
		escaped := strings.ReplaceAll(evidence, "\n", `\n`)
		if !strings.Contains(stdout, escaped) {
			t.Errorf("diff output must preserve the evidence verbatim %q:\n%s", evidence, stdout)
		}
	}

	// 比较后的归档内容保持原样。
	afterSnapshot := snapshot(t)
	if len(afterSnapshot) != len(original) {
		t.Fatalf("store file set changed by diff")
	}
	for name, data := range original {
		if afterSnapshot[name] != data {
			t.Errorf("diff modified archive %s", name)
		}
	}

	// 用户读回任一报告时仍能看到该次检查保存的反例。
	for _, tc := range []struct {
		name   string
		id     string
		notice string
	}{
		{"before", before.ReportID, cliDefectNoteBefore},
		{"after", after.ReportID, cliDefectNoteAfter},
	} {
		t.Run("readback-"+tc.name, func(t *testing.T) {
			reportOut, reportErr, reportCode := runCLIReport(t, bin, store, tc.id)
			if reportCode != 0 {
				t.Fatalf("report readback must succeed, exit=%d stderr=%s", reportCode, reportErr)
			}
			reloaded := decodeReport(t, reportOut)
			if len(reloaded.Rules) != 1 || len(reloaded.Findings) != 1 {
				t.Fatalf("reloaded report shape = %+v", reloaded)
			}
			if reloaded.Rules[0].Note != tc.notice || reloaded.Findings[0].Evidence != tc.notice {
				t.Errorf("readback lost its counterexample: note=%q evidence=%q, want %q",
					reloaded.Rules[0].Note, reloaded.Findings[0].Evidence, tc.notice)
			}
			if reloaded.Findings[0].ArtifactHash != hash || reloaded.Findings[0].RuleID != rule.ID ||
				reloaded.Findings[0].Version != rule.Version {
				t.Errorf("readback finding binding = %+v", reloaded.Findings[0])
			}
		})
	}
}

// TestCLIDiffDefectNoteTrailingSpaceIsNoteChange 在进程边界上固定说明按原文
// 比较的边界：仅增加一个尾随空格也属于说明变化，两侧文字逐字保留。
func TestCLIDiffDefectNoteTrailingSpaceIsNoteChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rule := cliDefectNoteRule()
	base := "反例：重入路径仍可达\n  第二行证据"

	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
			Status: contractsentinel.StatusDefect, Note: base}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
			Status: contractsentinel.StatusDefect, Note: base + " "}})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 || d.Results[0].Change != contractsentinel.ChangeNoteChanged {
		t.Fatalf("a trailing space is a note change: %+v", d.Results)
	}
	if d.Summary.NoteChanges != 1 || d.Summary.BeforeDefects != 1 || d.Summary.AfterDefects != 1 {
		t.Errorf("summary = %+v, want noteChanges=1 defects=1/1", d.Summary)
	}
	entry := d.Results[0]
	if entry.Before.Rule.Note != base || entry.Before.Finding == nil || entry.Before.Finding.Evidence != base {
		t.Errorf("before side must keep the note verbatim without trailing space: %+v", entry.Before)
	}
	if entry.After.Rule.Note != base+" " || entry.After.Finding == nil || entry.After.Finding.Evidence != base+" " {
		t.Errorf("after side must keep the trailing space verbatim: %+v", entry.After)
	}
	// 字节层面：带尾随空格的新证据逐字出现在输出里（JSON 转义后空格仍在）。
	escaped := strings.ReplaceAll(base+" ", "\n", `\n`)
	if !strings.Contains(stdout, escaped) {
		t.Errorf("diff output must preserve the trailing space verbatim:\n%s", stdout)
	}
}

// TestCLIDiffDefectNoteChangeWithVersionBumpIsRuleChange 固定分类边界：两侧
// 都发现缺陷且说明不同，但规则版本已变化时仍归为“规则变化”，不计说明变化。
func TestCLIDiffDefectNoteChangeWithVersionBumpIsRuleChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	beforeRule := cliDefectNoteRule()
	afterRule := cliDefectNoteRule()
	afterRule.Version = "1.4.3"

	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{beforeRule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: beforeRule.ID, Version: beforeRule.Version,
			Status: contractsentinel.StatusDefect, Note: cliDefectNoteBefore}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{afterRule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: afterRule.ID, Version: afterRule.Version,
			Status: contractsentinel.StatusDefect, Note: cliDefectNoteAfter}})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 || d.Results[0].Change != contractsentinel.ChangeRuleChanged {
		t.Fatalf("version bump must stay 规则变化: %+v", d.Results)
	}
	s := d.Summary
	if s.ChangedRules != 1 || s.NoteChanges != 0 {
		t.Errorf("changedRules/noteChanges = %d/%d, want 1/0", s.ChangedRules, s.NoteChanges)
	}
	if s.NewDefects != 0 || s.ResolvedDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("rule change must not count as defect or status change: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 1/1", s.BeforeDefects, s.AfterDefects)
	}
	entry := d.Results[0]
	if entry.Before.Finding == nil || entry.Before.Finding.Evidence != cliDefectNoteBefore ||
		entry.Before.Finding.Version != "1.4.2" {
		t.Errorf("before side must keep the old evidence at the old version: %+v", entry.Before.Finding)
	}
	if entry.After.Finding == nil || entry.After.Finding.Evidence != cliDefectNoteAfter ||
		entry.After.Finding.Version != "1.4.3" {
		t.Errorf("after side must keep the new evidence at the new version: %+v", entry.After.Finding)
	}
}
