package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护“规则变化”与“已消除缺陷”的区分：
// 同一规则标识在基准报告为“发现缺陷”、新报告为“通过”时，只有两侧完整规则
// 定义一致才是“已消除缺陷”；只改一项定义（这里刻意保持版本字符串不变、只
// 改严重级别）必须是“规则变化”。两侧报告都通过真实 audit 命令正常归档，再
// 由 diff 命令读回比较，既有报告格式、报告标识与基准/新比较方向保持兼容。

// cliRuleChangeRule 构造一条需要 ABI 的规则；两份报告都审计同一带 ABI 的
// 产物（mixedCheckArtifact），因此需要 ABI 的规则可以正常保存和读回。
func cliRuleChangeRule(severity string) cliWireRule {
	return cliWireRule{
		ID:          "reentrancy-guard",
		Kind:        "static",
		Severity:    severity,
		Invariant:   "no-reentrant-withdraw",
		RequiresABI: true,
		Version:     "10.2.0", // 漂移用例中版本字符串刻意保持不变
	}
}

// TestCLIDiffDefinitionDriftWithSameVersionIsRuleChange 在进程边界上覆盖：
// 版本字符串未变、严重级别已经改变时，发现缺陷 -> 通过只能记为“规则变化”。
func TestCLIDiffDefinitionDriftWithSameVersionIsRuleChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)

	beforeRule := cliRuleChangeRule("high")
	afterRule := cliRuleChangeRule("critical") // 只改严重级别，其余定义相同
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{beforeRule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: beforeRule.ID, Version: beforeRule.Version,
			Status: contractsentinel.StatusDefect, Note: resolvedEvidence}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{afterRule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: afterRule.ID, Version: afterRule.Version,
			Status: contractsentinel.StatusPass}})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	// 报告标识与比较方向按命令行参数保留，两侧产物为同一带 ABI 的产物。
	if d.Before.ReportID != before.ReportID || d.After.ReportID != after.ReportID {
		t.Errorf("refs = %q/%q, want %q/%q", d.Before.ReportID, d.After.ReportID, before.ReportID, after.ReportID)
	}
	if d.ArtifactNameChanged || d.ArtifactHashChanged {
		t.Error("same artifact must not be flagged changed")
	}

	if len(d.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(d.Results))
	}
	entry := d.Results[0]
	if entry.Change != contractsentinel.ChangeRuleChanged {
		t.Fatalf("change = %q, want %q", entry.Change, contractsentinel.ChangeRuleChanged)
	}

	// 计数：规则变化为一；已消除缺陷、新发现缺陷、检查状态变化均为零。
	s := d.Summary
	if s.ChangedRules != 1 {
		t.Errorf("changedRules = %d, want 1", s.ChangedRules)
	}
	if s.ResolvedDefects != 0 || s.NewDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("defect/status transitions must be zero when the definition changed: %+v", s)
	}
	// 两个缺陷总数反映各自报告的实际发现，不能被当作已消除缺陷数量。
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}

	// 两侧完整规则定义、原始状态和说明都保留。
	if entry.Before == nil || entry.After == nil {
		t.Fatal("both sides must be present")
	}
	if entry.Before.Rule.Severity != "high" || entry.After.Rule.Severity != "critical" {
		t.Errorf("severities = %q/%q", entry.Before.Rule.Severity, entry.After.Rule.Severity)
	}
	if entry.Before.Rule.Version != "10.2.0" || entry.After.Rule.Version != "10.2.0" {
		t.Errorf("version strings must be unchanged: %q/%q", entry.Before.Rule.Version, entry.After.Rule.Version)
	}
	if entry.Before.Rule.Status != contractsentinel.StatusDefect || entry.After.Rule.Status != contractsentinel.StatusPass {
		t.Errorf("statuses = %q/%q", entry.Before.Rule.Status, entry.After.Rule.Status)
	}

	// 基准侧缺陷仍带着原有产物哈希、规则标识、版本及反例证据；新侧没有缺陷
	// 记录。定义变化不能改写旧证据或把旧版本换成新版本。
	if entry.Before.Finding == nil {
		t.Fatal("baseline side must keep its defect finding")
	}
	f := entry.Before.Finding
	if f.ArtifactHash != hash || f.RuleID != beforeRule.ID || f.Version != beforeRule.Version {
		t.Errorf("baseline finding binding = %+v, want hash=%q rule=%q version=%q", f, hash, beforeRule.ID, beforeRule.Version)
	}
	if f.Evidence != resolvedEvidence {
		t.Errorf("baseline evidence = %q, want %q verbatim", f.Evidence, resolvedEvidence)
	}
	if entry.After.Finding != nil {
		t.Errorf("passing side must carry no finding: %+v", entry.After.Finding)
	}

	// 原始输出字节层面：证据中的中文、换行（JSON 转义为 \n）和前后空白逐字保留。
	if !strings.Contains(stdout, "  旧缺陷：重入路径仍可达\\n第二行证据  ") {
		t.Errorf("diff output must preserve the baseline evidence verbatim:\n%s", stdout)
	}
}

// TestCLIDiffSameDefinitionDefectToPassIsResolved 是定义全部一致的对照：
// 相同的“发现缺陷”到“通过”必须归为“已消除缺陷”，规则变化计数为零。
func TestCLIDiffSameDefinitionDefectToPassIsResolved(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)

	rule := cliRuleChangeRule("high")
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
			Status: contractsentinel.StatusDefect, Note: resolvedEvidence}})
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{rule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
			Status: contractsentinel.StatusPass}})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	if len(d.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(d.Results))
	}
	entry := d.Results[0]
	if entry.Change != contractsentinel.ChangeResolvedDefect {
		t.Fatalf("change = %q, want %q", entry.Change, contractsentinel.ChangeResolvedDefect)
	}
	s := d.Summary
	if s.ResolvedDefects != 1 {
		t.Errorf("resolvedDefects = %d, want 1", s.ResolvedDefects)
	}
	if s.ChangedRules != 0 {
		t.Errorf("changedRules = %d, want 0", s.ChangedRules)
	}
	if s.NewDefects != 0 || s.StatusChanges != 0 {
		t.Errorf("unexpected transition counts: %+v", s)
	}
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}
	if entry.Before == nil || entry.Before.Finding == nil ||
		entry.Before.Finding.Evidence != resolvedEvidence ||
		entry.Before.Finding.ArtifactHash != hash || entry.Before.Finding.Version != rule.Version {
		t.Errorf("baseline finding must be preserved: %+v", entry.Before)
	}
	if entry.After == nil || entry.After.Finding != nil {
		t.Errorf("passing side must be present without a finding: %+v", entry.After)
	}
}
