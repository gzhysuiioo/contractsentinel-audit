package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 diff --rule：提供规则标识时输出结构
// 不变、results 只含所选规则、summary 只统计该规则；不提供时输出与现有完整
// 比较完全一致。空标识或找不到的规则必须非零退出、原因进 stderr、stdout
// 空白；筛选不绕过整份归档校验，比较全程只读。

// runCLIDiffRule 在真实进程上运行带 --rule 的 diff。
func runCLIDiffRule(t *testing.T, bin, store, before, after, rule string) (string, string, int) {
	t.Helper()
	args := []string{"diff", "--store", store, "--before", before, "--after", after, "--rule", rule}
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return stdout.String(), stderr.String(), exitErr.ExitCode()
	}
	t.Fatalf("failed to start diff: %v", err)
	return "", "", 0
}

// 筛选成功路径：z-new-defect 从通过变成发现缺陷，results 只有它一条，
// summary 只计一条新发现缺陷，缺陷总数为 0 和 1（报告中另有其他缺陷，
// 不得计入）；顶层引用与产物变化标记保持完整比较的值。
func TestCLIDiffRuleFilterNewDefect(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))

	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "z-new-defect")
	if code != 0 {
		t.Fatalf("filtered diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	if d.Before.ReportID != before.ReportID || d.After.ReportID != after.ReportID {
		t.Errorf("refs = %q / %q", d.Before.ReportID, d.After.ReportID)
	}
	if d.Before.Artifact.Name != "Vault" || d.Before.Artifact.Hash != hash ||
		d.After.Artifact.Name != "Vault" || d.After.Artifact.Hash != hash {
		t.Errorf("artifact refs = %+v / %+v", d.Before.Artifact, d.After.Artifact)
	}
	if d.ArtifactNameChanged || d.ArtifactHashChanged {
		t.Errorf("same artifact must not be flagged changed: %v / %v",
			d.ArtifactNameChanged, d.ArtifactHashChanged)
	}

	if len(d.Results) != 1 {
		t.Fatalf("filtered results = %d, want 1", len(d.Results))
	}
	entry := d.Results[0]
	if entry.RuleID != "z-new-defect" || entry.Change != contractsentinel.ChangeNewDefect {
		t.Errorf("entry = %+v", entry)
	}
	if entry.Before == nil || entry.After == nil {
		t.Fatalf("both sides must be present: %+v", entry)
	}
	if entry.Before.Rule.Status != contractsentinel.StatusPass || entry.Before.Finding != nil {
		t.Errorf("before side = %+v", entry.Before)
	}
	if entry.After.Rule.Status != contractsentinel.StatusDefect || entry.After.Finding == nil {
		t.Fatalf("after side = %+v", entry.After)
	}
	// 缺陷侧保留当次归档哈希、规则版本与原始证据（中文、换行、前后空格逐字）。
	if entry.After.Finding.ArtifactHash != hash || entry.After.Finding.Version != "9" ||
		entry.After.Finding.Evidence != defectNote {
		t.Errorf("finding = %+v", entry.After.Finding)
	}
	if !strings.Contains(stdout, "  反例：攻击者可在 withdraw 中重入\\n  第二行证据  ") {
		t.Errorf("evidence must be preserved verbatim:\n%s", stdout)
	}

	s := d.Summary
	if s.NewDefects != 1 || s.ResolvedDefects != 0 || s.StatusChanges != 0 ||
		s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 ||
		s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("filtered summary = %+v", s)
	}
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}

// 状态变化类规则（超时→发现缺陷）筛选后仍按现有口径归为检查状态变化，
// 不得因为筛选后数量变化而推断成新发现缺陷。
func TestCLIDiffRuleFilterStatusChangeNotPromoted(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))

	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "m-timeout-to-defect")
	if code != 0 {
		t.Fatalf("filtered diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 1 || d.Results[0].Change != contractsentinel.ChangeStatusChanged {
		t.Fatalf("entry = %+v", d.Results)
	}
	s := d.Summary
	if s.StatusChanges != 1 || s.NewDefects != 0 || s.ResolvedDefects != 0 {
		t.Errorf("filtered summary = %+v", s)
	}
	// 新侧确有该规则的真实缺陷记录，基准侧没有。
	if s.BeforeDefects != 0 || s.AfterDefects != 1 {
		t.Errorf("defect totals = %d/%d, want 0/1", s.BeforeDefects, s.AfterDefects)
	}
}

// 规则标识精确匹配：大小写或前后空格不同都视为未找到；两份报告都没有的
// 标识同样失败。非零退出、stderr 指出未找到的标识、stdout 完全空白。
func TestCLIDiffRuleFilterNotFound(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))

	for _, id := range []string{"Z-New-Defect", " z-new-defect", "z-new-defect ", "no-such-rule"} {
		stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, id)
		if code == 0 {
			t.Fatalf("rule id %q must fail", id)
		}
		if !strings.Contains(stderr, id) {
			t.Errorf("stderr must name the missing rule %q:\n%s", id, stderr)
		}
		if stdout != "" {
			t.Errorf("stdout must be empty on failure, got:\n%s", stdout)
		}
	}
}

// 显式提供空规则标识：非零退出、stderr 说明参数为空、stdout 空白。
func TestCLIDiffRuleFilterEmptyFails(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))

	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "")
	if code == 0 {
		t.Fatal("empty --rule must exit non-zero")
	}
	if !strings.Contains(stderr, "rule") || !strings.Contains(stderr, "empty") {
		t.Fatalf("stderr must explain the empty rule id:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty, got:\n%s", stdout)
	}
}

// 筛选不绕过整份归档校验：第二份报告损坏时，即使所选规则本身完好，命令
// 仍按现有失败行为结束，stdout 不出现任何比较片段，归档保持原样。
func TestCLIDiffRuleFilterCorruptArchiveFails(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))
	badPath := filepath.Join(store, after.ReportID+".json")
	corrupt := []byte(`{broken`)
	if err := os.WriteFile(badPath, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLIDiffRule(t, bin, store, before.ReportID, after.ReportID, "z-new-defect")
	if code == 0 {
		t.Fatal("filtered diff against a corrupted archive must fail")
	}
	if !strings.Contains(stderr, "invalid JSON") {
		t.Fatalf("stderr must describe the corrupted archive:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
	}
	kept, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != string(corrupt) {
		t.Fatal("failed filtered diff must not repair the corrupted archive")
	}
}

// 不提供 --rule 时输出与现有完整比较逐字节一致（回归保护既有行为）。
func TestCLIDiffWithoutRuleFlagUnchanged(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("full diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != len(rules) {
		t.Fatalf("full results = %d, want %d", len(d.Results), len(rules))
	}
	if d.Summary.BeforeDefects != 3 || d.Summary.AfterDefects != 3 {
		t.Errorf("full defect totals = %d/%d, want 3/3", d.Summary.BeforeDefects, d.Summary.AfterDefects)
	}
}
