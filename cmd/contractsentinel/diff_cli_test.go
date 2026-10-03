package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 diff 命令：用户指定基准报告与新报告
// 后，命令必须输出可解析的完整比较 JSON，并严格保持分类口径——只有
// 通过→发现缺陷 才是“新发现缺陷”，反向才是“已消除缺陷”；未检查、工具缺失、
// 超时都不能证明合约安全或缺陷已修复。任一报告读取失败时必须非零退出、
// 原因进 stderr、stdout 不出现任何局部结果，且比较全程不改动归档。

// diffRules 是前后两份报告共用的同一批规则定义（id、kind、severity、
// invariant、ABI 要求、版本完全一致），只有这样两侧状态才允许直接比较。
func diffRules() []cliWireRule {
	return []cliWireRule{
		{ID: "a-resolved", Kind: "static", Severity: "high", Invariant: "inv-resolved", Version: "1"},
		{ID: "b-tool-to-pass", Kind: "static", Severity: "medium", Invariant: "inv-tool", RequiresABI: true, Version: "2"},
		{ID: "c-unchecked-to-pass", Kind: "static", Severity: "info", Invariant: "inv-unchecked", Version: "3"},
		{ID: "d-stable-defect", Kind: "static", Severity: "high", Invariant: "inv-stable-def", Version: "4"},
		{ID: "e-stable-pass", Kind: "static", Severity: "low", Invariant: "inv-stable-pass", Version: "5"},
		{ID: "f-note-change", Kind: "static", Severity: "low", Invariant: "inv-note", Version: "6"},
		{ID: "m-timeout-to-defect", Kind: "symbolic", Severity: "critical", Invariant: "inv-td", Version: "7"},
		{ID: "n-defect-to-timeout", Kind: "symbolic", Severity: "critical", Invariant: "inv-dt", Version: "8"},
		{ID: "z-new-defect", Kind: "static", Severity: "high", Invariant: "inv-new", Version: "9"},
	}
}

// 基准侧缺陷证据同样刻意保留中文、换行与前后空格。
const resolvedEvidence = "  旧缺陷：重入路径仍可达\n第二行证据  "

// diffBeforeChecks/diffAfterChecks 覆盖所有关键状态迁移。
// 基准侧：a/d/n 三条缺陷（共 3 个真实缺陷）；新侧：d/m/z 三条缺陷（共 3 个）。
func diffBeforeChecks(hash string) []cliWireCheck {
	return []cliWireCheck{
		{ArtifactHash: hash, RuleID: "z-new-defect", Version: "9", Status: contractsentinel.StatusPass},
		{ArtifactHash: hash, RuleID: "a-resolved", Version: "1", Status: contractsentinel.StatusDefect, Note: resolvedEvidence},
		{ArtifactHash: hash, RuleID: "m-timeout-to-defect", Version: "7", Status: contractsentinel.StatusTimeout, Note: "超过 60s 截止时间"},
		{ArtifactHash: hash, RuleID: "n-defect-to-timeout", Version: "8", Status: contractsentinel.StatusDefect, Note: "超时前发现的反例"},
		{ArtifactHash: hash, RuleID: "b-tool-to-pass", Version: "2", Status: contractsentinel.StatusToolMissing, Note: "符号执行引擎未安装"},
		// c-unchecked-to-pass 在基准侧刻意没有记录：应为未检查。
		{ArtifactHash: hash, RuleID: "d-stable-defect", Version: "4", Status: contractsentinel.StatusDefect, Note: "稳定缺陷证据"},
		{ArtifactHash: hash, RuleID: "e-stable-pass", Version: "5", Status: contractsentinel.StatusPass},
		{ArtifactHash: hash, RuleID: "f-note-change", Version: "6", Status: contractsentinel.StatusPass, Note: "旧说明"},
	}
}

func diffAfterChecks(hash string) []cliWireCheck {
	return []cliWireCheck{
		{ArtifactHash: hash, RuleID: "f-note-change", Version: "6", Status: contractsentinel.StatusPass, Note: "新说明"},
		{ArtifactHash: hash, RuleID: "z-new-defect", Version: "9", Status: contractsentinel.StatusDefect, Note: defectNote},
		{ArtifactHash: hash, RuleID: "a-resolved", Version: "1", Status: contractsentinel.StatusPass},
		{ArtifactHash: hash, RuleID: "b-tool-to-pass", Version: "2", Status: contractsentinel.StatusPass},
		{ArtifactHash: hash, RuleID: "c-unchecked-to-pass", Version: "3", Status: contractsentinel.StatusPass},
		{ArtifactHash: hash, RuleID: "m-timeout-to-defect", Version: "7", Status: contractsentinel.StatusDefect, Note: defectNote},
		{ArtifactHash: hash, RuleID: "n-defect-to-timeout", Version: "8", Status: contractsentinel.StatusTimeout, Note: "复跑超过 60s 截止时间"},
		{ArtifactHash: hash, RuleID: "d-stable-defect", Version: "4", Status: contractsentinel.StatusDefect, Note: "稳定缺陷证据"},
		{ArtifactHash: hash, RuleID: "e-stable-pass", Version: "5", Status: contractsentinel.StatusPass},
	}
}

// auditDiffReport 用给定规则与检查记录通过真实 audit 命令落盘一份报告并解码返回。
func auditDiffReport(t *testing.T, bin, work, store, name string, artifact cliWireArtifact, rules []cliWireRule, checks []cliWireCheck) contractsentinel.Report {
	t.Helper()
	in := cliWireInput{Artifact: artifact, Rules: rules, Checks: checks}
	input := writeStructInput(t, work, name, in)
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit %s must succeed, exit=%d stderr=%s", name, code, stderr)
	}
	return decodeReport(t, stdout)
}

// runCLIDiff 在真实进程上运行 diff，返回 stdout、stderr 与退出码。
func runCLIDiff(t *testing.T, bin, store, before, after string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, "diff", "--store", store, "--before", before, "--after", after)
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

func decodeDiff(t *testing.T, raw string) contractsentinel.DiffResult {
	t.Helper()
	var d contractsentinel.DiffResult
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatalf("diff output is not parseable JSON: %v\n%s", err, raw)
	}
	return d
}

func diffEntry(t *testing.T, d contractsentinel.DiffResult, ruleID string) contractsentinel.RuleDiff {
	t.Helper()
	for _, r := range d.Results {
		if r.RuleID == ruleID {
			return r
		}
	}
	t.Fatalf("diff result for rule %s not found", ruleID)
	return contractsentinel.RuleDiff{}
}

// 完整成功路径：同一批规则定义下所有关键迁移逐条正确归属，结果按规则 id
// 排序，汇总与逐条分类一致，证据逐字保留，参数位置决定基准/新报告方向。
func TestCLIDiffMixedTransitions(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()

	// 两侧规则与检查记录刻意使用不同的提交排列顺序，对应关系不得受影响。
	beforeRules := []cliWireRule{
		rules[8], rules[3], rules[0], rules[6], rules[1], rules[7], rules[4], rules[2], rules[5],
	}
	afterRules := []cliWireRule{
		rules[2], rules[7], rules[4], rules[0], rules[5], rules[8], rules[1], rules[6], rules[3],
	}
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, beforeRules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, afterRules, diffAfterChecks(hash))

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	// 基准与新报告的标识、产物信息必须与命令行选择一致。
	if d.Before.ReportID != before.ReportID {
		t.Errorf("before report id = %q, want %q", d.Before.ReportID, before.ReportID)
	}
	if d.After.ReportID != after.ReportID {
		t.Errorf("after report id = %q, want %q", d.After.ReportID, after.ReportID)
	}
	if d.Before.Artifact.Name != "Vault" || d.Before.Artifact.Hash != hash {
		t.Errorf("before artifact ref = %+v", d.Before.Artifact)
	}
	if d.After.Artifact.Name != "Vault" || d.After.Artifact.Hash != hash {
		t.Errorf("after artifact ref = %+v", d.After.Artifact)
	}
	if d.ArtifactNameChanged || d.ArtifactHashChanged {
		t.Errorf("same artifact must not be flagged changed: name=%v hash=%v", d.ArtifactNameChanged, d.ArtifactHashChanged)
	}

	// 每条规则恰好一个结果，且两侧都在（规则集合相同）。
	if len(d.Results) != len(rules) {
		t.Fatalf("results = %d, want %d", len(d.Results), len(rules))
	}
	changeByID := map[string]string{}
	for _, r := range d.Results {
		changeByID[r.RuleID] = r.Change
		if r.Before == nil || r.After == nil {
			t.Errorf("rule %s: both sides must be present for unchanged definitions", r.RuleID)
		}
	}
	wantChanges := map[string]string{
		"a-resolved":          contractsentinel.ChangeResolvedDefect,
		"b-tool-to-pass":      contractsentinel.ChangeStatusChanged,
		"c-unchecked-to-pass": contractsentinel.ChangeStatusChanged,
		"d-stable-defect":     contractsentinel.ChangeNoChange,
		"e-stable-pass":       contractsentinel.ChangeNoChange,
		"f-note-change":       contractsentinel.ChangeNoteChanged,
		"m-timeout-to-defect": contractsentinel.ChangeStatusChanged,
		"n-defect-to-timeout": contractsentinel.ChangeStatusChanged,
		"z-new-defect":        contractsentinel.ChangeNewDefect,
	}
	for id, want := range wantChanges {
		if changeByID[id] != want {
			t.Errorf("rule %s change = %q, want %q", id, changeByID[id], want)
		}
	}

	// 结果必须按规则标识排序，与输入报告中的排列顺序无关。
	ids := make([]string, 0, len(d.Results))
	for _, r := range d.Results {
		ids = append(ids, r.RuleID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}

	// 通过→发现缺陷：只有这一种迁移算新缺陷；缺陷侧携带当次归档的哈希、
	// 规则版本与原始证据，通过侧没有缺陷记录。
	z := diffEntry(t, d, "z-new-defect")
	if z.Before.Rule.Status != contractsentinel.StatusPass || z.After.Rule.Status != contractsentinel.StatusDefect {
		t.Errorf("z-new-defect statuses = %q/%q", z.Before.Rule.Status, z.After.Rule.Status)
	}
	if z.Before.Finding != nil {
		t.Errorf("passing side must not carry a finding: %+v", z.Before.Finding)
	}
	if z.After.Finding == nil {
		t.Fatal("defect side must carry its finding")
	}
	if z.After.Finding.ArtifactHash != hash || z.After.Finding.Version != "9" {
		t.Errorf("z finding binding = %+v", z.After.Finding)
	}
	if z.After.Finding.Evidence != defectNote {
		t.Errorf("z evidence = %q, want %q", z.After.Finding.Evidence, defectNote)
	}

	// 发现缺陷→通过：已消除缺陷；证据只在基准侧。
	a := diffEntry(t, d, "a-resolved")
	if a.Before.Rule.Status != contractsentinel.StatusDefect || a.After.Rule.Status != contractsentinel.StatusPass {
		t.Errorf("a-resolved statuses = %q/%q", a.Before.Rule.Status, a.After.Rule.Status)
	}
	if a.Before.Finding == nil || a.Before.Finding.Evidence != resolvedEvidence ||
		a.Before.Finding.ArtifactHash != hash || a.Before.Finding.Version != "1" {
		t.Errorf("resolved side finding = %+v", a.Before.Finding)
	}
	if a.After.Finding != nil {
		t.Errorf("passing side must not carry a finding: %+v", a.After.Finding)
	}

	// 超时→发现缺陷：只是检查状态变化，不能记为新缺陷；新侧确有缺陷记录。
	m := diffEntry(t, d, "m-timeout-to-defect")
	if m.Before.Rule.Status != contractsentinel.StatusTimeout || m.Before.Rule.Note != "超过 60s 截止时间" {
		t.Errorf("m before = %+v", m.Before.Rule)
	}
	if m.After.Rule.Status != contractsentinel.StatusDefect || m.After.Finding == nil ||
		m.After.Finding.Evidence != defectNote || m.After.Finding.Version != "7" || m.After.Finding.ArtifactHash != hash {
		t.Errorf("m after must carry the real defect finding: before=%+v after=%+v", m.Before, m.After)
	}
	if m.Before.Finding != nil {
		t.Errorf("timeout side must not carry a finding: %+v", m.Before.Finding)
	}

	// 发现缺陷→超时：只是检查状态变化，不能记为已消除；旧侧缺陷记录仍在。
	n := diffEntry(t, d, "n-defect-to-timeout")
	if n.Before.Rule.Status != contractsentinel.StatusDefect || n.Before.Finding == nil ||
		n.Before.Finding.Evidence != "超时前发现的反例" || n.Before.Finding.Version != "8" {
		t.Errorf("n before must keep its defect finding: %+v", n.Before)
	}
	if n.After.Rule.Status != contractsentinel.StatusTimeout || n.After.Rule.Note != "复跑超过 60s 截止时间" {
		t.Errorf("n after = %+v", n.After.Rule)
	}
	if n.After.Finding != nil {
		t.Errorf("timeout side must not carry a finding: %+v", n.After.Finding)
	}

	// 工具缺失→通过：工具缺失不证明安全，只能是状态变化；工具说明逐字保留。
	b := diffEntry(t, d, "b-tool-to-pass")
	if b.Before.Rule.Status != contractsentinel.StatusToolMissing || b.Before.Rule.Note != "符号执行引擎未安装" {
		t.Errorf("b before = %+v", b.Before.Rule)
	}
	if b.After.Rule.Status != contractsentinel.StatusPass || b.Before.Finding != nil || b.After.Finding != nil {
		t.Errorf("b sides = %+v / %+v", b.Before, b.After)
	}

	// 未检查→通过：同样不能当成缺陷已消除或安全证明。
	c := diffEntry(t, d, "c-unchecked-to-pass")
	if c.Before.Rule.Status != contractsentinel.StatusUnchecked || c.After.Rule.Status != contractsentinel.StatusPass {
		t.Errorf("c statuses = %q/%q", c.Before.Rule.Status, c.After.Rule.Status)
	}

	// 无变化项：两侧状态、说明与缺陷记录一致。
	stable := diffEntry(t, d, "d-stable-defect")
	if stable.Before.Finding == nil || stable.After.Finding == nil ||
		stable.Before.Finding.Evidence != "稳定缺陷证据" || stable.After.Finding.Evidence != "稳定缺陷证据" {
		t.Errorf("stable defect sides = %+v / %+v", stable.Before.Finding, stable.After.Finding)
	}
	pass := diffEntry(t, d, "e-stable-pass")
	if pass.Before.Finding != nil || pass.After.Finding != nil {
		t.Errorf("stable pass sides must not carry findings")
	}

	// 说明变化项各自保留自己一侧的说明。
	note := diffEntry(t, d, "f-note-change")
	if note.Before.Rule.Note != "旧说明" || note.After.Rule.Note != "新说明" {
		t.Errorf("note sides = %q / %q", note.Before.Rule.Note, note.After.Rule.Note)
	}

	// 汇总数量必须与逐条分类相符；缺陷总数只数真实缺陷，不含超时/工具缺失。
	s := d.Summary
	if s.NewDefects != 1 || s.ResolvedDefects != 1 || s.StatusChanges != 4 ||
		s.NoteChanges != 1 || s.NoChange != 2 {
		t.Errorf("summary counts = %+v", s)
	}
	if s.AddedRules != 0 || s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("same rule definitions must not add/remove/change rules: %+v", s)
	}
	if s.BeforeDefects != 3 || s.AfterDefects != 3 {
		t.Errorf("defect totals = %d/%d, want 3/3", s.BeforeDefects, s.AfterDefects)
	}

	// 原始输出字节层面：证据中的中文、换行、前后空格必须逐字保留（JSON 中换行转义为 \n）。
	if !strings.Contains(stdout, "  反例：攻击者可在 withdraw 中重入\\n  第二行证据  ") {
		t.Errorf("diff output must preserve the raw evidence verbatim:\n%s", stdout)
	}
	if !strings.Contains(stdout, "  旧缺陷：重入路径仍可达\\n第二行证据  ") {
		t.Errorf("diff output must preserve the baseline evidence verbatim:\n%s", stdout)
	}
}

// 交换基准/新报告参数：引用方向与迁移方向必须随选择反转，不得固定按归档顺序。
func TestCLIDiffSwapBeforeAfter(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))

	stdout, stderr, code := runCLIDiff(t, bin, store, after.ReportID, before.ReportID)
	if code != 0 {
		t.Fatalf("swapped diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if d.Before.ReportID != after.ReportID || d.After.ReportID != before.ReportID {
		t.Errorf("refs must follow flag order: before=%q after=%q", d.Before.ReportID, d.After.ReportID)
	}
	changeByID := map[string]string{}
	for _, r := range d.Results {
		changeByID[r.RuleID] = r.Change
	}
	if changeByID["z-new-defect"] != contractsentinel.ChangeResolvedDefect {
		t.Errorf("reversed z-new-defect = %q, want %q", changeByID["z-new-defect"], contractsentinel.ChangeResolvedDefect)
	}
	if changeByID["a-resolved"] != contractsentinel.ChangeNewDefect {
		t.Errorf("reversed a-resolved = %q, want %q", changeByID["a-resolved"], contractsentinel.ChangeNewDefect)
	}
	if d.Summary.NewDefects != 1 || d.Summary.ResolvedDefects != 1 {
		t.Errorf("reversed summary = %+v", d.Summary)
	}
}

// 同一对报告重复比较必须给出字节一致的结果，命令行输出确定可复现。
func TestCLIDiffDeterministicOutput(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))

	first, _, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatal("first diff must succeed")
	}
	second, _, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatal("second diff must succeed")
	}
	if first != second {
		t.Fatal("repeated diffs must render byte-identical output")
	}
	// 比较结果不得携带任何时间戳字段（规则 id 中的 "timeout" 字样不算）。
	for _, key := range []string{`"time"`, `"date"`, `"timestamp"`, `"createdAt"`} {
		if strings.Contains(first, key) {
			t.Errorf("diff output must not contain timestamp field %s", key)
		}
	}
}

// 任一报告不存在：非零退出、原因进 stderr、stdout 完全空白；第二份报告
// 出错时也不得把已读到的第一份报告当作成功结果输出。
func TestCLIDiffMissingReportFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	existing := auditDiffReport(t, bin, work, store, "only.json", artifact, rules, diffAfterChecks(hash))
	missing := strings.Repeat("0", 64)

	cases := []struct {
		name   string
		before string
		after  string
	}{
		{"before missing", missing, existing.ReportID},
		{"after missing", existing.ReportID, missing},
		{"both missing", strings.Repeat("1", 64), missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCLIDiff(t, bin, store, tc.before, tc.after)
			if code == 0 {
				t.Fatal("diff must exit non-zero for a missing report")
			}
			if !strings.Contains(stderr, "not found") {
				t.Fatalf("stderr must report a missing report:\n%s", stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
			}
			if strings.Contains(stdout, existing.ReportID) || strings.Contains(stdout, "results") ||
				strings.Contains(stdout, "summary") || strings.Contains(stdout, contractsentinel.StatusUnchecked) {
				t.Fatalf("stdout must not leak a partial result or the first report:\n%s", stdout)
			}
		})
	}
}

// 归档目录不存在时按“报告未找到”失败，且不得顺手创建目录。
func TestCLIDiffMissingStoreCreatesNothing(t *testing.T) {
	bin := auditBinary(t)
	store := filepath.Join(t.TempDir(), "never-created")
	id := strings.Repeat("a", 64)

	stdout, stderr, code := runCLIDiff(t, bin, store, id, id)
	if code == 0 {
		t.Fatal("diff against a missing store must fail")
	}
	if !strings.Contains(stderr, "not found") {
		t.Fatalf("stderr must report the missing report:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout must be empty, got:\n%s", stdout)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("diff must not create the store directory: %v", err)
	}
}

// 非法报告标识：非零退出并说明原因，stdout 无任何结果。
func TestCLIDiffInvalidReportIDFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	existing := auditDiffReport(t, bin, work, store, "only.json", artifact, diffRules(), diffAfterChecks(hash))

	for _, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"bad before", "xyz", existing.ReportID},
		{"bad after", existing.ReportID, "ABC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCLIDiff(t, bin, store, tc.before, tc.after)
			if code == 0 {
				t.Fatal("diff must exit non-zero for an invalid report id")
			}
			if !strings.Contains(stderr, "invalid report id") {
				t.Fatalf("stderr must explain the invalid id:\n%s", stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout must be empty, got:\n%s", stdout)
			}
		})
	}
}

// 归档内容损坏（包括第二份报告）：非零退出、原因进 stderr、stdout 不出现
// 比较结果或第一份报告的局部成功片段，更不能把读取失败降级成“未检查”。
func TestCLIDiffCorruptArchiveFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	good := auditDiffReport(t, bin, work, store, "good.json", artifact, rules, diffBeforeChecks(hash))
	bad := auditDiffReport(t, bin, work, store, "bad.json", artifact, rules, diffAfterChecks(hash))
	if err := os.WriteFile(filepath.Join(store, bad.ReportID+".json"), []byte(`{broken`), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		before string
		after  string
	}{
		{"second report corrupt", good.ReportID, bad.ReportID},
		{"first report corrupt", bad.ReportID, good.ReportID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCLIDiff(t, bin, store, tc.before, tc.after)
			if code == 0 {
				t.Fatal("diff must exit non-zero for a corrupted archive")
			}
			if !strings.Contains(stderr, "invalid JSON") {
				t.Fatalf("stderr must describe the corrupted archive:\n%s", stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
			}
			for _, marker := range []string{good.ReportID, bad.ReportID, `"results"`, `"summary"`,
				contractsentinel.ChangeNewDefect, contractsentinel.ChangeResolvedDefect,
				contractsentinel.StatusUnchecked, contractsentinel.StatusDefect} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak %q on failure:\n%s", marker, stdout)
				}
			}
		})
	}
}

// 比较只是读取操作：成功与失败都必须保持归档原样——不补写报告、不修复
// 损坏内容、不留下临时文件。
func TestCLIDiffNeverModifiesStore(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	before := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	after := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))

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
	gotKeys := func(m map[string]string) []string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}
	sameSnapshot := func(t *testing.T, got, want map[string]string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("store file set changed: %v vs %v", gotKeys(got), gotKeys(want))
		}
		for name, data := range want {
			if got[name] != data {
				t.Errorf("archive %s modified by diff", name)
			}
		}
	}

	original := snapshot(t)

	// 成功的比较不得改动任何归档。
	if _, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID); code != 0 {
		t.Fatalf("successful diff failed: %s", stderr)
	}
	sameSnapshot(t, snapshot(t), original)

	// 损坏第二份归档后，失败的比较既不修复它，也不碰其他归档。
	badPath := filepath.Join(store, after.ReportID+".json")
	corrupt := []byte(`{"reportId":"corrupt"}`)
	if err := os.WriteFile(badPath, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID); code == 0 {
		t.Fatalf("diff against corrupted archive must fail: %s", stderr)
	}
	names, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != len(original) {
		t.Fatalf("failure changed the store file set: %v", names)
	}
	kept, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, corrupt) {
		t.Fatal("failed diff must not repair or rewrite the corrupted archive")
	}
	goodBytes, err := os.ReadFile(filepath.Join(store, before.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(goodBytes) != original[before.ReportID+".json"] {
		t.Fatal("failed diff modified the untouched first report")
	}
}
