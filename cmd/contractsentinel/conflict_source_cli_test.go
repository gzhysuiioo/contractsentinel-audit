package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 audit 提交的“结论来源冲突”：两条规
// 则共享同一不变式时，一条已有合法外部检查记录，用户又在 invariants 中为该
// 共享名称给出布尔值（即使本意只是补充另一条规则），整份提交必须能从正常
// 审计入口观察到失败——非零退出、stderr 点名同时收到两种来源的规则并说明
// 原因、stdout 没有任何成功报告或部分规则结论，报告目录不创建、已有归档不
// 新增不改动。提交的产物哈希、规则版本与必填说明都合法，失败确实来自冲突。

// sharedConflictRules 是两条引用同一共享不变式的带版本规则。
func sharedConflictRules() []cliWireRule {
	return []cliWireRule{
		{ID: "rule-checked", Kind: "static", Severity: "high", Invariant: "shared-inv", Version: "1.2.0"},
		{ID: "rule-plain", Kind: "static", Severity: "low", Invariant: "shared-inv", Version: "3.4.0"},
	}
}

// sharedConflictInput 构造一份除冲突外完全合法的提交：rule-checked 的检查记
// 录绑定真实产物哈希与规则版本，需要说明的状态都带非空白说明；invariants
// 为共享名称给出布尔值（本意是补充 rule-plain）。
func sharedConflictInput(t *testing.T, status, note string, value bool) cliWireInput {
	t.Helper()
	return cliWireInput{
		Artifact:   mixedCheckArtifact(),
		Rules:      sharedConflictRules(),
		Invariants: map[string]bool{"shared-inv": value},
		Checks: []cliWireCheck{
			{ArtifactHash: mixedArtifactHash(t), RuleID: "rule-checked", Version: "1.2.0", Status: status, Note: note},
		},
	}
}

// assertConflictRejected 断言冲突提交从正常审计入口观察到的完整失败形态。
func assertConflictRejected(t *testing.T, stdout, stderr string, code int, store string) {
	t.Helper()
	if code == 0 {
		t.Fatalf("conflicting submission must exit non-zero, stdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "rule-checked") {
		t.Fatalf("stderr must name the rule that received both sources:\n%s", stderr)
	}
	if !strings.Contains(stderr, "both a check record and an invariant value") {
		t.Fatalf("stderr must state the conflict reason:\n%s", stderr)
	}
	// 绑定值全部合法：失败只能来自结论来源冲突，不能是哈希、版本或说明问题。
	for _, unrelated := range []string{"artifact hash mismatch", "version mismatch", "note is required"} {
		if strings.Contains(stderr, unrelated) {
			t.Fatalf("failure must come from the source conflict alone, stderr mentions %q:\n%s", unrelated, stderr)
		}
	}
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// 核心场景表：true 与 false 都是已提供的结论；通过+true、发现缺陷+false 两边
// 看起来一致也不能放行；工具缺失/超时同样不能拿布尔值补成正常结论。
func TestCLIAuditConflictSharedInvariantRejected(t *testing.T) {
	cases := []struct {
		name   string
		status string
		note   string
		value  bool
	}{
		{"pass record with true", contractsentinel.StatusPass, "", true},
		{"pass record with false", contractsentinel.StatusPass, "", false},
		{"defect record with false", contractsentinel.StatusDefect, "反例：receive 重入 withdraw", false},
		{"defect record with true", contractsentinel.StatusDefect, "反例：receive 重入 withdraw", true},
		{"tool missing with true", contractsentinel.StatusToolMissing, "PATH 中未找到 mythril", true},
		{"tool missing with false", contractsentinel.StatusToolMissing, "PATH 中未找到 mythril", false},
		{"timeout with true", contractsentinel.StatusTimeout, "300s 截止时间到达仍未遍历完", true},
		{"timeout with false", contractsentinel.StatusTimeout, "300s 截止时间到达仍未遍历完", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			input := writeStructInput(t, work, "in.json", sharedConflictInput(t, tc.status, tc.note, tc.value))
			store := filepath.Join(work, "nested", "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			assertConflictRejected(t, stdout, stderr, code, store)
		})
	}
}

// 冲突失败时 stdout 不能出现任何报告片段或规则结论字样，即使另一条规则本来
// 能通过或产生缺陷，也不能留下半份报告。
func TestCLIAuditConflictLeavesNoPartialReport(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	// rule-plain 换成能独立产生缺陷的独有不变式规则：它本可成功，但整份必须拒绝。
	in := sharedConflictInput(t, contractsentinel.StatusDefect, "反例：receive 重入 withdraw", false)
	in.Rules[1].Invariant = "plain-inv"
	in.Invariants["plain-inv"] = false
	input := writeStructInput(t, work, "in.json", in)
	store := filepath.Join(work, "reports")

	stdout, _, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("conflicting submission must fail even when another rule could conclude")
	}
	for _, marker := range []string{
		"reportId", "findings", "rule-checked", "rule-plain",
		contractsentinel.StatusPass, contractsentinel.StatusDefect,
		contractsentinel.StatusToolMissing, contractsentinel.StatusTimeout, contractsentinel.StatusUnchecked,
	} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak partial report fragment %q:\n%s", marker, stdout)
		}
	}
}

// 目录中已有合法归档时，冲突提交不新增文件、不改变原归档字节。
func TestCLIAuditConflictKeepsExistingArchive(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	// 先落一份合法报告：同一对共享不变式规则，只有检查记录、没有布尔值。
	good := sharedConflictInput(t, contractsentinel.StatusDefect, "反例：receive 重入 withdraw", false)
	good.Invariants = nil
	goodInput := writeStructInput(t, work, "good.json", good)
	if _, stderr, code := runCLIAudit(t, bin, goodInput, store); code != 0 {
		t.Fatalf("legal setup audit must succeed: %s", stderr)
	}
	before, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("setup expected 1 report, got %v", before)
	}
	existingPath := filepath.Join(store, before[0])
	existingBytes, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}

	// 再提交夹带共享名称布尔值的冲突提交。
	badInput := writeStructInput(t, work, "bad.json",
		sharedConflictInput(t, contractsentinel.StatusDefect, "反例：receive 重入 withdraw", false))
	stdout, stderr, code := runCLIAudit(t, bin, badInput, store)
	if code == 0 {
		t.Fatal("conflicting submission must exit non-zero")
	}
	if !strings.Contains(stderr, "both a check record and an invariant value") {
		t.Fatalf("stderr must state the conflict reason:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)

	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("rejected submission changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("rejected submission modified the existing archive bytes")
	}
}

// 允许的使用方式：移除共享名称下的布尔值后，有检查记录的规则保留自己的状
// 态与原始说明，没有结论的规则显示未检查。
func TestCLIAuditSharedInvariantBooleanRemovedSucceeds(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	const note = "  反例原文：含前后空格\n"
	in := sharedConflictInput(t, contractsentinel.StatusDefect, note, false)
	in.Invariants = nil
	input := writeStructInput(t, work, "in.json", in)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("removing the boolean must make the submission legal, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)

	statusByID := map[string]string{}
	noteByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
		noteByID[r.ID] = r.Note
	}
	if statusByID["rule-checked"] != contractsentinel.StatusDefect {
		t.Errorf("rule-checked = %q, want %q", statusByID["rule-checked"], contractsentinel.StatusDefect)
	}
	if noteByID["rule-checked"] != note {
		t.Errorf("rule-checked note = %q, must keep the original %q", noteByID["rule-checked"], note)
	}
	if statusByID["rule-plain"] != contractsentinel.StatusUnchecked {
		t.Errorf("rule-plain = %q, want %q", statusByID["rule-plain"], contractsentinel.StatusUnchecked)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "rule-checked" || f.Version != "1.2.0" || f.ArtifactHash != report.Artifact.Hash {
		t.Fatalf("defect must stay bound to rule-checked's version and the artifact hash: %+v", f)
	}
	if f.Evidence != note {
		t.Fatalf("external defect evidence must be the original note, got %q", f.Evidence)
	}
}

// 允许的使用方式：布尔值只对应另一条规则独有的不变式时，两种来源在一份提
// 交中共存；false 使引用它的规则产生缺陷（证据沿用现有表达），true 使其通过。
func TestCLIAuditCheckAndBooleanCoexistOnDistinctInvariants(t *testing.T) {
	bin := auditBinary(t)

	build := func(t *testing.T, value bool) cliWireInput {
		t.Helper()
		return cliWireInput{
			Artifact: mixedCheckArtifact(),
			Rules: []cliWireRule{
				{ID: "rule-checked", Kind: "static", Severity: "high", Invariant: "inv-checked", Version: "1.2.0"},
				{ID: "rule-bool", Kind: "static", Severity: "medium", Invariant: "inv-bool", Version: "2.0.0"},
			},
			Invariants: map[string]bool{"inv-bool": value},
			Checks: []cliWireCheck{
				{ArtifactHash: mixedArtifactHash(t), RuleID: "rule-checked", Version: "1.2.0", Status: contractsentinel.StatusPass},
			},
		}
	}

	// false：rule-bool 产生缺陷，检查记录一侧保持通过。
	work := t.TempDir()
	input := writeStructInput(t, work, "in.json", build(t, false))
	store := filepath.Join(work, "reports")
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("distinct invariants must allow both sources, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)
	statusByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["rule-checked"] != contractsentinel.StatusPass {
		t.Errorf("rule-checked = %q, want the check record's %q", statusByID["rule-checked"], contractsentinel.StatusPass)
	}
	if statusByID["rule-bool"] != contractsentinel.StatusDefect {
		t.Errorf("rule-bool = %q, want %q from the false boolean", statusByID["rule-bool"], contractsentinel.StatusDefect)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the boolean defect", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "rule-bool" || f.Version != "2.0.0" || f.ArtifactHash != report.Artifact.Hash || f.Invariant != "inv-bool" {
		t.Fatalf("boolean defect must bind rule-bool's own version and the artifact hash: %+v", f)
	}
	if f.Evidence != "invariant inv-bool does not hold" {
		t.Fatalf("boolean defect evidence must use the existing expression, got %q", f.Evidence)
	}

	// true：rule-bool 通过，整份报告没有缺陷。
	work = t.TempDir()
	input = writeStructInput(t, work, "in.json", build(t, true))
	store = filepath.Join(work, "reports")
	stdout, stderr, code = runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("true boolean on a distinct invariant must be legal, exit=%d stderr=%s", code, stderr)
	}
	report = decodeReport(t, stdout)
	statusByID = map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["rule-bool"] != contractsentinel.StatusPass {
		t.Errorf("rule-bool = %q, want %q from the true boolean", statusByID["rule-bool"], contractsentinel.StatusPass)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("true boolean must not produce defects: %+v", report.Findings)
	}
}

// 名称按原文精确匹配：大小写不同或带前后空格的名称不会自动合并，既不构成
// 冲突，也不成为任何规则的结论。
func TestCLIAuditInvariantNameMatchedExactly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	const note = "反例：receive 重入 withdraw"
	in := sharedConflictInput(t, contractsentinel.StatusDefect, note, false)
	in.Invariants = map[string]bool{
		"Shared-Inv":   false, // 大小写不同：另一个名字
		" shared-inv ": true,  // 前后空格：另一个名字
	}
	input := writeStructInput(t, work, "in.json", in)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("case/whitespace variants must not merge with the rule's invariant, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)
	statusByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["rule-checked"] != contractsentinel.StatusDefect {
		t.Errorf("rule-checked = %q, want the check record's %q", statusByID["rule-checked"], contractsentinel.StatusDefect)
	}
	if statusByID["rule-plain"] != contractsentinel.StatusUnchecked {
		t.Errorf("rule-plain = %q, want %q: variant names must not conclude it", statusByID["rule-plain"], contractsentinel.StatusUnchecked)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "rule-checked" || report.Findings[0].Evidence != note {
		t.Fatalf("only the external defect may appear, with its original note: %+v", report.Findings)
	}
}
