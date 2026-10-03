package main

// 本文件锁定 audit 导入外部检查结果（checks）的命令行回归行为：用户提供的
// 结论从输入 JSON 进入已保存报告后，仍按规则归属、携带本次产物哈希与规则
// 版本，并可用返回的报告标识经 report 原样读回；哈希或版本不匹配的记录使
// 整份提交在进程边界被拒绝，不产生部分报告、不创建存储、不改写已有报告。
//
// 布尔不变式提交的命令行保障见 main_test.go；这里只围绕 checks 导入。

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// cliArtifact 是本组测试使用的合约产物：ABI 与字节码齐全，满足 requiresABI
// 规则与 symbolic 规则的输入要求。
var cliArtifact = contractsentinel.Artifact{
	Name:     "Vault",
	ABI:      `[{"name":"withdraw"}]`,
	Bytecode: "0x6080",
	Source:   "Vault.sol",
}

func cliArtifactHash() string { return contractsentinel.ArtifactHash(cliArtifact) }

func cliArtifactWire() map[string]any {
	return map[string]any{
		"name":     cliArtifact.Name,
		"abi":      cliArtifact.ABI,
		"bytecode": cliArtifact.Bytecode,
		"source":   cliArtifact.Source,
	}
}

// writeObjectInput marshals a submission object (so Chinese, newlines and
// leading/trailing spaces in notes are encoded exactly) and writes it.
func writeObjectInput(t *testing.T, dir, name string, obj map[string]any) string {
	t.Helper()
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return writeInput(t, dir, name, string(data))
}

// runAuditCmd drives the real audit process and returns stdout, stderr.
func runAuditCmd(t *testing.T, bin, input, store string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "audit", "--input", input, "--store", store)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// runReportCmd drives the real report process and returns stdout, stderr.
func runReportCmd(t *testing.T, bin, store, id string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "report", "--store", store, "--id", id)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func mustParseReport(t *testing.T, out string) contractsentinel.Report {
	t.Helper()
	var r contractsentinel.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("output is not a report: %v\n%s", err, out)
	}
	return r
}

// fourStatusRules are four versioned rules covering the static, ABI-requiring
// and symbolic shapes, each with a distinct invariant.
func fourStatusRules() []map[string]any {
	return []map[string]any{
		{"id": "reentrancy-guard", "kind": "static", "severity": "high", "invariant": "reentrancy-safe", "version": "1.0.0"},
		{"id": "access-control", "kind": "static", "severity": "medium", "invariant": "owner-only", "requiresABI": true, "version": "2.1.0"},
		{"id": "fuzz-coverage", "kind": "fuzz", "severity": "low", "invariant": "fuzz-no-crash", "version": "0.4.2"},
		{"id": "invariant-preserved", "kind": "symbolic", "severity": "critical", "invariant": "balance-monotonic", "version": "0.9.0"},
	}
}

// 一份合法提交同时包含通过、发现缺陷、工具缺失、超时：audit 正常结束，stdout
// 给出完整报告并在指定目录保存；工具缺失与超时只是未完成，不进入 findings，
// 也不抹掉其他规则的有效结果；说明原文（中文、换行、前后空格）逐字保留，
// 通过记录允许没有说明。
func TestCLIAuditImportedChecksAllStatusesAndVerbatimNotes(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := cliArtifactHash()

	// 说明刻意包含中文、真实换行与前后空格，必须端到端逐字保留。
	defectNote := "  反例：攻击者可在外部调用返回前重复提款\n第二行证据  "
	toolNote := " 工具缺失：mythril 不在 PATH 中"
	timeoutNote := "超时：超过 30s 预算\n仍未遍历全部路径"

	checks := []map[string]any{
		// 通过记录刻意不带 note 字段。
		{"artifactHash": hash, "ruleId": "reentrancy-guard", "version": "1.0.0", "status": contractsentinel.StatusPass},
		{"artifactHash": hash, "ruleId": "access-control", "version": "2.1.0", "status": contractsentinel.StatusDefect, "note": defectNote},
		{"artifactHash": hash, "ruleId": "fuzz-coverage", "version": "0.4.2", "status": contractsentinel.StatusToolMissing, "note": toolNote},
		{"artifactHash": hash, "ruleId": "invariant-preserved", "version": "0.9.0", "status": contractsentinel.StatusTimeout, "note": timeoutNote},
	}
	input := writeObjectInput(t, work, "in.json", map[string]any{
		"artifact": cliArtifactWire(),
		"rules":    fourStatusRules(),
		"checks":   checks,
	})

	stdout, stderr, err := runAuditCmd(t, bin, input, store)
	if err != nil {
		t.Fatalf("valid checks submission must succeed: %v\n%s", err, stderr)
	}
	report := mustParseReport(t, stdout)

	if report.ReportID == "" || len(report.ReportID) != 64 {
		t.Fatalf("stdout report must carry a report id, got %q", report.ReportID)
	}
	if report.Artifact.Hash != hash || report.Artifact.Name != "Vault" {
		t.Fatalf("artifact header = %+v, want hash %s", report.Artifact, hash)
	}
	if len(report.Rules) != 4 {
		t.Fatalf("rules = %d, want 4", len(report.Rules))
	}

	statusByID := map[string]string{}
	noteByID := map[string]string{}
	for _, rl := range report.Rules {
		statusByID[rl.ID] = rl.Status
		noteByID[rl.ID] = rl.Note
	}
	if statusByID["reentrancy-guard"] != contractsentinel.StatusPass {
		t.Errorf("reentrancy-guard status = %q, want 通过", statusByID["reentrancy-guard"])
	}
	if noteByID["reentrancy-guard"] != "" {
		t.Errorf("pass note must be allowed to be empty, got %q", noteByID["reentrancy-guard"])
	}
	if statusByID["access-control"] != contractsentinel.StatusDefect || noteByID["access-control"] != defectNote {
		t.Errorf("access-control = %q note %q, want 发现缺陷 and verbatim note", statusByID["access-control"], noteByID["access-control"])
	}
	if statusByID["fuzz-coverage"] != contractsentinel.StatusToolMissing || noteByID["fuzz-coverage"] != toolNote {
		t.Errorf("fuzz-coverage = %q note %q, want 工具缺失 and verbatim note", statusByID["fuzz-coverage"], noteByID["fuzz-coverage"])
	}
	if statusByID["invariant-preserved"] != contractsentinel.StatusTimeout || noteByID["invariant-preserved"] != timeoutNote {
		t.Errorf("invariant-preserved = %q note %q, want 超时 and verbatim note", statusByID["invariant-preserved"], noteByID["invariant-preserved"])
	}

	// 只有发现缺陷产生 finding；工具缺失与超时绝不虚报为缺陷。
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1 (defect only): %+v", len(report.Findings), report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "access-control" {
		t.Fatalf("the only finding must belong to access-control, got %+v", f)
	}
	if f.ArtifactHash != hash || f.Version != "2.1.0" || f.Severity != "medium" ||
		f.Invariant != "owner-only" || f.Evidence != defectNote {
		t.Fatalf("finding binding/evidence not preserved verbatim: %+v", f)
	}
	// 证据必须是用户原文，而不是自动生成的通用说明。
	if strings.Contains(f.Evidence, "invariant ") && strings.Contains(f.Evidence, "does not hold") {
		t.Fatalf("checker note must not be replaced by the generic template: %q", f.Evidence)
	}

	// 报告必须保存到指定目录，文件名即报告标识。
	savedPath := filepath.Join(store, report.ReportID+".json")
	savedBytes, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("report must be saved under the store: %v", err)
	}
	saved := mustParseReport(t, string(savedBytes))
	if saved.ReportID != report.ReportID {
		t.Fatal("saved report id differs from stdout report id")
	}
	if matches, _ := filepath.Glob(filepath.Join(store, "*.json")); len(matches) != 1 {
		t.Fatalf("exactly one report file expected, got %v", matches)
	}

	// 用返回的报告标识经 report 读回，结论与说明必须与提交成功时一致，读取
	// 不重新解释结论。
	readOut, readErr, err := runReportCmd(t, bin, store, report.ReportID)
	if err != nil {
		t.Fatalf("report readback failed: %v\n%s", err, readErr)
	}
	reread := mustParseReport(t, readOut)
	if !reflect.DeepEqual(reread, report) {
		t.Fatalf("readback report differs from the audit output:\n got %+v\nwant %+v", reread, report)
	}
}

// 两条规则即使检查同名不变式，也可以一条通过、另一条发现缺陷。缺陷只能属于
// 后者并携带它的规则标识、版本、严重级别、不变式名与本次产物哈希；证据与
// 该记录说明完全一致。读回后归属不变。
func TestCLIAuditImportedChecksSharedInvariantAttribution(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := cliArtifactHash()

	defectNote := " 反例路径 A→B→A\n中文证据 "
	rules := []map[string]any{
		{"id": "rule-a", "kind": "static", "severity": "high", "invariant": "shared-inv", "version": "3.0.0"},
		{"id": "rule-b", "kind": "static", "severity": "low", "invariant": "shared-inv", "version": "5.2.1"},
	}
	checks := []map[string]any{
		{"artifactHash": hash, "ruleId": "rule-a", "version": "3.0.0", "status": contractsentinel.StatusPass},
		{"artifactHash": hash, "ruleId": "rule-b", "version": "5.2.1", "status": contractsentinel.StatusDefect, "note": defectNote},
	}
	input := writeObjectInput(t, work, "in.json", map[string]any{
		"artifact": cliArtifactWire(),
		"rules":    rules,
		"checks":   checks,
	})

	stdout, stderr, err := runAuditCmd(t, bin, input, store)
	if err != nil {
		t.Fatalf("shared-invariant checks submission must succeed: %v\n%s", err, stderr)
	}
	report := mustParseReport(t, stdout)

	statusByID := map[string]string{}
	for _, rl := range report.Rules {
		statusByID[rl.ID] = rl.Status
	}
	if statusByID["rule-a"] != contractsentinel.StatusPass || statusByID["rule-b"] != contractsentinel.StatusDefect {
		t.Fatalf("same invariant must allow pass/defect per rule: %+v", statusByID)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("exactly one finding expected, got %+v", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "rule-b" {
		t.Fatalf("defect must belong to rule-b only, got %+v", f)
	}
	if f.ArtifactHash != hash {
		t.Errorf("finding artifact hash = %q, want this submission's hash %q", f.ArtifactHash, hash)
	}
	if f.Version != "5.2.1" {
		t.Errorf("finding version = %q, want rule-b version 5.2.1", f.Version)
	}
	if f.Severity != "low" {
		t.Errorf("finding severity = %q, want rule-b severity low (not rule-a high)", f.Severity)
	}
	if f.Invariant != "shared-inv" {
		t.Errorf("finding invariant = %q, want shared-inv", f.Invariant)
	}
	if f.Evidence != defectNote {
		t.Errorf("evidence = %q, must equal the record note verbatim %q", f.Evidence, defectNote)
	}

	readOut, readErr, err := runReportCmd(t, bin, store, report.ReportID)
	if err != nil {
		t.Fatalf("report readback failed: %v\n%s", err, readErr)
	}
	if !reflect.DeepEqual(mustParseReport(t, readOut), report) {
		t.Fatal("readback must preserve per-rule attribution without reinterpretation")
	}
}

// 夹有产物哈希不匹配或规则版本不匹配的记录时，即使其他记录合法也必须整份
// 拒绝：非零退出、错误进 stderr 并指出规则与不匹配原因、stdout 没有成功
// 报告、尚不存在的存储目录不被创建。
func TestCLIAuditImportedChecksMismatchRejectsWholeSubmission(t *testing.T) {
	hash := cliArtifactHash()
	cases := []struct {
		name    string
		badRule string
		reason  string
		checks  []map[string]any
	}{
		{
			name:    "artifact-hash-mismatch",
			badRule: "reentrancy-guard",
			reason:  "artifact hash mismatch",
			checks: []map[string]any{
				{"artifactHash": hash, "ruleId": "access-control", "version": "2.1.0", "status": contractsentinel.StatusPass},
				{"artifactHash": strings.Repeat("f", 64), "ruleId": "reentrancy-guard", "version": "1.0.0", "status": contractsentinel.StatusDefect, "note": "不应进入报告"},
			},
		},
		{
			name:    "version-mismatch",
			badRule: "invariant-preserved",
			reason:  "version mismatch",
			checks: []map[string]any{
				{"artifactHash": hash, "ruleId": "access-control", "version": "2.1.0", "status": contractsentinel.StatusPass},
				{"artifactHash": hash, "ruleId": "invariant-preserved", "version": "9.9.9", "status": contractsentinel.StatusTimeout, "note": "不应进入报告"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			// 刻意指向尚不存在的嵌套目录：失败时连目录都不能出现。
			store := filepath.Join(work, "nested", "reports")
			input := writeObjectInput(t, work, "in.json", map[string]any{
				"artifact": cliArtifactWire(),
				"rules":    fourStatusRules(),
				"checks":   tc.checks,
			})

			stdout, stderr, err := runAuditCmd(t, bin, input, store)
			if err == nil {
				t.Fatal("a submission containing a mismatched check must exit non-zero")
			}
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 0 {
				t.Fatalf("exit code = 0, want non-zero")
			}
			if stdout != "" {
				t.Fatalf("stdout must not contain a partial report:\n%s", stdout)
			}
			for _, marker := range []string{"reportId", "发现缺陷", "超时", "工具缺失", "未检查"} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not mark the bad record as %q:\n%s", marker, stdout)
				}
			}
			if !strings.Contains(stderr, tc.badRule) {
				t.Fatalf("stderr must name the involved rule %q:\n%s", tc.badRule, stderr)
			}
			if !strings.Contains(stderr, tc.reason) {
				t.Fatalf("stderr must state the mismatch reason %q:\n%s", tc.reason, stderr)
			}
			if _, statErr := os.Stat(store); !os.IsNotExist(statErr) {
				t.Fatalf("rejected submission must not create the store: %v", statErr)
			}
			if _, statErr := os.Stat(filepath.Dir(store)); !os.IsNotExist(statErr) {
				t.Fatalf("rejected submission must not even create the store parent: %v", statErr)
			}
		})
	}
}

// 存储目录中已有报告时，一次被拒绝的 checks 提交不得新增报告，也不得改写已
// 有内容；这是提交无效，而不是带着错误记录产出部分报告。
func TestCLIAuditImportedChecksMismatchKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := cliArtifactHash()

	// 先放一份合法的 checks 报告作为既有报告。
	goodChecks := []map[string]any{
		{"artifactHash": hash, "ruleId": "reentrancy-guard", "version": "1.0.0", "status": contractsentinel.StatusDefect, "note": "既有反例"},
		{"artifactHash": hash, "ruleId": "access-control", "version": "2.1.0", "status": contractsentinel.StatusPass},
	}
	goodInput := writeObjectInput(t, work, "good.json", map[string]any{
		"artifact": cliArtifactWire(),
		"rules":    fourStatusRules(),
		"checks":   goodChecks,
	})
	setupOut, setupErr, err := runAuditCmd(t, bin, goodInput, store)
	if err != nil {
		t.Fatalf("valid setup audit failed: %v\n%s", err, setupErr)
	}
	setupReport := mustParseReport(t, setupOut)

	before, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("setup expected 1 report, got %d: %v", len(before), before)
	}
	existingPath := filepath.Join(store, before[0])
	existingBytes, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}

	// 另一份提交夹带哈希不匹配的记录，必须整体失败。
	badChecks := []map[string]any{
		{"artifactHash": hash, "ruleId": "access-control", "version": "2.1.0", "status": contractsentinel.StatusPass},
		{"artifactHash": strings.Repeat("1", 64), "ruleId": "fuzz-coverage", "version": "0.4.2", "status": contractsentinel.StatusDefect, "note": "坏记录"},
	}
	badInput := writeObjectInput(t, work, "bad.json", map[string]any{
		"artifact": cliArtifactWire(),
		"rules":    fourStatusRules(),
		"checks":   badChecks,
	})
	stdout, stderr, err := runAuditCmd(t, bin, badInput, store)
	if err == nil {
		t.Fatalf("submission with a hash mismatch must fail")
	}
	if !strings.Contains(stderr, "fuzz-coverage") || !strings.Contains(stderr, "artifact hash mismatch") {
		t.Fatalf("stderr must name the rule and reason:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("a rejected submission must not print a partial report:\n%s", stdout)
	}

	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("failure changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("failure modified the existing report bytes")
	}
	// 既有报告仍可按原标识读回，结论完全不变。
	readOut, readErr, err := runReportCmd(t, bin, store, setupReport.ReportID)
	if err != nil {
		t.Fatalf("existing report must still load unchanged: %v\n%s", err, readErr)
	}
	if !reflect.DeepEqual(mustParseReport(t, readOut), setupReport) {
		t.Fatal("the rejected submission changed the readable existing report")
	}
}
