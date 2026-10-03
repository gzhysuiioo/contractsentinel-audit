package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 audit 的“外部检查结果导入”：
// 用户给出满足 ABI/字节码要求的产物、带版本规则和 checks 记录后，
// 结论必须带着原产物哈希与规则版本进入已保存报告，并能用返回的报告标识
// 原样读回；任何一条哈希或版本不匹配的记录都必须整份拒绝提交。

// cliWireArtifact/cliWireRule/cliWireCheck 是提交 JSON 在测试侧的镜像，
// 字段与 contractsentinel 的线框格式一致，但独立定义，避免测试依赖内部类型。
type cliWireArtifact struct {
	Name     string `json:"name"`
	ABI      string `json:"abi"`
	Bytecode string `json:"bytecode"`
	Source   string `json:"source"`
}

type cliWireRule struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Invariant   string `json:"invariant"`
	RequiresABI bool   `json:"requiresABI"`
	Version     string `json:"version"`
}

type cliWireCheck struct {
	ArtifactHash string `json:"artifactHash"`
	RuleID       string `json:"ruleId"`
	Version      string `json:"version"`
	Status       string `json:"status"`
	Note         string `json:"note,omitempty"`
}

type cliWireInput struct {
	Artifact   cliWireArtifact `json:"artifact"`
	Rules      []cliWireRule   `json:"rules"`
	Invariants map[string]bool `json:"invariants,omitempty"`
	Checks     []cliWireCheck  `json:"checks,omitempty"`
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// 缺陷说明刻意包含中文、换行和前后空格，任何修剪或模板替换都会被抓到。
const defectNote = "  反例：攻击者可在 withdraw 中重入\n  第二行证据  "

// mixedCheckArtifact 是规则要求齐备的产物：非空 ABI 与字节码。
func mixedCheckArtifact() cliWireArtifact {
	return cliWireArtifact{
		Name:     "Vault",
		ABI:      `[{"name":"withdraw","type":"function"}]`,
		Bytecode: "0x60806040",
		Source:   "contract Vault {\n}\n",
	}
}

func mixedCheckRules() []cliWireRule {
	return []cliWireRule{
		{ID: "rule-pass", Kind: "static", Severity: "low", Invariant: "inv-pass", Version: "1.4.0"},
		{ID: "rule-defect", Kind: "static", Severity: "high", Invariant: "inv-defect", Version: "2.0.1"},
		{ID: "rule-tool", Kind: "static", Severity: "medium", Invariant: "inv-tool", RequiresABI: true, Version: "3.0.0"},
		{ID: "rule-timeout", Kind: "symbolic", Severity: "critical", Invariant: "inv-timeout", Version: "0.9.2"},
		{ID: "rule-unchecked", Kind: "static", Severity: "info", Invariant: "inv-unchecked", Version: "5.0.0"},
	}
}

// mixedCheckInput 构造一份同时含通过、缺陷、工具缺失、超时的合法提交；
// 第五条规则没有任何记录，应为未检查。
func mixedCheckInput(hash string) cliWireInput {
	return cliWireInput{
		Artifact: mixedCheckArtifact(),
		Rules:    mixedCheckRules(),
		Checks: []cliWireCheck{
			// 通过记录不带 note 字段：通过允许没有说明。
			{ArtifactHash: hash, RuleID: "rule-pass", Version: "1.4.0", Status: contractsentinel.StatusPass},
			{ArtifactHash: hash, RuleID: "rule-defect", Version: "2.0.1", Status: contractsentinel.StatusDefect, Note: defectNote},
			{ArtifactHash: hash, RuleID: "rule-tool", Version: "3.0.0", Status: contractsentinel.StatusToolMissing, Note: "符号执行引擎未安装"},
			{ArtifactHash: hash, RuleID: "rule-timeout", Version: "0.9.2", Status: contractsentinel.StatusTimeout, Note: "超过 60s 截止时间"},
		},
	}
}

func mixedArtifactHash(t *testing.T) string {
	t.Helper()
	a := mixedCheckArtifact()
	return contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name: a.Name, ABI: a.ABI, Bytecode: a.Bytecode, Source: a.Source,
	})
}

// writeStructInput 将提交对象编码为 JSON 写入临时目录并返回路径。
func writeStructInput(t *testing.T, dir, name string, v any) string {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return writeInput(t, dir, name, string(data))
}

// runCLIAudit 在真实进程上运行 audit，返回 stdout、stderr 与退出码。
func runCLIAudit(t *testing.T, bin, input, store string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, "audit", "--input", input, "--store", store)
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
	t.Fatalf("failed to start audit: %v", err)
	return "", "", 0
}

// runCLIReport 在真实进程上运行 report，返回 stdout、stderr 与退出码。
func runCLIReport(t *testing.T, bin, store, id string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, "report", "--store", store, "--id", id)
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
	t.Fatalf("failed to start report: %v", err)
	return "", "", 0
}

func decodeReport(t *testing.T, raw string) contractsentinel.Report {
	t.Helper()
	var report contractsentinel.Report
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatalf("output is not a report JSON: %v\n%s", err, raw)
	}
	return report
}

// assertNoPartialReport 失败提交的 stdout 绝不能携带任何报告片段：
// 错误记录不能被降级标成缺陷、超时或未检查后部分输出。
func assertNoPartialReport(t *testing.T, stdout string) {
	t.Helper()
	if stdout != "" {
		t.Fatalf("rejected submission must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- 合法提交：四种结论同存，说明原文保留，工具缺失/超时不进 findings ---

func TestCLIAuditImportChecksMixedStatuses(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	input := writeStructInput(t, work, "in.json", mixedCheckInput(hash))
	store := filepath.Join(work, "nested", "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("legal import must succeed, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)

	if !hex64.MatchString(report.ReportID) {
		t.Fatalf("report id must be 64 lowercase hex chars, got %q", report.ReportID)
	}
	if report.Artifact.Name != "Vault" || report.Artifact.Hash != hash {
		t.Fatalf("artifact header not bound to the submitted artifact: %+v", report.Artifact)
	}

	statusByID := map[string]string{}
	noteByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
		noteByID[r.ID] = r.Note
	}
	wantStatuses := map[string]string{
		"rule-pass":      contractsentinel.StatusPass,
		"rule-defect":    contractsentinel.StatusDefect,
		"rule-tool":      contractsentinel.StatusToolMissing,
		"rule-timeout":   contractsentinel.StatusTimeout,
		"rule-unchecked": contractsentinel.StatusUnchecked,
	}
	if !reflect.DeepEqual(statusByID, wantStatuses) {
		t.Fatalf("rule statuses = %+v, want %+v", statusByID, wantStatuses)
	}
	// 通过记录没有说明；其余三种结论的说明逐字保留（含中文、换行、前后空格）。
	if noteByID["rule-pass"] != "" {
		t.Errorf("pass rule note = %q, want empty", noteByID["rule-pass"])
	}
	if noteByID["rule-defect"] != defectNote {
		t.Errorf("defect note = %q, want %q", noteByID["rule-defect"], defectNote)
	}
	if noteByID["rule-tool"] != "符号执行引擎未安装" {
		t.Errorf("tool-missing note = %q", noteByID["rule-tool"])
	}
	if noteByID["rule-timeout"] != "超过 60s 截止时间" {
		t.Errorf("timeout note = %q", noteByID["rule-timeout"])
	}

	// 工具缺失与超时只是检查未完成：唯一缺陷只能来自 rule-defect。
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one defect", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "rule-defect" || f.Version != "2.0.1" || f.Severity != "high" || f.Invariant != "inv-defect" {
		t.Fatalf("defect attribution = %+v", f)
	}
	if f.ArtifactHash != hash {
		t.Fatalf("defect artifact hash = %q, want %q", f.ArtifactHash, hash)
	}
	if f.Evidence != defectNote {
		t.Fatalf("evidence = %q, must equal the original note %q", f.Evidence, defectNote)
	}
	if f.Evidence == "invariant inv-defect does not hold" {
		t.Fatal("imported defect evidence must not be replaced by the auto-generated template")
	}

	// 成功时必须在指定存储目录落盘，且落盘内容与 stdout 报告完全一致。
	savedPath := filepath.Join(store, report.ReportID+".json")
	savedBytes, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("report must be saved under the store directory: %v", err)
	}
	saved := decodeReport(t, string(savedBytes))
	if !reflect.DeepEqual(saved, report) {
		t.Fatalf("saved report does not match stdout report:\nsaved=%+v\nstdout=%+v", saved, report)
	}
	// 原始字节层面也要保留前后空格与中文，而不只是解码后凑巧相等。
	if !strings.Contains(string(savedBytes), "  反例：攻击者可在 withdraw 中重入\\n  第二行证据  ") {
		t.Fatalf("saved archive must preserve the raw note verbatim: %s", savedBytes)
	}
}

// --- 用返回的报告标识读回：不重新解释结论，归属与说明与提交成功时一致 ---

func TestCLIAuditImportChecksReadbackByReportID(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	input := writeStructInput(t, work, "in.json", mixedCheckInput(hash))
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("legal import must succeed, exit=%d stderr=%s", code, stderr)
	}
	submitted := decodeReport(t, stdout)

	readStdout, readStderr, readCode := runCLIReport(t, bin, store, submitted.ReportID)
	if readCode != 0 {
		t.Fatalf("report read-back must succeed, exit=%d stderr=%s", readCode, readStderr)
	}
	loaded := decodeReport(t, readStdout)

	// 完整报告一致：标识、规则状态与说明、缺陷证据及归属逐项相同。
	if !reflect.DeepEqual(loaded, submitted) {
		t.Fatalf("read-back re-interpreted the submission:\nloaded=%+v\nsubmitted=%+v", loaded, submitted)
	}
	if loaded.ReportID != submitted.ReportID || loaded.Artifact != submitted.Artifact {
		t.Fatalf("report id/artifact changed on read: %+v vs %+v", loaded.Artifact, submitted.Artifact)
	}
	for _, want := range submitted.Rules {
		var got *contractsentinel.ReportRule
		for i := range loaded.Rules {
			if loaded.Rules[i].ID == want.ID {
				got = &loaded.Rules[i]
			}
		}
		if got == nil {
			t.Fatalf("rule %s missing after read-back", want.ID)
		}
		if got.Status != want.Status || got.Note != want.Note || got.Version != want.Version {
			t.Fatalf("rule %s changed on read: got %+v want %+v", want.ID, *got, want)
		}
	}
	if len(loaded.Findings) != 1 {
		t.Fatalf("findings after read-back = %d, want 1", len(loaded.Findings))
	}
	got := loaded.Findings[0]
	want := submitted.Findings[0]
	if got.RuleID != want.RuleID || got.Version != want.Version || got.Severity != want.Severity ||
		got.Invariant != want.Invariant || got.ArtifactHash != want.ArtifactHash || got.Evidence != want.Evidence {
		t.Fatalf("finding attribution changed on read:\ngot  %+v\nwant %+v", got, want)
	}
	if got.Evidence != defectNote {
		t.Fatalf("evidence must stay the user note, got %q", got.Evidence)
	}
}

// --- 按规则归属：同名不变式、一个通过一个缺陷时，缺陷只属于后者 ---

func TestCLIAuditImportChecksSharedInvariantAttribution(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	a := mixedCheckArtifact()
	hash := contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name: a.Name, ABI: a.ABI, Bytecode: a.Bytecode, Source: a.Source,
	})
	const sharedInvariant = "shared-balance-invariant"
	const note = "\t共享不变式反例：第二行\n"
	in := cliWireInput{
		Artifact: a,
		Rules: []cliWireRule{
			{ID: "rule-a", Kind: "static", Severity: "high", Invariant: sharedInvariant, Version: "7"},
			{ID: "rule-b", Kind: "static", Severity: "low", Invariant: sharedInvariant, Version: "7"},
		},
		Checks: []cliWireCheck{
			{ArtifactHash: hash, RuleID: "rule-a", Version: "7", Status: contractsentinel.StatusPass},
			{ArtifactHash: hash, RuleID: "rule-b", Version: "7", Status: contractsentinel.StatusDefect, Note: note},
		},
	}
	input := writeStructInput(t, work, "in.json", in)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("legal shared-invariant import must succeed, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)

	statusByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["rule-a"] != contractsentinel.StatusPass || statusByID["rule-b"] != contractsentinel.StatusDefect {
		t.Fatalf("same invariant, different conclusions must be kept per rule: %+v", statusByID)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("exactly one rule defected, got findings %+v", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "rule-b" {
		t.Fatalf("defect must belong to rule-b only, got %q", f.RuleID)
	}
	if f.Version != "7" || f.Severity != "low" || f.Invariant != sharedInvariant || f.ArtifactHash != hash {
		t.Fatalf("finding must carry rule-b's own binding, got %+v", f)
	}
	if f.Evidence != note {
		t.Fatalf("evidence = %q, want the rule-b note %q", f.Evidence, note)
	}
	if f.Evidence == "invariant "+sharedInvariant+" does not hold" {
		t.Fatal("evidence must not be replaced by a generic auto-generated note")
	}
}

// --- 任一记录产物哈希不匹配：整份拒绝，不产生任何部分报告或存储副作用 ---

func TestCLIAuditImportChecksHashMismatchRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	in := mixedCheckInput(hash)
	// 其余记录全部合法，仅工具缺失记录引用了另一份产物的哈希。
	for i := range in.Checks {
		if in.Checks[i].RuleID == "rule-tool" {
			in.Checks[i].ArtifactHash = strings.Repeat("a", 64)
		}
	}
	input := writeStructInput(t, work, "bad.json", in)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("submission with a hash-mismatched check must exit non-zero")
	}
	if !strings.Contains(stderr, "rule-tool") {
		t.Fatalf("stderr must name the involved rule:\n%s", stderr)
	}
	if !strings.Contains(stderr, "artifact hash mismatch") {
		t.Fatalf("stderr must state the mismatch reason:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 任一记录规则版本不匹配：整份拒绝 ---

func TestCLIAuditImportChecksVersionMismatchRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	in := mixedCheckInput(hash)
	// 缺陷记录声称针对旧版本规则，与本次带版本规则不一致。
	for i := range in.Checks {
		if in.Checks[i].RuleID == "rule-defect" {
			in.Checks[i].Version = "1.0.0"
		}
	}
	input := writeStructInput(t, work, "bad.json", in)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("submission with a version-mismatched check must exit non-zero")
	}
	if !strings.Contains(stderr, "rule-defect") {
		t.Fatalf("stderr must name the involved rule:\n%s", stderr)
	}
	if !strings.Contains(stderr, "version mismatch") {
		t.Fatalf("stderr must state the mismatch reason:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// 拒绝是“提交无效”：stdout 不能把错误记录标成任何一种已知状态后部分输出。
func TestCLIAuditImportChecksMismatchHasNoStatusFragments(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	in := mixedCheckInput(hash)
	in.Checks[0].ArtifactHash = "0" + strings.TrimPrefix(hash, hash[:1])
	input := writeStructInput(t, work, "bad.json", in)
	store := filepath.Join(work, "reports")

	stdout, _, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("mismatched submission must fail")
	}
	for _, marker := range []string{"reportId", "findings", contractsentinel.StatusDefect, contractsentinel.StatusTimeout,
		contractsentinel.StatusToolMissing, contractsentinel.StatusUnchecked, contractsentinel.StatusPass} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a partial report fragment %q:\n%s", marker, stdout)
		}
	}
}

// --- 已有报告时拒绝提交：不新增报告，也不改写已有内容 ---

func TestCLIAuditImportChecksMismatchKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	// 先落一份合法的混合状态报告。
	good := writeStructInput(t, work, "good.json", mixedCheckInput(mixedArtifactHash(t)))
	if _, stderr, code := runCLIAudit(t, bin, good, store); code != 0 {
		t.Fatalf("valid setup audit must succeed: %s", stderr)
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

	// 再提交一份夹带哈希不匹配记录的提交。
	badIn := mixedCheckInput(mixedArtifactHash(t))
	badIn.Checks[2].ArtifactHash = strings.Repeat("b", 64)
	bad := writeStructInput(t, work, "bad.json", badIn)
	if _, _, code := runCLIAudit(t, bin, bad, store); code == 0 {
		t.Fatal("invalid submission must exit non-zero")
	}

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
		t.Fatal("rejected submission modified the existing report bytes")
	}
}

// 读回标识必须是 64 位十六进制；此处顺手保证导出的标识形态稳定可用。
func TestCLIAuditImportChecksReportIDIsHexHash(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	input := writeStructInput(t, work, "in.json", mixedCheckInput(hash))
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("legal import must succeed, stderr=%s", stderr)
	}
	report := decodeReport(t, stdout)
	if len(report.ReportID) != 64 {
		t.Fatalf("report id length = %d, want 64", len(report.ReportID))
	}
	if _, err := hex.DecodeString(report.ReportID); err != nil {
		t.Fatalf("report id must be hex: %v", err)
	}
}
