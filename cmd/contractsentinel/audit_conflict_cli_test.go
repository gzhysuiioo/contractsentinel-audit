package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 audit 提交的结论来源冲突：两条规则
// 共享同一不变式名时，外部检查记录按规则标识与版本归属，而 invariants 里的
// 布尔值按名称作用于所有引用该名的规则。只要共享名下给出布尔值（true 与
// false 都算已提供结论），带记录的规则就同时收到两种来源，整份提交必须
// 拒绝——即使记录为“通过”而布尔值为 true、记录为“发现缺陷”而布尔值为
// false 看似一致，即使记录是“工具缺失”或“超时”。失败从正常审计入口可观察：
// 非零退出、stderr 点名同时收到两种来源的规则并说明原因、stdout 没有任何
// 报告片段；报告目录尚不存在时不创建，已有合法归档不新增文件也不被改写。
// 提交的产物哈希、规则版本与必要说明全部合法，失败确实来自结论来源冲突：
// 同一份提交移除共享名下的布尔值后即成功。

// conflictCLIRules 两条共享 shared-inv 的规则与一条引用独立不变式的规则。
func conflictCLIRules() []cliWireRule {
	return []cliWireRule{
		{ID: "shared-a", Kind: "static", Severity: "high", Invariant: "shared-inv", Version: "1.0.0"},
		{ID: "shared-b", Kind: "static", Severity: "low", Invariant: "shared-inv", Version: "2.0.0"},
		{ID: "solo-c", Kind: "static", Severity: "medium", Invariant: "solo-inv", Version: "3.0.0"},
	}
}

// conflictCLIInput 构造共享不变式冲突提交：shared-a 携带合法外部记录，
// invariants 在共享名 shared-inv 下给出布尔值；solo-c 另带一条完全合法的
// 缺陷记录，用于证明其他规则再合法也不会留下半份报告。
func conflictCLIInput(hash, status, note string, value bool) cliWireInput {
	return cliWireInput{
		Artifact:   mixedCheckArtifact(),
		Rules:      conflictCLIRules(),
		Invariants: map[string]bool{"shared-inv": value},
		Checks: []cliWireCheck{
			{ArtifactHash: hash, RuleID: "shared-a", Version: "1.0.0", Status: status, Note: note},
			{ArtifactHash: hash, RuleID: "solo-c", Version: "3.0.0", Status: contractsentinel.StatusDefect, Note: "solo-c 外部反例"},
		},
	}
}

// --- 共享不变式冲突：四种记录状态 × true/false 都整份拒绝，stdout 干净，
// 不创建报告目录 ---

func TestCLIAuditSharedInvariantConflictFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	hash := mixedArtifactHash(t)
	cases := []struct {
		name   string
		status string
		note   string
		value  bool
	}{
		// 记录与布尔看似一致也不放行。
		{"pass_true_consistent", contractsentinel.StatusPass, "", true},
		{"pass_false", contractsentinel.StatusPass, "", false},
		{"defect_false_consistent", contractsentinel.StatusDefect, "外部反例：重入", false},
		{"defect_true", contractsentinel.StatusDefect, "外部反例：重入", true},
		// 工具缺失与超时同样不能拿布尔值补成正常结论。
		{"toolmissing_true", contractsentinel.StatusToolMissing, "符号执行引擎未安装", true},
		{"toolmissing_false", contractsentinel.StatusToolMissing, "符号执行引擎未安装", false},
		{"timeout_true", contractsentinel.StatusTimeout, "超过 300s 截止时间", true},
		{"timeout_false", contractsentinel.StatusTimeout, "超过 300s 截止时间", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			input := writeStructInput(t, work, "in.json", conflictCLIInput(hash, tc.status, tc.note, tc.value))
			store := filepath.Join(work, "nested", "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code == 0 {
				t.Fatalf("conflicting submission must exit non-zero, stdout:\n%s", stdout)
			}
			for _, want := range []string{"audit failed", "shared-a",
				"both a check record and an invariant value are provided"} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("stderr must contain %q (name the rule with both sources and the reason):\n%s", want, stderr)
				}
			}
			if strings.Contains(stderr, "shared-b") {
				t.Fatalf("the rule without a check record must not be named:\n%s", stderr)
			}
			assertNoPartialReport(t, stdout)
			for _, marker := range []string{"reportId", "findings", contractsentinel.StatusPass,
				contractsentinel.StatusDefect, contractsentinel.StatusToolMissing,
				contractsentinel.StatusTimeout, contractsentinel.StatusUnchecked} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a partial report fragment %q:\n%s", marker, stdout)
				}
			}
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("rejected submission must not create the store directory: %v", err)
			}
		})
	}
}

// --- 已有合法归档时冲突提交不新增文件、不改写原归档 ---

func TestCLIAuditSharedInvariantConflictKeepsExistingReports(t *testing.T) {
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

	// 再提交共享不变式冲突的提交（其中的 solo-c 缺陷记录本身完全合法）。
	bad := writeStructInput(t, work, "bad.json",
		conflictCLIInput(mixedArtifactHash(t), contractsentinel.StatusDefect, "外部反例：重入", false))
	if _, _, code := runCLIAudit(t, bin, bad, store); code == 0 {
		t.Fatal("conflicting submission must exit non-zero")
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

// --- 对照：同一份提交移除共享名下的布尔值即成功，证明上面的失败确实来自
// 结论来源冲突；记录规则保留状态与原始说明，无结论规则为未检查 ---

func TestCLIAuditSharedInvariantBooleanRemovedSucceeds(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	note := "  外部反例：重入\n第二行  "
	in := cliWireInput{
		Artifact: mixedCheckArtifact(),
		Rules:    conflictCLIRules(),
		Checks: []cliWireCheck{
			{ArtifactHash: hash, RuleID: "shared-a", Version: "1.0.0", Status: contractsentinel.StatusDefect, Note: note},
		},
	}
	input := writeStructInput(t, work, "in.json", in)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("removing the shared-name boolean must make the same submission succeed: %s", stderr)
	}
	report := decodeReport(t, stdout)

	statusByID := map[string]string{}
	noteByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
		noteByID[r.ID] = r.Note
	}
	if statusByID["shared-a"] != contractsentinel.StatusDefect || noteByID["shared-a"] != note {
		t.Fatalf("shared-a must keep the record status and original note: %+v", report.Rules)
	}
	for _, id := range []string{"shared-b", "solo-c"} {
		if statusByID[id] != contractsentinel.StatusUnchecked || noteByID[id] != "" {
			t.Fatalf("%s has no conclusion and must be 未检查: %+v", id, report.Rules)
		}
	}
	if len(report.Findings) != 1 {
		t.Fatalf("only shared-a defects, got %+v", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "shared-a" || f.Version != "1.0.0" || f.ArtifactHash != hash || f.Evidence != note {
		t.Fatalf("the defect must bind shared-a's version, artifact hash and verbatim note: %+v", f)
	}
	if _, err := os.Stat(filepath.Join(store, report.ReportID+".json")); err != nil {
		t.Fatalf("a successful audit must save the report: %v", err)
	}
}

// --- 允许用法：布尔值只对应另一条规则独有的不变式时，两种来源在一份提交中
// 共存；false 使引用它的规则产生缺陷，true 使该规则通过 ---

func TestCLIAuditCheckRecordAndBooleanCoexistAcrossRules(t *testing.T) {
	bin := auditBinary(t)
	hash := mixedArtifactHash(t)
	note := "shared-a 外部反例"
	for _, value := range []bool{false, true} {
		t.Run(fmt.Sprintf("solo-inv=%t", value), func(t *testing.T) {
			work := t.TempDir()
			in := cliWireInput{
				Artifact:   mixedCheckArtifact(),
				Rules:      conflictCLIRules(),
				Invariants: map[string]bool{"solo-inv": value},
				Checks: []cliWireCheck{
					{ArtifactHash: hash, RuleID: "shared-a", Version: "1.0.0", Status: contractsentinel.StatusDefect, Note: note},
				},
			}
			input := writeStructInput(t, work, "in.json", in)
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code != 0 {
				t.Fatalf("a boolean for another rule's own invariant must coexist with check records: %s", stderr)
			}
			report := decodeReport(t, stdout)

			statusByID := map[string]string{}
			for _, r := range report.Rules {
				statusByID[r.ID] = r.Status
			}
			if statusByID["shared-a"] != contractsentinel.StatusDefect {
				t.Fatalf("shared-a must keep its record conclusion: %+v", report.Rules)
			}
			if statusByID["shared-b"] != contractsentinel.StatusUnchecked {
				t.Fatalf("shared-b has no conclusion and must be 未检查: %+v", report.Rules)
			}

			findingByID := map[string]contractsentinel.ReportFinding{}
			for _, f := range report.Findings {
				findingByID[f.RuleID] = f
			}
			fA, ok := findingByID["shared-a"]
			if !ok || fA.Evidence != note || fA.Version != "1.0.0" || fA.ArtifactHash != hash {
				t.Fatalf("the external defect must keep the original note and binding: %+v", report.Findings)
			}
			fC, hasFC := findingByID["solo-c"]
			if !value {
				if statusByID["solo-c"] != contractsentinel.StatusDefect {
					t.Fatalf("solo-inv=false must make solo-c defect: %+v", report.Rules)
				}
				if !hasFC || fC.Evidence != "invariant solo-inv does not hold" ||
					fC.Version != "3.0.0" || fC.ArtifactHash != hash {
					t.Fatalf("the boolean defect must use the existing evidence wording and solo-c's binding: %+v", report.Findings)
				}
				if len(report.Findings) != 2 {
					t.Fatalf("each source contributes one defect, got %+v", report.Findings)
				}
			} else {
				if statusByID["solo-c"] != contractsentinel.StatusPass {
					t.Fatalf("solo-inv=true must make solo-c pass: %+v", report.Rules)
				}
				if hasFC || len(report.Findings) != 1 {
					t.Fatalf("a passing solo-c must not add a finding: %+v", report.Findings)
				}
			}
		})
	}
}
