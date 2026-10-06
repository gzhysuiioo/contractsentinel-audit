package contractsentinel

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交的结论来源冲突规则：同一条规则既收到 checks 外部
// 检查记录、又在 invariants 中收到它所引用不变式的布尔值时，整份提交必须
// 拒绝。重点回归场景是两条规则共享同一个不变式名：外部记录按规则标识与
// 版本归属，而不变式布尔值按名称作用于所有引用该名的规则，因此即使用户
// 的本意只是给另一条规则补结论，只要共享名下有布尔值，带记录的规则就
// 同时拿到了两种来源的结论。true 与 false 都是已提供的结论（false 不是
// “没提供”）；即使外部记录为“通过”而布尔值为 true、或记录为“发现缺陷”
// 而布尔值为 false，两边看似一致也不放行；记录为“工具缺失”“超时”时同样
// 不能拿布尔值补成正常结论。冲突拒绝是整份失败：其他规则再合法也不产生
// 部分报告。移除共享名下的布尔值、或布尔值只对应另一条规则独有的不变式
// 时，两种来源仍可共存；名称按原文精确匹配，大小写差异与前后空格不会
// 自动合并。

// conflictRulesJSON 是冲突回归共用的规则数组：rule-a 与 rule-b 共享不变式
// shared-inv，rule-c 引用独立不变式 solo-inv；三条规则版本各异。
const conflictRulesJSON = `[{"id":"rule-a","kind":"static","severity":"high","invariant":"shared-inv","requiresABI":false,"version":"1.0.0"},` +
	`{"id":"rule-b","kind":"static","severity":"low","invariant":"shared-inv","requiresABI":false,"version":"2.0.0"},` +
	`{"id":"rule-c","kind":"static","severity":"medium","invariant":"solo-inv","requiresABI":false,"version":"3.0.0"}]`

// conflictCheckJSON 拼出一条 checks 记录；note 为空时省略 note 成员
// （“通过”允许没有说明）。
func conflictCheckJSON(hash, ruleID, version, status, note string) string {
	rec := `{"artifactHash":` + jsonString(hash) +
		`,"ruleId":` + jsonString(ruleID) +
		`,"version":` + jsonString(version) +
		`,"status":` + jsonString(status)
	if note != "" {
		rec += `,"note":` + jsonString(note)
	}
	return rec + "}"
}

// conflictReportRule 按规则标识取出报告中的规则结果。
func conflictReportRule(t *testing.T, report Report, id string) ReportRule {
	t.Helper()
	for _, rule := range report.Rules {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("rule %s missing from report %+v", id, report.Rules)
	return ReportRule{}
}

// conflictFindingFor 按规则标识取出报告中的 finding。
func conflictFindingFor(t *testing.T, report Report, id string) (ReportFinding, bool) {
	t.Helper()
	for _, f := range report.Findings {
		if f.RuleID == id {
			return f, true
		}
	}
	return ReportFinding{}, false
}

// --- 核心场景：两条规则共享同一不变式，一条有合法外部记录，共享名下又给出
// 布尔值（本意可能只是补充另一条规则），整份提交必须拒绝 ---

func TestBuildReportSharedInvariantConflictRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	cases := []struct {
		name    string
		rule    string // 携带外部记录的规则
		version string
		status  string
		note    string
		value   bool
	}{
		// 记录与布尔看似一致也不放行：两种来源都已给出结论，false 同样算已提供。
		{"pass_true_consistent", "rule-a", "1.0.0", StatusPass, "", true},
		{"pass_false", "rule-a", "1.0.0", StatusPass, "", false},
		{"defect_false_consistent", "rule-a", "1.0.0", StatusDefect, "反例：重入 withdraw", false},
		{"defect_true", "rule-a", "1.0.0", StatusDefect, "反例：重入 withdraw", true},
		// 工具缺失与超时不是正常结论，同样不能拿布尔值补齐。
		{"toolmissing_true", "rule-a", "1.0.0", StatusToolMissing, "符号执行引擎未安装", true},
		{"toolmissing_false", "rule-a", "1.0.0", StatusToolMissing, "符号执行引擎未安装", false},
		{"timeout_true", "rule-a", "1.0.0", StatusTimeout, "超过 300s 截止时间", true},
		{"timeout_false", "rule-a", "1.0.0", StatusTimeout, "超过 300s 截止时间", false},
		// 记录在共享不变式的另一条规则上：错误点名实际带记录的规则。
		{"pass_true_on_rule_b", "rule-b", "2.0.0", StatusPass, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := conflictCheckJSON(hash, tc.rule, tc.version, tc.status, tc.note)
			in := ruleTextSubmission(conflictRulesJSON,
				fmt.Sprintf(`"invariants":{"shared-inv":%t}`, tc.value),
				`"checks":[`+rec+`]`)
			artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
			if err != nil {
				t.Fatalf("冲突是业务判断而非格式错误，提交本身必须能解析: %v", err)
			}
			report, err := BuildReport(artifact, rules, invariants, checks)
			if err == nil {
				t.Fatalf("记录与共享名布尔值并存必须整份拒绝\ninput: %s", in)
			}
			var ei errInvalid
			if !errors.As(err, &ei) {
				t.Fatalf("冲突拒绝是提交无效（errInvalid），got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), tc.rule) {
				t.Fatalf("错误必须点名同时收到两种来源的规则 %s: %v", tc.rule, err)
			}
			if !strings.Contains(err.Error(), "both a check record and an invariant value are provided") {
				t.Fatalf("错误必须说明同时收到记录与不变式布尔值: %v", err)
			}
			other := "rule-b"
			if tc.rule == "rule-b" {
				other = "rule-a"
			}
			if strings.Contains(err.Error(), other) {
				t.Fatalf("没有收到记录的共享规则 %s 不得被点名: %v", other, err)
			}
			if report.ReportID != "" || report.Rules != nil || report.Findings != nil {
				t.Fatalf("整份拒绝不得返回部分报告: %+v", report)
			}
		})
	}
}

// --- 其他规则完全合法（甚至自带缺陷记录）也不能留下半份报告 ---

func TestBuildReportSharedInvariantConflictRejectsWholeSubmission(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	// rule-c 自带一条完全合法的“发现缺陷”记录；rule-a 的记录与共享名布尔值冲突。
	recA := conflictCheckJSON(hash, "rule-a", "1.0.0", StatusPass, "")
	recC := conflictCheckJSON(hash, "rule-c", "3.0.0", StatusDefect, "rule-c 外部反例")
	in := ruleTextSubmission(conflictRulesJSON,
		`"invariants":{"shared-inv":true}`,
		`"checks":[`+recA+`,`+recC+`]`)
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err != nil {
		t.Fatalf("提交本身必须能解析: %v", err)
	}
	report, err := BuildReport(artifact, rules, invariants, checks)
	if err == nil {
		t.Fatal("任一规则的结论来源冲突必须整份拒绝，即使其他规则全部合法")
	}
	if !strings.Contains(err.Error(), "rule-a") {
		t.Fatalf("错误必须点名冲突规则 rule-a: %v", err)
	}
	if report.ReportID != "" || len(report.Rules) != 0 || len(report.Findings) != 0 {
		t.Fatalf("其他规则再合法也不得有部分报告: %+v", report)
	}
}

// --- 允许用法：移除共享名下的布尔值后，记录规则保留状态与原始说明，
// 没有结论的规则显示“未检查” ---

func TestBuildReportSharedInvariantBooleanRemovedKeepsRecord(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	note := "  外部反例：重入\n第二行  "
	rec := conflictCheckJSON(hash, "rule-a", "1.0.0", StatusDefect, note)
	in := ruleTextSubmission(conflictRulesJSON, `"checks":[`+rec+`]`)
	report := strictParsedReport(t, in)

	ruleA := conflictReportRule(t, report, "rule-a")
	if ruleA.Status != StatusDefect || ruleA.Note != note {
		t.Fatalf("rule-a 必须保留记录的状态与原始说明: %+v", ruleA)
	}
	for _, id := range []string{"rule-b", "rule-c"} {
		if r := conflictReportRule(t, report, id); r.Status != StatusUnchecked || r.Note != "" {
			t.Fatalf("没有结论的 %s 必须是未检查且无说明: %+v", id, r)
		}
	}
	if len(report.Findings) != 1 {
		t.Fatalf("只有 rule-a 一条缺陷，got %+v", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "rule-a" || f.Version != "1.0.0" || f.ArtifactHash != hash {
		t.Fatalf("缺陷必须归属 rule-a 并绑定其版本与产物哈希: %+v", f)
	}
	if f.Evidence != note {
		t.Fatalf("外部缺陷证据必须逐字保留原始说明，got %q", f.Evidence)
	}
}

// --- 允许用法：布尔值只对应另一条规则独有的不变式时，两种来源共存；
// false 使引用它的规则产生缺陷，true 使该规则通过 ---

func TestBuildReportCheckRecordAndBooleanCoexistAcrossDistinctInvariants(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	note := "rule-a 外部反例"
	rec := conflictCheckJSON(hash, "rule-a", "1.0.0", StatusDefect, note)
	for _, value := range []bool{false, true} {
		t.Run(fmt.Sprintf("solo-inv=%t", value), func(t *testing.T) {
			in := ruleTextSubmission(conflictRulesJSON,
				fmt.Sprintf(`"invariants":{"solo-inv":%t}`, value),
				`"checks":[`+rec+`]`)
			report := strictParsedReport(t, in)

			ruleA := conflictReportRule(t, report, "rule-a")
			if ruleA.Status != StatusDefect || ruleA.Note != note {
				t.Fatalf("rule-a 必须保留记录结论与原始说明: %+v", ruleA)
			}
			fA, ok := conflictFindingFor(t, report, "rule-a")
			if !ok {
				t.Fatalf("rule-a 的外部缺陷必须产生 finding: %+v", report.Findings)
			}
			if fA.Evidence != note || fA.Version != "1.0.0" || fA.ArtifactHash != hash {
				t.Fatalf("外部缺陷证据与绑定必须保持原值: %+v", fA)
			}
			if r := conflictReportRule(t, report, "rule-b"); r.Status != StatusUnchecked {
				t.Fatalf("rule-b 没有任何结论，必须是未检查: %+v", r)
			}

			ruleC := conflictReportRule(t, report, "rule-c")
			fC, hasFC := conflictFindingFor(t, report, "rule-c")
			if !value {
				if ruleC.Status != StatusDefect {
					t.Fatalf("solo-inv=false 必须使 rule-c 发现缺陷: %+v", ruleC)
				}
				if !hasFC {
					t.Fatalf("rule-c 的布尔缺陷必须产生 finding: %+v", report.Findings)
				}
				if fC.Evidence != invariantEvidence("solo-inv") {
					t.Fatalf("布尔结论的证据沿用现有表达，got %q", fC.Evidence)
				}
				if fC.Version != "3.0.0" || fC.ArtifactHash != hash || fC.Severity != "medium" {
					t.Fatalf("布尔缺陷必须绑定 rule-c 自身的版本与产物哈希: %+v", fC)
				}
				if len(report.Findings) != 2 {
					t.Fatalf("两条来源各产生一条缺陷，got %+v", report.Findings)
				}
			} else {
				if ruleC.Status != StatusPass {
					t.Fatalf("solo-inv=true 必须使 rule-c 通过: %+v", ruleC)
				}
				if hasFC {
					t.Fatalf("通过的 rule-c 不得有 finding: %+v", fC)
				}
				if len(report.Findings) != 1 {
					t.Fatalf("只有 rule-a 一条缺陷，got %+v", report.Findings)
				}
			}
		})
	}
}

// --- 名称按原文精确匹配：大小写不同或带前后空格的名称不会自动合并，
// 既不与共享名下的记录冲突，也不作用于任何规则 ---

func TestBuildReportConflictInvariantNameMatchingIsExact(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	rec := conflictCheckJSON(hash, "rule-a", "1.0.0", StatusPass, "")
	plain := ruleTextSubmission(conflictRulesJSON, `"checks":[`+rec+`]`)
	want := strictParsedReport(t, plain)

	in := ruleTextSubmission(conflictRulesJSON,
		`"invariants":{"Shared-Inv":false," shared-inv ":false}`,
		`"checks":[`+rec+`]`)
	got := strictParsedReport(t, in)

	if got.ReportID != want.ReportID {
		t.Fatalf("大小写/空格变体不得改变报告标识:\n got %s\nwant %s", got.ReportID, want.ReportID)
	}
	if r := conflictReportRule(t, got, "rule-a"); r.Status != StatusPass {
		t.Fatalf("rule-a 的结论必须来自检查记录: %+v", r)
	}
	for _, id := range []string{"rule-b", "rule-c"} {
		if r := conflictReportRule(t, got, id); r.Status != StatusUnchecked {
			t.Fatalf("变体名布尔值不得作用于 %s: %+v", id, r)
		}
	}
	if len(got.Findings) != 0 {
		t.Fatalf("变体名布尔值不得产生缺陷: %+v", got.Findings)
	}
}
