package contractsentinel

import (
	"strings"
	"testing"
)

// 本文件回归保护 audit 提交的“结论来源冲突”：外部检查记录按规则标识与版本
// 归属，而 invariants 中的布尔值按名称作用于所有引用该不变式的规则。因此
// 两条规则共享同一不变式时，只要其中一条已有 checks 记录，为该共享名称再
// 给布尔值——即使本意只是补充另一条规则——整份提交都必须拒绝。true 与
// false 都是“已经提供了结论”，false 不被当作没有提供；两边看起来一致
// （通过+true、发现缺陷+false）也不能放行，工具缺失/超时同样不能拿布尔值
// 补成正常结论。

// sharedInvariantRules 返回两条引用同一不变式的规则：rule-checked 将拿到
// 外部检查记录，rule-plain 没有任何结论。
func sharedInvariantRules() []Rule {
	return []Rule{
		{ID: "rule-checked", Kind: "static", Severity: "high", Invariant: "shared-inv", Version: "1.2.0"},
		{ID: "rule-plain", Kind: "static", Severity: "low", Invariant: "shared-inv", Version: "3.4.0"},
	}
}

// legalSharedCheck 构造一条绑定值完全合法的检查记录：产物哈希、规则版本与
// 必填说明都满足校验，使失败只能来自结论来源冲突。
func legalSharedCheck(status, note string) CheckRecord {
	return CheckRecord{
		ArtifactHash: ArtifactHash(sampleArtifact()),
		RuleID:       "rule-checked",
		Version:      "1.2.0",
		Status:       status,
		Note:         note,
	}
}

func assertConflictError(t *testing.T, err error, ruleID string) {
	t.Helper()
	if err == nil {
		t.Fatalf("check record + invariant boolean on the same name must be rejected (rule %s)", ruleID)
	}
	if !strings.Contains(err.Error(), "rule "+ruleID) {
		t.Fatalf("error must name the rule that received both sources, got: %v", err)
	}
	if !strings.Contains(err.Error(), "both a check record and an invariant value") {
		t.Fatalf("error must state the conflict reason, got: %v", err)
	}
}

// 核心场景：两条规则共享 shared-inv，rule-checked 已有合法检查记录；用户为
// shared-inv 给出 false——本意只是补充 rule-plain，但布尔值按名称同样落在
// rule-checked 上，整份提交必须拒绝。false 也是已提供的结论。
func TestBuildReportConflictSharedInvariantFalse(t *testing.T) {
	checks := []CheckRecord{legalSharedCheck(StatusPass, "")}
	invariants := map[string]bool{"shared-inv": false}
	_, err := BuildReport(sampleArtifact(), sharedInvariantRules(), invariants, checks)
	assertConflictError(t, err, "rule-checked")
}

// 同上，布尔值为 true：true 同样构成冲突，不是“确认一下已有的通过”。
func TestBuildReportConflictSharedInvariantTrue(t *testing.T) {
	checks := []CheckRecord{legalSharedCheck(StatusDefect, "反例：重入转出了同一笔余额")}
	invariants := map[string]bool{"shared-inv": true}
	_, err := BuildReport(sampleArtifact(), sharedInvariantRules(), invariants, checks)
	assertConflictError(t, err, "rule-checked")
}

// 冲突报错点名的是实际同时收到两种来源的规则：检查记录在 rule-plain 上时，
// 错误必须点名 rule-plain 而不是 rule-checked。
func TestBuildReportConflictNamesTheCheckedRule(t *testing.T) {
	check := legalSharedCheck(StatusPass, "")
	check.RuleID = "rule-plain"
	check.Version = "3.4.0"
	invariants := map[string]bool{"shared-inv": false}
	_, err := BuildReport(sampleArtifact(), sharedInvariantRules(), invariants, []CheckRecord{check})
	assertConflictError(t, err, "rule-plain")
	if strings.Contains(err.Error(), "rule-checked") {
		t.Fatalf("error must not blame the rule that only received the boolean: %v", err)
	}
}

// 两边看起来一致也不能放行：通过+true、发现缺陷+false 仍是两种来源各给了一
// 次结论；工具缺失/超时属于检查未得到正常结论，同样不能拿布尔值补成通过或
// 缺陷。所有记录的哈希、版本与必填说明都合法，失败只能来自来源冲突。
func TestBuildReportConflictConsistentLookingCombinations(t *testing.T) {
	cases := []struct {
		name   string
		status string
		note   string
		value  bool
	}{
		{"pass record with true", StatusPass, "", true},
		{"pass record with false", StatusPass, "", false},
		{"defect record with false", StatusDefect, "反例：call 在扣减前交出控制权", false},
		{"defect record with true", StatusDefect, "反例：call 在扣减前交出控制权", true},
		{"tool missing with true", StatusToolMissing, "PATH 中未找到 mythril", true},
		{"tool missing with false", StatusToolMissing, "PATH 中未找到 mythril", false},
		{"timeout with true", StatusTimeout, "300s 截止时间到达仍未遍历完", true},
		{"timeout with false", StatusTimeout, "300s 截止时间到达仍未遍历完", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checks := []CheckRecord{legalSharedCheck(tc.status, tc.note)}
			invariants := map[string]bool{"shared-inv": tc.value}
			_, err := BuildReport(sampleArtifact(), sharedInvariantRules(), invariants, checks)
			assertConflictError(t, err, "rule-checked")
		})
	}
}

// 允许的使用方式：移除共享名称下的布尔值后，有检查记录的规则保留自己的状
// 态与原始说明，没有结论的规则显示未检查。
func TestBuildReportSharedInvariantWithoutBooleanSucceeds(t *testing.T) {
	const note = "  反例原文：含前后空格与中文\n"
	checks := []CheckRecord{legalSharedCheck(StatusDefect, note)}
	report, err := BuildReport(sampleArtifact(), sharedInvariantRules(), nil, checks)
	if err != nil {
		t.Fatalf("removing the boolean must make the submission legal: %v", err)
	}
	statusByID := map[string]string{}
	noteByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
		noteByID[r.ID] = r.Note
	}
	if statusByID["rule-checked"] != StatusDefect {
		t.Errorf("rule-checked = %q, want %q", statusByID["rule-checked"], StatusDefect)
	}
	if noteByID["rule-checked"] != note {
		t.Errorf("rule-checked note = %q, must keep the original %q", noteByID["rule-checked"], note)
	}
	if statusByID["rule-plain"] != StatusUnchecked {
		t.Errorf("rule-plain = %q, want %q", statusByID["rule-plain"], StatusUnchecked)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "rule-checked" || f.Version != "1.2.0" || f.ArtifactHash != ArtifactHash(sampleArtifact()) {
		t.Fatalf("defect must stay bound to rule-checked's version and the artifact hash: %+v", f)
	}
	if f.Evidence != note {
		t.Fatalf("external defect evidence must be the original note, got %q", f.Evidence)
	}
}

// 允许的使用方式：布尔值只对应另一条规则独有的不变式时，两种来源在同一份
// 提交中共存。false 使引用它的规则产生缺陷（证据沿用现有表达），true 使该
// 规则通过；检查记录一侧的状态与说明不受影响。
func TestBuildReportCheckAndBooleanCoexistOnDistinctInvariants(t *testing.T) {
	rules := []Rule{
		{ID: "rule-checked", Kind: "static", Severity: "high", Invariant: "inv-checked", Version: "1.2.0"},
		{ID: "rule-bool", Kind: "static", Severity: "medium", Invariant: "inv-bool", Version: "2.0.0"},
	}
	const note = "外部反例：原文保留"
	checks := []CheckRecord{legalSharedCheck(StatusDefect, note)}
	hash := ArtifactHash(sampleArtifact())

	// false：rule-bool 产生缺陷，证据为现有的不变式表达。
	report, err := BuildReport(sampleArtifact(), rules, map[string]bool{"inv-bool": false}, checks)
	if err != nil {
		t.Fatalf("distinct invariants must allow both sources in one submission: %v", err)
	}
	statusByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["rule-checked"] != StatusDefect || statusByID["rule-bool"] != StatusDefect {
		t.Fatalf("statuses = %+v, want both 发现缺陷", statusByID)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %+v, want one per defecting rule", report.Findings)
	}
	findingByRule := map[string]ReportFinding{}
	for _, f := range report.Findings {
		findingByRule[f.RuleID] = f
	}
	external, ok := findingByRule["rule-checked"]
	if !ok {
		t.Fatalf("rule-checked finding missing: %+v", report.Findings)
	}
	if external.Evidence != note || external.Version != "1.2.0" || external.ArtifactHash != hash {
		t.Fatalf("external defect must keep the original note and rule binding: %+v", external)
	}
	boolean, ok := findingByRule["rule-bool"]
	if !ok {
		t.Fatalf("rule-bool finding missing: %+v", report.Findings)
	}
	if boolean.Evidence != "invariant inv-bool does not hold" {
		t.Fatalf("boolean defect evidence must use the existing expression, got %q", boolean.Evidence)
	}
	if boolean.Version != "2.0.0" || boolean.ArtifactHash != hash || boolean.Invariant != "inv-bool" {
		t.Fatalf("boolean defect must bind rule-bool's own version and the artifact hash: %+v", boolean)
	}

	// true：rule-bool 通过，缺陷只剩检查记录那一条。
	report, err = BuildReport(sampleArtifact(), rules, map[string]bool{"inv-bool": true}, checks)
	if err != nil {
		t.Fatal(err)
	}
	statusByID = map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["rule-bool"] != StatusPass {
		t.Errorf("rule-bool = %q, want %q", statusByID["rule-bool"], StatusPass)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "rule-checked" {
		t.Fatalf("true must clear rule-bool's defect: %+v", report.Findings)
	}
}

// 不变式名称按原文精确匹配：大小写不同或带前后空格的名称不会自动合并，因
// 此不会与检查记录构成冲突，也不会成为任何规则的结论。
func TestBuildReportInvariantNameMatchedExactly(t *testing.T) {
	checks := []CheckRecord{legalSharedCheck(StatusPass, "")}
	invariants := map[string]bool{
		"Shared-Inv":   false, // 大小写不同：另一个名字
		" shared-inv ": false, // 前后空格：另一个名字
	}
	report, err := BuildReport(sampleArtifact(), sharedInvariantRules(), invariants, checks)
	if err != nil {
		t.Fatalf("case/whitespace variants must not merge with the rule's invariant: %v", err)
	}
	statusByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["rule-checked"] != StatusPass {
		t.Errorf("rule-checked = %q, want the check record's %q", statusByID["rule-checked"], StatusPass)
	}
	if statusByID["rule-plain"] != StatusUnchecked {
		t.Errorf("rule-plain = %q, want %q: variant names must not conclude it", statusByID["rule-plain"], StatusUnchecked)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("variant names must not produce defects: %+v", report.Findings)
	}
}
