package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 直接返回缺陷列表的既有调用方式（Run）业务回归保障。报告路径
// （BuildReport 及其归档）由 report_test.go 等覆盖；本文件保护两种调用
// 方式在不变式布尔值审计上的一致业务语义，同时保留各自的公开行为差异：
// Run 直接返回 Finding 列表，规则版本可缺省，输入不足即整体失败。

// findingKey 是一条缺陷的业务归属。
type findingKey struct {
	Rule      string
	Severity  string
	Invariant string
	Evidence  string
}

func findingSet(findings []Finding) map[findingKey]int {
	set := make(map[findingKey]int, len(findings))
	for _, f := range findings {
		set[findingKey{f.Rule, f.Severity, f.Invariant, f.Evidence}]++
	}
	return set
}

// 一份合约产物可同时适用多条规则：每个不变式为 false 的规则各自产生缺陷，
// 缺陷保留所属规则、严重级别和不变式名。
func TestRunFalseInvariantProducesDefectPerReferencingRule(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv-a"},
		{ID: "r2", Kind: "static", Severity: "medium", Invariant: "inv-b"},
		{ID: "r3", Kind: "static", Severity: "low", Invariant: "inv-c"},
	}
	invariants := map[string]bool{"inv-a": false, "inv-b": false, "inv-c": false}
	findings, err := Run(sampleArtifact(), rules, invariants)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want one defect per rule (3): %+v", len(findings), findings)
	}
	byRule := map[string]Finding{}
	for _, f := range findings {
		byRule[f.Rule] = f
	}
	for _, want := range []struct {
		rule, severity, invariant string
	}{
		{"r1", "high", "inv-a"},
		{"r2", "medium", "inv-b"},
		{"r3", "low", "inv-c"},
	} {
		f, ok := byRule[want.rule]
		if !ok {
			t.Errorf("missing finding for rule %s: %+v", want.rule, findings)
			continue
		}
		if f.Severity != want.severity {
			t.Errorf("rule %s severity = %q, want %q", want.rule, f.Severity, want.severity)
		}
		if f.Invariant != want.invariant {
			t.Errorf("rule %s invariant = %q, want %q", want.rule, f.Invariant, want.invariant)
		}
		if f.Evidence != "invariant "+want.invariant+" does not hold" {
			t.Errorf("rule %s evidence = %q, want %q", want.rule, f.Evidence,
				"invariant "+want.invariant+" does not hold")
		}
	}
}

// 值为 true 或根本没有提供该名字，都不能产生缺陷；两者都没有 finding，
// 但它们是不同输入（报告路径必须仍能区分“通过”和“未检查”，见
// TestRunParityWithReportStatuses）。
func TestRunTrueOrAbsentInvariantProducesNoFinding(t *testing.T) {
	rules := []Rule{
		{ID: "pass", Kind: "static", Severity: "high", Invariant: "holds"},
		{ID: "unchecked", Kind: "static", Severity: "high", Invariant: "never-supplied"},
	}
	for name, invariants := range map[string]map[string]bool{
		"true only":   {"holds": true},
		"false other": {"holds": true, "other": false},
		"empty":       {},
		"nil":         nil,
	} {
		findings, err := Run(sampleArtifact(), rules, invariants)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(findings) != 0 {
			t.Errorf("%s: true/absent invariants must produce no findings, got %+v", name, findings)
		}
	}
}

// 输入中没有任何规则引用的 false 值不能凭空形成发现。
func TestRunUnreferencedFalseInvariantProducesNoFinding(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Kind: "static", Severity: "high", Invariant: "referenced"},
	}
	invariants := map[string]bool{"referenced": true, "nobody-uses-me": false, "also-orphan": false}
	findings, err := Run(sampleArtifact(), rules, invariants)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("false invariants referenced by no rule must create no finding: %+v", findings)
	}
}

// 证据固定为 invariant <不变式名> does not hold，名字采用规则中的原值：
// 大小写、空白和点号按原样保留，不做归一化或修剪。
func TestRunEvidenceUsesInvariantNameAsWritten(t *testing.T) {
	written := "Balance.Monotonic v2 "
	rules := []Rule{
		{ID: "r1", Kind: "static", Severity: "critical", Invariant: written},
	}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{written: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	want := "invariant " + written + " does not hold"
	if findings[0].Evidence != want {
		t.Errorf("evidence = %q, want %q (name must be the rule's original value)",
			findings[0].Evidence, want)
	}
	if findings[0].Invariant != written {
		t.Errorf("invariant = %q, want the original spelling %q", findings[0].Invariant, written)
	}
}

// 两条不同规则引用同一个不变式：值为 false 时必须分别留下各自的缺陷，
// 不能按不变式名合并成一条，也不能把第一条规则的严重级别带到另一条上。
func TestRunSharedFalseInvariantGivesTwoFindingsWithOwnSeverity(t *testing.T) {
	rules := []Rule{
		{ID: "rule-a", Kind: "static", Severity: "high", Invariant: "shared"},
		{ID: "rule-b", Kind: "symbolic", Severity: "low", Invariant: "shared"},
	}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{"shared": false})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (one per rule, not merged by invariant name)", len(findings))
	}
	byRule := map[string]Finding{}
	for _, f := range findings {
		if _, dup := byRule[f.Rule]; dup {
			t.Fatalf("rule %s produced duplicated findings: %+v", f.Rule, findings)
		}
		byRule[f.Rule] = f
	}
	a, okA := byRule["rule-a"]
	b, okB := byRule["rule-b"]
	if !okA || !okB {
		t.Fatalf("expected findings for both rules, got %+v", findings)
	}
	if a.Severity != "high" {
		t.Errorf("rule-a severity = %q, want high", a.Severity)
	}
	if b.Severity != "low" {
		t.Errorf("rule-b severity = %q, want its own severity low, not %q", b.Severity, a.Severity)
	}
	for _, f := range []Finding{a, b} {
		if f.Invariant != "shared" {
			t.Errorf("rule %s invariant = %q, want shared", f.Rule, f.Invariant)
		}
		if f.Evidence != "invariant shared does not hold" {
			t.Errorf("rule %s evidence = %q", f.Rule, f.Evidence)
		}
	}
}

// 同一不变式值为 true 时，两条规则都不产生缺陷。
func TestRunSharedTrueInvariantGivesNoFinding(t *testing.T) {
	rules := []Rule{
		{ID: "rule-a", Kind: "static", Severity: "high", Invariant: "shared"},
		{ID: "rule-b", Kind: "symbolic", Severity: "low", Invariant: "shared"},
	}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{"shared": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("a shared true invariant must give no findings, got %+v", findings)
	}
}

// 直接返回列表的既有调用方式允许规则没有版本：缺省 Version 仍应正常给出
// 原有结论，不能套用报告提交的版本必填要求。
func TestRunAllowsRulesWithoutVersion(t *testing.T) {
	rules := []Rule{
		{ID: "no-version", Kind: "static", Severity: "high", Invariant: "inv"},
	}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{"inv": false})
	if err != nil {
		t.Fatalf("Run must not require a rule version: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "no-version" {
		t.Fatalf("expected the original defect conclusion, got %+v", findings)
	}
	// 对照：同一份规则定义走报告路径必须因版本缺失而失败，两条调用方式
	// 各自的公开行为都保留。
	if _, err := BuildReport(sampleArtifact(), rules, map[string]bool{"inv": false}, nil); err == nil {
		t.Fatal("BuildReport must keep requiring a version; only the list API omits it")
	}
}

// 缺少执行规则所需的产物内容是输入错误（errInvalid），错误必须指出缺少的
// 内容及对应规则；结论与是否提供该规则的不变式值无关。
func TestRunRequiresABIMissing(t *testing.T) {
	rules := []Rule{{ID: "abi-rule", Kind: "static", Severity: "high",
		Invariant: "inv", RequiresABI: true}}
	artifact := Artifact{Name: "Vault", ABI: "", Bytecode: "0x6080", Source: "Vault.sol"}
	for name, invariants := range map[string]map[string]bool{
		"false invariant":  {"inv": false},
		"true invariant":   {"inv": true},
		"absent invariant": {"other": true},
		"no invariants":    nil,
	} {
		findings, err := Run(artifact, rules, invariants)
		if err == nil {
			t.Errorf("%s: expected failure for the empty ABI", name)
			continue
		}
		var ei errInvalid
		if !errors.As(err, &ei) {
			t.Errorf("%s: expected an input error (errInvalid), got %T: %v", name, err, err)
		}
		if !strings.Contains(err.Error(), "abi") {
			t.Errorf("%s: error must point at the missing ABI: %v", name, err)
		}
		if !strings.Contains(err.Error(), "abi-rule") {
			t.Errorf("%s: error must name the rule: %v", name, err)
		}
		if findings != nil {
			t.Errorf("%s: failure must return no findings at all, got %+v", name, findings)
		}
	}
}

// symbolic 规则遇到空字节码同样整体失败，与不变式值无关。
func TestRunSymbolicMissingBytecode(t *testing.T) {
	rules := []Rule{{ID: "sym-rule", Kind: "symbolic", Severity: "critical", Invariant: "inv"}}
	artifact := Artifact{Name: "Vault", ABI: "abi", Bytecode: "", Source: "Vault.sol"}
	for name, invariants := range map[string]map[string]bool{
		"false invariant":  {"inv": false},
		"true invariant":   {"inv": true},
		"absent invariant": nil,
	} {
		findings, err := Run(artifact, rules, invariants)
		if err == nil {
			t.Errorf("%s: expected failure for the empty bytecode", name)
			continue
		}
		var ei errInvalid
		if !errors.As(err, &ei) {
			t.Errorf("%s: expected an input error (errInvalid), got %T: %v", name, err, err)
		}
		if !strings.Contains(err.Error(), "bytecode") {
			t.Errorf("%s: error must point at the missing bytecode: %v", name, err)
		}
		if !strings.Contains(err.Error(), "sym-rule") {
			t.Errorf("%s: error must name the rule: %v", name, err)
		}
		if findings != nil {
			t.Errorf("%s: failure must return no findings at all, got %+v", name, findings)
		}
	}
}

// 即使同次输入中排在前面的规则已能确认缺陷，输入不足也必须整次审计失败：
// 不能返回那部分发现。
func TestRunMissingContentFailsWholeAuditWithoutPartialFindings(t *testing.T) {
	rules := []Rule{
		{ID: "already-defect", Kind: "static", Severity: "high", Invariant: "broken"},
		{ID: "needs-abi", Kind: "static", Severity: "medium", Invariant: "other", RequiresABI: true},
	}
	artifact := Artifact{Name: "Vault", ABI: "", Bytecode: "0x6080", Source: "Vault.sol"}
	findings, err := Run(artifact, rules, map[string]bool{"broken": false, "other": false})
	if err == nil {
		t.Fatal("the audit must fail when a rule lacks its ABI")
	}
	if !strings.Contains(err.Error(), "needs-abi") {
		t.Fatalf("error must name the rule missing content: %v", err)
	}
	if findings != nil {
		t.Fatalf("no partial findings may be returned on failure, got %+v", findings)
	}
}

// 同样，symbolic 规则的空字节码不能被前面规则已确认的缺陷掩盖。
func TestRunMissingBytecodeFailsWholeAuditWithoutPartialFindings(t *testing.T) {
	rules := []Rule{
		{ID: "already-defect", Kind: "static", Severity: "high", Invariant: "broken"},
		{ID: "needs-bytecode", Kind: "symbolic", Severity: "critical", Invariant: "other"},
	}
	artifact := Artifact{Name: "Vault", ABI: "abi", Bytecode: "", Source: "Vault.sol"}
	findings, err := Run(artifact, rules, map[string]bool{"broken": false, "other": false})
	if err == nil {
		t.Fatal("the audit must fail when a symbolic rule lacks bytecode")
	}
	if !strings.Contains(err.Error(), "needs-bytecode") {
		t.Fatalf("error must name the rule missing content: %v", err)
	}
	if findings != nil {
		t.Fatalf("no partial findings may be returned on failure, got %+v", findings)
	}
}

// 为规则补齐所需内容后，相同布尔值应恢复正常结论；先前的输入不足绝不能被
// 记作合约缺陷。
func TestRunRecoversAfterSupplyingRequiredContent(t *testing.T) {
	rules := []Rule{
		{ID: "abi-rule", Kind: "static", Severity: "high", Invariant: "inv-a", RequiresABI: true},
		{ID: "sym-rule", Kind: "symbolic", Severity: "critical", Invariant: "inv-b"},
	}
	invariants := map[string]bool{"inv-a": false, "inv-b": false}

	incomplete := Artifact{Name: "Vault", ABI: "", Bytecode: "", Source: "Vault.sol"}
	if findings, err := Run(incomplete, rules, invariants); err == nil {
		t.Fatalf("empty ABI and bytecode must fail, got findings %+v", findings)
	}

	complete := Artifact{Name: "Vault", ABI: `[{"name":"withdraw"}]`, Bytecode: "0x6080", Source: "Vault.sol"}
	findings, err := Run(complete, rules, invariants)
	if err != nil {
		t.Fatalf("with the required content supplied the same booleans must audit: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 real defects after content is supplied", len(findings))
	}
	set := findingSet(findings)
	for _, want := range []findingKey{
		{"abi-rule", "high", "inv-a", "invariant inv-a does not hold"},
		{"sym-rule", "critical", "inv-b", "invariant inv-b does not hold"},
	} {
		if set[want] != 1 {
			t.Errorf("missing expected finding %+v; got %+v", want, findings)
		}
	}
}

// 产物名为必填输入；空名字是输入错误且不返回任何发现。
func TestRunRequiresArtifactName(t *testing.T) {
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv"}}
	findings, err := Run(Artifact{ABI: "abi", Bytecode: "0x1"}, rules, map[string]bool{"inv": false})
	if err == nil {
		t.Fatal("an empty artifact name must be an input error")
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid, got %T: %v", err, err)
	}
	if findings != nil {
		t.Fatalf("failure must return no findings, got %+v", findings)
	}
}

// 对于规则版本完整的同一份有效输入，两种调用方式的缺陷归属（规则、严重
// 级别、不变式名）与证据必须一致；报告中的每条 finding 还应绑定本次产物
// 哈希和对应规则版本。报告路径上，true 是“通过”、未提供是“未检查”，
// 两者不能因为都没有 finding 而混为一种结论。
func TestRunParityWithReportFindings(t *testing.T) {
	rules := []Rule{
		{ID: "reentrancy-guard", Kind: "static", Severity: "high", Invariant: "no-reentrant-withdraw", Version: "1.0.0"},
		{ID: "access-control", Kind: "static", Severity: "medium", Invariant: "owner-only-withdraw", RequiresABI: true, Version: "2.1.0"},
		{ID: "invariant-preserved", Kind: "symbolic", Severity: "critical", Invariant: "balance-monotonic", Version: "0.9.0"},
		{ID: "shared-a", Kind: "static", Severity: "high", Invariant: "shared", Version: "3.0.0"},
		{ID: "shared-b", Kind: "static", Severity: "low", Invariant: "shared", Version: "3.0.0"},
		{ID: "passing", Kind: "static", Severity: "low", Invariant: "holds-explicitly", Version: "4.0.0"},
		{ID: "never-checked", Kind: "static", Severity: "low", Invariant: "no-value-given", Version: "5.0.0"},
	}
	invariants := map[string]bool{
		"no-reentrant-withdraw": false, // defect
		"owner-only-withdraw":   true,  // pass
		"balance-monotonic":     false, // defect
		"shared":                false, // two defects, one per rule
		"holds-explicitly":      true,  // pass
		"orphan-false":          false, // referenced by nobody: no finding either way
	}
	artifact := sampleArtifact()

	listFindings, err := Run(artifact, rules, invariants)
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(artifact, rules, invariants, nil)
	if err != nil {
		t.Fatal(err)
	}

	// “通过”与“未检查”在报告中分别显示，不能合并。
	statusByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["passing"] != StatusPass {
		t.Errorf("passing = %q, want %q", statusByID["passing"], StatusPass)
	}
	if statusByID["never-checked"] != StatusUnchecked {
		t.Errorf("never-checked = %q, want %q", statusByID["never-checked"], StatusUnchecked)
	}
	if statusByID["access-control"] != StatusPass {
		t.Errorf("access-control = %q, want %q", statusByID["access-control"], StatusPass)
	}

	// 缺陷集合一致：归属与证据逐条相同（顺序可能不同，按集合比较）。
	listSet := findingSet(listFindings)
	reportSet := make(map[findingKey]int, len(report.Findings))
	hash := ArtifactHash(artifact)
	versionByID := make(map[string]string, len(rules))
	for _, r := range rules {
		versionByID[r.ID] = r.Version
	}
	for _, f := range report.Findings {
		reportSet[findingKey{f.RuleID, f.Severity, f.Invariant, f.Evidence}]++
		// 每条报告 finding 绑定本次产物哈希与对应规则版本。
		if f.ArtifactHash != hash {
			t.Errorf("finding %s artifact hash = %q, want %q", f.RuleID, f.ArtifactHash, hash)
		}
		if f.Version == "" {
			t.Errorf("finding %s must bind the rule version", f.RuleID)
		} else if f.Version != versionByID[f.RuleID] {
			t.Errorf("finding %s version = %q, want %q", f.RuleID, f.Version, versionByID[f.RuleID])
		}
	}
	if len(listSet) != len(reportSet) {
		t.Fatalf("Run gives %d distinct findings, report gives %d:\nlist=%+v\nreport=%+v",
			len(listSet), len(reportSet), listFindings, report.Findings)
	}
	for key, n := range listSet {
		if reportSet[key] != n {
			t.Errorf("finding %+v count = %d from Run but %d from report", key, n, reportSet[key])
		}
	}
	for key, n := range reportSet {
		if listSet[key] != n {
			t.Errorf("finding %+v count = %d from report but %d from Run", key, n, listSet[key])
		}
	}

	// 具体期望：4 条缺陷，包括共享同一 false 不变式的两条规则。
	wantKeys := map[findingKey]bool{
		{"reentrancy-guard", "high", "no-reentrant-withdraw", "invariant no-reentrant-withdraw does not hold"}: true,
		{"invariant-preserved", "critical", "balance-monotonic", "invariant balance-monotonic does not hold"}:  true,
		{"shared-a", "high", "shared", "invariant shared does not hold"}:                                       true,
		{"shared-b", "low", "shared", "invariant shared does not hold"}:                                        true,
	}
	if len(listFindings) != len(wantKeys) {
		t.Fatalf("expected %d defects, got %d: %+v", len(wantKeys), len(listFindings), listFindings)
	}
	for key := range listSet {
		if !wantKeys[key] {
			t.Errorf("unexpected defect %+v", key)
		}
	}
}

// 把不变式值翻转后，两种调用方式应同步地从“有缺陷”变为“无缺陷”。
func TestRunParityWithReportWhenInvariantHolds(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"},
		{ID: "r2", Kind: "symbolic", Severity: "low", Invariant: "inv", Version: "2"},
	}
	artifact := sampleArtifact()
	listFindings, err := Run(artifact, rules, map[string]bool{"inv": true})
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(artifact, rules, map[string]bool{"inv": true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listFindings) != 0 || len(report.Findings) != 0 {
		t.Fatalf("true invariant must give no findings on either path: %+v %+v",
			listFindings, report.Findings)
	}
}
