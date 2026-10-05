package contractsentinel

// 本文件为“直接返回缺陷列表”的审计入口 Run 补充业务回归保障。既有测试主要
// 保护生成并落盘审计报告的链路（ParseAuditInput/BuildReport/SaveReport/
// LoadReport），Run 此前没有任何业务测试。这里锁定 Run 的公开行为，并对照
// 两种调用方式在同一份有效输入上的业务一致性：
//
//   - 不变式为 false 时，引用它的每条规则各自留下缺陷；true 与未提供该名字
//     都不产生缺陷；没有被任何规则引用的 false 值不能凭空形成发现。
//   - 缺陷保留所属规则、严重级别、不变式名，证据固定为
//     “invariant <规则中的不变式原值> does not hold”。
//   - Run 允许规则没有版本；版本必填只是报告提交入口的要求。
//   - 缺少执行规则所需的产物内容（ABI / 字节码）是整次审计的输入错误：
//     不返回部分发现，且与该规则自身的不变式值无关；补齐内容后相同布尔值
//     恢复正常结论，先前的输入不足永远不被记作合约缺陷。

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// expectRunInputError 断言 Run 把整次审计作为输入错误拒绝：错误是
// errInvalid，消息指出缺少的内容和对应规则，并且不交出任何缺陷（包括同次
// 输入中其他规则已经可以确认的缺陷）。
func expectRunInputError(t *testing.T, artifact Artifact, rules []Rule, inv map[string]bool, wantRule, wantContent string) {
	t.Helper()
	findings, err := Run(artifact, rules, inv)
	if err == nil {
		t.Fatalf("expected input error naming %s, audit succeeded with findings %+v", wantContent, findings)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid (input error), got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), wantRule) {
		t.Fatalf("error must name the rule %q: %v", wantRule, err)
	}
	if !strings.Contains(err.Error(), wantContent) {
		t.Fatalf("error must name the missing content %q: %v", wantContent, err)
	}
	if len(findings) != 0 {
		t.Fatalf("a refused audit must return no findings, not even confirmed ones: %+v", findings)
	}
}

// passUncheckedFixture 是一份版本完整的有效输入：一条 false（缺陷）、一条
// true（通过）、一条未提供值（未检查），外加一个没有任何规则引用的 false
// 值。两种调用方式在这份输入上的结论必须一致。
func passUncheckedFixture() (Artifact, []Rule, map[string]bool) {
	artifact := sampleArtifact()
	rules := []Rule{
		{ID: "r-defect", Kind: "static", Severity: "high", Invariant: "inv-bad", Version: "1.0.0"},
		{ID: "r-pass", Kind: "static", Severity: "medium", Invariant: "inv-good", Version: "2.0.0"},
		{ID: "r-unchecked", Kind: "static", Severity: "low", Invariant: "inv-missing", Version: "3.0.0"},
	}
	inv := map[string]bool{
		"inv-bad":      false,
		"inv-good":     true,
		"orphan-false": false, // 没有任何规则引用，绝不能凭空形成发现
	}
	return artifact, rules, inv
}

// --- 布尔不变式语义：false 产生缺陷，true 与未提供都不产生 ---

func TestRunFalseInvariantProducesFindingWithFullAttribution(t *testing.T) {
	rules := []Rule{
		{ID: "reentrancy-guard", Kind: "static", Severity: "high", Invariant: "no-reentrant-withdraw", Version: "1.0.0"},
	}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{"no-reentrant-withdraw": false})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Rule != "reentrancy-guard" {
		t.Errorf("finding must keep its rule, got %q", f.Rule)
	}
	if f.Severity != "high" {
		t.Errorf("finding must keep its severity, got %q", f.Severity)
	}
	if f.Invariant != "no-reentrant-withdraw" {
		t.Errorf("finding must keep its invariant name, got %q", f.Invariant)
	}
	if want := "invariant no-reentrant-withdraw does not hold"; f.Evidence != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
}

func TestRunTrueInvariantProducesNoFinding(t *testing.T) {
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv"}}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{"inv": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("a true invariant must produce no finding, got %+v", findings)
	}
}

func TestRunMissingInvariantProducesNoFinding(t *testing.T) {
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv"}}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{"other-inv": false})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("an invariant whose value was never provided must produce no finding, got %+v", findings)
	}
}

// 输入中没有任何规则引用的 false 值不能凭空形成发现，即使它显式为 false。
func TestRunUnreferencedFalseValueProducesNoFinding(t *testing.T) {
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "referenced"}}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{
		"referenced":   true,
		"unreferenced": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("only referenced rules may produce findings, got %+v", findings)
	}
}

// 没有规则时，任何 false 值都无处归属。
func TestRunNoRulesNoFindings(t *testing.T) {
	findings, err := Run(sampleArtifact(), nil, map[string]bool{"anything": false})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("no rules means no findings, got %+v", findings)
	}
}

// --- 证据中的不变式名采用规则中的原值，匹配也按原值精确进行 ---

func TestRunEvidenceUsesRuleInvariantNameVerbatim(t *testing.T) {
	// 带首尾空白、大小写混合的名字必须原样进入证据，不做修剪或规范化。
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: " InVaRiAnT "}}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{" InVaRiAnT ": false})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	want := "invariant " + rules[0].Invariant + " does not hold"
	if findings[0].Evidence != want {
		t.Fatalf("evidence = %q, want the rule's original invariant spelling %q", findings[0].Evidence, want)
	}
}

func TestRunInvariantLookupUsesExactName(t *testing.T) {
	// 规则引用 "Inv"：只给出 "inv" 的 false 不命中，不产生缺陷。
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "Inv"}}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{"inv": false})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("invariant names must match exactly; got %+v", findings)
	}
	// 给出规则中的原值时才产生缺陷，证据沿用规则中的拼写。
	findings, err = Run(sampleArtifact(), rules, map[string]bool{"Inv": false})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Evidence != "invariant Inv does not hold" {
		t.Fatalf("the rule's own spelling must drive the finding, got %+v", findings)
	}
}

// --- 两条规则引用同一个不变式：各自独立归属，不按不变式名合并 ---

func TestRunSharedFalseInvariantKeepsSeparateAttribution(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Kind: "static", Severity: "high", Invariant: "shared", Version: "1"},
		{ID: "r2", Kind: "static", Severity: "low", Invariant: "shared", Version: "2"},
	}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{"shared": false})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("one false value referenced by two rules is two defects, got %d: %+v", len(findings), findings)
	}
	byRule := map[string]Finding{}
	for _, f := range findings {
		if _, dup := byRule[f.Rule]; dup {
			t.Fatalf("findings merged by invariant name: %+v", findings)
		}
		byRule[f.Rule] = f
	}
	f1, ok1 := byRule["r1"]
	f2, ok2 := byRule["r2"]
	if !ok1 || !ok2 {
		t.Fatalf("both rules must keep their own defect: %+v", findings)
	}
	// 严重级别必须各自来自所属规则，不能把第一条规则的 high 带到 r2。
	if f1.Severity != "high" || f2.Severity != "low" {
		t.Fatalf("severities must follow each rule, got r1=%q r2=%q", f1.Severity, f2.Severity)
	}
	// 两条缺陷的证据都固定引用同一不变式原值。
	for _, f := range []Finding{f1, f2} {
		if f.Invariant != "shared" || f.Evidence != "invariant shared does not hold" {
			t.Errorf("finding %s attribution wrong: %+v", f.Rule, f)
		}
	}

	// 同一份输入走报告入口：同样是两条独立缺陷，归属一致，且各自绑定产物
	// 哈希与所属规则版本。
	report, err := BuildReport(sampleArtifact(), rules, map[string]bool{"shared": false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("report must carry two findings too, got %+v", report.Findings)
	}
	hash := ArtifactHash(sampleArtifact())
	for _, rf := range report.Findings {
		lf, ok := byRule[rf.RuleID]
		if !ok {
			t.Errorf("report finding for unknown rule %q", rf.RuleID)
			continue
		}
		if rf.Severity != lf.Severity || rf.Invariant != lf.Invariant || rf.Evidence != lf.Evidence {
			t.Errorf("report/run attribution mismatch for %s:\n report %+v\n list  %+v", rf.RuleID, rf, lf)
		}
		if rf.ArtifactHash != hash {
			t.Errorf("finding for %s must bind this artifact hash", rf.RuleID)
		}
		wantVersion := "1"
		if rf.RuleID == "r2" {
			wantVersion = "2"
		}
		if rf.Version != wantVersion {
			t.Errorf("finding for %s must bind its own rule version %q, got %q", rf.RuleID, wantVersion, rf.Version)
		}
	}
}

func TestRunSharedTrueInvariantLeavesNoDefect(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Kind: "static", Severity: "high", Invariant: "shared", Version: "1"},
		{ID: "r2", Kind: "static", Severity: "low", Invariant: "shared", Version: "2"},
	}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{"shared": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("a shared true invariant must clear both rules, got %+v", findings)
	}
	// 报告入口同样没有缺陷，两条规则各自显示“通过”。
	report, err := BuildReport(sampleArtifact(), rules, map[string]bool{"shared": true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("report must carry no findings, got %+v", report.Findings)
	}
	for _, r := range report.Rules {
		if r.Status != StatusPass {
			t.Errorf("rule %s status = %q, want %q", r.ID, r.Status, StatusPass)
		}
	}
}

// --- 两种调用方式在同一份有效输入上的业务一致性 ---

func TestRunAndReportAgreeOnDefectAttribution(t *testing.T) {
	artifact, rules, inv := passUncheckedFixture()
	list, err := Run(artifact, rules, inv)
	if err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(artifact, rules, inv, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 无引用的 orphan-false 在两种入口都不产生发现，整份输入只有一条缺陷。
	if len(list) != 1 {
		t.Fatalf("Run findings = %+v, want exactly the one referenced defect", list)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("report findings = %+v, want exactly the one referenced defect", report.Findings)
	}
	lf, rf := list[0], report.Findings[0]
	// 规则、严重级别、不变式名与证据跨两种调用方式完全一致。
	if rf.RuleID != lf.Rule || rf.Severity != lf.Severity ||
		rf.Invariant != lf.Invariant || rf.Evidence != lf.Evidence {
		t.Fatalf("report/list attribution mismatch:\n report %+v\n list  %+v", rf, lf)
	}
	if rf.RuleID != "r-defect" {
		t.Fatalf("the sole defect must belong to r-defect, got %q", rf.RuleID)
	}
	// 报告中的每条 finding 还绑定本次产物哈希和对应规则版本。
	if rf.ArtifactHash != ArtifactHash(artifact) {
		t.Errorf("artifact hash = %q, want %q", rf.ArtifactHash, ArtifactHash(artifact))
	}
	if rf.Version != "1.0.0" {
		t.Errorf("version = %q, want the defect rule's version 1.0.0", rf.Version)
	}
}

// 报告必须分别显示“通过”和“未检查”：两者都没有 finding，但结论不能混为一种。
// 列表入口对这两种情况同样都不留下缺陷。
func TestRunAndReportKeepPassAndUncheckedDistinct(t *testing.T) {
	artifact, rules, inv := passUncheckedFixture()
	list, err := Run(artifact, rules, inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if f.Rule == "r-pass" || f.Rule == "r-unchecked" {
			t.Fatalf("neither pass nor unchecked may leave a list finding: %+v", f)
		}
	}
	report, err := BuildReport(artifact, rules, inv, nil)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, r := range report.Rules {
		status[r.ID] = r.Status
	}
	if status["r-defect"] != StatusDefect {
		t.Errorf("r-defect = %q, want %q", status["r-defect"], StatusDefect)
	}
	if status["r-pass"] != StatusPass {
		t.Errorf("r-pass = %q, want %q", status["r-pass"], StatusPass)
	}
	if status["r-unchecked"] != StatusUnchecked {
		t.Errorf("r-unchecked = %q, want %q", status["r-unchecked"], StatusUnchecked)
	}
	if status["r-pass"] == status["r-unchecked"] {
		t.Fatal("通过 and 未检查 must stay distinct conclusions even though neither has a finding")
	}
}

// --- 直接返回列表的既有调用方式允许规则没有版本 ---

func TestRunAllowsRulesWithoutVersion(t *testing.T) {
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv"}} // Version 留空
	inv := map[string]bool{"inv": false}

	findings, err := Run(sampleArtifact(), rules, inv)
	if err != nil {
		t.Fatalf("Run must keep accepting versionless rules: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("versionless rule must still yield its defect, got %+v", findings)
	}
	if f := findings[0]; f.Rule != "r1" || f.Severity != "high" ||
		f.Invariant != "inv" || f.Evidence != "invariant inv does not hold" {
		t.Fatalf("versionless defect attribution wrong: %+v", f)
	}

	// 同一条规则走报告提交入口仍受版本必填约束，列表入口的宽松不能外传。
	if _, err := BuildReport(sampleArtifact(), rules, inv, nil); err == nil {
		t.Fatal("report submission must still require a rule version")
	} else if !strings.Contains(err.Error(), "version") {
		t.Fatalf("report error must name the missing version, got %v", err)
	}
}

// --- 缺少执行规则所需的产物内容：整次审计作为输入错误失败 ---

func TestRunMissingABIRefusesWholeAudit(t *testing.T) {
	noABI := Artifact{Name: "Vault", ABI: "", Bytecode: "0x6080"}
	rules := []Rule{
		// 排在前面的规则仅凭 false 不变式即可确认缺陷。
		{ID: "r-confirmed", Kind: "static", Severity: "critical", Invariant: "inv-other"},
		// 后面的规则需要 ABI，但产物没有 ABI。
		{ID: "r-abi", Kind: "static", Severity: "medium", Invariant: "inv-abi", RequiresABI: true},
	}
	// 拒绝与缺失规则自身的不变式值无关：true、false、未提供都必须整次失败。
	type tc struct {
		name string
		inv  map[string]bool
	}
	cases := []tc{
		{name: "missing-rule-invariant-true", inv: map[string]bool{"inv-other": false, "inv-abi": true}},
		{name: "missing-rule-invariant-false", inv: map[string]bool{"inv-other": false, "inv-abi": false}},
		{name: "missing-rule-invariant-absent", inv: map[string]bool{"inv-other": false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// r-confirmed 的已确认缺陷也不能在失败时返回。
			expectRunInputError(t, noABI, rules, tc.inv, "r-abi", "ABI")
		})
	}
}

func TestRunSymbolicMissingBytecodeRefusesWholeAudit(t *testing.T) {
	noBytecode := Artifact{Name: "Vault", ABI: "abi", Bytecode: ""}
	rules := []Rule{
		{ID: "r-confirmed", Kind: "static", Severity: "critical", Invariant: "inv-other"},
		{ID: "r-symbolic", Kind: "symbolic", Severity: "high", Invariant: "inv-sym"},
	}
	type tc struct {
		name string
		inv  map[string]bool
	}
	cases := []tc{
		{name: "missing-rule-invariant-true", inv: map[string]bool{"inv-other": false, "inv-sym": true}},
		{name: "missing-rule-invariant-false", inv: map[string]bool{"inv-other": false, "inv-sym": false}},
		{name: "missing-rule-invariant-absent", inv: map[string]bool{"inv-other": false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectRunInputError(t, noBytecode, rules, tc.inv, "r-symbolic", "bytecode")
		})
	}
}

// 报告入口对同样的输入不足同样整次失败，不返回一份看似成功的报告。
func TestRunAndReportBothRefuseInsufficientInput(t *testing.T) {
	cases := []struct {
		name        string
		artifact    Artifact
		rules       []Rule
		wantRule    string
		wantContent string
	}{
		{
			name:        "missing-abi",
			artifact:    Artifact{Name: "Vault", ABI: "", Bytecode: "0x6080"},
			rules:       []Rule{{ID: "r-abi", Kind: "static", Severity: "high", Invariant: "inv", RequiresABI: true, Version: "1"}},
			wantRule:    "r-abi",
			wantContent: "ABI",
		},
		{
			name:        "missing-bytecode",
			artifact:    Artifact{Name: "Vault", ABI: "abi", Bytecode: ""},
			rules:       []Rule{{ID: "r-symbolic", Kind: "symbolic", Severity: "high", Invariant: "inv", Version: "1"}},
			wantRule:    "r-symbolic",
			wantContent: "bytecode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := map[string]bool{"inv": false}
			expectRunInputError(t, tc.artifact, tc.rules, inv, tc.wantRule, tc.wantContent)

			report, err := BuildReport(tc.artifact, tc.rules, inv, nil)
			if err == nil {
				t.Fatalf("report must be refused too, got %+v", report)
			}
			var ei errInvalid
			if !errors.As(err, &ei) {
				t.Fatalf("report refusal must be an input error, got %T: %v", err, err)
			}
			if !reflect.DeepEqual(report, Report{}) {
				t.Fatalf("refusal must return no partial report, got %+v", report)
			}
		})
	}
}

// 为规则补齐所需内容后，相同布尔值恢复正常结论：先前的输入不足从未被记作
// 合约缺陷——false 只在内容齐备时产生一条归属完整的缺陷，true 仍然没有。
func TestRunRefusalClearsAfterSupplyingRequiredContent(t *testing.T) {
	cases := []struct {
		name        string
		missing     Artifact
		fixed       Artifact
		rules       []Rule
		wantContent string
	}{
		{
			name:        "abi-supplied",
			missing:     Artifact{Name: "Vault", Bytecode: "0x6080"},
			fixed:       Artifact{Name: "Vault", ABI: `[{"name":"withdraw"}]`, Bytecode: "0x6080"},
			rules:       []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", RequiresABI: true}},
			wantContent: "ABI",
		},
		{
			name:        "bytecode-supplied",
			missing:     Artifact{Name: "Vault", ABI: "abi"},
			fixed:       Artifact{Name: "Vault", ABI: "abi", Bytecode: "0x6080"},
			rules:       []Rule{{ID: "r1", Kind: "symbolic", Severity: "high", Invariant: "inv"}},
			wantContent: "bytecode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 内容缺失时，哪怕不变式为 false 也只能整次失败。
			expectRunInputError(t, tc.missing, tc.rules, map[string]bool{"inv": false}, "r1", tc.wantContent)

			// 补齐内容、布尔值仍为 false：恢复为一条归属完整的真实缺陷。
			findings, err := Run(tc.fixed, tc.rules, map[string]bool{"inv": false})
			if err != nil {
				t.Fatalf("audit must succeed once content is supplied: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %+v, want one defect", findings)
			}
			if f := findings[0]; f.Rule != "r1" || f.Severity != "high" ||
				f.Invariant != "inv" || f.Evidence != "invariant inv does not hold" {
				t.Fatalf("recovered defect attribution wrong: %+v", f)
			}

			// 相同输入但不变式为 true：没有缺陷，证明输入不足不会沉淀为缺陷。
			cleared, err := Run(tc.fixed, tc.rules, map[string]bool{"inv": true})
			if err != nil {
				t.Fatal(err)
			}
			if len(cleared) != 0 {
				t.Fatalf("true invariant after recovery must leave no defect, got %+v", cleared)
			}
		})
	}
}

// --- Run 既有的其他公开行为 ---

// 产物名是审计的必备输入。
func TestRunRequiresArtifactName(t *testing.T) {
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv"}}
	findings, err := Run(Artifact{ABI: "x", Bytecode: "y"}, rules, map[string]bool{"inv": false})
	if err == nil {
		t.Fatalf("expected input error for empty artifact name, got findings %+v", findings)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "name") {
		t.Fatalf("error must name the missing artifact name: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("refused audit must return no findings, got %+v", findings)
	}
}

// 列表保持既有的确定性顺序：按严重级别字符串字典序降序、同级按规则 id
// 升序排列（demo 直接按该顺序打印）。注意这里锁定的是 Run 现有的字符串
// 比较行为而非业务严重级别权重——字典序下 "low" 排在 "high" 之前——回归
// 保障不得悄悄改变该公开输出顺序。
func TestRunFindingsKeepSeverityThenRuleOrder(t *testing.T) {
	rules := []Rule{
		{ID: "r-high-b", Kind: "static", Severity: "high", Invariant: "i-high-b"},
		{ID: "r-high-a", Kind: "static", Severity: "high", Invariant: "i-high-a"},
		{ID: "r-low", Kind: "static", Severity: "low", Invariant: "i-low"},
	}
	findings, err := Run(sampleArtifact(), rules, map[string]bool{
		"i-low": false, "i-high-b": false, "i-high-a": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, f := range findings {
		got = append(got, f.Rule)
	}
	want := []string{"r-low", "r-high-a", "r-high-b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finding order = %v, want %v (severity string desc, then rule id asc)", got, want)
	}
}
