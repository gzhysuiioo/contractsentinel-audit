package contractsentinel

import (
	"os"
	"path/filepath"
	"testing"
)

// 本文件在进程内 API 层面钉住 README 完整 Vault 示例公开的绑定值：
// 产物哈希与成功报告标识由固定输入内容确定，任何使程序“只接受新计算结果、
// 却拒绝原合法外部结论”或悄悄改变报告标识的改动，都会在这里立刻失败。
// 冻结提交与命令行回归用例共用同一份夹具（cmd/contractsentinel/testdata）。

func vaultFixtureBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "cmd", "contractsentinel", "testdata", "vault-audit-input.json"))
	if err != nil {
		t.Fatalf("frozen Vault fixture is missing: %v", err)
	}
	return raw
}

// TestVaultExamplePublishedArtifactHash 产物哈希只由 abi、bytecode、source
// 三个字符串内容算出（名称不参与），必须等于 README 公开值。
func TestVaultExamplePublishedArtifactHash(t *testing.T) {
	artifact, _, _, _, err := ParseAuditInput(vaultFixtureBytes(t))
	if err != nil {
		t.Fatalf("the published Vault submission must parse: %v", err)
	}
	if got := ArtifactHash(artifact); got != "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7" {
		t.Fatalf("artifact hash = %q, want published 0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7", got)
	}
}

// TestVaultExamplePublishedReportID 原样导入三条外部检查结论后，整份报告的
// 内容寻址标识必须等于 README 公开值，且报告内容保持示例中的三种状态、
// 版本与唯一缺陷绑定。
func TestVaultExamplePublishedReportID(t *testing.T) {
	artifact, rules, invariants, checks, err := ParseAuditInput(vaultFixtureBytes(t))
	if err != nil {
		t.Fatalf("the published Vault submission must parse: %v", err)
	}
	report, err := BuildReport(artifact, rules, invariants, checks)
	if err != nil {
		t.Fatalf("importing the published conclusions must build a report: %v", err)
	}
	if report.ReportID != "a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34" {
		t.Fatalf("reportId = %q, want published a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34", report.ReportID)
	}
	if report.Artifact.Hash != "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7" {
		t.Fatalf("artifact hash = %q, want published hash", report.Artifact.Hash)
	}

	wantStatus := map[string]struct {
		version string
		status  string
	}{
		"reentrancy-guard":    {"1.4.2", StatusDefect},
		"owner-only-withdraw": {"2.1.0", StatusPass},
		"solvency-symbolic":   {"0.9.3", StatusToolMissing},
	}
	if len(report.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(report.Rules))
	}
	for _, rule := range report.Rules {
		want, ok := wantStatus[rule.ID]
		if !ok {
			t.Fatalf("unexpected rule %q", rule.ID)
		}
		if rule.Version != want.version || rule.Status != want.status {
			t.Fatalf("rule %s = %q/%q, want %q/%q", rule.ID, rule.Version, rule.Status, want.version, want.status)
		}
	}

	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the reentrancy defect", report.Findings)
	}
	finding := report.Findings[0]
	if finding.RuleID != "reentrancy-guard" || finding.Version != "1.4.2" {
		t.Fatalf("finding = %+v, want reentrancy-guard 1.4.2", finding)
	}
	if finding.ArtifactHash != report.Artifact.Hash {
		t.Fatalf("finding hash %q must bind the published artifact hash %q", finding.ArtifactHash, report.Artifact.Hash)
	}
	wantEvidence := "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
	if finding.Evidence != wantEvidence {
		t.Fatalf("evidence = %q, want the verbatim counterexample note", finding.Evidence)
	}

	// 同一份报告重复计算标识必须一致：外部检查器依赖的绑定值是确定性的。
	if got := ReportID(report); got != report.ReportID {
		t.Fatalf("ReportID is not deterministic: %q vs %q", got, report.ReportID)
	}
}

// TestVaultExampleStaleHashRejectsWholeSubmission 改动源码字符串内容却仍
// 携带原公开哈希的 checks 记录时，整份提交失败且错误能指出出错规则，
// 不会构造任何部分报告。
func TestVaultExampleStaleHashRejectsWholeSubmission(t *testing.T) {
	artifact, rules, invariants, checks, err := ParseAuditInput(vaultFixtureBytes(t))
	if err != nil {
		t.Fatalf("the published Vault submission must parse: %v", err)
	}
	artifact.Source += "\n" // 真实内容变化；checks 的哈希保持公开值不变。
	if _, err := BuildReport(artifact, rules, invariants, checks); err == nil {
		t.Fatal("stale checks artifact hash after a source change must reject the whole submission")
	} else if msg := err.Error(); msg != "check for rule reentrancy-guard: artifact hash mismatch" {
		t.Fatalf("error = %q, want the mismatch named after the first offending rule", msg)
	}
}
