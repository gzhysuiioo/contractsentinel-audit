package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// 本文件在真实命令行进程边界上回归保护“直接返回缺陷列表”的既有调用方式：
// demo 命令调用 contractsentinel.Run，规则不带版本，输出每条缺陷的规则、
// 严重级别、不变式名和证据，最后给出汇总。它不生成、也不打印审计报告。

type demoFinding struct {
	rule      string
	severity  string
	invariant string
	evidence  string
}

// parseDemoFindings 解析 demo 的 rule=... 行，返回每条缺陷。行格式固定为
// rule=<id> severity=<…> invariant=<名字> evidence=<文本>，证据本身含空格，
// 因此前三个字段按位置切分，余下整段作为证据。
func parseDemoFindings(t *testing.T, out string) map[string]demoFinding {
	t.Helper()
	findings := map[string]demoFinding{}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !strings.HasPrefix(line, "rule=") {
			continue
		}
		parts := strings.SplitN(line, " ", 4)
		if len(parts) != 4 ||
			!strings.HasPrefix(parts[1], "severity=") ||
			!strings.HasPrefix(parts[2], "invariant=") ||
			!strings.HasPrefix(parts[3], "evidence=") {
			t.Fatalf("malformed finding line %q", line)
		}
		f := demoFinding{
			rule:      strings.TrimPrefix(parts[0], "rule="),
			severity:  strings.TrimPrefix(parts[1], "severity="),
			invariant: strings.TrimPrefix(parts[2], "invariant="),
			evidence:  strings.TrimPrefix(parts[3], "evidence="),
		}
		if _, dup := findings[f.rule]; dup {
			t.Fatalf("rule %s listed twice in output:\n%s", f.rule, out)
		}
		findings[f.rule] = f
	}
	return findings
}

// 直接列表输出：false 不变式的规则各留一条缺陷，归属与证据完整；true 规则
// 不出现；没有版本字段；退出码为 0；汇总计数正确。
func TestCLIDemoListsDefectFindings(t *testing.T) {
	bin := auditBinary(t)
	cmd := exec.Command(bin, "demo")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("demo must succeed: %v\n%s", err, stderr.String())
	}
	out := stdout.String()

	findings := parseDemoFindings(t, out)
	if len(findings) != 2 {
		t.Fatalf("demo findings = %d, want 2 (two false invariants):\n%s", len(findings), out)
	}
	want := map[string]demoFinding{
		"reentrancy-guard": {"reentrancy-guard", "high", "no-reentrant-withdraw",
			"invariant no-reentrant-withdraw does not hold"},
		"invariant-preserved": {"invariant-preserved", "critical", "balance-monotonic",
			"invariant balance-monotonic does not hold"},
	}
	for rule, w := range want {
		got, ok := findings[rule]
		if !ok {
			t.Errorf("missing defect line for rule %s:\n%s", rule, out)
			continue
		}
		if got != w {
			t.Errorf("rule %s line = %+v, want %+v", rule, got, w)
		}
	}
	// owner-only-withdraw 为 true：是“通过”，直接列表不产生任何缺陷行。
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "access-control") || strings.Contains(line, "owner-only-withdraw") {
			t.Errorf("a passing rule must not appear as a finding:\n%s", out)
		}
	}
	// 直接列表格式不得混入报告产物。
	if strings.Contains(out, "reportId") || strings.Contains(out, "发现缺陷") {
		t.Errorf("demo emits the direct finding list, not a report:\n%s", out)
	}
	// 汇总行反映真实规则数与缺陷数。
	if !strings.Contains(out, "artifact=Vault rules=3 findings=2") {
		t.Errorf("missing/incorrect summary line:\n%s", out)
	}
}
