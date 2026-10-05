package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件回归保护 README「导入外部检查器的逐规则结论」一节公开的完整 Vault 示例。
// 该示例对外公开了固定的绑定值：产物哈希
// 0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7、
// 三条规则的版本（1.4.2 / 2.1.0 / 0.9.3）以及成功报告标识
// a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34。
// 外部检查器依靠这些已公开的值提交结论，因此这里的测试把示例原文与公开值
// 钉死：任何“程序仍接受按新计算结果填写的输入，却拒绝原来合法的外部结论，
// 或悄悄改变示例对应的报告标识”的回归都必须在这里失败。若产品行为确实需要
// 演进，应同步更新 README 的公开值，而不是在本测试里松动断言去迁就新结果。

// README 公开的成功报告标识与产物哈希（文档中的承诺值，不得在本测试中改写）。
const (
	readmeVaultReportID     = "a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34"
	readmeVaultArtifactHash = "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7"
)

// README 示例中两条说明的原文（含中文、标点与空格），证据必须逐字保留。
const (
	readmeVaultDefectNote = "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
	readmeVaultToolNote   = "符号执行引擎未安装：PATH 中未找到 mythril，无法求解 balances-cover-withdrawals。"
)

// readmeVaultInputJSON 是 README「完整示例输入」一节的 JSON 原文（audit-input.json）。
// 其中的 \n 与 \" 是 JSON 字符串转义，不是 Go 转义。
const readmeVaultInputJSON = `{
  "artifact": {
    "name": "Vault",
    "abi": "[{\"name\":\"withdraw\",\"type\":\"function\",\"stateMutability\":\"payable\"}]",
    "bytecode": "0x6080604052",
    "source": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract Vault {\n    mapping(address => uint256) private balances;\n\n    function withdraw(uint256 amount) public {\n        (bool sent, ) = msg.sender.call{value: amount}(\"\");\n        require(sent, \"transfer failed\");\n        balances[msg.sender] -= amount;\n    }\n}\n"
  },
  "rules": [
    {
      "id": "reentrancy-guard",
      "kind": "static",
      "severity": "high",
      "invariant": "no-reentrant-withdraw",
      "requiresABI": false,
      "version": "1.4.2"
    },
    {
      "id": "owner-only-withdraw",
      "kind": "static",
      "severity": "medium",
      "invariant": "withdraw-owner-only",
      "requiresABI": true,
      "version": "2.1.0"
    },
    {
      "id": "solvency-symbolic",
      "kind": "symbolic",
      "severity": "critical",
      "invariant": "balances-cover-withdrawals",
      "requiresABI": false,
      "version": "0.9.3"
    }
  ],
  "invariants": {},
  "checks": [
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "reentrancy-guard",
      "version": "1.4.2",
      "status": "发现缺陷",
      "note": "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
    },
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "owner-only-withdraw",
      "version": "2.1.0",
      "status": "通过"
    },
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "solvency-symbolic",
      "version": "0.9.3",
      "status": "工具缺失",
      "note": "符号执行引擎未安装：PATH 中未找到 mythril，无法求解 balances-cover-withdrawals。"
    }
  ]
}
`

// readmeVaultReport 是 README 示例提交成功后期望的完整报告内容，
// 以 JSON 文本给出（与 README 公开的成功输出一致），各测试统一解码后比较。
const readmeVaultReportJSON = `{
  "reportId": "a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34",
  "artifact": {
    "name": "Vault",
    "hash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7"
  },
  "rules": [
    {
      "id": "reentrancy-guard",
      "kind": "static",
      "severity": "high",
      "invariant": "no-reentrant-withdraw",
      "requiresABI": false,
      "version": "1.4.2",
      "status": "发现缺陷",
      "note": "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
    },
    {
      "id": "owner-only-withdraw",
      "kind": "static",
      "severity": "medium",
      "invariant": "withdraw-owner-only",
      "requiresABI": true,
      "version": "2.1.0",
      "status": "通过"
    },
    {
      "id": "solvency-symbolic",
      "kind": "symbolic",
      "severity": "critical",
      "invariant": "balances-cover-withdrawals",
      "requiresABI": false,
      "version": "0.9.3",
      "status": "工具缺失",
      "note": "符号执行引擎未安装：PATH 中未找到 mythril，无法求解 balances-cover-withdrawals。"
    }
  ],
  "findings": [
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "reentrancy-guard",
      "version": "1.4.2",
      "severity": "high",
      "invariant": "no-reentrant-withdraw",
      "evidence": "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
    }
  ]
}
`

// wantREADMEVaultReport 解码 README 公开的成功输出，作为各断言的基准。
func wantREADMEVaultReport(t *testing.T) contractsentinel.Report {
	t.Helper()
	return decodeReport(t, readmeVaultReportJSON)
}

// runCLIAuditWithEnv 与 runCLIAudit 相同，但允许替换进程环境。
func runCLIAuditWithEnv(t *testing.T, bin, input, store string, env []string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, "audit", "--input", input, "--store", store)
	cmd.Env = env
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

// --- 原样提交示例：公开的报告标识、产物哈希、逐规则状态与证据全部吻合 ---

func TestREADMEVaultExampleSubmitAsIs(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "audit-input.json", readmeVaultInputJSON)
	store := filepath.Join(work, "reports")

	// 导入只落盘检查器已有的结论，不启动符号执行或模糊测试：
	// 把 PATH 清空（mythril 等工具必然“找不到”）后提交仍必须成功，
	// 且 solvency-symbolic 的“工具缺失”只是被如实记录，而非现场探测的结果。
	stdout, stderr, code := runCLIAuditWithEnv(t, bin, input, store, []string{"PATH="})
	if code != 0 {
		t.Fatalf("README example submission must succeed, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)

	// 公开的两个标识必须逐字吻合。
	if report.ReportID != readmeVaultReportID {
		t.Fatalf("reportId = %q, want the published %q", report.ReportID, readmeVaultReportID)
	}
	if report.Artifact.Name != "Vault" || report.Artifact.Hash != readmeVaultArtifactHash {
		t.Fatalf("artifact header = %+v, want name Vault hash %s", report.Artifact, readmeVaultArtifactHash)
	}

	// 三条规则分别保留示例中的状态与版本。
	if len(report.Rules) != 3 {
		t.Fatalf("rules = %+v, want exactly the three README rules", report.Rules)
	}
	type wantRule struct{ status, version, note string }
	wantRules := map[string]wantRule{
		"reentrancy-guard":    {"发现缺陷", "1.4.2", readmeVaultDefectNote},
		"owner-only-withdraw": {"通过", "2.1.0", ""},
		"solvency-symbolic":   {"工具缺失", "0.9.3", readmeVaultToolNote},
	}
	for _, r := range report.Rules {
		want, ok := wantRules[r.ID]
		if !ok {
			t.Fatalf("unexpected rule in report: %+v", r)
		}
		if r.Status != want.status || r.Version != want.version {
			t.Errorf("rule %s = status %q version %q, want %q / %q", r.ID, r.Status, r.Version, want.status, want.version)
		}
		if r.Note != want.note {
			t.Errorf("rule %s note = %q, want %q", r.ID, r.Note, want.note)
		}
	}

	// findings 只有重入规则那一条缺陷，绑定同一产物哈希与规则版本，证据逐字等于原始 note。
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the reentrancy defect", report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "reentrancy-guard" || f.Version != "1.4.2" || f.Severity != "high" || f.Invariant != "no-reentrant-withdraw" {
		t.Fatalf("defect attribution = %+v", f)
	}
	if f.ArtifactHash != readmeVaultArtifactHash {
		t.Fatalf("defect artifact hash = %q, want %q", f.ArtifactHash, readmeVaultArtifactHash)
	}
	if f.Evidence != readmeVaultDefectNote {
		t.Fatalf("evidence = %q, must equal the original note verbatim %q", f.Evidence, readmeVaultDefectNote)
	}
	// 工具缺失说明只留在规则结果里，不能被当成缺陷证据。
	for _, finding := range report.Findings {
		if finding.RuleID == "solvency-symbolic" || finding.Evidence == readmeVaultToolNote {
			t.Fatalf("tool-missing note must never become defect evidence: %+v", finding)
		}
	}

	// 完整报告与 README 公开的成功输出逐字段一致。
	if want := wantREADMEVaultReport(t); !reflect.DeepEqual(report, want) {
		t.Fatalf("report differs from the README published output:\ngot  %+v\nwant %+v", report, want)
	}

	// 报告按公开标识落盘，落盘内容与 stdout 报告一致，原始字节保留中文原文。
	savedPath := filepath.Join(store, readmeVaultReportID+".json")
	savedBytes, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("report must be saved as <reportId>.json under the store: %v", err)
	}
	if saved := decodeReport(t, string(savedBytes)); !reflect.DeepEqual(saved, report) {
		t.Fatalf("saved report does not match stdout report:\nsaved=%+v\nstdout=%+v", saved, report)
	}
	if !bytes.Contains(savedBytes, []byte(readmeVaultDefectNote)) {
		t.Fatalf("saved archive must preserve the Chinese note verbatim: %s", savedBytes)
	}
}

// --- 按公开的报告标识读回：内容不被重新解释，中文、标点、空格逐字保留 ---

func TestREADMEVaultExampleReadbackByReportID(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "audit-input.json", readmeVaultInputJSON)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("README example submission must succeed, exit=%d stderr=%s", code, stderr)
	}
	submitted := decodeReport(t, stdout)

	readStdout, readStderr, readCode := runCLIReport(t, bin, store, readmeVaultReportID)
	if readCode != 0 {
		t.Fatalf("read-back by the published report id must succeed, exit=%d stderr=%s", readCode, readStderr)
	}
	loaded := decodeReport(t, readStdout)

	if !reflect.DeepEqual(loaded, submitted) {
		t.Fatalf("read-back re-interpreted the report:\nloaded=%+v\nsubmitted=%+v", loaded, submitted)
	}
	if want := wantREADMEVaultReport(t); !reflect.DeepEqual(loaded, want) {
		t.Fatalf("read-back differs from the README published output:\ngot  %+v\nwant %+v", loaded, want)
	}
	// 原始反例说明的中文、标点与空格在往返后逐字保留。
	if loaded.Findings[0].Evidence != readmeVaultDefectNote {
		t.Fatalf("evidence after read-back = %q, want %q", loaded.Findings[0].Evidence, readmeVaultDefectNote)
	}
	for _, r := range loaded.Rules {
		if r.ID == "reentrancy-guard" && r.Note != readmeVaultDefectNote {
			t.Fatalf("defect note after read-back = %q, want %q", r.Note, readmeVaultDefectNote)
		}
		if r.ID == "solvency-symbolic" && r.Note != readmeVaultToolNote {
			t.Fatalf("tool-missing note after read-back = %q, want %q", r.Note, readmeVaultToolNote)
		}
	}
}

// --- JSON 书写变化不是产物内容变化：缩进、成员顺序、等价转义都不影响绑定值 ---

// escapeNonASCIIForJSON 把字符串中的非 ASCII 字符改写为解码后内容相同的
// 合法 \uXXXX 转义（BMP 之外写成代理对）。
func escapeNonASCIIForJSON(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 128:
			b.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		}
	}
	return b.String()
}

// readmeVaultCosmeticVariants 生成与示例解码内容完全相同的 JSON 书写变体：
// 只改变缩进、对象成员顺序，或把字符串字符改写为等价转义。
func readmeVaultCosmeticVariants(t *testing.T) map[string]string {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(readmeVaultInputJSON), &decoded); err != nil {
		t.Fatalf("README example must be valid JSON: %v", err)
	}
	// map 重新编码后成员按字典序排列，与 README 原文的成员顺序不同。
	compact, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(decoded, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	// 等价转义：缺陷 note 的中文字符全部写成 Unicode 转义形式，source 中的 ASCII
	// 字母也改写一个（pragma 的第一个 a 用转义书写），解码后内容不变。
	// 反斜线由字节构造，避免测试源码本身依赖转义写法。
	backslash := string([]byte{0x5c})
	escaped := strings.Replace(string(compact), readmeVaultDefectNote, escapeNonASCIIForJSON(readmeVaultDefectNote), 1)
	escaped = strings.Replace(escaped, "pragma solidity", "pr"+backslash+"u0061gma solidity", 1)
	if strings.Contains(escaped, "反") {
		t.Fatalf("escaped variant must rewrite the Chinese note as \\u escapes: %s", escaped)
	}
	if !strings.Contains(escaped, backslash+"u0061") {
		t.Fatalf("escaped variant must rewrite one source letter as a \\u escape: %s", escaped)
	}
	return map[string]string{
		"compact reordered members": string(compact),
		"tab indented":              string(indented),
		"equivalent escapes":        escaped,
	}
}

func TestREADMEVaultExampleCosmeticJSONVariantsKeepBindings(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	for name, content := range readmeVaultCosmeticVariants(t) {
		t.Run(name, func(t *testing.T) {
			input := writeInput(t, work, "variant.json", content)
			store := filepath.Join(work, "reports-"+strings.ReplaceAll(name, " ", "-"))

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code != 0 {
				t.Fatalf("cosmetic variant must stay a legal submission, exit=%d stderr=%s", code, stderr)
			}
			report := decodeReport(t, stdout)

			// 书写变化不改变任何绑定值：报告标识、产物哈希、状态与证据全部保持公开值。
			if report.ReportID != readmeVaultReportID {
				t.Fatalf("reportId = %q, want the published %q", report.ReportID, readmeVaultReportID)
			}
			if report.Artifact.Hash != readmeVaultArtifactHash {
				t.Fatalf("artifact hash = %q, want %q", report.Artifact.Hash, readmeVaultArtifactHash)
			}
			if want := wantREADMEVaultReport(t); !reflect.DeepEqual(report, want) {
				t.Fatalf("cosmetic variant changed the report:\ngot  %+v\nwant %+v", report, want)
			}
			if report.Findings[0].Evidence != readmeVaultDefectNote {
				t.Fatalf("evidence = %q, want the decoded original note %q", report.Findings[0].Evidence, readmeVaultDefectNote)
			}
		})
	}
}

// --- source 永远是提交的字符串内容：写成文件名也不读本地文件 ---

func TestREADMEVaultExampleSourceStringIsNeverReadFromDisk(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	// 在磁盘上放一个内容完全不同的诱饵文件，并把 source 写成它的路径。
	// 参与哈希的必须是这个路径字符串本身，而不是文件内容。
	decoy := filepath.Join(work, "Vault.sol")
	if err := os.WriteFile(decoy, []byte("contract Decoy { function steal() public {} }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	input := strings.Replace(readmeVaultInputJSON,
		`"source": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract Vault {\n    mapping(address => uint256) private balances;\n\n    function withdraw(uint256 amount) public {\n        (bool sent, ) = msg.sender.call{value: amount}(\"\");\n        require(sent, \"transfer failed\");\n        balances[msg.sender] -= amount;\n    }\n}\n"`,
		`"source": `+strconv.Quote(decoy), 1)
	if !strings.Contains(input, strconv.Quote(decoy)) {
		t.Fatal("failed to rewrite the source member")
	}

	// 按“字符串内容”算出的哈希填写 checks：若程序按文件名读了诱饵文件，
	// 实际哈希会对不上，整份提交将被拒绝。
	stringHash := contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name:     "Vault",
		ABI:      `[{"name":"withdraw","type":"function","stateMutability":"payable"}]`,
		Bytecode: "0x6080604052",
		Source:   decoy,
	})
	input = strings.ReplaceAll(input, readmeVaultArtifactHash, stringHash)

	inputPath := writeInput(t, work, "filename-source.json", input)
	store := filepath.Join(work, "reports")
	stdout, stderr, code := runCLIAudit(t, bin, inputPath, store)
	if code != 0 {
		t.Fatalf("source string that looks like a filename must be hashed as content, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)
	if report.Artifact.Hash != stringHash {
		t.Fatalf("artifact hash = %q, want the hash of the source string %q", report.Artifact.Hash, stringHash)
	}
	if report.Artifact.Hash == readmeVaultArtifactHash {
		t.Fatal("artifact hash must change with the source string content")
	}
}

// --- 改了 source 却沿用原 checks 产物哈希：整份失败，不产生部分报告 ---

func TestREADMEVaultExampleChangedSourceWithStaleHashRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	// 实际改变示例的源码字符串（编译版本号 0.8.0 -> 0.8.1），
	// checks 记录仍携带 README 公开的原产物哈希。
	input := strings.Replace(readmeVaultInputJSON, `pragma solidity ^0.8.0;`, `pragma solidity ^0.8.1;`, 1)
	if !strings.Contains(input, `pragma solidity ^0.8.1;`) {
		t.Fatal("failed to rewrite the source member")
	}
	inputPath := writeInput(t, work, "stale-hash.json", input)
	store := filepath.Join(work, "nested", "reports")

	stdout, stderr, code := runCLIAudit(t, bin, inputPath, store)
	if code == 0 {
		t.Fatal("submission with a stale checks artifact hash must exit non-zero")
	}
	// 错误必须指出出错规则与原因。
	if !strings.Contains(stderr, "reentrancy-guard") {
		t.Fatalf("stderr must name the offending rule:\n%s", stderr)
	}
	if !strings.Contains(stderr, "artifact hash mismatch") {
		t.Fatalf("stderr must state the hash mismatch:\n%s", stderr)
	}
	// stdout 没有成功报告，其余合法记录也不会被保存成部分报告。
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}
