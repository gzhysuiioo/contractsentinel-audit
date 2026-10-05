package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件是 README“导入外部检查器的逐规则结论”一节中完整 Vault 示例的
// 兼容性回归保障。示例公开了外部检查器赖以提交结论的固定绑定值——产物哈希、
// 三条规则的版本、唯一缺陷的逐字证据以及成功报告的报告标识；这些值一旦发布
// 就必须持续可用。这里的用例在真实命令行进程边界上钉住它们：
//
//   - 原样提交示例：audit 成功、落盘完整报告，产物哈希与报告标识等于公开值，
//     三种结论（发现缺陷/通过/工具缺失）及其版本与证据逐字保留，并可用该
//     报告标识原样读回（中文、标点、空格不被改写）；
//   - 只是 JSON 书写方式不同（缩进、成员顺序、解码后等价的合法转义）时，
//     绑定值与报告标识保持不变；source 永远是提交的字符串内容，不会被
//     当成文件名去读盘；
//   - 真正改动源码字符串却仍携带旧 checks 产物哈希时，整份提交必须因哈希
//     不匹配失败并点名单条规则，stdout 没有成功报告，也不形成部分报告，
//     原本不存在的报告目录不会被创建。
//
// 冻结的提交字节位于 testdata/vault-audit-input.json，与 README 示例代码块
// 逐字节相同；测试不修改任何已公开的哈希或报告标识来迁就新结果。

const (
	// vaultPublishedArtifactHash 是 README 公开的产物哈希（由 abi、bytecode、
	// source 三个字符串内容算出，名称 Vault 不参与）。
	vaultPublishedArtifactHash = "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7"
	// vaultPublishedReportID 是原样提交示例时成功输出（并落盘）的报告标识。
	vaultPublishedReportID = "a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34"

	// vaultDefectNote 是重入规则缺陷记录的原始 note，必须逐字成为证据。
	vaultDefectNote = "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
	// vaultToolMissingNote 是符号执行规则的工具缺失说明：留在规则结果里，
	// 绝不能被当成缺陷证据。
	vaultToolMissingNote = "符号执行引擎未安装：PATH 中未找到 mythril，无法求解 balances-cover-withdrawals。"
)

// vaultExampleInput 读取与 README 示例逐字节相同的冻结提交。
func vaultExampleInput(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vault-audit-input.json"))
	if err != nil {
		t.Fatalf("frozen Vault example fixture is missing: %v", err)
	}
	return raw
}

// assertVaultPublishedReport 钉住成功报告与 README 公开值的全部绑定关系，
// 原样提交与各种“仅书写不同”的等价提交都必须通过它。
func assertVaultPublishedReport(t *testing.T, rawStdout string, savedArchive []byte) contractsentinel.Report {
	t.Helper()
	report := decodeReport(t, rawStdout)

	if report.Artifact.Hash != vaultPublishedArtifactHash {
		t.Fatalf("artifact hash = %q, want published %q", report.Artifact.Hash, vaultPublishedArtifactHash)
	}
	if report.ReportID != vaultPublishedReportID {
		t.Fatalf("reportId = %q, want published %q: published external conclusions must keep working",
			report.ReportID, vaultPublishedReportID)
	}
	if report.Artifact.Name != "Vault" {
		t.Fatalf("artifact name = %q, want Vault", report.Artifact.Name)
	}

	// 三条规则各自保留示例中的状态与版本。
	wantRules := map[string]struct {
		version string
		status  string
		note    string
	}{
		"reentrancy-guard":    {"1.4.2", contractsentinel.StatusDefect, vaultDefectNote},
		"owner-only-withdraw": {"2.1.0", contractsentinel.StatusPass, ""},
		"solvency-symbolic":   {"0.9.3", contractsentinel.StatusToolMissing, vaultToolMissingNote},
	}
	if len(report.Rules) != len(wantRules) {
		t.Fatalf("rules = %+v, want %d rules", report.Rules, len(wantRules))
	}
	for _, rule := range report.Rules {
		want, ok := wantRules[rule.ID]
		if !ok {
			t.Fatalf("unexpected rule %q in published report", rule.ID)
		}
		if rule.Version != want.version || rule.Status != want.status {
			t.Fatalf("rule %s = version %q status %q, want version %q status %q",
				rule.ID, rule.Version, rule.Status, want.version, want.status)
		}
		if rule.Note != want.note {
			t.Fatalf("rule %s note = %q, want %q", rule.ID, rule.Note, want.note)
		}
	}

	// findings 只包含重入规则那一条缺陷，绑定同一产物哈希与正确规则版本，
	// 证据逐字是原始 note；工具缺失说明不在 findings 里。
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the reentrancy defect", report.Findings)
	}
	finding := report.Findings[0]
	if finding.RuleID != "reentrancy-guard" || finding.Version != "1.4.2" {
		t.Fatalf("finding attribution = %+v, want reentrancy-guard 1.4.2", finding)
	}
	if finding.ArtifactHash != vaultPublishedArtifactHash {
		t.Fatalf("finding artifact hash = %q, want published hash", finding.ArtifactHash)
	}
	if finding.Severity != "high" || finding.Invariant != "no-reentrant-withdraw" {
		t.Fatalf("finding rule definition binding = %+v", finding)
	}
	if finding.Evidence != vaultDefectNote {
		t.Fatalf("finding evidence = %q, want the verbatim original note", finding.Evidence)
	}
	if strings.Contains(finding.Evidence, vaultToolMissingNote) || finding.Evidence == vaultToolMissingNote {
		t.Fatal("tool-missing note must never be used as defect evidence")
	}

	// 落盘归档与成功输出是同一份报告，且原始中文、全角标点和空格逐字节保留。
	saved := decodeReport(t, string(savedArchive))
	if !reflect.DeepEqual(saved, report) {
		t.Fatalf("saved report differs from stdout report:\nsaved=%+v\nstdout=%+v", saved, report)
	}
	for _, fragment := range []string{
		"反例：攻击者先存入 1 ether 后调用 withdraw；",
		"balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。",
		"符号执行引擎未安装：PATH 中未找到 mythril，无法求解 balances-cover-withdrawals。",
	} {
		if !bytes.Contains(savedArchive, []byte(fragment)) {
			t.Fatalf("saved archive rewrote Chinese/punctuation/spacing; missing %q in:\n%s", fragment, savedArchive)
		}
	}
	return report
}

// TestCLIVaultExamplePublishedBindings 原样提交 README 的 Vault 示例：
// audit 必须成功输出并保存完整报告，产物哈希、报告标识、三条规则的状态/版本、
// 唯一缺陷的归属与逐字证据全部与文档公开值一致；再按成功输出的报告标识
// 读回，内容与提交成功时逐字段、逐字节一致。这次提交只导入已有结论，
// 不实际启动任何检查器（命令行层面 audit 只做校验与落盘）。
func TestCLIVaultExamplePublishedBindings(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "audit-input.json", string(vaultExampleInput(t)))
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("the published Vault example must audit successfully, exit=%d stderr=%s", code, stderr)
	}

	savedArchive, err := os.ReadFile(filepath.Join(store, vaultPublishedReportID+".json"))
	if err != nil {
		t.Fatalf("report must be saved under the published report id filename: %v", err)
	}
	submitted := assertVaultPublishedReport(t, stdout, savedArchive)

	// 按成功输出的报告标识读回：同一份完整报告，stdout 逐字节相同。
	readStdout, readStderr, readCode := runCLIReport(t, bin, store, submitted.ReportID)
	if readCode != 0 {
		t.Fatalf("read-back by published report id must succeed, exit=%d stderr=%s", readCode, readStderr)
	}
	if readStdout != stdout {
		t.Fatalf("read-back re-interpreted the report:\nread: %s\nsent: %s", readStdout, stdout)
	}
	loaded := decodeReport(t, readStdout)
	if !reflect.DeepEqual(loaded, submitted) {
		t.Fatalf("read-back report differs from the successful submission:\n%+v\n%+v", loaded, submitted)
	}
}

// TestCLIVaultExampleFixtureCarriesPublishedChecks 冻结提交自身必须包含
// 三条引用公开产物哈希、版本与各自规则一一对应的 checks 记录；夹具与公开值
// 漂移时先在这里失败。
func TestCLIVaultExampleFixtureCarriesPublishedChecks(t *testing.T) {
	var in cliWireInput
	if err := json.Unmarshal(vaultExampleInput(t), &in); err != nil {
		t.Fatalf("frozen fixture must be valid JSON: %v", err)
	}
	if len(in.Checks) != 3 {
		t.Fatalf("checks = %d, want 3 published records", len(in.Checks))
	}
	want := map[string]struct {
		version string
		status  string
	}{
		"reentrancy-guard":    {"1.4.2", contractsentinel.StatusDefect},
		"owner-only-withdraw": {"2.1.0", contractsentinel.StatusPass},
		"solvency-symbolic":   {"0.9.3", contractsentinel.StatusToolMissing},
	}
	for _, check := range in.Checks {
		if check.ArtifactHash != vaultPublishedArtifactHash {
			t.Fatalf("check for %s carries hash %q, want published %q", check.RuleID, check.ArtifactHash, vaultPublishedArtifactHash)
		}
		w, ok := want[check.RuleID]
		if !ok {
			t.Fatalf("unexpected check record for %q", check.RuleID)
		}
		if check.Version != w.version || check.Status != w.status {
			t.Fatalf("check for %s = version %q status %q, want %q %q", check.RuleID, check.Version, check.Status, w.version, w.status)
		}
	}
	// 实际算一遍夹具产物：公开哈希必须确实由这三个字符串内容得出。
	if got := contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name: in.Artifact.Name, ABI: in.Artifact.ABI, Bytecode: in.Artifact.Bytecode, Source: in.Artifact.Source,
	}); got != vaultPublishedArtifactHash {
		t.Fatalf("fixture artifact recomputes to %q, published hash is %q", got, vaultPublishedArtifactHash)
	}
}

// TestCLIVaultExampleJSONWriteVariantsKeepBindings 区分 JSON 的书写变化与
// 产物内容变化：仅改变缩进、对象成员顺序，或把字符串字符改写成解码后内容
// 相同的合法 \uXXXX 转义，原有的产物哈希与成功报告标识必须仍然有效，
// 状态、归属与证据完全一致。
func TestCLIVaultExampleJSONWriteVariantsKeepBindings(t *testing.T) {
	original := vaultExampleInput(t)

	// 变体 1：压缩空白（缩进/换行变化），内容不变。
	var compact bytes.Buffer
	if err := json.Compact(&compact, original); err != nil {
		t.Fatalf("json.Compact failed: %v", err)
	}
	compactVariant := compact.Bytes()

	// 变体 2：经通用 map 往返后重编码——成员顺序按键排序，缩进消失。
	var generic any
	if err := json.Unmarshal(original, &generic); err != nil {
		t.Fatalf("unmarshal for reorder variant failed: %v", err)
	}
	reordered, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("marshal reorder variant failed: %v", err)
	}

	// 变体 3：在重排后的文本上，把三处字符改写成解码结果相同的合法 Unicode
	// 转义——字节码里的 '6'（U+0036）、缺陷 note 里的 '攻'（U+653B）以及
	// source 里的 'S'（U+0053，证明 source 转义也按解码后的内容参与哈希）。
	// 解码后内容完全不变，因此公开哈希与报告标识必须保持不变。
	escaped := bytes.Replace(reordered, []byte("0x6080604052"), []byte("0x\\u0036080604052"), 1)
	if bytes.Contains(escaped, []byte("0x6080604052")) {
		t.Fatal("test setup failed to rewrite the bytecode value")
	}
	escaped = bytes.Replace(escaped, []byte("SPDX-License-Identifier"), []byte("\\u0053PDX-License-Identifier"), 1)
	if bytes.Contains(escaped, []byte("SPDX-License-Identifier")) {
		t.Fatal("test setup failed to rewrite the source value")
	}
	escaped = bytes.ReplaceAll(escaped, []byte("攻"), []byte("\\u653b"))
	if bytes.Contains(escaped, []byte("攻")) {
		t.Fatal("test setup failed to rewrite the note character")
	}
	var originalDecoded, escapedDecoded any
	if err := json.Unmarshal(original, &originalDecoded); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(escaped, &escapedDecoded); err != nil {
		t.Fatalf("escape variant must be valid JSON: %v", err)
	}
	if !reflect.DeepEqual(escapedDecoded, originalDecoded) {
		t.Fatal("escape variant must decode to the exact same submission content")
	}

	variants := map[string][]byte{
		"compact-whitespace": compactVariant,
		"sorted-key-order":   reordered,
		"equivalent-escapes": escaped,
	}
	if bytes.Equal(compactVariant, original) || bytes.Equal(reordered, original) {
		t.Fatal("variants must actually differ in writing from the frozen fixture")
	}

	bin := auditBinary(t)
	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			work := t.TempDir()
			input := writeInput(t, work, "variant.json", string(variant))
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code != 0 {
				t.Fatalf("write-only JSON variant must stay accepted, exit=%d stderr=%s", code, stderr)
			}
			savedArchive, err := os.ReadFile(filepath.Join(store, vaultPublishedReportID+".json"))
			if err != nil {
				t.Fatalf("variant must save under the same published report id: %v", err)
			}
			assertVaultPublishedReport(t, stdout, savedArchive)
		})
	}
}

// TestCLIVaultExampleSourceIsNeverReadFromDisk source 始终是提交中的字符串
// 内容，即使写成文件名也不会去磁盘读取本地源码：参与哈希的是字符串本身。
// 这里在工作目录放一个同名但内容不同的诱饵文件，结论必须按字符串内容算哈希。
func TestCLIVaultExampleSourceIsNeverReadFromDisk(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	var generic map[string]any
	if err := json.Unmarshal(vaultExampleInput(t), &generic); err != nil {
		t.Fatal(err)
	}
	artifactMap := generic["artifact"].(map[string]any)
	artifactMap["source"] = "Vault.sol"

	// 与 source 同路径、内容完全不同的诱饵文件：若程序错误地按文件名读盘，
	// 算出的哈希就会偏离字符串 "Vault.sol" 的哈希。
	decoy := filepath.Join(work, "Vault.sol")
	if err := os.WriteFile(decoy, []byte("// decoy bytes that are not the literal Vault.sol\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	wantHash := contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name:     artifactMap["name"].(string),
		ABI:      artifactMap["abi"].(string),
		Bytecode: artifactMap["bytecode"].(string),
		Source:   "Vault.sol",
	})
	if wantHash == vaultPublishedArtifactHash {
		t.Fatal("test setup: changing source content must change the artifact hash")
	}
	for _, rec := range generic["checks"].([]any) {
		rec.(map[string]any)["artifactHash"] = wantHash
	}
	rewritten, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}

	input := writeInput(t, work, "filename-source.json", string(rewritten))
	store := filepath.Join(work, "reports")
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("literal-string source must be hashed as submitted, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)
	if report.Artifact.Hash != wantHash {
		t.Fatalf("artifact hash = %q, want hash of the literal string, not any file on disk (%q)", report.Artifact.Hash, wantHash)
	}
}

// TestCLIVaultExampleSourceChangeWithStaleHashesRejected 真正改动示例的源码
// 字符串，却继续携带原来的 checks 产物哈希时，整份提交必须因哈希不匹配失败：
// 命令非零退出、原因写入 stderr 并点名单条规则，stdout 没有成功报告，
// 其余两条合法记录不能被保存成部分报告，原本不存在的报告目录也不会被创建。
func TestCLIVaultExampleSourceChangeWithStaleHashesRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	var generic map[string]any
	if err := json.Unmarshal(vaultExampleInput(t), &generic); err != nil {
		t.Fatal(err)
	}
	// 实际改变源码字符串内容（在末尾再加一个换行），但 checks 的产物哈希
	// 原样保留为公开值。
	artifactMap := generic["artifact"].(map[string]any)
	artifactMap["source"] = artifactMap["source"].(string) + "\n"
	rewritten, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}

	input := writeInput(t, work, "tampered.json", string(rewritten))
	store := filepath.Join(work, "nested", "never-created-reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("tampered source with stale checks hashes must exit non-zero")
	}
	// checks 数组中第一条就是 reentrancy-guard：不匹配必须能指出出错规则。
	if !strings.Contains(stderr, "check for rule reentrancy-guard") {
		t.Fatalf("stderr must name the offending rule:\n%s", stderr)
	}
	if !strings.Contains(stderr, "artifact hash mismatch") {
		t.Fatalf("stderr must state the hash mismatch:\n%s", stderr)
	}
	// stdout 绝不出现成功报告片段。
	assertNoPartialReport(t, stdout)
	// 不保存其余合法记录形成部分报告；目录原本不存在时也不应被创建。
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the report directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(work, "nested")); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create any parent store directory: %v", err)
	}
}
