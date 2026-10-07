package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 audit 的产物哈希绑定：产物哈希绑定的
// 是 abi、bytecode、source 三个字符串解码后的实际文本（带长度前缀分隔字段，
// 合约名称不参与）。用户先取得一份合法产物的检查记录后，只改动提交里的 ABI
// 或字节码——哪怕只是在 ABI 字符串内部加一个空格、或把字节码改一个字符——
// 却仍带着原 artifactHash 时，整份提交必须因产物哈希不匹配而失败：非零退出、
// stderr 点名发生不匹配的规则、stdout 没有报告或成功标识、尚不存在的报告目录
// 不被创建、已有归档保持原样；这属于提交绑定错误，不会被记成缺陷、工具缺失
// 或超时。把一段字符从 ABI 挪到字节码（三字段拼接不变）仍是不同产物。合法
// 边界同样锁定：只改名称时旧记录仍可导入且产物哈希不变、报告标识不同；只改
// JSON 排版或用合法转义写同一字符串不算产物变化；真正修改内容后改用新内容
// 的正确哈希则正常出报告，结论与说明保留，缺陷绑定新哈希与原规则版本。

// hashOf 计算一个提交侧镜像产物的实际内容哈希。
func hashOf(t *testing.T, a cliWireArtifact) string {
	t.Helper()
	return contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name: a.Name, ABI: a.ABI, Bytecode: a.Bytecode, Source: a.Source,
	})
}

// tamperedArtifactInput 以 mixedCheckInput 为底，把产物换成 tampered，但 checks
// 记录保持原样（仍携带针对原产物的 hash）：规则标识、版本、状态、说明都不变。
func tamperedArtifactInput(tampered cliWireArtifact, hash string) cliWireInput {
	in := mixedCheckInput(hash)
	in.Artifact = tampered
	return in
}

// --- 只改 ABI 内部空格或字节码一个字符，旧 artifactHash 必须整份拒绝 ---

func TestCLIAuditTamperedArtifactWithStaleHashRejected(t *testing.T) {
	bin := auditBinary(t)
	orig := mixedCheckArtifact()
	oldHash := hashOf(t, orig)

	cases := []struct {
		name     string
		tampered cliWireArtifact
	}{
		// ABI 字符串内部只增加一个空格：解码后的文本不同，哈希必须不同。
		{"abi inner space", cliWireArtifact{
			Name:     orig.Name,
			ABI:      `[{"name":"withdraw", "type":"function"}]`,
			Bytecode: orig.Bytecode,
			Source:   orig.Source,
		}},
		// 字节码只改一个字符。
		{"bytecode one char", cliWireArtifact{
			Name:     orig.Name,
			ABI:      orig.ABI,
			Bytecode: "0x60806041",
			Source:   orig.Source,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			if hashOf(t, tc.tampered) == oldHash {
				t.Fatal("test setup: the tampered artifact must hash differently")
			}
			// 规则标识、版本、状态、说明全部不变，只有产物内容变了。
			input := writeStructInput(t, work, "in.json", tamperedArtifactInput(tc.tampered, oldHash))
			store := filepath.Join(work, "nested", "missing-store")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code == 0 {
				t.Fatal("a stale artifactHash with modified content must exit non-zero")
			}
			if !strings.Contains(stderr, "artifact hash mismatch") {
				t.Fatalf("stderr must state the hash mismatch:\n%s", stderr)
			}
			// 第一条记录（rule-pass）首先被校验，错误必须点名它。
			if !strings.Contains(stderr, "rule-pass") {
				t.Fatalf("stderr must name the rule whose record mismatched:\n%s", stderr)
			}
			assertNoPartialReport(t, stdout)
			// 这是提交绑定错误：不能被描述成缺陷、工具缺失、超时或未检查。
			for _, marker := range []string{contractsentinel.StatusDefect, contractsentinel.StatusToolMissing,
				contractsentinel.StatusTimeout, contractsentinel.StatusUnchecked} {
				if strings.Contains(stderr, marker) {
					t.Fatalf("a binding error must not be classified as %q:\n%s", marker, stderr)
				}
			}
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("rejected submission must not create the store directory: %v", err)
			}
		})
	}
}

// --- 把字符从 ABI 挪到字节码：三字段拼接不变，仍是不同产物，旧记录必须拒绝 ---

func TestCLIAuditMovedCharacterBetweenABIAndBytecodeRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	orig := mixedCheckArtifact()
	oldHash := hashOf(t, orig)

	// ABI 的最后一个字符挪到字节码最前：abi+bytecode+source 逐字相同。
	moved := orig
	moved.ABI = orig.ABI[:len(orig.ABI)-1]
	moved.Bytecode = orig.ABI[len(orig.ABI)-1:] + orig.Bytecode
	if orig.ABI+orig.Bytecode+orig.Source != moved.ABI+moved.Bytecode+moved.Source {
		t.Fatal("test setup: the concatenated content must be unchanged by the move")
	}
	if hashOf(t, moved) == oldHash {
		t.Fatal("test setup: field boundaries are length-prefixed, the move must change the hash")
	}

	input := writeStructInput(t, work, "in.json", tamperedArtifactInput(moved, oldHash))
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("moving a character between abi and bytecode must not keep the old hash valid")
	}
	if !strings.Contains(stderr, "artifact hash mismatch") {
		t.Fatalf("stderr must state the hash mismatch:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 其余记录绑定正确也不能让夹带的旧哈希记录被跳过或让提交部分成功 ---

func TestCLIAuditSingleStaleRecordFailsWholeSubmission(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	orig := mixedCheckArtifact()
	oldHash := hashOf(t, orig)

	// 修改 ABI，其余记录都改用新内容的正确哈希，只有 rule-defect 仍带旧哈希；
	// 且 rule-defect 不是第一条记录，它前面的记录全部绑定正确。
	tampered := orig
	tampered.ABI = `[{"name":"withdraw", "type":"function"}]`
	newHash := hashOf(t, tampered)
	in := tamperedArtifactInput(tampered, newHash)
	for i := range in.Checks {
		if in.Checks[i].RuleID == "rule-defect" {
			in.Checks[i].ArtifactHash = oldHash
		}
	}
	input := writeStructInput(t, work, "in.json", in)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("one stale record among correctly bound ones must still fail the whole submission")
	}
	if !strings.Contains(stderr, "rule-defect") {
		t.Fatalf("stderr must name the rule whose record kept the old hash:\n%s", stderr)
	}
	if !strings.Contains(stderr, "artifact hash mismatch") {
		t.Fatalf("stderr must state the hash mismatch:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 目录已有归档时，带旧哈希的篡改提交必须保持原有内容原样 ---

func TestCLIAuditStaleHashKeepsExistingArchive(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	orig := mixedCheckArtifact()
	oldHash := hashOf(t, orig)

	// 先落一份合法报告。
	good := writeStructInput(t, work, "good.json", mixedCheckInput(oldHash))
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

	// 字节码改一个字符、仍带旧哈希：整份拒绝，归档原样。
	tampered := orig
	tampered.Bytecode = "0x60806041"
	bad := writeStructInput(t, work, "bad.json", tamperedArtifactInput(tampered, oldHash))
	stdout, _, code := runCLIAudit(t, bin, bad, store)
	if code == 0 {
		t.Fatal("a tampered artifact with a stale hash must exit non-zero")
	}
	assertNoPartialReport(t, stdout)

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

// --- 只改合约名称：产物哈希不变，旧检查记录仍可导入，报告标识不同 ---

func TestCLIAuditNameOnlyChangeKeepsHashAndImports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	orig := mixedCheckArtifact()
	oldHash := hashOf(t, orig)

	// 原始提交。
	stdout, stderr, code := runCLIAudit(t, bin,
		writeStructInput(t, work, "orig.json", mixedCheckInput(oldHash)), store)
	if code != 0 {
		t.Fatalf("legal import must succeed, exit=%d stderr=%s", code, stderr)
	}
	origReport := decodeReport(t, stdout)

	// 只改名称，checks 记录逐字不变（仍携带原 artifactHash）。
	renamed := orig
	renamed.Name = "Vault-重命名"
	stdout, stderr, code = runCLIAudit(t, bin,
		writeStructInput(t, work, "renamed.json", tamperedArtifactInput(renamed, oldHash)), store)
	if code != 0 {
		t.Fatalf("a name-only change must still import the original checks, exit=%d stderr=%s", code, stderr)
	}
	renamedReport := decodeReport(t, stdout)

	// 名称不参与产物哈希：新报告绑定同一产物哈希，但显示新名称。
	if renamedReport.Artifact.Hash != oldHash || renamedReport.Artifact.Hash != origReport.Artifact.Hash {
		t.Fatalf("a name-only change must keep the artifact hash %q, got %q",
			oldHash, renamedReport.Artifact.Hash)
	}
	if renamedReport.Artifact.Name != "Vault-重命名" {
		t.Fatalf("the new report must show the new name, got %+v", renamedReport.Artifact)
	}
	// 名称参与报告标识：两份报告标识必须不同，且各自落盘。
	if renamedReport.ReportID == origReport.ReportID {
		t.Fatal("a name-only change must produce a different report id")
	}
	for _, id := range []string{origReport.ReportID, renamedReport.ReportID} {
		if _, err := os.Stat(filepath.Join(store, id+".json")); err != nil {
			t.Fatalf("report %s must be archived: %v", id, err)
		}
	}
	// 逐规则结论与说明不受改名影响。
	statusNote := func(r contractsentinel.Report) map[string][2]string {
		m := map[string][2]string{}
		for _, rule := range r.Rules {
			m[rule.ID] = [2]string{rule.Status, rule.Note}
		}
		return m
	}
	if got, want := statusNote(renamedReport), statusNote(origReport); !mapsEqual(got, want) {
		t.Fatalf("a name-only change must not alter conclusions:\ngot  %+v\nwant %+v", got, want)
	}
}

// mapsEqual 比较两个规则 id 到（状态，说明）的映射。
func mapsEqual(a, b map[string][2]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// --- 只改 JSON 排版或用合法转义写同一字符串：不算产物变化 ---

func TestCLIAuditFormattingAndEscapesNotArtifactChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	oldHash := mixedArtifactHash(t)

	// 基准提交：结构体编码的常规排版。
	stdout, stderr, code := runCLIAudit(t, bin,
		writeStructInput(t, work, "plain.json", mixedCheckInput(oldHash)), store)
	if code != 0 {
		t.Fatalf("legal import must succeed, exit=%d stderr=%s", code, stderr)
	}
	plainReport := decodeReport(t, stdout)

	// 同一份内容换种写法：成员间任意空白与换行；ABI 里 withdraw 的 w 用
	// \u0077 转义、source 里 Vault 的 V 用 \u0056 转义，解码后是同一字符串。
	raw := `{
		"artifact" : {
			"name" : "Vault",
			"abi" : "[{\"name\":\"withdraw\",\"type\":\"function\"}]",
			"bytecode" : "0x60806040",
			"source" : "contract Vault {\n}\n"
		},
		"rules" : [
			{"id":"rule-pass","kind":"static","severity":"low","invariant":"inv-pass","requiresABI":false,"version":"1.4.0"},
			{"id":"rule-defect","kind":"static","severity":"high","invariant":"inv-defect","requiresABI":false,"version":"2.0.1"},
			{"id":"rule-tool","kind":"static","severity":"medium","invariant":"inv-tool","requiresABI":true,"version":"3.0.0"},
			{"id":"rule-timeout","kind":"symbolic","severity":"critical","invariant":"inv-timeout","requiresABI":false,"version":"0.9.2"},
			{"id":"rule-unchecked","kind":"static","severity":"info","invariant":"inv-unchecked","requiresABI":false,"version":"5.0.0"}
		],
		"checks" : [
			{"artifactHash":"` + oldHash + `","ruleId":"rule-pass","version":"1.4.0","status":"通过"},
			{"artifactHash":"` + oldHash + `","ruleId":"rule-defect","version":"2.0.1","status":"发现缺陷","note":"  反例：攻击者可在 withdraw 中重入\n  第二行证据  "},
			{"artifactHash":"` + oldHash + `","ruleId":"rule-tool","version":"3.0.0","status":"工具缺失","note":"符号执行引擎未安装"},
			{"artifactHash":"` + oldHash + `","ruleId":"rule-timeout","version":"0.9.2","status":"超时","note":"超过 60s 截止时间"}
		]
	}`
	// 把 ABI 中的 w 与 source 中的 V 换成合法 Unicode 转义（运行期替换，保证
	// 提交给命令的字节确实携带转义写法）。ABI 出现在 checks 的反例说明之前，
	// 第一次替换命中的就是 ABI 里的 withdraw。
	raw = strings.Replace(raw, "withdraw", "\\"+"u0077ithdraw", 1)
	raw = strings.Replace(raw, "contract Vault", "contract "+"\\"+"u0056ault", 1)
	if !strings.Contains(raw, `\`+"u0077") || !strings.Contains(raw, `\`+"u0056") {
		t.Fatalf("test setup must carry the JSON escapes, got:\n%s", raw)
	}
	input := writeInput(t, work, "escaped.json", raw)

	stdout, stderr, code = runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("reformatted/escaped spellings of the same content must import, exit=%d stderr=%s", code, stderr)
	}
	escapedReport := decodeReport(t, stdout)
	// 同一批解码后的内容：产物哈希与报告标识都必须与基准一致。
	if escapedReport.Artifact.Hash != plainReport.Artifact.Hash {
		t.Fatalf("escapes/formatting must not change the artifact hash:\n%s\n%s",
			escapedReport.Artifact.Hash, plainReport.Artifact.Hash)
	}
	if escapedReport.ReportID != plainReport.ReportID {
		t.Fatalf("escapes/formatting must not change the report id:\n%s\n%s",
			escapedReport.ReportID, plainReport.ReportID)
	}
}

// --- 真正修改 ABI/字节码后改用新内容的正确哈希：正常出报告，绑定新哈希 ---

func TestCLIAuditModifiedArtifactWithRecomputedHashSucceeds(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	orig := mixedCheckArtifact()
	oldHash := hashOf(t, orig)

	// 先落原产物的报告作为对照。
	stdout, stderr, code := runCLIAudit(t, bin,
		writeStructInput(t, work, "orig.json", mixedCheckInput(oldHash)), store)
	if code != 0 {
		t.Fatalf("legal import must succeed, exit=%d stderr=%s", code, stderr)
	}
	origReport := decodeReport(t, stdout)

	// 真正修改产物：ABI 内部加空格、字节码改一个字符；检查记录改用新内容
	// 算出的正确哈希，规则结论与原始说明逐字保留。
	modified := orig
	modified.ABI = `[{"name":"withdraw", "type":"function"}]`
	modified.Bytecode = "0x60806041"
	newHash := hashOf(t, modified)
	if newHash == oldHash {
		t.Fatal("test setup: the modified artifact must hash differently")
	}
	in := tamperedArtifactInput(modified, newHash)
	stdout, stderr, code = runCLIAudit(t, bin, writeStructInput(t, work, "modified.json", in), store)
	if code != 0 {
		t.Fatalf("checks recomputed against the new content must import, exit=%d stderr=%s", code, stderr)
	}
	modifiedReport := decodeReport(t, stdout)

	// 报告绑定新产物哈希，且与原报告不是同一份。
	if modifiedReport.Artifact.Hash != newHash {
		t.Fatalf("report must bind the new artifact hash %q, got %q", newHash, modifiedReport.Artifact.Hash)
	}
	if modifiedReport.ReportID == origReport.ReportID {
		t.Fatal("a modified artifact must produce a different report id")
	}

	// 规则结论与原始说明逐字保留（含中文、换行、前后空格）。
	statusNote := map[string][2]string{}
	for _, r := range modifiedReport.Rules {
		statusNote[r.ID] = [2]string{r.Status, r.Note}
	}
	want := map[string][2]string{
		"rule-pass":      {contractsentinel.StatusPass, ""},
		"rule-defect":    {contractsentinel.StatusDefect, defectNote},
		"rule-tool":      {contractsentinel.StatusToolMissing, "符号执行引擎未安装"},
		"rule-timeout":   {contractsentinel.StatusTimeout, "超过 60s 截止时间"},
		"rule-unchecked": {contractsentinel.StatusUnchecked, ""},
	}
	if !mapsEqual(statusNote, want) {
		t.Fatalf("conclusions and notes must be preserved:\ngot  %+v\nwant %+v", statusNote, want)
	}

	// 缺陷记录绑定新产物哈希与原规则版本；工具缺失与超时不进 findings。
	if len(modifiedReport.Findings) != 1 {
		t.Fatalf("tool-missing and timeout must stay out of findings, got %+v", modifiedReport.Findings)
	}
	f := modifiedReport.Findings[0]
	if f.ArtifactHash != newHash {
		t.Fatalf("finding must bind the new artifact hash %q, got %q", newHash, f.ArtifactHash)
	}
	if f.RuleID != "rule-defect" || f.Version != "2.0.1" {
		t.Fatalf("finding must keep the original rule id and version, got %+v", f)
	}
	if f.Evidence != defectNote {
		t.Fatalf("evidence must stay the original note %q, got %q", defectNote, f.Evidence)
	}

	// 新报告可按标识原样读回。
	readStdout, readStderr, readCode := runCLIReport(t, bin, store, modifiedReport.ReportID)
	if readCode != 0 {
		t.Fatalf("the new report must read back by id, exit=%d stderr=%s", readCode, readStderr)
	}
	loaded := decodeReport(t, readStdout)
	if loaded.ReportID != modifiedReport.ReportID || loaded.Artifact != modifiedReport.Artifact ||
		len(loaded.Findings) != 1 || loaded.Findings[0] != f {
		t.Fatalf("read-back changed the report:\n%+v\n%+v", loaded, modifiedReport)
	}
}
