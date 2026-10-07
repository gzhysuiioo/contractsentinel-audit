package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护 audit 的产物哈希绑定：产物哈希绑定的
// 是 abi、bytecode、source 三个字符串解码后的实际文本（带长度前缀分隔字段），
// 合约名称不参与，也不按 ABI 含义或字节码执行含义合并内容。
//
// 拒绝侧：用户拿到合法产物的检查记录后，保持规则标识、版本、状态与说明不变，
// 只改动提交里的 ABI 或字节码（哪怕只是在字符串内部加一个空格、只改一处文本，
// 或把一段字符从 ABI 挪到字节码使三字段拼接不变），却仍带着原来的
// artifactHash，整份提交必须因产物哈希不匹配而失败——非零退出、stderr 点名
// 发生不匹配的规则、stdout 没有报告或成功标识、尚不存在的报告目录不被创建、
// 已有归档保持原样；这属于提交绑定错误，不能被记成缺陷、工具缺失或超时。
// 其余规则的记录即使绑定正确，也不能让这一条被跳过或让提交部分成功。
//
// 合法侧：仅改合约名称时原检查记录仍可导入（哈希不变、新报告显示新名称并取得
// 不同的报告标识）；只调整提交 JSON 排版或用合法转义表达同一字符串不算产物
// 变化；确实修改了 ABI/字节码的产物改用新内容的正确哈希后正常出报告，规则
// 结论与原始说明保留，缺陷绑定新哈希及原规则版本，工具缺失与超时仍不进
// findings。

// cliArtifactHash 用库函数算出提交侧镜像产物的内容哈希。
func cliArtifactHash(a cliWireArtifact) string {
	return contractsentinel.ArtifactHash(contractsentinel.Artifact{
		Name: a.Name, ABI: a.ABI, Bytecode: a.Bytecode, Source: a.Source,
	})
}

// assertHashBindingFailure 核对一次产物哈希不匹配拒绝的完整外部表现：
// 非零退出、stderr 点名规则与原因、stdout 无任何报告片段，且错误不被
// 归类成缺陷、工具缺失或超时。
func assertHashBindingFailure(t *testing.T, stdout, stderr string, code int, ruleID string) {
	t.Helper()
	if code == 0 {
		t.Fatal("a submission binding a stale artifact hash must exit non-zero")
	}
	if !strings.Contains(stderr, ruleID) {
		t.Fatalf("stderr must name the rule whose record mismatches:\n%s", stderr)
	}
	if !strings.Contains(stderr, "artifact hash mismatch") {
		t.Fatalf("stderr must state the artifact hash mismatch:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)
	// 这是提交绑定错误：stderr 不能把它描述成任何一种检查结论。
	for _, marker := range []string{contractsentinel.StatusDefect, contractsentinel.StatusToolMissing, contractsentinel.StatusTimeout} {
		if strings.Contains(stderr, marker) {
			t.Fatalf("a binding error must not be classified as %q:\n%s", marker, stderr)
		}
	}
}

// --- ABI 只在字符串内部增加空格：产物已变，旧 artifactHash 必须整份拒绝 ---

func TestCLIAuditHashBindingABIWhitespaceChangeRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	in := mixedCheckInput(mixedArtifactHash(t))
	// 规则标识、版本、状态与说明全部不动，只在 ABI 字符串内部增加一个空格。
	in.Artifact.ABI = strings.Replace(in.Artifact.ABI, `"name":"withdraw"`, `"name": "withdraw"`, 1)
	if cliArtifactHash(in.Artifact) == mixedArtifactHash(t) {
		t.Fatal("sanity: an in-string ABI whitespace change must change the artifact hash")
	}
	input := writeStructInput(t, work, "tampered.json", in)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	// checks 中第一条记录（rule-pass）先撞上不匹配的哈希。
	assertHashBindingFailure(t, stdout, stderr, code, "rule-pass")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 字节码只改一处文本：旧 artifactHash 必须整份拒绝，已有归档原样保留 ---

func TestCLIAuditHashBindingBytecodeCharChangeRejectedKeepsStore(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	// 先落一份合法报告作为既有归档。
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

	// 字节码只改一个字符（…40 → …41），检查记录仍带原 artifactHash。
	in := mixedCheckInput(mixedArtifactHash(t))
	in.Artifact.Bytecode = "0x60806041"
	if cliArtifactHash(in.Artifact) == mixedArtifactHash(t) {
		t.Fatal("sanity: a single bytecode character change must change the artifact hash")
	}
	bad := writeStructInput(t, work, "bad.json", in)

	stdout, stderr, code := runCLIAudit(t, bin, bad, store)
	assertHashBindingFailure(t, stdout, stderr, code, "rule-pass")

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

// --- 把一段字符从 ABI 挪到字节码：三字段拼接不变，仍是不同产物 ---

func TestCLIAuditHashBindingFieldBoundaryMoveRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	a := mixedCheckArtifact()
	moved := a
	// ABI 末尾的 "]" 挪到字节码开头：abi+bytecode+source 直接拼接与原来逐字相同。
	moved.ABI = a.ABI[:len(a.ABI)-1]
	moved.Bytecode = a.ABI[len(a.ABI)-1:] + a.Bytecode
	if moved.ABI+moved.Bytecode+moved.Source != a.ABI+a.Bytecode+a.Source {
		t.Fatal("sanity: the field-boundary move must keep the plain concatenation identical")
	}
	if cliArtifactHash(moved) == cliArtifactHash(a) {
		t.Fatal("sanity: length-prefixed fields must distinguish a different abi/bytecode split")
	}
	// 检查记录仍绑定原产物的哈希。
	in := mixedCheckInput(mixedArtifactHash(t))
	in.Artifact = moved
	input := writeStructInput(t, work, "moved.json", in)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertHashBindingFailure(t, stdout, stderr, code, "rule-pass")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 其余记录绑定都正确，也不能让一条带旧哈希的记录被跳过或部分成功 ---

func TestCLIAuditHashBindingOtherValidRecordsDoNotRescue(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	in := mixedCheckInput(mixedArtifactHash(t))
	// 产物确实被修改，其余三条记录都改用新内容的正确哈希，
	// 只有 rule-defect 一条仍带着针对旧产物的 artifactHash。
	in.Artifact.ABI = strings.Replace(in.Artifact.ABI, `"name":"withdraw"`, `"name": "withdraw"`, 1)
	newHash := cliArtifactHash(in.Artifact)
	for i := range in.Checks {
		in.Checks[i].ArtifactHash = newHash
		if in.Checks[i].RuleID == "rule-defect" {
			in.Checks[i].ArtifactHash = mixedArtifactHash(t)
		}
	}
	input := writeStructInput(t, work, "mixed.json", in)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertHashBindingFailure(t, stdout, stderr, code, "rule-defect")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("one mismatched record must fail the whole submission without creating the store: %v", err)
	}
}

// --- 仅更改合约名称：哈希不变，原检查记录仍可导入，新报告取新标识 ---

func TestCLIAuditHashBindingNameChangeKeepsImport(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	base := writeStructInput(t, work, "base.json", mixedCheckInput(mixedArtifactHash(t)))
	stdout1, stderr1, code1 := runCLIAudit(t, bin, base, store)
	if code1 != 0 {
		t.Fatalf("base import must succeed, exit=%d stderr=%s", code1, stderr1)
	}
	report1 := decodeReport(t, stdout1)

	// 只改合约名称，abi/bytecode/source 与全部 checks 记录（含原 artifactHash）不动。
	renamed := mixedCheckInput(mixedArtifactHash(t))
	renamed.Artifact.Name = "VaultPlus"
	renamedPath := writeStructInput(t, work, "renamed.json", renamed)
	stdout2, stderr2, code2 := runCLIAudit(t, bin, renamedPath, store)
	if code2 != 0 {
		t.Fatalf("a name-only change must keep the old check records importable, exit=%d stderr=%s", code2, stderr2)
	}
	report2 := decodeReport(t, stdout2)

	if report2.Artifact.Name != "VaultPlus" {
		t.Fatalf("the new report must show the new name, got %+v", report2.Artifact)
	}
	if report2.Artifact.Hash != report1.Artifact.Hash {
		t.Fatalf("the artifact name must not participate in the hash: %q vs %q",
			report2.Artifact.Hash, report1.Artifact.Hash)
	}
	if report2.ReportID == report1.ReportID {
		t.Fatal("a renamed artifact is a different report and must get a different report id")
	}
	files, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("both reports must be archived side by side, got %v", files)
	}
	// 新报告可按其标识读回，名称与结论保持导入时的样子。
	readStdout, readStderr, readCode := runCLIReport(t, bin, store, report2.ReportID)
	if readCode != 0 {
		t.Fatalf("the renamed report must read back by id, exit=%d stderr=%s", readCode, readStderr)
	}
	loaded := decodeReport(t, readStdout)
	if loaded.Artifact.Name != "VaultPlus" || loaded.Artifact.Hash != report1.Artifact.Hash {
		t.Fatalf("read-back changed the renamed artifact header: %+v", loaded.Artifact)
	}
}

// --- 只调整 JSON 排版、或用合法转义表达同一字符串：不算产物变化 ---

func TestCLIAuditHashBindingFormattingAndEscapesNotArtifactChange(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	plain := writeStructInput(t, work, "plain.json", mixedCheckInput(mixedArtifactHash(t)))
	stdout1, stderr1, code1 := runCLIAudit(t, bin, plain, store)
	if code1 != 0 {
		t.Fatalf("plain import must succeed, exit=%d stderr=%s", code1, stderr1)
	}
	report1 := decodeReport(t, stdout1)

	// 同一份内容换一种合法序列化：用反斜线-u 的 Unicode 转义表达同样的字符
	// （含缺陷说明里的中文），并改变空白排版。
	data, err := json.Marshal(mixedCheckInput(mixedArtifactHash(t)))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, repl := range [][2]string{
		{`"abi":"[`, `"abi":"\u005b`},
		{`"bytecode":"0x`, `"bytecode":"0\u0078`},
		{`"source":"contract V`, `"source":"contract \u0056`},
		{`反例`, `\u53cd\u4f8b`},
		{`,"checks":`, ",\n\t \"checks\" : "},
	} {
		if !strings.Contains(text, repl[0]) {
			t.Fatalf("sanity: marshaled submission must contain %q", repl[0])
		}
		text = strings.Replace(text, repl[0], repl[1], 1)
	}
	variant := writeInput(t, work, "variant.json", text)

	stdout2, stderr2, code2 := runCLIAudit(t, bin, variant, store)
	if code2 != 0 {
		t.Fatalf("a formatting/escape-only resubmission must succeed, exit=%d stderr=%s", code2, stderr2)
	}
	report2 := decodeReport(t, stdout2)
	if report2.Artifact.Hash != report1.Artifact.Hash {
		t.Fatalf("legal escapes and formatting must not change the artifact hash: %q vs %q",
			report2.Artifact.Hash, report1.Artifact.Hash)
	}
	if report2.ReportID != report1.ReportID {
		t.Fatalf("the same content must yield the same report id: %q vs %q",
			report2.ReportID, report1.ReportID)
	}
	// 说明里的中文经转义解码后逐字保留。
	for _, r := range report2.Rules {
		if r.ID == "rule-defect" && r.Note != defectNote {
			t.Fatalf("the escaped note must decode to the original text, got %q", r.Note)
		}
	}
	files, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("identical content must share one archive, got %v", files)
	}
}

// --- 确实修改了 ABI/字节码：改用新内容的正确哈希后正常出报告 ---

func TestCLIAuditHashBindingModifiedArtifactWithNewHashSucceeds(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

	// 先落原产物的报告，便于对照新报告取得不同标识。
	base := writeStructInput(t, work, "base.json", mixedCheckInput(mixedArtifactHash(t)))
	stdout1, stderr1, code1 := runCLIAudit(t, bin, base, store)
	if code1 != 0 {
		t.Fatalf("base import must succeed, exit=%d stderr=%s", code1, stderr1)
	}
	report1 := decodeReport(t, stdout1)

	// ABI 与字节码都真实修改，检查记录改用新内容的正确哈希；
	// 规则标识、版本、状态与说明保持原样。
	in := mixedCheckInput(mixedArtifactHash(t))
	in.Artifact.ABI = strings.Replace(in.Artifact.ABI, `"name":"withdraw"`, `"name": "withdraw"`, 1)
	in.Artifact.Bytecode = "0x60806041"
	newHash := cliArtifactHash(in.Artifact)
	if newHash == mixedArtifactHash(t) {
		t.Fatal("sanity: the modified artifact must hash differently")
	}
	for i := range in.Checks {
		in.Checks[i].ArtifactHash = newHash
	}
	modified := writeStructInput(t, work, "modified.json", in)

	stdout2, stderr2, code2 := runCLIAudit(t, bin, modified, store)
	if code2 != 0 {
		t.Fatalf("re-binding the checks to the new artifact hash must succeed, exit=%d stderr=%s", code2, stderr2)
	}
	report2 := decodeReport(t, stdout2)

	if report2.Artifact.Hash != newHash {
		t.Fatalf("report must bind the new artifact hash %q, got %q", newHash, report2.Artifact.Hash)
	}
	if report2.ReportID == report1.ReportID {
		t.Fatal("a modified artifact is a different report and must get a different report id")
	}

	// 规则结论与原始说明逐字保留。
	statusByID := map[string]string{}
	noteByID := map[string]string{}
	for _, r := range report2.Rules {
		statusByID[r.ID] = r.Status
		noteByID[r.ID] = r.Note
	}
	wantStatuses := map[string]string{
		"rule-pass":      contractsentinel.StatusPass,
		"rule-defect":    contractsentinel.StatusDefect,
		"rule-tool":      contractsentinel.StatusToolMissing,
		"rule-timeout":   contractsentinel.StatusTimeout,
		"rule-unchecked": contractsentinel.StatusUnchecked,
	}
	for id, want := range wantStatuses {
		if statusByID[id] != want {
			t.Fatalf("rule %s status = %q, want %q", id, statusByID[id], want)
		}
	}
	if noteByID["rule-defect"] != defectNote {
		t.Fatalf("defect note = %q, want the original %q", noteByID["rule-defect"], defectNote)
	}

	// 缺陷记录绑定新产物哈希与原规则版本；工具缺失与超时不进 findings。
	if len(report2.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one defect", report2.Findings)
	}
	f := report2.Findings[0]
	if f.RuleID != "rule-defect" || f.Version != "2.0.1" {
		t.Fatalf("defect must keep its rule and original version, got %+v", f)
	}
	if f.ArtifactHash != newHash {
		t.Fatalf("defect must bind the new artifact hash %q, got %q", newHash, f.ArtifactHash)
	}
	if f.Evidence != defectNote {
		t.Fatalf("evidence = %q, must equal the original note %q", f.Evidence, defectNote)
	}

	// 新报告落盘并可按标识读回，内容不变。
	savedPath := filepath.Join(store, report2.ReportID+".json")
	if _, err := os.Stat(savedPath); err != nil {
		t.Fatalf("the modified-artifact report must be archived: %v", err)
	}
	readStdout, readStderr, readCode := runCLIReport(t, bin, store, report2.ReportID)
	if readCode != 0 {
		t.Fatalf("the new report must read back by id, exit=%d stderr=%s", readCode, readStderr)
	}
	loaded := decodeReport(t, readStdout)
	if loaded.ReportID != report2.ReportID || loaded.Artifact != report2.Artifact ||
		len(loaded.Findings) != 1 || loaded.Findings[0] != f {
		t.Fatalf("read-back changed the modified-artifact report:\n%+v\n%+v", loaded, report2)
	}
}
