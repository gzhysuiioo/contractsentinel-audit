package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护：audit 提交 checks 数组中每条记录的
// 正式 note 成员（约定拼写，含 Unicode 转义写法）一旦写出，值就必须是 JSON
// 字符串。写成 null（或布尔值、数字、对象、数组）时整份提交必须失败——非零
// 退出、原因进 stderr 并点名 checks 数组中从零开始的位置与“note must be a
// string”（记录带合法 ruleId 时同时点名规则），stdout 为空，尚不存在的报告
// 目录不被创建，已有归档保持原样；这条规则对通过、发现缺陷、工具缺失、超时
// 四种状态都有效。省略 note 与显式空串的既有行为不变：通过允许没有说明，
// 也允许空串或纯空白串；其余三种状态缺少非空白说明仍按原方式失败。Note、
// 两侧带空格的名称及未知成员只是扩展信息，其中的非字符串值不触发本类型
// 错误，也不能补位或挽救正式 note。

// noteCLIDoc 构造一份含一条 r1 检查记录的提交；tail 是 status 之后的原始
// 成员片段（例如 `"note":null`），为空表示不再追加成员。
func noteCLIDoc(hash, status, tail string) string {
	artifact, _ := json.Marshal(mixedCheckArtifact())
	rule, _ := json.Marshal(cliWireRule{
		ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1.0.0",
	})
	suffix := ""
	if tail != "" {
		suffix = "," + tail
	}
	check := fmt.Sprintf(`{"artifactHash":%q,"ruleId":"r1","version":"1.0.0","status":%q%s}`,
		hash, status, suffix)
	return fmt.Sprintf(`{"artifact":%s,"rules":[%s],"checks":[%s]}`, artifact, rule, check)
}

// assertCheckNoteSubmitFailure 断言非字符串正式 note 的完整失败契约。
func assertCheckNoteSubmitFailure(t *testing.T, stdout, stderr string, code int, position, rule string) {
	t.Helper()
	if code == 0 {
		t.Fatal("audit must exit non-zero when a formal note is not a string")
	}
	if stdout != "" {
		t.Fatalf("stdout must stay empty on a rejected submission:\n%s", stdout)
	}
	if !strings.Contains(stderr, position) {
		t.Fatalf("stderr must name the checks-array position %q:\n%s", position, stderr)
	}
	if !strings.Contains(stderr, "note must be a string") {
		t.Fatalf("stderr must state note must be a string:\n%s", stderr)
	}
	if rule != "" {
		if !strings.Contains(stderr, "(rule "+rule+")") {
			t.Fatalf("stderr must name the legal rule id %q:\n%s", rule, stderr)
		}
	}
	// 这是提交格式错误：不能落入既有业务失败措辞，也不能被描述成检查结论。
	for _, marker := range []string{"note is required", "unknown status",
		contractsentinel.StatusDefect, contractsentinel.StatusToolMissing, contractsentinel.StatusTimeout} {
		if strings.Contains(stderr, marker) {
			t.Fatalf("a note type error must not be reported as %q:\n%s", marker, stderr)
		}
	}
}

// --- 四种状态写出 null note：非零退出、stderr 点名位置/规则/字符串要求 ---

func TestCLIAuditNullNoteFailsForAllStatuses(t *testing.T) {
	bin := auditBinary(t)
	hash := mixedArtifactHash(t)
	for _, status := range []string{
		contractsentinel.StatusPass, contractsentinel.StatusDefect,
		contractsentinel.StatusToolMissing, contractsentinel.StatusTimeout,
	} {
		t.Run(status, func(t *testing.T) {
			work := t.TempDir()
			input := writeInput(t, work, "in.json", noteCLIDoc(hash, status, `"note":null`))
			store := filepath.Join(work, "nested", "missing-store")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			assertCheckNoteSubmitFailure(t, stdout, stderr, code, "checks[0]", "r1")
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("failure must not create the report store: %v", err)
			}
		})
	}
}

// --- 布尔值、数字、对象、数组同样失败，stdout 不泄露任何报告片段 ---

func TestCLIAuditNonStringNoteFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	hash := mixedArtifactHash(t)
	for _, val := range []string{"true", "false", "42", "{}", `["x"]`} {
		t.Run(val, func(t *testing.T) {
			work := t.TempDir()
			input := writeInput(t, work, "in.json", noteCLIDoc(hash, contractsentinel.StatusPass, `"note":`+val))
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			assertCheckNoteSubmitFailure(t, stdout, stderr, code, "checks[0]", "r1")
			for _, marker := range []string{`"reportId"`, `"rules"`, `"findings"`} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a report fragment %q", marker)
				}
			}
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("failure must not create the report store: %v", err)
			}
		})
	}
}

// --- 其他记录全部合法也不能挽救；错误按记录在 checks 数组中的位置定位 ---

func TestCLIAuditNullNoteAmongLegalRecordsNamesPosition(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	// 紧凑 JSON 便于按成员子串改写其中一条记录。
	goodBytes, err := json.Marshal(mixedCheckInput(hash))
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(work, "nested", "missing-store")

	// checks[0]：唯一的“通过”记录（rule-pass）原本省略 note，改成 null。
	first := strings.Replace(string(goodBytes), `"status":"通过"}`, `"status":"通过","note":null}`, 1)
	if first == string(goodBytes) {
		t.Fatal("test setup failed to locate the pass record")
	}
	input := writeInput(t, work, "first.json", first)
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertCheckNoteSubmitFailure(t, stdout, stderr, code, "checks[0]", "rule-pass")

	// checks[2]：工具缺失记录的合法说明换成 null，其余三条记录全部合法。
	third := strings.Replace(string(goodBytes),
		`"status":"工具缺失","note":"符号执行引擎未安装"`,
		`"status":"工具缺失","note":null`, 1)
	if third == string(goodBytes) {
		t.Fatal("test setup failed to locate the tool-missing record")
	}
	input = writeInput(t, work, "third.json", third)
	stdout, stderr, code = runCLIAudit(t, bin, input, store)
	assertCheckNoteSubmitFailure(t, stdout, stderr, code, "checks[2]", "rule-tool")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("failure must not create the report store: %v", err)
	}
}

// --- 目录中已有归档时，一次 null note 提交必须保持原有归档原样不变 ---

func TestCLIAuditNullNoteKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	good := writeStructInput(t, work, "good.json", mixedCheckInput(mixedArtifactHash(t)))
	store := filepath.Join(work, "reports")
	if out, err := exec.Command(bin, "audit", "--input", good, "--store", store).CombinedOutput(); err != nil {
		t.Fatalf("valid audit setup failed: %v\n%s", err, out)
	}
	before, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("setup expected 1 report, got %d: %v", len(before), before)
	}
	existingPath := filepath.Join(store, before[0])
	existingBytes, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}

	badInput := writeInput(t, work, "bad.json",
		noteCLIDoc(mixedArtifactHash(t), contractsentinel.StatusPass, `"note":null`))
	var stdout bytes.Buffer
	cmd := exec.Command(bin, "audit", "--input", badInput, "--store", store)
	cmd.Stdout = &stdout
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("invalid audit must fail, output:\n%s", out)
	}
	if stdout.String() != "" {
		t.Fatalf("rejected submission must print nothing to stdout:\n%s", stdout.String())
	}
	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("failure changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existingBytes) {
		t.Fatal("failure modified the existing report")
	}
}

// --- 变体名称是扩展信息：其非字符串值不触发本类型错误，也不能补位或挽救 ---

func TestCLIAuditNoteVariantsDoNotTriggerOrRescue(t *testing.T) {
	bin := auditBinary(t)
	hash := mixedArtifactHash(t)

	// 正式 note 省略或合法，变体携带 null/数字/对象：合法提交，不触发类型错误。
	for _, tail := range []string{
		`"Note":null`,                 // 正式 note 省略
		`" note ":42`,                 // 带空格名称 + 数字
		`"mystery":{"a":1},"note":""`, // 未知对象 + 显式空串
		`"note":" 说明 \n","Note":[1]`,  // 正式合法说明 + 变体数组
	} {
		work := t.TempDir()
		input := writeInput(t, work, "in.json", noteCLIDoc(hash, contractsentinel.StatusPass, tail))
		stdout, stderr, code := runCLIAudit(t, bin, input, filepath.Join(work, "reports"))
		if code != 0 {
			t.Fatalf("a non-string under a variant/unknown name is extension data: %s", stderr)
		}
		if stdout == "" {
			t.Fatal("the legal submission must still print its report")
		}
	}

	// 缺陷记录缺正式 note，只有变体给字符串：不能补位，沿用既有必填失败，
	// 而不是 note 类型错误。
	work := t.TempDir()
	missing := noteCLIDoc(hash, contractsentinel.StatusDefect, `"Note":"变体里的说明"`)
	input := writeInput(t, work, "in.json", missing)
	_, stderr, code := runCLIAudit(t, bin, input, filepath.Join(work, "reports"))
	if code == 0 {
		t.Fatal("a variant note must not fill a missing formal note")
	}
	if !strings.Contains(stderr, "note is required for status "+contractsentinel.StatusDefect) {
		t.Fatalf("the omission must keep the existing required-note failure:\n%s", stderr)
	}

	// 正式 note 为 null，变体携带合法字符串（位于其前或其后）都不能挽救。
	for _, tail := range []string{`"Note":"说明","note":null`, `"note":null," note ":"说明"`} {
		sub := t.TempDir()
		badInput := writeInput(t, sub, "in.json", noteCLIDoc(hash, contractsentinel.StatusPass, tail))
		stdout, errText, exitCode := runCLIAudit(t, bin, badInput, filepath.Join(sub, "reports"))
		assertCheckNoteSubmitFailure(t, stdout, errText, exitCode, "checks[0]", "r1")
	}
}

// --- Unicode 转义写出的正式名称：解码后恰为 note，null 同样拒绝 ---

func TestCLIAuditEscapedNoteNameRejectsNull(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	// "n\u006fte" 解码后就是 "note"。
	in := noteCLIDoc(hash, contractsentinel.StatusPass, `"n\u006fte":null`)
	if !strings.Contains(in, `\u006fte`) {
		t.Fatalf("test setup must carry the JSON escape, got %s", in)
	}
	input := writeInput(t, work, "in.json", in)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertCheckNoteSubmitFailure(t, stdout, stderr, code, "checks[0]", "r1")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("failure must not create the report store: %v", err)
	}
}

// --- 省略、显式空串与纯空白串对通过仍然合法，且省略与空串报告标识一致 ---

func TestCLIAuditPassAcceptsOmittedEmptyAndWhitespaceNote(t *testing.T) {
	bin := auditBinary(t)
	hash := mixedArtifactHash(t)

	run := func(tail string) contractsentinel.Report {
		work := t.TempDir()
		input := writeInput(t, work, "in.json", noteCLIDoc(hash, contractsentinel.StatusPass, tail))
		stdout, stderr, code := runCLIAudit(t, bin, input, filepath.Join(work, "reports"))
		if code != 0 {
			t.Fatalf("legal pass note must succeed, exit=%d stderr=%s", code, stderr)
		}
		return decodeReport(t, stdout)
	}

	omitted := run("")
	empty := run(`"note":""`)
	if omitted.ReportID != empty.ReportID {
		t.Fatalf("omitted and explicit-empty pass notes must share the report id:\n %s\n %s",
			omitted.ReportID, empty.ReportID)
	}
	if omitted.Rules[0].Note != "" {
		t.Fatalf("an omitted note must read back empty: %q", omitted.Rules[0].Note)
	}

	// 纯空白说明合法且原样保留（不修剪），落盘后可按报告标识读回同一文本。
	ws := " \t\n "
	wsWork := t.TempDir()
	wsInput := writeInput(t, wsWork, "in.json", noteCLIDoc(hash, contractsentinel.StatusPass, `"note":" \t\n "`))
	wsStore := filepath.Join(wsWork, "reports")
	stdout, stderr, code := runCLIAudit(t, bin, wsInput, wsStore)
	if code != 0 {
		t.Fatalf("whitespace note submission must succeed: %s", stderr)
	}
	whitespace := decodeReport(t, stdout)
	if whitespace.Rules[0].Note != ws {
		t.Fatalf("whitespace-only note must be preserved verbatim: got %q want %q",
			whitespace.Rules[0].Note, ws)
	}
	readStdout, _, readCode := runCLIReport(t, bin, wsStore, whitespace.ReportID)
	if readCode != 0 || decodeReport(t, readStdout).Rules[0].Note != ws {
		t.Fatalf("the whitespace note must read back verbatim by report id: %q", readStdout)
	}

	// 其余三种状态给出空串/纯空白：沿用既有 “note is required” 失败。
	for _, status := range []string{
		contractsentinel.StatusDefect, contractsentinel.StatusToolMissing, contractsentinel.StatusTimeout,
	} {
		for _, tail := range []string{`"note":""`, `"note":" \n  "`} {
			sub := t.TempDir()
			badInput := writeInput(t, sub, "in.json", noteCLIDoc(hash, status, tail))
			_, stderr, code := runCLIAudit(t, bin, badInput, filepath.Join(sub, "reports"))
			if code == 0 {
				t.Fatalf("status %s with a blank note must keep failing", status)
			}
			if !strings.Contains(stderr, "note is required for status "+status) {
				t.Fatalf("status %s must keep the blank-note failure:\n%s", status, stderr)
			}
		}
	}
}

// --- 合法说明的中文、换行、前后空格原样进入规则说明与缺陷证据 ---

func TestCLIAuditLegalNoteContentPreservedVerbatim(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	note := "  反例：攻击者可在 withdraw 中重入\n第二行证据  "
	noteJSON, _ := json.Marshal(note)
	in := noteCLIDoc(hash, contractsentinel.StatusDefect, `"note":`+string(noteJSON))
	input := writeInput(t, work, "in.json", in)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("a legal defect note must succeed: %s", stderr)
	}
	report := decodeReport(t, stdout)
	if report.Rules[0].Note != note {
		t.Fatalf("rule note must be verbatim:\n got %q\nwant %q", report.Rules[0].Note, note)
	}
	if len(report.Findings) != 1 || report.Findings[0].Evidence != note {
		t.Fatalf("the finding evidence must be the submitted note verbatim: %+v", report.Findings)
	}
	readStdout, _, readCode := runCLIReport(t, bin, store, report.ReportID)
	if readCode != 0 {
		t.Fatal("the saved report must read back by id")
	}
	if loaded := decodeReport(t, readStdout); loaded.Findings[0].Evidence != note {
		t.Fatalf("read-back changed the evidence: %q", loaded.Findings[0].Evidence)
	}
}
