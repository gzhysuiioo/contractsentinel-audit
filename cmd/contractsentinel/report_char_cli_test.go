package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件在真实命令行进程边界上回归 report / diff / audit 读取已保存归档时对
// 非法字符的拒绝：归档任何位置的非法 UTF-8 字节、JSON 字符串中孤立或错序的
// Unicode 代理转义，即使解码（改写为 U+FFFD）后报告标识与缺陷归属校验都能
// 通过，也必须把整份报告判为损坏——非零退出、stdout 无报告片段、stderr 指出
// 报告标识并区分字符编码 / Unicode 转义问题且给出位置，归档原字节保留。
// 合法存在的 U+FFFD 与正确配对的代理转义继续正常读取。

// auditFFFDReport 落盘一份说明与证据都含合法 U+FFFD 的缺陷报告，返回其标识。
func auditFFFDReport(t *testing.T, bin, work, store string) string {
	t.Helper()
	hash := contractsentinelArtifactHashForCharset()
	input := writeInput(t, work, "fffd.json",
		charsetDefectDoc(hash, `"反例：含 � 字符"`))
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit with a legal U+FFFD note must succeed: %s", stderr)
	}
	return decodeReport(t, stdout).ReportID
}

// corruptArchive 对 id 的归档做一次文本替换并写回，返回改写后的字节。
func corruptArchive(t *testing.T, store, id, old, new string) []byte {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.ReplaceAll(string(data), old, new)
	if doc == string(data) {
		t.Fatalf("test setup: archive does not contain %q", old)
	}
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return []byte(doc)
}

// assertCharFailure 断言读取失败的完整契约：非零退出、stdout 为空、stderr
// 点名报告标识并包含全部定位片段。
func assertCharFailure(t *testing.T, stdout, stderr string, code int, id string, want ...string) {
	t.Helper()
	if code == 0 {
		t.Fatal("an archive with illegal characters must exit non-zero")
	}
	if !strings.Contains(stderr, "corrupt") {
		t.Fatalf("stderr must classify the archive as corrupt:\n%s", stderr)
	}
	if !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the report id %q:\n%s", id, stderr)
	}
	for _, w := range want {
		if !strings.Contains(stderr, w) {
			t.Fatalf("stderr must contain %q:\n%s", w, stderr)
		}
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- report：合法 U+FFFD 被换成孤立代理转义，标识仍一致，仍整份拒绝 ---

func TestCLIReportLoneSurrogateArchiveRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditFFFDReport(t, bin, work, store)
	corrupt := corruptArchive(t, store, id, "�", `\uD800`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCharFailure(t, stdout, stderr, code, id,
		"Unicode escape", "surrogate", ".rules[0].note", "byte offset", "line ", "column")

	kept, err := os.ReadFile(filepath.Join(store, id+".json"))
	if err != nil || !bytes.Equal(kept, corrupt) {
		t.Fatalf("failed report read must leave the corrupt archive untouched: %v", err)
	}
}

// --- report：非法 UTF-8 字节按字符编码错误拒绝 ---

func TestCLIReportInvalidUTF8ArchiveRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditFFFDReport(t, bin, work, store)
	corruptArchive(t, store, id, "�", "\xFF")

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCharFailure(t, stdout, stderr, code, id,
		"character encoding", "UTF-8", "byte offset")
}

// --- report：未知扩展成员嵌套内容里的孤立代理项也不放行 ---

func TestCLIReportLoneSurrogateInExtensionRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditFFFDReport(t, bin, work, store)
	corruptArchive(t, store, id, `{"reportId"`, `{"mystery":{"deep":["x\uDC00y"]},"reportId"`)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertCharFailure(t, stdout, stderr, code, id, "Unicode escape", "surrogate", ".mystery.deep[0]")
}

// --- diff：任一侧归档含非法字符，整次比较失败，无部分结果 ---

func TestCLIDiffBadCharArchiveEitherSideFails(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := contractsentinelArtifactHashForCharset()

	beforeID := auditFFFDReport(t, bin, work, store)
	timeoutDoc := `{"artifact":` + charsetArtifactJSON + `,"rules":` + charsetRulesJSON +
		`,"checks":[{"artifactHash":"` + hash + `","ruleId":"r1","version":"1.0.0","status":"超时","note":"符号执行超时，未得出结论"}]}`
	afterInput := writeInput(t, work, "after.json", timeoutDoc)
	afterOut, afterErr, code := runCLIAudit(t, bin, afterInput, store)
	if code != 0 {
		t.Fatalf("setup timeout audit must succeed: %s", afterErr)
	}
	afterID := decodeReport(t, afterOut).ReportID

	// 基准侧归档损坏：两个参数顺序都必须整体失败。
	corrupt := corruptArchive(t, store, beforeID, "�", `\uD800`)
	for _, tc := range []struct{ before, after string }{
		{beforeID, afterID},
		{afterID, beforeID},
	} {
		stdout, stderr, code := runCLIDiff(t, bin, store, tc.before, tc.after)
		assertCharFailure(t, stdout, stderr, code, beforeID, "Unicode escape", "surrogate")
		for _, marker := range []string{`"results"`, `"summary"`, "检查状态变化"} {
			if strings.Contains(stdout, marker) {
				t.Fatalf("stdout must not leak a partial diff %q:\n%s", marker, stdout)
			}
		}
	}
	kept, err := os.ReadFile(filepath.Join(store, beforeID+".json"))
	if err != nil || !bytes.Equal(kept, corrupt) {
		t.Fatalf("failed diff must leave the corrupt archive untouched: %v", err)
	}
}

// --- audit：同标识既有归档含非法字符，不能当成保存成功 ---

func TestCLIAuditBadCharExistingArchiveFailsAndKeepsFile(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditFFFDReport(t, bin, work, store)
	corrupt := corruptArchive(t, store, id, "�", `\uD800`)

	// 用完全相同的合法提交再审计一次：同标识归档已损坏，必须失败。
	hash := contractsentinelArtifactHashForCharset()
	again := writeInput(t, work, "again.json", charsetDefectDoc(hash, `"反例：含 � 字符"`))
	stdout, stderr, code := runCLIAudit(t, bin, again, store)
	if code == 0 {
		t.Fatal("audit against a corrupt-character existing archive must exit non-zero")
	}
	if !strings.Contains(stderr, "corrupt") || !strings.Contains(stderr, "surrogate") {
		t.Fatalf("stderr must report the character corruption:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("failed audit must print nothing to stdout:\n%s", stdout)
	}
	kept, err := os.ReadFile(filepath.Join(store, id+".json"))
	if err != nil || !bytes.Equal(kept, corrupt) {
		t.Fatalf("failed audit must leave the corrupt archive untouched: %v", err)
	}
}

// --- 合法 U+FFFD 归档继续正常读取，说明原文保留 ---

func TestCLIReportLegalFFFDArchiveStillReads(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditFFFDReport(t, bin, work, store)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("a literal U+FFFD archive must read successfully: %s", stderr)
	}
	if !strings.Contains(stdout, "反例：含 � 字符") {
		t.Fatalf("stdout must carry the decoded original note:\n%s", stdout)
	}
}
