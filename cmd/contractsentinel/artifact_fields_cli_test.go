package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件在真实命令行进程边界上回归保护：artifact 正式写出的 name、abi、
// bytecode、source 都必须是 JSON 字符串。任意一个字段写成 null（或布尔、
// 数字、对象、数组）时，整份提交必须失败——非零退出、原因进 stderr 并点名
// 具体字段（例如 artifact.source）必须是字符串、stdout 没有报告或成功
// 标识、尚不存在的报告目录不被创建、已有归档保持原样。即使产物名称合法、
// 规则数组为空，source:null 也不能得到成功报告。省略字段与显式空字符串
// 的既有行为不变。

// nullSourceInput 是任务描述中的核心场景：名称合法、没有规则与检查记录，
// 仅 source 写成 null。
const nullSourceInput = `{
	"artifact": {"name":"Vault","abi":"","bytecode":"","source":null},
	"rules": []
}`

// emptySourceInput 与上面的唯一差别是显式空字符串：这是用户明确提交的
// 空文本，没有规则要求时必须继续成功。
const emptySourceInput = `{
	"artifact": {"name":"Vault","abi":"","bytecode":"","source":""},
	"rules": []
}`

// nullArtifactFieldInput 把指定产物字段替换成 null，其余字段保持合法。
func nullArtifactFieldInput(field string) string {
	vals := map[string]string{
		"name":     `"Vault"`,
		"abi":      `"abi"`,
		"bytecode": `"0x1"`,
		"source":   `"Vault.sol"`,
	}
	vals[field] = "null"
	return `{
	"artifact": {"name":` + vals["name"] + `,"abi":` + vals["abi"] +
		`,"bytecode":` + vals["bytecode"] + `,"source":` + vals["source"] + `},
	"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}],
	"invariants": {"inv": true}
}`
}

// 合法名称 + source:null + 空规则：非零退出，stderr 点名 artifact.source
// 必须是字符串，stdout 不出现报告或成功标识。
func TestCLIAuditNullSourceFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", nullSourceInput)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code == 0 {
		t.Fatal("audit must exit non-zero for a null artifact source")
	}
	if stdout != "" {
		t.Fatalf("stdout must not contain a report or success marker:\n%s", stdout)
	}
	if !strings.Contains(stderr, "artifact.source") {
		t.Fatalf("stderr must name artifact.source:\n%s", stderr)
	}
	if !strings.Contains(stderr, "must be a string") {
		t.Fatalf("stderr must state the field must be a string:\n%s", stderr)
	}
	// 格式错误不能被记成缺陷、工具缺失或超时。
	for _, marker := range []string{"发现缺陷", "工具缺失", "超时", "reportId"} {
		if strings.Contains(stderr, marker) || strings.Contains(stdout, marker) {
			t.Fatalf("a format error must not be reported as %q", marker)
		}
	}
}

// 四个字段任意一个为 null 都必须失败并点名该字段。
func TestCLIAuditNullArtifactFieldsRejected(t *testing.T) {
	bin := auditBinary(t)
	for _, field := range []string{"name", "abi", "bytecode", "source"} {
		t.Run(field, func(t *testing.T) {
			work := t.TempDir()
			input := writeInput(t, work, "in.json", nullArtifactFieldInput(field))
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code == 0 {
				t.Fatalf("artifact.%s: null must reject the whole submission", field)
			}
			if stdout != "" {
				t.Fatalf("rejected submission must print nothing to stdout:\n%s", stdout)
			}
			if !strings.Contains(stderr, "artifact."+field+" must be a string") {
				t.Fatalf("stderr must say artifact.%s must be a string:\n%s", field, stderr)
			}
		})
	}
}

// 失败时不得创建尚不存在的报告目录或任何归档。
func TestCLIAuditNullSourceCreatesNoStore(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", nullSourceInput)
	store := filepath.Join(work, "nested", "missing-store")

	if out, err := exec.Command(bin, "audit", "--input", input, "--store", store).CombinedOutput(); err == nil {
		t.Fatalf("audit must fail, output:\n%s", out)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("failure must not create the report store: %v", err)
	}
}

// 目录中已有报告时，一次 null source 提交必须保持原有内容原样不变。
func TestCLIAuditNullSourceKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	validInput := writeInput(t, work, "valid.json", emptySourceInput)
	store := filepath.Join(work, "reports")

	setup := exec.Command(bin, "audit", "--input", validInput, "--store", store)
	if out, err := setup.CombinedOutput(); err != nil {
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

	badInput := writeInput(t, work, "bad.json", nullSourceInput)
	if out, err := exec.Command(bin, "audit", "--input", badInput, "--store", store).CombinedOutput(); err == nil {
		t.Fatalf("invalid audit must fail, output:\n%s", out)
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

// 显式空字符串在没有规则要求时仍然合法并产生成功报告（回归保护：与省略
// source 等价）。
func TestCLIAuditExplicitEmptySourceStillWorks(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", emptySourceInput)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("an explicit empty source without rules must stay legal: exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "reportId") {
		t.Fatalf("stdout must contain the success report:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(store)); err != nil {
		t.Fatalf("the legal submission must have created the store: %v", err)
	}
}
