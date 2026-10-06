package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护：audit 提交中产物的正式 name、abi、
// bytecode、source 成员一旦写出就必须是 JSON 字符串。写成 null（或布尔值、
// 数字、对象、数组）时整份提交必须失败——非零退出、原因进 stderr 并点名
// 具体字段（例如 artifact.source）与“必须是字符串”，stdout 没有报告或成功
// 标识，尚不存在的报告目录不被创建，已有归档保持原样。省略成员与显式空
// 字符串的既有行为不变：名称合法、其余字段显式写成 ""、规则为空时仍能
// 成功出报告，这与同位置写 null 形成对照。

// artifactNullFieldInput 是名称合法、规则为空、仅一个产物字段为 null 的提交。
func artifactNullFieldInput(field string) string {
	values := map[string]string{
		"name":     `null`,
		"abi":      `null`,
		"bytecode": `null`,
		"source":   `null`,
	}
	fields := []string{`"name":"Vault"`}
	for _, f := range []string{"abi", "bytecode", "source"} {
		v := `""`
		if f == field {
			v = values[f]
		}
		fields = append(fields, `"`+f+`":`+v)
	}
	if field == "name" {
		fields[0] = `"name":null`
	}
	return `{"artifact":{` + strings.Join(fields, ",") + `},"rules":[]}`
}

// 四个字段的 null：非零退出、stderr 点名字段与字符串要求、stdout 为空。

func TestCLIAuditNullArtifactFieldFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	for _, field := range []string{"name", "abi", "bytecode", "source"} {
		t.Run(field, func(t *testing.T) {
			work := t.TempDir()
			input := writeInput(t, work, "in.json", artifactNullFieldInput(field))
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code == 0 {
				t.Fatalf("audit must exit non-zero when artifact.%s is null", field)
			}
			if stdout != "" {
				t.Fatalf("stdout must not contain a report or success marker:\n%s", stdout)
			}
			if !strings.Contains(stderr, "artifact."+field) {
				t.Fatalf("stderr must name artifact.%s:\n%s", field, stderr)
			}
			if !strings.Contains(stderr, "must be a string") {
				t.Fatalf("stderr must state the field must be a string:\n%s", stderr)
			}
			// 这是提交格式错误：stderr 不能把它描述成缺陷、工具缺失或超时。
			for _, marker := range []string{contractsentinel.StatusDefect, "tool", "timeout", "超时"} {
				if strings.Contains(stderr, marker) {
					t.Fatalf("a format error must not be classified as %q:\n%s", marker, stderr)
				}
			}
		})
	}
}

// 失败时不得创建尚不存在的报告目录，也不留归档。

func TestCLIAuditNullArtifactFieldCreatesNoStore(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", artifactNullFieldInput("source"))
	store := filepath.Join(work, "nested", "missing-store")

	if out, err := exec.Command(bin, "audit", "--input", input, "--store", store).CombinedOutput(); err == nil {
		t.Fatalf("audit must fail, output:\n%s", out)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("failure must not create the report store: %v", err)
	}
}

// 目录中已有报告时，一次 null 字段提交必须保持原有内容原样不变。

func TestCLIAuditNullArtifactFieldKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	// 先落一份合法报告：名称合法、其余字段显式空文本、规则为空。
	validInput := writeInput(t, work, "valid.json",
		`{"artifact":{"name":"Vault","abi":"","bytecode":"","source":""},"rules":[]}`)
	store := filepath.Join(work, "reports")
	if out, err := exec.Command(bin, "audit", "--input", validInput, "--store", store).CombinedOutput(); err != nil {
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

	badInput := writeInput(t, work, "bad.json", artifactNullFieldInput("source"))
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

// 布尔值、数字、对象、数组写在正式 source 上同样整份拒绝。

func TestCLIAuditNonStringArtifactSourceFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	for _, val := range []string{"true", "false", "42", "{}", `["s"]`} {
		t.Run(val, func(t *testing.T) {
			work := t.TempDir()
			in := `{"artifact":{"name":"Vault","abi":"","bytecode":"","source":` + val + `},"rules":[]}`
			input := writeInput(t, work, "in.json", in)
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code == 0 {
				t.Fatalf("audit must exit non-zero when source is %s", val)
			}
			if stdout != "" {
				t.Fatalf("stdout must stay empty:\n%s", stdout)
			}
			if !strings.Contains(stderr, "artifact.source must be a string") {
				t.Fatalf("stderr must name artifact.source and the string requirement:\n%s", stderr)
			}
			if _, err := os.Stat(store); !os.IsNotExist(err) {
				t.Fatalf("failure must not create the report store: %v", err)
			}
		})
	}
}

// 显式空字符串与 null 形成对照：没有相关要求时，合法空文本仍成功出报告。

func TestCLIAuditExplicitEmptySourceStillSucceeds(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json",
		`{"artifact":{"name":"Vault","abi":"","bytecode":"","source":""},"rules":[]}`)
	store := filepath.Join(work, "nested", "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("an explicit empty source with no rules must succeed, exit=%d stderr=%s", code, stderr)
	}
	report := decodeReport(t, stdout)
	if report.Artifact.Name != "Vault" {
		t.Fatalf("report must bind the submitted artifact name: %+v", report.Artifact)
	}
	// 成功时必须落盘，且可按返回的报告标识原样读回。
	savedPath := filepath.Join(store, report.ReportID+".json")
	if _, err := os.Stat(savedPath); err != nil {
		t.Fatalf("a successful submission must archive the report: %v", err)
	}
	readStdout, _, readCode := runCLIReport(t, bin, store, report.ReportID)
	if readCode != 0 {
		t.Fatalf("the saved report must read back by id, exit=%d", readCode)
	}
	loaded := decodeReport(t, readStdout)
	if loaded.ReportID != report.ReportID || loaded.Artifact != report.Artifact {
		t.Fatalf("read-back changed the report:\n%+v\n%+v", loaded, report)
	}
}

// 大小写变体或带空格名称携带的合法字符串不能挽救正式 source 的 null。

func TestCLIAuditVariantArtifactNameCannotRescueNull(t *testing.T) {
	bin := auditBinary(t)
	for _, tc := range []struct {
		name string
		frag string
	}{
		{"case variant before", `"Source":"Vault.sol","source":null`},
		{"case variant after", `"source":null,"Source":"Vault.sol"`},
		{"padded before", `" source ":"Vault.sol","source":null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			in := `{"artifact":{"name":"Vault","abi":"","bytecode":"",` + tc.frag + `},"rules":[]}`
			input := writeInput(t, work, "in.json", in)
			store := filepath.Join(work, "reports")

			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code == 0 {
				t.Fatal("a variant-named member must not rescue a null formal source")
			}
			if stdout != "" {
				t.Fatalf("stdout must stay empty:\n%s", stdout)
			}
			if !strings.Contains(stderr, "artifact.source must be a string") {
				t.Fatalf("stderr must name the formal field and its type:\n%s", stderr)
			}
		})
	}
}
