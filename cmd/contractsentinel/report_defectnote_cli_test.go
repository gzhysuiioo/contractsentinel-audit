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

// 本文件在真实命令行进程边界上回归保护 report / diff 读取已保存报告时对
// 缺陷说明的空白校验：一条“发现缺陷”规则的 note 是非空字符串却完全由空格、
// 制表符或换行组成，且对应 finding 的 evidence 保存同一段空白时，即使产物
// 哈希、规则版本、其余绑定与重新计算的报告标识全部吻合，整份归档也必须判为
// 损坏——非零退出、原因进 stderr（含请求的报告标识、所属规则，并指出缺陷
// 说明为空白），stdout 不出现任何报告片段或比较分类，原归档原样保留。只提交
// 不变式值 false 生成的无说明缺陷报告（证据为 invariant <名> does not hold）
// 仍正常读回。

// blankOutArchivedDefectNote 把归档中 ruleID 规则的 note 与对应 finding 的
// evidence 改写为同一段纯空白文本，按改写后内容重新计算报告标识并以新标识
// 落盘（旧文件删除）。返回新标识与落盘字节；归档标识与内容完全一致，拒绝
// 只能来自空白说明校验。
func blankOutArchivedDefectNote(t *testing.T, store, id, ruleID, blank string) (string, []byte) {
	t.Helper()
	path := filepath.Join(store, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report contractsentinel.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	changed := false
	for i := range report.Rules {
		if report.Rules[i].ID == ruleID {
			report.Rules[i].Note = blank
			changed = true
		}
	}
	if !changed {
		t.Fatalf("test setup: rule %s not found in archive", ruleID)
	}
	for i := range report.Findings {
		if report.Findings[i].RuleID == ruleID {
			report.Findings[i].Evidence = blank
		}
	}
	report.ReportID = contractsentinel.ReportID(report)
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, report.ReportID+".json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	return report.ReportID, out
}

// assertBlankNoteFailure 断言空白缺陷说明的完整 CLI 失败契约：非零退出，
// stderr 给出报告标识、所属规则与“说明为空白”的原因，stdout 为空。
func assertBlankNoteFailure(t *testing.T, stdout, stderr string, code int, id, rule string) {
	t.Helper()
	if code == 0 {
		t.Fatal("an archive with a whitespace-only defect note must exit non-zero")
	}
	if !strings.Contains(stderr, id) {
		t.Fatalf("stderr must name the requested report id %q:\n%s", id, stderr)
	}
	if !strings.Contains(stderr, rule) {
		t.Fatalf("stderr must name the owning rule %q:\n%s", rule, stderr)
	}
	if !strings.Contains(stderr, "blank note") {
		t.Fatalf("stderr must state the defect note is blank:\n%s", stderr)
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- report：note 与 evidence 同为纯空白、标识与内容吻合，也必须整份拒绝 ---

func TestCLIReportBlankDefectNoteFailsCleanly(t *testing.T) {
	for _, blank := range []string{" ", "\t\n", "  \t \n "} {
		t.Run(strings.NewReplacer(" ", "s", "\t", "t", "\n", "n").Replace(blank), func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			id := auditOneReport(t, bin, work, store)
			badID, mutated := blankOutArchivedDefectNote(t, store, id, "rule-defect", blank)

			stdout, stderr, code := runCLIReport(t, bin, store, badID)
			assertBlankNoteFailure(t, stdout, stderr, code, badID, "rule-defect")
			for _, marker := range []string{`"reportId"`, `"rules"`, `"findings"`, contractsentinel.StatusDefect} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a report fragment %q:\n%s", marker, stdout)
				}
			}

			// 归档必须原样保留，不被自动修补、删除或补写自动证据。
			kept, err := os.ReadFile(filepath.Join(store, badID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(kept, mutated) {
				t.Fatalf("failed report read must leave the corrupt archive untouched:\n%s", kept)
			}
		})
	}
}

// --- diff：任一侧归档带空白缺陷说明都整体失败，不输出比较分类或统计 ---

func TestCLIDiffBlankDefectNoteEitherSideFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	goodID := auditOneReport(t, bin, work, store)
	// 第二份合法报告：同产物、同规则，但缺陷说明不同，标识不同。
	otherWork := t.TempDir()
	hash := mixedArtifactHash(t)
	otherIn := mixedCheckInput(hash)
	for i := range otherIn.Checks {
		if otherIn.Checks[i].RuleID == "rule-defect" {
			otherIn.Checks[i].Note = "另一个反例：第二行"
		}
	}
	otherInput := writeStructInput(t, otherWork, "other.json", otherIn)
	otherStdout, otherStderr, otherCode := runCLIAudit(t, bin, otherInput, store)
	if otherCode != 0 {
		t.Fatalf("setup audit of the second report must succeed: %s", otherStderr)
	}
	cleanID := decodeReport(t, otherStdout).ReportID

	badID, mutated := blankOutArchivedDefectNote(t, store, cleanID, "rule-defect", " \t\n")

	for _, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"second report corrupt", goodID, badID},
		{"first report corrupt", badID, goodID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCLIDiff(t, bin, store, tc.before, tc.after)
			if code == 0 {
				t.Fatal("diff must exit non-zero when a side carries a blank defect note")
			}
			if !strings.Contains(stderr, badID) || !strings.Contains(stderr, "rule-defect") ||
				!strings.Contains(stderr, "blank note") {
				t.Fatalf("stderr must name the corrupt report, the rule and the blank note:\n%s", stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
			}
			for _, marker := range []string{`"results"`, `"summary"`, contractsentinel.ChangeNoChange, contractsentinel.ChangeNoteChanged} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a partial diff %q:\n%s", marker, stdout)
				}
			}
		})
	}

	kept, err := os.ReadFile(filepath.Join(store, badID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, mutated) {
		t.Fatal("failed diff must leave the corrupt archive untouched")
	}
}

// --- 布尔不变式报告保留原有证据形式：无说明缺陷报告正常读回 ---

func TestCLIReportBooleanOnlyDefectReadsBack(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", validInvariantInput)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("boolean-only audit must succeed: %s", stderr)
	}
	report := decodeReport(t, stdout)
	if len(report.Rules) != 1 || report.Rules[0].Note != "" {
		t.Fatalf("boolean-only defect rule must carry no note: %+v", report.Rules)
	}

	readStdout, readStderr, readCode := runCLIReport(t, bin, store, report.ReportID)
	if readCode != 0 {
		t.Fatalf("boolean-only report must read back: %s", readStderr)
	}
	loaded := decodeReport(t, readStdout)
	if len(loaded.Findings) != 1 ||
		loaded.Findings[0].Evidence != "invariant balance-monotonic does not hold" {
		t.Fatalf("boolean-only evidence form must be preserved: %+v", loaded.Findings)
	}
	if loaded.Rules[0].Status != contractsentinel.StatusDefect || loaded.Rules[0].Note != "" {
		t.Fatalf("boolean-only rule must stay a note-less defect: %+v", loaded.Rules[0])
	}
}
