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
// “发现缺陷”规则说明的校验：一条缺陷规则的 note 是非空字符串、却完全由
// 空格、制表符或换行组成，对应 finding 的 evidence 也保存同样的空白时，
// 即使产物哈希、规则版本、其他绑定和重算的报告标识全部吻合，report 也必须
// 非零退出、原因进 stderr（点名请求的报告标识、所属规则和空白缺陷说明），
// stdout 不出现报告片段，原归档原样保留；diff 的任一侧遇到同样的归档必须
// 整体失败，不输出比较分类或统计。省略 note 与显式空字符串配合自动证据的
// 布尔型报告继续正常读回，含中文、换行和前后空格的合法说明逐字保留。

// blankNoteArchive rewrites the archived report named by id into one whose
// rule-defect note and its finding evidence both equal blank, recomputes the
// content id and stores the corrupt variant under that new id, leaving the
// original archive untouched. The returned archive has an id matching its
// (corrupt) content exactly, so rejection can only come from the blank-note
// judgement, not from an id/content mismatch.
func blankNoteArchive(t *testing.T, store, id, blank string) (string, []byte) {
	t.Helper()
	return blankNoteArchiveRule(t, store, id, "rule-defect", blank)
}

// blankNoteCLIError asserts the full CLI failure contract for a whitespace-only
// defect note: the requested report id, the offending rule and the blank-note
// reason all reach stderr, nothing reaches stdout. The archive-corruption
// classification itself is asserted against the errCorrupt type at the package
// level; the validateReport-family messages here read like the other rule
// binding errors ("report <id> rule <rule> …").
func blankNoteCLIError(t *testing.T, stdout, stderr string, code int, id, rule string) {
	t.Helper()
	if code == 0 {
		t.Fatal("an archive with a whitespace-only defect note must exit non-zero")
	}
	for _, want := range []string{id, rule, "blank defect note"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must contain %q:\n%s", want, stderr)
		}
	}
	if stdout != "" {
		t.Fatalf("rejected read must print nothing to stdout, got:\n%s", stdout)
	}
}

// --- report：各种纯空白 note 都使整份归档损坏，且不能只返回其余规则 ---

func TestCLIReportBlankDefectNoteRejected(t *testing.T) {
	for name, blank := range map[string]string{
		"spaces":   "   ",
		"tab":      "\t",
		"newlines": "\n\r\n",
		"mixed":    " \t \n ",
	} {
		t.Run(name, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			origin := auditOneReport(t, bin, work, store)
			corruptID, mutated := blankNoteArchive(t, store, origin, blank)

			stdout, stderr, code := runCLIReport(t, bin, store, corruptID)
			blankNoteCLIError(t, stdout, stderr, code, corruptID, "rule-defect")
			for _, marker := range []string{`"reportId"`, `"rules"`, `"findings"`, "发现缺陷", "rule-pass", "rule-unchecked"} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a report fragment %q:\n%s", marker, stdout)
				}
			}

			// 原归档保持原样：失败读取不删除、不修复、不留临时文件。
			kept, err := os.ReadFile(filepath.Join(store, corruptID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(kept, mutated) {
				t.Fatal("failed report read must leave the corrupt archive untouched")
			}
		})
	}
}

// --- report：合法说明（中文、换行、前后空格）逐字保留，读回不被误拒 ---

func TestCLIReportLegalNoteWithWhitespaceReadsBack(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("the legal mixed report must read back: %s", stderr)
	}
	// 缺陷证据逐字保留：前导空格、换行（JSON 中转义为 \n）、尾随空格都在。
	if !strings.Contains(stdout, `  反例：攻击者可在 withdraw 中重入\n  第二行证据  `) {
		t.Fatalf("the checker note with CJK text, newline and padding must survive verbatim:\n%s", stdout)
	}
}

// --- report：只提交不变式 false 的布尔型报告没有 note，证据为自动模板，照常读回 ---

func TestCLIReportBooleanOnlyDefectReadsBack(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	input := writeInput(t, work, "in.json", validInvariantInput)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("boolean-only audit must succeed: %s", stderr)
	}
	id := decodeReport(t, stdout).ReportID

	readStdout, readStderr, readCode := runCLIReport(t, bin, store, id)
	if readCode != 0 {
		t.Fatalf("boolean-only defect report must read back: %s", readStderr)
	}
	if !strings.Contains(readStdout, "invariant balance-monotonic does not hold") {
		t.Fatalf("auto-generated invariant evidence must be preserved:\n%s", readStdout)
	}
	if strings.Contains(readStdout, `"note"`) {
		t.Fatalf("a boolean-only defect rule must carry no note member:\n%s", readStdout)
	}
}

// --- diff：任一侧归档含纯空白缺陷说明，比较前整体失败 ---

func TestCLIDiffBlankDefectNoteEitherSideFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	rules := diffRules()
	beforeReport := auditDiffReport(t, bin, work, store, "before.json", artifact, rules, diffBeforeChecks(hash))
	afterReport := auditDiffReport(t, bin, work, store, "after.json", artifact, rules, diffAfterChecks(hash))

	// 两侧各造一份“标识与内容相符”的空白说明归档（d-stable-defect 在两侧
	// 都是稳定缺陷），原始合法归档字节留作保留断言。
	corruptSide := func(id string) (string, []byte) {
		return blankNoteArchiveRule(t, store, id, "d-stable-defect", " \n\t ")
	}
	corruptBefore, mutatedBefore := corruptSide(beforeReport.ReportID)
	corruptAfter, mutatedAfter := corruptSide(afterReport.ReportID)

	cases := []struct {
		name   string
		before string
		after  string
	}{
		{"second report corrupt", beforeReport.ReportID, corruptAfter},
		{"first report corrupt", corruptBefore, afterReport.ReportID},
		{"both corrupt", corruptBefore, corruptAfter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCLIDiff(t, bin, store, tc.before, tc.after)
			if code == 0 {
				t.Fatal("diff must exit non-zero against a blank-note archive")
			}
			if !strings.Contains(stderr, "d-stable-defect") || !strings.Contains(stderr, "blank defect note") {
				t.Fatalf("stderr must name the rule and the blank-note reason:\n%s", stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout must be empty on failure, got:\n%s", stdout)
			}
			for _, marker := range []string{`"results"`, `"summary"`, "新发现缺陷", "已消除缺陷", "无变化", "检查说明变化"} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak a comparison fragment %q:\n%s", marker, stdout)
				}
			}
			// 失败的比较不修复、不改写任何一侧的损坏归档。
			for side, mutated := range map[string][]byte{corruptBefore: mutatedBefore, corruptAfter: mutatedAfter} {
				kept, err := os.ReadFile(filepath.Join(store, side+".json"))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(kept, mutated) {
					t.Fatalf("failed diff must leave corrupt archive %s untouched", side)
				}
			}
		})
	}

	// 两份合法归档恢复后比较成功，分类与统计不受本次校验影响。
	stdout, stderr, code := runCLIDiff(t, bin, store, beforeReport.ReportID, afterReport.ReportID)
	if code != 0 {
		t.Fatalf("the legal reports must still diff successfully: %s", stderr)
	}
	if !strings.Contains(stdout, `"results"`) || !strings.Contains(stdout, `"summary"`) {
		t.Fatalf("restored diff must print the full comparison:\n%s", stdout)
	}
}

// blankNoteArchiveRule blanks the note and finding evidence of ruleID in the
// archive id, recomputes the content id and writes the corrupt variant as an
// additional archive under the new id, leaving the original file untouched.
// It returns the new content-matching id and the archived bytes.
func blankNoteArchiveRule(t *testing.T, store, id, ruleID, blank string) (string, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(store, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored contractsentinel.Report
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	for i := range stored.Rules {
		if stored.Rules[i].ID == ruleID {
			stored.Rules[i].Note = blank
		}
	}
	for i := range stored.Findings {
		if stored.Findings[i].RuleID == ruleID {
			stored.Findings[i].Evidence = blank
		}
	}
	stored.ReportID = contractsentinel.ReportID(stored)
	out, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	newID := stored.ReportID
	if err := os.WriteFile(filepath.Join(store, newID+".json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	return newID, out
}
