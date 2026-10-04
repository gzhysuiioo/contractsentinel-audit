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
// “requiresABI 非布尔值”的拒绝：归档中任何规则的正式 requiresABI 成员一旦
// 在场却写成 null（或字符串、数字、对象、数组），即使重算后 reportId、
// 产物哈希、规则状态与缺陷证据都与解码内容吻合，整份归档也必须判为损坏
// ——非零退出、原因进 stderr（含报告标识、出错规则与“必须是布尔值”），
// stdout 不出现任何报告/比较片段，原归档原样保留，不被自动修补。省略
// requiresABI 与合法 true/false 的读回行为保持不变。

// corruptRequiresABIArchive replaces the requiresABI literal of ruleID in the
// pristine archive src with the raw JSON token, recomputes the reportId from
// the content the token would be laundered to (every non-bool decodes as the
// zero value false), writes the result under the new id and returns that id.
// ReportId, artifact hash, statuses and finding evidence therefore all match
// the on-disk content; only the requiresABI type is illegal.
func corruptRequiresABIArchive(t *testing.T, store, ruleID, token string, src []byte) string {
	t.Helper()
	var report contractsentinel.Report
	if err := json.Unmarshal(src, &report); err != nil {
		t.Fatal(err)
	}
	id := report.ReportID
	literal := "false"
	var invariant string
	for _, rl := range report.Rules {
		if rl.ID == ruleID {
			invariant = rl.Invariant
			if rl.RequiresABI {
				literal = "true"
			}
		}
	}
	if invariant == "" {
		t.Fatalf("test setup: rule %s not found in report %s", ruleID, id)
	}
	old := `"invariant":"` + invariant + `","requiresABI":` + literal
	doc := string(src)
	if !strings.Contains(doc, old) {
		t.Fatalf("test setup: archive does not contain %q", old)
	}
	doc = strings.Replace(doc, old,
		`"invariant":"`+invariant+`","requiresABI":`+token, 1)

	// Compute the id the illegal token would be laundered to: normalize every
	// non-boolean formal requiresABI back to false before hashing.
	var generic map[string]any
	if err := json.Unmarshal([]byte(doc), &generic); err != nil {
		t.Fatal(err)
	}
	if rules, ok := generic["rules"].([]any); ok {
		for _, e := range rules {
			rule, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if v, present := rule["requiresABI"]; present {
				if _, isBool := v.(bool); !isBool {
					rule["requiresABI"] = false
				}
			}
		}
	}
	normalized, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	var decoded contractsentinel.Report
	if err := json.Unmarshal(normalized, &decoded); err != nil {
		t.Fatal(err)
	}
	newID := contractsentinel.ReportID(decoded)
	doc = strings.Replace(doc, `"reportId":"`+id+`"`, `"reportId":"`+newID+`"`, 1)
	if err := os.WriteFile(filepath.Join(store, newID+".json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return newID
}

// assertRequiresABICorruptFailure checks the full process-level failure
// contract for a non-boolean requiresABI archive.
func assertRequiresABICorruptFailure(t *testing.T, stdout, stderr string, code int, id, rule string) {
	t.Helper()
	if code == 0 {
		t.Fatal("a non-boolean requiresABI archive must make the command exit non-zero")
	}
	for _, want := range []string{"corrupt", id, rule, "requiresABI must be a boolean"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must contain %q:\n%s", want, stderr)
		}
	}
	if stdout != "" {
		t.Fatalf("stdout must not contain any report fragment:\n%s", stdout)
	}
}

// --- report：null requiresABI，无论规则是缺陷、通过还是工具缺失，都判损坏 ---

func TestCLIReportNullRequiresABIFailsCleanly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ruleID string
	}{
		{"defect rule", "rule-defect"},
		{"passing rule", "rule-pass"},
		{"tool-missing rule", "rule-tool"},
		{"unchecked rule", "rule-unchecked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			originID := auditOneReport(t, bin, work, store)
			originPath := filepath.Join(store, originID+".json")
			pristine, err := os.ReadFile(originPath)
			if err != nil {
				t.Fatal(err)
			}
			id := corruptRequiresABIArchive(t, store, tc.ruleID, "null", pristine)
			path := filepath.Join(store, id+".json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertRequiresABICorruptFailure(t, stdout, stderr, code, id, tc.ruleID)

			// stdout 不得夹带任何报告字段。
			for _, marker := range []string{"reportId", `"rules"`, `"findings"`,
				contractsentinel.StatusDefect, contractsentinel.StatusPass} {
				if strings.Contains(stdout, marker) {
					t.Fatalf("stdout must not leak %q:\n%s", marker, stdout)
				}
			}
			// 原归档原样保留，不被自动修补成 false。
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) || !strings.Contains(string(after), `"requiresABI":null`) {
				t.Fatal("failed report read must leave the null requiresABI archive untouched")
			}
		})
	}
}

// --- report：字符串、数字、对象、数组与 null 一样判损坏，且不转成默认值 ---

func TestCLIReportNonBooleanRequiresABIFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	originID := auditOneReport(t, bin, work, store)
	pristine, err := os.ReadFile(filepath.Join(store, originID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{`"false"`, `0`, `1`, `{}`, `[true]`} {
		t.Run(token, func(t *testing.T) {
			// Every non-bool launders to false, so the recomputed id equals the
			// origin id: restore the pristine archive before corrupting it.
			if err := os.WriteFile(filepath.Join(store, originID+".json"), pristine, 0o644); err != nil {
				t.Fatal(err)
			}
			id := corruptRequiresABIArchive(t, store, "rule-pass", token, pristine)
			stdout, stderr, code := runCLIReport(t, bin, store, id)
			assertRequiresABICorruptFailure(t, stdout, stderr, code, id, "rule-pass")
		})
	}
}

// --- report：原本为 true 的规则被改成 null 同样判损坏 ---

func TestCLIReportNullReplacingTrueRequiresABIFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	originID := auditOneReport(t, bin, work, store)
	pristine, err := os.ReadFile(filepath.Join(store, originID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	// rule-tool 在 mixedCheckRules 中 requiresABI 为 true。
	id := corruptRequiresABIArchive(t, store, "rule-tool", "null", pristine)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	assertRequiresABICorruptFailure(t, stdout, stderr, code, id, "rule-tool")
}

// --- report：合法归档读回不受影响，true/false 原样呈现 ---

func TestCLIReportLegalRequiresABIReadbackUnchanged(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	id := auditOneReport(t, bin, work, store)

	stdout, stderr, code := runCLIReport(t, bin, store, id)
	if code != 0 {
		t.Fatalf("a legal report must read back: %s", stderr)
	}
	var report contractsentinel.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("readback output must be a report: %v\n%s", err, stdout)
	}
	abiByRule := map[string]bool{}
	for _, rl := range report.Rules {
		abiByRule[rl.ID] = rl.RequiresABI
	}
	if !abiByRule["rule-tool"] {
		t.Fatal("rule-tool requiresABI=true must read back as true")
	}
	if abiByRule["rule-pass"] {
		t.Fatal("rule-pass requiresABI=false must read back as false")
	}
}

// --- diff：任一侧归档含 null requiresABI 都在输出比较结果前失败 ---

func TestCLIDiffBadRequiresABIEitherSideFailsCleanly(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	hash := mixedArtifactHash(t)
	artifact := mixedCheckArtifact()
	beforeReport := auditDiffReport(t, bin, work, store, "before.json", artifact, diffRules(), diffBeforeChecks(hash))
	afterReport := auditDiffReport(t, bin, work, store, "after.json", artifact, diffRules(), diffAfterChecks(hash))
	beforeID, afterID := beforeReport.ReportID, afterReport.ReportID

	// 用独立干净存储保存两侧原文件，便于恢复损坏的一侧。
	cleanBefore := mustMarshalStoreReport(t, bin, filepath.Join(work, "clean-b"), "before.json", artifact, hash, "before")
	cleanAfter := mustMarshalStoreReport(t, bin, filepath.Join(work, "clean-a"), "after.json", artifact, hash, "after")

	corruptSide := func(side string) string {
		t.Helper()
		if side == "after" {
			return corruptRequiresABIArchive(t, store, "a-resolved", "null", cleanAfter)
		}
		return corruptRequiresABIArchive(t, store, "a-resolved", "null", cleanBefore)
	}

	// 第二份损坏。
	corruptAfter := corruptSide("after")
	stdout, stderr, code := runCLIDiff(t, bin, store, beforeID, corruptAfter)
	assertRequiresABICorruptFailure(t, stdout, stderr, code, corruptAfter, "a-resolved")
	for _, marker := range []string{`"results"`, `"summary"`,
		contractsentinel.ChangeNewDefect, contractsentinel.ChangeNoChange, contractsentinel.StatusUnchecked} {
		if strings.Contains(stdout, marker) {
			t.Fatalf("stdout must not leak a partial diff %q:\n%s", marker, stdout)
		}
	}

	// 第一份损坏、第二份恢复。
	if err := os.WriteFile(filepath.Join(store, afterID+".json"), cleanAfter, 0o644); err != nil {
		t.Fatal(err)
	}
	corruptBefore := corruptSide("before")
	stdout, stderr, code = runCLIDiff(t, bin, store, corruptBefore, afterID)
	assertRequiresABICorruptFailure(t, stdout, stderr, code, corruptBefore, "a-resolved")
	if stdout != "" {
		t.Fatalf("stdout must stay empty on failure:\n%s", stdout)
	}

	// 失败的比较不修复、不覆盖任何一侧归档。
	if kept, err := os.ReadFile(filepath.Join(store, corruptBefore+".json")); err != nil ||
		!strings.Contains(string(kept), `"requiresABI":null`) {
		t.Fatalf("failed diff must leave the corrupt first archive untouched: %v", err)
	}
	if kept, err := os.ReadFile(filepath.Join(store, afterID+".json")); err != nil || !bytes.Equal(kept, cleanAfter) {
		t.Fatalf("failed diff must leave the restored second archive untouched: %v", err)
	}

	// 两侧恢复合法后比较照常成功：坏值从未被默认成 false 后参与“规则变化/
	// 无变化”的判断。
	if err := os.WriteFile(filepath.Join(store, beforeID+".json"), cleanBefore, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLIDiff(t, bin, store, beforeID, afterID)
	if code != 0 {
		t.Fatalf("restored archives must diff successfully: %s", stderr)
	}
	d := decodeDiff(t, stdout)
	if d.Summary.NoChange != 2 || d.Summary.NewDefects != 1 {
		t.Fatalf("legal diff must show the original outcomes: %+v", d.Summary)
	}
}
