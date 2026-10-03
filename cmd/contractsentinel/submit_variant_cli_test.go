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

// 本文件在真实命令行进程边界上回归保护 audit 提交的固定字段大小写规则：检查
// 记录里正式 status 与扩展成员 StAtus 同现时，扩展成员既不能覆盖正式结论，
// 也不能在正式 status 缺失或非法时顶替。合法提交的结论、证据、产物哈希、规
// 则版本与报告标识完全不变；正式 status 缺失/非法时整份拒绝——非零退出、
// 原因进 stderr 且点名对应规则与 status，stdout 不输出完整或部分报告，不创
// 建存储目录、不新增或改写已有报告。最外层、产物、规则层级同理，且不变式名
// 称由用户定义、不属于固定字段。

// spliceDefectCheck marshals the standard mixed submission and rewrites the
// status member of the rule-defect check according to rewrite, returning the
// resulting document text.
func spliceDefectCheck(t *testing.T, hash string, rewrite func(string) string) string {
	t.Helper()
	raw, err := json.MarshalIndent(mixedCheckInput(hash), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	anchor := `"ruleId": "rule-defect"`
	idx := strings.Index(doc, anchor)
	if idx < 0 {
		t.Fatal("test setup: rule-defect check not found")
	}
	statusPair := `"status": "` + contractsentinel.StatusDefect + `"`
	at := strings.Index(doc[idx:], statusPair)
	if at < 0 {
		t.Fatal("test setup: defect status pair not found")
	}
	at += idx
	return doc[:at] + rewrite(statusPair) + doc[at+len(statusPair):]
}

// --- 合法缺陷记录加 StAtus=通过：两种成员顺序都保留缺陷，且报告标识不变 ---

func TestCLIAuditCaseVariantStatusKeepsDefect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rewrite func(string) string
	}{
		{"variant after formal", func(pair string) string {
			return pair + `, "StAtus": "` + contractsentinel.StatusPass + `"`
		}},
		{"variant before formal", func(pair string) string {
			return `"StAtus": "` + contractsentinel.StatusPass + `", ` + pair
		}},
		{"variant carries a number", func(pair string) string {
			return pair + `, "StAtus": 123`
		}},
		{"whitespace-padded variant", func(pair string) string {
			return `" status ": "` + contractsentinel.StatusPass + `", ` + pair
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			hash := mixedArtifactHash(t)
			store := filepath.Join(work, "reports")

			// 基准：不带任何扩展成员的同一提交。
			baseInput := writeStructInput(t, work, "base.json", mixedCheckInput(hash))
			baseOut, baseErr, baseCode := runCLIAudit(t, bin, baseInput, store)
			if baseCode != 0 {
				t.Fatalf("baseline audit must succeed: %s", baseErr)
			}
			baseID := decodeReport(t, baseOut).ReportID

			// 同一目录、同一提交，仅在缺陷记录里多一个扩展成员。
			input := writeInput(t, work, "in.json", spliceDefectCheck(t, hash, tc.rewrite))
			stdout, stderr, code := runCLIAudit(t, bin, input, store)
			if code != 0 {
				t.Fatalf("extension members must not fail a legal submission: %s", stderr)
			}
			report := decodeReport(t, stdout)
			if report.ReportID != baseID {
				t.Fatalf("extension members changed the report id:\n got %s\nwant %s", report.ReportID, baseID)
			}
			statusByID := map[string]string{}
			for _, r := range report.Rules {
				statusByID[r.ID] = r.Status
			}
			if statusByID["rule-defect"] != contractsentinel.StatusDefect {
				t.Fatalf("rule-defect status = %q, want the formal 发现缺陷", statusByID["rule-defect"])
			}
			if statusByID["rule-pass"] != contractsentinel.StatusPass {
				t.Fatalf("rule-pass status = %q, want 通过", statusByID["rule-pass"])
			}
			if len(report.Findings) != 1 || report.Findings[0].RuleID != "rule-defect" ||
				report.Findings[0].Evidence != defectNote || report.Findings[0].ArtifactHash != hash ||
				report.Findings[0].Version != "2.0.1" {
				t.Fatalf("defect binding altered by extension data: %+v", report.Findings)
			}
			// 同一标识：扩展提交与基准共享一份归档，不新增报告。
			entries, err := listFiles(store)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("extension-only submission must not add a report, got %v", entries)
			}
		})
	}
}

// assertAuditRejected 断言整份拒绝契约：非零退出、stderr 点名规则与 status、
// stdout 无任何报告片段。
func assertAuditRejected(t *testing.T, stdout, stderr string, code int) {
	t.Helper()
	if code == 0 {
		t.Fatal("submission must exit non-zero")
	}
	if !strings.Contains(stderr, "rule-defect") {
		t.Fatalf("stderr must identify the involved rule:\n%s", stderr)
	}
	if !strings.Contains(stderr, "status") {
		t.Fatalf("stderr must point at the formal status field:\n%s", stderr)
	}
	assertNoPartialReport(t, stdout)
}

// --- 缺少正式 status，仅有 StAtus=通过：整份拒绝，不创建存储目录 ---

func TestCLIAuditMissingFormalStatusRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	doc := spliceDefectCheck(t, hash, func(_ string) string {
		return `"StAtus": "` + contractsentinel.StatusPass + `"`
	})
	input := writeInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertAuditRejected(t, stdout, stderr, code)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 正式 status 非法，StAtus=通过 也不能洗白 ---

func TestCLIAuditInvalidFormalStatusRejected(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	hash := mixedArtifactHash(t)
	doc := spliceDefectCheck(t, hash, func(_ string) string {
		return `"status": "bogus", "StAtus": "` + contractsentinel.StatusPass + `"`
	})
	input := writeInput(t, work, "bad.json", doc)
	store := filepath.Join(work, "nested", "missing-store")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	assertAuditRejected(t, stdout, stderr, code)
	if !strings.Contains(stderr, "bogus") {
		t.Fatalf("stderr must name the unsupported formal status:\n%s", stderr)
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("rejected submission must not create the store directory: %v", err)
	}
}

// --- 拒绝提交不新增或改写已有报告 ---

func TestCLIAuditCaseVariantRejectionKeepsExistingReports(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")

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
	existing, err := os.ReadFile(filepath.Join(store, before[0]))
	if err != nil {
		t.Fatal(err)
	}

	bad := writeInput(t, work, "bad.json", spliceDefectCheck(t, mixedArtifactHash(t), func(_ string) string {
		return `"StAtus": "` + contractsentinel.StatusPass + `"`
	}))
	if stdout, stderr, code := runCLIAudit(t, bin, bad, store); code == 0 {
		t.Fatal("submission missing a formal status must fail")
	} else {
		assertNoPartialReport(t, stdout)
		if !strings.Contains(stderr, "rule-defect") {
			t.Fatalf("stderr must name the rule:\n%s", stderr)
		}
	}

	after, err := listFiles(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0] != before[0] {
		t.Fatalf("rejected submission changed the store contents:\nbefore=%v\nafter=%v", before, after)
	}
	kept, err := os.ReadFile(filepath.Join(store, after[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, existing) {
		t.Fatal("rejected submission modified the existing report bytes")
	}
}

// --- 不变式名称由用户定义：Inv 与 inv 独立、空白不修剪；名称两侧带空格的
// 顶层成员仍是扩展信息，不能替代 invariants ---

func TestCLIAuditInvariantNamesUserDefined(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()

	// Inv=false 与 inv=true 是两个独立不变式；" Inv " 保留空白，是第三个。
	doc := `{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [
			{"id":"rule-upper","kind":"static","severity":"high","invariant":"Inv","version":"1"},
			{"id":"rule-lower","kind":"static","severity":"low","invariant":"inv","version":"1"},
			{"id":"rule-padded","kind":"static","severity":"medium","invariant":" Inv ","version":"1"}
		],
		"invariants": {"Inv": false, "inv": true, " Inv ": false}
	}`
	input := writeInput(t, work, "in.json", doc)
	store := filepath.Join(work, "reports")

	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("three user-defined invariants must be accepted: %s", stderr)
	}
	report := decodeReport(t, stdout)
	statusByID := map[string]string{}
	for _, r := range report.Rules {
		statusByID[r.ID] = r.Status
	}
	if statusByID["rule-upper"] != contractsentinel.StatusDefect ||
		statusByID["rule-lower"] != contractsentinel.StatusPass ||
		statusByID["rule-padded"] != contractsentinel.StatusDefect {
		t.Fatalf("Inv/inv/\" Inv \" must be independent conclusions: %+v", statusByID)
	}

	// 用户定义不变式若取非布尔值，仍按布尔规则拒绝，即使名字与固定字段同名。
	bad := `{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [],
		"invariants": {"RULES": 7}
	}`
	badInput := writeInput(t, work, "bad.json", bad)
	badStore := filepath.Join(work, "nested", "missing-store")
	if out, badErr, badCode := runCLIAudit(t, bin, badInput, badStore); badCode == 0 {
		t.Fatal("non-boolean user invariant must be rejected")
	} else {
		assertNoPartialReport(t, out)
		if !strings.Contains(badErr, "RULES") || !strings.Contains(badErr, "boolean") {
			t.Fatalf("stderr must name RULES and require a boolean:\n%s", badErr)
		}
		if _, err := os.Stat(badStore); !os.IsNotExist(err) {
			t.Fatalf("rejected submission must not create the store: %v", err)
		}
	}
}
