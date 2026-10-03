package contractsentinel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 本文件围绕读取入口 LoadReport 锁定“规则结论 ↔ 缺陷记录”的对应关系：
// 合法报告中每条“发现缺陷”规则恰好对应一条记录；损坏该关系的归档即使
// 报告 id 与归档内容相符（重算 id 后写盘），也必须被当作损坏归档拒绝，
// 而不是靠 id 不匹配才被发现。
//
// 关键手法：storeAndCorrupt 先写出一份 id 与内容完全相符的合法归档，再
// 修改字段并重新计算 id、改名为新文件写回，因此 LoadReport 的拒绝只能
// 来自 validateReport 的关系校验，不来自 ReportID(r) != r.ReportID 这一关。

// writeReportWithFreshID marshals r after recomputing its content id, so the
// archive on disk has an id matching its content. It returns that id.
func writeReportWithFreshID(t *testing.T, dir string, r Report) string {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, r.ReportID+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return r.ReportID
}

// oneDefectFixture is a hand-built but legal report with three conclusions:
// one pass, one defect (with a checker note) and one unchecked, plus the single
// finding that belongs to the defect rule.
func oneDefectFixture() Report {
	return Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: ArtifactHash(sampleArtifact())},
		Rules: []ReportRule{
			{ID: "r-pass", Kind: "static", Severity: "medium", Invariant: "inv-pass", Version: "1", Status: StatusPass},
			{ID: "r-bad", Kind: "static", Severity: "high", Invariant: "inv-bad", Version: "2", Status: StatusDefect, Note: "counterexample: x"},
			{ID: "r-none", Kind: "symbolic", Severity: "low", Invariant: "inv-none", Version: "3", Status: StatusUnchecked},
		},
		Findings: []ReportFinding{
			{ArtifactHash: ArtifactHash(sampleArtifact()), RuleID: "r-bad", Version: "2", Severity: "high", Invariant: "inv-bad", Evidence: "counterexample: x"},
		},
	}
}

// otherHash returns a structurally valid 64-hex hash that differs from h.
func otherHash(h string) string {
	if strings.HasPrefix(h, "0") {
		return strings.Repeat("a", 64)
	}
	return "0" + h[1:]
}

// storeAndCorrupt writes r with a fresh matching id, decodes it back, applies
// mutate, recomputes the id and rewrites the archive under the new id. The
// returned archive has an id that matches its (now corrupt) content exactly.
func storeAndCorrupt(t *testing.T, dir string, r Report, mutate func(*Report)) string {
	t.Helper()
	id := writeReportWithFreshID(t, dir, r)
	path := filepath.Join(dir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored Report
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	mutate(&stored)
	stored.ReportID = ReportID(stored)
	out, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stored.ReportID+".json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	return stored.ReportID
}

// expectCorruptLoad loads id and asserts the read is rejected as a corrupt
// archive: errCorrupt (not errInvalid/errNotFound), no report returned, and the
// message names the involved rule.
func expectCorruptLoad(t *testing.T, dir, id, rule string) {
	t.Helper()
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("expected corrupt rejection, load succeeded: %+v", got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T: %v", err, err)
	}
	if rule != "" && !strings.Contains(err.Error(), rule) {
		t.Fatalf("error must name involved rule %q: %v", rule, err)
	}
}

// --- 合法读取：完整保留审计时的归属信息，不重新计算 ---

func TestLoadReportPreservesFindingBinding(t *testing.T) {
	dir := t.TempDir()
	report := oneDefectFixture()
	id := writeReportWithFreshID(t, dir, report)

	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("legal report must load: %v", err)
	}
	if loaded.ReportID != id || loaded.Artifact != report.Artifact {
		t.Fatalf("report header not preserved: %+v", loaded)
	}
	if len(loaded.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(loaded.Findings))
	}
	// 记录中的产物哈希、规则版本、严重级别、不变式和证据必须原样保留。
	if f := loaded.Findings[0]; f != report.Findings[0] {
		t.Fatalf("finding not preserved:\n got %+v\nwant %+v", f, report.Findings[0])
	}
	statusByID := map[string]string{}
	for _, rl := range loaded.Rules {
		statusByID[rl.ID] = rl.Status
	}
	if statusByID["r-bad"] != StatusDefect || statusByID["r-pass"] != StatusPass || statusByID["r-none"] != StatusUnchecked {
		t.Fatalf("rule conclusions not preserved: %+v", statusByID)
	}
}

// 同一报告里两条规则检查同一不变式，仍是两个独立归属：一条通过、另一条
// 发现缺陷时，缺陷只能属于后者，不能按不变式名合并或转移。
func TestLoadReportSharedInvariantSeparateAttribution(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "shared-inv", Version: "1", Status: StatusPass},
			{ID: "r2", Kind: "static", Severity: "low", Invariant: "shared-inv", Version: "1", Status: StatusDefect, Note: "counterexample: shared"},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r2", Version: "1", Severity: "low", Invariant: "shared-inv", Evidence: "counterexample: shared"},
		},
	}
	id := writeReportWithFreshID(t, dir, report)

	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("legal shared-invariant report must load: %v", err)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].RuleID != "r2" {
		t.Fatalf("defect must belong to r2 only: %+v", loaded.Findings)
	}
	if loaded.Findings[0].Severity != "low" {
		t.Fatalf("finding must carry r2's severity, not r1's: %+v", loaded.Findings[0])
	}
}

// 规则保留检查说明时，缺陷证据应与原说明一致。
func TestLoadReportCheckNoteEvidencePreserved(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	note := "counterexample: path A->B->A"
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect, Note: note},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: note},
		},
	}
	id := writeReportWithFreshID(t, dir, report)
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("report with checker note must load: %v", err)
	}
	if got := loaded.Findings[0].Evidence; got != note {
		t.Fatalf("evidence = %q, want the original checker note %q", got, note)
	}
}

// 由布尔不变式结果生成、没有检查说明的缺陷，保留现有自动生成证据。
func TestLoadReportAutoGeneratedEvidencePreserved(t *testing.T) {
	dir := t.TempDir()
	built, err := BuildReport(sampleArtifact(), []Rule{
		{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"},
	}, map[string]bool{"inv": false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, built); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, built.ReportID)
	if err != nil {
		t.Fatalf("boolean-only report must load: %v", err)
	}
	if len(loaded.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(loaded.Findings))
	}
	want := "invariant inv does not hold"
	if got := loaded.Findings[0].Evidence; got != want {
		t.Fatalf("evidence = %q, want auto-generated %q", got, want)
	}
	if n := loaded.Rules[0].Note; n != "" {
		t.Fatalf("boolean-only rule must carry no note, got %q", n)
	}
}

// 布尔型合法报告以“重算 id 写盘”的方式读取也必须成功（与 SaveReport 路径
// 无关），证明无说明报告的自动证据规则在读取侧同样被接受。
func TestLoadReportAutogenEvidenceAcceptedWithFreshID(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: "invariant inv does not hold"},
		},
	}
	id := writeReportWithFreshID(t, dir, report)
	if _, err := LoadReport(dir, id); err != nil {
		t.Fatalf("legal autogen-evidence report must load: %v", err)
	}
}

// --- 损坏归属：同一条缺陷被重复列出 ---

func TestLoadReportRejectsDuplicateFinding(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings = append(stored.Findings, stored.Findings[0])
	})
	expectCorruptLoad(t, dir, id, "r-bad")
}

// --- 损坏归属：缺陷引用不存在的规则 ---

func TestLoadReportRejectsFindingForUnknownRule(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		// Point the finding at a rule that does not exist, and make every other
		// field self-consistent (autogen evidence matching its own invariant),
		// so the ONLY illegality is the dangling rule id. r-bad becomes a
		// finding-less pass.
		stored.Findings[0].RuleID = "ghost"
		stored.Findings[0].Invariant = "ghost-inv"
		stored.Findings[0].Evidence = "invariant ghost-inv does not hold"
		for i := range stored.Rules {
			if stored.Rules[i].ID == "r-bad" {
				stored.Rules[i].Status = StatusPass
				stored.Rules[i].Note = ""
			}
		}
	})
	expectCorruptLoad(t, dir, id, "ghost")
}

// --- 损坏归属：缺陷引用状态不是“发现缺陷”的规则 ---

func TestLoadReportRejectsFindingForPassingRule(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		// Retarget the finding onto r-pass and make every finding field
		// consistent with that passing rule, so ONLY the fact that its status
		// is 通过 (not 发现缺陷) can reject the archive. r-bad becomes a
		// finding-less pass.
		stored.Findings[0].RuleID = "r-pass"
		stored.Findings[0].Version = "1"
		stored.Findings[0].Severity = "medium"
		stored.Findings[0].Invariant = "inv-pass"
		stored.Findings[0].Evidence = "invariant inv-pass does not hold"
		for i := range stored.Rules {
			if stored.Rules[i].ID == "r-bad" {
				stored.Rules[i].Status = StatusPass
				stored.Rules[i].Note = ""
			}
		}
	})
	expectCorruptLoad(t, dir, id, "r-pass")
}

func TestLoadReportRejectsFindingForUncheckedRule(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		// Same isolation for an unchecked rule: every field matches r-none,
		// only its 未检查 status makes the attribution illegal.
		stored.Findings[0].RuleID = "r-none"
		stored.Findings[0].Version = "3"
		stored.Findings[0].Severity = "low"
		stored.Findings[0].Invariant = "inv-none"
		stored.Findings[0].Evidence = "invariant inv-none does not hold"
		for i := range stored.Rules {
			if stored.Rules[i].ID == "r-bad" {
				stored.Rules[i].Status = StatusPass
				stored.Rules[i].Note = ""
			}
		}
	})
	expectCorruptLoad(t, dir, id, "r-none")
}

// --- 损坏归属：规则声明发现缺陷却没有对应记录 ---

func TestLoadReportRejectsDefectWithoutFinding(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings = nil
	})
	expectCorruptLoad(t, dir, id, "r-bad")
}

// --- 损坏归属：缺陷引用正确规则但绑定其他产物 ---

func TestLoadReportRejectsFindingWrongArtifactHash(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings[0].ArtifactHash = otherHash(stored.Artifact.Hash)
	})
	expectCorruptLoad(t, dir, id, "r-bad")
}

// --- 损坏归属：携带与规则不一致的版本/严重级别/不变式 ---

func TestLoadReportRejectsFindingVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings[0].Version = "9.9.9"
	})
	expectCorruptLoad(t, dir, id, "r-bad")
}

func TestLoadReportRejectsFindingSeverityMismatch(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings[0].Severity = "critical"
	})
	expectCorruptLoad(t, dir, id, "r-bad")
}

func TestLoadReportRejectsFindingInvariantMismatch(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings[0].Invariant = "other-inv"
	})
	expectCorruptLoad(t, dir, id, "r-bad")
}

// --- 损坏归属：证据与规则说明 / 自动生成规则不一致 ---

// 有检查说明的报告，证据必须与说明一致。
func TestLoadReportRejectsEvidenceNotMatchingNote(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings[0].Evidence = "different counterexample"
	})
	expectCorruptLoad(t, dir, id, "r-bad")
}

// 有说明的规则，证据被替换成自动生成模板也不合法。
func TestLoadReportRejectsNoteStyleReportCarryingAutogenEvidence(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings[0].Evidence = "invariant inv-bad does not hold"
	})
	expectCorruptLoad(t, dir, id, "r-bad")
}

// 没有检查说明的布尔型报告，证据必须等于自动生成值。
func TestLoadReportRejectsEvidenceNotMatchingAutogen(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: "invariant inv does not hold"},
		},
	}
	id := storeAndCorrupt(t, dir, report, func(stored *Report) {
		stored.Findings[0].Evidence = "hand-written claim"
	})
	expectCorruptLoad(t, dir, id, "r1")
}

// 布尔型报告把自动证据里的不变式名写错，同样拒绝。
func TestLoadReportRejectsAutogenEvidenceWrongInvariant(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1", Status: StatusDefect},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv", Evidence: "invariant inv does not hold"},
		},
	}
	id := storeAndCorrupt(t, dir, report, func(stored *Report) {
		stored.Findings[0].Evidence = "invariant other-inv does not hold"
	})
	expectCorruptLoad(t, dir, id, "r1")
}

// --- 关键保障：拒绝发生时 id 仍与内容相符，不依赖标识不匹配 ---

func TestLoadReportCorruptDespiteMatchingID(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings = nil // defect rule with no finding
	})
	// 直接验证：归档内 reportId、请求 id、重算内容 id 三者一致，
	// 排除“靠 id 不匹配才发现问题”。
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk Report
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.ReportID != id || ReportID(onDisk) != id {
		t.Fatalf("test setup: id must match corrupt content, onDisk=%q recomputed=%q requested=%q", onDisk.ReportID, ReportID(onDisk), id)
	}
	expectCorruptLoad(t, dir, id, "r-bad")
}

// --- 拒绝时不返回部分有效报告，也不自动删除/修复归档 ---

func TestLoadReportFailureReturnsNoPartialReport(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings[0].Version = "9.9.9"
	})
	loaded, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("expected rejection, got %+v", loaded)
	}
	if !reflect.DeepEqual(loaded, Report{}) {
		t.Fatalf("failed read must return the zero report, got %+v", loaded)
	}
}

func TestLoadReportDoesNotDeleteOrRepairCorruptArchive(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings = append(stored.Findings, stored.Findings[0])
	})
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := LoadReport(dir, id); err == nil {
			t.Fatal("expected corrupt rejection on repeated reads")
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must not be deleted: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed read must not rewrite or repair the archive")
	}
}

// 成功读取同样不得改写归档。
func TestLoadReportSuccessDoesNotModifyArchive(t *testing.T) {
	dir := t.TempDir()
	id := writeReportWithFreshID(t, dir, oneDefectFixture())
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(dir, id); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("successful read must not rewrite the archive")
	}
}

// 损坏拒绝不得创建任何额外的存储文件（读取路径只读）。
func TestLoadReportFailureCreatesNoFiles(t *testing.T) {
	dir := t.TempDir()
	id := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings[0].Invariant = "other-inv"
	})
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(dir, id); err == nil {
		t.Fatal("expected corrupt rejection")
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("failed read changed file count: %d -> %d", len(before), len(after))
	}
}

// --- 错误三分类：损坏 ≠ 不存在 ≠ 请求标识不合法 ---

func TestLoadReportErrorClassificationDistinct(t *testing.T) {
	dir := t.TempDir()

	// 1) 损坏归档
	corruptID := storeAndCorrupt(t, dir, oneDefectFixture(), func(stored *Report) {
		stored.Findings = nil
	})
	if _, err := LoadReport(dir, corruptID); err == nil {
		t.Fatal("expected corrupt error")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("corrupt archive -> expected errCorrupt, got %T: %v", err, err)
		}
	}

	// 2) 报告不存在（标识合法但无文件）
	missing := strings.Repeat("0", 64)
	if _, err := LoadReport(dir, missing); err == nil {
		t.Fatal("expected not found error")
	} else {
		var enf errNotFound
		if !errors.As(err, &enf) {
			t.Fatalf("missing report -> expected errNotFound, got %T: %v", err, err)
		}
	}

	// 3) 请求标识不合法（根本不进存储查找）
	for _, bad := range []string{"", "xyz", strings.Repeat("G", 64), strings.Repeat("0", 63)} {
		if _, err := LoadReport(dir, bad); err == nil {
			t.Fatalf("id %q: expected error", bad)
		} else {
			var ei errInvalid
			if !errors.As(err, &ei) {
				t.Fatalf("id %q: expected errInvalid, got %T: %v", bad, err, err)
			}
		}
	}
}
