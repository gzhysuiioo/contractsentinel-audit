package contractsentinel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件锁定“归档读取”侧固定字段的大小写规则：报告标识、产物信息、每条
// 规则和缺陷记录中已经定义的字段，只认报告 JSON 中原有的大小写写法。
// encoding/json 在精确匹配失败后会退化为大小写不敏感匹配，因此一个名为
// "StAtus" 的扩展成员也会解码进 status 字段：它出现在原字段之后时会覆盖
// 真正的结论，出现在原字段之前时又能用合法值掩盖原字段里的非法值——同
// 一份归档仅因成员位置不同就得到不同读取结果。修正后，这些大小写变体与
// 两侧带空白的名字都只是被忽略的扩展字段，可信内容完全由固定字段决定。

// statusByID 索引读出报告的规则结论。
func statusByID(r Report) map[string]string {
	out := map[string]string{}
	for _, rule := range r.Rules {
		out[rule.ID] = rule.Status
	}
	return out
}

// writeVariantArchiveText marshals a legal report with a fresh matching id,
// applies a textual mutation, then recomputes the report id from the fixed
// fields only and rewrites the reportId member to match. Extension members
// (case variants, unknown fields) stay in the archive text but do not
// influence the id, so any rejection comes from report validation itself,
// never from the id check.
func writeVariantArchiveText(t *testing.T, dir string, r Report, mutate func(string) string) string {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	doc := mutate(string(data))
	if doc == string(data) {
		t.Fatal("test setup: mutation did not change the archive")
	}
	strict, err := strictReportJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(strict, &decoded); err != nil {
		t.Fatal(err)
	}
	newID := ReportID(decoded)
	doc = strings.Replace(doc, `"reportId":"`+r.ReportID+`"`, `"reportId":"`+newID+`"`, 1)
	if err := os.WriteFile(filepath.Join(dir, newID+".json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return newID
}

// --- 核心场景：合法缺陷报告加入 StAtus 扩展字段，两种成员顺序读出同一结论 ---

func TestLoadReportCaseVariantStatusDoesNotOverride(t *testing.T) {
	for _, tc := range []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "variant after fixed field",
			old:  `"status":"` + StatusDefect + `"`,
			new:  `"status":"` + StatusDefect + `","StAtus":"` + StatusPass + `"`,
		},
		{
			name: "variant before fixed field",
			old:  `"status":"` + StatusDefect + `"`,
			new:  `"StAtus":"` + StatusPass + `","status":"` + StatusDefect + `"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := writeDupArchiveText(t, dir, oneDefectFixture(), dupOnce(tc.old, tc.new))

			loaded, err := LoadReport(dir, id)
			if err != nil {
				t.Fatalf("a case-variant extension member must not corrupt the report: %v", err)
			}
			if loaded.ReportID != id {
				t.Fatalf("report id not preserved: %q", loaded.ReportID)
			}
			// 缺陷结论仍由原有 status 决定，不随扩展字段的位置变化。
			if got := statusByID(loaded)["r-bad"]; got != StatusDefect {
				t.Fatalf("r-bad status = %q, want the original %q", got, StatusDefect)
			}
			if got := statusByID(loaded)["r-pass"]; got != StatusPass {
				t.Fatalf("r-pass status = %q, want %q", got, StatusPass)
			}
			// 说明、证据、产物哈希与规则版本原样保留。
			rule := loaded.Rules[1]
			if rule.ID != "r-bad" || rule.Note != "counterexample: x" || rule.Version != "2" {
				t.Fatalf("rule not preserved: %+v", rule)
			}
			if len(loaded.Findings) != 1 {
				t.Fatalf("findings = %d, want 1", len(loaded.Findings))
			}
			f := loaded.Findings[0]
			if f.Evidence != "counterexample: x" || f.ArtifactHash != loaded.Artifact.Hash || f.Version != "2" {
				t.Fatalf("finding not preserved: %+v", f)
			}
		})
	}
}

// --- 原字段写了不支持的状态，不能靠大小写变体提供合法状态来通过校验 ---

func TestLoadReportCaseVariantCannotLaunderInvalidStatus(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"bogus","StAtus":"`+StatusPass+`"`))
	expectCorruptLoad(t, dir, id, "r-pass")
}

// --- 缺少原本的固定字段时，大小写变体不能替代该字段 ---

func TestLoadReportCaseVariantCannotReplaceMissingStatus(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`, `"StAtus":"`+StatusPass+`"`))
	expectCorruptLoad(t, dir, id, "r-pass")
}

func TestLoadReportCaseVariantCannotReplaceMissingReportID(t *testing.T) {
	dir := t.TempDir()
	r := oneDefectFixture()
	r.ReportID = ReportID(r)
	id := writeDupArchiveText(t, dir, r, func(doc string) string {
		return strings.Replace(doc, `{"reportId":"`+r.ReportID+`"`, `{"ReportId":"`+r.ReportID+`"`, 1)
	})
	expectCorruptLoad(t, dir, id, "")
}

func TestLoadReportCaseVariantCannotReplaceMissingArtifactName(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"artifact":{"name":"Vault"`, `"artifact":{"Name":"Vault"`))
	expectCorruptLoad(t, dir, id, "")
}

// --- 产物信息、规则与缺陷记录的其他固定字段同样只认原有写法 ---

func TestLoadReportCaseVariantsIgnoredAcrossAllFixedFields(t *testing.T) {
	dir := t.TempDir()
	id := writeDupArchiveText(t, dir, oneDefectFixture(), func(doc string) string {
		// 每个已知对象都塞入一个拼写变体：产物名与哈希、规则版本与说明、
		// 缺陷记录的证据。它们都只是扩展字段，读出结果必须逐字段等于原报告。
		doc = strings.Replace(doc, `"artifact":{"name":"Vault"`,
			`"artifact":{"Name":"Other","HASH":"`+strings.Repeat("0", 64)+`","name":"Vault"`, 1)
		doc = strings.Replace(doc, `"version":"2","status"`,
			`"Version":"9.9.9","NOTE":"fake","version":"2","status"`, 1)
		doc = strings.Replace(doc, `"evidence":"counterexample: x"`,
			`"Evidence":"forged","evidence":"counterexample: x"`, 1)
		return doc
	})

	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("case-variant extension members must be ignored, not rejected: %v", err)
	}
	want := oneDefectFixture()
	if loaded.Artifact != want.Artifact {
		t.Fatalf("artifact changed by variants: got %+v want %+v", loaded.Artifact, want.Artifact)
	}
	if loaded.Rules[1].Version != "2" || loaded.Rules[1].Note != "counterexample: x" {
		t.Fatalf("rule changed by variants: %+v", loaded.Rules[1])
	}
	if loaded.Findings[0] != want.Findings[0] {
		t.Fatalf("finding changed by variants: got %+v want %+v", loaded.Findings[0], want.Findings[0])
	}
}

// --- 字段名两侧带空格的成员也不替代固定字段 ---

func TestLoadReportWhitespacePaddedNameCannotReplaceStatus(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`, `" status ":"`+StatusPass+`"`))
	expectCorruptLoad(t, dir, id, "r-pass")
}

// --- 用 JSON 转义写出的同一个字段名依然表示同一字段 ---

func TestLoadReportUnicodeEscapedFixedNameStillDecodes(t *testing.T) {
	dir := t.TempDir()
	// "status" 写作 "status"（0x73 == 's'）仍是固定字段本身。
	escaped := `"` + "\\u0073" + `tatus":"` + StatusPass + `"`
	id := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`, escaped))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("an escaped spelling of a fixed field must decode as that field: %v", err)
	}
	if got := statusByID(loaded)["r-pass"]; got != StatusPass {
		t.Fatalf("r-pass status = %q, want %q", got, StatusPass)
	}
}

// --- diff 读取同一归档时使用一致的字段含义 ---

func TestDiffStoreIgnoresCaseVariantMembers(t *testing.T) {
	dir := t.TempDir()
	plain := oneDefectFixture()
	plainID := writeReportWithFreshID(t, dir, plain)
	// 同一份报告，仅多一个 StAtus 扩展字段：diff 必须读出与原文一致的结论。
	extendedID := writeDupArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusDefect+`"`,
			`"status":"`+StatusDefect+`","StAtus":"`+StatusPass+`"`))
	if extendedID != plainID {
		t.Fatalf("test setup: extension members must not change the report id")
	}

	diff, err := DiffStore(dir, plainID, extendedID)
	if err != nil {
		t.Fatalf("diff must read both archives with the same field meaning: %v", err)
	}
	if diff.Summary.NoChange != 3 || diff.Summary.StatusChanges != 0 || diff.Summary.NewDefects != 0 {
		t.Fatalf("extension members must not change any comparison outcome: %+v", diff.Summary)
	}
	for _, res := range diff.Results {
		if res.RuleID == "r-bad" && res.After.Rule.Status != StatusDefect {
			t.Fatalf("diff must report the original defect conclusion, got %q", res.After.Rule.Status)
		}
	}
}
