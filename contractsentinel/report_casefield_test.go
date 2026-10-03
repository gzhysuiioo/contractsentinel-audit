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

// 本文件锁定读取侧“只认固定字段原有大小写写法”的规则：归档里与固定字段
// 大小写不同（或两侧带空白）的成员只是未知扩展字段，绝不能参与状态解码、
// 覆盖原固定字段的结论，也不能在原字段缺失或取值非法时顶替它。固定字段
// 覆盖报告标识（reportId）、产物信息（name/hash）、每条规则（id/kind/
// severity/invariant/requiresABI/version/status/note）和每条缺陷记录
// （artifactHash/ruleId/version/severity/invariant/evidence）。
//
// 这些用例全部以“干净合法归档 + 纯文本注入扩展成员”的方式构造：扩展不
// 改变解码后的可信内容，因此原报告标识继续有效，读取结果必须与无扩展时
// 逐字段一致，且与扩展成员出现的位置无关。

// writeVariantArchiveText 与 writeDupArchiveText 相同：在合法归档文本上做
// 一次纯文本注入，文件名仍用内容标识（扩展不参与标识计算）。
func writeVariantArchiveText(t *testing.T, dir string, r Report, mutate func(string) string) string {
	t.Helper()
	return writeDupArchiveText(t, dir, r, mutate)
}

// decodeArchiveText 直接走读取侧严格解码器，便于在字段层面断言扩展成员没
// 有顶替固定字段。
func decodeArchiveText(t *testing.T, doc string) Report {
	t.Helper()
	r, err := decodeStoredReport([]byte(doc))
	if err != nil {
		t.Fatalf("strict decoder rejected legal archive text: %v\n%s", err, doc)
	}
	return r
}

// marshalFixtureText 序列化一份带匹配标识的合法归档文本。
func marshalFixtureText(t *testing.T, r Report) string {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// writeVariantTextFreshID 用于“原固定字段非法/缺失”的隔离构造：先注入
// 文本，再按严格解码后的内容重算标识并把文本中的 reportId 一并换掉，使
// 拒绝只能来自目标字段本身，而不是标识不匹配。
func writeVariantTextFreshID(t *testing.T, dir string, r Report, mutate func(string) string) string {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	doc := mutate(string(data))
	decoded, derr := decodeStoredReport([]byte(doc))
	if derr != nil {
		// 解码器对结构性非法输入也会报错；这些用例需要解码成功后由校验拒绝，
		// 因此这里不允许解码失败。
		t.Fatalf("test setup: strict decode failed: %v\n%s", derr, doc)
	}
	fresh := ReportID(decoded)
	doc = strings.Replace(doc, `"reportId":"`+r.ReportID+`"`, `"reportId":"`+fresh+`"`, 1)
	if err := os.WriteFile(filepath.Join(dir, fresh+".json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return fresh
}

// --- 核心场景：固定 status=发现缺陷，扩展 StAtus=通过，结论仍是缺陷 ---

func TestLoadReportCaseVariantStatusDoesNotOverrideDefect(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusDefect+`"`,
			`"status":"`+StatusDefect+`","StAtus":"`+StatusPass+`"`))

	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("a case-variant extension must not corrupt a legal defect report: %v", err)
	}
	statusByID := map[string]string{}
	for _, rl := range loaded.Rules {
		statusByID[rl.ID] = rl.Status
	}
	if statusByID["r-bad"] != StatusDefect {
		t.Fatalf("fixed defect conclusion overridden by StAtus: %+v", statusByID)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].RuleID != "r-bad" {
		t.Fatalf("the original defect finding must stay: %+v", loaded.Findings)
	}
	want := oneDefectFixture()
	want.ReportID = id
	if !reflect.DeepEqual(loaded, want) {
		t.Fatalf("loaded report differs from the original:\n got %+v\nwant %+v", loaded, want)
	}
}

// 反过来，固定 status=通过 加扩展 StAtus=发现缺陷，也不能把通过伪装成缺陷。

func TestLoadReportCaseVariantStatusDoesNotForgeDefect(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"`+StatusPass+`","StAtus":"`+StatusDefect+`"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("legal archive must load: %v", err)
	}
	for _, rl := range loaded.Rules {
		if rl.ID == "r-pass" && rl.Status != StatusPass {
			t.Fatalf("pass conclusion changed to %q", rl.Status)
		}
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].RuleID != "r-bad" {
		t.Fatalf("only the fixed r-bad defect may exist: %+v", loaded.Findings)
	}
}

// --- 位置无关：扩展写在固定成员前后，读出来是同一份报告和同一个标识 ---

func TestLoadReportCaseVariantPositionIndependent(t *testing.T) {
	dir := t.TempDir()
	base := oneDefectFixture()

	before := writeVariantArchiveText(t, dir, base,
		dupOnce(`"status":"`+StatusDefect+`"`,
			`"StAtus":"`+StatusPass+`","status":"`+StatusDefect+`"`))
	afterData := marshalFixtureText(t, base)
	afterData = strings.Replace(afterData, `"status":"`+StatusDefect+`"`,
		`"status":"`+StatusDefect+`","StAtus":"`+StatusPass+`"`, 1)
	// 两种写法内容标识相同，写入同一归档文件即可；直接比较解码结果。
	rBefore := decodeArchiveText(t, mustReadArchiveText(t, dir, before))
	rAfter := decodeArchiveText(t, afterData)
	if !reflect.DeepEqual(rBefore, rAfter) {
		t.Fatalf("member position changed the decoded report:\n before=%+v\n after=%+v", rBefore, rAfter)
	}
	if rBefore.ReportID != ReportID(base) {
		t.Fatalf("extension members must not change the report id: got %q want %q", rBefore.ReportID, ReportID(base))
	}
}

func mustReadArchiveText(t *testing.T, dir, id string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// --- JSON 转义写出的大小写变体同样只是扩展；转义写出的同名成员仍是固定字段 ---

func TestLoadReportEscapedCaseVariantIgnored(t *testing.T) {
	dir := t.TempDir()
	// 归档文本里的成员名写作 "StAtus"（首字符 S 用 JSON 转义 S 表示）；
	// JSON 解码后成员名是 "Status"，只是固定 status 的大小写变体，属于扩
	// 展，不能参与状态解码。
	const variantKey = "\"\\u0053tAtus\"" // 归档原文："StAtus"（S 转义）
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusDefect+`"`,
			`"status":"`+StatusDefect+`",`+variantKey+`:"`+StatusPass+`"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("escaped case variant is an ordinary extension: %v", err)
	}
	if loaded.Rules[1].Status != StatusDefect {
		t.Fatalf("escaped Status must not override status, got %q", loaded.Rules[1].Status)
	}
}

// 用 JSON 转义写出的同名固定成员（s 解码为小写 's'，即 "status"）与
// 直接书写的 status 出现两次，仍按重复成员拒绝（现有规则不变）。
func TestLoadReportEscapedExactDuplicateStillRejected(t *testing.T) {
	dir := t.TempDir()
	const escapedStatusKey = "\"\\u0073tatus\"" // 归档原文："status"（s 转义）
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusPass+`"`,
			`"status":"`+StatusDefect+`", `+escapedStatusKey+`:"`+StatusPass+`"`))
	if _, err := LoadReport(dir, id); err == nil {
		t.Fatal("an escaped exact-name duplicate must still be rejected")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("expected errCorrupt, got %T: %v", err, err)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			t.Fatalf("error must classify the member as duplicated: %v", err)
		}
	}
}

// --- 两侧带空白的成员名不顶替固定字段 ---

func TestLoadReportWhitespacePaddedVariantIgnored(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusDefect+`"`,
			`" status ":"`+StatusPass+`","status":"`+StatusDefect+`"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("whitespace-padded member must stay an extension: %v", err)
	}
	if loaded.Rules[1].Status != StatusDefect {
		t.Fatalf("padded-name member overrode status: %q", loaded.Rules[1].Status)
	}
}

// --- 扩展值是对象/数组时也被整体跳过，字符串里像 JSON 的文字只是内容 ---

func TestLoadReportComplexExtensionValueSkipped(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusDefect+`"`,
			`"StAtus":{"nested":["通过",{"k":"v"}]},"status":"`+StatusDefect+`"`))
	if _, err := LoadReport(dir, id); err != nil {
		t.Fatalf("object/array extension values must be skipped: %v", err)
	}
}

func TestLoadReportJSONLookingEvidenceWithVariantStillLoads(t *testing.T) {
	dir := t.TempDir()
	r := oneDefectFixture()
	r.Rules[1].Note = `反例 {"status":"通过"}`
	r.Findings[0].Evidence = r.Rules[1].Note
	id := writeVariantArchiveText(t, dir, r,
		dupOnce(`"status":"`+StatusDefect+`"`,
			`"StAtus":"x","status":"`+StatusDefect+`"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("legal report must load: %v", err)
	}
	if got := loaded.Findings[0].Evidence; got != r.Findings[0].Evidence {
		t.Fatalf("evidence not preserved verbatim: %q", got)
	}
}

// --- 原固定字段取非法状态时，不能靠大小写变体提供合法状态蒙混过关 ---

func TestLoadReportBadFixedStatusNotRescuedByVariant(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantTextFreshID(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusDefect+`"`,
			`"status":"奇怪状态","StAtus":"`+StatusDefect+`"`))
	// 标识已按解码内容重算，唯一非法点就是固定 status 的取值；扩展被忽略，
	// 规则因此带着未知状态进入校验。
	expectCorruptLoad(t, dir, id, "r-bad")
}

// --- 缺少原必需字段时，仅提供大小写变体不能替代该字段 ---

func TestLoadReportMissingRuleIDNotSubstitutedByVariant(t *testing.T) {
	dir := t.TempDir()
	base := oneDefectFixture()
	base.ReportID = ReportID(base)
	doc := marshalFixtureText(t, base)
	// 移除固定 id，仅留下大小写变体 ID。
	doc = strings.Replace(doc, `"id":"r-bad",`, `"ID":"r-bad",`, 1)

	// 字段层面：变体没有填进固定 ID。
	decoded := decodeArchiveText(t, doc)
	for _, rl := range decoded.Rules {
		if rl.ID == "r-bad" {
			t.Fatalf("variant ID must not populate the fixed id: %+v", rl)
		}
	}

	// 重算标识写盘后，归档仍因空 id（必需字段缺失）被拒绝。
	fresh := ReportID(decoded)
	doc = strings.Replace(doc, `"reportId":"`+base.ReportID+`"`, `"reportId":"`+fresh+`"`, 1)
	if err := os.WriteFile(filepath.Join(dir, fresh+".json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	expectCorruptLoad(t, dir, fresh, "empty id")
}

// --- 产物信息的固定字段同样只认原写法 ---

func TestLoadReportArtifactCaseVariantsIgnored(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"artifact":{"name":"Vault"`,
			`"artifact":{"Name":"Other"," name ":"Other2","name":"Vault"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("artifact name variants must be ignored: %v", err)
	}
	if loaded.Artifact.Name != "Vault" {
		t.Fatalf("artifact name = %q, want Vault", loaded.Artifact.Name)
	}
}

// 产物哈希的变体不能覆盖固定 hash；读出的哈希必须原样保留。
func TestLoadReportArtifactHashVariantIgnored(t *testing.T) {
	dir := t.TempDir()
	base := oneDefectFixture()
	id := writeVariantArchiveText(t, dir, base,
		dupOnce(`"hash":"`+base.Artifact.Hash+`"`,
			`"hash":"`+base.Artifact.Hash+`","Hash":"`+strings.Repeat("f", 64)+`"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("hash variant must be ignored: %v", err)
	}
	if loaded.Artifact.Hash != base.Artifact.Hash {
		t.Fatalf("artifact hash not preserved: %q", loaded.Artifact.Hash)
	}
	if loaded.Findings[0].ArtifactHash != base.Artifact.Hash {
		t.Fatalf("finding artifact hash must stay verbatim: %q", loaded.Findings[0].ArtifactHash)
	}
}

// --- 缺陷记录里的固定字段只认原写法，变体不能改归属 ---

func TestLoadReportFindingCaseVariantsIgnored(t *testing.T) {
	dir := t.TempDir()
	base := oneDefectFixture()
	id := writeVariantArchiveText(t, dir, base,
		dupOnce(`"ruleId":"r-bad","version":"2"`,
			`"ruleID":"ghost","RuleId":"ghost2","ruleId":"r-bad","version":"2","Version":"9"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("finding variants must be ignored: %v", err)
	}
	f := loaded.Findings[0]
	if f.RuleID != "r-bad" || f.Version != "2" {
		t.Fatalf("finding attribution changed by variants: %+v", f)
	}
	if !reflect.DeepEqual(f, base.Findings[0]) {
		t.Fatalf("finding not preserved verbatim:\n got %+v\nwant %+v", f, base.Findings[0])
	}
}

// --- 报告标识的大小写变体不能顶替 reportId ---

func TestLoadReportReportIDVariantIgnored(t *testing.T) {
	dir := t.TempDir()
	base := oneDefectFixture()
	base.ReportID = ReportID(base)
	id := writeVariantArchiveText(t, dir, base,
		dupOnce(`{"reportId":"`+base.ReportID+`"`,
			`{"ReportId":"`+strings.Repeat("1", 64)+`","reportId":"`+base.ReportID+`"`))
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("reportId variant must be ignored: %v", err)
	}
	if loaded.ReportID != id {
		t.Fatalf("report id = %q, want %q", loaded.ReportID, id)
	}
}

// --- 说明、证据、规则版本在带扩展时原样保留 ---

func TestLoadReportFixedValuesPreservedVerbatimWithVariants(t *testing.T) {
	dir := t.TempDir()
	base := oneDefectFixture()
	id := writeVariantArchiveText(t, dir, base, func(doc string) string {
		doc = strings.Replace(doc, `"note":"counterexample: x"`,
			`"Note":"别的说明","note":"counterexample: x"`, 1)
		doc = strings.Replace(doc, `"evidence":"counterexample: x"`,
			`"Evidence":"别的证据","evidence":"counterexample: x"`, 1)
		doc = strings.Replace(doc, `"id":"r-bad","kind":"static","severity":"high","invariant":"inv-bad","requiresABI":false,"version":"2"`,
			`"id":"r-bad","kind":"static","severity":"high","invariant":"inv-bad","requiresABI":false,"version":"2","Version":"9","Severity":"critical"`, 1)
		return doc
	})
	loaded, err := LoadReport(dir, id)
	if err != nil {
		t.Fatalf("legal archive with variants must load: %v", err)
	}
	if got := loaded.Rules[1]; !reflect.DeepEqual(got, base.Rules[1]) {
		t.Fatalf("rule not preserved verbatim:\n got %+v\nwant %+v", got, base.Rules[1])
	}
	if got := loaded.Findings[0]; !reflect.DeepEqual(got, base.Findings[0]) {
		t.Fatalf("finding not preserved verbatim:\n got %+v\nwant %+v", got, base.Findings[0])
	}
}

// --- diff 读取同一归档使用一致含义：扩展不改变比较结果，仍走完整校验 ---

func TestDiffStoreVariantArchiveUsesFixedFields(t *testing.T) {
	dir := t.TempDir()
	id := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"status":"`+StatusDefect+`"`,
			`"StAtus":"`+StatusPass+`","status":"`+StatusDefect+`"`))

	got, err := DiffStore(dir, id, id)
	if err != nil {
		t.Fatalf("diff of a legal variant archive must succeed: %v", err)
	}
	base := oneDefectFixture()
	want := DiffReports(base, base)
	if !reflect.DeepEqual(got.Summary, want.Summary) {
		t.Fatalf("diff summary changed by extension:\n got %+v\nwant %+v", got.Summary, want)
	}
	for _, res := range got.Results {
		if res.Change != ChangeNoChange {
			t.Fatalf("every rule must compare unchanged, got %q for %s", res.Change, res.RuleID)
		}
	}
}

// --- audit 保存遇到含大小写变体的同标识已有归档：合法即视为已保存，不报错 ---

func TestSaveReportVariantExistingArchiveAccepted(t *testing.T) {
	dir := t.TempDir()
	r := oneDefectFixture()
	id := writeVariantArchiveText(t, dir, r,
		dupOnce(`"status":"`+StatusPass+`"`,
			`"StAtus":"`+StatusDefect+`","status":"`+StatusPass+`"`))
	r.ReportID = id
	if err := SaveReport(dir, r); err != nil {
		t.Fatalf("a legal variant-bearing archive must count as the same saved report: %v", err)
	}
}

// --- 严格解码器的结构性错误仍归类为损坏（经由 LoadReport 验证）---

func TestDecodeStoredReportStructuralErrors(t *testing.T) {
	for _, doc := range []string{
		`null`,
		`[1,2]`,
		`{"rules": 1}`,
		`{"artifact": "x"}`,
		`{"rules": [1]}`,
		`{"reportId": 5}`,
		`{"rules": [{"requiresABI": "x"}]}`,
		`{"reportId":"x"} extra`,
		`{broken`,
	} {
		if _, err := decodeStoredReport([]byte(doc)); err == nil {
			t.Errorf("expected decode error for %q", doc)
		}
	}
}
