package contractsentinel

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// jsonEscapedR is the six-character JSON unicode escape that decodes to the
// letter r; it is built by concatenation so the source never carries the
// escape-looking literal as one piece.
const jsonEscapedR = `\` + `u0072`

// 本文件锁定“归档读取”侧规则定义 requiresABI 成员的类型规则。audit 提交侧
// 早已拒绝 null 等非布尔值，但读取已保存报告时 json.Unmarshal 会把正式
// requiresABI 成员的 null 静默解码成 Go 零值 false：把一条原本“不需要 ABI”
// 的规则在归档里从 false 改成 null，重算的报告标识、规则状态与缺陷绑定仍
// 全部成立，读出的规则定义也显示 false，归档内容不合法的事实被完全掩盖。
//
// 修正后，正式成员（约定拼写，含 Unicode 转义写法）一旦出现就只允许 JSON
// 布尔值 true/false；null、字符串、数字、对象、数组都使整份归档判为损坏，
// 与规则是否已检查、是否发现缺陷无关，也不能只跳过该规则返回其余部分。
// 省略该成员仍表示 false；RequiresABI 或两侧带空格的名称只是扩展信息，其
// 中的 null 不触发本错误，也不能替代或挽救正式成员。

// mutateRuleRequiresABI 把归档中指定规则的 requiresABI 成员做一次文本替换。
func mutateRuleRequiresABI(t *testing.T, doc, ruleID, newFragment string) string {
	t.Helper()
	old := `"id":"` + ruleID + `","kind":"`
	idx := strings.Index(doc, old)
	if idx < 0 {
		t.Fatalf("test setup: rule %s not found in archive", ruleID)
	}
	rest := doc[idx:]
	marker := `"requiresABI":`
	at := strings.Index(rest, marker)
	if at < 0 {
		t.Fatalf("test setup: rule %s has no requiresABI member", ruleID)
	}
	valueStart := idx + at + len(marker)
	// 找到该值之后的第一个逗号（规则对象内 requiresABI 后面总跟着 version）。
	comma := strings.IndexByte(doc[valueStart:], ',')
	if comma < 0 {
		t.Fatalf("test setup: rule %s requiresABI value has no trailing comma", ruleID)
	}
	valueEnd := valueStart + comma
	if newFragment == "" {
		// 省略整个成员：连前导逗号一起删掉，避免留下空逗号。
		return doc[:idx+at] + doc[valueEnd+1:]
	}
	return doc[:idx+at] + newFragment + doc[valueEnd:]
}

// writeArchiveWithRuleRequiresABI marshals a legal report and replaces the
// requiresABI member of one rule with a raw fragment. When the fragment
// launders through the plain decoder (null decodes into the bool zero value),
// the reportId is recomputed so the archive is self-consistent and rejection
// can only come from the type gate. Other non-boolean JSON types never
// unmarshal into a Go bool, so the original id is kept: it may mismatch, but
// the type gate runs before the id comparison and rejects with the same
// corruption error.
func writeArchiveWithRuleRequiresABI(t *testing.T, dir string, r Report, ruleID, fragment string) string {
	t.Helper()
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	doc := mutateRuleRequiresABI(t, string(data), ruleID, fragment)
	if doc == string(data) {
		t.Fatal("test setup: mutation did not change the archive")
	}
	id := r.ReportID
	if strict, err := strictReportJSON([]byte(doc)); err == nil {
		var decoded Report
		if err := json.Unmarshal(strict, &decoded); err == nil {
			newID := ReportID(decoded)
			doc = strings.Replace(doc, `"reportId":"`+id+`"`, `"reportId":"`+newID+`"`, 1)
			id = newID
		}
	}
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return id
}

// expectCorruptRequiresABILoad asserts the full read-side contract for an
// illegal formal requiresABI value: errCorrupt naming the report id, the
// offending rule and the boolean requirement, a zero report and an untouched
// archive.
func expectCorruptRequiresABILoad(t *testing.T, dir, id, rule string) {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("a non-boolean formal requiresABI must reject the whole archive, got %+v", got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("illegal requiresABI classifies as errCorrupt, got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, id) {
		t.Fatalf("error must name the report id %q: %v", id, err)
	}
	if !strings.Contains(msg, rule) {
		t.Fatalf("error must name the offending rule %q: %v", rule, err)
	}
	if !strings.Contains(msg, "requiresABI must be a boolean") {
		t.Fatalf("error must state requiresABI must be a boolean: %v", err)
	}
	if !reflect.DeepEqual(got, Report{}) {
		t.Fatalf("failed read must return the zero report, got %+v", got)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must not be deleted: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed read must not rewrite or repair the archive")
	}
}

// --- null 落在任何检查结论的规则上都使整份归档损坏，不能跳过该规则 ---

func allStatusFixture() Report {
	hash := ArtifactHash(sampleArtifact())
	report := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r-pass", Kind: "static", Severity: "low", Invariant: "inv-pass", Version: "1", Status: StatusPass},
			{ID: "r-defect", Kind: "static", Severity: "high", Invariant: "inv-defect", Version: "2", Status: StatusDefect, Note: "counterexample: x"},
			{ID: "r-unchecked", Kind: "symbolic", Severity: "info", Invariant: "inv-unchecked", Version: "3", Status: StatusUnchecked},
			{ID: "r-tool", Kind: "static", Severity: "medium", Invariant: "inv-tool", RequiresABI: true, Version: "4", Status: StatusToolMissing, Note: "符号执行引擎未安装"},
			{ID: "r-timeout", Kind: "symbolic", Severity: "critical", Invariant: "inv-timeout", Version: "5", Status: StatusTimeout, Note: "超过 60s 截止时间"},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r-defect", Version: "2", Severity: "high", Invariant: "inv-defect", Evidence: "counterexample: x"},
		},
	}
	return report
}

func TestLoadReportNullRequiresABIRejectedForEveryRuleStatus(t *testing.T) {
	for _, ruleID := range []string{"r-pass", "r-defect", "r-unchecked", "r-tool", "r-timeout"} {
		t.Run(ruleID, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleRequiresABI(t, dir, allStatusFixture(), ruleID, `"requiresABI":null`)
			expectCorruptRequiresABILoad(t, dir, id, ruleID)
		})
	}
}

// --- 字符串、数字、对象、数组同样判为损坏，不能默认成 false ---

func TestLoadReportNonBooleanRequiresABIRejected(t *testing.T) {
	for _, val := range []string{`"false"`, `"true"`, `0`, `1`, `{}`, `[true]`} {
		t.Run(val, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-pass", `"requiresABI":`+val)
			expectCorruptRequiresABILoad(t, dir, id, "r-pass")
		})
	}
}

// --- 拒绝不依赖标识不匹配：null 被洗成 false 后重算标识仍然一致 ---

func TestLoadReportNullRequiresABICorruptDespiteMatchingID(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-bad", `"requiresABI":null`)

	// 归档内 reportId、请求 id 与按解码内容重算的 id 三者一致：null 已被
	// 洗成 false，除类型关外没有任何一关能拒绝它。
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	strict, err := strictReportJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(strict, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportID != id || ReportID(decoded) != id {
		t.Fatalf("test setup: id must match the laundered content, archive=%q recomputed=%q requested=%q",
			decoded.ReportID, ReportID(decoded), id)
	}
	if decoded.Rules[1].RequiresABI {
		t.Fatal("test setup: null must launder to false under the plain decoder")
	}
	expectCorruptRequiresABILoad(t, dir, id, "r-bad")
}

// --- 缺陷规则写 null 时，即使缺陷证据与解码内容完全吻合也必须拒绝 ---

func TestLoadReportNullRequiresABIDefectBindingStillRejected(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-bad", `"requiresABI":null`)
	// 直接核对：读出的（未经类型关的）缺陷绑定与规则一一吻合，唯一的不
	// 合法点就是 requiresABI 的 null。
	data, _ := os.ReadFile(filepath.Join(dir, id+".json"))
	strict, _ := strictReportJSON(data)
	var decoded Report
	if err := json.Unmarshal(strict, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validateReport(decoded, func(msg string) error { return errCorrupt(msg) }); err != nil {
		t.Fatalf("test setup: rule/finding correspondence must otherwise be legal: %v", err)
	}
	expectCorruptRequiresABILoad(t, dir, id, "r-bad")
}

// --- 兼容行为：省略仍为 false；显式 true/false 按原值读回，标识与证据不变 ---

func TestLoadReportRequiresABIOmittedAndExplicitValuesPreserved(t *testing.T) {
	dir := t.TempDir()

	// 省略 r-pass 的 requiresABI：读回 false，且与显式 false 的归档同标识。
	omittedID := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-pass", ``)
	omitted, err := LoadReport(dir, omittedID)
	if err != nil {
		t.Fatalf("an omitted requiresABI must still load: %v", err)
	}
	if omitted.Rules[0].RequiresABI {
		t.Fatal("omitted requiresABI must keep meaning false")
	}
	if want := ReportID(oneDefectFixture()); omittedID != want {
		t.Fatalf("omitted and explicit false must share the report id:\n%s\n%s", omittedID, want)
	}

	// 显式 true 按原值读回，规则状态与归属保持不变。
	withTrue := oneDefectFixture()
	withTrue.Rules[0].RequiresABI = true
	trueID := writeReportWithFreshID(t, dir, withTrue)
	loadedTrue, err := LoadReport(dir, trueID)
	if err != nil {
		t.Fatalf("explicit true must load: %v", err)
	}
	if !loadedTrue.Rules[0].RequiresABI {
		t.Fatal("explicit true must read back as true")
	}
	if loadedTrue.Rules[0].Status != StatusPass {
		t.Fatalf("rule status must be preserved, got %q", loadedTrue.Rules[0].Status)
	}
	if len(loadedTrue.Findings) != 1 || loadedTrue.Findings[0].Evidence != "counterexample: x" {
		t.Fatalf("finding binding must be preserved: %+v", loadedTrue.Findings)
	}
}

// --- 大小写变体或带空格名称中的 null 是扩展信息：不触发错误 ---

func TestLoadReportRequiresABIVariantNullIgnored(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fragment string
	}{
		{"case variant", `"RequiresABI":null`},
		{"whitespace padded", `" requiresABI ":null`},
		{"case variant true", `"RequiresABI":true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-pass", tc.fragment)
			loaded, err := LoadReport(dir, id)
			if err != nil {
				t.Fatalf("a variant-named member is extension data and must be ignored: %v", err)
			}
			if loaded.Rules[0].RequiresABI {
				t.Fatal("a variant member must not supply the formal value")
			}
			if want := ReportID(oneDefectFixture()); id != want {
				t.Fatalf("extension data must not change the report id:\n got %s\nwant %s", id, want)
			}
		})
	}
}

// --- 正式成员非法时，旁边的大小写变体即使写了合法布尔值也不能挽救（前后两种位置） ---

func TestLoadReportRequiresABIVariantCannotRescueFormalNull(t *testing.T) {
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			dir := t.TempDir()
			fragment := `"requiresABI":null,"RequiresABI":false`
			if pos == "before" {
				fragment = `"RequiresABI":false,"requiresABI":null`
			}
			id := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-pass", fragment)
			expectCorruptRequiresABILoad(t, dir, id, "r-pass")
		})
	}
}

// --- Unicode 转义写出的正式名称遵守同一布尔规则 ---

func TestLoadReportEscapedRequiresABINameFollowsSameRule(t *testing.T) {
	// "\u0072equiresABI" 解码后就是 requiresABI：null 同样判为损坏。
	dir := t.TempDir()
	nullID := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-pass",
		`"`+jsonEscapedR+`equiresABI":null`)
	expectCorruptRequiresABILoad(t, dir, nullID, "r-pass")

	// 转义写法携带合法 true 时，与直接书写 true 的报告标识一致并按原值读回。
	escapedTrueID := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-pass",
		`"`+jsonEscapedR+`equiresABI":true`)
	loadedEscaped, err := LoadReport(dir, escapedTrueID)
	if err != nil {
		t.Fatalf("escaped spelling with a legal boolean must load: %v", err)
	}
	if !loadedEscaped.Rules[0].RequiresABI {
		t.Fatal("escaped requiresABI:true must read back as true")
	}
	plainTrue := oneDefectFixture()
	plainTrue.Rules[0].RequiresABI = true
	if got, want := escapedTrueID, ReportID(plainTrue); got != want {
		t.Fatalf("escaped and plain spellings must share the report id:\n%s\n%s", got, want)
	}
}

// --- 拒绝时不创建任何额外文件，重复读取始终拒绝 ---

func TestLoadReportNullRequiresABINoFilesAndRepeatedRejection(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-none", `"requiresABI":null`)
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := LoadReport(dir, id); err == nil {
			t.Fatal("repeated reads must keep rejecting the archive")
		}
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("failed reads must create no files, got %v", after)
	}
}

// --- diff：任一侧归档含非法 requiresABI 都整体失败，不输出局部差异，不把
// 被洗成 false 的规则拿去比较“无变化”或“规则变化” ---

func TestDiffStoreRejectsBadRequiresABIEitherSide(t *testing.T) {
	dir := t.TempDir()
	good := oneDefectFixture()
	goodID := writeReportWithFreshID(t, dir, good)

	// 另一侧是另一份合法报告（多一条规则），损坏后落盘；null 会被洗成
	// false，所以损坏归档与合法归档共用同一标识，先留一份干净字节便于恢复。
	other := oneDefectFixture()
	other.Rules = append(other.Rules,
		ReportRule{ID: "r-extra", Kind: "static", Severity: "info", Invariant: "inv-extra", Version: "9", Status: StatusPass})
	otherID := writeReportWithFreshID(t, dir, other)
	cleanOther, err := os.ReadFile(filepath.Join(dir, otherID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	badID := writeArchiveWithRuleRequiresABI(t, dir, other, "r-extra", `"requiresABI":null`)
	if badID != otherID {
		t.Fatalf("test setup: null launders to false, so the id must stay %q, got %q", otherID, badID)
	}
	badBytes, err := os.ReadFile(filepath.Join(dir, badID+".json"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		before string
		after  string
		named  string
	}{
		{"second report corrupt", goodID, badID, badID},
		{"first report corrupt", badID, goodID, badID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if data, _ := os.ReadFile(filepath.Join(dir, badID+".json")); !bytes.Contains(data, []byte(`"requiresABI":null`)) {
				t.Fatalf("subtest start: archive already repaired:\n%s", data)
			}
			diff, err := DiffStore(dir, tc.before, tc.after)
			if data, _ := os.ReadFile(filepath.Join(dir, badID+".json")); !bytes.Contains(data, []byte(`"requiresABI":null`)) {
				t.Fatalf("subtest end: DiffStore rewrote the archive:\n%s", data)
			}
			if err == nil {
				t.Fatalf("diff must fail when a side carries a bad requiresABI, got %+v", diff)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), "r-extra") ||
				!strings.Contains(err.Error(), "requiresABI must be a boolean") ||
				!strings.Contains(err.Error(), tc.named) {
				t.Fatalf("error must name the report, rule and boolean requirement: %v", err)
			}
			if !reflect.DeepEqual(diff, DiffResult{}) {
				t.Fatalf("failed diff must return the zero result, got %+v", diff)
			}
		})
	}

	// 失败的比较不得修复、覆盖损坏侧归档：重复失败后损坏字节原样保留。
	for i := 0; i < 2; i++ {
		if _, err := DiffStore(dir, goodID, badID); err == nil {
			t.Fatal("diff against the corrupt side must keep failing")
		}
		kept, err := os.ReadFile(filepath.Join(dir, badID+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(kept, []byte(`"requiresABI":null`)) {
			t.Fatalf("failed diff must leave the corrupt archive untouched:\n%s", kept)
		}
	}

	// 恢复另一侧后比较成功：证明失败只来自类型关，而非报告对本身有问题，
	// 且成功的比较同样不重写归档。
	if err := os.WriteFile(filepath.Join(dir, otherID+".json"), cleanOther, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DiffStore(dir, goodID, otherID); err != nil {
		t.Fatalf("restored archive must diff successfully: %v", err)
	}
	afterRestore, err := os.ReadFile(filepath.Join(dir, otherID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterRestore, cleanOther) {
		t.Fatal("successful diff must not rewrite the archive")
	}
	// 损坏阶段的字节与干净字节确实不同，保证前面的保留断言有效。
	if bytes.Equal(badBytes, cleanOther) {
		t.Fatal("test setup: the mutated archive must differ from the clean one")
	}
}

// --- audit 保存遇到同标识已有损坏归档：不能被当成保存成功，原文件保留 ---

func TestSaveReportBadRequiresABIExistingArchiveFails(t *testing.T) {
	dir := t.TempDir()
	id := writeArchiveWithRuleRequiresABI(t, dir, oneDefectFixture(), "r-pass", `"requiresABI":null`)
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	r := oneDefectFixture()
	r.ReportID = id
	err = SaveReport(dir, r)
	if err == nil {
		t.Fatal("a corrupt existing archive must not count as a successful save")
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "r-pass") ||
		!strings.Contains(err.Error(), "requiresABI must be a boolean") {
		t.Fatalf("error must name the report, rule and boolean requirement: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must be kept: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed save must leave the corrupt archive untouched")
	}
}
