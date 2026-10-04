package contractsentinel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// 本文件锁定“归档读取”侧规则定义 requiresABI 成员的类型规则。audit 提交侧
// 早已拒绝 null 等非布尔值（见 report_requiresabi_submit_test.go），但读取
// 已保存报告时 json.Unmarshal 会把在场的 null 静默解码成零值 false：一份把
// 原本“不需要 ABI”规则归档里的 false 换成 null 的文件，重算报告标识后，
// 标识、产物哈希、规则状态与缺陷绑定都可能与解码后的内容吻合，读出的规则
// 也显示为 false，归档不合法的事实就此被掩盖。
//
// 修正后，正式 requiresABI 成员（约定拼写，含 Unicode 转义写法）一旦在场，
// 值必须是 JSON 布尔值 true 或 false；null、字符串、数字、对象或数组都使整
// 份归档被判为损坏，与规则是否已检查、是否发现缺陷无关，也不能只跳过该规
// 则。省略仍表示 false；RequiresABI 或两侧带空格的名称只是扩展信息，其中
// 的 null 既不触发本错误，也不能替代或挽救正式成员。读取与比较都不修改
// 归档。

// normalizedRequiresABIFalse rewrites every present non-boolean formal
// requiresABI token in strict rule objects to false, so the content id can be
// computed from the value a naive bool decode would have laundered it to.
// Legal booleans are left untouched.
func normalizedRequiresABIFalse(t *testing.T, strict []byte) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(strict, &top); err != nil {
		t.Fatal(err)
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(top["rules"], &rules); err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		raw, ok := rule["requiresABI"]
		if !ok {
			continue
		}
		var b bool
		if json.Unmarshal(raw, &b) != nil {
			rule["requiresABI"] = json.RawMessage("false")
		}
	}
	rb, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	top["rules"] = rb
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// writeRequiresABIArchiveText marshals a legal report with a fresh matching id,
// replaces the requiresABI literal of the rule bound to invariant with
// fragment, then recomputes and rewrites reportId from the content the illegal
// token would be laundered to (null and every non-boolean type decode as the
// zero value false). The on-disk archive therefore matches its content in
// reportId, artifact hash, statuses and finding evidence in every respect —
// only the requiresABI type is illegal, so rejection can only come from the
// type gate.
func writeRequiresABIArchiveText(t *testing.T, dir string, r Report, invariant, fragment string) string {
	t.Helper()
	literal := "false"
	for _, rule := range r.Rules {
		if rule.Invariant == invariant && rule.RequiresABI {
			literal = "true"
		}
	}
	r.ReportID = ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	old := `"invariant":"` + invariant + `","requiresABI":` + literal
	if !strings.Contains(doc, old) {
		t.Fatalf("test setup: archive does not contain %q", old)
	}
	doc = strings.Replace(doc, old,
		`"invariant":"`+invariant+`","requiresABI":`+fragment, 1)
	strict, err := strictReportJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(normalizedRequiresABIFalse(t, strict), &decoded); err != nil {
		t.Fatal(err)
	}
	newID := ReportID(decoded)
	doc = strings.Replace(doc, `"reportId":"`+r.ReportID+`"`, `"reportId":"`+newID+`"`, 1)
	if err := os.WriteFile(filepath.Join(dir, newID+".json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return newID
}

// expectCorruptRequiresABILoad asserts the full corruption contract: errCorrupt
// (never errInvalid/errNotFound), a zero report, and a message that classifies
// the archive as corrupt and names the report id, the offending rule and the
// boolean requirement.
func expectCorruptRequiresABILoad(t *testing.T, dir, id, rule string) {
	t.Helper()
	got, err := LoadReport(dir, id)
	if err == nil {
		t.Fatalf("expected corrupt rejection, load succeeded: %+v", got)
	}
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("rejection must be errCorrupt, got %T: %v", err, err)
	}
	msg := err.Error()
	for _, want := range []string{"corrupt", id, rule, "requiresABI must be a boolean"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must contain %q", msg, want)
		}
	}
	if !reflect.DeepEqual(got, Report{}) {
		t.Fatalf("failed read must return the zero report, got %+v", got)
	}
}

// archiveDecodesSelfConsistently 自证：除 requiresABI 类型关外，归档的
// reportId、重算内容标识与缺陷绑定都与解码内容吻合。
func archiveDecodesSelfConsistently(t *testing.T, dir, id string, wantFindings int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportID != id || ReportID(decoded) != id {
		t.Fatal("test setup: archive id must match the decoded (null-as-false) content")
	}
	if len(decoded.Findings) != wantFindings {
		t.Fatalf("test setup: findings must stay bound, got %+v", decoded.Findings)
	}
}

// --- 核心场景：null 落在任一结论的规则上都判损坏，即使标识与归属全部自洽 ---

func TestLoadReportNullRequiresABICorruptRegardlessOfStatus(t *testing.T) {
	// 三种规则结论各覆盖一次：通过（r-pass）、发现缺陷且有绑定证据
	// （r-bad）、未检查（r-none）。
	for _, tc := range []struct {
		name         string
		invariant    string
		rule         string
		wantFindings int
	}{
		{"passing rule", "inv-pass", "r-pass", 1},
		{"defect rule with bound finding", "inv-bad", "r-bad", 1},
		{"unchecked rule", "inv-none", "r-none", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := writeRequiresABIArchiveText(t, dir, oneDefectFixture(), tc.invariant, "null")
			archiveDecodesSelfConsistently(t, dir, id, tc.wantFindings)
			expectCorruptRequiresABILoad(t, dir, id, tc.rule)
		})
	}
}

// --- 字符串、数字、对象、数组同样判损坏，不能转成默认值 ---

func TestLoadReportNonBooleanRequiresABICorrupt(t *testing.T) {
	values := []string{`"false"`, `"true"`, `0`, `1`, `{}`, `[true]`}
	for _, val := range values {
		t.Run(val, func(t *testing.T) {
			dir := t.TempDir()
			id := writeRequiresABIArchiveText(t, dir, oneDefectFixture(), "inv-pass", val)
			expectCorruptRequiresABILoad(t, dir, id, "r-pass")
		})
	}
}

// --- 兼容行为不变：省略仍表示 false，true/false 按原值读回，标识/状态/证据不变 ---

func TestLoadReportRequiresABIOmittedAndBooleansStillLoad(t *testing.T) {
	dir := t.TempDir()

	// 显式 false 的既有合法报告原样读回。
	falseID := writeReportWithFreshID(t, dir, oneDefectFixture())
	loadedFalse, err := LoadReport(dir, falseID)
	if err != nil {
		t.Fatalf("explicit false report must load: %v", err)
	}
	if loadedFalse.Rules[0].RequiresABI {
		t.Fatal("explicit false must read back as false")
	}

	// 显式 true 按原值读回。
	withTrue := oneDefectFixture()
	withTrue.Rules[0].RequiresABI = true
	trueID := writeReportWithFreshID(t, dir, withTrue)
	loadedTrue, err := LoadReport(dir, trueID)
	if err != nil {
		t.Fatalf("explicit true report must load: %v", err)
	}
	if !loadedTrue.Rules[0].RequiresABI {
		t.Fatal("explicit true must read back as true")
	}

	// 省略 requiresABI：文本中删掉该成员后重算标识，读出值为 false，且与
	// 显式 false 报告的标识、规则状态和证据完全一致。
	omittedID := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"invariant":"inv-pass","requiresABI":false,`, `"invariant":"inv-pass",`))
	if omittedID != falseID {
		t.Fatalf("omitted and explicit false must share the report id:\n got %s\nwant %s", omittedID, falseID)
	}
	loadedOmitted, err := LoadReport(dir, omittedID)
	if err != nil {
		t.Fatalf("an omitted requiresABI member must still mean false: %v", err)
	}
	if loadedOmitted.Rules[0].RequiresABI {
		t.Fatal("omitted requiresABI must read back as false")
	}
	if !reflect.DeepEqual(loadedOmitted, loadedFalse) {
		t.Fatalf("omitted and explicit false must read back identically:\n got %+v\nwant %+v", loadedOmitted, loadedFalse)
	}
}

// --- 原本为 true 的规则被改成 null：即使其余字段自洽也判损坏 ---

func TestLoadReportNullReplacingTrueRequiresABICorrupt(t *testing.T) {
	dir := t.TempDir()
	withTrue := oneDefectFixture()
	withTrue.Rules[0].RequiresABI = true
	id := writeRequiresABIArchiveText(t, dir, withTrue, "inv-pass", "null")

	// null 被解码成 false 后内容本身自洽，id 也已重算匹配；仍必须拒绝。
	archiveDecodesSelfConsistently(t, dir, id, 1)
	if got, err := LoadReport(dir, id); err == nil {
		t.Fatalf("null replacing a true requiresABI must corrupt the archive: %+v", got)
	}
}

// --- 大小写变体与带空格名称中的 null 只是扩展信息，不触发错误 ---

func TestLoadReportRequiresABIVariantNullIgnored(t *testing.T) {
	anchor := `"invariant":"inv-pass","requiresABI":false`
	for _, tc := range []struct {
		name    string
		mutated string
	}{
		{"case variant after", `"invariant":"inv-pass","requiresABI":false,"RequiresABI":null`},
		{"case variant before", `"invariant":"inv-pass","RequiresABI":null,"requiresABI":false`},
		{"whitespace padded after", `"invariant":"inv-pass","requiresABI":false," requiresABI ":null`},
		{"whitespace padded before", `"invariant":"inv-pass"," requiresABI ":null,"requiresABI":false`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := writeVariantArchiveText(t, dir, oneDefectFixture(), dupOnce(anchor, tc.mutated))
			loaded, err := LoadReport(dir, id)
			if err != nil {
				t.Fatalf("a null on a variant name is extension data and must be ignored: %v", err)
			}
			if loaded.Rules[0].ID != "r-pass" || loaded.Rules[0].RequiresABI {
				t.Fatal("a variant requiresABI member must not supply the formal value")
			}
			// 与不含扩展成员的报告标识一致。
			if id != ReportID(oneDefectFixture()) {
				t.Fatal("extension members must not change the report id")
			}
		})
	}
}

// --- 正式成员为 null 时，旁边的大小写变体即使写了合法布尔值也不能挽救 ---

func TestLoadReportRequiresABIVariantCannotRescueFormalNull(t *testing.T) {
	anchor := `"invariant":"inv-pass","requiresABI":false`
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			dir := t.TempDir()
			var mutated string
			if pos == "before" {
				mutated = `"invariant":"inv-pass","RequiresABI":false,"requiresABI":null`
			} else {
				mutated = `"invariant":"inv-pass","requiresABI":null,"RequiresABI":false`
			}
			id := writeVariantArchiveText(t, dir, oneDefectFixture(), dupOnce(anchor, mutated))
			expectCorruptRequiresABILoad(t, dir, id, "r-pass")
		})
	}
}

// --- JSON 转义后恰好为 requiresABI 的名称遵守同一类型要求 ---

func TestLoadReportEscapedRequiresABINameFollowsSameRule(t *testing.T) {
	dir := t.TempDir()
	// escR 是 'r' 的 JSON Unicode 转义文本；用 Sprintf 构造，避免和源码里
	// 直接书写的成员名混淆。
	escR := fmt.Sprintf(`\u%04x`, 'r')

	// 正式名称的首字母用 Unicode 转义写出，解码后仍是 requiresABI：携带
	// null 时与直接书写的 null 一样判损坏。
	nullID := writeVariantArchiveText(t, dir, oneDefectFixture(),
		dupOnce(`"invariant":"inv-pass","requiresABI":false`,
			`"invariant":"inv-pass","`+escR+`equiresABI":null`))
	expectCorruptRequiresABILoad(t, dir, nullID, "r-pass")

	// 同一个转义名称携带 true：与直接书写 true 的报告标识一致并按 true 读回。
	withTrue := oneDefectFixture()
	withTrue.Rules[0].RequiresABI = true
	escapedTrueID := writeVariantArchiveText(t, dir, withTrue,
		dupOnce(`"invariant":"inv-pass","requiresABI":true`,
			`"invariant":"inv-pass","`+escR+`equiresABI":true`))
	plainTrueID := writeReportWithFreshID(t, t.TempDir(), withTrue)
	if escapedTrueID != plainTrueID {
		t.Fatalf("escaped and plain true must share the report id:\n%s\n%s", escapedTrueID, plainTrueID)
	}
	loaded, err := LoadReport(dir, escapedTrueID)
	if err != nil {
		t.Fatalf("an escaped formal name with a legal boolean must load: %v", err)
	}
	if !loaded.Rules[0].RequiresABI {
		t.Fatal("escaped requiresABI:true must read back as true")
	}
}

// --- 失败读取不跳过坏规则、不修复归档，重复读取结论一致 ---

func TestLoadReportBadRequiresABINoPartialResultAndArchiveUntouched(t *testing.T) {
	dir := t.TempDir()
	id := writeRequiresABIArchiveText(t, dir, oneDefectFixture(), "inv-bad", "null")
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		got, err := LoadReport(dir, id)
		if err == nil {
			t.Fatal("the archive must stay rejected, not skip the bad rule")
		}
		if !reflect.DeepEqual(got, Report{}) {
			t.Fatalf("no partial report may be returned: %+v", got)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed reads must not rewrite or repair the archive")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("failed reads must create no files, got %v", entries)
	}
}

// --- 错误三分类：requiresABI 类型错误是损坏，不与不存在/标识不合法混淆 ---

func TestLoadReportBadRequiresABIErrorClassDistinct(t *testing.T) {
	dir := t.TempDir()
	corruptID := writeRequiresABIArchiveText(t, dir, oneDefectFixture(), "inv-pass", "null")
	if _, err := LoadReport(dir, corruptID); err == nil {
		t.Fatal("expected corrupt error")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("bad requiresABI archive -> expected errCorrupt, got %T: %v", err, err)
		}
	}
	missing := strings.Repeat("0", 64)
	if _, err := LoadReport(dir, missing); err == nil {
		t.Fatal("expected not found error")
	} else {
		var enf errNotFound
		if !errors.As(err, &enf) {
			t.Fatalf("missing report -> expected errNotFound, got %T: %v", err, err)
		}
	}
	if _, err := LoadReport(dir, "xyz"); err == nil {
		t.Fatal("expected invalid id error")
	} else {
		var ei errInvalid
		if !errors.As(err, &ei) {
			t.Fatalf("invalid id -> expected errInvalid, got %T: %v", err, err)
		}
	}
}

// --- diff：任一侧归档含非布尔 requiresABI 都在比较前整体失败 ---

func TestDiffStoreRejectsBadRequiresABIEitherSide(t *testing.T) {
	dir := t.TempDir()
	goodID := writeReportWithFreshID(t, dir, oneDefectFixture())
	// 另一侧多一条合法规则，再把该规则的 requiresABI 改成 null，重算标识。
	other := oneDefectFixture()
	other.Rules = append(other.Rules,
		ReportRule{ID: "r-extra", Kind: "static", Severity: "info", Invariant: "inv-extra", Version: "9", Status: StatusPass})
	badID := writeRequiresABIArchiveText(t, dir, other, "inv-extra", "null")

	for _, tc := range []struct {
		name   string
		before string
		after  string
	}{
		{"second report corrupt", goodID, badID},
		{"first report corrupt", badID, goodID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diff, err := DiffStore(dir, tc.before, tc.after)
			if err == nil {
				t.Fatalf("diff must fail when a side carries a non-boolean requiresABI: %+v", diff)
			}
			var ec errCorrupt
			if !errors.As(err, &ec) {
				t.Fatalf("expected errCorrupt, got %T: %v", err, err)
			}
			if !reflect.DeepEqual(diff, DiffResult{}) {
				t.Fatalf("failed diff must return the zero result, got %+v", diff)
			}
			msg := err.Error()
			for _, want := range []string{badID, "r-extra", "requiresABI must be a boolean"} {
				if !strings.Contains(msg, want) {
					t.Fatalf("error %q must contain %q", msg, want)
				}
			}
		})
	}

	// 对照：同一对报告在两侧都合法时可以正常比较，证明坏归档从未被默认成
	// false 后拿去判断“规则变化/无变化”，而是在比较前就不可读。
	cleanDir := t.TempDir()
	cleanGoodID := writeReportWithFreshID(t, cleanDir, oneDefectFixture())
	cleanOther := oneDefectFixture()
	cleanOther.Rules = append(cleanOther.Rules,
		ReportRule{ID: "r-extra", Kind: "static", Severity: "info", Invariant: "inv-extra", Version: "9", Status: StatusPass})
	cleanOtherID := writeReportWithFreshID(t, cleanDir, cleanOther)
	diff, err := DiffStore(cleanDir, cleanOtherID, cleanGoodID)
	if err != nil {
		t.Fatalf("two legal archives must diff: %v", err)
	}
	if diff.Summary.RemovedRules != 1 {
		t.Fatalf("legal r-extra must compare as a removed rule, got %+v", diff.Summary)
	}
}

// --- 审计保存遇到同标识已有损坏归档：不能当成保存成功，原文件保留 ---

func TestSaveReportBadRequiresABIExistingArchiveNotTreatedAsSaved(t *testing.T) {
	dir := t.TempDir()
	id := writeRequiresABIArchiveText(t, dir, oneDefectFixture(), "inv-pass", "null")
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 提交一份与“解码后内容”标识相同的合法报告：已有归档损坏，保存必须
	// 失败而不是静默地按同标识成功，原文件原样保留。
	r := oneDefectFixture()
	r.ReportID = id
	if err := SaveReport(dir, r); err == nil {
		t.Fatal("a non-boolean requiresABI existing archive must not count as a successful save")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("expected errCorrupt, got %T: %v", err, err)
		}
		msg := err.Error()
		for _, want := range []string{id, "r-pass", "requiresABI must be a boolean"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("error %q must contain %q", msg, want)
			}
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("corrupt archive must be kept: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("failed save must leave the corrupt archive untouched")
	}
}
