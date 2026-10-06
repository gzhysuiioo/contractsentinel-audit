package contractsentinel

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// 本文件回归保护报告标识（reportId）的一项既有约定，三条行为必须同时成立、
// 互不越界：
//
//  1. 标识只由报告内容确定：规则与缺陷怎样排列都不影响标识（规则数组、
//     checks 数组、findings 数组的排列都是“排列不同、内容相同”）；
//  2. 取得标识不改变报告本身：提交成功的报告保留提交时的规则与缺陷顺序，
//     归档读回的报告保留归档中的顺序；比较结果按规则标识排序是 diff 自己
//     的行为，不能反过来重排任何一份报告；
//  3. 排列无关不等于内容无关：规则定义、检查结论、原始说明（含证据）只要
//     真的改变，标识就必须改变——一条已通过规则的说明仅多出一个尾随空格
//     也是另一份报告。说明与证据中的中文、换行与前后空格逐字保留，不能为
//     了让标识一致而修剪或改写。
//
// 用例刻意使用多条规则、至少两条缺陷，并让提交顺序与按规则标识排序的顺序
// 不同，使“偷偷排序”与“保持原序”都能被直接观察到。

// orderReportNotes 携带中文、换行与前后空格；任何修剪、模板改写或随位置
// 交换都会被逐字比较抓到。
const (
	orderEvidenceA = "  缺陷一证据：越权调用\n  第二行  "
	orderEvidenceC = "  缺陷三证据：重入攻击\n  第二行  "
	orderPassNote  = " 通过说明：首行\n  末行 "
)

// orderRules 返回三条规则，调用方通过 perm 给出排列；规则标识的字典序为
// r01 < r02 < r03，与下方刻意使用的提交顺序不同。
func orderRules(perm ...int) []Rule {
	all := []Rule{
		{ID: "r01", Kind: "static", Severity: "low", Invariant: "inv-a", RequiresABI: true, Version: "1.0.0"},
		{ID: "r02", Kind: "symbolic", Severity: "medium", Invariant: "inv-b", Version: "2.0.0"},
		{ID: "r03", Kind: "static", Severity: "high", Invariant: "inv-c", Version: "3.0.0"},
	}
	out := make([]Rule, 0, len(perm))
	for _, i := range perm {
		out = append(out, all[i])
	}
	return out
}

// orderCheckFor 生成一条规则的外部检查记录：r01、r03 发现缺陷（各自携带
// 逐字证据），r02 通过（带含空白与换行的说明）。
func orderCheckFor(hash string, id string) CheckRecord {
	switch id {
	case "r01":
		return CheckRecord{ArtifactHash: hash, RuleID: id, Version: "1.0.0", Status: StatusDefect, Note: orderEvidenceA}
	case "r02":
		return CheckRecord{ArtifactHash: hash, RuleID: id, Version: "2.0.0", Status: StatusPass, Note: orderPassNote}
	case "r03":
		return CheckRecord{ArtifactHash: hash, RuleID: id, Version: "3.0.0", Status: StatusDefect, Note: orderEvidenceC}
	}
	return CheckRecord{}
}

func orderChecks(hash string, perm ...int) []CheckRecord {
	ids := []string{"r01", "r02", "r03"}
	out := make([]CheckRecord, 0, len(perm))
	for _, i := range perm {
		out = append(out, orderCheckFor(hash, ids[i]))
	}
	return out
}

// mutateRule 在规则切片中按标识找到一条规则并就地修改，避免用例把排列
// 位置误当成规则标识。
func mutateRule(rules []Rule, id string, fn func(*Rule)) {
	for i := range rules {
		if rules[i].ID == id {
			fn(&rules[i])
			return
		}
	}
}

// mutateCheck 是 checks 记录的按标识修改版本。
func mutateCheck(checks []CheckRecord, id string, fn func(*CheckRecord)) {
	for i := range checks {
		if checks[i].RuleID == id {
			fn(&checks[i])
			return
		}
	}
}

func reportRuleIDs(r Report) []string {
	ids := make([]string, len(r.Rules))
	for i, rule := range r.Rules {
		ids[i] = rule.ID
	}
	return ids
}

func reportFindingRuleIDs(r Report) []string {
	ids := make([]string, len(r.Findings))
	for i, f := range r.Findings {
		ids[i] = f.RuleID
	}
	return ids
}

func assertIDSequence(t *testing.T, where string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s order = %v, want %v", where, got, want)
	}
}

// assertFindingBindings 逐规则核对缺陷仍绑定自己的规则版本、产物哈希、严重
// 级别、不变式与逐字证据——证据不能跟着缺陷在数组中的位置交换。
func assertFindingBindings(t *testing.T, r Report, hash string) {
	t.Helper()
	want := map[string]struct {
		version, severity, invariant, evidence string
	}{
		"r01": {"1.0.0", "low", "inv-a", orderEvidenceA},
		"r03": {"3.0.0", "high", "inv-c", orderEvidenceC},
	}
	byID := make(map[string]ReportFinding, len(r.Findings))
	for _, f := range r.Findings {
		byID[f.RuleID] = f
	}
	if len(byID) != len(r.Findings) {
		t.Fatalf("findings contain a duplicated rule id: %v", reportFindingRuleIDs(r))
	}
	for id, w := range want {
		f, ok := byID[id]
		if !ok {
			t.Fatalf("missing finding for %s", id)
		}
		if f.ArtifactHash != hash {
			t.Errorf("finding %s artifact hash = %q, want %q", id, f.ArtifactHash, hash)
		}
		if f.Version != w.version {
			t.Errorf("finding %s version = %q, want %q", id, f.Version, w.version)
		}
		if f.Severity != w.severity {
			t.Errorf("finding %s severity = %q, want %q", id, f.Severity, w.severity)
		}
		if f.Invariant != w.invariant {
			t.Errorf("finding %s invariant = %q, want %q", id, f.Invariant, w.invariant)
		}
		if f.Evidence != w.evidence {
			t.Errorf("finding %s evidence = %q, want verbatim %q", id, f.Evidence, w.evidence)
		}
	}
	for _, rule := range r.Rules {
		switch rule.ID {
		case "r02":
			if rule.Note != orderPassNote {
				t.Errorf("rule r02 note = %q, want verbatim %q", rule.Note, orderPassNote)
			}
		case "r01":
			if rule.Note != orderEvidenceA {
				t.Errorf("rule r01 note = %q, want verbatim %q", rule.Note, orderEvidenceA)
			}
		case "r03":
			if rule.Note != orderEvidenceC {
				t.Errorf("rule r03 note = %q, want verbatim %q", rule.Note, orderEvidenceC)
			}
		}
	}
}

// TestReportIDIgnoresRuleAndFindingPermutation 同一份合法报告（多条规则、
// 两条缺陷）分别调整规则数组和 checks 数组的排列后，构建出的两份报告缺陷
// 顺序也随之不同，但报告标识必须一致。
func TestReportIDIgnoresRuleAndFindingPermutation(t *testing.T) {
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)

	// 提交顺序刻意与 r01<r02<r03 的字典序不同；findings 随规则迭代生成，
	// 因此两份报告的缺陷顺序分别为 r03,r01 与 r01,r03。
	first, err := BuildReport(artifact, orderRules(2, 0, 1), nil, orderChecks(hash, 2, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildReport(artifact, orderRules(0, 1, 2), nil, orderChecks(hash, 1, 2, 0))
	if err != nil {
		t.Fatal(err)
	}
	assertIDSequence(t, "first rules", reportRuleIDs(first), []string{"r03", "r01", "r02"})
	assertIDSequence(t, "first findings", reportFindingRuleIDs(first), []string{"r03", "r01"})
	assertIDSequence(t, "second rules", reportRuleIDs(second), []string{"r01", "r02", "r03"})
	assertIDSequence(t, "second findings", reportFindingRuleIDs(second), []string{"r01", "r03"})

	if first.ReportID != second.ReportID {
		t.Fatalf("permuting rules and findings must not change the id:\n%q\n%q", first.ReportID, second.ReportID)
	}
	if got := ReportID(first); got != first.ReportID {
		t.Fatalf("ReportID not deterministic: %q vs %q", got, first.ReportID)
	}
	// 即使只重排 checks（规则顺序不动），标识同样不变。
	third, err := BuildReport(artifact, orderRules(2, 0, 1), nil, orderChecks(hash, 0, 2, 1))
	if err != nil {
		t.Fatal(err)
	}
	if third.ReportID != first.ReportID {
		t.Fatal("check record order must not affect the id")
	}
	assertFindingBindings(t, first, hash)
	assertFindingBindings(t, second, hash)
}

// TestReportIDNeverReordersFreshReport 对刚生成的报告取得标识（包括直接
// 调用内部 canonicalize）后，规则顺序、缺陷顺序及每条记录的内容都必须与
// 取得标识前逐字段相同：计算标识时忽略顺序只能发生在副本上。
func TestReportIDNeverReordersFreshReport(t *testing.T) {
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	report, err := BuildReport(artifact, orderRules(2, 0, 1), nil, orderChecks(hash, 2, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := report

	_ = ReportID(report)
	canonical := canonicalize(report)
	_ = ReportID(report)

	if !reflect.DeepEqual(report, snapshot) {
		t.Fatalf("computing the id reordered the report:\nbefore=%+v\nafter =%+v", snapshot, report)
	}
	assertIDSequence(t, "rules after ReportID", reportRuleIDs(report), []string{"r03", "r01", "r02"})
	assertIDSequence(t, "findings after ReportID", reportFindingRuleIDs(report), []string{"r03", "r01"})
	// 规范形自身按标识排序，但那只用于求标识。
	canonicalRuleIDs := make([]string, len(canonical.Rules))
	for i, r := range canonical.Rules {
		canonicalRuleIDs[i] = r.ID
	}
	if !sort.StringsAreSorted(canonicalRuleIDs) {
		t.Fatalf("canonical rules must be sorted: %v", canonicalRuleIDs)
	}
	assertFindingBindings(t, report, hash)
}

// TestLoadedReportKeepsArchiveOrderAfterRecomputingID 从归档读回的报告，
// 在读回后再次取得标识，顺序与内容都必须保持归档原样；读回重算的标识与
// 归档标识相符。
func TestLoadedReportKeepsArchiveOrderAfterRecomputingID(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	report, err := BuildReport(artifact, orderRules(2, 0, 1), nil, orderChecks(hash, 2, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := loaded
	if got := ReportID(loaded); got != report.ReportID {
		t.Fatalf("recomputed id = %q, want archive id %q", got, report.ReportID)
	}
	if !reflect.DeepEqual(loaded, snapshot) {
		t.Fatalf("recomputing the id on a loaded report reordered it:\nbefore=%+v\nafter =%+v", snapshot, loaded)
	}
	assertIDSequence(t, "loaded rules", reportRuleIDs(loaded), []string{"r03", "r01", "r02"})
	assertIDSequence(t, "loaded findings", reportFindingRuleIDs(loaded), []string{"r03", "r01"})
	if !reflect.DeepEqual(loaded, report) {
		t.Fatalf("loaded report differs from the first saved report:\n%+v\n%+v", loaded, report)
	}
	assertFindingBindings(t, loaded, hash)
}

// TestFirstSavedOrderWinsUnderPermutation 首次保存一份合法报告后，再以不同
// 排列提交同一内容（同一标识），读回应看到首次保存时的顺序，归档字节不被
// 替换；比较用的按标识排序不能影响任何一份归档。
func TestFirstSavedOrderWinsUnderPermutation(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	first, err := BuildReport(artifact, orderRules(2, 0, 1), nil, orderChecks(hash, 2, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, first); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, first.ReportID+".json")
	firstBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildReport(artifact, orderRules(0, 2, 1), nil, orderChecks(hash, 0, 2, 1))
	if err != nil {
		t.Fatal(err)
	}
	if second.ReportID != first.ReportID {
		t.Fatal("permutation must keep the same id")
	}
	if err := SaveReport(dir, second); err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("the permuted resubmission replaced the first archive bytes")
	}
	loaded, err := LoadReport(dir, first.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	assertIDSequence(t, "loaded rules", reportRuleIDs(loaded), []string{"r03", "r01", "r02"})
	assertIDSequence(t, "loaded findings", reportFindingRuleIDs(loaded), []string{"r03", "r01"})

	// Diff 的结果按规则标识排序，但它不得重排两侧报告本身。
	other, err := BuildReport(artifact, orderRules(1, 2, 0), nil, orderChecks(hash, 1, 2, 0))
	if err != nil {
		t.Fatal(err)
	}
	diff := DiffReports(loaded, other)
	gotIDs := make([]string, len(diff.Results))
	for i, res := range diff.Results {
		gotIDs[i] = res.RuleID
	}
	assertIDSequence(t, "diff results", gotIDs, []string{"r01", "r02", "r03"})
	assertIDSequence(t, "loaded rules after diff", reportRuleIDs(loaded), []string{"r03", "r01", "r02"})
	assertIDSequence(t, "other rules after diff", reportRuleIDs(other), []string{"r02", "r03", "r01"})
	assertIDSequence(t, "loaded findings after diff", reportFindingRuleIDs(loaded), []string{"r03", "r01"})
}

// TestReportIDDistinguishesContentChanges 排列无关不能被推广成内容无关：
// 规则定义、检查结论或原始说明的任何真实改变都必须体现在标识中。
func TestReportIDDistinguishesContentChanges(t *testing.T) {
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	base, err := BuildReport(artifact, orderRules(2, 0, 1), nil, orderChecks(hash, 2, 0, 1))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		// mutate 返回一份“只改变一处真实内容”的提交要素。
		build func() (Report, error)
	}{
		{"rule severity", func() (Report, error) {
			rules := orderRules(2, 0, 1)
			mutateRule(rules, "r01", func(r *Rule) { r.Severity = "critical" })
			return BuildReport(artifact, rules, nil, orderChecks(hash, 2, 0, 1))
		}},
		{"rule version", func() (Report, error) {
			rules := orderRules(2, 0, 1)
			mutateRule(rules, "r01", func(r *Rule) { r.Version = "1.0.1" })
			checks := orderChecks(hash, 2, 0, 1)
			mutateCheck(checks, "r01", func(c *CheckRecord) { c.Version = "1.0.1" })
			return BuildReport(artifact, rules, nil, checks)
		}},
		{"rule kind", func() (Report, error) {
			rules := orderRules(2, 0, 1)
			mutateRule(rules, "r01", func(r *Rule) { r.Kind = "symbolic" })
			return BuildReport(artifact, rules, nil, orderChecks(hash, 2, 0, 1))
		}},
		{"rule invariant", func() (Report, error) {
			rules := orderRules(2, 0, 1)
			mutateRule(rules, "r02", func(r *Rule) { r.Invariant = "inv-b-v2" })
			return BuildReport(artifact, rules, nil, orderChecks(hash, 2, 0, 1))
		}},
		{"check status pass to timeout", func() (Report, error) {
			checks := orderChecks(hash, 2, 0, 1)
			mutateCheck(checks, "r02", func(c *CheckRecord) {
				c.Status = StatusTimeout
				c.Note = "超过 300s 截止时间，未得到结论"
			})
			return BuildReport(artifact, orderRules(2, 0, 1), nil, checks)
		}},
		{"defect evidence extended", func() (Report, error) {
			checks := orderChecks(hash, 2, 0, 1)
			mutateCheck(checks, "r03", func(c *CheckRecord) { c.Note = orderEvidenceC + "追加一句" })
			return BuildReport(artifact, orderRules(2, 0, 1), nil, checks)
		}},
		{"pass note gains one trailing space", func() (Report, error) {
			checks := orderChecks(hash, 2, 0, 1)
			mutateCheck(checks, "r02", func(c *CheckRecord) { c.Note = orderPassNote + " " })
			return BuildReport(artifact, orderRules(2, 0, 1), nil, checks)
		}},
		{"pass note loses trailing whitespace", func() (Report, error) {
			checks := orderChecks(hash, 2, 0, 1)
			mutateCheck(checks, "r02", func(c *CheckRecord) { c.Note = " 通过说明：首行\n  末行" })
			return BuildReport(artifact, orderRules(2, 0, 1), nil, checks)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := tc.build()
			if err != nil {
				t.Fatal(err)
			}
			if changed.ReportID == base.ReportID {
				t.Fatalf("a real content change (%s) must produce a new id; both = %q", tc.name, base.ReportID)
			}
		})
	}
}

// TestPassNoteTrailingSpaceEndToEnd 单条已通过规则的说明仅增加一个尾随
// 空格时，保存与读回都必须把两份报告视为不同内容：文件名不同、读回标识
// 各自相符，带空格的说明逐字读回。
func TestPassNoteTrailingSpaceEndToEnd(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := []Rule{{ID: "r01", Kind: "static", Severity: "low", Invariant: "inv-a", RequiresABI: true, Version: "1.0.0"}}
	build := func(note string) Report {
		report, err := BuildReport(artifact, rules, nil, []CheckRecord{
			{ArtifactHash: hash, RuleID: "r01", Version: "1.0.0", Status: StatusPass, Note: note},
		})
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	plain := build("检查通过")
	spaced := build("检查通过 ")
	if plain.ReportID == spaced.ReportID {
		t.Fatal("a single trailing space in a pass note must change the id")
	}
	if err := SaveReport(dir, plain); err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, spaced); err != nil {
		t.Fatal(err)
	}
	for _, want := range []Report{plain, spaced} {
		got, err := LoadReport(dir, want.ReportID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Rules[0].Note != want.Rules[0].Note {
			t.Fatalf("note = %q, want verbatim %q", got.Rules[0].Note, want.Rules[0].Note)
		}
	}
}

// TestEmptyAndMissingCollectionsEquivalent 没有规则或没有缺陷的合法报告
// 保持原有结果：空集合不能使取得标识失败；未提供集合（nil）与提供空集合
// 在标识上等价，并能正常保存、读回。
func TestEmptyAndMissingCollectionsEquivalent(t *testing.T) {
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	art := ReportArtifact{Name: artifact.Name, Hash: hash}

	// ReportID 层面：nil 切片与空切片同标识。
	nilReport := Report{Artifact: art}
	emptyReport := Report{Artifact: art, Rules: []ReportRule{}, Findings: []ReportFinding{}}
	if ReportID(nilReport) != ReportID(emptyReport) {
		t.Fatal("nil and empty collections must hash alike")
	}
	if ReportID(nilReport) == "" {
		t.Fatal("a report without rules or findings still needs an id")
	}

	// BuildReport 层面：省略 rules/checks 与显式空集合等价。
	builtNil, err := BuildReport(artifact, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	builtEmpty, err := BuildReport(artifact, []Rule{}, map[string]bool{}, []CheckRecord{})
	if err != nil {
		t.Fatal(err)
	}
	if builtNil.ReportID != builtEmpty.ReportID {
		t.Fatal("omitted and explicit empty collections must hash alike")
	}

	// 空报告与“只有通过规则、没有缺陷”的报告都能保存和原样读回。
	for _, report := range []Report{builtNil, builtEmpty} {
		dir := t.TempDir()
		if err := SaveReport(dir, report); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadReport(dir, report.ReportID)
		if err != nil {
			t.Fatal(err)
		}
		if len(loaded.Rules) != 0 || len(loaded.Findings) != 0 {
			t.Fatalf("empty report must load empty, got rules=%d findings=%d", len(loaded.Rules), len(loaded.Findings))
		}
		if ReportID(loaded) != report.ReportID {
			t.Fatal("loaded empty report id mismatch")
		}
	}

	passOnly, err := BuildReport(artifact,
		[]Rule{{ID: "r01", Kind: "static", Severity: "low", Invariant: "inv-a", Version: "1.0.0"}},
		nil,
		[]CheckRecord{{ArtifactHash: hash, RuleID: "r01", Version: "1.0.0", Status: StatusPass}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(passOnly.Findings) != 0 {
		t.Fatalf("a pass-only report must carry no findings: %+v", passOnly.Findings)
	}
	dir := t.TempDir()
	if err := SaveReport(dir, passOnly); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, passOnly.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Findings) != 0 || loaded.Rules[0].Status != StatusPass {
		t.Fatalf("pass-only report changed on load: %+v", loaded)
	}
}

// TestOmittedAndEmptyNoteShareIDDistinguishesNonEmpty 规则说明省略与明确
// 写成空字符串沿用既有同标识约定（canonical 中 note 的 omitempty），但该
// 约定不能推广到非空说明：归档里省略 note、写 "note":"" 与写 "note":"x"
// 三种写法只有前两种同标识。
func TestOmittedAndEmptyNoteShareIDDistinguishesNonEmpty(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)
	rules := []Rule{{ID: "r01", Kind: "static", Severity: "low", Invariant: "inv-a", Version: "1.0.0"}}
	noNote, err := BuildReport(artifact, rules, nil, []CheckRecord{
		{ArtifactHash: hash, RuleID: "r01", Version: "1.0.0", Status: StatusPass},
	})
	if err != nil {
		t.Fatal(err)
	}
	emptyNote, err := BuildReport(artifact, rules, nil, []CheckRecord{
		{ArtifactHash: hash, RuleID: "r01", Version: "1.0.0", Status: StatusPass, Note: ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	nonEmptyNote, err := BuildReport(artifact, rules, nil, []CheckRecord{
		{ArtifactHash: hash, RuleID: "r01", Version: "1.0.0", Status: StatusPass, Note: "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if noNote.ReportID != emptyNote.ReportID {
		t.Fatal("an omitted note and an explicit empty-string note must share the id")
	}
	if nonEmptyNote.ReportID == noNote.ReportID {
		t.Fatal("a non-empty note must not be laundered into an omitted note")
	}

	// 归档层面：把省略 note 的归档改写为显式 "note":""，仍必须按同一标识
	// 合法读回，且与原报告逐字段相同。
	if err := SaveReport(dir, noNote); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, noNote.ReportID+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// json.Marshal 按结构体字段序输出，note 是最后一个字段，省略时规则
	// 对象以 "status":"通过"} 结尾；只在该处插入显式空字符串说明。
	marker := []byte(`"status":"通过"}`)
	withEmptyNote := bytes.Replace(raw, marker, []byte(`"status":"通过","note":""}`), 1)
	if string(withEmptyNote) == string(raw) {
		t.Fatal("test setup: archive did not contain the expected pass rule")
	}
	if err := os.WriteFile(path, withEmptyNote, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, noNote.ReportID)
	if err != nil {
		t.Fatalf("an explicit empty-string note must load as the omitted note: %v", err)
	}
	if !reflect.DeepEqual(loaded, noNote) {
		t.Fatalf("empty-note archive must equal the omitted-note report:\n%+v\n%+v", loaded, noNote)
	}

	// 反过来：非空说明的归档不能冒充无说明报告。
	data, err := json.Marshal(nonEmptyNote)
	if err != nil {
		t.Fatal(err)
	}
	otherDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(otherDir, noNote.ReportID+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(otherDir, noNote.ReportID); err == nil {
		t.Fatal("a non-empty-note archive stored under the no-note id must fail the content check")
	}
}
