package contractsentinel

import (
	"reflect"
	"strings"
	"testing"
)

// 本文件为报告标识（ReportID）补充回归保障，锁定一项已有约定：
//
//	标识只由报告内容决定，规则与缺陷的排列顺序不参与；
//	但取得标识是只读操作，绝不能反过来重排调用方手里的报告——
//	用户提交成功时保留的顺序、归档中保存的顺序，与 diff 比较结果
//	按规则标识排序是三件不同的事。
//
// 同一份合法报告在“仅排列不同”时必须给出同一标识，而任何真实内容
// 差异（规则定义、检查结论、原始说明，哪怕只是一个尾随空格）都必须
// 体现在标识中。说明与证据中的中文、换行与前后空格逐字保留。

// 顺序夹具：三条规则、两条缺陷，id 的字典序与提交刻意不一致。
//
//	提交顺序 [b, pass, a]（规则）/ [b, a]（缺陷）
//	字典顺序 [a, b, pass]（规则）/ [a, b]（缺陷）
func orderRules() []Rule {
	return []Rule{
		{ID: "r-defect-b", Kind: "static", Severity: "critical", Invariant: "inv-b", Version: "2.0"},
		{ID: "r-pass", Kind: "static", Severity: "low", Invariant: "inv-p", Version: "1.5"},
		{ID: "r-defect-a", Kind: "static", Severity: "high", Invariant: "inv-a", Version: "1.0"},
	}
}

// 说明/证据刻意包含中文、换行、制表符与前后空格；任何修剪或模板替换
// 都会让下面的逐字断言失败。
const (
	orderNoteA    = "  反例 A：重入可达\nA 第二行  "
	orderNoteB    = "\t缺陷 B：换行之后还有一行\n  B 证据尾部保留 "
	orderPassNote = " 通过说明 首行 \n 次行 "
)

// orderChecks 用规则 id 映射的方式构造检查记录；记录自身的排列也刻意
// 与规则排列不同，保证检查记录顺序同样不影响标识。
func orderChecks(hash string) []CheckRecord {
	return []CheckRecord{
		{ArtifactHash: hash, RuleID: "r-pass", Version: "1.5", Status: StatusPass, Note: orderPassNote},
		{ArtifactHash: hash, RuleID: "r-defect-a", Version: "1.0", Status: StatusDefect, Note: orderNoteA},
		{ArtifactHash: hash, RuleID: "r-defect-b", Version: "2.0", Status: StatusDefect, Note: orderNoteB},
	}
}

func assertRuleIDSequence(t *testing.T, label string, rules []ReportRule, want ...string) {
	t.Helper()
	got := make([]string, len(rules))
	for i, r := range rules {
		got[i] = r.ID
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s rule order = %v, want %v", label, got, want)
	}
}

func assertFindingRuleIDSequence(t *testing.T, label string, findings []ReportFinding, want ...string) {
	t.Helper()
	got := make([]string, len(findings))
	for i, f := range findings {
		got[i] = f.RuleID
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s finding order = %v, want %v", label, got, want)
	}
}

// assertFindingsBoundToOwnRules 校验：缺陷排在哪个位置，就携带哪个规则
// 的版本、严重级别、不变式、产物哈希与证据，证据绝不跟着位置交换。
func assertFindingsBoundToOwnRules(t *testing.T, label string, r Report, hash string) {
	t.Helper()
	noteByID := map[string]string{"r-defect-a": orderNoteA, "r-defect-b": orderNoteB}
	want := map[string]ReportFinding{}
	for _, rule := range r.Rules {
		if rule.Status != StatusDefect {
			continue
		}
		want[rule.ID] = ReportFinding{
			ArtifactHash: hash,
			RuleID:       rule.ID,
			Version:      rule.Version,
			Severity:     rule.Severity,
			Invariant:    rule.Invariant,
			Evidence:     noteByID[rule.ID],
		}
	}
	if len(r.Findings) != len(want) {
		t.Fatalf("%s: findings = %d, want %d", label, len(r.Findings), len(want))
	}
	for i, got := range r.Findings {
		w, ok := want[got.RuleID]
		if !ok {
			t.Fatalf("%s findings[%d]: unexpected finding for rule %s", label, i, got.RuleID)
		}
		if got != w {
			t.Fatalf("%s findings[%d] for rule %s lost its own binding:\n got %+v\nwant %+v",
				label, i, got.RuleID, got, w)
		}
	}
}

// --- 排列不同、内容相同：标识一致；各自的排列与归属原样保留 ---

func TestReportIDPermutationIndependent(t *testing.T) {
	hash := ArtifactHash(sampleArtifact())
	rules := orderRules()

	// 甲：规则 [b, pass, a]，检查记录 [pass, a, b]。
	rA, err := BuildReport(sampleArtifact(), []Rule{rules[0], rules[1], rules[2]}, nil, orderChecks(hash))
	if err != nil {
		t.Fatal(err)
	}
	// 乙：规则 [a, pass, b]，检查记录整体反转。
	checks := orderChecks(hash)
	reversedChecks := []CheckRecord{checks[2], checks[1], checks[0]}
	rB, err := BuildReport(sampleArtifact(), []Rule{rules[2], rules[1], rules[0]}, nil, reversedChecks)
	if err != nil {
		t.Fatal(err)
	}

	if rA.ReportID != rB.ReportID {
		t.Fatalf("permutation must keep the same id:\n A=%s\n B=%s", rA.ReportID, rB.ReportID)
	}

	// 提交成功的报告保持各自的规则排列，不按标识排序。
	assertRuleIDSequence(t, "A", rA.Rules, "r-defect-b", "r-pass", "r-defect-a")
	assertRuleIDSequence(t, "B", rB.Rules, "r-defect-a", "r-pass", "r-defect-b")
	// 缺陷排列随提交的规则排列，不被重排。
	assertFindingRuleIDSequence(t, "A", rA.Findings, "r-defect-b", "r-defect-a")
	assertFindingRuleIDSequence(t, "B", rB.Findings, "r-defect-a", "r-defect-b")

	// 同一槽位在两份排列里属于不同规则：证据跟着规则走，不跟着槽位走。
	if rA.Findings[0].RuleID != "r-defect-b" || rA.Findings[0].Evidence != orderNoteB {
		t.Fatalf("A slot 0 must belong to b: %+v", rA.Findings[0])
	}
	if rB.Findings[0].RuleID != "r-defect-a" || rB.Findings[0].Evidence != orderNoteA {
		t.Fatalf("B slot 0 must belong to a: %+v", rB.Findings[0])
	}
	assertFindingsBoundToOwnRules(t, "A", rA, hash)
	assertFindingsBoundToOwnRules(t, "B", rB, hash)
}

// 缺陷排列还可以独立于规则排列调整（归档允许任意合法排列）：只交换
// findings 切片、规则不动，标识仍必须一致。
func TestReportIDFindingsPermutedIndependently(t *testing.T) {
	hash := ArtifactHash(sampleArtifact())
	handbuilt := func(findingOrder ...string) Report {
		r := Report{
			Artifact: ReportArtifact{Name: "Vault", Hash: hash},
			Rules: []ReportRule{
				{ID: "r-defect-b", Kind: "static", Severity: "critical", Invariant: "inv-b", Version: "2.0", Status: StatusDefect, Note: orderNoteB},
				{ID: "r-pass", Kind: "static", Severity: "low", Invariant: "inv-p", Version: "1.5", Status: StatusPass, Note: orderPassNote},
				{ID: "r-defect-a", Kind: "static", Severity: "high", Invariant: "inv-a", Version: "1.0", Status: StatusDefect, Note: orderNoteA},
			},
			Findings: []ReportFinding{},
		}
		byID := map[string]ReportFinding{
			"r-defect-a": {ArtifactHash: hash, RuleID: "r-defect-a", Version: "1.0", Severity: "high", Invariant: "inv-a", Evidence: orderNoteA},
			"r-defect-b": {ArtifactHash: hash, RuleID: "r-defect-b", Version: "2.0", Severity: "critical", Invariant: "inv-b", Evidence: orderNoteB},
		}
		for _, id := range findingOrder {
			r.Findings = append(r.Findings, byID[id])
		}
		r.ReportID = ReportID(r)
		return r
	}

	rulesBA := handbuilt("r-defect-b", "r-defect-a")
	rulesAB := handbuilt("r-defect-a", "r-defect-b")
	if rulesBA.ReportID != rulesAB.ReportID {
		t.Fatalf("independent finding permutation must keep the id:\n %s\n %s", rulesBA.ReportID, rulesAB.ReportID)
	}
	assertRuleIDSequence(t, "both", rulesBA.Rules, "r-defect-b", "r-pass", "r-defect-a")
	assertFindingRuleIDSequence(t, "BA", rulesBA.Findings, "r-defect-b", "r-defect-a")
	assertFindingRuleIDSequence(t, "AB", rulesAB.Findings, "r-defect-a", "r-defect-b")
}

// --- 取得标识是只读操作：新生成的报告与读回的报告都不被重排或改写 ---

func TestReportIDComputationDoesNotMutateReport(t *testing.T) {
	hash := ArtifactHash(sampleArtifact())
	rules := orderRules()
	original, err := BuildReport(sampleArtifact(), rules, nil, orderChecks(hash))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := original // 浅拷贝即可：切片头与底层数组都不应被动到

	// 反复取得标识，包括再算一次的赋值写法。
	for i := 0; i < 3; i++ {
		original.ReportID = ReportID(original)
	}
	if !reflect.DeepEqual(original, snapshot) {
		t.Fatalf("computing the id reordered or rewrote the report:\n got %+v\nwant %+v", original, snapshot)
	}
	assertRuleIDSequence(t, "fresh", original.Rules, "r-defect-b", "r-pass", "r-defect-a")
	assertFindingRuleIDSequence(t, "fresh", original.Findings, "r-defect-b", "r-defect-a")
}

func TestReportIDOfLoadedReportDoesNotMutateOrReorder(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	rules := orderRules()
	first, err := BuildReport(sampleArtifact(), rules, nil, orderChecks(hash))
	if err != nil {
		t.Fatal(err)
	}
	// 第二份只是排列不同：同一标识，归档必须保留首次保存的排列。
	permuted, err := BuildReport(sampleArtifact(),
		[]Rule{rules[2], rules[1], rules[0]}, nil,
		[]CheckRecord{orderChecks(hash)[2], orderChecks(hash)[1], orderChecks(hash)[0]})
	if err != nil {
		t.Fatal(err)
	}
	if permuted.ReportID != first.ReportID {
		t.Fatalf("setup: permuted reports must share an id, got %s and %s", permuted.ReportID, first.ReportID)
	}
	if err := SaveReport(dir, first); err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, permuted); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadReport(dir, first.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	before := loaded
	loaded.ReportID = ReportID(loaded)
	if !reflect.DeepEqual(loaded, before) {
		t.Fatalf("computing the id of a loaded report reordered or rewrote it:\n got %+v\nwant %+v", loaded, before)
	}

	// 读回的是首次保存时的排列，而不是按标识排序、也不是后到提交的排列。
	assertRuleIDSequence(t, "loaded", loaded.Rules, "r-defect-b", "r-pass", "r-defect-a")
	assertFindingRuleIDSequence(t, "loaded", loaded.Findings, "r-defect-b", "r-defect-a")
	if !reflect.DeepEqual(loaded, first) {
		t.Fatalf("read-back must return the first saved ordering:\nloaded %+v\nfirst  %+v", loaded, first)
	}
	if ReportID(loaded) != first.ReportID {
		t.Fatalf("recomputed id %s must match the archived id %s", ReportID(loaded), first.ReportID)
	}
	assertFindingsBoundToOwnRules(t, "loaded", loaded, hash)
}

// --- 区分“排列不同”和“内容真的改变”：任何实质差异都改变标识 ---

func TestReportIDContentChangesProduceNewID(t *testing.T) {
	hash := ArtifactHash(sampleArtifact())
	base := func(rules []Rule, checks []CheckRecord) string {
		r, err := BuildReport(sampleArtifact(), rules, nil, checks)
		if err != nil {
			t.Fatal(err)
		}
		return r.ReportID
	}
	rules := orderRules()
	checks := orderChecks(hash)
	id0 := base(rules, checks)

	cases := []struct {
		name   string
		rules  []Rule
		checks []CheckRecord
	}{
		{
			name:   "rule severity changed",
			rules:  withRule(rules, "r-pass", func(r *Rule) { r.Severity = "high" }),
			checks: checks,
		},
		{
			name:   "rule version changed",
			rules:  withRule(rules, "r-defect-a", func(r *Rule) { r.Version = "1.1" }),
			checks: withCheck(checks, "r-defect-a", func(c *CheckRecord) { c.Version = "1.1" }),
		},
		{
			name:   "rule invariant changed",
			rules:  withRule(rules, "r-defect-b", func(r *Rule) { r.Invariant = "inv-b-renamed" }),
			checks: checks,
		},
		{
			name:   "pass conclusion changed to defect",
			rules:  rules,
			checks: withCheck(checks, "r-pass", func(c *CheckRecord) { c.Status = StatusDefect; c.Note = "新缺陷反例" }),
		},
		{
			name:   "pass note gains one trailing space",
			rules:  rules,
			checks: withCheck(checks, "r-pass", func(c *CheckRecord) { c.Note = orderPassNote + " " }),
		},
		{
			name:  "defect evidence loses one trailing space",
			rules: rules,
			checks: withCheck(checks, "r-defect-a", func(c *CheckRecord) {
				c.Note = strings.TrimSuffix(orderNoteA, " ")
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := base(tc.rules, tc.checks); got == id0 {
				t.Fatalf("%s must change the id, both are %s", tc.name, id0)
			}
		})
	}

	// 对照组：只调整排列，标识保持一致——上面那些差异不是“顺序噪声”造成的。
	permutedRules := []Rule{rules[2], rules[1], rules[0]}
	permutedChecks := []CheckRecord{checks[2], checks[1], checks[0]}
	if got := base(permutedRules, permutedChecks); got != id0 {
		t.Fatalf("pure permutation must keep the id %s, got %s", id0, got)
	}
}

func withRule(rules []Rule, id string, mutate func(*Rule)) []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	for i := range out {
		if out[i].ID == id {
			mutate(&out[i])
		}
	}
	return out
}

func withCheck(checks []CheckRecord, id string, mutate func(*CheckRecord)) []CheckRecord {
	out := make([]CheckRecord, len(checks))
	copy(out, checks)
	for i := range out {
		if out[i].RuleID == id {
			mutate(&out[i])
		}
	}
	return out
}

// --- 中文、换行与前后空格逐字保留，不为让标识一致而修剪文本 ---

func TestReportIDVerbatimNotesAndEvidence(t *testing.T) {
	hash := ArtifactHash(sampleArtifact())
	r, err := BuildReport(sampleArtifact(), orderRules(), nil, orderChecks(hash))
	if err != nil {
		t.Fatal(err)
	}
	noteByID := map[string]string{}
	for _, rule := range r.Rules {
		noteByID[rule.ID] = rule.Note
	}
	if noteByID["r-defect-a"] != orderNoteA {
		t.Errorf("note A = %q, want %q", noteByID["r-defect-a"], orderNoteA)
	}
	if noteByID["r-defect-b"] != orderNoteB {
		t.Errorf("note B = %q, want %q", noteByID["r-defect-b"], orderNoteB)
	}
	if noteByID["r-pass"] != orderPassNote {
		t.Errorf("pass note = %q, want %q", noteByID["r-pass"], orderPassNote)
	}
	evidenceByID := map[string]string{}
	for _, f := range r.Findings {
		evidenceByID[f.RuleID] = f.Evidence
	}
	if evidenceByID["r-defect-a"] != orderNoteA || evidenceByID["r-defect-b"] != orderNoteB {
		t.Fatalf("evidence not verbatim: %+v", evidenceByID)
	}
	// 前后空格是内容的一部分：修剪掉之后必须是另一份报告。
	trimmedChecks := withCheck(orderChecks(hash), "r-defect-a", func(c *CheckRecord) {
		c.Note = strings.TrimSpace(orderNoteA)
	})
	trimmed, err := BuildReport(sampleArtifact(), orderRules(), nil, trimmedChecks)
	if err != nil {
		t.Fatal(err)
	}
	if trimmed.ReportID == r.ReportID {
		t.Fatal("trimmed evidence must not hash alike")
	}
}

// --- 空集合：取得标识不失败；未提供集合与显式空集合在标识上等价 ---

func TestReportIDEmptyAndMissingCollectionsEquivalent(t *testing.T) {
	// BuildReport 路径：nil 与空 map/切片产出同一标识，标识非空。
	nilBuilt, err := BuildReport(sampleArtifact(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyBuilt, err := BuildReport(sampleArtifact(), []Rule{}, map[string]bool{}, []CheckRecord{})
	if err != nil {
		t.Fatal(err)
	}
	if nilBuilt.ReportID == "" {
		t.Fatal("empty report still needs an id")
	}
	if nilBuilt.ReportID != emptyBuilt.ReportID {
		t.Fatalf("nil and empty collections must hash alike:\n nil=%s\n empty=%s", nilBuilt.ReportID, emptyBuilt.ReportID)
	}

	// 直接取得标识：nil 切片与空切片规范形式相同，均不因空集合失败。
	hash := ArtifactHash(sampleArtifact())
	nilReport := Report{Artifact: ReportArtifact{Name: "Vault", Hash: hash}}
	emptyReport := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules:    []ReportRule{}, Findings: []ReportFinding{},
	}
	nilReport.ReportID = ReportID(nilReport)
	emptyReport.ReportID = ReportID(emptyReport)
	if nilReport.ReportID != emptyReport.ReportID {
		t.Fatalf("nil and empty slices must hash alike: %s vs %s", nilReport.ReportID, emptyReport.ReportID)
	}

	// 空报告同样可以归档并按标识读回，空集合不影响校验与读取。
	dir := t.TempDir()
	emptyBuilt.ReportID = ReportID(emptyBuilt)
	if err := SaveReport(dir, emptyBuilt); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, emptyBuilt.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ReportID != emptyBuilt.ReportID || len(loaded.Rules) != 0 || len(loaded.Findings) != 0 {
		t.Fatalf("empty report round trip mismatch: %+v", loaded)
	}
}

// --- 既有约定：规则说明省略 == 显式空字符串；不得推广到非空说明 ---

func TestReportIDOmittedNoteEqualsEmptyStringOnly(t *testing.T) {
	hash := ArtifactHash(sampleArtifact())
	reportWithNote := func(note string, present bool) Report {
		rule := ReportRule{ID: "r1", Kind: "static", Severity: "low", Invariant: "inv", Version: "1", Status: StatusPass}
		if present {
			rule.Note = note
		}
		r := Report{
			Artifact: ReportArtifact{Name: "Vault", Hash: hash},
			Rules:    []ReportRule{rule},
			Findings: []ReportFinding{},
		}
		r.ReportID = ReportID(r)
		return r
	}

	omitted := reportWithNote("", false)
	emptyString := reportWithNote("", true)
	if omitted.ReportID != emptyString.ReportID {
		t.Fatalf("omitted note and explicit \"\" must share the id:\n %s\n %s", omitted.ReportID, emptyString.ReportID)
	}

	// 同标识约定只适用于空说明：非空文本、哪怕全是空白，也是不同内容。
	for _, note := range []string{"x", " ", "\n", "\t "} {
		nonEmpty := reportWithNote(note, true)
		if nonEmpty.ReportID == omitted.ReportID {
			t.Fatalf("non-empty note %q must not share the omitted-note id", note)
		}
	}
}

// --- 兼容锁定：既有合法报告的标识不随本次保障改变 ---
//
// 下列两个标识是当前规范形式（canonicalReport 的 JSON 经 SHA-256）对固定
// 夹具的输出。历史归档无需迁移，任何对规范形式的无意改动（就地排序、
// 修剪文本、改动字段集合等）都会先让这里失败。

func TestReportIDCanonicalFormCompatibilityPins(t *testing.T) {
	hash := ArtifactHash(sampleArtifact())
	empty := Report{Artifact: ReportArtifact{Name: "Vault", Hash: hash}}
	empty.ReportID = ReportID(empty)
	const wantEmpty = "5454aea6e460eb73605a9f4065561ff0030026e22c9876c5d202260ab66e6ba8"

	full := Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: hash},
		Rules: []ReportRule{
			{ID: "r-defect-b", Kind: "static", Severity: "critical", Invariant: "inv-b", RequiresABI: false, Version: "2.0", Status: StatusDefect, Note: orderNoteB},
			{ID: "r-pass", Kind: "static", Severity: "low", Invariant: "inv-p", Version: "1.5", Status: StatusPass, Note: orderPassNote},
			{ID: "r-defect-a", Kind: "static", Severity: "high", Invariant: "inv-a", Version: "1.0", Status: StatusDefect, Note: orderNoteA},
		},
		Findings: []ReportFinding{
			{ArtifactHash: hash, RuleID: "r-defect-b", Version: "2.0", Severity: "critical", Invariant: "inv-b", Evidence: orderNoteB},
			{ArtifactHash: hash, RuleID: "r-defect-a", Version: "1.0", Severity: "high", Invariant: "inv-a", Evidence: orderNoteA},
		},
	}
	full.ReportID = ReportID(full)
	const wantFull = "081dd84e36a56f5a8661316da0054de23d31c8776194298d8e0183eb0a466253"

	if empty.ReportID != wantEmpty || full.ReportID != wantFull {
		t.Fatalf("canonical ids drifted:\n empty=%s want=%s\n full=%s want=%s",
			empty.ReportID, wantEmpty, full.ReportID, wantFull)
	}
}
