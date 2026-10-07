package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护“基准报告发现缺陷，新报告规则仍在却没
// 有任何检查结论”：用户比较两份已保存的报告时，同一合约产物、同一条规则
// （标识、版本及其余定义完全一致），新报告既没有该规则的外部检查记录，也没
// 有它引用的不变式布尔值，规则状态只能是“未检查”，比较必须归为“检查状态变
// 化”，不能因为新侧没有缺陷就显示缺陷已消除。基准侧仍保留原缺陷记录（产物
// 哈希、规则版本、严重级别、不变式名称、证据均为原值），新侧保留完整规则但
// 缺陷记录为空。外部检查器反例与不变式值为 false 时生成的证据这两种缺陷来
// 源得到相同分类，外部说明中的中文、换行和前后空格逐字保留。两份报告都通过
// 真实 audit 命令落盘，再由 diff 命令读回比较，沿用既有报告格式与比较输出。

// uncheckedExternalEvidence 刻意包含中文、换行与前后空格，任何修剪、清空或
// 模板替换都会被抓到。
const uncheckedExternalEvidence = "  旧反例：未复检不能当作修复\n第二行证据  "

// auditDiffReportInv 是 auditDiffReport 的带不变式版本：同时提交 invariants
// 与 checks（二者分属引用不同不变式的规则时合法），通过真实 audit 命令落盘。
func auditDiffReportInv(t *testing.T, bin, work, store, name string, artifact cliWireArtifact,
	rules []cliWireRule, invariants map[string]bool, checks []cliWireCheck) contractsentinel.Report {
	t.Helper()
	in := cliWireInput{Artifact: artifact, Rules: rules, Invariants: invariants, Checks: checks}
	input := writeStructInput(t, work, name, in)
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit %s must succeed, exit=%d stderr=%s", name, code, stderr)
	}
	return decodeReport(t, stdout)
}

// uncheckedRule 返回两侧共用的同一条规则定义，标识、版本及其余字段一致。
func uncheckedRule(id, invariant, version string) cliWireRule {
	return cliWireRule{ID: id, Kind: "static", Severity: "high", Invariant: invariant, Version: version}
}

// TestCLIDiffDefectToUncheckedIsStatusChange 在进程边界覆盖核心口径：基准侧
// “发现缺陷”，新报告保留同一条规则但既无外部检查记录也无不变式值（状态
// “未检查”），必须归为“检查状态变化”而不是“已消除缺陷”。基准缺陷的两种
// 现有来源（外部检查器反例、invariant=false 生成证据）分类相同，旧证据逐字
// 保留，新侧缺陷记录为空。
func TestCLIDiffDefectToUncheckedIsStatusChange(t *testing.T) {
	cases := []struct {
		name         string
		ruleID       string
		invariant    string
		version      string
		useInvariant bool // true: 基准缺陷来自 invariant=false；false: 来自外部检查记录
		wantEvidence string
		wantNote     string
	}{
		{
			name:         "external checker counterexample",
			ruleID:       "reentrancy-guard",
			invariant:    "no-reentrant-withdraw",
			version:      "1.4.2",
			useInvariant: false,
			wantEvidence: uncheckedExternalEvidence,
			wantNote:     uncheckedExternalEvidence,
		},
		{
			name:         "invariant false generated evidence",
			ruleID:       "balance-monotonic",
			invariant:    "balance-monotonic",
			version:      "0.9.0",
			useInvariant: true,
			wantEvidence: "invariant balance-monotonic does not hold",
			wantNote:     "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			artifact := mixedCheckArtifact()
			hash := mixedArtifactHash(t)
			rule := uncheckedRule(tc.ruleID, tc.invariant, tc.version)

			// 基准侧带缺陷：两种来源分别构造。
			var before contractsentinel.Report
			if tc.useInvariant {
				before = auditDiffReportInv(t, bin, work, store, "before.json", artifact,
					[]cliWireRule{rule}, map[string]bool{rule.Invariant: false}, nil)
			} else {
				before = auditDiffReport(t, bin, work, store, "before.json", artifact,
					[]cliWireRule{rule},
					[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
						Status: contractsentinel.StatusDefect, Note: uncheckedExternalEvidence}})
			}
			// 新报告：规则仍在，但没有该规则的外部检查记录，invariants 中也没有
			// 它引用的不变式，因此落盘为“未检查”，且没有缺陷记录。
			after := auditDiffReportInv(t, bin, work, store, "after.json", artifact,
				[]cliWireRule{rule}, nil, nil)

			if before.ReportID == after.ReportID {
				t.Fatal("a defect report and an unchecked report must have different report ids")
			}

			stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
			if code != 0 {
				t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
			}
			d := decodeDiff(t, stdout)

			if d.Before.ReportID != before.ReportID || d.After.ReportID != after.ReportID {
				t.Errorf("refs = %q/%q", d.Before.ReportID, d.After.ReportID)
			}
			if d.ArtifactNameChanged || d.ArtifactHashChanged {
				t.Error("same artifact must not be flagged changed")
			}

			if len(d.Results) != 1 {
				t.Fatalf("results = %d, want 1", len(d.Results))
			}
			entry := d.Results[0]
			if entry.RuleID != rule.ID {
				t.Fatalf("rule id = %q, want %q", entry.RuleID, rule.ID)
			}
			if entry.Change != contractsentinel.ChangeStatusChanged {
				t.Fatalf("change = %q, want %q (a missing conclusion is not a fix)",
					entry.Change, contractsentinel.ChangeStatusChanged)
			}
			if entry.Before == nil || entry.After == nil {
				t.Fatal("a rule still present in both reports must keep both sides")
			}

			// 两侧规则定义完全一致。
			b, a := entry.Before.Rule, entry.After.Rule
			if b.Kind != a.Kind || b.Severity != a.Severity || b.Invariant != a.Invariant ||
				b.RequiresABI != a.RequiresABI || b.Version != a.Version {
				t.Errorf("rule definitions must stay identical: before=%+v after=%+v", b, a)
			}

			// 基准侧保留原缺陷记录：状态、说明与证据绑定均为原值。
			if b.Status != contractsentinel.StatusDefect {
				t.Errorf("before status = %q, want 发现缺陷", b.Status)
			}
			if b.Note != tc.wantNote {
				t.Errorf("before note = %q, want %q verbatim", b.Note, tc.wantNote)
			}
			if entry.Before.Finding == nil {
				t.Fatal("baseline side must keep its original defect finding")
			}
			bf := entry.Before.Finding
			if bf.ArtifactHash != hash || bf.RuleID != rule.ID || bf.Version != rule.Version ||
				bf.Severity != rule.Severity || bf.Invariant != rule.Invariant {
				t.Errorf("baseline finding binding = %+v", *bf)
			}
			if bf.Evidence != tc.wantEvidence {
				t.Errorf("baseline evidence = %q, want %q verbatim", bf.Evidence, tc.wantEvidence)
			}

			// 新侧规则仍在、状态“未检查”，说明为空、缺陷记录为空。
			if a.Status != contractsentinel.StatusUnchecked {
				t.Errorf("after status = %q, want 未检查 (no check record and no invariant value)", a.Status)
			}
			if a.Note != "" {
				t.Errorf("unchecked after side must carry no note, got %q", a.Note)
			}
			if entry.After.Finding != nil {
				t.Errorf("unchecked after side must carry no finding, got %+v", entry.After.Finding)
			}

			// 汇总：状态变化一条，绝不是已消除缺陷或新发现缺陷。
			s := d.Summary
			if s.StatusChanges != 1 {
				t.Errorf("statusChanges = %d, want 1", s.StatusChanges)
			}
			if s.ResolvedDefects != 0 {
				t.Errorf("resolvedDefects = %d, want 0: an unchecked rule is not a resolved defect", s.ResolvedDefects)
			}
			if s.NewDefects != 0 {
				t.Errorf("newDefects = %d, want 0", s.NewDefects)
			}
			if s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 ||
				s.RemovedRules != 0 || s.ChangedRules != 0 {
				t.Errorf("every other count must be zero: %+v", s)
			}
			if s.BeforeDefects != 1 || s.AfterDefects != 0 {
				t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
			}

			// 原始输出字节层面：外部说明的中文、换行（JSON 转义为 \n）与前后
			// 空格逐字保留，且新侧渲染为未检查而非通过。
			if !strings.Contains(stdout, `"change": "`+contractsentinel.ChangeStatusChanged+`"`) {
				t.Errorf("diff output must carry the 检查状态变化 category:\n%s", stdout)
			}
			if strings.Contains(stdout, contractsentinel.ChangeResolvedDefect) {
				t.Errorf("diff output must not label the missing conclusion as resolved:\n%s", stdout)
			}
			if !tc.useInvariant {
				escaped := strings.ReplaceAll(uncheckedExternalEvidence, "\n", `\n`)
				if !strings.Contains(stdout, escaped) {
					t.Errorf("diff output must preserve the baseline evidence verbatim:\n%s", stdout)
				}
			}
		})
	}
}

// TestCLIDiffRealFixAndUncheckedCountedPerRule 在进程边界保护真实修复与未检
// 查并存时的统计：两条引用不同不变式、定义不变的规则，基准侧两条均发现缺
// 陷；新侧一条明确通过，另一条无检查记录且无不变式值（未检查）。比较分别给
// 出“已消除缺陷”和“检查状态变化”，缺陷总数 2 -> 0，但已消除只计 1、状态变
// 化只计 1，没有新发现缺陷；每条结果携带各自规则的证据，互不相串。
func TestCLIDiffRealFixAndUncheckedCountedPerRule(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	// fixed：外部检查记录缺陷 -> 明确通过。
	fixed := uncheckedRule("fixed-reentrancy", "inv-fixed", "1.4.2")
	// skipped：invariant=false 缺陷 -> 新侧既无布尔值也无检查记录（未检查）。
	skipped := uncheckedRule("skipped-monotonic", "inv-skipped", "0.9.0")
	rules := []cliWireRule{skipped, fixed}
	skippedEvidence := "invariant " + skipped.Invariant + " does not hold"

	before := auditDiffReportInv(t, bin, work, store, "before.json", artifact, rules,
		map[string]bool{skipped.Invariant: false},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: fixed.ID, Version: fixed.Version,
			Status: contractsentinel.StatusDefect, Note: uncheckedExternalEvidence}})
	after := auditDiffReportInv(t, bin, work, store, "after.json", artifact, rules,
		nil,
		[]cliWireCheck{{ArtifactHash: hash, RuleID: fixed.ID, Version: fixed.Version,
			Status: contractsentinel.StatusPass}})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	if len(d.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(d.Results))
	}
	ids := make([]string, 0, len(d.Results))
	for _, r := range d.Results {
		ids = append(ids, r.RuleID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}

	// 明确修复的规则：已消除缺陷，基准侧只带自己的证据，通过侧无缺陷记录。
	gotFixed := diffEntry(t, d, fixed.ID)
	if gotFixed.Change != contractsentinel.ChangeResolvedDefect {
		t.Errorf("fixed change = %q, want %q", gotFixed.Change, contractsentinel.ChangeResolvedDefect)
	}
	if gotFixed.Before == nil || gotFixed.After == nil {
		t.Fatal("fixed rule must keep both sides")
	}
	if gotFixed.Before.Rule.Status != contractsentinel.StatusDefect ||
		gotFixed.After.Rule.Status != contractsentinel.StatusPass {
		t.Errorf("fixed statuses = %q/%q, want 发现缺陷/通过", gotFixed.Before.Rule.Status, gotFixed.After.Rule.Status)
	}
	if gotFixed.Before.Finding == nil || gotFixed.Before.Finding.Evidence != uncheckedExternalEvidence ||
		gotFixed.Before.Finding.RuleID != fixed.ID || gotFixed.Before.Finding.Invariant != fixed.Invariant ||
		gotFixed.Before.Finding.ArtifactHash != hash || gotFixed.Before.Finding.Version != fixed.Version {
		t.Errorf("fixed baseline must keep its own finding: %+v", gotFixed.Before.Finding)
	}
	if gotFixed.After.Finding != nil {
		t.Errorf("passing side must carry no finding: %+v", gotFixed.After.Finding)
	}

	// 缺少结论的规则：检查状态变化，基准侧保留 invariant=false 生成的证据，
	// 新侧未检查、无说明、无缺陷记录。
	gotSkipped := diffEntry(t, d, skipped.ID)
	if gotSkipped.Change != contractsentinel.ChangeStatusChanged {
		t.Errorf("skipped change = %q, want %q", gotSkipped.Change, contractsentinel.ChangeStatusChanged)
	}
	if gotSkipped.Before == nil || gotSkipped.After == nil {
		t.Fatal("a still-present unchecked rule must keep both sides")
	}
	if gotSkipped.Before.Rule.Status != contractsentinel.StatusDefect ||
		gotSkipped.After.Rule.Status != contractsentinel.StatusUnchecked {
		t.Errorf("skipped statuses = %q/%q, want 发现缺陷/未检查", gotSkipped.Before.Rule.Status, gotSkipped.After.Rule.Status)
	}
	if gotSkipped.Before.Rule.Note != "" {
		t.Errorf("invariant-form defect carries no rule note, got %q", gotSkipped.Before.Rule.Note)
	}
	if gotSkipped.Before.Finding == nil || gotSkipped.Before.Finding.Evidence != skippedEvidence ||
		gotSkipped.Before.Finding.RuleID != skipped.ID || gotSkipped.Before.Finding.Invariant != skipped.Invariant ||
		gotSkipped.Before.Finding.Severity != skipped.Severity ||
		gotSkipped.Before.Finding.ArtifactHash != hash || gotSkipped.Before.Finding.Version != skipped.Version {
		t.Errorf("skipped baseline must keep its invariant-form finding: %+v", gotSkipped.Before.Finding)
	}
	if gotSkipped.After.Rule.Note != "" {
		t.Errorf("unchecked side must carry no note, got %q", gotSkipped.After.Rule.Note)
	}
	if gotSkipped.After.Finding != nil {
		t.Errorf("unchecked side must carry no finding, got %+v", gotSkipped.After.Finding)
	}

	// 证据按规则标识各自归属，不把通过规则的结论或另一条规则的证据串过来。
	if gotFixed.Before.Finding.Evidence == skippedEvidence ||
		gotSkipped.Before.Finding.Evidence == uncheckedExternalEvidence {
		t.Error("each result must carry its own rule's evidence, not the other rule's")
	}

	// 汇总：缺陷总数 2 -> 0，但逐规则仍是已消除 1、状态变化 1，没有新缺陷。
	s := d.Summary
	if s.ResolvedDefects != 1 || s.StatusChanges != 1 {
		t.Errorf("resolved/statusChanges = %d/%d, want 1/1", s.ResolvedDefects, s.StatusChanges)
	}
	if s.NewDefects != 0 {
		t.Errorf("newDefects = %d, want 0", s.NewDefects)
	}
	if s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 ||
		s.RemovedRules != 0 || s.ChangedRules != 0 {
		t.Errorf("every other count must be zero: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0; the total drop must not replace per-rule classification",
			s.BeforeDefects, s.AfterDefects)
	}

	// 输出里两个分类各出现一次，未检查侧不携带缺陷证据。
	if !strings.Contains(stdout, contractsentinel.ChangeResolvedDefect) ||
		!strings.Contains(stdout, contractsentinel.ChangeStatusChanged) {
		t.Errorf("diff output must carry both categories:\n%s", stdout)
	}
}

// TestCLIDiffUncheckedPresentRuleIsNotRemovedRule 在进程边界区分“规则仍在但
// 未检查”与“规则被删除”：基准侧两条缺陷规则，新报告保留其中一条但没有结论
// （未检查），另一条完全不再包含。前者是“检查状态变化”，新侧为完整的未检
// 查规则；后者才是“移除规则”，新侧整体为 null。
func TestCLIDiffUncheckedPresentRuleIsNotRemovedRule(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)
	present := uncheckedRule("present-unchecked", "inv-present", "1.2.0")
	removed := uncheckedRule("gone-removed", "inv-removed", "2.3.0")
	presentEvidence := "  保留规则的旧反例\n第二行  "
	removedEvidence := "  被移除规则的旧反例\n第二行  "

	// 基准侧两条都由外部检查器判定缺陷，证据各不相同；提交顺序刻意乱序。
	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{removed, present},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: present.ID, Version: present.Version, Status: contractsentinel.StatusDefect, Note: presentEvidence},
			{ArtifactHash: hash, RuleID: removed.ID, Version: removed.Version, Status: contractsentinel.StatusDefect, Note: removedEvidence},
		})
	// 新报告只保留 present，且没有检查记录、没有不变式值 -> 未检查；removed 缺席。
	after := auditDiffReportInv(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{present}, nil, nil)

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)
	if len(d.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(d.Results))
	}

	// 仍在但未检查：检查状态变化，新侧是完整规则（未检查）而不是 null。
	gotPresent := diffEntry(t, d, present.ID)
	if gotPresent.Change != contractsentinel.ChangeStatusChanged {
		t.Errorf("present change = %q, want %q", gotPresent.Change, contractsentinel.ChangeStatusChanged)
	}
	if gotPresent.Before == nil || gotPresent.After == nil {
		t.Fatal("present unchecked rule must keep both sides")
	}
	if pa := gotPresent.After.Rule; pa.ID != present.ID || pa.Status != contractsentinel.StatusUnchecked ||
		pa.Version != present.Version || pa.Invariant != present.Invariant {
		t.Errorf("present after side = %+v, want the full identical rule with 未检查", pa)
	}
	if gotPresent.After.Finding != nil {
		t.Errorf("unchecked side must carry no finding, got %+v", gotPresent.After.Finding)
	}
	if gotPresent.Before.Finding == nil || gotPresent.Before.Finding.Evidence != presentEvidence {
		t.Errorf("present baseline must keep its own finding: %+v", gotPresent.Before.Finding)
	}

	// 完全缺席：移除规则，新侧整体 null，基准侧保留原缺陷记录。
	gotRemoved := diffEntry(t, d, removed.ID)
	if gotRemoved.Change != contractsentinel.ChangeRuleRemoved {
		t.Errorf("removed change = %q, want %q", gotRemoved.Change, contractsentinel.ChangeRuleRemoved)
	}
	if gotRemoved.After != nil {
		t.Errorf("an absent rule must render the new side null, got %+v", gotRemoved.After)
	}
	if gotRemoved.Before == nil || gotRemoved.Before.Finding == nil ||
		gotRemoved.Before.Finding.Evidence != removedEvidence {
		t.Errorf("removed baseline must keep the original defect: %+v", gotRemoved.Before)
	}

	// 两类计数各自独立：状态变化 1、移除规则 1，都不是已消除缺陷。
	s := d.Summary
	if s.StatusChanges != 1 || s.RemovedRules != 1 {
		t.Errorf("statusChanges/removedRules = %d/%d, want 1/1", s.StatusChanges, s.RemovedRules)
	}
	if s.ResolvedDefects != 0 || s.NewDefects != 0 {
		t.Errorf("neither an unchecked rule nor a removed one is a resolved defect: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0", s.BeforeDefects, s.AfterDefects)
	}

	// 字节层面：缺席新侧渲染为 null，仍在的未检查规则渲染为非 null 完整规则，
	// 两份旧证据逐字保留。
	if !strings.Contains(stdout, `"after": null`) {
		t.Errorf("removed entry must render the absent side as null:\n%s", stdout)
	}
	for _, evidence := range []string{presentEvidence, removedEvidence} {
		escaped := strings.ReplaceAll(evidence, "\n", `\n`)
		if !strings.Contains(stdout, escaped) {
			t.Errorf("diff output must preserve evidence %q verbatim:\n%s", evidence, stdout)
		}
	}
}
