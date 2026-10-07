package main

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

// 本文件在真实命令行进程边界上回归保护一项比较口径：基准报告曾对某条规则发现
// 缺陷，新报告仍包含同一条规则（标识、版本、检查种类、严重级别、引用的不变式
// 与 ABI 要求完全一致），但这次既没有该规则的外部检查记录，也没有它引用的
// 不变式布尔值。该规则的状态只能是“未检查”，diff 不能把它渲染成“通过”，也
// 不能仅凭缺陷总数下降就输出“已消除缺陷”：它必须归为“检查状态变化”，前后两
// 侧都保留完整规则，基准侧保留原缺陷记录，新侧缺陷记录为 null。
//
// 基准缺陷的两种既有来源——外部检查器的反例说明、不变式 false 生成的证据——
// 必须得到相同分类。同一份比较中真实修复（缺陷 -> 明确通过）与未检查并存时，
// 已消除缺陷与检查状态变化各计其一。规则被完全删除仍是“移除规则”，新侧整体
// 为 null，不能与规则仍在但未检查的结果混淆。
//
// 两份报告都通过真实 audit 命令归档，再由真实 diff 命令读回比较，沿用既有报告
// 格式、报告标识与比较输出。

// uncheckedCLIEvidence 刻意包含中文、换行与前后空格，任何修剪、清空或模板替
// 换都会被抓到。
const uncheckedCLIEvidence = "  旧反例：该规则本次未安排复跑\n  callvalue 跨调用余额仍可污染  "

// uncheckedCLIRule 是前后两份报告共用的规则定义。
func uncheckedCLIRule() cliWireRule {
	return cliWireRule{
		ID:        "unchecked-reentrancy",
		Kind:      "static",
		Severity:  "high",
		Invariant: "unchecked-reentrant-withdraw",
		Version:   "5.2.0",
	}
}

// auditDiffReportWith 用给定规则、不变式布尔值与检查记录通过真实 audit 命令
// 落盘一份报告并解码返回。
func auditDiffReportWith(t *testing.T, bin, work, store, name string,
	artifact cliWireArtifact, rules []cliWireRule, invariants map[string]bool, checks []cliWireCheck) contractsentinel.Report {
	t.Helper()
	in := cliWireInput{Artifact: artifact, Rules: rules, Invariants: invariants, Checks: checks}
	input := writeStructInput(t, work, name, in)
	stdout, stderr, code := runCLIAudit(t, bin, input, store)
	if code != 0 {
		t.Fatalf("setup audit %s must succeed, exit=%d stderr=%s", name, code, stderr)
	}
	return decodeReport(t, stdout)
}

// TestCLIDiffDefectToUncheckedIsStatusChange 进程边界核心用例：两种基准缺陷
// 来源面对“规则仍在但本次未检查”的新报告，都必须输出“检查状态变化”。
func TestCLIDiffDefectToUncheckedIsStatusChange(t *testing.T) {
	cases := []struct {
		name       string
		baseline   func(t *testing.T, bin, work, store string, artifact cliWireArtifact, hash string, rule cliWireRule) contractsentinel.Report
		evidence   string
		beforeNote string
	}{
		{
			name: "external checker counterexample",
			baseline: func(t *testing.T, bin, work, store string, artifact cliWireArtifact, hash string, rule cliWireRule) contractsentinel.Report {
				return auditDiffReport(t, bin, work, store, "before.json", artifact, []cliWireRule{rule},
					[]cliWireCheck{{ArtifactHash: hash, RuleID: rule.ID, Version: rule.Version,
						Status: contractsentinel.StatusDefect, Note: uncheckedCLIEvidence}})
			},
			evidence:   uncheckedCLIEvidence,
			beforeNote: uncheckedCLIEvidence,
		},
		{
			name: "invariant false generated evidence",
			baseline: func(t *testing.T, bin, work, store string, artifact cliWireArtifact, hash string, rule cliWireRule) contractsentinel.Report {
				// 只有不变式值 false、没有外部检查记录：证据由报告按不变式名生成。
				return auditDiffReportWith(t, bin, work, store, "before.json", artifact, []cliWireRule{rule},
					map[string]bool{rule.Invariant: false}, nil)
			},
			evidence:   "invariant unchecked-reentrant-withdraw does not hold",
			beforeNote: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := auditBinary(t)
			work := t.TempDir()
			store := filepath.Join(work, "reports")
			artifact := mixedCheckArtifact()
			hash := mixedArtifactHash(t)
			rule := uncheckedCLIRule()

			before := tc.baseline(t, bin, work, store, artifact, hash, rule)
			// 新报告：规则定义原样保留，但没有检查记录，invariants 中也没有该规
			// 则引用的不变式（只放一个无关名字）-> 未检查、无缺陷记录。
			after := auditDiffReportWith(t, bin, work, store, "after.json", artifact, []cliWireRule{rule},
				map[string]bool{"some-other-invariant": true}, nil)

			// 归档读回：基准侧一条真实缺陷，新侧没有缺陷记录。
			reloadedBefore, err := contractsentinel.LoadReport(store, before.ReportID)
			if err != nil {
				t.Fatalf("load before: %v", err)
			}
			reloadedAfter, err := contractsentinel.LoadReport(store, after.ReportID)
			if err != nil {
				t.Fatalf("load after: %v", err)
			}
			if len(reloadedBefore.Findings) != 1 || reloadedBefore.Findings[0].RuleID != rule.ID {
				t.Fatalf("baseline findings = %+v", reloadedBefore.Findings)
			}
			if len(reloadedAfter.Findings) != 0 || reloadedAfter.Rules[0].Status != contractsentinel.StatusUnchecked {
				t.Fatalf("new report must have no findings and an unchecked rule: %+v", reloadedAfter)
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
				t.Fatalf("results = %d, want 1: %+v", len(d.Results), d.Results)
			}
			entry := d.Results[0]
			if entry.RuleID != rule.ID || entry.Change != contractsentinel.ChangeStatusChanged {
				t.Fatalf("entry = %q/%q, want %q/%q", entry.RuleID, entry.Change, rule.ID, contractsentinel.ChangeStatusChanged)
			}

			// 前后两侧都是完整规则；基准侧保留原状态、说明与缺陷记录，新侧为未
			// 检查且缺陷记录为 null（不是整个侧为 null）。
			if entry.Before == nil || entry.After == nil {
				t.Fatal("a rule present in both reports must keep both sides")
			}
			if br := entry.Before.Rule; br.ID != rule.ID || br.Version == "" || br.Status != contractsentinel.StatusDefect ||
				br.Note != tc.beforeNote {
				t.Errorf("baseline rule = %+v, want defect with the archived note %q", br, tc.beforeNote)
			}
			if ar := entry.After.Rule; ar.ID != rule.ID || ar.Kind != rule.Kind || ar.Severity != rule.Severity ||
				ar.Invariant != rule.Invariant || ar.RequiresABI != rule.RequiresABI || ar.Version != rule.Version ||
				ar.Status != contractsentinel.StatusUnchecked || ar.Note != "" {
				t.Errorf("new rule = %+v, want the identical definition with status %q", ar, contractsentinel.StatusUnchecked)
			}
			bf := entry.Before.Finding
			if bf == nil {
				t.Fatal("baseline side must keep the defect record")
			}
			if bf.ArtifactHash != hash || bf.RuleID != rule.ID || bf.Version != rule.Version ||
				bf.Severity != rule.Severity || bf.Invariant != rule.Invariant {
				t.Errorf("baseline finding binding = %+v, want hash=%q rule=%q version=%q", bf, hash, rule.ID, rule.Version)
			}
			if bf.Evidence != tc.evidence {
				t.Errorf("baseline evidence = %q, want %q verbatim", bf.Evidence, tc.evidence)
			}
			if entry.After.Finding != nil {
				t.Errorf("unchecked side must render the defect record as null, got %+v", entry.After.Finding)
			}

			// 汇总：检查状态变化一条，已消除缺陷与新发现缺陷均为零；缺陷总数
			// 1 -> 0 也不能把未检查计成已消除。
			s := d.Summary
			if s.StatusChanges != 1 {
				t.Errorf("statusChanges = %d, want 1", s.StatusChanges)
			}
			if s.ResolvedDefects != 0 || s.NewDefects != 0 {
				t.Errorf("unchecked must not be a defect transition: %+v", s)
			}
			if s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 ||
				s.RemovedRules != 0 || s.ChangedRules != 0 {
				t.Errorf("every other count must be zero: %+v", s)
			}
			if s.BeforeDefects != 1 || s.AfterDefects != 0 {
				t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
			}

			// 原始输出字节层面：新侧状态必须是“未检查”，其缺陷记录渲染为 null；
			// 外部反例的中文、换行（JSON 转义为 \n）与前后空格逐字保留，不被清
			// 空、缩短或替换。
			if !strings.Contains(stdout, `"change": "`+contractsentinel.ChangeStatusChanged+`"`) {
				t.Errorf("output must carry the %q category:\n%s", contractsentinel.ChangeStatusChanged, stdout)
			}
			if !strings.Contains(stdout, `"status": "`+contractsentinel.StatusUnchecked+`"`) {
				t.Errorf("output must show the new side as %q:\n%s", contractsentinel.StatusUnchecked, stdout)
			}
			if tc.name == "external checker counterexample" {
				if !strings.Contains(stdout, "  旧反例：该规则本次未安排复跑\\n  callvalue 跨调用余额仍可污染  ") {
					t.Errorf("output must preserve the baseline evidence verbatim:\n%s", stdout)
				}
			}
			// 不能出现“已消除缺陷”的分类字样（类别字符串不与任何字段值重合）。
			if strings.Contains(stdout, contractsentinel.ChangeResolvedDefect) {
				t.Errorf("unchecked must never render as %q:\n%s", contractsentinel.ChangeResolvedDefect, stdout)
			}
		})
	}
}

// TestCLIDiffResolvedAndUncheckedCountedSeparately 进程边界混合统计：两条引用
// 不同不变式、定义不变的规则，基准侧都有缺陷，新侧一条明确通过、另一条未检
// 查；已消除缺陷与检查状态变化各计其一，缺陷总数 2 -> 0，没有新发现缺陷，
// 每条结果只带自己规则的证据。
func TestCLIDiffResolvedAndUncheckedCountedSeparately(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)

	fixedRule := cliWireRule{ID: "fixed-reentrancy", Kind: "static", Severity: "high",
		Invariant: "fixed-reentrant-withdraw", Version: "1.4.0"}
	uncheckedRule := cliWireRule{ID: "rechecked-later", Kind: "static", Severity: "medium",
		Invariant: "rechecked-balance-monotonic", Version: "2.0.0"}
	const fixedEvidence = "  旧反例：修复前 balances 扣减晚于外部调用\n  第二行  "

	// 基准侧：fixed-reentrancy 由外部检查器给出带反例的缺陷；rechecked-later
	// 的不变式值为 false，由报告生成缺陷证据。
	before := auditDiffReportWith(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{uncheckedRule, fixedRule},
		map[string]bool{uncheckedRule.Invariant: false},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: fixedRule.ID, Version: fixedRule.Version,
			Status: contractsentinel.StatusDefect, Note: fixedEvidence}})
	// 新侧：fixed-reentrancy 明确通过；rechecked-later 无检查记录、无不变式值。
	after := auditDiffReport(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{fixedRule, uncheckedRule},
		[]cliWireCheck{{ArtifactHash: hash, RuleID: fixedRule.ID, Version: fixedRule.Version,
			Status: contractsentinel.StatusPass}})

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	if len(d.Results) != 2 {
		t.Fatalf("results = %d, want 2: %+v", len(d.Results), d.Results)
	}
	ids := make([]string, 0, len(d.Results))
	for _, r := range d.Results {
		ids = append(ids, r.RuleID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("results not sorted by rule id: %v", ids)
	}

	fixed := diffEntry(t, d, fixedRule.ID)
	recheck := diffEntry(t, d, uncheckedRule.ID)

	if fixed.Change != contractsentinel.ChangeResolvedDefect {
		t.Fatalf("fixed rule change = %q, want %q", fixed.Change, contractsentinel.ChangeResolvedDefect)
	}
	if fixed.Before.Finding == nil || fixed.Before.Finding.Evidence != fixedEvidence ||
		fixed.Before.Finding.RuleID != fixedRule.ID || fixed.After.Finding != nil ||
		fixed.After.Rule.Status != contractsentinel.StatusPass {
		t.Errorf("resolved rule sides = %+v / %+v", fixed.Before, fixed.After)
	}

	if recheck.Change != contractsentinel.ChangeStatusChanged {
		t.Fatalf("unchecked rule change = %q, want %q", recheck.Change, contractsentinel.ChangeStatusChanged)
	}
	if recheck.Before == nil || recheck.After == nil {
		t.Fatal("unchecked rule must keep both sides")
	}
	if recheck.Before.Rule.Status != contractsentinel.StatusDefect ||
		recheck.After.Rule.Status != contractsentinel.StatusUnchecked {
		t.Errorf("unchecked statuses = %q/%q", recheck.Before.Rule.Status, recheck.After.Rule.Status)
	}
	if recheck.Before.Finding == nil ||
		recheck.Before.Finding.Evidence != "invariant rechecked-balance-monotonic does not hold" ||
		recheck.Before.Finding.RuleID != uncheckedRule.ID {
		t.Errorf("unchecked baseline finding = %+v", recheck.Before.Finding)
	}
	if recheck.After.Finding != nil {
		t.Errorf("unchecked new side must carry no finding: %+v", recheck.After.Finding)
	}
	// 通过规则的结论不能套到未检查规则上；两条证据按规则标识各自保留。
	if recheck.After.Rule.Status == fixed.After.Rule.Status {
		t.Error("the passing conclusion must not be applied to the unchecked rule")
	}
	if fixed.Before.Finding.Evidence == recheck.Before.Finding.Evidence {
		t.Error("each rule must keep its own evidence")
	}

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
		t.Errorf("defect totals = %d/%d, want 2/0", s.BeforeDefects, s.AfterDefects)
	}

	// 输出必须逐字保留通过规则的基准反例，且同时携带两种分类。
	if !strings.Contains(stdout, "  旧反例：修复前 balances 扣减晚于外部调用\\n  第二行  ") {
		t.Errorf("output must preserve the resolved rule evidence verbatim:\n%s", stdout)
	}
	if !strings.Contains(stdout, contractsentinel.ChangeResolvedDefect) ||
		!strings.Contains(stdout, contractsentinel.ChangeStatusChanged) {
		t.Errorf("output must carry both categories:\n%s", stdout)
	}
}

// TestCLIDiffUncheckedPresentDiffersFromRemovedRule 进程边界对照：规则仍在但
// 未检查 -> “检查状态变化”（新侧是完整的未检查规则、finding 为 null）；规则
// 完全删除 -> “移除规则”（新侧整体 null）。两者不能混淆。
func TestCLIDiffUncheckedPresentDiffersFromRemovedRule(t *testing.T) {
	bin := auditBinary(t)
	work := t.TempDir()
	store := filepath.Join(work, "reports")
	artifact := mixedCheckArtifact()
	hash := mixedArtifactHash(t)

	presentRule := uncheckedCLIRule()
	goneRule := cliWireRule{ID: "dropped-reentrancy", Kind: "static", Severity: "critical",
		Invariant: "dropped-reentrant-withdraw", Version: "9.0.1"}
	const goneEvidence = "  旧反例：规则随检查范围一并删除\n  delegatecall 路径  "

	before := auditDiffReport(t, bin, work, store, "before.json", artifact,
		[]cliWireRule{goneRule, presentRule},
		[]cliWireCheck{
			{ArtifactHash: hash, RuleID: presentRule.ID, Version: presentRule.Version,
				Status: contractsentinel.StatusDefect, Note: uncheckedCLIEvidence},
			{ArtifactHash: hash, RuleID: goneRule.ID, Version: goneRule.Version,
				Status: contractsentinel.StatusDefect, Note: goneEvidence},
		})
	// 新报告只保留 presentRule，且没有检查记录、没有它的不变式值 -> 未检查；
	// goneRule 完全缺席。
	after := auditDiffReportWith(t, bin, work, store, "after.json", artifact,
		[]cliWireRule{presentRule}, nil, nil)

	stdout, stderr, code := runCLIDiff(t, bin, store, before.ReportID, after.ReportID)
	if code != 0 {
		t.Fatalf("diff must succeed, exit=%d stderr=%s", code, stderr)
	}
	d := decodeDiff(t, stdout)

	present := diffEntry(t, d, presentRule.ID)
	gone := diffEntry(t, d, goneRule.ID)

	if present.Change != contractsentinel.ChangeStatusChanged {
		t.Fatalf("present rule change = %q, want %q", present.Change, contractsentinel.ChangeStatusChanged)
	}
	if present.After == nil || present.After.Rule.Status != contractsentinel.StatusUnchecked ||
		present.After.Finding != nil {
		t.Errorf("present new side must be a full unchecked rule without finding: %+v", present.After)
	}
	if present.Before == nil || present.Before.Finding == nil ||
		present.Before.Finding.Evidence != uncheckedCLIEvidence {
		t.Errorf("present baseline side must keep the archived defect: %+v", present.Before)
	}

	if gone.Change != contractsentinel.ChangeRuleRemoved {
		t.Fatalf("gone rule change = %q, want %q", gone.Change, contractsentinel.ChangeRuleRemoved)
	}
	if gone.After != nil {
		t.Fatalf("removed rule new side must be null, got %+v", gone.After)
	}
	if gone.Before == nil || gone.Before.Finding == nil || gone.Before.Finding.Evidence != goneEvidence {
		t.Errorf("removed baseline side must keep its defect: %+v", gone.Before)
	}

	s := d.Summary
	if s.StatusChanges != 1 || s.RemovedRules != 1 {
		t.Errorf("statusChanges/removedRules = %d/%d, want 1/1", s.StatusChanges, s.RemovedRules)
	}
	if s.ResolvedDefects != 0 || s.NewDefects != 0 {
		t.Errorf("neither case is a defect transition: %+v", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0", s.BeforeDefects, s.AfterDefects)
	}

	// 字节层面：移除规则渲染整体新侧 null；未检查规则只把 finding 渲染为
	// null，仍带完整规则与“未检查”状态；两份基准证据逐字保留。
	if !strings.Contains(stdout, `"after": null`) {
		t.Errorf("removed entry must render the absent side as null:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"status": "`+contractsentinel.StatusUnchecked+`"`) {
		t.Errorf("present entry must render the new-side rule as %q:\n%s", contractsentinel.StatusUnchecked, stdout)
	}
	if !strings.Contains(stdout, "  旧反例：该规则本次未安排复跑\\n  callvalue 跨调用余额仍可污染  ") ||
		!strings.Contains(stdout, "  旧反例：规则随检查范围一并删除\\n  delegatecall 路径  ") {
		t.Errorf("both baseline evidences must be preserved verbatim:\n%s", stdout)
	}
}
