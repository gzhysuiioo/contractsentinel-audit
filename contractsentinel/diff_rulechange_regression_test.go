package contractsentinel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件围绕比较功能的一项业务回归口径：同一规则标识在基准报告中为
// “发现缺陷”、在新报告中为“通过”时，只有两侧规则的完整定义——版本、检查
// 种类、严重级别、引用的不变式、requiresABI 是否需要 ABI——完全一致，才能
// 把它记为“已消除缺陷”。只改动其中一项定义时必须记为“规则变化”：用户看到
// 缺陷总数下降，需要分清是同一检查标准下的缺陷消除，还是检查标准本身已经
// 变化。版本字符串相同不能替代完整定义的一致性。
//
// 所有用例都走 BuildReport -> SaveReport -> DiffStore 的正常归档与读回路径，
// 比较的是同一产物（同一名称、同一内容哈希）的两份合法报告；产物自带 ABI 与
// 字节码，使 requiresABI 的规则和 symbolic 规则的报告都能正常保存和读回。

// ruleChangeEvidence 刻意包含中文、换行与前后空白；定义变化不得改写旧证据。
const ruleChangeEvidence = "  旧反例：调用顺序如下\n  attacker.withdraw() 再入  "

// ruleChangeBaseRule 是基准侧规则定义；每个漂移用例只改其中一个字段。
func ruleChangeBaseRule() Rule {
	return Rule{
		ID:          "reentrancy-guard",
		Kind:        "static",
		Severity:    "high",
		Invariant:   "no-reentrant-withdraw",
		RequiresABI: false,
		Version:     "3.1.0",
	}
}

// saveRuleChangeCheckReport 通过外部检查记录落盘一份单规则报告：基准侧保留
// 具体反例，新侧记录通过。证据中的中文、换行和前后空白随检查说明原样归档。
func saveRuleChangeCheckReport(t *testing.T, dir string, artifact Artifact, rule Rule, status string, note string) Report {
	t.Helper()
	report := saveCheckReport(t, dir, artifact, []Rule{rule}, []CheckRecord{{
		ArtifactHash: ArtifactHash(artifact),
		RuleID:       rule.ID,
		Version:      rule.Version,
		Status:       status,
		Note:         note,
	}})
	return report
}

// assertRuleFields 比较归档读回的完整规则定义与期望定义。
func assertRuleFields(t *testing.T, where string, got ReportRule, want Rule, status, note string) {
	t.Helper()
	if got.ID != want.ID || got.Kind != want.Kind || got.Severity != want.Severity ||
		got.Invariant != want.Invariant || got.RequiresABI != want.RequiresABI ||
		got.Version != want.Version {
		t.Errorf("%s definition = {id:%q kind:%q severity:%q invariant:%q requiresABI:%v version:%q}, want {id:%q kind:%q severity:%q invariant:%q requiresABI:%v version:%q}",
			where, got.ID, got.Kind, got.Severity, got.Invariant, got.RequiresABI, got.Version,
			want.ID, want.Kind, want.Severity, want.Invariant, want.RequiresABI, want.Version)
	}
	if got.Status != status {
		t.Errorf("%s status = %q, want %q", where, got.Status, status)
	}
	if got.Note != note {
		t.Errorf("%s note = %q, want %q", where, got.Note, note)
	}
}

// TestDiffDefectToPassWithSingleDefinitionDriftIsRuleChange 逐项覆盖五个定义
// 字段：每个用例只改其中一项，其余定义保持相同。四种用例刻意保持版本字符串
// 不变——版本相同不代表定义一致。
func TestDiffDefectToPassWithSingleDefinitionDriftIsRuleChange(t *testing.T) {
	cases := []struct {
		name  string
		drift func(Rule) Rule
	}{
		{"version only", func(r Rule) Rule {
			r.Version = "3.2.0"
			return r
		}},
		{"kind only, version unchanged", func(r Rule) Rule {
			r.Kind = "symbolic"
			return r
		}},
		{"severity only, version unchanged", func(r Rule) Rule {
			r.Severity = "critical"
			return r
		}},
		{"invariant only, version unchanged", func(r Rule) Rule {
			r.Invariant = "no-reentrant-withdraw-v2"
			return r
		}},
		{"requiresABI only, version unchanged", func(r Rule) Rule {
			r.RequiresABI = true
			return r
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// 产物自带 ABI 与字节码：requiresABI 的新侧规则与 symbolic 检查种类
			// 都满足输入要求，两份报告可以正常保存和读回。
			artifact := sampleArtifact()
			hash := ArtifactHash(artifact)

			beforeRule := ruleChangeBaseRule()
			afterRule := tc.drift(ruleChangeBaseRule())
			before := saveRuleChangeCheckReport(t, dir, artifact, beforeRule, StatusDefect, ruleChangeEvidence)
			after := saveRuleChangeCheckReport(t, dir, artifact, afterRule, StatusPass, "")

			// 两份报告必须能从归档独立读回，且基准侧仍带着原有产物哈希、规则
			// 标识、版本及反例证据，新侧没有缺陷记录。
			loadedBefore, err := LoadReport(dir, before.ReportID)
			if err != nil {
				t.Fatalf("load before: %v", err)
			}
			loadedAfter, err := LoadReport(dir, after.ReportID)
			if err != nil {
				t.Fatalf("load after: %v", err)
			}
			if len(loadedBefore.Findings) != 1 || len(loadedAfter.Findings) != 0 {
				t.Fatalf("archived findings = %d/%d, want 1/0", len(loadedBefore.Findings), len(loadedAfter.Findings))
			}

			diff, err := DiffStore(dir, before.ReportID, after.ReportID)
			if err != nil {
				t.Fatalf("diff must succeed for a definition drift: %v", err)
			}

			// 比较方向与报告标识按归档选择保留。
			if diff.Before.ReportID != before.ReportID || diff.After.ReportID != after.ReportID {
				t.Errorf("refs = %q/%q, want %q/%q", diff.Before.ReportID, diff.After.ReportID, before.ReportID, after.ReportID)
			}
			if diff.ArtifactHashChanged || diff.ArtifactNameChanged {
				t.Error("same artifact must not be flagged changed")
			}

			// 恰好一条“规则变化”，不能记成已消除缺陷。
			if len(diff.Results) != 1 {
				t.Fatalf("results = %d, want 1: %+v", len(diff.Results), diff.Results)
			}
			entry := diff.Results[0]
			if entry.RuleID != beforeRule.ID {
				t.Errorf("rule id = %q, want %q", entry.RuleID, beforeRule.ID)
			}
			if entry.Change != ChangeRuleChanged {
				t.Fatalf("change = %q, want %q", entry.Change, ChangeRuleChanged)
			}

			// 计数：规则变化为一；已消除缺陷、新发现缺陷、检查状态变化（及其余
			// 类别）均为零。
			s := diff.Summary
			if s.ChangedRules != 1 {
				t.Errorf("changedRules = %d, want 1", s.ChangedRules)
			}
			if s.ResolvedDefects != 0 || s.NewDefects != 0 || s.StatusChanges != 0 ||
				s.NoteChanges != 0 || s.NoChange != 0 || s.AddedRules != 0 || s.RemovedRules != 0 {
				t.Errorf("every non-rule-change count must be zero: %+v", s)
			}
			// 两个缺陷总数反映各自报告里的实际发现，不代表已消除缺陷的数量。
			if s.BeforeDefects != 1 || s.AfterDefects != 0 {
				t.Errorf("defect totals = %d/%d, want 1/0 (actual findings, not resolved count)",
					s.BeforeDefects, s.AfterDefects)
			}

			// 两侧完整规则、原始状态和说明都保留。
			if entry.Before == nil || entry.After == nil {
				t.Fatal("both sides must be present for 规则变化")
			}
			assertRuleFields(t, "before side", entry.Before.Rule, beforeRule, StatusDefect, ruleChangeEvidence)
			assertRuleFields(t, "after side", entry.After.Rule, afterRule, StatusPass, "")

			// 基准侧缺陷仍带着原有产物哈希、规则标识、版本及反例证据；定义变化
			// 不能改写旧证据，也不能把旧版本换成新版本。
			finding := entry.Before.Finding
			if finding == nil {
				t.Fatal("baseline defect must keep its finding")
			}
			if finding.ArtifactHash != hash {
				t.Errorf("finding artifact hash = %q, want %q", finding.ArtifactHash, hash)
			}
			if finding.RuleID != beforeRule.ID {
				t.Errorf("finding rule id = %q, want %q", finding.RuleID, beforeRule.ID)
			}
			if finding.Version != beforeRule.Version {
				t.Errorf("finding version = %q, want baseline %q (must not be rewritten to the new version)",
					finding.Version, beforeRule.Version)
			}
			if finding.Severity != beforeRule.Severity {
				t.Errorf("finding severity = %q, want baseline %q", finding.Severity, beforeRule.Severity)
			}
			if finding.Invariant != beforeRule.Invariant {
				t.Errorf("finding invariant = %q, want baseline %q", finding.Invariant, beforeRule.Invariant)
			}
			if finding.Evidence != ruleChangeEvidence {
				t.Errorf("finding evidence = %q, want %q verbatim", finding.Evidence, ruleChangeEvidence)
			}
			if entry.After.Finding != nil {
				t.Errorf("passing side must carry no finding: %+v", entry.After.Finding)
			}

			// 归档字节层面：证据中的中文、换行（JSON 中转义为 \n）和前后空白
			// 必须原样落盘，不能被修剪或替换。
			data, err := os.ReadFile(filepath.Join(dir, before.ReportID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			wantEscaped := `"evidence":"  旧反例：调用顺序如下\n  attacker.withdraw() 再入  "`
			if !strings.Contains(string(data), wantEscaped) {
				t.Errorf("baseline archive must keep the raw evidence verbatim:\n%s", string(data))
			}
		})
	}
}

// TestDiffDefectToPassIdenticalDefinitionIsResolved 是定义全部一致的对照：
// 相同的“发现缺陷”到“通过”变化应归为“已消除缺陷”，而不是“规则变化”。
func TestDiffDefectToPassIdenticalDefinitionIsResolved(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)

	rule := ruleChangeBaseRule()
	before := saveRuleChangeCheckReport(t, dir, artifact, rule, StatusDefect, ruleChangeEvidence)
	after := saveRuleChangeCheckReport(t, dir, artifact, rule, StatusPass, "")

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(diff.Results))
	}
	entry := diff.Results[0]
	if entry.Change != ChangeResolvedDefect {
		t.Fatalf("change = %q, want %q", entry.Change, ChangeResolvedDefect)
	}
	s := diff.Summary
	if s.ResolvedDefects != 1 {
		t.Errorf("resolvedDefects = %d, want 1", s.ResolvedDefects)
	}
	if s.ChangedRules != 0 {
		t.Errorf("changedRules = %d, want 0", s.ChangedRules)
	}
	if s.NewDefects != 0 || s.StatusChanges != 0 || s.NoteChanges != 0 || s.NoChange != 0 {
		t.Errorf("unexpected counts: %+v", s)
	}
	// 同样的真实发现总数：一和零；对照用例与漂移用例在这里结果一致，区别只在
	// 分类（已消除缺陷 vs 规则变化）。
	if s.BeforeDefects != 1 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 1/0", s.BeforeDefects, s.AfterDefects)
	}
	if entry.Before == nil || entry.After == nil {
		t.Fatal("both sides must be present")
	}
	assertRuleFields(t, "before side", entry.Before.Rule, rule, StatusDefect, ruleChangeEvidence)
	assertRuleFields(t, "after side", entry.After.Rule, rule, StatusPass, "")
	if entry.Before.Finding == nil || entry.Before.Finding.ArtifactHash != hash ||
		entry.Before.Finding.RuleID != rule.ID || entry.Before.Finding.Version != rule.Version ||
		entry.Before.Finding.Evidence != ruleChangeEvidence {
		t.Errorf("baseline finding must be preserved: %+v", entry.Before.Finding)
	}
	if entry.After.Finding != nil {
		t.Errorf("passing side must carry no finding: %+v", entry.After.Finding)
	}
}

// TestDiffRuleChangeIsNotCountedAsResolved 把一个漂移场景与对照场景放在同一
// 份输出的相邻规则上，回归保障必须能区分用户实际得到的两类比较结果：标准未
// 变下的缺陷消除，与标准已变的规则变化。
func TestDiffRuleChangeIsNotCountedAsResolved(t *testing.T) {
	dir := t.TempDir()
	artifact := sampleArtifact()
	hash := ArtifactHash(artifact)

	// 第一条：定义漂移（版本字符串不变，严重级别改变）+ 发现缺陷 -> 通过。
	driftedBefore := ruleChangeBaseRule()
	driftedAfter := ruleChangeBaseRule()
	driftedAfter.Severity = "critical"
	// 第二条：定义完全一致 + 发现缺陷 -> 通过。
	sameRule := ruleChangeBaseRule()
	sameRule.ID = "access-control"
	sameRule.Severity = "medium"
	sameRule.Invariant = "owner-only-withdraw"
	sameRule.Version = "4.0.0"

	before := saveCheckReport(t, dir, artifact, []Rule{driftedBefore, sameRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: driftedBefore.ID, Version: driftedBefore.Version, Status: StatusDefect, Note: ruleChangeEvidence},
		{ArtifactHash: hash, RuleID: sameRule.ID, Version: sameRule.Version, Status: StatusDefect, Note: " 旧缺陷二 "},
	})
	after := saveCheckReport(t, dir, artifact, []Rule{driftedAfter, sameRule}, []CheckRecord{
		{ArtifactHash: hash, RuleID: driftedAfter.ID, Version: driftedAfter.Version, Status: StatusPass},
		{ArtifactHash: hash, RuleID: sameRule.ID, Version: sameRule.Version, Status: StatusPass},
	})

	diff, err := DiffStore(dir, before.ReportID, after.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	changeByID := map[string]string{}
	for _, r := range diff.Results {
		changeByID[r.RuleID] = r.Change
	}
	if changeByID[driftedBefore.ID] != ChangeRuleChanged {
		t.Errorf("drifted rule = %q, want %q", changeByID[driftedBefore.ID], ChangeRuleChanged)
	}
	if changeByID[sameRule.ID] != ChangeResolvedDefect {
		t.Errorf("identical rule = %q, want %q", changeByID[sameRule.ID], ChangeResolvedDefect)
	}
	s := diff.Summary
	if s.ChangedRules != 1 || s.ResolvedDefects != 1 {
		t.Errorf("summary = %+v, want one rule change and one resolved defect", s)
	}
	if s.BeforeDefects != 2 || s.AfterDefects != 0 {
		t.Errorf("defect totals = %d/%d, want 2/0", s.BeforeDefects, s.AfterDefects)
	}
}
