package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交侧 checks 记录正式 note 成员的类型规则。note 在
// wireCheck 中是 Go 字符串，json.Unmarshal 会把正式成员的 null 静默解码成
// 零值 ""：产物、规则与检查记录的绑定全部合法时，一条状态为“通过”的记录
// 即使写了 "note":null，也会成功生成报告，与省略说明的提交得到同一份报告，
// 格式错误被洗成了合法提交。
//
// 修正后，正式 note（约定拼写，含 Unicode 转义写法）一旦写出，其值就必须
// 是 JSON 字符串；null、布尔值、数字、对象、数组都使整份提交失败
// （errInvalid），对“通过”“发现缺陷”“工具缺失”“超时”四种状态都有效，
// 其他记录合法也不能输出或保存部分报告。错误点名 checks 数组中从零开始的
// 位置并说明 note 必须是字符串，记录带合法非空 ruleId 时同时点名该规则；
// ruleId 自身非法时凭位置定位。省略 note 仍按状态走原有业务判断：“通过”
// 允许没有说明，也允许显式空串或纯空白串；其余三种状态仍要求非空白说明。
// Note、带前后空格的名称及未知成员只是扩展信息，既不能补上缺失的正式说明，
// 也不能挽救非法正式值，与成员先后顺序无关。

// checkNoteRulesJSON 是 note 用例共用的单条静态规则：不要求 ABI、版本合法。
const checkNoteRulesJSON = `[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"}]`

// checkNoteRecord 拼出一条 checks 记录：withNote 为 false 时省略正式 note
// 成员，为 true 时写入原始片段 noteToken（可为 null、true、"文本" 等）。
func checkNoteRecord(hash, ruleID, version, status, noteToken string, withNote bool) string {
	rec := `{"artifactHash":` + jsonString(hash) +
		`,"ruleId":` + jsonString(ruleID) +
		`,"version":` + jsonString(version) +
		`,"status":` + jsonString(status)
	if withNote {
		rec += `,"note":` + noteToken
	}
	return rec + "}"
}

// checkNoteSubmission 用单条规则和给定检查记录数组拼出一份完整提交。
func checkNoteSubmission(checks ...string) string {
	return ruleTextSubmission(checkNoteRulesJSON, `"checks":[`+strings.Join(checks, ",")+`]`)
}

// expectInvalidCheckNote 断言整份提交在解析阶段被拒绝：errInvalid、错误
// 点名 checks 数组位置与 note 字符串要求；ruleID 为 "" 时错误不得携带规则
// 标识，且不返回任何部分数据。
func expectInvalidCheckNote(t *testing.T, in, position, ruleID string) {
	t.Helper()
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err == nil {
		t.Fatalf("a non-string formal note must reject the whole submission\ninput: %s", in)
	}
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("a note type error is a submission format error (errInvalid), got %T: %v", err, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, position) {
		t.Fatalf("error must name the checks-array position %q: %v", position, err)
	}
	if !strings.Contains(msg, "note must be a string") {
		t.Fatalf("error must state note must be a string: %v", err)
	}
	if ruleID != "" {
		if !strings.Contains(msg, "(rule "+ruleID+")") {
			t.Fatalf("error must name the legal rule id %q: %v", ruleID, err)
		}
	} else if strings.Contains(msg, "(rule ") {
		t.Fatalf("an illegal ruleId must leave the record locatable by position alone: %v", err)
	}
	// 这是提交格式错误，不得记成任何检查结论。
	for _, marker := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		if strings.Contains(msg, marker) {
			t.Fatalf("a format error must not be reported as the conclusion %q: %v", marker, err)
		}
	}
	if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
		t.Fatalf("rejection must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
	}
}

// --- 核心场景：四种状态写 "note":null 都整份拒绝；“通过”是本次修复的漏洞 ---

func TestParseAuditNullNoteRejectedForEveryStatus(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	for _, status := range []string{StatusPass, StatusDefect, StatusToolMissing, StatusTimeout} {
		t.Run(status, func(t *testing.T) {
			rec := checkNoteRecord(hash, "r1", "1.0.0", status, "null", true)
			expectInvalidCheckNote(t, checkNoteSubmission(rec), "checks[0]", "r1")
		})
	}
}

// --- 布尔值、数字、对象、数组同样整份拒绝，不能转成空串、文字或跳过记录 ---

func TestParseAuditNonStringNoteRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	tokens := []string{"true", "false", "0", "123", "3.5", "null", "{}", "[]", `["x"]`, `{"text":"x"}`}
	for _, status := range []string{StatusPass, StatusDefect, StatusToolMissing, StatusTimeout} {
		for _, token := range tokens {
			t.Run(status+"/"+token, func(t *testing.T) {
				rec := checkNoteRecord(hash, "r1", "1.0.0", status, token, true)
				artifact, _, _, _, err := ParseAuditInput([]byte(checkNoteSubmission(rec)))
				if err == nil {
					t.Fatalf("status=%s note=%s must reject the whole submission", status, token)
				}
				if !strings.Contains(err.Error(), "checks[0]") ||
					!strings.Contains(err.Error(), "note must be a string") {
					t.Fatalf("error must name the position and string requirement: %v", err)
				}
				if artifact != (Artifact{}) {
					t.Fatalf("rejection must return no partial artifact: %+v", artifact)
				}
			})
		}
	}
}

// --- 位置与点名：按数组下标报最靠前的记录，记录带合法 ruleId 时同时点名 ---

func TestParseAuditNoteErrorNamesPositionAndRule(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	// 第一条合法、第二条非法：报 checks[1] 与 r2。
	good := checkNoteRecord(hash, "r1", "1.0.0", StatusPass, "", false)
	bad := checkNoteRecord(hash, "r2", "1.0.0", StatusPass, "null", true)
	// 两条记录引用同一条规则定义不可行（重复记录会触发业务错误），因此用
	// 两条规则承载。
	twoRules := `[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"},` +
		`{"id":"r2","kind":"static","severity":"low","invariant":"inv2","requiresABI":false,"version":"1.0.0"}]`
	in := ruleTextSubmission(twoRules, `"checks":[`+good+","+bad+`]`)
	expectInvalidCheckNote(t, in, "checks[1]", "r2")

	// 多条记录非法：报数组中最靠前的一条（checks[0] 与 r1），即使其后还有非法记录。
	badFirst := checkNoteRecord(hash, "r1", "1.0.0", StatusPass, "null", true)
	badSecond := checkNoteRecord(hash, "r2", "1.0.0", StatusPass, "true", true)
	in = ruleTextSubmission(twoRules, `"checks":[`+badFirst+","+badSecond+`]`)
	_, _, _, _, err := ParseAuditInput([]byte(in))
	if err == nil || !strings.Contains(err.Error(), "checks[0]") ||
		!strings.Contains(err.Error(), "r1") ||
		!strings.Contains(err.Error(), "note must be a string") {
		t.Fatalf("the first offending record must be reported by its array index: %v", err)
	}

	// ruleId 自身为 null：没有可点名的合法规则标识，只凭 checks[0] 定位。
	rec := checkNoteRecord(hash, "", "1.0.0", StatusPass, "null", true)
	rec = strings.Replace(rec, `"ruleId":""`, `"ruleId":null`, 1)
	expectInvalidCheckNote(t, checkNoteSubmission(rec), "checks[0]", "")
}

// --- 其他记录全部合法也不能挽救；格式错误不被记成缺陷、工具缺失或超时 ---

func TestParseAuditNullNoteRejectsWholeSubmission(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	twoRules := `[{"id":"r1","kind":"static","severity":"high","invariant":"inv","requiresABI":false,"version":"1.0.0"},` +
		`{"id":"r2","kind":"static","severity":"low","invariant":"inv2","requiresABI":false,"version":"2.0.0"}]`
	// r2 的缺陷记录（含中文说明）完全合法；r1 的通过记录携带 null note。
	goodDefect := checkNoteRecord(hash, "r2", "2.0.0", StatusDefect, jsonString(" 反例：重入\n第二行 "), true)
	badPass := checkNoteRecord(hash, "r1", "1.0.0", StatusPass, "null", true)
	in := ruleTextSubmission(twoRules, `"checks":[`+goodDefect+","+badPass+`]`)
	expectInvalidCheckNote(t, in, "checks[1]", "r1")
}

// --- 省略 note：通过合法；其余三种状态沿用原有的“说明必填”业务失败 ---

func TestParseAuditOmittedNoteKeepsStatusBusinessRule(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	// 通过：省略说明仍然合法。
	rec := checkNoteRecord(hash, "r1", "1.0.0", StatusPass, "", false)
	report := strictParsedReport(t, checkNoteSubmission(rec))
	if report.Rules[0].Status != StatusPass || report.Rules[0].Note != "" {
		t.Fatalf("an omitted pass note must stay legal: %+v", report.Rules[0])
	}
	if len(report.Findings) != 0 {
		t.Fatalf("a passing check must produce no findings: %+v", report.Findings)
	}

	for _, status := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		t.Run(status, func(t *testing.T) {
			rec := checkNoteRecord(hash, "r1", "1.0.0", status, "", false)
			artifact, rules, invariants, checks, err := ParseAuditInput([]byte(checkNoteSubmission(rec)))
			if err != nil {
				t.Fatalf("omitting a note must parse (the blank-note rule is business logic): %v", err)
			}
			_, err = BuildReport(artifact, rules, invariants, checks)
			if err == nil {
				t.Fatalf("status %s still requires a note", status)
			}
			if !strings.Contains(err.Error(), "note is required for status "+status) ||
				strings.Contains(err.Error(), "must be a string") {
				t.Fatalf("the original business failure must survive, got: %v", err)
			}
		})
	}
}

// --- 显式空串与纯空白串：类型关通过，通过状态合法，其余状态仍是业务失败 ---

func TestParseAuditEmptyAndWhitespaceNoteAreStrings(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	omitted := checkNoteSubmission(checkNoteRecord(hash, "r1", "1.0.0", StatusPass, "", false))

	for _, note := range []string{"", "  ", "\t\n  "} {
		t.Run("pass/"+note, func(t *testing.T) {
			rec := checkNoteRecord(hash, "r1", "1.0.0", StatusPass, jsonString(note), true)
			report := strictParsedReport(t, checkNoteSubmission(rec))
			if report.Rules[0].Note != note {
				t.Fatalf("note = %q, must be preserved verbatim", report.Rules[0].Note)
			}
			// 显式空串与省略等价（omitempty）；纯空白说明非空，会进入报告标识。
			if note == "" {
				if report.ReportID != strictParsedReport(t, omitted).ReportID {
					t.Fatal("an explicit empty-string note and an omitted note must share the report id")
				}
			} else {
				if report.ReportID == strictParsedReport(t, omitted).ReportID {
					t.Fatal("a whitespace note must not be laundered into an omitted note")
				}
			}
		})
	}

	// 其余三种状态：纯空白串仍触发原有的“非空白说明”业务失败，而不是类型错误。
	for _, status := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		rec := checkNoteRecord(hash, "r1", "1.0.0", status, jsonString(" \n\t "), true)
		artifact, rules, invariants, checks, err := ParseAuditInput([]byte(checkNoteSubmission(rec)))
		if err != nil {
			t.Fatalf("a whitespace note is a legal string and must parse: %v", err)
		}
		if _, err := BuildReport(artifact, rules, invariants, checks); err == nil ||
			!strings.Contains(err.Error(), "note is required for status "+status) {
			t.Fatalf("status %s must keep the non-blank business error, got: %v", status, err)
		}
	}
}

// --- 合法说明逐字保留：中文、换行、前后空格；缺陷证据用原文，工具缺失/超时
// 不进缺陷列表；产物哈希与报告标识与直接构造一致 ---

func TestParseAuditLegalNotePreservedVerbatim(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	cases := []struct {
		status string
		note   string
	}{
		{StatusPass, "  通过备注：第二行\n仍在备注里  "},
		{StatusDefect, "  反例：攻击者可在 withdraw 中重入\n  第二行证据  "},
		{StatusToolMissing, " 符号执行引擎未安装\n请安装后重跑 "},
		{StatusTimeout, " 超过 60s 截止时间\n仍在说明里 "},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			rec := checkNoteRecord(hash, "r1", "1.0.0", tc.status, jsonString(tc.note), true)
			artifact, rules, invariants, checks, err := ParseAuditInput([]byte(checkNoteSubmission(rec)))
			if err != nil {
				t.Fatalf("a legal note with CJK/newlines/spaces must parse: %v", err)
			}
			if checks[0].Note != tc.note {
				t.Fatalf("note = %q, want %q", checks[0].Note, tc.note)
			}
			report, err := BuildReport(artifact, rules, invariants, checks)
			if err != nil {
				t.Fatalf("a legal submission must build a report: %v", err)
			}
			if report.Artifact.Hash != hash {
				t.Fatal("legal text must keep the original artifact hash")
			}
			if report.Rules[0].Note != tc.note {
				t.Fatalf("report note = %q, want the verbatim note %q", report.Rules[0].Note, tc.note)
			}

			// 与直接用同值 Go 结构构建的报告共享标识。
			directChecks := []CheckRecord{{ArtifactHash: hash, RuleID: "r1", Version: "1.0.0",
				Status: tc.status, Note: tc.note}}
			directRules := []Rule{{ID: "r1", Kind: "static", Severity: "high",
				Invariant: "inv", RequiresABI: false, Version: "1.0.0"}}
			want, err := BuildReport(strictTestArtifact(), directRules, nil, directChecks)
			if err != nil {
				t.Fatal(err)
			}
			if report.ReportID != want.ReportID {
				t.Fatalf("report id changed:\n got %s\nwant %s", report.ReportID, want.ReportID)
			}

			switch tc.status {
			case StatusDefect:
				if len(report.Findings) != 1 {
					t.Fatalf("a defect check must produce exactly one finding: %+v", report.Findings)
				}
				if report.Findings[0].Evidence != tc.note {
					t.Fatalf("evidence must be the verbatim note, got %q", report.Findings[0].Evidence)
				}
			case StatusToolMissing, StatusTimeout, StatusPass:
				if len(report.Findings) != 0 {
					t.Fatalf("status %s must not enter the findings list: %+v", tc.status, report.Findings)
				}
			}
		})
	}
}

// --- 大小写变体、带空格名称与未知成员是扩展信息：非字符串值不触发本项错误，
// 合法字符串既不能补上缺失的正式说明，也不能挽救非法正式值（顺序无关） ---

func TestParseAuditNoteVariantsIgnored(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	// 正式 note 省略，变体携带 null：只是扩展信息。“通过”仍合法，报告标识
	// 与不含任何变体的提交一致。
	plain := checkNoteSubmission(checkNoteRecord(hash, "r1", "1.0.0", StatusPass, "", false))
	for _, ext := range []string{
		`"Note":null`,
		`" note ":null`,
		`"mystery":["x"]`,
		`"Note":{}`,
		`" note ":123`,
	} {
		rec := strings.TrimSuffix(checkNoteRecord(hash, "r1", "1.0.0", StatusPass, "", false), "}") +
			"," + ext + "}"
		got := strictParsedReport(t, checkNoteSubmission(rec))
		if got.Rules[0].Note != "" {
			t.Fatalf("extension member %s must not supply a missing formal note: %+v", ext, got.Rules[0])
		}
		if got.ReportID != strictParsedReport(t, plain).ReportID {
			t.Fatalf("extension member %s changed the report id", ext)
		}
	}

	// 正式 note 省略、缺陷状态，变体携带合法字符串：不能补上缺失说明，
	// 仍走原有的业务失败，而不是类型错误。
	for _, ext := range []string{`"Note":"反例"`, `" note ":" 反例 "`, `"mystery":"x"`} {
		rec := strings.TrimSuffix(checkNoteRecord(hash, "r1", "1.0.0", StatusDefect, "", false), "}") +
			"," + ext + "}"
		artifact, rules, invariants, checks, err := ParseAuditInput([]byte(checkNoteSubmission(rec)))
		if err != nil {
			t.Fatalf("extension data must parse: %v", err)
		}
		if _, err := BuildReport(artifact, rules, invariants, checks); err == nil ||
			!strings.Contains(err.Error(), "note is required for status "+StatusDefect) ||
			strings.Contains(err.Error(), "must be a string") {
			t.Fatalf("an extension string must not fill the missing formal note, got: %v", err)
		}
	}

	// 正式 note 为 null，变体携带合法字符串，无论写在其前还是其后都不能挽救。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			head := strings.TrimSuffix(checkNoteRecord(hash, "r1", "1.0.0", StatusPass, "", false), "}")
			var rec string
			if pos == "before" {
				rec = head + `,"Note":"passing"` + `,"note":null}`
			} else {
				rec = head + `,"note":null` + `," note ":"passing"}`
			}
			expectInvalidCheckNote(t, checkNoteSubmission(rec), "checks[0]", "r1")
		})
	}
}

// --- Unicode 转义写出的正式名称遵守同一规则 ---

func TestParseAuditEscapedNoteNameFollowsSameRule(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	// "note" 首字母 n 的码位是 0x6e：转义写出后解码仍是正式 note。
	escName := "\\" + "u006e" + "ote"

	rec := strings.TrimSuffix(checkNoteRecord(hash, "r1", "1.0.0", StatusPass, "", false), "}") +
		`,"` + escName + `":null}`
	in := checkNoteSubmission(rec)
	if !strings.Contains(in, `\`+"u006eote") {
		t.Fatalf("test setup must carry the JSON escape, got %s", in)
	}
	expectInvalidCheckNote(t, in, "checks[0]", "r1")

	// 转义写法携带合法字符串时，与直接书写解析到同一记录、同一报告标识。
	escaped := strings.TrimSuffix(checkNoteRecord(hash, "r1", "1.0.0", StatusDefect, "", false), "}") +
		`,"` + escName + `":` + jsonString(" 转义说明\n第二行 ") + `}`
	plainLegal := checkNoteSubmission(checkNoteRecord(hash, "r1", "1.0.0",
		StatusDefect, jsonString(" 转义说明\n第二行 "), true))
	if strictParsedReport(t, checkNoteSubmission(escaped)).ReportID !=
		strictParsedReport(t, plainLegal).ReportID {
		t.Fatal("escaped and plain spellings of a legal note must share the report id")
	}
}

// --- 只给不变式布尔值、不提供检查记录的提交继续按原有方式处理 ---

func TestParseAuditInvariantsOnlySubmissionUnaffected(t *testing.T) {
	in := strictDoc(
		`"artifact":`+strictArtifactJSON,
		`"rules":`+checkNoteRulesJSON,
		`"invariants":{"inv":false}`)
	report := strictParsedReport(t, in)
	if report.Rules[0].Status != StatusDefect || report.Rules[0].Note != "" {
		t.Fatalf("an invariants-only submission must keep its original behaviour: %+v", report.Rules[0])
	}
	if len(report.Findings) != 1 || report.Findings[0].Evidence != invariantEvidence("inv") {
		t.Fatalf("the boolean defect must keep its template evidence: %+v", report.Findings)
	}
}
