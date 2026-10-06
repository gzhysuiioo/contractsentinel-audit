package contractsentinel

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 本文件锁定 audit 提交侧 checks 记录正式 note 成员的类型规则：约定拼写
// （含 Unicode 转义写法）的 note 一旦写出，值就必须是 JSON 字符串。
// wireCheck.Note 是 Go 字符串，json.Unmarshal 会把正式 null 静默解码成
// 零值 ""：一条“通过”记录即使写了 "note":null，也会与省略 note 的提交
// 得到逐字节相同的报告与报告标识，格式错误被洗成合法提交。
//
// 修正后，四种可导入状态（通过、发现缺陷、工具缺失、超时）的记录只要写出
// 正式 note，其值为 null、布尔值、数字、对象或数组都使整份提交失败
// （errInvalid），其他记录合法也不能输出或保存部分报告。错误点名 checks
// 数组中从零开始的位置与“note must be a string”，记录带合法非空 ruleId
// 时同时点名规则；ruleId 缺失或自身非法时凭位置定位。省略 note 仍按既有
// 状态判断：通过允许无说明，显式空串或纯空白串也合法；其余三种状态仍要求
// 非空白说明，沿用既有失败。Note、带前后空格的名称及未知成员只是扩展信息，
// 既不能补上缺失的正式说明，也不能挽救正式 note 的非法值，与成员顺序无关。

// checkNoteSubmission 拼装一份 audit 提交：rulesJSON/checksJSON 是对应数组
// 的完整 JSON（含方括号），extra 是额外顶层片段。
func checkNoteSubmission(rulesJSON, checksJSON string, extra ...string) string {
	sections := append([]string{
		`"artifact":` + strictArtifactJSON,
		`"rules":` + rulesJSON,
		`"checks":` + checksJSON,
	}, extra...)
	return strictDoc(sections...)
}

// checkObject 用给出的原始成员片段拼出一个 checks 记录对象。
func checkObject(members ...string) string {
	return "{" + strings.Join(members, ",") + "}"
}

// noteCheck 构造一条针对 r1（1.0.0）、绑定正确产物哈希、给定状态与额外
// 成员片段的检查记录。noteMember 为形如 `"note":null` 的原始片段，省略时
// 传 ""。
func noteCheck(hash, status, noteMember string, more ...string) string {
	members := append([]string{
		fmt.Sprintf(`"artifactHash":%q`, hash),
		`"ruleId":"r1"`,
		`"version":"1.0.0"`,
		`"status":` + jsonString(status),
	}, more...)
	if noteMember != "" {
		members = append(members, noteMember)
	}
	return checkObject(members...)
}

// expectInvalidCheckNote 断言整份提交被拒绝：errInvalid、错误点名 checks
// 数组位置并说明 note 必须是字符串；id 为 "" 时错误不得携带规则标识。
func expectInvalidCheckNote(t *testing.T, in, position, id string) {
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
	if id != "" {
		if !strings.Contains(msg, "(rule "+id+")") {
			t.Fatalf("error must name the legal rule id %q: %v", id, err)
		}
	} else if strings.Contains(msg, "(rule ") {
		t.Fatalf("a record without a legal rule id must stay locatable by position alone: %v", err)
	}
	// 这是提交格式错误，不得被记成任何检查结论。
	for _, marker := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		if strings.Contains(msg, marker) {
			t.Fatalf("a format error must not be reported as the conclusion %q: %v", marker, err)
		}
	}
	if artifact != (Artifact{}) || rules != nil || invariants != nil || checks != nil {
		t.Fatalf("rejection must return no partial data: %+v %+v %+v %+v", artifact, rules, invariants, checks)
	}
}

// --- 四种状态写出 null note 都整份拒绝，错误都点名 checks[0] 与规则 ---

func TestParseAuditNullNoteRejectedForEveryStatus(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	for _, status := range []string{StatusPass, StatusDefect, StatusToolMissing, StatusTimeout} {
		t.Run(status, func(t *testing.T) {
			in := checkNoteSubmission("["+artifactTextRule+"]",
				"["+noteCheck(hash, status, `"note":null`)+"]")
			expectInvalidCheckNote(t, in, "checks[0]", "r1")
		})
	}
}

// --- 布尔值、数字、对象、数组写在正式 note 位置同样整份拒绝（通过状态） ---

func TestParseAuditNonStringNoteRejected(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	for _, val := range []string{"true", "false", "0", "42", "{}", "[]", `["x"]`} {
		t.Run(val, func(t *testing.T) {
			in := checkNoteSubmission("["+artifactTextRule+"]",
				"["+noteCheck(hash, StatusPass, `"note":`+val)+"]")
			expectInvalidCheckNote(t, in, "checks[0]", "r1")
		})
	}
}

// --- 位置与点名：出错记录按数组下标定位，多条非法报最靠前的一条 ---

func TestParseAuditNoteErrorNamesPositionAndRule(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	rules := "[" +
		`{"id":"r0","kind":"static","severity":"low","invariant":"i0","requiresABI":false,"version":"1"}` + "," +
		`{"id":"r1","kind":"static","severity":"high","invariant":"i1","requiresABI":false,"version":"1.0.0"}` +
		"]"
	pass0 := checkObject(
		fmt.Sprintf(`"artifactHash":%q`, hash), `"ruleId":"r0"`, `"version":"1"`,
		`"status":`+jsonString(StatusPass))
	bad1 := checkObject(
		fmt.Sprintf(`"artifactHash":%q`, hash), `"ruleId":"r1"`, `"version":"1.0.0"`,
		`"status":`+jsonString(StatusPass), `"note":null`)
	in := checkNoteSubmission(rules, "["+pass0+","+bad1+"]")
	expectInvalidCheckNote(t, in, "checks[1]", "r1")

	// 两条记录都非法：报数组中最靠前的一条。
	bad0 := checkObject(
		fmt.Sprintf(`"artifactHash":%q`, hash), `"ruleId":"r0"`, `"version":"1"`,
		`"status":`+jsonString(StatusTimeout), `"note":123`)
	in = checkNoteSubmission(rules, "["+bad0+","+bad1+"]")
	expectInvalidCheckNote(t, in, "checks[0]", "r0")

	// ruleId 缺失或自身不是字符串：没有可点名的规则标识，仍凭位置定位。
	for _, tc := range []struct {
		name     string
		idMember string
	}{
		{"missing", ``}, {"null", `"ruleId":null`}, {"number", `"ruleId":42`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := []string{
				fmt.Sprintf(`"artifactHash":%q`, hash),
				`"version":"1.0.0"`,
				`"status":` + jsonString(StatusPass),
				`"note":null`,
			}
			if tc.idMember != "" {
				members = append(members, tc.idMember)
			}
			in := checkNoteSubmission("["+artifactTextRule+"]", "["+checkObject(members...)+"]")
			expectInvalidCheckNote(t, in, "checks[0]", "")
		})
	}

	// ruleId 合法但引用了不存在的规则：类型关仍先于业务关，错误点名该标识。
	unknown := checkObject(
		fmt.Sprintf(`"artifactHash":%q`, hash), `"ruleId":"ghost"`, `"version":"1.0.0"`,
		`"status":`+jsonString(StatusPass), `"note":null`)
	in = checkNoteSubmission("["+artifactTextRule+"]", "["+unknown+"]")
	expectInvalidCheckNote(t, in, "checks[0]", "ghost")
}

// --- 其他记录全部合法也不能挽救；通过记录的 null 也不例外 ---

func TestParseAuditNullNoteRejectedRegardlessOfOtherRecords(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	// 第一条是完全合法的“发现缺陷”记录，第二条的通过记录写了 null：其他记录
	// 合法不能挽救，错误定位到第二条（checks[1]）。为避免同一 ruleId 两条记录
	// 的业务重复干扰，这里用两条不同规则。
	rules := "[" +
		`{"id":"r0","kind":"static","severity":"low","invariant":"i0","requiresABI":false,"version":"1"}` + "," +
		artifactTextRule + "]"
	good := checkObject(
		fmt.Sprintf(`"artifactHash":%q`, hash), `"ruleId":"r0"`, `"version":"1"`,
		`"status":`+jsonString(StatusDefect), `"note":"反例原文"`)
	bad := checkObject(
		fmt.Sprintf(`"artifactHash":%q`, hash), `"ruleId":"r1"`, `"version":"1.0.0"`,
		`"status":`+jsonString(StatusPass), `"note":null`)
	in := checkNoteSubmission(rules, "["+good+","+bad+"]")
	expectInvalidCheckNote(t, in, "checks[1]", "r1")
}

// --- 省略 note 的既有行为不变 ---

func TestParseAuditOmittedNoteKeepsStatusRules(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	// 通过：允许省略说明，报告正常生成且没有 finding。
	in := checkNoteSubmission("["+artifactTextRule+"]",
		"["+noteCheck(hash, StatusPass, "")+"]")
	report := strictParsedReport(t, in)
	if report.Rules[0].Status != StatusPass || report.Rules[0].Note != "" {
		t.Fatalf("an omitted pass note must stay empty: %+v", report.Rules[0])
	}
	if len(report.Findings) != 0 {
		t.Fatalf("a pass must produce no findings: %+v", report.Findings)
	}

	// 发现缺陷、工具缺失、超时：省略说明仍是既有的必填业务错误，不是类型错误。
	for _, status := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		t.Run(status, func(t *testing.T) {
			in := checkNoteSubmission("["+artifactTextRule+"]",
				"["+noteCheck(hash, status, "")+"]")
			artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
			if err != nil {
				t.Fatalf("omitting the note must parse (business check is later): %v", err)
			}
			_, err = BuildReport(artifact, rules, invariants, checks)
			if err == nil {
				t.Fatalf("status %s with an omitted note must keep failing", status)
			}
			if !strings.Contains(err.Error(), "note is required for status "+status) {
				t.Fatalf("error must keep the existing required-note wording: %v", err)
			}
			if strings.Contains(err.Error(), "must be a string") {
				t.Fatalf("an omitted note must not be a type error: %v", err)
			}
		})
	}
}

// --- 显式空串与纯空白串：通过允许；其余三种状态沿用既有空白失败 ---

func TestParseAuditEmptyAndWhitespaceNoteBusinessRules(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	// 显式 "" 与省略对通过状态等价：同一报告标识。
	omitted := checkNoteSubmission("["+artifactTextRule+"]",
		"["+noteCheck(hash, StatusPass, "")+"]")
	empty := checkNoteSubmission("["+artifactTextRule+"]",
		"["+noteCheck(hash, StatusPass, `"note":""`)+"]")
	if strictParsedReport(t, omitted).ReportID != strictParsedReport(t, empty).ReportID {
		t.Fatal("an omitted and an explicit-empty pass note must share the report id")
	}

	// 只有空白的说明对通过合法，且原文逐字保留。
	ws := " \t\n "
	whitespace := checkNoteSubmission("["+artifactTextRule+"]",
		"["+noteCheck(hash, StatusPass, `"note":`+jsonString(ws))+"]")
	report := strictParsedReport(t, whitespace)
	if report.Rules[0].Note != ws {
		t.Fatalf("whitespace-only pass note must be preserved verbatim: %q", report.Rules[0].Note)
	}

	// 其余三种状态：显式空串或纯空白仍是既有 “note is required” 业务失败。
	for _, status := range []string{StatusDefect, StatusToolMissing, StatusTimeout} {
		for _, val := range []string{`""`, `"  \n  "`} {
			artifact, rules, invariants, checks := parseCheckNoteSubmission(t,
				checkNoteSubmission("["+artifactTextRule+"]",
					"["+noteCheck(hash, status, `"note":`+val)+"]"))
			_, err := BuildReport(artifact, rules, invariants, checks)
			if err == nil || !strings.Contains(err.Error(), "note is required for status "+status) {
				t.Fatalf("status %s note %s must keep the blank-note failure, got: %v", status, val, err)
			}
		}
	}
}

// parseCheckNoteSubmission 解析一份提交，失败即终止；供业务阶段断言使用。
func parseCheckNoteSubmission(t *testing.T, in string) (Artifact, []Rule, map[string]bool, []CheckRecord) {
	t.Helper()
	artifact, rules, invariants, checks, err := ParseAuditInput([]byte(in))
	if err != nil {
		t.Fatalf("legal submission must parse: %v\ninput: %s", err, in)
	}
	return artifact, rules, invariants, checks
}

// --- 合法说明逐字保留：中文、换行、前后空格；证据采用原文；工具缺失/超时不进缺陷 ---

func TestParseAuditLegalNotePreservedVerbatim(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	notes := map[string]string{
		StatusDefect:      "  反例：攻击者可在 withdraw 中重入\n第二行证据  ",
		StatusToolMissing: " 符号执行引擎未安装：PATH 中没有 mythril\n",
		StatusTimeout:     "\t超过 300s 截止时间仍未遍历完 ",
	}
	for status, note := range notes {
		t.Run(status, func(t *testing.T) {
			in := checkNoteSubmission("["+artifactTextRule+"]",
				"["+noteCheck(hash, status, `"note":`+jsonString(note))+"]")
			artifact, rules, invariants, checks := parseCheckNoteSubmission(t, in)
			if checks[0].Note != note {
				t.Fatalf("note must be preserved verbatim:\n got %q\nwant %q", checks[0].Note, note)
			}
			report, err := BuildReport(artifact, rules, invariants, checks)
			if err != nil {
				t.Fatalf("a legal note must build a report: %v", err)
			}
			if report.Rules[0].Note != note {
				t.Fatalf("rule note must be verbatim: %q", report.Rules[0].Note)
			}
			// 与直接用 Go 值构建的报告共享标识。
			direct, err := BuildReport(strictTestArtifact(),
				[]Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1.0.0"}},
				nil,
				[]CheckRecord{{ArtifactHash: hash, RuleID: "r1", Version: "1.0.0", Status: status, Note: note}})
			if err != nil {
				t.Fatal(err)
			}
			if report.ReportID != direct.ReportID {
				t.Fatalf("report id must keep its existing value:\n got %s\nwant %s", report.ReportID, direct.ReportID)
			}
			if status == StatusDefect {
				if len(report.Findings) != 1 {
					t.Fatalf("a defect must produce exactly one finding: %+v", report.Findings)
				}
				if report.Findings[0].Evidence != note {
					t.Fatalf("evidence must be the submitted note verbatim:\n got %q\nwant %q", report.Findings[0].Evidence, note)
				}
			} else {
				if len(report.Findings) != 0 {
					t.Fatalf("%s must not enter the findings list: %+v", status, report.Findings)
				}
			}
		})
	}
}

// --- 大小写变体、带空格名称是扩展信息：不触发本类型错误，也不能补位或挽救 ---

func TestParseAuditNoteVariantsIgnored(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())

	// 正式 note 省略，变体携带任意类型（含 null）：只是扩展信息，通过仍成功，
	// 报告标识与不含变体的提交一致。
	plain := checkNoteSubmission("["+artifactTextRule+"]",
		"["+noteCheck(hash, StatusPass, "")+"]")
	for _, ext := range []string{`"Note":null`, `" note ":null`, `"mystery":[1,2]`, `"Note":"说明"`} {
		t.Run(ext, func(t *testing.T) {
			in := checkNoteSubmission("["+artifactTextRule+"]",
				"["+noteCheck(hash, StatusPass, ext)+"]")
			got := strictParsedReport(t, in)
			if got.Rules[0].Note != "" {
				t.Fatalf("extension member %s must not supply the formal note: %+v", ext, got.Rules[0])
			}
			if got.ReportID != strictParsedReport(t, plain).ReportID {
				t.Fatalf("extension member %s changed the report id", ext)
			}
		})
	}

	// 缺陷记录缺少正式 note，变体给了合法字符串：不能补位，仍是必填业务失败。
	missing := checkObject(
		fmt.Sprintf(`"artifactHash":%q`, hash), `"ruleId":"r1"`, `"version":"1.0.0"`,
		`"status":`+jsonString(StatusDefect), `"Note":"变体里的说明"`)
	in := checkNoteSubmission("["+artifactTextRule+"]", "["+missing+"]")
	artifact, rules, invariants, checks := parseCheckNoteSubmission(t, in)
	_, err := BuildReport(artifact, rules, invariants, checks)
	if err == nil || !strings.Contains(err.Error(), "note is required for status "+StatusDefect) {
		t.Fatalf("a variant note must not fill a missing formal note, got: %v", err)
	}

	// 正式 note 为 null，旁边的变体携带合法字符串（位于其前或其后）都不能挽救。
	for _, pos := range []string{"before", "after"} {
		t.Run(pos, func(t *testing.T) {
			var rec string
			if pos == "before" {
				rec = noteCheck(hash, StatusPass, `"Note":"说明","note":null`)
			} else {
				rec = noteCheck(hash, StatusPass, `"note":null," note ":"说明"`)
			}
			in := checkNoteSubmission("["+artifactTextRule+"]", "["+rec+"]")
			expectInvalidCheckNote(t, in, "checks[0]", "r1")
		})
	}
}

// --- Unicode 转义写出的正式名称遵守同一字符串规则 ---

func TestParseAuditEscapedNoteNameFollowsSameRule(t *testing.T) {
	hash := ArtifactHash(strictTestArtifact())
	// "note" 的首字母 n 的码位是 0x6e：转义写出后解码仍是正式 note，null 拒绝。
	escName := "\\" + "u006e" + "ote"
	rec := noteCheck(hash, StatusPass, `"`+escName+`":null`)
	in := checkNoteSubmission("["+artifactTextRule+"]", "["+rec+"]")
	if !strings.Contains(in, `\`+"u006eote") {
		t.Fatalf("test setup must carry the JSON escape, got %s", in)
	}
	expectInvalidCheckNote(t, in, "checks[0]", "r1")

	// 转义写法携带合法字符串时，与直接书写解析到同一记录、同一报告标识。
	escaped := checkNoteSubmission("["+artifactTextRule+"]",
		"["+noteCheck(hash, StatusDefect, `"`+escName+`":`+jsonString("反例"))+"]")
	plainLegal := checkNoteSubmission("["+artifactTextRule+"]",
		"["+noteCheck(hash, StatusDefect, `"note":`+jsonString("反例"))+"]")
	if strictParsedReport(t, escaped).ReportID != strictParsedReport(t, plainLegal).ReportID {
		t.Fatal("escaped and plain spellings of a legal note must share the report id")
	}
}
