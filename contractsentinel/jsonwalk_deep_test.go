package contractsentinel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// 本文件锁定深层嵌套输入（对象、数组交替的长链，数千层未知扩展信息）下的
// 两类行为：
//
//   - 合法深嵌套内容继续受支持：audit 提交、report 读回与 diff 两侧的检查
//     结果与没有扩展内容时逐字节一致；扩展成员不参与产物哈希、报告标识与
//     规则结论。
//   - 重复成员检查与字符合法性检查的附加内存随输入大小和最大嵌套深度线性
//     增长（共享路径栈），不再按深度平方复制路径；一个分支处理完后，后面
//     兄弟分支里的问题定位不混入前一个分支的成员名或数组下标。

// deepNestJSON 把 leaf 包进 depth 层对象/数组交替的嵌套（{"a":[{"a":[...leaf...]}]}），
// 并返回 leaf 值相对嵌套根的定位路径（".a[0].a[0]..."）。
func deepNestJSON(depth int, leaf string) (nested string, leafPath string) {
	var b, p strings.Builder
	for i := 0; i < depth; i++ {
		if i%2 == 0 {
			b.WriteString(`{"a":`)
			p.WriteString(".a")
		} else {
			b.WriteString(`[`)
			p.WriteString("[0]")
		}
	}
	b.WriteString(leaf)
	for i := depth - 1; i >= 0; i-- {
		if i%2 == 0 {
			b.WriteString(`}`)
		} else {
			b.WriteString(`]`)
		}
	}
	return b.String(), p.String()
}

// --- 合法深嵌套：提交与归档行为逐字节不变 ---

func TestParseAuditInputDeepExtensionNestUnchanged(t *testing.T) {
	nest, _ := deepNestJSON(4000, `{"leaf":[1,2,3]}`)
	baseline := []byte(`{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1.0.0"}],
		"invariants": {"inv": false}
	}`)
	deep := []byte(`{
		"artifact": {"name":"Vault","abi":"abi","bytecode":"0x1","source":"Vault.sol"},
		"rules": [{"id":"r1","kind":"static","severity":"high","invariant":"inv","version":"1.0.0"}],
		"invariants": {"inv": false},
		"mystery": ` + nest + `
	}`)
	a0, r0, i0, c0, err := ParseAuditInput(baseline)
	if err != nil {
		t.Fatalf("baseline must parse: %v", err)
	}
	a1, r1, i1, c1, err := ParseAuditInput(deep)
	if err != nil {
		t.Fatalf("thousands of nested extension layers must stay supported: %v", err)
	}
	rep0, err := BuildReport(a0, r0, i0, c0)
	if err != nil {
		t.Fatal(err)
	}
	rep1, err := BuildReport(a1, r1, i1, c1)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep0, rep1) {
		t.Fatalf("extension nest must not change the report:\n%+v\n%+v", rep0, rep1)
	}
	if rep1.ReportID != rep0.ReportID {
		t.Fatalf("report id changed by extension data: %s vs %s", rep0.ReportID, rep1.ReportID)
	}
	if len(rep1.Findings) != 1 || rep1.Findings[0].Evidence != "invariant inv does not hold" {
		t.Fatalf("defect and evidence must be preserved: %+v", rep1.Findings)
	}
}

func TestLoadStoredReportDeepExtensionNest(t *testing.T) {
	artifact := Artifact{Name: "Vault", ABI: "abi", Bytecode: "0x1", Source: "Vault.sol"}
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1.0.0"}}
	rep, err := BuildReport(artifact, rules, map[string]bool{"inv": false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	// 在归档 JSON 里加入数千层嵌套的未知扩展成员：不参与标识与结论，读回必须成功。
	nest, _ := deepNestJSON(4000, `"深"`)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	obj["mystery"] = json.RawMessage(nest)
	ext, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, rep.ReportID+".json"), ext, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadReport(dir, rep.ReportID)
	if err != nil {
		t.Fatalf("archive with a deep extension nest must load: %v", err)
	}
	if !reflect.DeepEqual(got, rep) {
		t.Fatalf("loaded report differs:\n%+v\n%+v", rep, got)
	}
	diff, err := DiffStore(dir, rep.ReportID, rep.ReportID)
	if err != nil {
		t.Fatalf("diff over deep-extension archives must work: %v", err)
	}
	if diff.Summary.NoChange != len(rep.Rules) || len(diff.Results) != len(rep.Rules) {
		t.Fatalf("self-diff must report every rule unchanged: %+v", diff.Summary)
	}
}

// --- 附加内存随输入大小与最大嵌套深度线性增长 ---

func TestWalkDeepNestMemoryGrowsLinearly(t *testing.T) {
	walkAlloc := func(depth int) (uint64, int) {
		nest, _ := deepNestJSON(depth, `"leaf"`)
		data := []byte(`{"mystery":` + nest + `}`)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		if e := validateJSONCharacters(data); e != nil {
			t.Fatalf("depth %d: legal input rejected: %v", depth, e)
		}
		if d := findDuplicateJSONMember(data); d != nil {
			t.Fatalf("depth %d: legal input has no duplicate: %v", depth, d)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc, len(data)
	}
	alloc1k, _ := walkAlloc(1000)
	alloc4k, size4k := walkAlloc(4000)
	// 深度变为 4 倍时，线性实现的附加内存约 4 倍；逐层复制路径的实现约 16 倍。
	if alloc4k > alloc1k*6 {
		t.Fatalf("walk memory grows superlinearly in depth: depth 1000 -> %d bytes, depth 4000 -> %d bytes", alloc1k, alloc4k)
	}
	// 附加内存不超过输入大小的固定倍数。
	if alloc4k > uint64(size4k)*500 {
		t.Fatalf("walk memory exceeds a constant multiple of the input: %d bytes for %d input bytes", alloc4k, size4k)
	}
}

// --- 分支处理完后，后面分支的错误定位不混入前一分支 ---

func TestDeepNestSiblingBranchErrorLocation(t *testing.T) {
	nest, _ := deepNestJSON(200, `"leaf"`)

	t.Run("duplicate in later top-level branch", func(t *testing.T) {
		data := []byte(`{"mystery":` + nest + `,"invariants":{"inv":false,"inv":true}}`)
		dup := findDuplicateJSONMember(data)
		if dup == nil {
			t.Fatal("duplicate in the later branch must be found")
		}
		msg := duplicateMemberMessage(data, dup)
		if !strings.HasSuffix(msg, `in the invariants object`) {
			t.Fatalf("location must name the invariants object, got %q", msg)
		}
		if strings.Contains(msg, "mystery") || strings.Contains(msg, "[0]") {
			t.Fatalf("location must not leak the finished extension branch: %q", msg)
		}
	})

	t.Run("duplicate in later rules entry", func(t *testing.T) {
		data := []byte(`{"rules":[{"id":"r1","version":"1","extra":` + nest + `},{"id":"r2","id":"r2","version":"1"}]}`)
		dup := findDuplicateJSONMember(data)
		if dup == nil {
			t.Fatal("duplicate in rules[1] must be found")
		}
		msg := duplicateMemberMessage(data, dup)
		if !strings.HasSuffix(msg, `rule "r2" (rules[1])`) {
			t.Fatalf("location must name rules[1] and its id, got %q", msg)
		}
		if strings.Contains(msg, "extra") {
			t.Fatalf("location must not leak the previous entry's extension branch: %q", msg)
		}
	})

	t.Run("duplicate in later checks entry", func(t *testing.T) {
		data := []byte(`{"checks":[{"ruleId":"r1","extra":` + nest + `},{"ruleId":"r2","ruleId":"r2"}]}`)
		dup := findDuplicateJSONMember(data)
		if dup == nil {
			t.Fatal("duplicate in checks[1] must be found")
		}
		msg := duplicateMemberMessage(data, dup)
		if !strings.HasSuffix(msg, `check record for rule "r2" (checks[1])`) {
			t.Fatalf("location must name checks[1] and its ruleId, got %q", msg)
		}
	})

	t.Run("character error in later branch", func(t *testing.T) {
		data := []byte(`{"mystery":` + nest + `,"checks":[{"note":"x\uD800y"}]}`)
		e := validateJSONCharacters(data)
		if e == nil {
			t.Fatal("lone surrogate in the later branch must be rejected")
		}
		if !strings.Contains(e.Error(), ".checks[0].note") {
			t.Fatalf("location must name the later branch's value, got %q", e.Error())
		}
		if strings.Contains(e.Error(), "mystery") {
			t.Fatalf("location must not leak the finished extension branch: %q", e.Error())
		}
	})

	t.Run("duplicate after wide sibling array", func(t *testing.T) {
		data := []byte(`{"arr":[[["x"]],[{"y":1,"y":2}]]}`)
		dup := findDuplicateJSONMember(data)
		if dup == nil {
			t.Fatal("duplicate in the second array element must be found")
		}
		msg := duplicateMemberMessage(data, dup)
		if !strings.HasSuffix(msg, `object at .arr[1][0]`) {
			t.Fatalf("location must use the second element's own indices, got %q", msg)
		}
	})
}

// --- 深嵌套内部的错误定位：完整成员路径与从零开始的数组下标 ---

func TestDeepNestInteriorErrorLocation(t *testing.T) {
	const depth = 60

	t.Run("duplicate member deep inside", func(t *testing.T) {
		nest, leafPath := deepNestJSON(depth, `{"x":1,"x":2}`)
		data := []byte(`{"mystery":` + nest + `}`)
		dup := findDuplicateJSONMember(data)
		if dup == nil {
			t.Fatal("duplicate at the bottom of the nest must be found")
		}
		if dup.member != "x" {
			t.Fatalf("duplicate member = %q, want x", dup.member)
		}
		want := "object at .mystery" + leafPath
		msg := duplicateMemberMessage(data, dup)
		if !strings.HasSuffix(msg, want) {
			t.Fatalf("location must render the full deep path %q, got %q", want, msg)
		}
	})

	t.Run("character error deep inside", func(t *testing.T) {
		nest, leafPath := deepNestJSON(depth, `"a\uD800b"`)
		data := []byte(`{"mystery":` + nest + `}`)
		e := validateJSONCharacters(data)
		if e == nil {
			t.Fatal("lone surrogate at the bottom of the nest must be rejected")
		}
		want := ".mystery" + leafPath
		if !strings.Contains(e.Error(), want) {
			t.Fatalf("location must render the full deep path %q, got %q", want, e.Error())
		}
		// 字节偏移指向转义反斜线；单行输入下列号为偏移加一。
		if data[e.offset] != '\\' {
			t.Fatalf("offset %d must point at the escape backslash, got %q", e.offset, data[e.offset])
		}
		if e.line != 1 || e.column != e.offset+1 {
			t.Fatalf("single-line input: position = line %d column %d, want 1:%d", e.line, e.column, e.offset+1)
		}
	})
}
