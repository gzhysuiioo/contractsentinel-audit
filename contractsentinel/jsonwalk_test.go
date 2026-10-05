package contractsentinel

import (
	"errors"
	"strings"
	"testing"
)

// 本文件锁定两类整文档检查共用的唯一结构遍历（jsonwalk.go）：对象/数组的
// 逐层识别、数组下标、成员名解码、字符串原子性，以及路径约定。重复成员检查与
// 字符合法性检查都建立在这次遍历之上，因此嵌套处理只需在此维护一份。

// recordVisitor 记录一次遍历见到的对象边界、成员名与字符串值及其路径。
type recordVisitor struct {
	begins  []string
	members []string
	values  []string
	stopAt  string
	stopped bool
}

func (r *recordVisitor) beginObject(path []jsonPathStep) {
	r.begins = append(r.begins, renderJSONPath(path))
}

func (r *recordVisitor) endObject() {}

func (r *recordVisitor) memberName(key string, _ []byte, _, _ int, objectPath []jsonPathStep) error {
	r.members = append(r.members, renderJSONPath(objectPath)+"#"+key)
	if r.stopped && key == r.stopAt {
		return errJSONWalkStop
	}
	return nil
}

func (r *recordVisitor) stringValue(data []byte, start, end int, valuePath []jsonPathStep) error {
	r.values = append(r.values, renderJSONPath(valuePath)+"="+string(data[start:end]))
	return nil
}

func TestWalkReachesEveryObjectArrayAndExtension(t *testing.T) {
	in := []byte(`{
		"artifact": {"name": "A"},
		"rules": [{"id": "r1"}, {"id": "r2"}],
		"mystery": {"deep": [{"note": "nested"}]}
	}`)
	r := &recordVisitor{}
	if err := walkJSONStructure(in, r); err != nil {
		t.Fatalf("walk of legal input must not error: %v", err)
	}
	wantBegins := []string{"", ".artifact", ".rules[0]", ".rules[1]", ".mystery", ".mystery.deep[0]"}
	if strings.Join(r.begins, "|") != strings.Join(wantBegins, "|") {
		t.Fatalf("object paths = %v, want %v", r.begins, wantBegins)
	}
	// 未知扩展成员深层嵌套的字符串值同样可达。
	var sawNestedNote bool
	for _, v := range r.values {
		if strings.HasPrefix(v, ".mystery.deep[0].note=") {
			sawNestedNote = true
		}
	}
	if !sawNestedNote {
		t.Fatalf("walker must reach strings nested under unknown extensions: %v", r.values)
	}
}

func TestWalkMemberNameUsesDecodedText(t *testing.T) {
	// inv 解码后是 "inv"：成员名按解码后的实际文字上报。
	r := &recordVisitor{}
	if err := walkJSONStructure([]byte(`{"inv": true}`), r); err != nil {
		t.Fatal(err)
	}
	want := "#inv"
	if len(r.members) != 1 || r.members[0] != want {
		t.Fatalf("member = %v, want %q (decoded name)", r.members, want)
	}
}

func TestWalkMemberNamePathIsContainingObject(t *testing.T) {
	r := &recordVisitor{}
	if err := walkJSONStructure([]byte(`{"outer":{"inner":1}}`), r); err != nil {
		t.Fatal(err)
	}
	// 成员名定位到包含它的对象：inner 之前的对象路径是 .outer。
	want := []string{"#outer", ".outer#inner"}
	if strings.Join(r.members, "|") != strings.Join(want, "|") {
		t.Fatalf("member name paths = %v, want %v", r.members, want)
	}
}

func TestWalkStringsAreAtomic(t *testing.T) {
	// 字符串内容里再像 JSON 的文字也只是普通内容：不产生新对象、不产生新成员。
	r := &recordVisitor{}
	in := []byte(`{"note":"{\"a\":1, \"a\":2}","arr":["{\"x\":1}"]}`)
	if err := walkJSONStructure(in, r); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.begins, "|") != "" {
		t.Fatalf("only the top-level object may be opened, got %v", r.begins)
	}
	wantMembers := []string{"#note", "#arr"}
	if strings.Join(r.members, "|") != strings.Join(wantMembers, "|") {
		t.Fatalf("members = %v, want %v", r.members, wantMembers)
	}
}

func TestWalkTopLevelScalars(t *testing.T) {
	for _, in := range []string{`"顶层字符串"`, `123`, `true`, `null`, `[1,"二",3]`} {
		r := &recordVisitor{}
		if err := walkJSONStructure([]byte(in), r); err != nil {
			t.Errorf("walk %q errored: %v", in, err)
		}
	}
	// 顶层字符串值的路径为空。
	r := &recordVisitor{}
	if err := walkJSONStructure([]byte(`"顶层字符串"`), r); err != nil {
		t.Fatal(err)
	}
	if len(r.values) != 1 || !strings.HasSuffix(r.values[0], `="顶层字符串"`) {
		t.Fatalf("top-level string value = %v", r.values)
	}
}

func TestWalkStringTokenSpansQuotes(t *testing.T) {
	r := &recordVisitor{}
	in := []byte(`{"a":  "xy" }`)
	if err := walkJSONStructure(in, r); err != nil {
		t.Fatal(err)
	}
	if len(r.values) != 1 {
		t.Fatalf("values = %v", r.values)
	}
	// 片面前缘可能带分隔空白，但以闭合引号收尾；首个引号即开引号。
	raw := strings.SplitN(r.values[0], "=", 2)[1]
	if !strings.HasSuffix(raw, `"`) || !strings.Contains(raw, `"xy"`) {
		t.Fatalf("token slice must cover the quoted string, got %q", raw)
	}
}

func TestWalkRetainedPathsAreIndependent(t *testing.T) {
	// 访问者保留的路径不能被后续兄弟节点的遍历覆盖。
	keep := &keepVisitor{}
	in := []byte(`{"rules":[{"id":"r0"},{"id":"r1"},{"id":"r2"}]}`)
	if err := walkJSONStructure(in, keep); err != nil {
		t.Fatal(err)
	}
	want := []string{"", ".rules[0]", ".rules[1]", ".rules[2]"}
	if strings.Join(keep.paths, "|") != strings.Join(want, "|") {
		t.Fatalf("retained object paths = %v, want %v", keep.paths, want)
	}
}

type keepVisitor struct{ paths []string }

func (k *keepVisitor) beginObject(path []jsonPathStep) {
	k.paths = append(k.paths, renderJSONPath(path))
}
func (k *keepVisitor) endObject() {}
func (k *keepVisitor) memberName(string, []byte, int, int, []jsonPathStep) error {
	return nil
}
func (k *keepVisitor) stringValue([]byte, int, int, []jsonPathStep) error { return nil }

func TestWalkStopAborts(t *testing.T) {
	r := &recordVisitor{stopped: true, stopAt: "b"}
	in := []byte(`{"a":1,"b":2,"c":3}`)
	err := walkJSONStructure(in, r)
	if !errors.Is(err, errJSONWalkStop) {
		t.Fatalf("err = %v, want errJSONWalkStop", err)
	}
	for _, m := range r.members {
		if strings.HasSuffix(m, "#c") {
			t.Fatalf("walk must stop before member c: %v", r.members)
		}
	}
}

func TestWalkMalformedJSONReturnsDecoderError(t *testing.T) {
	// 纯语法错误不由遍历臆造结论：返回解码器错误，交由 json.Unmarshal 统一报。
	for _, in := range []string{``, `{`, `{"a":1 "b":2}`, `{"a":`} {
		if err := walkJSONStructure([]byte(in), &recordVisitor{}); err == nil {
			t.Errorf("malformed input %q must return a decoder error", in)
		}
	}
}

func TestRenderJSONPath(t *testing.T) {
	if got := renderJSONPath(nil); got != "" {
		t.Fatalf("empty path = %q, want empty string", got)
	}
	got := renderJSONPath([]jsonPathStep{jsonMemberStep("checks"), jsonIndexStep(1), jsonMemberStep("note")})
	if want := ".checks[1].note"; got != want {
		t.Fatalf("renderJSONPath = %q, want %q", got, want)
	}
}
