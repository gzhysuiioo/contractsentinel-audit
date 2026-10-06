package contractsentinel

import (
	"strings"
	"testing"
)

// 本文件锁定结构遍历本身的资源与定位行为：
//   - 由对象、数组交替组成的深层嵌套链（数千层、位于未知扩展成员之下）
//     必须照常通过两项检查并整体受理；
//   - 遍历完一个分支后，后续分支里的问题必须定位到实际出错的位置，
//     不能混入前一个分支的成员名或数组下标；
//   - 深层链中的重复成员仍按解码后的成员名检出，路径深度与实际一致。

// nestAlternating 生成 depth 层对象/数组交替的嵌套链，包裹 inner。
func nestAlternating(inner string, depth int) string {
	var b strings.Builder
	for i := 0; i < depth; i++ {
		if i%2 == 0 {
			b.WriteString(`{"k":`)
		} else {
			b.WriteByte('[')
		}
	}
	b.WriteString(inner)
	for i := depth - 1; i >= 0; i-- {
		if i%2 == 0 {
			b.WriteByte('}')
		} else {
			b.WriteByte(']')
		}
	}
	return b.String()
}

func TestWalkDeepAlternatingNestingAccepted(t *testing.T) {
	const depth = 5000 // 数千层交替嵌套，全部位于未知扩展成员之下
	leaf := `{"note":"合法中文与换行\n","pair":"𝄞"}`
	data := []byte(`{"artifact":{"name":"A"},"rules":[],"mystery":` +
		nestAlternating(leaf, depth) + `}`)

	if dup := findDuplicateJSONMember(data); dup != nil {
		t.Fatalf("legal deep nesting must not yield a duplicate: %+v", dup)
	}
	if charErr := validateJSONCharacters(data); charErr != nil {
		t.Fatalf("legal deep nesting must not yield a character error: %v", charErr)
	}
	if _, _, _, _, err := ParseAuditInput(data); err != nil {
		t.Fatalf("deeply nested extension data must stay accepted: %v", err)
	}
}

func TestWalkDeepNestingDuplicateLocatedAtDepth(t *testing.T) {
	const depth = 2000
	data := []byte(`{"mystery":` + nestAlternating(`{"x":1,"x":2}`, depth) + `}`)
	dup := findDuplicateJSONMember(data)
	if dup == nil {
		t.Fatal("a duplicate member at the bottom of a deep chain must be detected")
	}
	if dup.member != "x" {
		t.Fatalf("duplicate member = %q, want x", dup.member)
	}
	// 路径必须一路定位到最内层对象：mystery 一层加上 depth 层交替嵌套。
	if got, want := len(dup.path), depth+1; got != want {
		t.Fatalf("duplicate path depth = %d, want %d", got, want)
	}
}

func TestWalkLaterBranchErrorNotPollutedByEarlierBranch(t *testing.T) {
	// 前一个分支处理完毕后，后一个分支里的重复成员必须定位到后一个分支，
	// 不得残留前一个分支的成员名或下标。
	data := []byte(`{"mystery":{"first":[0,1,{"k":[2,3]}],"second":{"x":1,"x":2}}}`)
	dup := findDuplicateJSONMember(data)
	if dup == nil {
		t.Fatal("duplicate in the later branch must be detected")
	}
	if got, want := renderJSONPath(dup.path), ".mystery.second"; got != want {
		t.Fatalf("duplicate located at %q, want %q", got, want)
	}

	// 字符错误同理：后一个分支的非法转义必须指到后一个分支的值。
	charData := []byte(`{"mystery":{"first":["ok","fine"],"second":"\uD800"}}`)
	charErr := validateJSONCharacters(charData)
	if charErr == nil {
		t.Fatal("unpaired surrogate in the later branch must be detected")
	}
	if got, want := renderJSONPath(charErr.path), ".mystery.second"; got != want {
		t.Fatalf("character error located at %q, want %q", got, want)
	}
}

func TestWalkWideArrayKeepsSiblingIndexes(t *testing.T) {
	// 宽数组中每个元素的下标必须各自独立：错误定位到实际出错的元素。
	data := []byte(`{"mystery":[0,1,2,{"x":1,"x":2},4]}`)
	dup := findDuplicateJSONMember(data)
	if dup == nil {
		t.Fatal("duplicate inside an array element must be detected")
	}
	if got, want := renderJSONPath(dup.path), ".mystery[3]"; got != want {
		t.Fatalf("duplicate located at %q, want %q", got, want)
	}
}
