// Package contractsentinel: strict detection of repeated JSON object members.
package contractsentinel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// dupPathStep locates one level of a JSON value: a member step when the value
// was reached through an object member, or an index step when it is an
// element of an array.
type dupPathStep struct {
	key   string // member name for an object step; "" for an array step
	index int    // 0-based array index for an array step; -1 for an object step
}

// duplicateMemberError records the repeated member name and the path of the
// object containing it. The path is schema-free; duplicateMemberMessage turns
// it into a user-facing message that names the rule id or check ruleId when
// the object is a rules/checks array entry.
type duplicateMemberError struct {
	member string
	path   []dupPathStep
}

func (e *duplicateMemberError) Error() string {
	return "duplicate JSON member " + strconv.Quote(e.member)
}

// findDuplicateJSONMember scans data structurally and returns the first JSON
// object that repeats a member name. encoding/json keeps only the last value
// for a repeated key, so without this scan an invariants object writing the
// same invariant as false then true would import just the pass, and null
// then false would smuggle a defect past the non-boolean rejection.
//
// Member names are compared after JSON string decoding: "inv" written
// literally and the same name written with a Unicode escape collide.
// Comparison is case sensitive and never trims whitespace. Every object is
// checked, including the top-level object, nested objects and every array
// element; identical member names in different objects are normal. String
// values are consumed atomically, so text inside a string that looks like
// JSON is ordinary content and is never scanned.
//
// Malformed JSON yields nil here; json.Unmarshal remains the single source
// of syntax errors and runs right after this scan.
func findDuplicateJSONMember(data []byte) *duplicateMemberError {
	dec := json.NewDecoder(bytes.NewReader(data))
	// Keep number literals as text so oversized exponents cannot abort the
	// structural scan; values themselves are irrelevant to duplicate keys.
	dec.UseNumber()
	dup, _ := scanJSONValue(dec, nil)
	return dup
}

// scanJSONValue consumes exactly one JSON value from dec and reports the
// first repeated object member at or below it. path locates the consumed
// value within its document.
func scanJSONValue(dec *json.Decoder, path []dupPathStep) (*duplicateMemberError, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil, nil // null, bool, string or number: a complete scalar
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			// Between More() and the value, Token can only be a member name.
			key := keyTok.(string)
			if seen[key] {
				// path locates this object, not the repeated member; take a
				// copy so later siblings cannot overwrite the retained path.
				where := append([]dupPathStep(nil), path...)
				return &duplicateMemberError{member: key, path: where}, nil
			}
			seen[key] = true
			child := append(path, dupPathStep{key: key, index: -1})
			dup, err := scanJSONValue(dec, child)
			if err != nil {
				return nil, err
			}
			if dup != nil {
				return dup, nil
			}
		}
		_, err := dec.Token() // consume '}'
		return nil, err
	case '[':
		for i := 0; dec.More(); i++ {
			child := append(path, dupPathStep{index: i})
			dup, err := scanJSONValue(dec, child)
			if err != nil {
				return nil, err
			}
			if dup != nil {
				return dup, nil
			}
		}
		_, err := dec.Token() // consume ']'
		return nil, err
	default:
		// '}' and ']' are consumed by callers and never start a value.
		return nil, nil
	}
}

// duplicateMemberMessage renders the user-facing error: it states that a
// member is duplicated, quotes the decoded member name, and locates the
// object. Rules and check records are named by their id / ruleId so the user
// can tell which entry is wrong.
func duplicateMemberMessage(data []byte, dup *duplicateMemberError) string {
	return "duplicate JSON member " + strconv.Quote(dup.member) + " in " + locateDupObject(data, dup.path)
}

// locateDupObject describes the object that contains the repeated member.
func locateDupObject(data []byte, path []dupPathStep) string {
	if len(path) == 0 {
		return "the top-level object"
	}
	head := path[0]
	switch head.key {
	case "artifact":
		if len(path) == 1 {
			return "the artifact object"
		}
		return "the artifact object (" + renderDupPath(path[1:]) + ")"
	case "invariants":
		if len(path) == 1 {
			return "the invariants object"
		}
		return "the invariants object (" + renderDupPath(path[1:]) + ")"
	case "rules", "checks", "findings":
		// The entry itself is the second path step (an array index).
		if len(path) >= 2 && path[1].index >= 0 {
			loc := fmt.Sprintf("%s[%d]", head.key, path[1].index) + renderDupPath(path[2:])
			if id := arrayEntryID(data, head.key, path[1].index); id != "" {
				switch head.key {
				case "rules":
					return fmt.Sprintf("rule %q (%s)", id, loc)
				case "checks":
					return fmt.Sprintf("check record for rule %q (%s)", id, loc)
				default:
					return fmt.Sprintf("finding for rule %q (%s)", id, loc)
				}
			}
			switch head.key {
			case "rules":
				return "rule entry " + loc
			case "checks":
				return "check record " + loc
			default:
				return "finding entry " + loc
			}
		}
	}
	return "object at " + renderDupPath(path)
}

// arrayEntryID extracts the identifying field of one rules/checks/findings
// array element. Rules carry their own id; check and finding records name the
// rule via ruleId. The unmarshal is last-key-wins for repeated members, which
// is fine here: identification only needs some id carried by the offending
// entry, and the index already makes it unambiguous.
func arrayEntryID(data []byte, field string, index int) string {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return ""
	}
	arr, ok := root[field].([]any)
	if !ok || index < 0 || index >= len(arr) {
		return ""
	}
	obj, ok := arr[index].(map[string]any)
	if !ok {
		return ""
	}
	idKey := "ruleId"
	if field == "rules" {
		idKey = "id"
	}
	if v, ok := obj[idKey].(string); ok {
		return v
	}
	return ""
}

// renderDupPath renders schema-free path steps as ".key" and "[index]".
func renderDupPath(path []dupPathStep) string {
	var b strings.Builder
	for _, step := range path {
		if step.index >= 0 {
			fmt.Fprintf(&b, "[%d]", step.index)
		} else {
			b.WriteByte('.')
			b.WriteString(step.key)
		}
	}
	return b.String()
}
