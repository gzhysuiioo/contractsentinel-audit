// Package contractsentinel: strict detection of repeated JSON object members.
package contractsentinel

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// duplicateMemberError records the repeated member name and the path of the
// object containing it. The path is schema-free; duplicateMemberMessage turns
// it into a user-facing message that names the rule id or check ruleId when
// the object is a rules/checks array entry.
type duplicateMemberError struct {
	member string
	path   []jsonPathStep
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
// The structural walk itself — which values are objects or arrays, how deep
// they nest and which path locates each of them — is shared with the
// character-legality check in walkJSONTokens, so the two checks can never
// drift apart on how nested input is traversed. This check only adds its own
// per-object bookkeeping of the member names already seen.
//
// Malformed JSON yields nil here; json.Unmarshal remains the single source
// of syntax errors and runs right after this scan.
func findDuplicateJSONMember(data []byte) *duplicateMemberError {
	var dup *duplicateMemberError
	// seenStack holds the member names seen so far in each open object,
	// innermost object last; enterObject and exitObject keep it in step with
	// the walk.
	var seenStack []map[string]bool
	walkJSONTokens(data, jsonWalkHooks{
		enterObject: func(path []jsonPathStep) {
			seenStack = append(seenStack, make(map[string]bool))
		},
		exitObject: func(path []jsonPathStep) {
			seenStack = seenStack[:len(seenStack)-1]
		},
		memberName: func(path []jsonPathStep, name string, start, end int) bool {
			seen := seenStack[len(seenStack)-1]
			if seen[name] {
				// path locates the containing object, not the repeated member;
				// take a copy so later walk events cannot overwrite the
				// retained path.
				dup = &duplicateMemberError{member: name, path: append([]jsonPathStep(nil), path...)}
				return true
			}
			seen[name] = true
			return false
		},
	})
	return dup
}

// duplicateMemberMessage renders the user-facing error: it states that a
// member is duplicated, quotes the decoded member name, and locates the
// object. Rules and check records are named by their id / ruleId so the user
// can tell which entry is wrong.
func duplicateMemberMessage(data []byte, dup *duplicateMemberError) string {
	return "duplicate JSON member " + strconv.Quote(dup.member) + " in " + locateDupObject(data, dup.path)
}

// locateDupObject describes the object that contains the repeated member.
func locateDupObject(data []byte, path []jsonPathStep) string {
	if len(path) == 0 {
		return "the top-level object"
	}
	head := path[0]
	switch head.key {
	case "artifact":
		if len(path) == 1 {
			return "the artifact object"
		}
		return "the artifact object (" + renderJSONPath(path[1:]) + ")"
	case "invariants":
		if len(path) == 1 {
			return "the invariants object"
		}
		return "the invariants object (" + renderJSONPath(path[1:]) + ")"
	case "rules", "checks", "findings":
		// The entry itself is the second path step (an array index).
		if len(path) >= 2 && path[1].index >= 0 {
			loc := fmt.Sprintf("%s[%d]", head.key, path[1].index) + renderJSONPath(path[2:])
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
	return "object at " + renderJSONPath(path)
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
