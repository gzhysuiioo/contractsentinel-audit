// Package contractsentinel jsonwalk: the structural walk over a JSON document
// shared by the duplicate-member check and the character-legality check.
//
// Both checks must reach exactly the same values — every object member name
// and every string value, at every depth, including content nested under
// unknown extension members — so the layer-by-layer recognition of objects
// and arrays, and the path that locates each value, is defined exactly once
// here. The checks themselves (which names repeat inside one object, which
// characters a string literal may contain) stay in their own files and plug
// into this walk as hooks.
package contractsentinel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// jsonPathStep locates one level of a JSON value: a member step when the
// value was reached through an object member, or an index step when it is an
// element of an array.
type jsonPathStep struct {
	key   string // member name for an object step; "" for an array step
	index int    // 0-based array index for an array step; -1 for an object step
}

// jsonWalkHooks receives the events of one structural walk over a JSON
// document. Every path slice is owned by the walk and reused for later
// events; a hook that retains a path must copy it. memberName and
// stringValue return true to stop the walk immediately, which is how a check
// reports its first problem.
type jsonWalkHooks struct {
	// enterObject fires right after an object's opening brace; path locates
	// the object itself.
	enterObject func(path []jsonPathStep)
	// exitObject fires after the matching object's closing brace.
	exitObject func(path []jsonPathStep)
	// memberName fires for every object member name. path locates the
	// containing object (not the member), name is the decoded member name,
	// and start/end bound the raw name token in the input.
	memberName func(path []jsonPathStep, name string, start, end int) (stop bool)
	// stringValue fires for every string that is a value, never a member
	// name. path locates the value and start/end bound the raw string token.
	stringValue func(path []jsonPathStep, start, end int) (stop bool)
}

// walkJSONTokens scans data structurally once, firing hooks for every object,
// member name and string value at every depth: the top-level value, nested
// objects, array elements and the contents of unknown extension members
// alike. String values are consumed atomically by the decoder, so text inside
// a string that looks like JSON is ordinary content and never produces
// events. Number literals are kept as text so an oversized exponent cannot
// abort the walk; scalar values themselves are irrelevant to both checks.
// Member names are compared after JSON string decoding, so a name written
// literally and the same name written with Unicode escapes are the same name.
//
// The walk is best-effort over syntax: a decoder error stops it quietly,
// because json.Unmarshal remains the single source of syntax errors and runs
// right after these scans.
func walkJSONTokens(data []byte, hooks jsonWalkHooks) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	walkJSONValue(dec, nil, hooks)
}

// walkJSONValue consumes exactly one JSON value from dec, firing the hooks at
// and below it. path locates the value within its document. It reports true
// when the walk stopped, either because a hook asked to stop or because the
// input turned out to be malformed.
func walkJSONValue(dec *json.Decoder, path []jsonPathStep, hooks jsonWalkHooks) (stop bool) {
	start := int(dec.InputOffset())
	tok, err := dec.Token()
	if err != nil {
		return true // malformed JSON: defer to json.Unmarshal
	}
	end := int(dec.InputOffset())
	switch v := tok.(type) {
	case string:
		if hooks.stringValue != nil {
			return hooks.stringValue(path, start, end)
		}
		return false
	case json.Delim:
		switch v {
		case '{':
			if hooks.enterObject != nil {
				hooks.enterObject(path)
			}
			for dec.More() {
				keyStart := int(dec.InputOffset())
				keyTok, err := dec.Token()
				if err != nil {
					return true // malformed JSON: defer
				}
				keyEnd := int(dec.InputOffset())
				// Between More() and the value, Token can only be a member name.
				key, _ := keyTok.(string)
				if hooks.memberName != nil && hooks.memberName(path, key, keyStart, keyEnd) {
					return true
				}
				child := append(append([]jsonPathStep(nil), path...), jsonPathStep{key: key, index: -1})
				if walkJSONValue(dec, child, hooks) {
					return true
				}
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return true // malformed JSON: defer
			}
			if hooks.exitObject != nil {
				hooks.exitObject(path)
			}
			return false
		case '[':
			for i := 0; dec.More(); i++ {
				child := append(append([]jsonPathStep(nil), path...), jsonPathStep{index: i})
				if walkJSONValue(dec, child, hooks) {
					return true
				}
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return true // malformed JSON: defer
			}
			return false
		}
	}
	// '}' and ']' are consumed by the enclosing object or array and never
	// start a value; numbers, booleans and null are complete scalars.
	return false
}

// renderJSONPath renders schema-free path steps as ".key" and "[index]".
func renderJSONPath(path []jsonPathStep) string {
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
