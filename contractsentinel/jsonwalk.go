// Package contractsentinel jsonwalk: the single schema-free structural walk
// over a JSON document shared by the two whole-document gates, repeated-member
// detection (jsondup.go) and character-legality validation (jsonchars.go).
//
// Both gates must recognise exactly the same nesting -- the top-level value,
// every object and array at every depth, including objects and arrays nested
// under unknown extension members and inside array elements -- and locate a
// value with the same path convention. Maintaining that descent twice let the
// two checks drift whenever nested input handling changed. The walker now owns
// object/array recognition, array indices and path rendering once; each gate
// supplies only its own policy through a jsonStructureVisitor. String tokens
// are consumed atomically like every other scalar: the walker never descends
// into their contents, so text inside a string that looks like JSON is
// ordinary content for every visitor.
package contractsentinel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// jsonPathStep locates one level of a JSON value: a member step when the value
// was reached through an object member, or an index step when it is an element
// of an array. This is the one schema-free position convention shared by every
// structural check.
type jsonPathStep struct {
	key   string // decoded member name for an object step; "" for an array step
	index int    // 0-based array index for an array step; -1 for an object step
}

// jsonMemberStep builds the step for the value reached through member key.
func jsonMemberStep(key string) jsonPathStep {
	return jsonPathStep{key: key, index: -1}
}

// jsonIndexStep builds the step for array element i.
func jsonIndexStep(i int) jsonPathStep {
	return jsonPathStep{index: i}
}

// jsonPathCopy returns a detached copy of path so a retained slice cannot be
// overwritten by later sibling descent.
func jsonPathCopy(path []jsonPathStep) []jsonPathStep {
	return append([]jsonPathStep(nil), path...)
}

// renderJSONPath renders schema-free path steps as ".key" and "[index]". An
// empty path renders as the empty string; callers name the root themselves.
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

// errJSONWalkStop aborts a walk without signalling malformed JSON: a visitor
// returns it once it has found what it is looking for, and the walker unwinds
// immediately.
var errJSONWalkStop = errors.New("json structure walk stopped")

// jsonStructureVisitor observes one structural walk. Path slices passed to
// the hooks belong to the walker only for the call's duration; a hook that
// keeps one must copy it (see jsonPathCopy). Likewise data[start:end] token
// slices may begin with the whitespace or structural punctuation that
// separated the token, and always end on the token's closing quote.
type jsonStructureVisitor interface {
	// beginObject marks entry into the object located by path; endObject marks
	// its closing brace. Calls nest and balance on a complete walk, but a
	// visitor that aborts early receives no matching endObject.
	beginObject(path []jsonPathStep)
	endObject()

	// memberName reports one member name token. objectPath locates the
	// containing object and deliberately does not include the name itself:
	// character validation must locate a bad name by its parent because the
	// raw name may be unrenderable. key carries the JSON-decoded name, which
	// is what name equality compares on.
	memberName(key string, data []byte, start, end int, objectPath []jsonPathStep) error

	// stringValue reports one JSON string value located by valuePath, which
	// ends in the member step or array index that leads to it.
	stringValue(data []byte, start, end int, valuePath []jsonPathStep) error
}

// walkJSONStructure walks exactly one JSON value and reports the first visitor
// rejection at or below it. Malformed JSON yields the decoder error and is not
// a check finding: json.Unmarshal is the single source of syntax errors and
// runs right after the gates that use this walker. A visitor aborts an
// otherwise well-formed walk with errJSONWalkStop.
func walkJSONStructure(data []byte, v jsonStructureVisitor) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	// Keep number literals as text so an oversized exponent cannot abort the
	// structural walk; number contents are irrelevant to both gates.
	dec.UseNumber()
	start := 0
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	end := int(dec.InputOffset())
	switch t := tok.(type) {
	case string:
		return v.stringValue(data, start, end, nil)
	case json.Delim:
		switch t {
		case '{':
			return walkJSONObject(dec, data, nil, v)
		case '[':
			return walkJSONArray(dec, data, nil, v)
		}
	}
	return nil // null, bool or number: a complete scalar
}

// walkJSONObject walks one object whose opening brace was just consumed; path
// locates that object.
func walkJSONObject(dec *json.Decoder, data []byte, path []jsonPathStep, v jsonStructureVisitor) error {
	v.beginObject(path)
	for dec.More() {
		keyStart := int(dec.InputOffset())
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		keyEnd := int(dec.InputOffset())
		// Between More() and the value, Token can only be a member name.
		key, _ := keyTok.(string)
		if err := v.memberName(key, data, keyStart, keyEnd, path); err != nil {
			return err
		}
		valStart := int(dec.InputOffset())
		valTok, err := dec.Token()
		if err != nil {
			return err
		}
		valEnd := int(dec.InputOffset())
		valuePath := append(jsonPathCopy(path), jsonMemberStep(key))
		switch t := valTok.(type) {
		case string:
			if err := v.stringValue(data, valStart, valEnd, valuePath); err != nil {
				return err
			}
		case json.Delim:
			switch t {
			case '{':
				if err := walkJSONObject(dec, data, valuePath, v); err != nil {
					return err
				}
			case '[':
				if err := walkJSONArray(dec, data, valuePath, v); err != nil {
					return err
				}
			}
		}
	}
	if _, err := dec.Token(); err != nil { // consume '}'
		return err
	}
	v.endObject()
	return nil
}

// walkJSONArray walks one array whose opening bracket was just consumed; path
// locates that array and elements are numbered from zero in document order.
func walkJSONArray(dec *json.Decoder, data []byte, path []jsonPathStep, v jsonStructureVisitor) error {
	for i := 0; dec.More(); i++ {
		elemStart := int(dec.InputOffset())
		elemTok, err := dec.Token()
		if err != nil {
			return err
		}
		elemEnd := int(dec.InputOffset())
		elemPath := append(jsonPathCopy(path), jsonIndexStep(i))
		switch t := elemTok.(type) {
		case string:
			if err := v.stringValue(data, elemStart, elemEnd, elemPath); err != nil {
				return err
			}
		case json.Delim:
			switch t {
			case '{':
				if err := walkJSONObject(dec, data, elemPath, v); err != nil {
					return err
				}
			case '[':
				if err := walkJSONArray(dec, data, elemPath, v); err != nil {
					return err
				}
			}
		}
	}
	if _, err := dec.Token(); err != nil { // consume ']'
		return err
	}
	return nil
}
