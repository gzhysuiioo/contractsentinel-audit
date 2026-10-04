// Shared JSON decoding primitives for offline config and request parsing.
//
// Config and request documents are read as raw JSON values and then
// shape-checked in the same fixed order, so the basic checks live here once:
//
//  1. jsonValue confirms the bytes are one syntactically complete JSON value.
//     Only a failure at this stage is a parse failure; it never carries a
//     guessed field name or route position.
//  2. Callers inspect the value's outer type (jsonTypeName) and decode the
//     object's fields (jsonObject) or an array's elements (jsonArray). A
//     syntactically legal value of the wrong shape is a business error
//     (invalid_config or invalid_request), never another parse failure.
//  3. jsonStringField type-checks individual string-typed fields in one
//     place: an absent field is left to the caller's content validation,
//     while null or any other non-string value is a field type error whose
//     JSON type name the caller renders with its own business vocabulary.
package contractsentinel

import (
	"bytes"
	"encoding/json"
)

// jsonValue decodes data as one complete JSON value. The RawMessage is only
// usable when err is nil, so callers that branch on err can treat the result
// as a syntactically legal JSON token and check its shape themselves.
func jsonValue(data []byte) (json.RawMessage, error) {
	var doc json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// jsonObject decodes one JSON object's fields as raw values. Fields are read
// into a map rather than a typed struct so callers can check required fields
// in their own fixed order, independent of the order in which keys were
// written. Duplicate keys resolve to the last occurrence, as with a struct.
func jsonObject(body json.RawMessage) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// jsonArray decodes one JSON array's elements as raw values so each element
// can be type-checked against its own 1-based position. A JSON null must be
// rejected by the caller before calling: json.Unmarshal accepts null as a
// nil slice.
func jsonArray(body json.RawMessage) ([]json.RawMessage, error) {
	var elems []json.RawMessage
	if err := json.Unmarshal(body, &elems); err != nil {
		return nil, err
	}
	return elems, nil
}

// jsonStringField decodes one raw field value that must hold a string. An
// absent field (nil raw) is acceptable and leaves dst untouched, so callers
// keep their own missing-field content checks; an empty JSON string is a
// legal string and is decoded like any other. A present null or any other
// non-string value is a field type error: ok is false and got names the JSON
// type that was actually supplied, via jsonTypeName ("null", "a number",
// "an object", ...).
func jsonStringField(raw json.RawMessage, dst *string) (got string, ok bool) {
	if len(raw) == 0 {
		return "", true
	}
	body := bytes.TrimSpace(raw)
	if body[0] == '"' && json.Unmarshal(body, dst) == nil {
		return "", true
	}
	return jsonTypeName(body), false
}

// jsonTypeName names the JSON type of a syntactically valid raw value, in the
// terms the error reasons use: "null", "a boolean", "a number", "a string",
// "an array" or "an object".
func jsonTypeName(raw json.RawMessage) string {
	switch bytes.TrimSpace(raw)[0] {
	case 'n':
		return "null"
	case 't', 'f':
		return "a boolean"
	case '"':
		return "a string"
	case '[':
		return "an array"
	case '{':
		return "an object"
	default:
		return "a number"
	}
}
