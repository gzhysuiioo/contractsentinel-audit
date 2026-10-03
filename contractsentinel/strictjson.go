// Package contractsentinel strictjson: fixed-field recognition shared by the
// audit submission and the stored report.
package contractsentinel

import "encoding/json"

// fixedShape describes the fixed fields of one JSON object: keys lists the
// agreed member spellings kept at this level, objects names members whose
// values are themselves objects with their own fixed shape, and arrays names
// members whose values are arrays of such objects. Members not named anywhere
// in the shape are extension data.
//
// Both entry points that decode user-supplied JSON — the audit submission and
// the stored report archive — are decoded through a fixedShape, so the
// recognition convention exists exactly once: a member denotes a fixed field
// only when its JSON-decoded name matches the agreed spelling byte for byte.
// encoding/json otherwise falls back to case-insensitive field matching, so
// an extension member such as "StAtus" would silently decode into the status
// field and could override — or launder — the conclusion carried by the
// formal "status" member, depending on where the extension member appears.
// Case variants, whitespace-padded names and unknown members never reach the
// decoder: they can neither override a formal value nor substitute for a
// missing, mistyped or unsupported one, whatever JSON type the extension
// value has. Names are compared after JSON string decoding, so a fixed name
// written with escapes still denotes that field.
type fixedShape struct {
	keys    []string
	objects map[string]fixedShape
	arrays  map[string]fixedShape
}

// strictFixedJSON rewrites data to the fixed fields of shape, at this level
// and inside every nested object member and every element of every nested
// array member named by the shape. Member order and extension members no
// longer influence the decoded values. Exact duplicate members were already
// rejected by findDuplicateJSONMember, so each kept name appears at most
// once. A null object member stays null so the decoded value keeps the same
// nil-ness as before.
func strictFixedJSON(data []byte, shape fixedShape) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	out := make(map[string]json.RawMessage, len(shape.keys))
	for _, k := range shape.keys {
		if v, ok := obj[k]; ok {
			out[k] = v
		}
	}
	for name, sub := range shape.objects {
		if raw, ok := out[name]; ok && string(raw) != "null" {
			f, err := strictFixedJSON(raw, sub)
			if err != nil {
				return nil, err
			}
			out[name] = f
		}
	}
	for name, sub := range shape.arrays {
		if raw, ok := out[name]; ok {
			f, err := strictFixedJSONArray(raw, sub)
			if err != nil {
				return nil, err
			}
			out[name] = f
		}
	}
	return json.Marshal(out)
}

// strictFixedJSONArray rewrites every element of a JSON array with
// strictFixedJSON. A null array stays null so the decoded slice keeps the
// same nil-ness as before.
func strictFixedJSONArray(raw json.RawMessage, shape fixedShape) (json.RawMessage, error) {
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, err
	}
	if elems == nil {
		return raw, nil
	}
	out := make([]json.RawMessage, 0, len(elems))
	for _, e := range elems {
		f, err := strictFixedJSON(e, shape)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return json.Marshal(out)
}
