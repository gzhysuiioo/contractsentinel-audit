// Package contractsentinel jsonchars: whole-document validation of the
// character legality of a JSON submission.
//
// encoding/json decodes two classes of illegal input without an error
// and silently rewrites the text: an invalid UTF-8 byte inside a JSON
// string, and an unpaired (or wrongly ordered) UTF-16 surrogate escape,
// are both replaced by U+FFFD. A check note carrying an isolated
// high-surrogate escape (such as \uD800) would therefore build a
// "successful" report whose evidence no longer matches the submitted
// bytes, and a source string hit by the same rewrite would change the
// content that feeds the artifact hash. The scan below re-inspects every
// raw JSON string literal -- member names and string values, at every
// depth, including members dropped later as extension data -- and rejects
// the whole submission with a precise location instead of letting any
// character be deleted or replaced.
package contractsentinel

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

const (
	// charKindEncoding classifies an invalid UTF-8 byte.
	charKindEncoding = "invalid character encoding"
	// charKindEscape classifies an unpaired or misordered surrogate escape.
	charKindEscape = "invalid Unicode escape"
)

// charEncodingError is a character-legality rejection. kind classifies it as
// an encoding or Unicode-escape problem, problem describes the exact cause,
// and offset/line/column point at the bad byte or at the backslash of the
// offending escape so the submitter can fix the original content.
type charEncodingError struct {
	kind    string
	problem string // e.g. `unpaired high surrogate escape \uD800`
	where   string // "member name", "string value" or "input"
	path    []jsonPathStep
	offset  int
	line    int
	column  int
}

func (e *charEncodingError) Error() string {
	// A whole-document encoding error carries no value path: the bad byte is
	// in whitespace or another gap outside the string literals.
	if e.where == "input" && len(e.path) == 0 {
		return fmt.Sprintf("%s: %s in JSON input (byte offset %d, line %d, column %d)",
			e.kind, e.problem, e.offset, e.line, e.column)
	}
	// An empty value path is the document root: a scalar at the top of the
	// document, or the top-level object when the bad token is a member name.
	loc := "the top-level value"
	if len(e.path) > 0 {
		loc = renderJSONPath(e.path)
	}
	if e.where == "member name" && len(e.path) == 0 {
		loc = "the top-level object"
	}
	return fmt.Sprintf("%s: %s in JSON %s at %s (byte offset %d, line %d, column %d)",
		e.kind, e.problem, e.where, loc, e.offset, e.line, e.column)
}

// validateJSONCharacters scans data and returns the first character-legality
// violation in document order: an invalid UTF-8 byte anywhere in the document,
// or an unpaired / wrongly ordered surrogate escape inside any JSON string
// literal (member names included, at every depth and inside unknown extension
// members). It returns nil when no character problem exists; malformed JSON
// alone is left for json.Unmarshal to report, which runs right after this
// scan, mirroring findDuplicateJSONMember.
func validateJSONCharacters(data []byte) *charEncodingError {
	utf8Err := firstInvalidUTF8Byte(data)
	escapeErr := scanJSONStringEscapes(data)
	switch {
	case escapeErr != nil && (utf8Err == nil || escapeErr.offset <= utf8Err.offset):
		// On equal offsets the structural message carries the value path.
		return escapeErr
	case utf8Err != nil:
		return utf8Err
	default:
		return nil
	}
}

// firstInvalidUTF8Byte returns the first byte that is not valid UTF-8. The
// byte sweep is structural-blind, so it also covers bytes in whitespace and
// gaps that the token walk cannot reach; string-interior bytes found there
// lose the offset comparison against the path-qualified error from
// scanJSONStringEscapes.
func firstInvalidUTF8Byte(data []byte) *charEncodingError {
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			line, column := lineColumn(data, i)
			return &charEncodingError{
				kind:    charKindEncoding,
				problem: fmt.Sprintf("invalid UTF-8 byte 0x%02x", data[i]),
				where:   "input",
				offset:  i,
				line:    line,
				column:  column,
			}
		}
		i += size
	}
	return nil
}

// characterVisitor is the character-legality policy plugged into the shared
// jsonStructureVisitor walk. Every string token the walker reaches -- a
// member name or a string value, at any depth and inside unknown extension
// members -- is checked raw. Object and array recognition, array indices and
// paths come from the single shared walk, identical to the repeated-member
// gate. The first violation aborts the walk; any decoder error (malformed
// JSON) leaves err unset, deferring to json.Unmarshal.
type characterVisitor struct {
	err *charEncodingError
}

func (v *characterVisitor) beginObject(_ []jsonPathStep) {}
func (v *characterVisitor) endObject()                   {}

func (v *characterVisitor) memberName(_ string, data []byte, start, end int, objectPath []jsonPathStep) error {
	// The member name itself is a JSON string and must be legal even when the
	// member is an unknown extension that never reaches the decoder. Its
	// location is the containing object: an unpaired escape in the name cannot
	// render the name itself, so the path stops at the parent.
	if e := checkStringToken(data, start, end, objectPath, true); e != nil {
		v.err = e
		return errJSONWalkStop
	}
	return nil
}

func (v *characterVisitor) stringValue(data []byte, start, end int, valuePath []jsonPathStep) error {
	if e := checkStringToken(data, start, end, valuePath, false); e != nil {
		v.err = e
		return errJSONWalkStop
	}
	return nil
}

// scanJSONStringEscapes walks the document with characterVisitor and reports
// the first illegal string token in document order. It is best-effort over
// syntax: any decoder error stops the walk and yields nil, because
// json.Unmarshal owns syntax errors. String tokens reached before a later
// syntax problem still carry precise bounds and are validated.
func scanJSONStringEscapes(data []byte) *charEncodingError {
	v := &characterVisitor{}
	_ = walkJSONStructure(data, v)
	return v.err
}

// checkStringToken validates one raw token slice data[start:end] holding a
// JSON string token. The slice may begin with the whitespace or structural
// punctuation that separated the token from the previous one, but it always
// ends on the token's closing quote and JSON grammar permits no quote in that
// prefix, so the first quote byte is the opening quote. isMemberName selects
// how the location is described.
func checkStringToken(data []byte, start, end int, path []jsonPathStep, isMemberName bool) *charEncodingError {
	raw := data[start:end]
	q := bytes.IndexByte(raw, '"')
	if q < 0 || raw[len(raw)-1] != '"' {
		return nil // unreachable for a token returned by encoding/json
	}
	openQuote := start + q
	body := data[openQuote+1 : end-1]

	where := "string value"
	if isMemberName {
		where = "member name"
	}

	// One left-to-right pass over the literal content. Plain bytes are decoded
	// as UTF-8; backslash escapes are parsed structurally so that a backslash
	// that escapes another backslash ("\\uD800") is ordinary text, while a
	// surrogate escape must pair high-before-low with the very next escape.
	for i := 0; i < len(body); {
		abs := openQuote + 1 + i
		b := body[i]
		if b != '\\' {
			r, size := utf8.DecodeRune(body[i:])
			if r == utf8.RuneError && size == 1 {
				return charError(charKindEncoding,
					fmt.Sprintf("invalid UTF-8 byte 0x%02x", b), where, path, abs, data)
			}
			i += size
			continue
		}
		// b == '\\': an escape introduced by this backslash.
		if i+1 >= len(body) {
			return nil // malformed JSON: defer
		}
		switch body[i+1] {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			i += 2
			continue
		case 'u':
			r, ok := parseHex4(body, i)
			if !ok {
				return nil // malformed JSON: defer
			}
			switch {
			case isHighSurrogate(r):
				// The immediately following escape must be \uXXXX with a low
				// surrogate; any intervening character, a second high
				// surrogate, end of string or non-surrogate escape leaves this
				// one unpaired.
				if _, paired := pairedLowSurrogate(body, i+6); !paired {
					return charError(charKindEscape,
						fmt.Sprintf("unpaired high surrogate escape \\u%04X", r),
						where, path, abs, data)
				}
				i += 12
			case isLowSurrogate(r):
				// A low surrogate with no preceding high surrogate: this
				// includes a low-before-high ordering, whose first escape is
				// the unpaired low one.
				return charError(charKindEscape,
					fmt.Sprintf("unpaired low surrogate escape \\u%04X", r),
					where, path, abs, data)
			default:
				i += 6
			}
		default:
			return nil // malformed JSON: defer
		}
	}
	return nil
}

// parseHex4 parses the four hex digits of the "\uXXXX" escape whose backslash
// is at index i.
func parseHex4(body []byte, i int) (rune, bool) {
	if i+5 >= len(body) || body[i] != '\\' || body[i+1] != 'u' {
		return 0, false
	}
	var r rune
	for j := i + 2; j < i+6; j++ {
		c := body[j]
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, false
		}
		r = r<<4 | d
	}
	return r, true
}

// pairedLowSurrogate reports whether body[at:] begins with a "\uXXXX" escape
// denoting a low surrogate (0xDC00..0xDFFF), the only legal successor of a
// high surrogate escape. at == len(body) (end of string) is unpaired.
func pairedLowSurrogate(body []byte, at int) (rune, bool) {
	if at >= len(body) || body[at] != '\\' {
		return 0, false
	}
	r, ok := parseHex4(body, at)
	if !ok || !isLowSurrogate(r) {
		return 0, false
	}
	return r, true
}

func isHighSurrogate(r rune) bool { return 0xD800 <= r && r <= 0xDBFF }
func isLowSurrogate(r rune) bool  { return 0xDC00 <= r && r <= 0xDFFF }

// charError builds a charEncodingError, deriving line and column once.
func charError(kind, problem, where string, path []jsonPathStep, offset int, data []byte) *charEncodingError {
	line, column := lineColumn(data, offset)
	return &charEncodingError{
		kind:    kind,
		problem: problem,
		where:   where,
		path:    jsonPathCopy(path),
		offset:  offset,
		line:    line,
		column:  column,
	}
}

// lineColumn returns the 1-based line and rune column of byte offset off.
func lineColumn(data []byte, off int) (int, int) {
	line, lineStart := 1, 0
	for i := 0; i < off && i < len(data); i++ {
		if data[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}
	return line, utf8.RuneCount(data[lineStart:off]) + 1
}
