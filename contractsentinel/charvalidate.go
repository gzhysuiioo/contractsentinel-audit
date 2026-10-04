// Package contractsentinel charvalidate: character-level legality checks for
// user-supplied audit submissions, performed before any JSON decoding.
//
// encoding/json silently rewrites two kinds of bad input into the replacement
// character U+FFFD instead of rejecting it:
//
//   - bytes that are not valid UTF-8, anywhere in the document;
//   - Unicode escapes (\uXXXX) inside JSON strings that do not form a legal
//     surrogate pair: a lone high surrogate, a lone low surrogate, or a high
//     surrogate followed by anything other than a low surrogate (a reversed
//     pair included).
//
// Left uncaught, the rewrite changes the evidence text of a 发现缺陷 record
// into replacement characters, and changes the very content that feeds the
// artifact hash when the bad text appears in the source. A successful report
// must never be built from rewritten content, so the whole submission is
// rejected at the character level first.
//
// Legal content stays legal: a directly written U+FFFD is an ordinary
// character, and the literal text "\uD800" (an escaped backslash followed by
// uD800) is ordinary text — neither is a surrogate problem.
package contractsentinel

import (
	"fmt"
	"unicode/utf8"
)

// charPos is one 1-based (line, column) position with an additional 0-based
// byte offset. Columns count runes, so a multi-byte character occupies one
// column. For a surrogate escape, surrogate records the escaped code point.
type charPos struct {
	line      int
	column    int
	offset    int
	surrogate rune
}

// charError locates one character-legality problem.
type charError struct {
	problem string // "invalid UTF-8 encoding" or "invalid Unicode escape in JSON string"
	pos     charPos
	detail  string
}

func (e *charError) Error() string {
	return fmt.Sprintf("%s at line %d, column %d (byte offset %d): %s",
		e.problem, e.pos.line, e.pos.column, e.pos.offset, e.detail)
}

// validateJSONCharacters scans data as JSON text and rejects the first
// character-legality violation: an illegal UTF-8 byte anywhere, or an
// unpaired / misordered surrogate escape within any JSON string (member names
// included — strings are strings, whether they carry a fixed field, a value,
// or nested extension data). It performs no JSON syntax validation: malformed
// JSON is left to the decoder that runs next, and a document that was valid
// JSON never produces a character error here.
func validateJSONCharacters(data []byte) error {
	i, n := 0, len(data)
	line, column := 1, 1
	inString := false

	// Position of a high surrogate waiting for its low surrogate, so a lone
	// high is reported where it was written rather than where pairing failed.
	pending := charPos{}
	hasPending := false

	for i < n {
		c := data[i]

		// Non-ASCII bytes are validated as UTF-8 both inside and outside
		// strings. A genuinely encoded U+FFFD decodes as U+FFFD over three
		// bytes and is ordinary content; only an illegal encoding yields
		// RuneError with size 1.
		if c >= 0x80 {
			r, size := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && size == 1 {
				return &charError{
					problem: "invalid UTF-8 encoding",
					pos:     charPos{line: line, column: column, offset: i},
					detail:  fmt.Sprintf("illegal byte 0x%02X is not valid UTF-8", c),
				}
			}
			// A literal rune is not a low surrogate, so a waiting high
			// surrogate is already unpaired.
			if inString && hasPending {
				return loneHighError(pending)
			}
			i += size
			column++
			continue
		}

		if !inString {
			if c == '"' {
				inString = true
			}
			i, line, column = advanceChar(c, i, line, column)
			continue
		}

		// Inside a JSON string.
		switch c {
		case '"':
			if hasPending {
				return loneHighError(pending)
			}
			inString = false
			i, line, column = advanceChar(c, i, line, column)
		case '\\':
			if esc, pos, ok := surrogateEscape(data, i, line, column); ok {
				switch {
				case isHighSurrogate(esc):
					if hasPending {
						// The previous high escape was never completed by a low
						// escape; another high escape is not its pair.
						return loneHighError(pending)
					}
					pending, hasPending = pos, true
				case isLowSurrogate(esc):
					if !hasPending {
						return &charError{
							problem: "invalid Unicode escape in JSON string",
							pos:     pos,
							detail:  fmt.Sprintf("lone low surrogate \\u%04X has no preceding high surrogate \\uD800-\\uDBFF", esc),
						}
					}
					hasPending = false
				default:
					// A non-surrogate escape cannot complete a waiting high.
					if hasPending {
						return loneHighError(pending)
					}
				}
				i += 6
				column += 6
			} else {
				// Any other escape (\\, \", \n, a malformed \u...): one token
				// that is not a low surrogate. Consuming both bytes of "\\uD800"
				// together keeps the backslash-u-D800 text literal instead of
				// opening a surrogate escape. Malformed \u escapes are left for
				// the JSON decoder after the already-unpaired high is reported.
				if hasPending {
					return loneHighError(pending)
				}
				if i+1 < n {
					i += 2
					column += 2
				} else {
					i++
					column++
				}
			}
		default:
			// A literal byte is another JSON character, so a waiting high
			// surrogate proves unpaired. Raw control characters are left to the
			// decoder.
			if hasPending {
				return loneHighError(pending)
			}
			i, line, column = advanceChar(c, i, line, column)
		}
	}
	if hasPending {
		return loneHighError(pending)
	}
	return nil
}

// advanceChar moves one ASCII byte, tracking line and column.
func advanceChar(c byte, i, line, column int) (int, int, int) {
	if c == '\n' {
		return i + 1, line + 1, 1
	}
	return i + 1, line, column + 1
}

// surrogateEscape interprets data[i:] as a \uXXXX escape with exactly four hex
// digits, returning the escaped code point and the escape's start position.
// ok is false when the escape is malformed; callers leave those to the JSON
// decoder.
func surrogateEscape(data []byte, i, line, column int) (rune, charPos, bool) {
	if i+5 >= len(data) || data[i] != '\\' || data[i+1] != 'u' {
		return 0, charPos{}, false
	}
	var v rune
	for k := 0; k < 4; k++ {
		d, ok := hexDigit(data[i+2+k])
		if !ok {
			return 0, charPos{}, false
		}
		v = v<<4 | d
	}
	return v, charPos{line: line, column: column, offset: i, surrogate: v}, true
}

func hexDigit(b byte) (rune, bool) {
	switch {
	case b >= '0' && b <= '9':
		return rune(b - '0'), true
	case b >= 'a' && b <= 'f':
		return rune(b-'a') + 10, true
	case b >= 'A' && b <= 'F':
		return rune(b-'A') + 10, true
	}
	return 0, false
}

func isHighSurrogate(r rune) bool { return r >= 0xD800 && r <= 0xDBFF }
func isLowSurrogate(r rune) bool  { return r >= 0xDC00 && r <= 0xDFFF }

// loneHighError reports a high surrogate that was not followed by a low one.
func loneHighError(p charPos) error {
	return &charError{
		problem: "invalid Unicode escape in JSON string",
		pos:     p,
		detail:  fmt.Sprintf("lone high surrogate \\u%04X is not followed by a low surrogate \\uDC00-\\uDFFF", p.surrogate),
	}
}
