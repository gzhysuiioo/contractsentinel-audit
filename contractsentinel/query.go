// Query-string rewriting for matched routes: queryTransforms are applied
// after route selection and never touch path matching or joining. The
// rewriter works on raw fragments so unmodified parameters (including
// duplicates, empty values and empty fragments) keep their original bytes
// and relative order; only a rule's target parameter is decoded for name
// comparison and re-encoded when set.
package contractsentinel

import "strings"

// queryItem is one '&'-separated fragment of a query string in its current
// order. Empty fragments ("" between separators) are retained but never
// match a parameter name.
type queryItem struct {
	empty bool   // an empty fragment, kept verbatim but not a parameter
	name  string // decoded parameter name (only meaningful when !empty)
	raw   string // original fragment text, or the encoded pair after a set
}

// applyQueryTransforms parses the raw query of target (the text after the
// first '?') and applies the route's transforms in array order. It returns
// the full query suffix including a leading '?', or "" when the final
// result has no query string.
func applyQueryTransforms(transforms []*QueryTransform, target string) (string, *Failure) {
	i := strings.IndexByte(target, '?')
	if len(transforms) == 0 {
		// No rules: the original query is preserved byte for byte.
		if i < 0 {
			return "", nil
		}
		return target[i:], nil
	}

	var items []queryItem
	present := false
	if i >= 0 {
		present = true
		raw := target[i+1:]
		// An empty query string ("?") has no fragments at all; every other
		// empty fragment (e.g. from "?&" or "?a=1&") is retained as such.
		if raw != "" {
			for _, frag := range strings.Split(raw, "&") {
				if frag == "" {
					items = append(items, queryItem{empty: true})
					continue
				}
				namePart := frag
				if j := strings.IndexByte(frag, '='); j >= 0 {
					namePart = frag[:j] // the first '=' splits name and value
				}
				name, ok := decodeQueryName(namePart)
				if !ok {
					// ParseRequest validates the whole target, so this is a
					// belt-and-braces guard.
					return "", failuref("invalid_request", "target contains an invalid percent escape")
				}
				items = append(items, queryItem{name: name, raw: frag})
			}
		}
	}

	for _, tr := range transforms {
		switch tr.Op {
		case "remove":
			present, items = applyRemove(items, present, tr.Name)
		case "set":
			present, items = applySet(items, present, tr.Name, tr.Value)
		case "rename":
			items = applyRename(items, tr.Name, tr.To)
		case "copy":
			items = applyCopy(items, tr.Name, tr.To)
		}
	}

	if !present {
		return "", nil
	}
	parts := make([]string, len(items))
	for k, it := range items {
		parts[k] = it.raw
	}
	return "?" + strings.Join(parts, "&"), nil
}

// matchesName is the one shared parameter-matching rule: an item is a hit
// when it is a parameter (not an empty fragment) whose decoded name equals
// name. Name decoding itself happens once at parse time, so every op compares
// the same decoded, case-sensitive form.
func matchesName(it queryItem, name string) bool {
	return !it.empty && it.name == name
}

// firstNameHit returns the index of the first parameter matching name, or -1
// when no parameter carries that name.
func firstNameHit(items []queryItem, name string) int {
	for k := range items {
		if matchesName(items[k], name) {
			return k
		}
	}
	return -1
}

// dropName is the one shared keep-the-rest rule: it compacts items in place,
// removing every parameter matching name while empty fragments and all other
// parameters keep their relative order and original bytes.
func dropName(items []queryItem, name string) []queryItem {
	kept := items[:0]
	for _, it := range items {
		if !matchesName(it, name) {
			kept = append(kept, it)
		}
	}
	return kept
}

// applyRemove deletes every parameter whose decoded name equals name. With
// no hit the query is untouched; after a hit the '?' is dropped only when no
// parameters or empty fragments remain.
func applyRemove(items []queryItem, present bool, name string) (bool, []queryItem) {
	if firstNameHit(items, name) < 0 {
		return present, items
	}
	kept := dropName(items, name)
	if len(kept) == 0 {
		return false, kept
	}
	return true, kept
}

// applySet merges all parameters with the decoded name into one encoded
// name=value pair at the first hit's position; a name that is absent is
// appended to the end and creates a query string when none existed.
func applySet(items []queryItem, present bool, name, value string) (bool, []queryItem) {
	encoded := encodeQueryComponent(name) + "=" + encodeQueryComponent(value)
	first := firstNameHit(items, name)
	if first < 0 {
		items = append(items, queryItem{name: name, raw: encoded})
		return true, items
	}
	// The merged pair takes the first hit's place; every later duplicate is
	// dropped by the same keep-the-rest rule remove uses.
	items[first].raw = encoded
	return true, append(items[:first+1], dropName(items[first+1:], name)...)
}

// applyRename renames in place every parameter whose decoded name equals
// name: its name is re-encoded as to while the '=' (if any) and the raw
// value bytes after it are kept verbatim. Parameters already named to,
// empty fragments and non-matching parameters are untouched; when nothing
// matches (or name and to are identical) every fragment keeps its bytes.
func applyRename(items []queryItem, name, to string) []queryItem {
	if name == to {
		// Renaming to the same name must not re-encode existing names.
		return items
	}
	encodedTo := encodeQueryComponent(to)
	for k := range items {
		if !matchesName(items[k], name) {
			continue
		}
		frag := items[k].raw
		if j := strings.IndexByte(frag, '='); j >= 0 {
			// Keep the '=' and everything after it byte for byte.
			frag = encodedTo + frag[j:]
		} else {
			frag = encodedTo
		}
		items[k].raw = frag
		items[k].name = to
	}
	return items
}

// applyCopy duplicates every parameter whose decoded name equals name: the
// original stays in place and its copy follows it immediately. The copy's
// name is encoded the way set encodes names, while the '=' (if any) and the
// raw value bytes after it are copied verbatim — a valueless source yields a
// valueless copy, an empty value keeps its '=', and percent escapes, '+' and
// extra '=' inside the value are never rewritten. Parameters already named
// to, empty fragments and non-matching parameters are untouched (existing
// target-name parameters are kept, never merged or overwritten), and the
// copies made by this rule are not themselves re-copied. When nothing
// matches (or name and to are identical) every fragment keeps its bytes.
func applyCopy(items []queryItem, name, to string) []queryItem {
	if name == to {
		// Copying onto the same name must not re-encode existing names.
		return items
	}
	encodedTo := encodeQueryComponent(to)
	out := make([]queryItem, 0, len(items))
	for _, it := range items {
		out = append(out, it)
		if !matchesName(it, name) {
			continue
		}
		frag := it.raw
		if j := strings.IndexByte(frag, '='); j >= 0 {
			// Keep the '=' and everything after it byte for byte.
			frag = encodedTo + frag[j:]
		} else {
			frag = encodedTo
		}
		out = append(out, queryItem{name: to, raw: frag})
	}
	return out
}

// decodeQueryName percent-decodes a raw parameter name with '+' treated as a
// space, as application/x-www-form-urlencoded does. Matching is
// case-sensitive and applies no other normalization. The bool reports
// whether every percent escape was well-formed.
func decodeQueryName(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '+':
			b.WriteByte(' ')
		case '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return "", false
			}
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), true
}

// encodeQueryComponent renders a literal name or value as query text: ASCII
// letters, digits and -._~ stay as-is, every other byte (including spaces
// and the individual bytes of multi-byte UTF-8 sequences) becomes an
// uppercase percent escape.
func encodeQueryComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexDigit(c >> 4))
			b.WriteByte(hexDigit(c & 0x0f))
		}
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '.', '_', '~':
		return true
	}
	return false
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func hexDigit(n byte) byte {
	const digits = "0123456789ABCDEF"
	return digits[n]
}
