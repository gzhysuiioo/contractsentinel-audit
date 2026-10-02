// Query-string rewriting for matched routes: queryTransforms are applied
// after route selection and never touch path matching or joining. The
// rewriter works on raw fragments so unmodified parameters (including
// duplicates, empty values and empty fragments) keep their original bytes
// and relative order; only a rule's target parameter is decoded for name
// comparison and re-encoded when set, and renamed parameters keep their
// value bytes verbatim.
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
			present, items = applyRename(items, present, tr.Name, tr.To)
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

// applyRemove deletes every parameter whose decoded name equals name. With
// no hit the query is untouched; after a hit the '?' is dropped only when no
// parameters or empty fragments remain.
func applyRemove(items []queryItem, present bool, name string) (bool, []queryItem) {
	first := -1
	for k := range items {
		if !items[k].empty && items[k].name == name {
			first = k
			break
		}
	}
	if first < 0 {
		return present, items
	}
	kept := items[:0]
	for _, it := range items {
		if it.empty || it.name != name {
			kept = append(kept, it)
		}
	}
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
	first := -1
	for k := range items {
		if !items[k].empty && items[k].name == name {
			first = k
			break
		}
	}
	if first < 0 {
		items = append(items, queryItem{name: name, raw: encoded})
		return true, items
	}
	items[first].raw = encoded
	kept := items[:first+1]
	for _, it := range items[first+1:] {
		if it.empty || it.name != name {
			kept = append(kept, it)
		}
	}
	return true, kept
}

// applyRename renames every parameter whose decoded name equals old, each at
// its original position: only the name is re-encoded (with the same encoding
// as set), while the '=' and everything after it is copied byte for byte so
// values keep their '+', percent escapes, extra '=' and case. Parameters
// already named to are kept untouched and are never merged or overwritten,
// and empty fragments never match a name. With no hit the query is unchanged
// (rename never creates a query string); a no-op rename (old == to) leaves
// every existing name encoding as-is.
func applyRename(items []queryItem, present bool, old, to string) (bool, []queryItem) {
	if old == to {
		return present, items
	}
	newName := encodeQueryComponent(to)
	hit := false
	for k := range items {
		if items[k].empty || items[k].name != old {
			continue
		}
		hit = true
		frag := items[k].raw
		rest := ""
		if j := strings.IndexByte(frag, '='); j >= 0 {
			rest = frag[j:] // keep the '=' and the value byte for byte
		}
		items[k].raw = newName + rest
		items[k].name = to // later rules match the renamed parameter
	}
	if !hit {
		return present, items
	}
	return present, items
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
