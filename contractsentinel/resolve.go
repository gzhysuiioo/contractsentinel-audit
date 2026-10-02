// Offline route resolution: match a request against configured route prefixes
// and join the remainder onto the upstream base path without any network I/O.
package contractsentinel

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Route is one configured route: an id, accepted methods, a path prefix, the
// upstream URL requests on that route are forwarded to, and optional rules
// that rewrite the query string after matching.
type Route struct {
	ID              string          `json:"id"`
	Methods         []string        `json:"methods"`
	PathPrefix      string          `json:"pathPrefix"`
	Upstream        string          `json:"upstream"`
	QueryTransforms json.RawMessage `json:"queryTransforms"`

	// queryRules is the validated, parsed form of QueryTransforms; it is
	// populated by ParseConfig and never read from JSON directly.
	queryRules []QueryTransform
}

// QueryTransform is one rule that rewrites the query string of the matched
// route's upstream URL. Rules run in array order against the result of the
// previous rule.
type QueryTransform struct {
	Op    string  `json:"op"`
	Name  string  `json:"name"`
	Value *string `json:"value"`
}

// Config is the resolve configuration: a flat array of routes.
type Config struct {
	Routes []Route `json:"routes"`
}

// Request is one resolution request: an HTTP method and a request target
// (path with an optional raw query string).
type Request struct {
	Method string `json:"method"`
	Target string `json:"target"`
}

// Resolution is the successful result of matching a request.
type Resolution struct {
	RouteID     string `json:"routeId"`
	UpstreamURL string `json:"upstreamURL"`
}

// Failure carries a stable machine-readable code and a human-readable reason.
type Failure struct {
	Code       string   `json:"code"`
	Reason     string   `json:"reason"`
	Candidates []string `json:"candidates,omitempty"`
}

func (f *Failure) Error() string { return f.Code + ": " + f.Reason }

func failuref(code, format string, args ...any) *Failure {
	return &Failure{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// ParseConfig parses and fully validates the route configuration.
func ParseConfig(data []byte) (*Config, *Failure) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, failuref("invalid_config", "config is not valid JSON: %v", err)
	}
	if f := cfg.validate(); f != nil {
		return nil, f
	}
	return &cfg, nil
}

func (cfg *Config) validate() *Failure {
	seenIDs := make(map[string]int, len(cfg.Routes))
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		loc := fmt.Sprintf("route %d", i+1)
		if route.ID == "" {
			return failuref("invalid_config", "%s: id must be non-empty", loc)
		}
		if first, ok := seenIDs[route.ID]; ok {
			return failuref("invalid_config", "%s: duplicate id %q (already used by route %d)", loc, route.ID, first)
		}
		seenIDs[route.ID] = i + 1

		if len(route.Methods) == 0 {
			return failuref("invalid_config", "%s (id %q): methods must be a non-empty array", loc, route.ID)
		}
		for _, method := range route.Methods {
			switch {
			case method == "":
				return failuref("invalid_config", "%s (id %q): methods must not contain empty entries", loc, route.ID)
			case method == "*":
				// Wildcard matching any legal method.
			case !isToken(method):
				return failuref("invalid_config", "%s (id %q): invalid method %q", loc, route.ID, method)
			}
		}

		if f := validatePrefix(route.PathPrefix, loc, route.ID); f != nil {
			return f
		}
		if f := validateUpstream(route.Upstream, loc, route.ID); f != nil {
			return f
		}
		rules, f := validateQueryTransforms(route.QueryTransforms, loc, route.ID)
		if f != nil {
			return f
		}
		route.queryRules = rules
	}
	return nil
}

func validatePrefix(prefix, loc, id string) *Failure {
	switch {
	case prefix == "" || prefix[0] != '/':
		return failuref("invalid_config", "%s (id %q): pathPrefix must start with /", loc, id)
	case prefix != "/" && strings.HasSuffix(prefix, "/"):
		return failuref("invalid_config", "%s (id %q): pathPrefix must not end with / except for root", loc, id)
	case strings.ContainsAny(prefix, "?#"):
		return failuref("invalid_config", "%s (id %q): pathPrefix must not contain a query string or fragment", loc, id)
	case !validPercentEscapes(prefix):
		return failuref("invalid_config", "%s (id %q): pathPrefix contains an invalid percent escape", loc, id)
	}
	return nil
}

func validateUpstream(raw, loc, id string) *Failure {
	if strings.ContainsAny(raw, "?#") {
		return failuref("invalid_config", "%s (id %q): upstream must not contain a query string or fragment", loc, id)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return failuref("invalid_config", "%s (id %q): upstream is not a valid URL: %v", loc, id, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return failuref("invalid_config", "%s (id %q): upstream must be an absolute http or https URL", loc, id)
	}
	if u.Host == "" {
		return failuref("invalid_config", "%s (id %q): upstream must include a host", loc, id)
	}
	return nil
}

// validateQueryTransforms parses and fully validates the optional
// queryTransforms array. A missing field yields no rules; an explicit null,
// a non-array value, a null rule, a rule with a wrong-typed or unknown op,
// an empty name, a set missing a string value, or a remove carrying a value
// all invalidate the whole configuration. Rule errors carry the 1-based
// index of the rule within the array.
func validateQueryTransforms(raw json.RawMessage, loc, id string) ([]QueryTransform, *Failure) {
	if raw == nil {
		return nil, nil
	}
	if string(raw) == "null" {
		return nil, failuref("invalid_config", "%s (id %q): queryTransforms must not be null", loc, id)
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, failuref("invalid_config", "%s (id %q): queryTransforms must be an array of rules: %v", loc, id, err)
	}
	out := make([]QueryTransform, 0, len(rules))
	for i, rraw := range rules {
		rloc := fmt.Sprintf("%s (id %q): queryTransforms rule %d", loc, id, i+1)
		if len(rraw) == 0 || string(rraw) == "null" {
			return nil, failuref("invalid_config", "%s: rule must not be null", rloc)
		}
		var rule QueryTransform
		if err := json.Unmarshal(rraw, &rule); err != nil {
			return nil, failuref("invalid_config", "%s: rule has invalid fields: %v", rloc, err)
		}
		switch rule.Op {
		case "set", "remove":
		default:
			return nil, failuref("invalid_config", "%s: op must be \"set\" or \"remove\", got %q", rloc, rule.Op)
		}
		if rule.Name == "" {
			return nil, failuref("invalid_config", "%s: name must be a non-empty string", rloc)
		}
		if rule.Op == "set" && rule.Value == nil {
			return nil, failuref("invalid_config", "%s: set requires a string value", rloc)
		}
		if rule.Op == "remove" && rule.Value != nil {
			return nil, failuref("invalid_config", "%s: remove must not have a value", rloc)
		}
		out = append(out, rule)
	}
	return out, nil
}

// ParseRequest parses and validates one JSON request.
func ParseRequest(data []byte) (*Request, *Failure) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, failuref("invalid_request", "request is not valid JSON: %v", err)
	}
	switch {
	case req.Method == "":
		return nil, failuref("invalid_request", "method is required")
	case !isToken(req.Method):
		return nil, failuref("invalid_request", "method %q is not a legal HTTP method", req.Method)
	}
	switch {
	case req.Target == "" || req.Target[0] != '/':
		return nil, failuref("invalid_request", "target must start with /")
	case strings.Contains(req.Target, "#"):
		return nil, failuref("invalid_request", "target must not contain a fragment")
	case !validPercentEscapes(req.Target):
		return nil, failuref("invalid_request", "target contains an invalid percent escape")
	}
	return &req, nil
}

// Resolve matches a validated request against a validated configuration and
// computes the upstream URL. Failure codes are route_not_found and
// route_conflict.
func Resolve(cfg *Config, req *Request) (*Resolution, *Failure) {
	path := req.Target
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}

	type candidate struct {
		route    *Route
		concrete bool
	}
	var matched []candidate
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		concrete, wildcard := methodMatch(route.Methods, req.Method)
		if !concrete && !wildcard {
			continue
		}
		if !prefixMatch(route.PathPrefix, path) {
			continue
		}
		matched = append(matched, candidate{route, concrete})
	}
	if len(matched) == 0 {
		return nil, failuref("route_not_found", "no route matches %s %s", req.Method, path)
	}

	// Longest prefix wins.
	bestLen := 0
	for _, c := range matched {
		if n := len(c.route.PathPrefix); n > bestLen {
			bestLen = n
		}
	}
	winners := matched[:0]
	for _, c := range matched {
		if len(c.route.PathPrefix) == bestLen {
			winners = append(winners, c)
		}
	}

	// Among equal prefixes a concrete method beats the wildcard.
	var concrete []candidate
	for _, c := range winners {
		if c.concrete {
			concrete = append(concrete, c)
		}
	}
	if len(concrete) > 0 {
		winners = concrete
	}
	if len(winners) > 1 {
		ids := make([]string, 0, len(winners))
		for _, c := range winners {
			ids = append(ids, c.route.ID)
		}
		sort.Strings(ids)
		f := failuref("route_conflict", "multiple routes match %s %s", req.Method, path)
		f.Candidates = ids
		return nil, f
	}

	upstreamURL, f := joinUpstream(winners[0].route, path, req.Target)
	if f != nil {
		return nil, f
	}
	return &Resolution{RouteID: winners[0].route.ID, UpstreamURL: upstreamURL}, nil
}

// methodMatch reports whether the method list matches the request method
// concretely (an exact, case-sensitive entry) or via the "*" wildcard.
func methodMatch(methods []string, method string) (concrete, wildcard bool) {
	for _, m := range methods {
		switch {
		case m == "*":
			wildcard = true
		case m == method:
			concrete = true
		}
	}
	return concrete, wildcard
}

// prefixMatch matches raw encoded paths on segment boundaries: "%2F" is never
// treated as a separator and the root prefix matches every origin-path.
func prefixMatch(prefix, path string) bool {
	if prefix == "/" {
		return true
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix) && path[len(prefix)] == '/'
}

// joinUpstream strips the route prefix from the request path and joins the
// remainder onto the upstream base path with exactly one slash at the
// junction. The base path and raw query string are carried over byte for
// byte: joining never re-encodes, reorders or drops anything.
func joinUpstream(route *Route, path, target string) (string, *Failure) {
	if _, err := url.Parse(route.Upstream); err != nil {
		// Config validation already rejected this.
		return "", failuref("invalid_config", "route %q has an invalid upstream: %v", route.ID, err)
	}

	var remainder string
	switch {
	case route.PathPrefix == "/":
		// Root keeps the whole following path; "/" itself has an empty remainder.
		if path != "/" {
			remainder = path
		}
	default:
		remainder = path[len(route.PathPrefix):] // "" or "/...", boundary is a literal slash
	}

	// Slice the validated upstream raw so nothing outside the junction is
	// normalized or re-escaped (scheme://[userinfo@]host[/base-path]).
	schemeEnd := strings.Index(route.Upstream, "://")
	tail := route.Upstream[schemeEnd+3:]
	hostPart, basePath := tail, ""
	if i := strings.IndexByte(tail, '/'); i >= 0 {
		hostPart, basePath = tail[:i], tail[i:]
	}
	joined := strings.TrimSuffix(basePath, "/")
	if remainder == "" {
		joined += "/" // the junction slash is kept even with no remaining path
	} else {
		joined += remainder
	}

	result := route.Upstream[:schemeEnd+3] + hostPart + joined

	qidx := strings.IndexByte(target, '?')
	hadQuery := qidx >= 0
	rawQuery := ""
	if hadQuery {
		rawQuery = target[qidx+1:]
	}
	transformed, nfrags, f := applyQueryTransforms(route.queryRules, rawQuery)
	if f != nil {
		return "", f
	}
	switch {
	case nfrags > 0:
		// At least one fragment (empty ones included) survives: re-emit the
		// question mark with whatever text remains.
		result += "?" + transformed
	case hadQuery && rawQuery == "":
		// An originally empty query string keeps its bare question mark even
		// when no rule changed anything.
		result += "?"
		// Otherwise every fragment (and there was at least one) was removed:
		// the question mark disappears along with them.
	}
	return result, nil
}

// queryFragment is one piece of a query string split on "&". Empty fragments
// (from "&&" or a trailing "&") are preserved verbatim and never treated as
// parameters. A non-empty fragment is a parameter: its name is the part
// before the first "=" (or the whole fragment when there is no "="), decoded
// for name matching.
type queryFragment struct {
	text    string // current output text; replaced when a rule rewrites it
	isParam bool
	name    string // decoded name, valid only when isParam
}

// applyQueryTransforms runs the route's rules in array order over the raw
// query string. With no rules the raw string is returned byte for byte.
// Splitting is on "&" only; the first "=" separates the name from the value.
// Names are compared case-sensitively after decoding percent escapes and
// treating "+" as a space, with no other normalization. The second return
// value is the number of surviving fragments (empty fragments included),
// which the caller needs to decide whether the question mark survives.
func applyQueryTransforms(rules []QueryTransform, rawQuery string) (string, int, *Failure) {
	var frags []queryFragment
	if rawQuery != "" {
		for _, part := range strings.Split(rawQuery, "&") {
			if part == "" {
				frags = append(frags, queryFragment{text: part})
				continue
			}
			name := part
			if eq := strings.IndexByte(part, '='); eq >= 0 {
				name = part[:eq]
			}
			decoded, f := decodeQueryName(name)
			if f != nil {
				return "", 0, f
			}
			frags = append(frags, queryFragment{text: part, isParam: true, name: decoded})
		}
	}

	for _, rule := range rules {
		switch rule.Op {
		case "set":
			frags = applySet(frags, rule)
		case "remove":
			frags = applyRemove(frags, rule)
		}
	}

	texts := make([]string, len(frags))
	for i := range frags {
		texts[i] = frags[i].text
	}
	return strings.Join(texts, "&"), len(frags), nil
}

// applySet merges every parameter with the rule's name into a single
// fragment placed at the first match; when none matches, the new fragment is
// appended at the end. The rule's name and value are used literally and
// percent-encoded only on output.
func applySet(frags []queryFragment, rule QueryTransform) []queryFragment {
	encoded := encodeQueryComponent(rule.Name) + "=" + encodeQueryComponent(*rule.Value)
	first := -1
	for i := range frags {
		if frags[i].isParam && frags[i].name == rule.Name {
			first = i
			break
		}
	}
	if first < 0 {
		return append(frags, queryFragment{text: encoded, isParam: true, name: rule.Name})
	}
	frags[first].text = encoded
	kept := frags[:0]
	for i := range frags {
		if i != first && frags[i].isParam && frags[i].name == rule.Name {
			continue // merge away the other matches into the first position
		}
		kept = append(kept, frags[i])
	}
	return kept
}

// applyRemove deletes every parameter whose decoded name matches the rule's
// name. Empty fragments are not parameters and are always kept.
func applyRemove(frags []queryFragment, rule QueryTransform) []queryFragment {
	kept := frags[:0]
	for i := range frags {
		if frags[i].isParam && frags[i].name == rule.Name {
			continue
		}
		kept = append(kept, frags[i])
	}
	return kept
}

// encodeQueryComponent renders a literal name or value for the query string.
// ASCII letters, digits and "-._~" appear unchanged; every other byte (spaces
// included) is emitted as an uppercase percent escape, with a space written
// as "%20" rather than "+".
func encodeQueryComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isUnreserved(c):
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
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

// decodeQueryName reverses percent escapes in a parameter name for matching:
// "%XX" yields the byte XX, "+" yields a space, and everything else is taken
// literally. Malformed escapes are rejected (request validation normally
// catches these up front).
func decodeQueryName(s string) (string, *Failure) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b.WriteByte(' ')
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return "", failuref("invalid_request", "target contains an invalid percent escape")
			}
			b.WriteByte(hexVal(s[i+1])<<4 | hexVal(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// isToken reports whether s is an RFC 7230 token, i.e. a legal HTTP method.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// validPercentEscapes checks that every "%' is followed by two hex digits.
// Matching and joining stay on raw strings, but malformed escapes are rejected
// up front for both prefixes and request targets.
func validPercentEscapes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
			return false
		}
		i += 2
	}
	return true
}

func isHex(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		return true
	}
	return false
}
