// Package contractsentinel implements audit rule evaluation over contract artifacts.
package contractsentinel

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Route is one offline routing rule mapping a method/prefix pair to an upstream.
type Route struct {
	ID         string   `json:"id"`
	Methods    []string `json:"methods"`
	PathPrefix string   `json:"pathPrefix"`
	Upstream   string   `json:"upstream"`
}

// routeConfigFile is the on-disk routing configuration.
type routeConfigFile struct {
	// Pointer so a missing routes array can be distinguished from an empty one.
	Routes *[]Route `json:"routes"`
}

// Request is an incoming routing request read as JSON from standard input.
type Request struct {
	Method string `json:"method"`
	Target string `json:"target"`
}

// Resolution is the matched route and the composed upstream URL.
type Resolution struct {
	RouteID     string `json:"routeId"`
	UpstreamURL string `json:"upstreamURL"`
}

// ConfigError means the routing configuration is unreadable or invalid.
type ConfigError struct {
	Reason string
}

func (e *ConfigError) Error() string { return e.Reason }

// RequestError means the incoming request JSON is missing or malformed.
type RequestError struct {
	Reason string
}

func (e *RequestError) Error() string { return e.Reason }

// ResolutionError means no single route could be selected.
// Code is either "route_not_found" or "route_conflict"; Candidates lists
// the tied route ids (sorted) for a conflict.
type ResolutionError struct {
	Code       string
	Reason     string
	Candidates []string
}

func (e *ResolutionError) Error() string { return e.Reason }

// LoadRoutes reads and validates the routing configuration at path.
// The whole configuration is checked before any request is processed.
func LoadRoutes(path string) ([]Route, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigError{Reason: fmt.Sprintf("无法读取配置文件: %v", err)}
	}
	var cfg routeConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, &ConfigError{Reason: fmt.Sprintf("配置 JSON 无效: %v", err)}
	}
	if cfg.Routes == nil {
		return nil, &ConfigError{Reason: "配置缺少 routes 数组"}
	}
	if err := validateRoutes(*cfg.Routes); err != nil {
		return nil, err
	}
	return *cfg.Routes, nil
}

func validateRoutes(routes []Route) error {
	seen := make(map[string]bool)
	for i, r := range routes {
		loc := fmt.Sprintf("路由 #%d", i)
		if r.ID != "" {
			loc += fmt.Sprintf(" (id=%q)", r.ID)
		}
		if r.ID == "" {
			return &ConfigError{Reason: loc + ": id 不能为空"}
		}
		if seen[r.ID] {
			return &ConfigError{Reason: loc + fmt.Sprintf(": id %q 重复", r.ID)}
		}
		seen[r.ID] = true
		if len(r.Methods) == 0 {
			return &ConfigError{Reason: loc + ": methods 必须是非空数组"}
		}
		for _, m := range r.Methods {
			if m != "*" && !isHTTPToken(m) {
				return &ConfigError{Reason: loc + fmt.Sprintf(": 非法方法名 %q", m)}
			}
		}
		if err := validatePrefix(r.PathPrefix); err != nil {
			return &ConfigError{Reason: loc + ": " + err.Error()}
		}
		if err := validateUpstream(r.Upstream); err != nil {
			return &ConfigError{Reason: loc + ": " + err.Error()}
		}
	}
	return nil
}

func validatePrefix(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") {
		return fmt.Errorf("pathPrefix 必须以 / 开头")
	}
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		return fmt.Errorf("pathPrefix 不能以 / 结尾（根前缀 / 除外）")
	}
	if strings.ContainsAny(p, "?#") {
		return fmt.Errorf("pathPrefix 不能包含查询串或片段")
	}
	return nil
}

func validateUpstream(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("upstream 不是合法 URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("upstream 必须是 http 或 https 的绝对地址")
	}
	if u.Host == "" {
		return fmt.Errorf("upstream 必须包含主机")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("upstream 不能包含查询串")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("upstream 不能包含片段")
	}
	return nil
}

// ParseRequest decodes and validates a request JSON document.
func ParseRequest(data []byte) (Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return req, &RequestError{Reason: fmt.Sprintf("请求 JSON 无效: %v", err)}
	}
	if req.Method == "" {
		return req, &RequestError{Reason: "method 缺失"}
	}
	if !isHTTPToken(req.Method) {
		return req, &RequestError{Reason: fmt.Sprintf("method 不合法: %q", req.Method)}
	}
	if req.Method == "*" {
		return req, &RequestError{Reason: "method 不合法: * 是配置侧通配符，不能作为请求方法"}
	}
	t := req.Target
	if !strings.HasPrefix(t, "/") {
		return req, &RequestError{Reason: "target 必须以 / 开头"}
	}
	if strings.Contains(t, "#") {
		return req, &RequestError{Reason: "target 不能包含片段"}
	}
	if err := checkPercentEscapes(t); err != nil {
		return req, &RequestError{Reason: "target 含非法百分号转义: " + err.Error()}
	}
	return req, nil
}

// isHTTPToken reports whether s is a valid HTTP method token per RFC 7230
// (tchar: letters, digits and !#$%&'*+-.^_`|~).
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c > 127 {
			return false
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) &&
			!(c >= 'a' && c <= 'z') &&
			!(c >= 'A' && c <= 'Z') &&
			!(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// checkPercentEscapes verifies every '%' is followed by exactly two hex digits.
func checkPercentEscapes(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) || !isHexDigit(s[i+1]) || !isHexDigit(s[i+2]) {
				return fmt.Errorf("%% 后必须跟两个十六进制字符")
			}
		}
	}
	return nil
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Resolve selects the best route for req and composes the upstream URL.
//
// Matching is on the raw (percent-encoded) request path, segment-boundary
// aware: /api matches /api and /api/orders but not /apiv2, and %2F is not
// a separator. Query strings never participate in matching but are appended
// verbatim to the result.
func Resolve(routes []Route, req Request) (Resolution, error) {
	path := req.Target
	query := ""
	if i := strings.Index(path, "?"); i >= 0 {
		query = path[i:] // keep the '?' and everything after it verbatim
		path = path[:i]
	}

	var best *Route
	bestConcrete := false
	var conflicts []string

	for i := range routes {
		r := &routes[i]
		if !prefixMatches(r.PathPrefix, path) {
			continue
		}
		concrete := methodMatches(r.Methods, req.Method)
		if !concrete && !methodMatches(r.Methods, "*") {
			continue
		}
		if best == nil {
			best = r
			bestConcrete = concrete
			conflicts = nil
			continue
		}
		// Longest prefix wins; on equal prefix a concrete method beats '*'.
		if len(r.PathPrefix) > len(best.PathPrefix) ||
			(len(r.PathPrefix) == len(best.PathPrefix) && concrete && !bestConcrete) {
			best = r
			bestConcrete = concrete
			conflicts = nil
			continue
		}
		if len(r.PathPrefix) == len(best.PathPrefix) && concrete == bestConcrete {
			if conflicts == nil {
				conflicts = []string{best.ID}
			}
			conflicts = append(conflicts, r.ID)
		}
	}

	if best == nil {
		return Resolution{}, &ResolutionError{
			Code:   "route_not_found",
			Reason: fmt.Sprintf("没有路由匹配 %s %s", req.Method, req.Target),
		}
	}
	if conflicts != nil {
		sort.Strings(conflicts)
		return Resolution{}, &ResolutionError{
			Code:       "route_conflict",
			Reason:     fmt.Sprintf("多条路由匹配 %s %s", req.Method, req.Target),
			Candidates: conflicts,
		}
	}

	// Strip the matched prefix; the remainder is either empty or starts
	// with '/' (prefixMatches guarantees a segment boundary).
	remainder := path[len(best.PathPrefix):]
	u, err := url.Parse(best.Upstream)
	if err != nil {
		// Validated at load time; unreachable in practice.
		return Resolution{}, &ResolutionError{Code: "invalid_config", Reason: err.Error()}
	}
	upstreamURL := u.Scheme + "://" + u.Host + joinPath(u.EscapedPath(), remainder) + query
	return Resolution{RouteID: best.ID, UpstreamURL: upstreamURL}, nil
}

// prefixMatches reports whether path falls under prefix on a segment boundary.
func prefixMatches(prefix, path string) bool {
	if prefix == "/" {
		return true
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

func methodMatches(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

// joinPath joins the upstream base path with the request remainder, keeping
// exactly one '/' at the junction even when either side is empty or already
// carries a slash.
func joinPath(base, remainder string) string {
	if remainder == "" {
		if base == "" {
			return "/"
		}
		if strings.HasSuffix(base, "/") {
			return base
		}
		return base + "/"
	}
	if base == "" {
		if strings.HasPrefix(remainder, "/") {
			return remainder
		}
		return "/" + remainder
	}
	switch {
	case strings.HasSuffix(base, "/") && strings.HasPrefix(remainder, "/"):
		return base + remainder[1:]
	case !strings.HasSuffix(base, "/") && !strings.HasPrefix(remainder, "/"):
		return base + "/" + remainder
	default:
		return base + remainder
	}
}
