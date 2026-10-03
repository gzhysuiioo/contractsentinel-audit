// Package contractsentinel: case-sensitive decoding of stored report archives.
package contractsentinel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// decodeStoredReport parses one report archive using strict, case-sensitive
// member recognition. Only the fixed member names defined by Report,
// ReportArtifact, ReportRule and ReportFinding (their original json tags:
// reportId, artifact, name, hash, rules, findings, id, kind, severity,
// invariant, requiresABI, version, status, note, artifactHash, ruleId and
// evidence) populate domain fields. Every other member is an unknown
// extension and is skipped together with its value, exactly as
// json.Unmarshal ignores an unknown field.
//
// json.Unmarshal matches members case-insensitively, so an archive that
// carries both "status" and "StAtus" loads the variant into the fixed Status
// field, last member in document order winning. The duplicate-member scan
// cannot catch this: decoded names differ in case, so "StAtus" is not a
// repeated member. The extension could then overwrite a 发现缺陷 conclusion
// with 通过 (or rescue an unsupported/missing fixed value), moving the
// trusted conclusion with member position. Recognizing only the original
// fixed spellings keeps the decoded report independent of where extensions
// appear.
//
// Recognition otherwise matches encoding/json: member names are compared
// after JSON string decoding (a Unicode-escaped name denotes the same
// member), case is never folded and surrounding whitespace is never
// trimmed, and the contents of a string value are ordinary text even when
// they look like JSON. Repeated identical members are rejected earlier by
// findDuplicateJSONMember, which scans every object including unknown
// extensions; this decoder never has to choose between two same-named
// values.
func decodeStoredReport(data []byte) (Report, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return Report{}, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return Report{}, fmt.Errorf("the archive must be a JSON object")
	}
	var r Report
	if err := readReportObject(dec, &r); err != nil {
		return Report{}, err
	}
	// A Decoder allows another value after the first one; the archive is
	// exactly one object, so require end of input here.
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return Report{}, fmt.Errorf("unexpected trailing content after the report object")
		}
		return Report{}, err
	}
	return r, nil
}

// readObject consumes an opened object ('{' already read) and invokes field
// once per member. field must consume exactly the member value.
func readObject(dec *json.Decoder, field func(key string) error) error {
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("invalid JSON object member name")
		}
		if err := field(key); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing '}'
	return err
}

// isNullToken reports whether tok is the JSON null literal.
func isNullToken(tok any) bool {
	return tok == nil
}

// readReportObject consumes the top-level report object body.
func readReportObject(dec *json.Decoder, r *Report) error {
	return readObject(dec, func(key string) error {
		switch key {
		case "reportId":
			v, err := expectString(dec, "reportId")
			r.ReportID = v
			return err
		case "artifact":
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			if isNullToken(tok) {
				return nil // artifact: null leaves the zero artifact, like Unmarshal
			}
			if d, ok := tok.(json.Delim); !ok || d != '{' {
				return fmt.Errorf("member %q must be a JSON object, got %s", "artifact", scalarKind(tok))
			}
			return readArtifactObject(dec, &r.Artifact)
		case "rules":
			return readRulesArray(dec, r)
		case "findings":
			return readFindingsArray(dec, r)
		default:
			return skipJSONValue(dec)
		}
	})
}

// readArtifactObject consumes the artifact member value.
func readArtifactObject(dec *json.Decoder, a *ReportArtifact) error {
	return readObject(dec, func(key string) error {
		switch key {
		case "name":
			v, err := expectString(dec, "artifact.name")
			a.Name = v
			return err
		case "hash":
			v, err := expectString(dec, "artifact.hash")
			a.Hash = v
			return err
		default:
			return skipJSONValue(dec)
		}
	})
}

// readRulesArray consumes the rules member value, one object per rule.
func readRulesArray(dec *json.Decoder, r *Report) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if isNullToken(tok) {
		return nil // rules: null leaves a nil slice, like Unmarshal
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("member %q must be a JSON array, got %s", "rules", scalarKind(tok))
	}
	rules := []ReportRule{}
	for i := 0; dec.More(); i++ {
		elementTok, err := dec.Token()
		if err != nil {
			return err
		}
		if isNullToken(elementTok) {
			// A null element still occupies its index as a zero rule.
			rules = append(rules, ReportRule{})
			continue
		}
		if d, ok := elementTok.(json.Delim); !ok || d != '{' {
			return fmt.Errorf("rules[%d] must be a JSON object, got %s", i, scalarKind(elementTok))
		}
		rule := ReportRule{}
		if err := readRuleObject(dec, &rule, i); err != nil {
			return err
		}
		rules = append(rules, rule)
	}
	if _, err := dec.Token(); err != nil { // closing ']'
		return err
	}
	r.Rules = rules
	return nil
}

// readRuleObject consumes one rules array element body.
func readRuleObject(dec *json.Decoder, rule *ReportRule, idx int) error {
	return readObject(dec, func(key string) error {
		where := fmt.Sprintf("rules[%d].%s", idx, key)
		switch key {
		case "id":
			v, err := expectString(dec, where)
			rule.ID = v
			return err
		case "kind":
			v, err := expectString(dec, where)
			rule.Kind = v
			return err
		case "severity":
			v, err := expectString(dec, where)
			rule.Severity = v
			return err
		case "invariant":
			v, err := expectString(dec, where)
			rule.Invariant = v
			return err
		case "requiresABI":
			v, err := expectBool(dec, where)
			rule.RequiresABI = v
			return err
		case "version":
			v, err := expectString(dec, where)
			rule.Version = v
			return err
		case "status":
			v, err := expectString(dec, where)
			rule.Status = v
			return err
		case "note":
			v, err := expectString(dec, where)
			rule.Note = v
			return err
		default:
			return skipJSONValue(dec)
		}
	})
}

// readFindingsArray consumes the findings member value, one object each.
func readFindingsArray(dec *json.Decoder, r *Report) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if isNullToken(tok) {
		return nil // findings: null leaves a nil slice, like Unmarshal
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("member %q must be a JSON array, got %s", "findings", scalarKind(tok))
	}
	findings := []ReportFinding{}
	for i := 0; dec.More(); i++ {
		elementTok, err := dec.Token()
		if err != nil {
			return err
		}
		if isNullToken(elementTok) {
			findings = append(findings, ReportFinding{})
			continue
		}
		if d, ok := elementTok.(json.Delim); !ok || d != '{' {
			return fmt.Errorf("findings[%d] must be a JSON object, got %s", i, scalarKind(elementTok))
		}
		finding := ReportFinding{}
		if err := readFindingObject(dec, &finding, i); err != nil {
			return err
		}
		findings = append(findings, finding)
	}
	if _, err := dec.Token(); err != nil { // closing ']'
		return err
	}
	r.Findings = findings
	return nil
}

// readFindingObject consumes one findings array element body.
func readFindingObject(dec *json.Decoder, finding *ReportFinding, idx int) error {
	return readObject(dec, func(key string) error {
		where := fmt.Sprintf("findings[%d].%s", idx, key)
		switch key {
		case "artifactHash":
			v, err := expectString(dec, where)
			finding.ArtifactHash = v
			return err
		case "ruleId":
			v, err := expectString(dec, where)
			finding.RuleID = v
			return err
		case "version":
			v, err := expectString(dec, where)
			finding.Version = v
			return err
		case "severity":
			v, err := expectString(dec, where)
			finding.Severity = v
			return err
		case "invariant":
			v, err := expectString(dec, where)
			finding.Invariant = v
			return err
		case "evidence":
			v, err := expectString(dec, where)
			finding.Evidence = v
			return err
		default:
			return skipJSONValue(dec)
		}
	})
}

// expectString consumes one scalar token and requires a JSON string. JSON
// null leaves the zero value, as it does under json.Unmarshal.
func expectString(dec *json.Decoder, member string) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	if isNullToken(tok) {
		return "", nil
	}
	s, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("member %q must be a JSON string, got %s", member, scalarKind(tok))
	}
	return s, nil
}

// expectBool consumes one scalar token and requires a JSON boolean. JSON null
// leaves false, as it does under json.Unmarshal.
func expectBool(dec *json.Decoder, member string) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	if isNullToken(tok) {
		return false, nil
	}
	b, ok := tok.(bool)
	if !ok {
		return false, fmt.Errorf("member %q must be a JSON boolean, got %s", member, scalarKind(tok))
	}
	return b, nil
}

// scalarKind describes a scalar token for error messages.
func scalarKind(tok any) string {
	switch tok.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64, json.Number:
		return "number"
	case string:
		return "string"
	default:
		return "another JSON value"
	}
}

// skipJSONValue consumes exactly one unknown member value, including nested
// objects and arrays.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // null, bool, string or number
	}
	switch delim {
	case '{':
		for dec.More() {
			if _, err := dec.Token(); err != nil { // unknown member name
				return err
			}
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	default:
		// '}' and ']' are consumed by callers and never start a value.
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
}
