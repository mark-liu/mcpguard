package scan

import "encoding/json"

// ExtractStrings unmarshals a JSON document and returns every string value
// longer than the minimum scan length, recursively. Returns nil on parse error.
//
// Used by callers that have JSON bytes and want a flat list of scannable
// strings — both the stdio proxy and the Claude Code hook subcommand.
func ExtractStrings(data []byte) []string {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil
	}
	var out []string
	WalkStrings(v, &out)
	return out
}

// WalkStrings recursively collects scannable strings longer than 3 chars
// from an unmarshalled JSON tree, including object KEYS as well as values.
//
// Map keys are scanned because Claude sees structured object keys in tool
// output; a malicious MCP could put "ignore previous instructions" in a
// property name and a benign value in the value slot. Skipping keys is a
// silent bypass.
//
// The minimum-length filter avoids scanning trivially short values while
// still catching short injection markers like "[INST]" (6) and "<<sys>>"
// (7). Do not raise this minimum without re-running the short-pattern tests.
func WalkStrings(v interface{}, out *[]string) {
	switch val := v.(type) {
	case string:
		if len(val) > 3 {
			*out = append(*out, val)
		}
	case map[string]interface{}:
		for k, v := range val {
			if len(k) > 3 {
				*out = append(*out, k)
			}
			WalkStrings(v, out)
		}
	case []interface{}:
		for _, v := range val {
			WalkStrings(v, out)
		}
	}
}
