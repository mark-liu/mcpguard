package main

import (
	"fmt"
	"io"

	"github.com/mark-liu/mcpguard/internal/scan"
)

// runExplain prints the definition of one pattern_id (id, category, severity,
// type, value, rationale). Lets an operator triage a fired pattern surfaced
// by `mcpguard audit` without needing the live matched bytes.
func runExplain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printExplainUsage(stderr)
		if len(args) == 0 {
			return 1
		}
		return 0
	}

	id := args[0]
	p, ok := scan.PatternByID(id)
	if !ok {
		fmt.Fprintf(stderr, "mcpguard explain: unknown pattern_id %q\n", id)
		return 1
	}

	typeName := "literal"
	if p.Type == scan.PatternRegex {
		typeName = "regex"
	}

	fmt.Fprintf(stdout, "%s  %s  %s  %s match\n",
		p.ID, p.Category, p.Severity, typeName)
	fmt.Fprintf(stdout, "  pattern: %s\n", p.Value)
	if r := rationaleFor(p.Category); r != "" {
		fmt.Fprintf(stdout, "  rationale: %s\n", r)
	}
	return 0
}

// rationaleFor returns a short human-readable description of what a pattern
// category is trying to detect. Static category-level rationale keeps the
// signal-to-noise high without requiring per-pattern prose.
func rationaleFor(category string) string {
	switch category {
	case "instruction-override":
		return "phrases used to tell the model to discard its prior instructions"
	case "prompt-marker":
		return "literal tokens used to forge system/instruction boundaries (e.g. <|im_start|>, [INST], <<sys>>)"
	case "authority-claim":
		return "false claims of operator authority (e.g. 'I am your developer', 'admin override', 'DAN mode')"
	case "exfil-instruction":
		return "phrases that direct the model to send data, fetch URLs, or embed tracking pixels"
	case "tool-manipulation":
		return "phrases that direct the model to invoke specific MCP tools or function calls"
	case "context-hijacking":
		return "high-attention markers used to elevate attacker text to instruction status"
	case "output-manipulation":
		return "phrases that constrain the model's response shape ('respond only with', 'do not mention')"
	case "unicode-obfuscation":
		return "zero-width, bidi, PUA, or tag-range Unicode used to hide payloads from human readers"
	case "encoded-injection":
		return "code constructs that execute base64/hex-decoded payloads at runtime"
	case "delimiter-injection":
		return "fake END/BEGIN PROMPT markers or forged role JSON blocks"
	default:
		return ""
	}
}

func printExplainUsage(w io.Writer) {
	fmt.Fprint(w, `mcpguard explain — describe one detection pattern

Usage: mcpguard explain <pattern_id>

Prints the definition of a single mcpguard pattern by its id (e.g. io-001,
ei-002, uo-004). Use this when triaging an audit event — the audit log
records pattern_ids but never the live matched bytes; `+"`mcpguard explain`"+`
tells you what the pattern looks for so you can decide whether the hit
was real or a false positive without ever rendering attacker text.

Example:
  $ mcpguard audit --last
  ... match[0]: ei-002 (exfil-instruction/high) ...

  $ mcpguard explain ei-002
  ei-002  exfil-instruction  high  literal match
    pattern: exfiltrate
    rationale: phrases that direct the model to send data ...
`)
}
