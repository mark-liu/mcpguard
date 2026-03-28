// Package scan implements prompt injection detection for MCP tool results.
package scan

import "regexp"

// PatternType distinguishes literal (case-insensitive substring) from regex patterns.
type PatternType int

const (
	PatternLiteral PatternType = iota
	PatternRegex
)

// Severity indicates how dangerous a pattern match is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Pattern is a single detection rule.
type Pattern struct {
	ID       string
	Category string
	Severity Severity
	Type     PatternType
	Value    string  // literal text (lowercased) or regex string
	Weight   float64 // scoring weight derived from severity
}

// Match records a single pattern hit.
type Match struct {
	PatternID string   `json:"pattern_id"`
	Category  string   `json:"category"`
	Severity  Severity `json:"severity"`
	Text      string   `json:"text"`
	Offset    int      `json:"offset"`
}

type compiledRegex struct {
	re      *regexp.Regexp
	pattern Pattern
}

// severityWeight returns the scoring weight for a severity level.
func severityWeight(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return 2.0
	case SeverityHigh:
		return 1.5
	case SeverityMedium:
		return 1.0
	case SeverityLow:
		return 0.5
	default:
		return 1.0
	}
}

// allPatterns returns the full set of detection patterns, ported from webguard
// and extended with MCP/LLM-specific injection vectors.
func allPatterns() []Pattern {
	p := func(id, category string, sev Severity, typ PatternType, value string) Pattern {
		return Pattern{
			ID:       id,
			Category: category,
			Severity: sev,
			Type:     typ,
			Value:    value,
			Weight:   severityWeight(sev),
		}
	}

	return []Pattern{
		// instruction-override (7)
		p("io-001", "instruction-override", SeverityCritical, PatternLiteral, "ignore previous instructions"),
		p("io-002", "instruction-override", SeverityCritical, PatternLiteral, "ignore all previous"),
		p("io-003", "instruction-override", SeverityCritical, PatternLiteral, "disregard previous instructions"),
		p("io-004", "instruction-override", SeverityHigh, PatternLiteral, "forget your instructions"),
		p("io-005", "instruction-override", SeverityHigh, PatternLiteral, "from now on you will"),
		p("io-006", "instruction-override", SeverityHigh, PatternLiteral, "new instructions:"),
		p("io-007", "instruction-override", SeverityCritical, PatternRegex, `(?i)ignore\s+(any|all|every)\s+(prior|previous|earlier)\s+(instructions?|prompts?|rules?)`),

		// prompt-marker (6)
		p("pm-001", "prompt-marker", SeverityCritical, PatternLiteral, "<|im_start|>system"),
		p("pm-002", "prompt-marker", SeverityHigh, PatternLiteral, "<|im_start|>"),
		p("pm-003", "prompt-marker", SeverityHigh, PatternLiteral, "[system]:"),
		p("pm-004", "prompt-marker", SeverityHigh, PatternLiteral, "[inst]"),
		p("pm-005", "prompt-marker", SeverityCritical, PatternLiteral, "<<sys>>"),
		p("pm-006", "prompt-marker", SeverityHigh, PatternRegex, `(?i)\[/?INST\]`),

		// authority-claim (6)
		p("ac-001", "authority-claim", SeverityCritical, PatternLiteral, "i am your developer"),
		p("ac-002", "authority-claim", SeverityHigh, PatternLiteral, "i am the system administrator"),
		p("ac-003", "authority-claim", SeverityHigh, PatternLiteral, "dan mode"),
		p("ac-004", "authority-claim", SeverityHigh, PatternLiteral, "admin override"),
		p("ac-005", "authority-claim", SeverityMedium, PatternLiteral, "you are now in"),
		p("ac-006", "authority-claim", SeverityCritical, PatternRegex, `(?i)(I\s+am|this\s+is)\s+(your|the)\s+(developer|creator|admin|administrator|owner)`),

		// exfil-instruction (5)
		p("ei-001", "exfil-instruction", SeverityCritical, PatternLiteral, "send all data to"),
		p("ei-002", "exfil-instruction", SeverityHigh, PatternLiteral, "exfiltrate"),
		p("ei-003", "exfil-instruction", SeverityCritical, PatternRegex, `(?i)send\s+(all|the|this|your)\s+(the\s+)?(data|information|context|conversation)\s+(and\s+\w+\s+)?to\s+(https?://|//|[a-z0-9.-]+\.[a-z]{2,})`),
		p("ei-004", "exfil-instruction", SeverityHigh, PatternRegex, `(?i)(fetch|load|visit|open|navigate)\s+(https?://|//)[^\s]+`),
		p("ei-005", "exfil-instruction", SeverityHigh, PatternRegex, `!\[(track|pixel|1x1|beacon|exfil)\w*\]\(https?://[^\)]+\)`),

		// output-manipulation (4)
		p("om-001", "output-manipulation", SeverityMedium, PatternLiteral, "respond only with"),
		p("om-002", "output-manipulation", SeverityMedium, PatternLiteral, "do not mention"),
		p("om-003", "output-manipulation", SeverityHigh, PatternRegex, `(?i)never\s+(mention|reveal|disclose|discuss)\s+(that|this|the|your)`),
		p("om-004", "output-manipulation", SeverityMedium, PatternRegex, `(?i)(always|must|should)\s+respond\s+(with|by|using)\s+`),

		// tool-manipulation — MCP-specific (5)
		p("tm-001", "tool-manipulation", SeverityHigh, PatternLiteral, "call the tool"),
		p("tm-002", "tool-manipulation", SeverityHigh, PatternLiteral, "use the function"),
		p("tm-003", "tool-manipulation", SeverityHigh, PatternLiteral, "execute command"),
		p("tm-004", "tool-manipulation", SeverityHigh, PatternRegex, `(?i)(invoke|run|call|use)\s+(the\s+)?(tool|function|mcp)\s+["'\x60]`),
		p("tm-005", "tool-manipulation", SeverityCritical, PatternRegex, `(?i)(call|invoke|run)\s+mcp_\w+`),

		// context-hijacking (5)
		p("ch-001", "context-hijacking", SeverityMedium, PatternLiteral, "IMPORTANT:"),
		p("ch-002", "context-hijacking", SeverityMedium, PatternLiteral, "CRITICAL:"),
		p("ch-003", "context-hijacking", SeverityMedium, PatternLiteral, "OVERRIDE:"),
		p("ch-004", "context-hijacking", SeverityHigh, PatternLiteral, "<system>"),
		p("ch-005", "context-hijacking", SeverityHigh, PatternLiteral, "</system>"),

		// unicode-obfuscation (4)
		p("uo-001", "unicode-obfuscation", SeverityHigh, PatternRegex, `[\x{200B}\x{200C}\x{200D}\x{FEFF}]{3,}`),
		p("uo-002", "unicode-obfuscation", SeverityMedium, PatternRegex, `[\x{202A}-\x{202E}\x{2066}-\x{2069}]{2,}`),
		p("uo-003", "unicode-obfuscation", SeverityMedium, PatternRegex, `[\x{E000}-\x{F8FF}]{2,}`),
		p("uo-004", "unicode-obfuscation", SeverityHigh, PatternRegex, `[\x{E0001}-\x{E007F}]`),

		// delimiter-injection (3)
		p("di-001", "delimiter-injection", SeverityHigh, PatternLiteral, "---end system prompt---"),
		p("di-002", "delimiter-injection", SeverityHigh, PatternRegex, `(?i)-{3,}\s*(END|BEGIN)\s+(SYSTEM|USER|ASSISTANT)\s+(PROMPT|MESSAGE|INSTRUCTIONS?)\s*-{3,}`),
		p("di-003", "delimiter-injection", SeverityHigh, PatternRegex, `\{\s*"role"\s*:\s*"(system|assistant)"\s*`),

		// encoded-injection (3)
		p("enc-001", "encoded-injection", SeverityHigh, PatternRegex, `(?i)eval\s*\(\s*atob\s*\(`),
		p("enc-002", "encoded-injection", SeverityMedium, PatternRegex, `(?i)base64[_\-]?decode`),
		p("enc-003", "encoded-injection", SeverityMedium, PatternRegex, `(?i)String\.fromCharCode\s*\(`),
	}
}
