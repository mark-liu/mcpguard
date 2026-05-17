package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Truncate shortens s to max bytes, appending "..." when truncated.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// FormatMatches writes one indented line per match to w, RAW (includes the
// attacker-controlled match text). DANGEROUS: any caller writing this output
// to a path Claude later reads creates a re-injection channel. Prefer
// FormatMatchesSafe; this function only exists for opt-in --show-excerpts
// debugging where the operator has accepted that risk.
func FormatMatches(w io.Writer, matches []Match, maxTextWidth int) {
	for _, m := range matches {
		fmt.Fprintf(w, "  %s [%s/%s]: %q\n",
			m.PatternID, m.Category, m.Severity, Truncate(m.Text, maxTextWidth))
	}
}

// FormatMatchesSafe writes one indented line per match using ONLY metadata
// fields that cannot carry an attacker payload — pattern_id, category,
// severity, offset, text length, and a hash prefix for correlation. The
// operator can pipe the pattern_id into `mcpguard explain` to learn what
// the pattern looks for without ever rendering the live matched bytes.
func FormatMatchesSafe(w io.Writer, matches []Match) {
	for _, m := range matches {
		fmt.Fprintf(w, "  %s [%s/%s] offset=%d len=%d sha256=%s\n",
			m.PatternID, m.Category, m.Severity,
			m.Offset, len(m.Text), Sha256Prefix(m.Text))
	}
}

// Sha256Prefix returns the first 16 hex chars (64 bits) of the SHA-256 of s.
// Sufficient for correlating "two events tripped on the same payload" in
// audit logs without storing the payload itself.
func Sha256Prefix(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// DefangText interleaves U+00B7 (middle dot) between every character of s.
// Three properties matter:
//
//  1. The resulting string contains none of the literal substrings any
//     mcpguard pattern looks for, so it cannot re-trigger a scan.
//  2. It remains human-readable for triage — "i·g·n·o·r·e p·r·e·v·i·o·u·s"
//     is recognisable as the original phrase to an operator scanning a
//     warning, but visually flagged as data-not-instruction.
//  3. Most LLMs will not parse it as an executable instruction because the
//     character interleaving breaks tokenisation of the directive verbs.
//
// Only used in opt-in display paths (`mcpguard audit --unsafe-show-excerpts`).
// The audit log on disk never stores raw OR defanged text — only hashes.
func DefangText(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) * 3)
	runes := []rune(s)
	for i, r := range runes {
		b.WriteRune(r)
		if i < len(runes)-1 && r != ' ' && runes[i+1] != ' ' {
			b.WriteRune('·')
		}
	}
	return b.String()
}

// AggregateScan is a package-level convenience for callers that want one
// verdict across many strings. Delegates to engine.AggregateScan which
// unions all matches before deciding the verdict — preserves the threshold
// semantics when sub-threshold hits are split across multiple fields.
func AggregateScan(engine *Engine, texts []string) Result {
	return engine.AggregateScan(texts)
}

// PatternByID returns the pattern definition with the given ID. Used by the
// `mcpguard explain` subcommand so operators can triage a fired pattern_id
// without needing the live matched bytes. ok=false if no such pattern.
func PatternByID(id string) (Pattern, bool) {
	for _, p := range allPatterns() {
		if p.ID == id {
			return p, true
		}
	}
	return Pattern{}, false
}
