package scan

import (
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Verdict is the outcome of a scan.
type Verdict string

const (
	VerdictPass  Verdict = "pass"
	VerdictWarn  Verdict = "warn"
	VerdictBlock Verdict = "block"
)

// Result holds the output of a scan.
type Result struct {
	Verdict  Verdict `json:"verdict"`
	Score    float64 `json:"score"`
	Matches  []Match `json:"matches,omitempty"`
	TimingUS int64   `json:"timing_us"`
}

// Engine is the prompt injection scanner.
type Engine struct {
	sensitivity string
	threshold   float64
	literals    []Pattern       // literal patterns (matched via lowercased substring)
	regexes     []compiledRegex // compiled regex patterns
	all         []Pattern
}

// NewEngine creates a scanner engine with the given sensitivity level.
// Sensitivity controls the scoring threshold: low=2.0, medium=1.0, high=0.5.
func NewEngine(sensitivity string) *Engine {
	var threshold float64
	switch strings.ToLower(sensitivity) {
	case "low":
		threshold = 2.0
	case "high":
		threshold = 0.5
	default: // medium
		threshold = 1.0
	}

	defs := allPatterns()
	var literals []Pattern
	var regexes []compiledRegex

	for _, d := range defs {
		switch d.Type {
		case PatternLiteral:
			literals = append(literals, d)
		case PatternRegex:
			re := regexp.MustCompile(d.Value)
			regexes = append(regexes, compiledRegex{re: re, pattern: d})
		}
	}

	return &Engine{
		sensitivity: strings.ToLower(sensitivity),
		threshold:   threshold,
		literals:    literals,
		regexes:     regexes,
		all:         defs,
	}
}

// PatternCount returns the total number of detection patterns.
func (e *Engine) PatternCount() int {
	return len(e.all)
}

// Scan runs the detection pipeline on a text string and returns a result.
func (e *Engine) Scan(text string) Result {
	start := time.Now()
	clean := stripInvisible(text)
	matches := e.scanText(clean)
	return e.verdictFromMatches(matches, start)
}

// AggregateScan scans every input text, unions the matches across all of
// them, and produces ONE verdict from the combined match set. Used by
// one-shot consumers (e.g. the PostToolUse hook) that need cross-field
// aggregation — two high-severity hits split across two strings each fall
// below the per-string threshold, but the combined set should still block.
func (e *Engine) AggregateScan(texts []string) Result {
	start := time.Now()
	var all []Match
	for _, text := range texts {
		all = append(all, e.scanText(stripInvisible(text))...)
	}
	return e.verdictFromMatches(all, start)
}

// verdictFromMatches applies the critical-short-circuit and threshold rules
// to a match set and returns a Result. Shared by single-string Scan and
// multi-string AggregateScan so the scoring semantics stay identical.
func (e *Engine) verdictFromMatches(matches []Match, start time.Time) Result {
	timing := func() int64 { return time.Since(start).Microseconds() }

	if len(matches) == 0 {
		return Result{Verdict: VerdictPass, TimingUS: timing()}
	}

	for _, m := range matches {
		if m.Severity == SeverityCritical {
			return Result{
				Verdict:  VerdictBlock,
				Score:    e.score(matches),
				Matches:  matches,
				TimingUS: timing(),
			}
		}
	}

	score := e.score(matches)
	verdict := VerdictPass
	if score >= e.threshold {
		verdict = VerdictBlock
	}
	return Result{
		Verdict:  verdict,
		Score:    score,
		Matches:  matches,
		TimingUS: timing(),
	}
}

// scanText runs literal substring + regex matching on a single text string.
func (e *Engine) scanText(text string) []Match {
	if len(text) == 0 {
		return nil
	}

	var matches []Match
	lower := strings.ToLower(text)

	// Literal matching (case-insensitive via lowered text).
	for _, pat := range e.literals {
		idx := 0
		needle := strings.ToLower(pat.Value)
		for {
			pos := strings.Index(lower[idx:], needle)
			if pos < 0 {
				break
			}
			absPos := idx + pos
			matches = append(matches, Match{
				PatternID: pat.ID,
				Category:  pat.Category,
				Severity:  pat.Severity,
				Text:      text[absPos : absPos+len(needle)],
				Offset:    absPos,
			})
			idx = absPos + len(needle)
		}
	}

	// Regex matching on original text.
	for _, re := range e.regexes {
		locs := re.re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			matches = append(matches, Match{
				PatternID: re.pattern.ID,
				Category:  re.pattern.Category,
				Severity:  re.pattern.Severity,
				Text:      text[loc[0]:loc[1]],
				Offset:    loc[0],
			})
		}
	}

	return dedup(matches)
}

// score sums weighted match scores. Multiple hits in different categories
// amplify the score (category diversity bonus).
func (e *Engine) score(matches []Match) float64 {
	var total float64
	categories := make(map[string]bool)

	for _, m := range matches {
		total += severityWeight(m.Severity)
		categories[m.Category] = true
	}

	// Category diversity bonus: +0.25 per additional category beyond the first.
	if n := len(categories); n > 1 {
		total += float64(n-1) * 0.25
	}

	return total
}

// dedup removes duplicate matches at the same offset with the same pattern ID.
func dedup(matches []Match) []Match {
	if len(matches) <= 1 {
		return matches
	}

	type key struct {
		id     string
		offset int
	}
	seen := make(map[key]bool)
	var out []Match

	for _, m := range matches {
		k := key{m.PatternID, m.Offset}
		if !seen[k] {
			seen[k] = true
			out = append(out, m)
		}
	}

	return out
}

// stripInvisible removes zero-width characters and other invisible formatters
// that could be used to evade pattern matching. The Unicode tag range
// U+E0001\u2013U+E007F is preserved here so the uo-004 obfuscation pattern can
// still match \u2014 stripping the tag chars before scanning would silently
// disarm that detector.
func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\uFEFF':
			return -1
		}
		if r >= 0xE0001 && r <= 0xE007F {
			return r
		}
		if r != '\n' && r != '\r' && r != '\t' && r != ' ' && unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, s)
}
