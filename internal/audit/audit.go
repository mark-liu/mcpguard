// Package audit records mcpguard hook events to a local JSONL log so an
// operator can triage false positives and trace block decisions after the
// fact.
//
// Threat-model note: the log is DESIGNED to be safe to read into Claude's
// context. It stores ONLY metadata — pattern_id, category, severity, offset,
// length, and a SHA-256 prefix of the matched substring. The raw matched
// bytes (which are attacker-controlled by definition) are NEVER persisted
// here. Operators triaging a hit can pipe pattern_id into `mcpguard explain`
// to learn what the pattern looks for; they cannot re-derive the live
// payload from the log alone. This breaks the audit-log-as-backdoor channel.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark-liu/mcpguard/internal/scan"
)

// DefaultPath is ~/.local/share/mcpguard/hook-audit.jsonl, mirroring
// webguard's ~/.local/share/webguard-mcp/audit.jsonl convention.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "hook-audit.jsonl"
	}
	return filepath.Join(home, ".local/share/mcpguard/hook-audit.jsonl")
}

// MatchRecord captures one fired pattern. NO raw text field by design.
type MatchRecord struct {
	PatternID  string `json:"pattern_id"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Offset     int    `json:"offset"`
	TextLen    int    `json:"text_len"`
	TextSHA256 string `json:"text_sha256"`
}

// Event is one hook invocation that produced a non-pass verdict (or, if
// LogPasses is enabled by the caller, every invocation).
type Event struct {
	Timestamp   time.Time     `json:"ts"`
	ToolName    string        `json:"tool_name"`
	Sensitivity string        `json:"sensitivity"`
	Mode        string        `json:"mode"`
	Verdict     string        `json:"verdict"`
	Score       float64       `json:"score"`
	NumMatches  int           `json:"num_matches"`
	Redacted    bool          `json:"redacted"`
	Matches     []MatchRecord `json:"matches,omitempty"`
}

// EventFromResult builds an Event from a scan.Result + invocation context.
// Match records are reduced to metadata only.
func EventFromResult(toolName, sensitivity, mode string, redacted bool, r scan.Result) Event {
	records := make([]MatchRecord, len(r.Matches))
	for i, m := range r.Matches {
		records[i] = MatchRecord{
			PatternID:  m.PatternID,
			Category:   m.Category,
			Severity:   string(m.Severity),
			Offset:     m.Offset,
			TextLen:    len(m.Text),
			TextSHA256: scan.Sha256Prefix(m.Text),
		}
	}
	return Event{
		Timestamp:   time.Now().UTC(),
		ToolName:    toolName,
		Sensitivity: sensitivity,
		Mode:        mode,
		Verdict:     string(r.Verdict),
		Score:       r.Score,
		NumMatches:  len(r.Matches),
		Redacted:    redacted,
		Matches:     records,
	}
}

// Append appends one event as a single JSON line to path. Creates the parent
// directory on first use. Returns an error rather than panicking so callers
// (e.g. the hook) can degrade gracefully — an audit-log write failure must
// never block a tool call.
func Append(path string, e Event) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("audit: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return enc.Encode(e)
}

// Filter narrows which events Read returns. Zero values mean "no filter".
type Filter struct {
	Since   time.Time // only events with ts >= Since
	Verdict string    // exact match against Event.Verdict
	Tool    string    // substring match against Event.ToolName
	Limit   int       // return at most this many (newest first); 0 = all
}

// Read parses path as JSONL and returns events matching f, newest-first.
// Malformed lines are skipped silently so a single bad write doesn't
// poison subsequent queries.
func Read(path string, f Filter) ([]Event, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read: %w", err)
	}
	var out []Event
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
			continue
		}
		if f.Verdict != "" && e.Verdict != f.Verdict {
			continue
		}
		if f.Tool != "" && !strings.Contains(e.ToolName, f.Tool) {
			continue
		}
		out = append(out, e)
	}
	// newest-first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}
