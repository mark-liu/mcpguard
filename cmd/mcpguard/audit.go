package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mark-liu/mcpguard/internal/audit"
)

// runAudit reads ~/.local/share/mcpguard/hook-audit.jsonl and prints recent
// events. Default output is metadata-only; no flag exists to display raw
// matched bytes because the log never stored them — that's the point.
func runAudit(args []string, stdout, stderr io.Writer) int {
	var (
		sinceArg string
		verdict  string
		toolSub  string
		last     bool
		limit    = 20
		path     = audit.DefaultPath()
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--since":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "mcpguard audit: --since requires a duration (e.g. 1h, 30m, 24h)")
				return 1
			}
			i++
			sinceArg = args[i]
		case "--verdict":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "mcpguard audit: --verdict requires pass|warn|block")
				return 1
			}
			i++
			verdict = args[i]
		case "--tool":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "mcpguard audit: --tool requires a substring")
				return 1
			}
			i++
			toolSub = args[i]
		case "--last":
			last = true
		case "--limit":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "mcpguard audit: --limit requires N")
				return 1
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				fmt.Fprintf(stderr, "mcpguard audit: invalid --limit %q\n", args[i])
				return 1
			}
			limit = n
		case "--path":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "mcpguard audit: --path requires a file path")
				return 1
			}
			i++
			path = args[i]
		case "-h", "--help":
			printAuditUsage(stderr)
			return 0
		default:
			fmt.Fprintf(stderr, "mcpguard audit: unknown flag %q\n", args[i])
			return 1
		}
	}

	f := audit.Filter{Verdict: verdict, Tool: toolSub, Limit: limit}
	if last {
		f.Limit = 1
	}
	if sinceArg != "" {
		d, err := time.ParseDuration(sinceArg)
		if err != nil {
			fmt.Fprintf(stderr, "mcpguard audit: invalid --since %q: %v\n", sinceArg, err)
			return 1
		}
		f.Since = time.Now().Add(-d).UTC()
	}

	events, err := audit.Read(path, f)
	if err != nil {
		fmt.Fprintf(stderr, "mcpguard audit: %v\n", err)
		return 1
	}
	if len(events) == 0 {
		fmt.Fprintln(stdout, "(no matching events)")
		return 0
	}

	if last {
		printEventDetail(stdout, events[0])
	} else {
		printEventTable(stdout, events)
	}
	return 0
}

func printEventTable(w io.Writer, events []audit.Event) {
	fmt.Fprintf(w, "%-25s %-7s %-6s %-7s %s\n", "ts", "verdict", "score", "matches", "tool_name")
	fmt.Fprintln(w, strings.Repeat("-", 100))
	for _, e := range events {
		fmt.Fprintf(w, "%-25s %-7s %-6.1f %-7d %s\n",
			e.Timestamp.Format("2006-01-02T15:04:05Z"),
			e.Verdict, e.Score, e.NumMatches, e.ToolName)
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Detail:    mcpguard audit --last  [--tool <substr>] [--verdict block]")
	fmt.Fprintln(w, "Explain:   mcpguard explain <pattern_id>")
}

func printEventDetail(w io.Writer, e audit.Event) {
	fmt.Fprintf(w, "Event %s\n", e.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, "  tool:        %s\n", e.ToolName)
	fmt.Fprintf(w, "  verdict:     %s  (mode=%s sensitivity=%s)\n", e.Verdict, e.Mode, e.Sensitivity)
	fmt.Fprintf(w, "  score:       %.2f across %d matches\n", e.Score, e.NumMatches)
	fmt.Fprintf(w, "  redacted:    %v\n", e.Redacted)
	for i, m := range e.Matches {
		fmt.Fprintf(w, "  match[%d]:    %s (%s/%s)\n", i, m.PatternID, m.Category, m.Severity)
		fmt.Fprintf(w, "               offset=%d text_len=%d sha256=%s\n",
			m.Offset, m.TextLen, m.TextSHA256)
		fmt.Fprintf(w, "               → run: mcpguard explain %s\n", m.PatternID)
	}
}

func printAuditUsage(w io.Writer) {
	fmt.Fprint(w, `mcpguard audit — read the hook event log

Usage: mcpguard audit [filters] [--last] [--limit N]

Reads ~/.local/share/mcpguard/hook-audit.jsonl and prints matching events
newest-first. The log stores metadata only — pattern_id, category, severity,
offset, text length, and a SHA-256 prefix per match. The matched bytes
themselves are never persisted, because Claude reads this log.

Filters (combinable):
  --since <dur>     1h, 30m, 24h — events with ts >= now-dur
  --verdict <v>     pass | warn | block (exact match)
  --tool <substr>   substring match on tool_name (e.g. notion, slack)
  --limit N         show at most N (default 20, newest first)
  --last            shorthand for --limit 1, prints full event detail
  --path <file>     read from this file instead of the default

For each match the pattern_id tells you which detector fired. Look up
the pattern itself (without ever rendering attacker bytes) with:
  mcpguard explain <pattern_id>
`)
}
