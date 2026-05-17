package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/mark-liu/mcpguard/internal/audit"
	"github.com/mark-liu/mcpguard/internal/scan"
)

// hookEnvelope mirrors the Claude Code PostToolUse JSON sent on stdin.
// We inspect tool_name, tool_input, and tool_response. tool_input is the
// model-constructed argument vector — attacker content in a prior turn's
// response can poison the model into shaping a follow-up call's input
// (indirect injection), so we scan both sides and aggregate the verdict.
type hookEnvelope struct {
	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolResponse json.RawMessage `json:"tool_response"`
}

// hookResponse is the JSON written to stdout per the Claude Code PostToolUse
// hook contract. In block mode we use HookSpecificOutput.UpdatedMCPToolOutput
// (for mcp__* tools) or UpdatedToolOutput (everything else) to actually
// REPLACE the malicious tool_response that reaches the model — exit codes
// alone cannot do this; PostToolUse runs after the tool has executed.
//
// Reference: https://code.claude.com/docs/en/hooks#exit-code-output
type hookResponse struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName        string `json:"hookEventName"`
	UpdatedMCPToolOutput string `json:"updatedMCPToolOutput,omitempty"`
	UpdatedToolOutput    string `json:"updatedToolOutput,omitempty"`
}

// runHookIO scans tool_response from a Claude Code PostToolUse envelope read
// from stdin. On a Block verdict:
//   - --mode warn  → emit metadata-only warning to stderr (Claude sees it as
//     context), leave original tool_response intact, exit 0.
//   - --mode block → emit warning to stderr AND emit JSON on stdout that
//     redacts the original tool_response via updatedMCPToolOutput, exit 0.
//
// Default stderr output is metadata-only (pattern_id, category, severity,
// offset, len, sha256 prefix). Raw match excerpts are never written here
// because Claude will read this stderr — the audit-log-as-backdoor channel.
// Pass --show-excerpts to opt back into the unsafe legacy behaviour (with
// a one-line warning preamble) for active debug sessions.
//
// Every non-pass verdict is appended to the audit log at
// ~/.local/share/mcpguard/hook-audit.jsonl as metadata-only Event records.
// Audit-log write failures are logged to stderr but never block the tool.
//
// We never use exit code 2: PostToolUse runs AFTER the tool, so exit 2
// merely surfaces stderr to Claude — it does not stop the malicious payload
// from reaching the model. Replacement via JSON is the only real boundary.
//
// Internal failures (stdin read, JSON parse) exit 0 with stderr diagnostics
// — never block a tool call because of our own malfunction. Flag errors
// exit 1 (operator-visible misconfiguration).
func runHookIO(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runHookIOPath(args, stdin, stdout, stderr, audit.DefaultPath())
}

// runHookIOPath is the test-overridable variant — accepts an explicit audit
// log path so tests don't pollute ~/.local/share/mcpguard/hook-audit.jsonl.
func runHookIOPath(args []string, stdin io.Reader, stdout, stderr io.Writer, auditPath string) int {
	sensitivity := "medium"
	mode := "warn"
	showExcerpts := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--sensitivity":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "mcpguard hook: --sensitivity requires low|medium|high")
				return 1
			}
			i++
			sensitivity = args[i]
		case "--mode":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "mcpguard hook: --mode requires warn|block")
				return 1
			}
			i++
			mode = args[i]
		case "--show-excerpts":
			showExcerpts = true
		case "-h", "--help":
			printHookUsage(stderr)
			return 0
		default:
			fmt.Fprintf(stderr, "mcpguard hook: unknown flag %q\n", args[i])
			return 1
		}
	}

	switch sensitivity {
	case "low", "medium", "high":
	default:
		fmt.Fprintf(stderr, "mcpguard hook: invalid sensitivity %q (want low|medium|high)\n", sensitivity)
		return 1
	}
	switch mode {
	case "warn", "block":
	default:
		fmt.Fprintf(stderr, "mcpguard hook: invalid mode %q (want warn|block)\n", mode)
		return 1
	}

	raw, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "mcpguard hook: read stdin: %v\n", err)
		return 0
	}

	var env hookEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		fmt.Fprintf(stderr, "mcpguard hook: parse envelope: %v\n", err)
		return 0
	}
	if len(env.ToolResponse) == 0 && len(env.ToolInput) == 0 {
		return 0
	}

	engine := scan.NewEngine(sensitivity)
	texts := scan.ExtractStrings(env.ToolResponse)
	if len(env.ToolInput) > 0 {
		texts = append(texts, scan.ExtractStrings(env.ToolInput)...)
	}
	result := scan.AggregateScan(engine, texts)

	if result.Verdict == scan.VerdictPass {
		return 0
	}

	willRedact := mode == "block"

	fmt.Fprintf(stderr,
		"[mcpguard] %s on %s (score=%.1f, %d matches)\n",
		labelFor(mode), env.ToolName, result.Score, len(result.Matches))
	if showExcerpts {
		fmt.Fprintln(stderr, "  [excerpts enabled — output contains attacker-controlled text]")
		scan.FormatMatches(stderr, result.Matches, 80)
	} else {
		scan.FormatMatchesSafe(stderr, result.Matches)
		fmt.Fprintln(stderr, "  (run `mcpguard explain <pattern_id>` for pattern detail)")
	}

	// Audit log — metadata only, never the matched bytes. Failure here must
	// not block the tool call.
	ev := audit.EventFromResult(env.ToolName, sensitivity, mode, willRedact, result)
	if err := audit.Append(auditPath, ev); err != nil {
		fmt.Fprintf(stderr, "[mcpguard] audit log write failed: %v\n", err)
	}

	if willRedact {
		emitRedaction(stdout, env.ToolName, result)
	}
	return 0
}

// emitRedaction writes a PostToolUse hook response that replaces the
// original tool output with a short notice. updatedMCPToolOutput is used
// for MCP tool names (mcp__*), updatedToolOutput for everything else.
func emitRedaction(stdout io.Writer, toolName string, result scan.Result) {
	notice := fmt.Sprintf(
		"[mcpguard redacted: PostToolUse scanner detected possible prompt injection "+
			"(score=%.1f, %d pattern matches). Original tool output suppressed. "+
			"Run `mcpguard audit --last` for the metadata-only event record.]",
		result.Score, len(result.Matches))

	out := hookResponse{
		HookSpecificOutput: hookSpecificOutput{
			HookEventName: "PostToolUse",
		},
	}
	if strings.HasPrefix(toolName, "mcp__") {
		out.HookSpecificOutput.UpdatedMCPToolOutput = notice
	} else {
		out.HookSpecificOutput.UpdatedToolOutput = notice
	}
	_ = json.NewEncoder(stdout).Encode(out)
}

// labelFor renders the stderr prefix. Both modes exit 0; the label only
// tells the operator whether the original output was forwarded ("WARNING"
// = warn mode, payload reached the model) or redacted ("BLOCKED" = block
// mode, payload replaced via updatedMCPToolOutput).
func labelFor(mode string) string {
	if mode == "block" {
		return "BLOCKED: injection detected (redacted)"
	}
	return "WARNING: potential injection"
}

func printHookUsage(w io.Writer) {
	fmt.Fprint(w, `mcpguard hook — PostToolUse scanner for Claude Code MCP responses

Usage: mcpguard hook [--sensitivity low|medium|high] [--mode warn|block] [--show-excerpts]

Reads a Claude Code PostToolUse JSON envelope from stdin and scans every
string in tool_response (including object keys) for prompt-injection
patterns. On a hit:
  --mode warn   logs metadata (pattern_id, category, severity, offset, len,
                sha256 prefix) to stderr; original tool output reaches the
                model unchanged.
  --mode block  logs metadata to stderr AND emits a PostToolUse JSON
                response on stdout that replaces tool_response with a
                redaction notice via updatedMCPToolOutput.

Every non-pass verdict is appended to ~/.local/share/mcpguard/hook-audit.jsonl
as a metadata-only event (never the raw matched bytes). Query with:
    mcpguard audit --last
    mcpguard explain <pattern_id>

Flags:
  --sensitivity     low (threshold 2.0), medium (1.0), high (0.5). Default medium.
  --mode            warn (default) or block. Both exit 0.
  --show-excerpts   include raw match text in stderr (UNSAFE — Claude can
                    re-ingest it). Only for active debug sessions.

Claude Code's hook matcher is a regex; anchored alternation is what you
want — a bare "mcp__notion-*__*" glob does NOT match in regex semantics
(the "-*" means repeated hyphens):

  {
    "PostToolUse": [{
      "matcher": "^mcp__notion-(twinstake|partly)__.*$",
      "hooks": [{
        "type": "command",
        "command": "$HOME/.local/bin/mcpguard hook --sensitivity medium --mode block"
      }]
    }]
  }
`)
}
