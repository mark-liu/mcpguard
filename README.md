# mcpguard

MCP stdio proxy that scans tool results for prompt injection and compresses payloads before they reach the LLM context window.

## Why

MCP servers return user-generated content — Discord messages, Telegram chats, Slack threads — that flows directly into the LLM's context. Any user in a monitored channel can inject prompts. The responses are also bloated with metadata (avatars, file references, access hashes) that the model doesn't need and that wastes context tokens.

mcpguard sits between Claude Code and any MCP server, intercepting JSON-RPC tool results. Two passes: compress (strip fields, cap content length, truncate arrays) then scan (pattern-based prompt injection detection). A detected injection is redacted (or blocked, per config) before it reaches stdout; every scan is also logged metadata-only to the audit log.

## Install

### Homebrew

```bash
brew install mark-liu/tap/mcpguard
```

### Go

```bash
go install github.com/mark-liu/mcpguard/cmd/mcpguard@latest
```

### From source

```bash
git clone https://github.com/mark-liu/mcpguard.git
cd mcpguard
go build -o mcpguard ./cmd/mcpguard/
```

## Usage

```bash
# Scan-only (default when no config provided)
mcpguard npx -y some-mcp-server

# With compression + scanning
mcpguard --config configs/discord.yaml /path/to/discord-mcp

# Telegram with stats on exit
mcpguard --config configs/telegram.yaml --stats uv --directory /path/to/telegram-mcp run main.py

# Name the server in the audit log (default: the command's basename)
mcpguard --name discord --config configs/discord.yaml /path/to/discord-mcp

# Compression only (no injection scanning)
mcpguard --config configs/discord.yaml --compress-only /path/to/discord-mcp
```

### Claude Code integration

```bash
claude mcp add discord -s user -- mcpguard --config /path/to/discord.yaml /path/to/discord-mcp
```

Or add to `~/.claude.json` manually:

```json
{
  "mcpServers": {
    "discord": {
      "command": "mcpguard",
      "args": ["--config", "/path/to/discord.yaml", "/path/to/discord-mcp"]
    }
  }
}
```

### PostToolUse hook

`mcpguard hook` scans every tool result Claude Code receives, without wrapping
the server. Register it in `settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "^mcp__.*$",
        "hooks": [{ "type": "command", "command": "mcpguard hook --sensitivity medium --mode redact", "timeout": 5 }]
      }
    ]
  }
}
```

| `--mode` | On a hit |
|---|---|
| `warn` (default) | stderr warning, output passes through |
| `block` | whole output replaced with a notice |
| `redact` | like `block`, but when the only problem in an MCP result is a URL (ei-004/005/006), just those URLs become `[mcpguard: URL blocked (<ids>)]` and the rest passes |

`redact` fails closed: a critical match, or any match left when the rewritten
output is rescanned, falls back to the whole-output notice.

### Audit log and stats

Every scan, pass included, from both the hook and the proxy appends one
metadata-only row to `~/.local/share/mcpguard/hook-audit.jsonl`: server, tool,
source (`hook`/`proxy`), bytes scanned, verdict, `scan_ms` and the rule ids that
fired. Payload text is never written. The log rolls to `hook-audit.jsonl.1` at
8 MiB.

```bash
mcpguard audit --stats --since 24h   # per-server calls, blocks, block %, scan time
mcpguard audit --last                # full detail of the newest event
```

Rows written by older versions are detections only, so a rate over a window that
includes them is skewed; scope with `--since`.

## Config

YAML config with two sections: `compress` and `scan`.

```yaml
compress:
  max_content_length: 500          # truncate content fields beyond this length
  strip_fields:                     # recursively remove these fields from JSON objects
    - avatar
    - banner
    - accent_color
  content_fields:                   # which string fields to apply max_content_length to
    - content
    - text
    - body
    - message
  max_messages: 50                  # cap message arrays to N most recent
  max_array_items: 100              # generic array cap

scan:
  sensitivity: medium               # low (threshold=2.0), medium (1.0), high (0.5)
  action: warn                      # warn, or block (JSON-RPC error); see "Proxy enforcement"
  enforce: true                     # proxy only; false = log and warn, payload untouched
  allow:                            # drop known-benign matches before scoring
    hosts: []                       # host suffixes that are not exfil destinations
    patterns: []                    # pattern ids to disable, e.g. ch-002
```

See `configs/` for Discord and Telegram examples, and `configs/hook.example.yaml`
for the PostToolUse hook.

### Proxy enforcement

The proxy acts on a block verdict the way the hook does, so the two layers are
real defence in depth rather than a warning that only the child's stderr sees.
With `scan.enforce: true` (the default):

- `action: warn` redacts like `hook --mode redact`: a URL-only hit blanks just
  those URLs, anything else replaces the whole result with a notice
- `action: block` answers with a JSON-RPC error instead of the result
- `enforce: false` restores log-and-warn only; detections still reach the audit log

Only `tools/call` results are altered. Responses to other methods (`tools/list`,
`initialize`) are scanned and logged on a hit but never changed, because tool
descriptions routinely contain words like "IMPORTANT:" and blocking them would
make the server unusable. A response whose request id was never seen is treated
as a tool call (fail closed). The proxy scans each result as one aggregate, the
same as the hook. JSON-RPC `error` responses (message and data) are scanned the
same way, batch arrays are handled element by element, and a line that looks like
JSON but cannot be parsed is withheld rather than forwarded unscanned.

### Sensitivity levels

Scoring: each match contributes its severity weight (critical 2.0, high 1.5,
medium 1.0, low 0.5), plus a **+0.25 bonus per additional category** present.
A payload blocks when the total reaches the threshold. An identical URL-bearing
match repeated across the payload (one footer in N search results) counts once;
literal matches still count per occurrence, except `ch-002` ("critical:"), a
severity label that counts once per result item however often other items repeat it.

- **low** (threshold 2.0): needs a critical match, two highs, or a broader mix
- **medium** (threshold 1.0): **any single match of medium severity or above blocks on its own**
- **high** (threshold 0.5): any single match of any severity blocks

Be deliberate about `medium`: because the medium weight (1.0) equals the medium
threshold (1.0), **53 of the 57 patterns block alone** at that setting. That is
the intended posture for a fail-closed scanner, but it means a single
unremarkable literal in a large payload suppresses the whole tool result, so
expect to use `scan.allow` to tune out benign sources rather than reaching for a
lower sensitivity.

Critical-severity patterns (e.g. "ignore previous instructions", `<|im_start|>system`) trigger an immediate block regardless of threshold.

### Suppressing false positives (`scan.allow`)

Every detector is content-shaped: none of them know who authored the text or
where a URL points. First-party vendor boilerplate -- a monitoring alert linking
to your own dashboard -- is byte-identical in shape to an exfil instruction.
Without an escape hatch the only knobs are the global threshold and
warn-vs-block, so operators end up routing around the scanner entirely, which is
strictly worse for coverage than tuning it.

```yaml
scan:
  allow:
    hosts:
      - grafana.net      # also allows example.grafana.net, NOT grafana.net.evil.tld
    patterns:
      - ch-002           # the bare literal "critical:" -- a severity label in ops corpora
```

Semantics, deliberately narrow:

- Suppression happens **after matching, before scoring**, so an allowed match
  contributes nothing to the score, the category bonus, or the critical
  short-circuit. It is as if that detector had not fired.
- It never suppresses anything else in the payload. A real injection sitting
  beside an allowed match still blocks.
- `hosts` matches the URL's **real host**: userinfo before `@` is discarded and
  ports are stripped, so `https://grafana.net@evil.tld/x` is *not* allowed.
  Suffix matching is label-aware. A URL whose host cannot be parsed is never
  allowed (fail closed).
- **Every** URL in the matched span must be allowed, so an allowed URL nested in
  a query (`//evil.tld/c?next=https://grafana.net/x`) does not vouch for the
  URL around it. Hosts carrying `\`, `%` or non-ASCII are never allowed.
- `patterns` entries are validated against the pattern table at load time, so a
  typo fails loudly instead of silently disabling nothing.

## Detection patterns

57 patterns across 12 categories, ported from the [webguard-mcp](https://github.com/mark-liu/webguard-mcp) pattern engine and extended with MCP-specific vectors:

| Category | Patterns | Examples |
|----------|----------|----------|
| instruction-override | 7 | "ignore previous instructions", "new instructions:" |
| prompt-marker | 6 | `<\|im_start\|>system`, `[INST]`, `<<SYS>>` |
| authority-claim | 6 | "i am your developer", "admin override" |
| exfil-instruction | 7 | "send all data to", tracking pixels, `fetch <url>?d={secret}` (a plain "Visit <url>" is Low) |
| tool-manipulation | 5 | "call mcp_slack", "use the function" |
| context-hijacking | 5 | "IMPORTANT:", `<system>`, "OVERRIDE:" |
| output-manipulation | 4 | "respond only with", "do not mention" |
| unicode-obfuscation | 4 | zero-width chars, bidi overrides, tag chars |
| delimiter-injection | 3 | "---END SYSTEM PROMPT---", fake role JSON |
| encoded-injection | 3 | `eval(atob(`, `base64_decode` |

## How it works

1. mcpguard spawns the wrapped MCP server as a child process
2. stdin from Claude Code passes through to the child unchanged
3. Child stdout is intercepted line-by-line (JSON-RPC newline-delimited)
4. For tool result responses (`"result"` key present):
   - **Compress**: strip fields, cap content length, truncate arrays
   - **Scan**: extract all string values, run pattern matching, score and verdict
5. Warnings/blocks are logged to stderr
6. The (compressed) message is forwarded to Claude Code on stdout
7. Child stderr passes through to parent stderr

## Related

- [webguard-mcp](https://github.com/mark-liu/webguard-mcp) — web fetch scanning (same pattern engine concept, different input surface)
- [snap](https://github.com/mark-liu/snap) — MCP stdio compression proxy for Playwright (same proxy architecture, different purpose)

## License

MIT
