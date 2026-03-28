# mcpguard

MCP stdio proxy that scans tool results for prompt injection and compresses payloads before they reach the LLM context window.

## Why

MCP servers return user-generated content — Discord messages, Telegram chats, Slack threads — that flows directly into the LLM's context. Any user in a monitored channel can inject prompts. The responses are also bloated with metadata (avatars, file references, access hashes) that the model doesn't need and that wastes context tokens.

mcpguard sits between Claude Code and any MCP server, intercepting JSON-RPC tool results. Two passes: compress (strip fields, cap content length, truncate arrays) then scan (pattern-based prompt injection detection). Warnings go to stderr; the (possibly compressed) payload continues to stdout.

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
  action: warn                      # warn (log to stderr) or block
```

See `configs/` for Discord and Telegram examples.

### Sensitivity levels

- **low** (threshold 2.0): only fires on multiple high-severity matches or critical patterns
- **medium** (threshold 1.0): fires on a single high-severity match or multiple medium matches
- **high** (threshold 0.5): fires on any single medium-severity match

Critical-severity patterns (e.g. "ignore previous instructions", `<|im_start|>system`) trigger an immediate block regardless of threshold.

## Detection patterns

48 patterns across 10 categories, ported from the [webguard-mcp](https://github.com/mark-liu/webguard-mcp) pattern engine and extended with MCP-specific vectors:

| Category | Patterns | Examples |
|----------|----------|----------|
| instruction-override | 7 | "ignore previous instructions", "new instructions:" |
| prompt-marker | 6 | `<\|im_start\|>system`, `[INST]`, `<<SYS>>` |
| authority-claim | 6 | "i am your developer", "admin override" |
| exfil-instruction | 5 | "send all data to", tracking pixels |
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
