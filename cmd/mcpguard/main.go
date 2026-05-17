// mcpguard is an MCP stdio proxy that scans tool results for prompt injection
// and compresses payloads before they enter the LLM context window.
//
// Usage:
//
//	mcpguard [flags] <command> [args...]
//
// Examples:
//
//	mcpguard --config discord.yaml /path/to/discord-mcp
//	mcpguard --config telegram.yaml uv --directory /path/to/telegram-mcp run main.py
//	mcpguard npx -y some-mcp-server
package main

import (
	"fmt"
	"os"

	"github.com/mark-liu/mcpguard/internal/config"
	"github.com/mark-liu/mcpguard/internal/proxy"
)

const version = "0.1.0"

func main() {
	args := os.Args[1:]

	// Subcommand dispatch happens before flag parsing so subcommand-specific
	// flags don't collide with the proxy mode's --config / --scan-only / etc.
	if len(args) > 0 {
		switch args[0] {
		case "hook":
			os.Exit(runHookIO(args[1:], os.Stdin, os.Stdout, os.Stderr))
		case "audit":
			os.Exit(runAudit(args[1:], os.Stdout, os.Stderr))
		case "explain":
			os.Exit(runExplain(args[1:], os.Stdout, os.Stderr))
		}
	}

	var (
		configPath   string
		scanOnly     bool
		compressOnly bool
		showStats    bool
	)

	// Parse flags manually to preserve child command args exactly.
	var childArgs []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config", "-c":
			if i+1 >= len(args) {
				fatal("--config requires a path argument")
			}
			i++
			configPath = args[i]
		case "--scan-only":
			scanOnly = true
		case "--compress-only":
			compressOnly = true
		case "--stats":
			showStats = true
		case "--version", "-v":
			fmt.Fprintf(os.Stdout, "mcpguard %s\n", version)
			os.Exit(0)
		case "--help", "-h":
			printUsage()
			os.Exit(0)
		default:
			// First non-flag arg starts the child command.
			childArgs = args[i:]
			i = len(args) // break
		}
	}

	if len(childArgs) == 0 {
		printUsage()
		os.Exit(1)
	}

	if scanOnly && compressOnly {
		fatal("--scan-only and --compress-only are mutually exclusive")
	}

	// Load config.
	var cfg config.Config
	if configPath != "" {
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			fatal("config: %v", err)
		}
	} else {
		cfg = config.DefaultConfig()
		scanOnly = true // no config = scan-only with defaults
	}

	p := proxy.New(cfg, scanOnly, compressOnly, showStats)
	code, err := p.Run(childArgs)
	if err != nil {
		fatal("%v", err)
	}

	os.Exit(code)
}

func printUsage() {
	fmt.Fprint(os.Stderr, `mcpguard — MCP stdio proxy for prompt injection scanning and payload compression

Usage:
  mcpguard [flags] <command> [args...]      proxy mode (stdio MCP wrapper)
  mcpguard hook [hook-flags]                PostToolUse hook for Claude Code
  mcpguard audit [filters]                  query the hook event log
  mcpguard explain <pattern_id>             describe one detection pattern

Flags (proxy mode):
  --config, -c <path>   YAML config file (optional, defaults to scan-only)
  --scan-only            Skip compression, only scan for injection
  --compress-only        Skip scanning, only compress
  --stats                Print compression stats to stderr on exit
  --version, -v          Print version
  --help, -h             Print this help

Examples:
  mcpguard --config discord.yaml /path/to/discord-mcp
  mcpguard --config telegram.yaml uv --directory /path/to/telegram-mcp run main.py
  mcpguard npx -y some-mcp-server
  mcpguard hook --sensitivity medium --mode warn   (see "mcpguard hook --help")
`)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "mcpguard: "+format+"\n", args...)
	os.Exit(1)
}
