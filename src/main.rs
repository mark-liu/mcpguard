mod audit;
mod cli;
mod compress;
mod config;
mod proxy;
mod scan;

use std::process;

const VERSION: &str = "0.2.0";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Subcommand dispatch before flag parsing — subcommand-specific flags
    // must not collide with proxy mode's --config / --scan-only / etc.
    if let Some(sub) = args.first() {
        match sub.as_str() {
            "hook" => {
                let code = cli::hook::run_hook(
                    &args[1..],
                    &mut std::io::stdin(),
                    &mut std::io::stdout(),
                    &mut std::io::stderr(),
                );
                process::exit(code);
            }
            "audit" => {
                let code = cli::audit::run_audit(
                    &args[1..],
                    &mut std::io::stdout(),
                    &mut std::io::stderr(),
                );
                process::exit(code);
            }
            "explain" => {
                let code = cli::explain::run_explain(
                    &args[1..],
                    &mut std::io::stdout(),
                    &mut std::io::stderr(),
                );
                process::exit(code);
            }
            _ => {}
        }
    }

    // Proxy mode: manual flag parse to preserve child argv exactly.
    let mut config_path: Option<String> = None;
    let mut scan_only = false;
    let mut compress_only = false;
    let mut show_stats = false;
    let mut child_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                if i >= args.len() {
                    fatal("--config requires a path argument");
                }
                config_path = Some(args[i].clone());
            }
            "--scan-only" => scan_only = true,
            "--compress-only" => compress_only = true,
            "--stats" => show_stats = true,
            "--version" | "-v" => {
                println!("mcpguard {VERSION}");
                process::exit(0);
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => {
                // First non-flag arg begins the child command.
                child_args = args[i..].to_vec();
                break;
            }
        }
        i += 1;
    }

    if child_args.is_empty() {
        print_usage();
        process::exit(1);
    }

    if scan_only && compress_only {
        fatal("--scan-only and --compress-only are mutually exclusive");
    }

    // Load config.
    let cfg = if let Some(ref path) = config_path {
        match config::load(path) {
            Ok(c) => c,
            Err(e) => fatal_ret(&format!("config: {e}")),
        }
    } else {
        // No config = scan-only with defaults.
        scan_only = true;
        config::default_config()
    };

    let p = proxy::Proxy::new(cfg, scan_only, compress_only, show_stats);
    let (code, err) = p.run(&child_args);
    if let Some(e) = err {
        eprintln!("mcpguard: {e}");
    }
    process::exit(code);
}

fn print_usage() {
    eprintln!(
        r#"mcpguard — MCP stdio proxy for prompt injection scanning and payload compression

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
  mcpguard hook --sensitivity medium --mode warn   (see "mcpguard hook --help")"#
    );
}

fn fatal(msg: &str) -> ! {
    eprintln!("mcpguard: {msg}");
    process::exit(1);
}

fn fatal_ret(msg: &str) -> ! {
    fatal(msg)
}
