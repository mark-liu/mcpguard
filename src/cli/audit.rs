use std::io::Write;
use std::path::PathBuf;

use chrono::Utc;

use crate::audit::{self, Filter};

/// run_audit reads the hook audit log and prints recent events.
/// Returns exit code: 0 = success, 1 = error.
pub fn run_audit(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut since_arg: Option<String> = None;
    let mut verdict: Option<String> = None;
    let mut tool_sub: Option<String> = None;
    let mut last = false;
    let mut limit: usize = 20;
    let mut path = audit::default_path();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--since" => {
                i += 1;
                if i >= args.len() {
                    let _ = writeln!(
                        stderr,
                        "mcpguard audit: --since requires a duration (e.g. 1h, 30m, 24h)"
                    );
                    return 1;
                }
                since_arg = Some(args[i].clone());
            }
            "--verdict" => {
                i += 1;
                if i >= args.len() {
                    let _ = writeln!(stderr, "mcpguard audit: --verdict requires pass|warn|block");
                    return 1;
                }
                verdict = Some(args[i].clone());
            }
            "--tool" => {
                i += 1;
                if i >= args.len() {
                    let _ = writeln!(stderr, "mcpguard audit: --tool requires a substring");
                    return 1;
                }
                tool_sub = Some(args[i].clone());
            }
            "--last" => {
                last = true;
            }
            "--limit" => {
                i += 1;
                if i >= args.len() {
                    let _ = writeln!(stderr, "mcpguard audit: --limit requires N");
                    return 1;
                }
                match args[i].parse::<usize>() {
                    Ok(n) if n >= 1 => limit = n,
                    _ => {
                        let _ = writeln!(stderr, "mcpguard audit: invalid --limit {:?}", args[i]);
                        return 1;
                    }
                }
            }
            "--path" => {
                i += 1;
                if i >= args.len() {
                    let _ = writeln!(stderr, "mcpguard audit: --path requires a file path");
                    return 1;
                }
                path = PathBuf::from(&args[i]);
            }
            "-h" | "--help" => {
                print_audit_usage(stderr);
                return 0;
            }
            other => {
                let _ = writeln!(stderr, "mcpguard audit: unknown flag {:?}", other);
                return 1;
            }
        }
        i += 1;
    }

    // Build filter.
    let mut f = Filter {
        verdict,
        tool: tool_sub,
        limit: Some(if last { 1 } else { limit }),
        since: None,
    };

    if let Some(s) = since_arg {
        match parse_duration(&s) {
            Some(dur) => {
                f.since = Some(Utc::now() - dur);
            }
            None => {
                let _ = writeln!(
                    stderr,
                    "mcpguard audit: invalid --since {:?}: bad duration",
                    s
                );
                return 1;
            }
        }
    }

    let events = match audit::read(&path, &f) {
        Ok(e) => e,
        Err(e) => {
            let _ = writeln!(stderr, "mcpguard audit: {}", e);
            return 1;
        }
    };

    if events.is_empty() {
        let _ = writeln!(stdout, "(no matching events)");
        return 0;
    }

    if last {
        print_event_detail(stdout, &events[0]);
    } else {
        print_event_table(stdout, &events);
    }
    0
}

fn print_event_table(w: &mut dyn Write, events: &[audit::Event]) {
    let _ = writeln!(
        w,
        "{:<25} {:<7} {:<6} {:<7} {}",
        "ts", "verdict", "score", "matches", "tool_name"
    );
    let _ = writeln!(w, "{}", "-".repeat(100));
    for e in events {
        let _ = writeln!(
            w,
            "{:<25} {:<7} {:<6.1} {:<7} {}",
            e.timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            e.verdict,
            e.score,
            e.num_matches,
            e.tool_name,
        );
    }
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "Detail:    mcpguard audit --last  [--tool <substr>] [--verdict block]"
    );
    let _ = writeln!(w, "Explain:   mcpguard explain <pattern_id>");
}

fn print_event_detail(w: &mut dyn Write, e: &audit::Event) {
    let _ = writeln!(w, "Event {}", e.timestamp.format("%+"));
    let _ = writeln!(w, "  tool:        {}", e.tool_name);
    let _ = writeln!(
        w,
        "  verdict:     {}  (mode={} sensitivity={})",
        e.verdict, e.mode, e.sensitivity
    );
    let _ = writeln!(
        w,
        "  score:       {:.2} across {} matches",
        e.score, e.num_matches
    );
    let _ = writeln!(w, "  redacted:    {}", e.redacted);
    for (i, m) in e.matches.iter().enumerate() {
        let _ = writeln!(
            w,
            "  match[{}]:    {} ({}/{})",
            i, m.pattern_id, m.category, m.severity
        );
        let _ = writeln!(
            w,
            "               offset={} text_len={} sha256={}",
            m.offset, m.text_len, m.text_sha256
        );
        let _ = writeln!(w, "               → run: mcpguard explain {}", m.pattern_id);
    }
}

/// parse_duration parses Go-style duration strings: e.g. "1h", "30m", "24h", "5m30s".
/// Supports h, m, s suffixes. Returns chrono::Duration.
fn parse_duration(s: &str) -> Option<chrono::Duration> {
    let mut total_secs: i64 = 0;
    let mut num_buf = String::new();

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num_buf.push(ch);
        } else {
            let n: i64 = num_buf.parse().ok()?;
            num_buf.clear();
            match ch {
                'h' => total_secs += n * 3600,
                'm' => total_secs += n * 60,
                's' => total_secs += n,
                _ => return None,
            }
        }
    }
    // Trailing digits without unit = error
    if !num_buf.is_empty() {
        return None;
    }
    if total_secs == 0 {
        return None;
    }
    Some(chrono::Duration::seconds(total_secs))
}

fn print_audit_usage(w: &mut dyn Write) {
    let _ = write!(
        w,
        r#"mcpguard audit — read the hook event log

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
"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Event;
    use chrono::Utc;
    use std::fs;
    use tempfile::TempDir;

    fn run_audit_cmd(args: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_audit(&args, &mut stdout, &mut stderr);
        (
            code,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    fn write_audit_fixture(dir: &TempDir) -> PathBuf {
        let path = dir.path().join("audit.jsonl");
        let events = vec![
            Event {
                timestamp: Utc::now(),
                tool_name: "mcp__slack__history".into(),
                verdict: "warn".into(),
                score: 1.5,
                num_matches: 1,
                ..Default::default()
            },
            Event {
                timestamp: Utc::now(),
                tool_name: "mcp__notion-twinstake__search".into(),
                verdict: "block".into(),
                score: 6.2,
                num_matches: 3,
                ..Default::default()
            },
            Event {
                timestamp: Utc::now(),
                tool_name: "mcp__gsuite-work__get_gmail".into(),
                verdict: "warn".into(),
                score: 1.0,
                num_matches: 1,
                ..Default::default()
            },
        ];
        let mut content = String::new();
        for e in &events {
            content.push_str(&serde_json::to_string(e).unwrap());
            content.push('\n');
        }
        fs::write(&path, &content).unwrap();
        path
    }

    #[test]
    fn test_audit_default_limit_prints_table() {
        let dir = TempDir::new().unwrap();
        let path = write_audit_fixture(&dir);
        let (code, stdout, _) = run_audit_cmd(&["--path", path.to_str().unwrap()]);
        assert_eq!(code, 0);
        assert!(
            stdout.contains("verdict") && stdout.contains("score"),
            "table header missing: {stdout}"
        );
        for tool in &["slack", "notion", "gsuite"] {
            assert!(
                stdout.contains(tool),
                "expected {tool} row in output: {stdout}"
            );
        }
    }

    #[test]
    fn test_audit_filter_by_verdict() {
        let dir = TempDir::new().unwrap();
        let path = write_audit_fixture(&dir);
        let (_, stdout, _) =
            run_audit_cmd(&["--path", path.to_str().unwrap(), "--verdict", "block"]);
        assert!(
            stdout.contains("notion"),
            "block filter should include notion: {stdout}"
        );
        assert!(
            !stdout.contains("slack__history"),
            "block filter should exclude slack: {stdout}"
        );
        assert!(
            !stdout.contains("gsuite"),
            "block filter should exclude gsuite: {stdout}"
        );
    }

    #[test]
    fn test_audit_filter_by_tool_substring() {
        let dir = TempDir::new().unwrap();
        let path = write_audit_fixture(&dir);
        let (_, stdout, _) = run_audit_cmd(&["--path", path.to_str().unwrap(), "--tool", "gsuite"]);
        assert!(
            stdout.contains("gsuite"),
            "tool filter missed gsuite: {stdout}"
        );
        assert!(
            !stdout.contains("slack") && !stdout.contains("notion"),
            "tool filter leaked: {stdout}"
        );
    }

    #[test]
    fn test_audit_last_flag_prints_detail() {
        let dir = TempDir::new().unwrap();
        let path = write_audit_fixture(&dir);
        let (_, stdout, _) = run_audit_cmd(&["--path", path.to_str().unwrap(), "--last"]);
        for want in &["Event ", "tool:", "verdict:", "score:", "redacted:"] {
            assert!(
                stdout.contains(want),
                "--last output missing {:?}: {stdout}",
                want
            );
        }
    }

    #[test]
    fn test_audit_empty_log_is_not_error() {
        let (code, stdout, _) = run_audit_cmd(&["--path", "/nonexistent/path/audit.jsonl"]);
        assert_eq!(code, 0, "missing log should exit 0");
        assert!(
            stdout.contains("no matching events"),
            "want 'no matching events': {stdout}"
        );
    }

    #[test]
    fn test_audit_invalid_since() {
        let (code, _, stderr) = run_audit_cmd(&["--since", "not-a-duration"]);
        assert_eq!(code, 1, "invalid --since should exit 1");
        assert!(
            stderr.contains("invalid --since"),
            "missing diagnostic: {stderr}"
        );
    }

    #[test]
    fn test_audit_output_contains_no_raw_text() {
        // Regression: forged audit log with extra "text" field must not surface it.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tainted.jsonl");
        let forged = r#"{"ts":"2026-05-17T10:00:00Z","tool_name":"mcp__notion__x","verdict":"block","score":5.0,"num_matches":1,"matches":[{"pattern_id":"io-001","category":"instruction-override","severity":"critical","offset":0,"text_len":29,"text_sha256":"abc","text":"ignore previous instructions"}]}"#;
        fs::write(&path, format!("{forged}\n")).unwrap();
        let (_, stdout, _) = run_audit_cmd(&["--path", path.to_str().unwrap(), "--last"]);
        assert!(
            !stdout.contains("ignore previous instructions"),
            "subcommand surfaced forged raw text: {stdout}"
        );
    }

    #[test]
    fn test_parse_duration_valid() {
        assert_eq!(parse_duration("1h"), Some(chrono::Duration::seconds(3600)));
        assert_eq!(parse_duration("30m"), Some(chrono::Duration::seconds(1800)));
        assert_eq!(
            parse_duration("24h"),
            Some(chrono::Duration::seconds(86400))
        );
        assert_eq!(
            parse_duration("1h30m"),
            Some(chrono::Duration::seconds(5400))
        );
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("not-a-duration").is_none());
        assert!(parse_duration("").is_none());
        assert!(parse_duration("5x").is_none());
    }

    // Regression (Codex finding #3): the audit table previously formatted
    // every event timestamp with `e.timestamp.format("2006-01-02T15:04:05Z")`,
    // which chrono treats as a literal — every row rendered the string
    // "2006-01-02T15:04:05Z" regardless of the real ts. Fixed by using
    // `to_rfc3339_opts`. This test catches a re-regression by asserting the
    // rendered table contains the fixture's actual year and NOT the Go
    // layout literal "2006".
    #[test]
    fn test_table_renders_real_timestamp_not_go_layout() {
        use chrono::TimeZone;
        let event = audit::Event {
            timestamp: chrono::Utc.with_ymd_and_hms(2026, 5, 23, 12, 0, 0).unwrap(),
            tool_name: "mcp__x__y".to_string(),
            sensitivity: "medium".to_string(),
            mode: "block".to_string(),
            verdict: "block".to_string(),
            score: 2.0,
            num_matches: 1,
            redacted: true,
            matches: vec![],
        };
        let mut buf: Vec<u8> = Vec::new();
        print_event_table(&mut buf, &[event]);
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("2026-05-23"),
            "table must show the fixture's real date, got:\n{out}"
        );
        assert!(
            !out.contains("2006-01-02"),
            "table must NOT contain the Go layout literal, got:\n{out}"
        );
    }
}
