use std::io::Write;

use crate::scan::patterns::{PatternType, pattern_by_id};

/// run_explain prints the definition of one pattern_id.
/// Returns exit code: 0 = success, 1 = error.
pub fn run_explain(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_explain_usage(stderr);
        return if args.is_empty() { 1 } else { 0 };
    }

    let id = &args[0];
    let p = match pattern_by_id(id) {
        Some(p) => p,
        None => {
            let _ = writeln!(stderr, "mcpguard explain: unknown pattern_id {:?}", id);
            return 1;
        }
    };

    let type_name = match p.pattern_type {
        PatternType::Literal => "literal",
        PatternType::Regex => "regex",
    };

    let _ = writeln!(
        stdout,
        "{}  {}  {}  {} match",
        p.id, p.category, p.severity, type_name
    );
    let _ = writeln!(stdout, "  pattern: {}", p.value);
    if let Some(r) = rationale_for(p.category) {
        let _ = writeln!(stdout, "  rationale: {}", r);
    }
    0
}

/// rationale_for returns a short human-readable description of what a pattern
/// category is trying to detect.
pub fn rationale_for(category: &str) -> Option<&'static str> {
    match category {
        "instruction-override" => {
            Some("phrases used to tell the model to discard its prior instructions")
        }
        "prompt-marker" => Some(
            "literal tokens used to forge system/instruction boundaries (e.g. <|im_start|>, [INST], <<sys>>)",
        ),
        "authority-claim" => Some(
            "false claims of operator authority (e.g. 'I am your developer', 'admin override', 'DAN mode')",
        ),
        "exfil-instruction" => {
            Some("phrases that direct the model to send data, fetch URLs, or embed tracking pixels")
        }
        "tool-manipulation" => {
            Some("phrases that direct the model to invoke specific MCP tools or function calls")
        }
        "context-hijacking" => {
            Some("high-attention markers used to elevate attacker text to instruction status")
        }
        "output-manipulation" => Some(
            "phrases that constrain the model's response shape ('respond only with', 'do not mention')",
        ),
        "unicode-obfuscation" => Some(
            "zero-width, bidi, PUA, or tag-range Unicode used to hide payloads from human readers",
        ),
        "encoded-injection" => {
            Some("code constructs that execute base64/hex-decoded payloads at runtime")
        }
        "delimiter-injection" => Some("fake END/BEGIN PROMPT markers or forged role JSON blocks"),
        _ => None,
    }
}

fn print_explain_usage(w: &mut dyn Write) {
    let _ = write!(
        w,
        r#"mcpguard explain — describe one detection pattern

Usage: mcpguard explain <pattern_id>

Prints the definition of a single mcpguard pattern by its id (e.g. io-001,
ei-002, uo-004). Use this when triaging an audit event — the audit log
records pattern_ids but never the live matched bytes; `mcpguard explain`
tells you what the pattern looks for so you can decide whether the hit
was real or a false positive without ever rendering attacker text.

Example:
  $ mcpguard audit --last
  ... match[0]: ei-002 (exfil-instruction/high) ...

  $ mcpguard explain ei-002
  ei-002  exfil-instruction  high  literal match
    pattern: exfiltrate
    rationale: phrases that direct the model to send data ...
"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_explain(&args, &mut stdout, &mut stderr);
        (
            code,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    #[test]
    fn test_explain_known_pattern() {
        let (code, stdout, _) = run(&["io-001"]);
        assert_eq!(code, 0);
        assert!(stdout.contains("io-001"));
        assert!(stdout.contains("instruction-override"));
        assert!(stdout.contains("rationale:"));
    }

    #[test]
    fn test_explain_unknown_pattern() {
        let (code, _, stderr) = run(&["xx-999"]);
        assert_eq!(code, 1);
        assert!(stderr.contains("unknown pattern_id"));
    }

    #[test]
    fn test_explain_no_args() {
        let (code, _, stderr) = run(&[]);
        assert_eq!(code, 1);
        assert!(stderr.contains("Usage:"));
    }

    #[test]
    fn test_explain_all_categories_have_rationale() {
        let categories = [
            "instruction-override",
            "prompt-marker",
            "authority-claim",
            "exfil-instruction",
            "tool-manipulation",
            "context-hijacking",
            "output-manipulation",
            "unicode-obfuscation",
            "encoded-injection",
            "delimiter-injection",
        ];
        for c in &categories {
            assert!(
                rationale_for(c).is_some(),
                "category {:?} has no rationale",
                c
            );
        }
    }
}
