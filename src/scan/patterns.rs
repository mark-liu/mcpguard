/// PatternType distinguishes literal (case-insensitive substring) from regex patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternType {
    Literal,
    Regex,
}

/// Severity indicates how dangerous a pattern match is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }

    // Severity::weight() lived here as a precomputed scoring helper, but the
    // engine's score() does an inline match on the string form of severity to
    // mirror Go's severityWeight() free function. Removed per Codex review;
    // re-add together with refactoring Match.severity from String to Severity
    // if you want enum-typed scoring.
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Pattern is a single detection rule.
///
/// Go's struct precomputed `Weight` as a cached f64, but the scoring engine
/// calls `severity.weight()` directly per match — the cache was never read.
/// Dropping the field keeps the struct minimal (per Codex review).
#[derive(Debug, Clone)]
pub struct Pattern {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub pattern_type: PatternType,
    /// For literal: the lowercased match string. For regex: the regex source.
    pub value: &'static str,
}

fn p(
    id: &'static str,
    category: &'static str,
    severity: Severity,
    pattern_type: PatternType,
    value: &'static str,
) -> Pattern {
    Pattern {
        id,
        category,
        severity,
        pattern_type,
        value,
    }
}

/// Returns the full set of detection patterns, ported from Go mcpguard patterns.go.
/// 55 patterns total.
pub fn all_patterns() -> Vec<Pattern> {
    use PatternType::{Literal, Regex};
    use Severity::{Critical, High, Medium};

    vec![
        // instruction-override (7)
        p(
            "io-001",
            "instruction-override",
            Critical,
            Literal,
            "ignore previous instructions",
        ),
        p(
            "io-002",
            "instruction-override",
            Critical,
            Literal,
            "ignore all previous",
        ),
        p(
            "io-003",
            "instruction-override",
            Critical,
            Literal,
            "disregard previous instructions",
        ),
        p(
            "io-004",
            "instruction-override",
            High,
            Literal,
            "forget your instructions",
        ),
        p(
            "io-005",
            "instruction-override",
            High,
            Literal,
            "from now on you will",
        ),
        p(
            "io-006",
            "instruction-override",
            High,
            Literal,
            "new instructions:",
        ),
        p(
            "io-007",
            "instruction-override",
            Critical,
            Regex,
            r"(?i)ignore[\t\n\f\r ]+(any|all|every)[\t\n\f\r ]+(prior|previous|earlier)[\t\n\f\r ]+(instructions?|prompts?|rules?)",
        ),
        // prompt-marker (6)
        p(
            "pm-001",
            "prompt-marker",
            Critical,
            Literal,
            "<|im_start|>system",
        ),
        p("pm-002", "prompt-marker", High, Literal, "<|im_start|>"),
        p("pm-003", "prompt-marker", High, Literal, "[system]:"),
        p("pm-004", "prompt-marker", High, Literal, "[inst]"),
        p("pm-005", "prompt-marker", Critical, Literal, "<<sys>>"),
        p("pm-006", "prompt-marker", High, Regex, r"(?i)\[/?INST\]"),
        // authority-claim (6)
        p(
            "ac-001",
            "authority-claim",
            Critical,
            Literal,
            "i am your developer",
        ),
        p(
            "ac-002",
            "authority-claim",
            High,
            Literal,
            "i am the system administrator",
        ),
        p("ac-003", "authority-claim", High, Literal, "dan mode"),
        p("ac-004", "authority-claim", High, Literal, "admin override"),
        p(
            "ac-005",
            "authority-claim",
            Medium,
            Literal,
            "you are now in",
        ),
        p(
            "ac-006",
            "authority-claim",
            Critical,
            Regex,
            r"(?i)(I[\t\n\f\r ]+am|this[\t\n\f\r ]+is)[\t\n\f\r ]+(your|the)[\t\n\f\r ]+(developer|creator|admin|administrator|owner)",
        ),
        // exfil-instruction (5)
        p(
            "ei-001",
            "exfil-instruction",
            Critical,
            Literal,
            "send all data to",
        ),
        p("ei-002", "exfil-instruction", High, Literal, "exfiltrate"),
        p(
            "ei-003",
            "exfil-instruction",
            Critical,
            Regex,
            r"(?i)send[\t\n\f\r ]+(all|the|this|your)[\t\n\f\r ]+(the[\t\n\f\r ]+)?(data|information|context|conversation)[\t\n\f\r ]+(and[\t\n\f\r ]+[0-9A-Za-z_]+[\t\n\f\r ]+)?to[\t\n\f\r ]+(https?://|//|[a-z0-9.-]+\.[a-z]{2,})",
        ),
        p(
            "ei-004",
            "exfil-instruction",
            High,
            Regex,
            r"(?i)(fetch|load|visit|open|navigate)[\t\n\f\r ]+(https?://|//)[^\t\n\f\r ]+",
        ),
        p(
            "ei-005",
            "exfil-instruction",
            High,
            Regex,
            r"!\[(track|pixel|1x1|beacon|exfil)[0-9A-Za-z_]*\]\(https?://[^\)]+\)",
        ),
        // output-manipulation (4)
        p(
            "om-001",
            "output-manipulation",
            Medium,
            Literal,
            "respond only with",
        ),
        p(
            "om-002",
            "output-manipulation",
            Medium,
            Literal,
            "do not mention",
        ),
        p(
            "om-003",
            "output-manipulation",
            High,
            Regex,
            r"(?i)never[\t\n\f\r ]+(mention|reveal|disclose|discuss)[\t\n\f\r ]+(that|this|the|your)",
        ),
        p(
            "om-004",
            "output-manipulation",
            Medium,
            Regex,
            r"(?i)(always|must|should)[\t\n\f\r ]+respond[\t\n\f\r ]+(with|by|using)[\t\n\f\r ]+",
        ),
        // tool-manipulation (5)
        p(
            "tm-001",
            "tool-manipulation",
            High,
            Literal,
            "call the tool",
        ),
        p(
            "tm-002",
            "tool-manipulation",
            High,
            Literal,
            "use the function",
        ),
        p(
            "tm-003",
            "tool-manipulation",
            High,
            Literal,
            "execute command",
        ),
        p(
            "tm-004",
            "tool-manipulation",
            High,
            Regex,
            r##"(?i)(invoke|run|call|use)[\t\n\f\r ]+(the[\t\n\f\r ]+)?(tool|function|mcp)[\t\n\f\r ]+["'`]"##,
        ),
        p(
            "tm-005",
            "tool-manipulation",
            Critical,
            Regex,
            r"(?i)(call|invoke|run)[\t\n\f\r ]+mcp_[0-9A-Za-z_]+",
        ),
        // context-hijacking (5)
        p("ch-001", "context-hijacking", Medium, Literal, "important:"),
        p("ch-002", "context-hijacking", Medium, Literal, "critical:"),
        p("ch-003", "context-hijacking", Medium, Literal, "override:"),
        p("ch-004", "context-hijacking", High, Literal, "<system>"),
        p("ch-005", "context-hijacking", High, Literal, "</system>"),
        // unicode-obfuscation (4)
        p(
            "uo-001",
            "unicode-obfuscation",
            High,
            Regex,
            r"[\x{200B}\x{200C}\x{200D}\x{FEFF}]{3,}",
        ),
        p(
            "uo-002",
            "unicode-obfuscation",
            Medium,
            Regex,
            r"[\x{202A}-\x{202E}\x{2066}-\x{2069}]{2,}",
        ),
        p(
            "uo-003",
            "unicode-obfuscation",
            Medium,
            Regex,
            r"[\x{E000}-\x{F8FF}]{2,}",
        ),
        p(
            "uo-004",
            "unicode-obfuscation",
            High,
            Regex,
            r"[\x{E0001}-\x{E007F}]",
        ),
        // delimiter-injection (3)
        p(
            "di-001",
            "delimiter-injection",
            High,
            Literal,
            "---end system prompt---",
        ),
        p(
            "di-002",
            "delimiter-injection",
            High,
            Regex,
            r"(?i)-{3,}[\t\n\f\r ]*(END|BEGIN)[\t\n\f\r ]+(SYSTEM|USER|ASSISTANT)[\t\n\f\r ]+(PROMPT|MESSAGE|INSTRUCTIONS?)[\t\n\f\r ]*-{3,}",
        ),
        p(
            "di-003",
            "delimiter-injection",
            High,
            Regex,
            r#"\{[\t\n\f\r ]*"role"[\t\n\f\r ]*:[\t\n\f\r ]*"(system|assistant)"[\t\n\f\r ]*"#,
        ),
        // encoded-injection (3)
        p(
            "enc-001",
            "encoded-injection",
            High,
            Regex,
            r"(?i)eval[\t\n\f\r ]*\([\t\n\f\r ]*atob[\t\n\f\r ]*\(",
        ),
        p(
            "enc-002",
            "encoded-injection",
            Medium,
            Regex,
            r"(?i)base64[_\-]?decode",
        ),
        p(
            "enc-003",
            "encoded-injection",
            Medium,
            Regex,
            r"(?i)String\.fromCharCode[\t\n\f\r ]*\(",
        ),
        // html-injection (5)
        p(
            "hi-001",
            "html-injection",
            Medium,
            Regex,
            r#"(?i)[\t\n\f\r ]on(load|error|click|focus|mouseover|submit|toggle|animationend)[\t\n\f\r ]*=[\t\n\f\r ]*["']"#,
        ),
        p(
            "hi-002",
            "html-injection",
            Medium,
            Regex,
            r"(?i)data:text/html",
        ),
        p(
            "hi-003",
            "html-injection",
            Medium,
            Regex,
            r"(?i)data:application/(x-)?(java)?script",
        ),
        p(
            "hi-004",
            "html-injection",
            High,
            Regex,
            r#"(?i)expression[\t\n\f\r ]*\([\t\n\f\r ]*['"a-z(]"#,
        ),
        p(
            "hi-005",
            "html-injection",
            High,
            Regex,
            r"<!--[\t\n\f\r ]*(?i)(ignore|disregard|forget)[\t\n\f\r ]+(any|all|previous|your)",
        ),
        // svg-injection (2)
        p(
            "svg-001",
            "svg-injection",
            Medium,
            Regex,
            r"(?i)<svg[^>]*[\t\n\f\r ]on[0-9A-Za-z_]+[\t\n\f\r ]*=",
        ),
        p(
            "svg-002",
            "svg-injection",
            Medium,
            Regex,
            r"(?i)<foreignObject[\t\n\f\r >]",
        ),
    ]
}

/// Returns the pattern with the given ID, if it exists.
pub fn pattern_by_id(id: &str) -> Option<Pattern> {
    all_patterns().into_iter().find(|p| p.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_count_is_55() {
        assert_eq!(all_patterns().len(), 55);
    }

    #[test]
    fn test_all_pattern_ids_unique() {
        let patterns = all_patterns();
        let mut ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for p in &patterns {
            assert!(ids.insert(p.id), "duplicate pattern id: {}", p.id);
        }
    }

    #[test]
    fn test_pattern_by_id_known() {
        let p = pattern_by_id("io-001").unwrap();
        assert_eq!(p.id, "io-001");
        assert_eq!(p.category, "instruction-override");
        assert_eq!(p.severity, Severity::Critical);
    }

    #[test]
    fn test_pattern_by_id_unknown() {
        assert!(pattern_by_id("xx-999").is_none());
    }
}
