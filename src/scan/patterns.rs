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

    /// Returns the scoring weight for this severity level.
    pub fn weight(&self) -> f64 {
        match self {
            Severity::Critical => 2.0,
            Severity::High => 1.5,
            Severity::Medium => 1.0,
            Severity::Low => 0.5,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Pattern is a single detection rule.
#[derive(Debug, Clone)]
pub struct Pattern {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub pattern_type: PatternType,
    /// For literal: the lowercased match string. For regex: the regex source.
    pub value: &'static str,
    pub weight: f64,
}

fn p(
    id: &'static str,
    category: &'static str,
    severity: Severity,
    pattern_type: PatternType,
    value: &'static str,
) -> Pattern {
    let weight = severity.weight();
    Pattern {
        id,
        category,
        severity,
        pattern_type,
        value,
        weight,
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
            r"(?i)ignore\s+(any|all|every)\s+(prior|previous|earlier)\s+(instructions?|prompts?|rules?)",
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
            r"(?i)(I\s+am|this\s+is)\s+(your|the)\s+(developer|creator|admin|administrator|owner)",
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
            r"(?i)send\s+(all|the|this|your)\s+(the\s+)?(data|information|context|conversation)\s+(and\s+\w+\s+)?to\s+(https?://|//|[a-z0-9.-]+\.[a-z]{2,})",
        ),
        p(
            "ei-004",
            "exfil-instruction",
            High,
            Regex,
            r"(?i)(fetch|load|visit|open|navigate)\s+(https?://|//)[^\s]+",
        ),
        p(
            "ei-005",
            "exfil-instruction",
            High,
            Regex,
            r"!\[(track|pixel|1x1|beacon|exfil)\w*\]\(https?://[^\)]+\)",
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
            r"(?i)never\s+(mention|reveal|disclose|discuss)\s+(that|this|the|your)",
        ),
        p(
            "om-004",
            "output-manipulation",
            Medium,
            Regex,
            r"(?i)(always|must|should)\s+respond\s+(with|by|using)\s+",
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
            "(?i)(invoke|run|call|use)\\s+(the\\s+)?(tool|function|mcp)\\s+[\"'`]",
        ),
        p(
            "tm-005",
            "tool-manipulation",
            Critical,
            Regex,
            r"(?i)(call|invoke|run)\s+mcp_\w+",
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
            r"(?i)-{3,}\s*(END|BEGIN)\s+(SYSTEM|USER|ASSISTANT)\s+(PROMPT|MESSAGE|INSTRUCTIONS?)\s*-{3,}",
        ),
        p(
            "di-003",
            "delimiter-injection",
            High,
            Regex,
            r#"\{\s*"role"\s*:\s*"(system|assistant)"\s*"#,
        ),
        // encoded-injection (3)
        p(
            "enc-001",
            "encoded-injection",
            High,
            Regex,
            r"(?i)eval\s*\(\s*atob\s*\(",
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
            r"(?i)String\.fromCharCode\s*\(",
        ),
        // html-injection (5)
        p(
            "hi-001",
            "html-injection",
            Medium,
            Regex,
            r#"(?i)\son(load|error|click|focus|mouseover|submit|toggle|animationend)\s*=\s*["']"#,
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
            r#"(?i)expression\s*\(\s*['"a-z(]"#,
        ),
        p(
            "hi-005",
            "html-injection",
            High,
            Regex,
            r"<!--\s*(?i)(ignore|disregard|forget)\s+(any|all|previous|your)",
        ),
        // svg-injection (2)
        p(
            "svg-001",
            "svg-injection",
            Medium,
            Regex,
            r"(?i)<svg[^>]*\son\w+\s*=",
        ),
        p(
            "svg-002",
            "svg-injection",
            Medium,
            Regex,
            r"(?i)<foreignObject[\s>]",
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
