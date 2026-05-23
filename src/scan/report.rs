use sha2::{Digest, Sha256};
use std::fmt::Write as FmtWrite;
use std::io;

use super::engine::Match;

/// Truncate shortens s to max bytes, appending "..." when truncated.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

/// format_matches writes one indented line per match to w, RAW (includes the
/// attacker-controlled match text). Only for opt-in --show-excerpts debugging.
pub fn format_matches(w: &mut dyn io::Write, matches: &[Match], max_text_width: usize) {
    for m in matches {
        let _ = writeln!(
            w,
            "  {} [{}/{}]: {:?}",
            m.pattern_id,
            m.category,
            m.severity,
            truncate(&m.text, max_text_width)
        );
    }
}

/// format_matches_safe writes one indented line per match using ONLY metadata
/// fields that cannot carry an attacker payload — pattern_id, category,
/// severity, offset, text length, and a hash prefix for correlation.
pub fn format_matches_safe(w: &mut dyn io::Write, matches: &[Match]) {
    for m in matches {
        let _ = writeln!(
            w,
            "  {} [{}/{}] offset={} len={} sha256={}",
            m.pattern_id,
            m.category,
            m.severity,
            m.offset,
            m.text.len(),
            sha256_prefix(&m.text)
        );
    }
}

/// sha256_prefix returns the first 16 hex chars (64 bits) of the SHA-256 of s.
/// Sufficient for correlating "two events tripped on the same payload" in
/// audit logs without storing the payload itself.
pub fn sha256_prefix(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)[..16].to_string()
}

/// defang_text interleaves U+00B7 (middle dot) between every character of s.
/// Only used in opt-in display paths. Disk log never stores raw OR defanged text.
pub fn defang_text(s: &str) -> String {
    if s.is_empty() {
        return s.to_string();
    }
    let runes: Vec<char> = s.chars().collect();
    let mut b = String::with_capacity(s.len() * 3);
    for (i, &r) in runes.iter().enumerate() {
        b.push(r);
        if i < runes.len() - 1 && r != ' ' && runes[i + 1] != ' ' {
            b.push('·');
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_prefix_length() {
        let p = sha256_prefix("hello");
        assert_eq!(p.len(), 16);
    }

    #[test]
    fn test_sha256_prefix_hex() {
        let p = sha256_prefix("hello");
        assert!(p.chars().all(|c| c.is_ascii_hexdigit()), "not hex: {}", p);
    }

    #[test]
    fn test_sha256_prefix_deterministic() {
        assert_eq!(sha256_prefix("test"), sha256_prefix("test"));
        assert_ne!(sha256_prefix("test"), sha256_prefix("test2"));
    }

    #[test]
    fn test_defang_text_empty() {
        assert_eq!(defang_text(""), "");
    }

    #[test]
    fn test_defang_text_interleaves() {
        let out = defang_text("ignore");
        // Should have dots between characters (not before/after spaces)
        assert!(out.contains('·'));
        // No contiguous letter runs
        assert!(!out.contains("ign"));
    }

    #[test]
    fn test_defang_text_spaces_not_dotted() {
        let out = defang_text("ignore previous");
        // Dot should not appear before/after the space
        let chars: Vec<char> = out.chars().collect();
        for i in 0..chars.len() {
            if chars[i] == '·' {
                // Dot must not be adjacent to space
                assert!(i > 0 && chars[i - 1] != ' ');
                assert!(i + 1 < chars.len() && chars[i + 1] != ' ');
            }
        }
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello world", 5), "hello...");
        assert_eq!(truncate("hello", 5), "hello");
        assert_eq!(truncate("hi", 10), "hi");
    }
}
