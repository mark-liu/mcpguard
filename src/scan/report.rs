use sha2::{Digest, Sha256};
use std::io;

use super::engine::Match;

/// Truncate shortens s to at most `max` bytes, clamping the cut to the
/// nearest UTF-8 char boundary ≤ max so a multibyte codepoint is never split.
/// Returns a borrowed slice for cheap reuse; callers needing an owned String
/// can `.to_string()` it.
///
/// Go's strings can be byte-sliced through a codepoint without panicking
/// (producing invalid UTF-8); Rust's `str` slicing panics on a non-boundary.
/// This helper bridges the gap safely — and since truncation only runs AFTER
/// scanning (SPEC §5.4), the slightly different cut byte doesn't affect any
/// verdict.
pub fn truncate_at_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Convenience wrapper appending "..." when truncated. Used by
/// `format_matches` (raw match excerpts, --show-excerpts only).
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", truncate_at_char_boundary(s, max))
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

// defang_text removed per Codex review: no CLI path wires `--unsafe-show-excerpts`,
// so the helper had no caller. Add it back together with that flag if/when raw
// match display is actually exposed.

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
    fn test_truncate() {
        assert_eq!(truncate("hello world", 5), "hello...");
        assert_eq!(truncate("hello", 5), "hello");
        assert_eq!(truncate("hi", 10), "hi");
    }

    // Regression (Codex finding #4): truncate must not panic when `max` lands
    // inside a multibyte codepoint. --show-excerpts in the hook calls this
    // with width 80 on attacker-controlled bytes; a tag-range/emoji match
    // whose boundary lies mid-codepoint would have panicked the hook.
    #[test]
    fn test_truncate_multibyte_boundary() {
        // "abc🦀def" — emoji is 4 bytes; cutting at byte 5 lands mid-emoji.
        let s = "abc🦀def";
        let out = truncate(s, 5);
        // Boundary-safe: clamps to 3 (after "abc") and appends "...".
        assert_eq!(out, "abc...");
        // Returned string is valid UTF-8 (Rust requires this; this is the
        // panic prevention — if the helper byte-sliced through the emoji
        // it would have panicked before we got here).
        assert!(out.is_char_boundary(out.len()));
    }
}
