use serde_json::Value;
use std::collections::HashSet;

/// Config controls payload compression behaviour.
#[derive(Debug, Clone)]
pub struct Config {
    pub max_content_length: usize, // 0 = no cap
    pub strip_fields: HashSet<String>,
    pub content_fields: HashSet<String>,
    pub max_messages: usize,    // 0 = no cap on message arrays
    pub max_array_items: usize, // 0 = no cap
}

impl Config {
    /// Builds a Config from slices, converting to sets for O(1) lookup.
    pub fn new(
        max_content: usize,
        strip_fields: &[&str],
        content_fields: &[&str],
        max_messages: usize,
        max_array_items: usize,
    ) -> Self {
        Config {
            max_content_length: max_content,
            strip_fields: strip_fields.iter().map(|s| s.to_string()).collect(),
            content_fields: content_fields.iter().map(|s| s.to_string()).collect(),
            max_messages,
            max_array_items,
        }
    }
}

/// Stats tracks compression metrics.
///
/// Test-only diagnostic: tests use these fields to assert byte counts.
/// The proxy tracks bytes_in/bytes_out via atomics in `proxy::Stats` for the
/// `--stats` output, so it ignores this struct's fields. `#[allow(dead_code)]`
/// keeps the struct around for tests without triggering the dead-field warning
/// on `cargo build --release` (per Codex review — alternative was to thread
/// the fields into proxy::Stats, which would duplicate the byte counters).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Stats {
    pub original_size: usize,
    pub compressed_size: usize,
}

/// Compress applies field stripping, content capping, and array truncation to
/// a JSON byte slice. Returns the modified JSON and compression stats.
/// On JSON parse/marshal failure, returns original bytes unchanged.
pub fn compress(data: &[u8], cfg: &Config) -> (Vec<u8>, Stats) {
    let orig_size = data.len();

    let v: Value = match serde_json::from_slice(data) {
        Err(_) => {
            return (
                data.to_vec(),
                Stats {
                    original_size: orig_size,
                    compressed_size: orig_size,
                },
            );
        }
        Ok(v) => v,
    };

    let v = process_value(v, cfg, "");

    match serde_json::to_vec(&v) {
        Err(_) => (
            data.to_vec(),
            Stats {
                original_size: orig_size,
                compressed_size: orig_size,
            },
        ),
        Ok(out) => {
            let compressed_size = out.len();
            (
                out,
                Stats {
                    original_size: orig_size,
                    compressed_size,
                },
            )
        }
    }
}

/// process_value recursively walks JSON values applying compression rules.
fn process_value(v: Value, cfg: &Config, field_name: &str) -> Value {
    match v {
        Value::Object(map) => process_object(map, cfg),
        Value::Array(arr) => process_array(arr, cfg, field_name),
        Value::String(s) => Value::String(process_string(s, cfg, field_name)),
        other => other,
    }
}

/// process_object strips fields and recurses into remaining values.
fn process_object(map: serde_json::Map<String, Value>, cfg: &Config) -> Value {
    let mut result = serde_json::Map::new();
    for (k, v) in map {
        if cfg.strip_fields.contains(&k) {
            continue;
        }
        let processed = process_value(v, cfg, &k);
        result.insert(k, processed);
    }
    Value::Object(result)
}

/// process_array applies max_messages/max_array_items caps and recurses.
fn process_array(mut arr: Vec<Value>, cfg: &Config, field_name: &str) -> Value {
    // Apply message-specific cap for known message array fields.
    if cfg.max_messages > 0 && is_message_field(field_name) && arr.len() > cfg.max_messages {
        let skip = arr.len() - cfg.max_messages;
        arr = arr.into_iter().skip(skip).collect();
    }

    // Generic array cap — keeps the tail (newest).
    if cfg.max_array_items > 0 && arr.len() > cfg.max_array_items {
        let skip = arr.len() - cfg.max_array_items;
        arr = arr.into_iter().skip(skip).collect();
    }

    let result: Vec<Value> = arr.into_iter().map(|v| process_value(v, cfg, "")).collect();
    Value::Array(result)
}

/// process_string handles stringified JSON and truncates content fields.
fn process_string(s: String, cfg: &Config, field_name: &str) -> String {
    // If the string looks like embedded JSON, parse, compress, and re-stringify.
    if s.len() > 1 && (s.starts_with('{') || s.starts_with('[')) {
        if let Ok(inner) = serde_json::from_str::<Value>(&s) {
            let inner = process_value(inner, cfg, "");
            if let Ok(out) = serde_json::to_string(&inner) {
                return out;
            }
        }
    }

    if cfg.max_content_length == 0 {
        return s;
    }

    if !cfg.content_fields.contains(field_name) {
        return s;
    }

    if s.len() <= cfg.max_content_length {
        return s;
    }

    // UTF-8-safe byte slicing: cut at the nearest char boundary ≤ max so
    // multibyte codepoints (emoji, CJK) at the boundary don't panic. The Go
    // source byte-slices freely; Rust would panic on a non-boundary index.
    // The truncated_len count reflects what was actually dropped after
    // boundary clamp (slightly more bytes than max_content_length when the
    // boundary is mid-codepoint), so the printed count remains accurate.
    let kept = crate::scan::report::truncate_at_char_boundary(&s, cfg.max_content_length);
    let truncated_len = s.len() - kept.len();
    format!("{}...[truncated {} chars]", kept, truncated_len)
}

/// isMessageField returns true if the field name looks like it holds messages.
fn is_message_field(name: &str) -> bool {
    matches!(
        name,
        "messages" | "history" | "results" | "items" | "entries"
    )
}

// default_content_fields lives in `crate::config` — Codex flagged this as a
// duplicate. Use config::default_content_fields() if you need it.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk_cfg(
        max_content: usize,
        strip: &[&str],
        content: &[&str],
        max_msgs: usize,
        max_arr: usize,
    ) -> Config {
        Config::new(max_content, strip, content, max_msgs, max_arr)
    }

    #[test]
    fn test_strip_fields() {
        let input = br#"{"name":"alice","avatar":"abc123","content":"hello world"}"#;
        let cfg = mk_cfg(0, &["avatar"], &["content"], 0, 0);
        let (out, stats) = compress(input, &cfg);
        assert_eq!(stats.original_size, input.len());
        let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(result.get("avatar").is_none(), "avatar should be stripped");
        assert_eq!(result["name"], "alice");
    }

    #[test]
    fn test_max_content_length() {
        let input =
            br#"{"content":"this is a very long message that should be truncated at some point"}"#;
        let cfg = mk_cfg(20, &[], &["content"], 0, 0);
        let (out, _) = compress(input, &cfg);
        let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let content = result["content"].as_str().unwrap();
        assert!(
            content.len() <= 60,
            "content too long: {} chars: {}",
            content.len(),
            content
        );
        assert_eq!(&content[..20], "this is a very long ");
    }

    #[test]
    fn test_max_messages() {
        let input = br#"{"messages":[{"id":1},{"id":2},{"id":3},{"id":4},{"id":5}]}"#;
        let cfg = mk_cfg(0, &[], &[], 3, 0);
        let (out, _) = compress(input, &cfg);
        let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let msgs = result["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3, "expected 3 messages");
        // Should keep the last 3 (ids 3, 4, 5)
        assert_eq!(msgs[0]["id"], 3.0_f64);
    }

    #[test]
    fn test_max_array_items() {
        let items: Vec<i64> = (0..100).collect();
        let input_val = json!({"data": items});
        let input = serde_json::to_vec(&input_val).unwrap();
        let cfg = mk_cfg(0, &[], &[], 0, 10);
        let (out, _) = compress(&input, &cfg);
        let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let data = result["data"].as_array().unwrap();
        assert_eq!(data.len(), 10);
    }

    #[test]
    fn test_no_config() {
        let input = br#"{"content":"hello","avatar":"xyz"}"#;
        let cfg = mk_cfg(0, &[], &[], 0, 0);
        let (out, stats) = compress(input, &cfg);
        // With preserve_order, sizes may differ from plain map output but should be ≈ same
        // The important thing is content preservation.
        let orig: serde_json::Value = serde_json::from_slice(input).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(result["content"], orig["content"]);
        assert_eq!(result["avatar"], orig["avatar"]);
        // Original size should match
        assert_eq!(stats.original_size, input.len());
    }

    #[test]
    fn test_embedded_json_string_recurses() {
        // Embedded JSON string should be recursively compressed.
        let inner = json!({"content": "a".repeat(200), "strip_me": "x"});
        let outer = json!({"text": inner.to_string()});
        let input = serde_json::to_vec(&outer).unwrap();
        let cfg = mk_cfg(50, &["strip_me"], &["content"], 0, 0);
        let (out, _) = compress(&input, &cfg);
        let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let text = result["text"].as_str().unwrap();
        // After re-stringifying, it should be valid JSON and not contain strip_me
        let inner_parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(
            inner_parsed.get("strip_me").is_none(),
            "strip_me should be removed from embedded JSON"
        );
        let content = inner_parsed["content"].as_str().unwrap();
        assert!(
            content.len() <= 80,
            "embedded content should be truncated: {}",
            content.len()
        );
    }

    // Regression (Codex finding #1): truncate must not panic when
    // max_content_length lands inside a multibyte codepoint. Go byte-slices
    // freely; Rust `&s[..n]` panics on a non-char-boundary index.
    #[test]
    fn test_truncate_panics_on_multibyte_boundary() {
        // "abc🦀def" — emoji is 4 bytes (F0 9F A6 80); cutting at byte 5 lands
        // mid-emoji. Previous code panicked here.
        let input = r#"{"content":"abc🦀def"}"#.as_bytes();
        let cfg = mk_cfg(5, &[], &["content"], 0, 0);
        let (out, _) = compress(input, &cfg);
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let content = parsed["content"].as_str().unwrap();
        // Truncated at a valid char boundary ≤ 5 (here: 3, after "abc") + suffix.
        assert!(
            content.starts_with("abc"),
            "expected 'abc' prefix, got: {content:?}"
        );
        assert!(
            content.contains("...[truncated"),
            "expected truncation marker, got: {content:?}"
        );
    }

    #[test]
    fn test_truncate_cjk_boundary_safe() {
        // 工 = 3 bytes (E5 B7 A5). max=4 → falls mid-codepoint of second char.
        let input = "{\"content\":\"工具書\"}".as_bytes();
        let cfg = mk_cfg(4, &[], &["content"], 0, 0);
        let (out, _) = compress(input, &cfg);
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(parsed["content"].as_str().unwrap().starts_with("工"));
    }
}
