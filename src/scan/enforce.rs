//! Verdict handling shared by the hook and the proxy: what to hand the model
//! in place of a payload that scanned as a block.

use serde_json::Value;

use super::engine::{Engine, Result};
use super::extract::walk_strings;
use super::redact::redact_urls;

/// collect_texts gathers every scannable string, keys included, from the tool
/// response. Tool input is the model's own text, never scanned.
pub fn collect_texts(resp: Option<&Value>) -> Vec<String> {
    let mut texts = Vec::new();
    if let Some(v) = resp {
        walk_strings(v, &mut texts);
    }
    texts
}

/// partial_redaction blanks eligible URL spans, returning the response and span
/// count, or None when the whole output must go. Fails closed: a critical match
/// rules it out and the rewrite must rescan with ZERO matches.
pub fn partial_redaction(
    engine: &Engine,
    resp: Option<&Value>,
    result: &Result,
) -> Option<(Value, usize)> {
    if result.matches.iter().any(|m| m.severity == "critical") {
        return None;
    }
    let mut resp = resp?.clone();
    let n = redact_urls(engine, &mut resp);
    if n == 0 {
        return None;
    }
    let mut texts = collect_texts(Some(&resp));
    // Adjacent blocks read as one text, so rescan them joined (`text` fields only).
    // The hook sees the block array itself, the proxy sees it under `content`.
    let blocks: Vec<&str> = resp
        .as_array()
        .or_else(|| resp.get("content")?.as_array())
        .into_iter()
        .flatten()
        .filter_map(|b| b.get("text")?.as_str())
        .collect();
    texts.extend([blocks.concat(), blocks.join(" ")]);
    let rescan = engine.aggregate_scan(&texts);
    rescan.matches.is_empty().then_some((resp, n))
}

/// redaction_notice is the stand-in text; `scanner` names who redacted ("PostToolUse" or "proxy").
pub fn redaction_notice(scanner: &str, result: &Result) -> String {
    format!(
        "[mcpguard redacted: {scanner} scanner detected possible prompt injection \
(score={:.1}, {} pattern matches). Original tool output suppressed. \
Run `mcpguard audit --last` for the metadata-only event record.]",
        result.score,
        result.matches.len()
    )
}
