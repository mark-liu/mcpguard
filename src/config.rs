use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;

/// Config is the top-level configuration for an mcpguard proxy instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub compress: CompressConfig,
    #[serde(default)]
    pub scan: ScanConfig,
}

/// CompressConfig controls payload compression behaviour.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompressConfig {
    #[serde(default)]
    pub max_content_length: usize,
    #[serde(default)]
    pub strip_fields: Vec<String>,
    #[serde(default)]
    pub content_fields: Vec<String>,
    #[serde(default)]
    pub max_messages: usize,
    #[serde(default)]
    pub max_array_items: usize,
}

/// ScanConfig controls prompt injection scanning behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// low, medium, high
    #[serde(default = "default_sensitivity")]
    pub sensitivity: String,
    /// warn, block
    #[serde(default = "default_action")]
    pub action: String,
    /// Matches to drop before scoring. See AllowConfig.
    #[serde(default)]
    pub allow: AllowConfig,
}

/// AllowConfig suppresses known-benign matches before they reach scoring.
///
/// Motivation: every detector here is content-shaped, with no notion of who
/// authored the text or where a URL points. First-party vendor boilerplate --
/// a Grafana alert linking to your own Grafana -- is byte-identical in shape
/// to an exfil instruction. Without an escape hatch the only knobs are the
/// global threshold and warn-vs-block, so operators route around the guard
/// instead of tuning it, which is strictly worse for coverage.
///
/// This is deliberately a SUPPRESSION list, not a trust system: entries drop
/// matches before scoring, they never lower the threshold or bypass the
/// critical short-circuit for anything else in the payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllowConfig {
    /// Host suffixes whose URLs should not count as exfil destinations, e.g.
    /// "grafana.net" also allows "twinstake.grafana.net". Matching is on the
    /// URL's real host: userinfo before '@' is discarded and ports are
    /// stripped, so "https://grafana.net@evil.tld/x" is NOT allowed.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Pattern ids to disable outright, e.g. "ch-002". Validated against the
    /// pattern table at load time so a typo fails loudly instead of silently
    /// disabling nothing.
    #[serde(default)]
    pub patterns: Vec<String>,
}

fn default_sensitivity() -> String {
    "medium".to_string()
}

fn default_action() -> String {
    "warn".to_string()
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            sensitivity: "medium".to_string(),
            action: "warn".to_string(),
            allow: AllowConfig::default(),
        }
    }
}

/// DefaultConfig returns a config suitable for scan-only mode with medium sensitivity.
pub fn default_config() -> Config {
    Config {
        scan: ScanConfig::default(),
        compress: CompressConfig::default(),
    }
}

/// default_content_fields returns the default set of field names treated as content.
pub fn default_content_fields() -> Vec<String> {
    vec![
        "content".into(),
        "text".into(),
        "body".into(),
        "message".into(),
        "description".into(),
        "caption".into(),
    ]
}

/// load reads a YAML config file from disk.
pub fn load(path: &str) -> Result<Config> {
    let data = fs::read_to_string(path).with_context(|| format!("read config: {path}"))?;

    let mut cfg: Config =
        serde_yaml::from_str(&data).with_context(|| format!("parse config: {path}"))?;

    // Apply defaults for content fields if none specified.
    if cfg.compress.content_fields.is_empty() {
        cfg.compress.content_fields = default_content_fields();
    }

    if cfg.scan.sensitivity.is_empty() {
        cfg.scan.sensitivity = "medium".to_string();
    }
    if cfg.scan.action.is_empty() {
        cfg.scan.action = "warn".to_string();
    }

    // Validate action — a typo here silently makes all detections no-ops.
    match cfg.scan.action.as_str() {
        "warn" | "block" => {}
        other => bail!(
            "invalid scan action {:?}: must be \"warn\" or \"block\"",
            other
        ),
    }

    // Validate sensitivity.
    match cfg.scan.sensitivity.as_str() {
        "low" | "medium" | "high" => {}
        other => bail!(
            "invalid scan sensitivity {:?}: must be \"low\", \"medium\", or \"high\"",
            other
        ),
    }

    // Validate allowlisted pattern ids against the real pattern table. A typo
    // here would silently disable nothing, which is the same failure mode the
    // action/sensitivity checks above exist to prevent -- except worse,
    // because the operator believes a noisy detector is off when it is not.
    let known: std::collections::HashSet<&str> = crate::scan::patterns::all_patterns()
        .iter()
        .map(|p| p.id)
        .collect();
    for id in &cfg.scan.allow.patterns {
        if !known.contains(id.as_str()) {
            bail!(
                "unknown pattern id {:?} in scan.allow.patterns: no such detector",
                id
            );
        }
    }

    // An empty or whitespace-only host entry would suffix-match every URL and
    // silently disable ei-00x wholesale. Reject it rather than fail open.
    for h in &cfg.scan.allow.hosts {
        if h.trim().is_empty() {
            bail!("empty host in scan.allow.hosts: would match every URL");
        }
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_cfg(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_load_invalid_action() {
        let f = write_cfg("scan:\n  sensitivity: medium\n  action: \"blcok\"\n");
        let result = load(f.path().to_str().unwrap());
        assert!(result.is_err(), "expected error for invalid action 'blcok'");
    }

    #[test]
    fn test_load_valid_actions() {
        for action in &["warn", "block", ""] {
            let content = if action.is_empty() {
                "scan:\n  sensitivity: medium\n".to_string()
            } else {
                format!("scan:\n  sensitivity: medium\n  action: {action}\n")
            };
            let f = write_cfg(&content);
            let cfg = load(f.path().to_str().unwrap())
                .unwrap_or_else(|e| panic!("action={action:?}: unexpected error: {e}"));
            let expected = if action.is_empty() { "warn" } else { action };
            assert_eq!(cfg.scan.action, expected, "action={action:?}");
        }
    }

    #[test]
    fn test_load_invalid_sensitivity() {
        let f = write_cfg("scan:\n  sensitivity: \"extreme\"\n  action: warn\n");
        let result = load(f.path().to_str().unwrap());
        assert!(
            result.is_err(),
            "expected error for invalid sensitivity 'extreme'"
        );
    }

    #[test]
    fn test_load_defaults_content_fields() {
        let f = write_cfg("scan:\n  sensitivity: medium\n");
        let cfg = load(f.path().to_str().unwrap()).unwrap();
        assert!(!cfg.compress.content_fields.is_empty());
        assert!(cfg.compress.content_fields.contains(&"content".to_string()));
    }

    #[test]
    fn test_load_allow_defaults_empty() {
        let f = write_cfg("scan:\n  sensitivity: medium\n");
        let cfg = load(f.path().to_str().unwrap()).unwrap();
        assert!(cfg.scan.allow.hosts.is_empty());
        assert!(cfg.scan.allow.patterns.is_empty());
    }

    #[test]
    fn test_load_allow_valid() {
        let f = write_cfg(
            "scan:\n  sensitivity: medium\n  allow:\n    hosts:\n      - grafana.net\n    patterns:\n      - ch-002\n",
        );
        let cfg = load(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.scan.allow.hosts, vec!["grafana.net".to_string()]);
        assert_eq!(cfg.scan.allow.patterns, vec!["ch-002".to_string()]);
    }

    #[test]
    fn test_load_allow_rejects_unknown_pattern_id() {
        // A typo must fail loudly: silently disabling nothing is the worst
        // outcome, because the operator believes a noisy detector is off.
        let f =
            write_cfg("scan:\n  sensitivity: medium\n  allow:\n    patterns:\n      - ch-999\n");
        let err = load(f.path().to_str().unwrap()).unwrap_err();
        assert!(
            format!("{err:#}").contains("ch-999"),
            "error should name the bad id, got: {err:#}"
        );
    }

    #[test]
    fn test_load_allow_rejects_empty_host() {
        // An empty host would suffix-match every URL and disable ei-00x.
        let f = write_cfg("scan:\n  sensitivity: medium\n  allow:\n    hosts:\n      - \"  \"\n");
        assert!(load(f.path().to_str().unwrap()).is_err());
    }
}
