use anyhow::{bail, Context, Result};
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
}
