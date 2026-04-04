// Package config handles per-server YAML configuration for mcpguard.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for an mcpguard proxy instance.
type Config struct {
	Compress CompressConfig `yaml:"compress"`
	Scan     ScanConfig     `yaml:"scan"`
}

// CompressConfig controls payload compression behaviour.
type CompressConfig struct {
	MaxContentLength int      `yaml:"max_content_length"` // 0 = no cap
	StripFields      []string `yaml:"strip_fields"`
	ContentFields    []string `yaml:"content_fields"` // which string fields to cap (default: content, text, body, message)
	MaxMessages      int      `yaml:"max_messages"`   // 0 = no cap on message arrays
	MaxArrayItems    int      `yaml:"max_array_items"`
}

// ScanConfig controls prompt injection scanning behaviour.
type ScanConfig struct {
	Sensitivity string `yaml:"sensitivity"` // low, medium, high
	Action      string `yaml:"action"`      // warn, block
}

// DefaultConfig returns a config suitable for scan-only mode with medium sensitivity.
func DefaultConfig() Config {
	return Config{
		Scan: ScanConfig{
			Sensitivity: "medium",
			Action:      "warn",
		},
	}
}

// DefaultContentFields returns the default set of field names treated as content.
func DefaultContentFields() []string {
	return []string{"content", "text", "body", "message", "description", "caption"}
}

// Load reads a YAML config file from disk.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	// Apply defaults for content fields if none specified.
	if len(cfg.Compress.ContentFields) == 0 {
		cfg.Compress.ContentFields = DefaultContentFields()
	}

	if cfg.Scan.Sensitivity == "" {
		cfg.Scan.Sensitivity = "medium"
	}
	if cfg.Scan.Action == "" {
		cfg.Scan.Action = "warn"
	}

	// Validate action — a typo here silently makes all detections no-ops.
	switch cfg.Scan.Action {
	case "warn", "block":
		// valid
	default:
		return Config{}, fmt.Errorf("invalid scan action %q: must be \"warn\" or \"block\"", cfg.Scan.Action)
	}

	// Validate sensitivity.
	switch cfg.Scan.Sensitivity {
	case "low", "medium", "high":
		// valid
	default:
		return Config{}, fmt.Errorf("invalid scan sensitivity %q: must be \"low\", \"medium\", or \"high\"", cfg.Scan.Sensitivity)
	}

	return cfg, nil
}
