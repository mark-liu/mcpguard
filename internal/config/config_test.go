package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadInvalidAction(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "bad.yaml")

	err := os.WriteFile(cfgFile, []byte(`
scan:
  sensitivity: medium
  action: "blcok"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(cfgFile)
	if err == nil {
		t.Error("expected error for invalid action 'blcok', but Load succeeded")
	}
}

func TestLoadValidActions(t *testing.T) {
	for _, action := range []string{"warn", "block", ""} {
		dir := t.TempDir()
		cfgFile := filepath.Join(dir, "ok.yaml")

		content := "scan:\n  sensitivity: medium\n"
		if action != "" {
			content += "  action: " + action + "\n"
		}

		err := os.WriteFile(cfgFile, []byte(content), 0644)
		if err != nil {
			t.Fatal(err)
		}

		cfg, err := Load(cfgFile)
		if err != nil {
			t.Errorf("action=%q: unexpected error: %v", action, err)
			continue
		}

		// Empty defaults to "warn".
		expected := action
		if expected == "" {
			expected = "warn"
		}
		if cfg.Scan.Action != expected {
			t.Errorf("action=%q: got %q, want %q", action, cfg.Scan.Action, expected)
		}
	}
}

func TestLoadInvalidSensitivity(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "bad.yaml")

	err := os.WriteFile(cfgFile, []byte(`
scan:
  sensitivity: "extreme"
  action: warn
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(cfgFile)
	if err == nil {
		t.Error("expected error for invalid sensitivity 'extreme', but Load succeeded")
	}
}
