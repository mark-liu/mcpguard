package main

import (
	"bytes"
	"strings"
	"testing"
)

func runExplainCmd(args []string) (code int, stdout, stderr string) {
	var out, errBuf bytes.Buffer
	code = runExplain(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestExplain_KnownPattern(t *testing.T) {
	code, stdout, _ := runExplainCmd([]string{"io-001"})
	if code != 0 {
		t.Errorf("want exit 0, got %d", code)
	}
	if !strings.Contains(stdout, "io-001") {
		t.Errorf("output missing id: %s", stdout)
	}
	if !strings.Contains(stdout, "instruction-override") {
		t.Errorf("output missing category: %s", stdout)
	}
	if !strings.Contains(stdout, "rationale:") {
		t.Errorf("output missing rationale: %s", stdout)
	}
}

func TestExplain_UnknownPattern(t *testing.T) {
	code, _, stderr := runExplainCmd([]string{"xx-999"})
	if code != 1 {
		t.Errorf("unknown id should exit 1, got %d", code)
	}
	if !strings.Contains(stderr, "unknown pattern_id") {
		t.Errorf("missing diagnostic: %s", stderr)
	}
}

func TestExplain_NoArgs(t *testing.T) {
	code, _, stderr := runExplainCmd(nil)
	if code != 1 {
		t.Errorf("no args should exit 1, got %d", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("should print usage: %s", stderr)
	}
}

func TestExplain_AllCategoriesHaveRationale(t *testing.T) {
	// Every category referenced by a shipped pattern should have a
	// rationaleFor() entry so `mcpguard explain <any-valid-id>` always
	// surfaces a useful description.
	categories := []string{
		"instruction-override", "prompt-marker", "authority-claim",
		"exfil-instruction", "tool-manipulation", "context-hijacking",
		"output-manipulation", "unicode-obfuscation", "encoded-injection",
		"delimiter-injection",
	}
	for _, c := range categories {
		if r := rationaleFor(c); r == "" {
			t.Errorf("category %q has no rationale", c)
		}
	}
}
