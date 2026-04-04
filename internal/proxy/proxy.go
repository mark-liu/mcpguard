// Package proxy implements the stdio proxy that sits between Claude Code and
// a wrapped MCP server, intercepting JSON-RPC tool results for compression
// and prompt injection scanning.
package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/mark-liu/mcpguard/internal/compress"
	"github.com/mark-liu/mcpguard/internal/config"
	"github.com/mark-liu/mcpguard/internal/scan"
)

// Stats tracks proxy-level metrics.
type Stats struct {
	MessagesTotal      int64
	MessagesProcessed  int64
	BytesIn            int64
	BytesOut           int64
	InjectionWarnings  int64
	InjectionBlocks    int64
}

// Proxy is the main stdio proxy.
type Proxy struct {
	cfg          config.Config
	compressCfg  compress.Config
	scanner      *scan.Engine
	stats        Stats
	scanOnly     bool
	compressOnly bool
	showStats    bool
}

// New creates a proxy from the given configuration and mode flags.
func New(cfg config.Config, scanOnly, compressOnly, showStats bool) *Proxy {
	ccfg := compress.NewConfig(
		cfg.Compress.MaxContentLength,
		cfg.Compress.StripFields,
		cfg.Compress.ContentFields,
		cfg.Compress.MaxMessages,
		cfg.Compress.MaxArrayItems,
	)

	return &Proxy{
		cfg:          cfg,
		compressCfg:  ccfg,
		scanner:      scan.NewEngine(cfg.Scan.Sensitivity),
		scanOnly:     scanOnly,
		compressOnly: compressOnly,
		showStats:    showStats,
	}
}

// Run spawns the child MCP server and proxies stdio. Returns the child's exit code.
func (p *Proxy) Run(args []string) (int, error) {
	if len(args) == 0 {
		return 1, fmt.Errorf("no command to wrap")
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr

	childIn, err := cmd.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("stdin pipe: %w", err)
	}

	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start child: %w", err)
	}

	// Forward signals to child.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// stdin -> child stdin (passthrough).
	go func() {
		defer wg.Done()
		defer childIn.Close()
		_, _ = io.Copy(childIn, os.Stdin)
	}()

	// child stdout -> process -> stdout.
	go func() {
		defer wg.Done()
		p.processOutput(childOut, os.Stdout)
	}()

	err = cmd.Wait()
	wg.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	if p.showStats {
		p.printStats()
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}

	return 0, nil
}

// processOutput reads JSON-RPC lines from the child, applies compress+scan
// pipeline to tool results, and writes to the parent stdout.
func (p *Proxy) processOutput(r io.Reader, w io.Writer) {
	scanner := bufio.NewScanner(r)
	// MCP messages can be large; 10MB buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		atomic.AddInt64(&p.stats.MessagesTotal, 1)

		processed := p.processMessage(line)
		_, _ = w.Write(processed)
		_, _ = w.Write([]byte("\n"))
	}
}

// processMessage handles a single JSON-RPC message. Only tool result responses
// are processed; everything else passes through unchanged.
func (p *Proxy) processMessage(line []byte) []byte {
	atomic.AddInt64(&p.stats.BytesIn, int64(len(line)))

	// Fast path: not JSON.
	if len(line) == 0 || line[0] != '{' {
		atomic.AddInt64(&p.stats.BytesOut, int64(len(line)))
		return line
	}

	var msg map[string]json.RawMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		atomic.AddInt64(&p.stats.BytesOut, int64(len(line)))
		return line
	}

	// Only intercept JSON-RPC results (tool responses).
	resultRaw, hasResult := msg["result"]
	if !hasResult {
		atomic.AddInt64(&p.stats.BytesOut, int64(len(line)))
		return line
	}

	atomic.AddInt64(&p.stats.MessagesProcessed, 1)

	processed := []byte(resultRaw)

	// Scan pass FIRST: scan the original uncompressed data so truncation
	// cannot hide injection payloads in the tail.
	if !p.compressOnly {
		if p.scanResult(processed) {
			// Injection detected and action is "block" — return a JSON-RPC
			// error instead of forwarding the original payload.
			errResp := map[string]interface{}{
				"jsonrpc": "2.0",
				"error": map[string]interface{}{
					"code":    -32001,
					"message": "mcpguard: request blocked due to detected prompt injection",
				},
			}
			if id, ok := msg["id"]; ok {
				errResp["id"] = json.RawMessage(id)
			}
			out, err := json.Marshal(errResp)
			if err != nil {
				atomic.AddInt64(&p.stats.BytesOut, int64(len(line)))
				return line
			}
			atomic.AddInt64(&p.stats.BytesOut, int64(len(out)))
			return out
		}
	}

	// Compress pass AFTER scan: safe to truncate now that scanning is done.
	if !p.scanOnly {
		compressed, _ := compress.Compress(processed, p.compressCfg)
		processed = compressed
	}

	// Reassemble the message with the compressed result.
	msg["result"] = json.RawMessage(processed)
	out, err := json.Marshal(msg)
	if err != nil {
		atomic.AddInt64(&p.stats.BytesOut, int64(len(line)))
		return line
	}

	atomic.AddInt64(&p.stats.BytesOut, int64(len(out)))
	return out
}

// scanResult extracts text strings from the result and scans them.
// Returns true if the message should be blocked (verdict=block AND action=block).
func (p *Proxy) scanResult(data []byte) bool {
	blocked := false
	texts := extractStrings(data)
	for _, text := range texts {
		result := p.scanner.Scan(text)
		switch result.Verdict {
		case scan.VerdictBlock:
			atomic.AddInt64(&p.stats.InjectionBlocks, 1)
			action := p.cfg.Scan.Action
			if action == "block" {
				blocked = true
				fmt.Fprintf(os.Stderr, "[mcpguard] BLOCKED: injection detected (score=%.1f, %d matches)\n", result.Score, len(result.Matches))
				for _, m := range result.Matches {
					fmt.Fprintf(os.Stderr, "  %s [%s/%s]: %q\n", m.PatternID, m.Category, m.Severity, truncate(m.Text, 80))
				}
			} else {
				fmt.Fprintf(os.Stderr, "[mcpguard] WARNING: potential injection (score=%.1f, %d matches)\n", result.Score, len(result.Matches))
				for _, m := range result.Matches {
					fmt.Fprintf(os.Stderr, "  %s [%s/%s]: %q\n", m.PatternID, m.Category, m.Severity, truncate(m.Text, 80))
				}
			}
			atomic.AddInt64(&p.stats.InjectionWarnings, 1)
		case scan.VerdictPass:
			if len(result.Matches) > 0 {
				// Sub-threshold matches — log at debug level.
				fmt.Fprintf(os.Stderr, "[mcpguard] low-score matches (score=%.1f, threshold not met)\n", result.Score)
			}
		}
	}
	return blocked
}

// extractStrings pulls all string values from a JSON structure for scanning.
func extractStrings(data []byte) []string {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil
	}

	var strings []string
	walkStrings(v, &strings)
	return strings
}

// walkStrings recursively collects string values longer than 3 chars.
// The minimum avoids scanning trivially short values (single chars, empty)
// while still catching short injection markers like "[INST]" (6), "<<sys>>" (7).
func walkStrings(v interface{}, out *[]string) {
	switch val := v.(type) {
	case string:
		if len(val) > 3 {
			*out = append(*out, val)
		}
	case map[string]interface{}:
		for _, v := range val {
			walkStrings(v, out)
		}
	case []interface{}:
		for _, v := range val {
			walkStrings(v, out)
		}
	}
}

// truncate shortens a string to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// printStats writes compression and scan stats to stderr.
func (p *Proxy) printStats() {
	total := atomic.LoadInt64(&p.stats.MessagesTotal)
	processed := atomic.LoadInt64(&p.stats.MessagesProcessed)
	bytesIn := atomic.LoadInt64(&p.stats.BytesIn)
	bytesOut := atomic.LoadInt64(&p.stats.BytesOut)
	warns := atomic.LoadInt64(&p.stats.InjectionWarnings)
	blocks := atomic.LoadInt64(&p.stats.InjectionBlocks)

	fmt.Fprintf(os.Stderr, "\n[mcpguard] stats:\n")
	fmt.Fprintf(os.Stderr, "  messages: %d total, %d processed\n", total, processed)
	if bytesIn > 0 {
		pct := float64(bytesIn-bytesOut) / float64(bytesIn) * 100
		fmt.Fprintf(os.Stderr, "  bytes: %d in, %d out (%.1f%% reduction)\n", bytesIn, bytesOut, pct)
	}
	fmt.Fprintf(os.Stderr, "  injection: %d warnings, %d blocks\n", warns, blocks)
}
