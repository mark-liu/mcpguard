// Package compress implements field stripping, content capping, and array
// truncation for JSON payloads from MCP tool results.
package compress

import (
	"encoding/json"
	"fmt"
)

// Config mirrors the compress section of the YAML config.
type Config struct {
	MaxContentLength int
	StripFields      map[string]bool
	ContentFields    map[string]bool
	MaxMessages      int
	MaxArrayItems    int
}

// Stats tracks compression metrics.
type Stats struct {
	OriginalSize   int `json:"original_size"`
	CompressedSize int `json:"compressed_size"`
}

// NewConfig builds a compress.Config from slices (converting to sets for O(1) lookup).
func NewConfig(maxContent int, stripFields, contentFields []string, maxMessages, maxArrayItems int) Config {
	sf := make(map[string]bool, len(stripFields))
	for _, f := range stripFields {
		sf[f] = true
	}

	cf := make(map[string]bool, len(contentFields))
	for _, f := range contentFields {
		cf[f] = true
	}

	return Config{
		MaxContentLength: maxContent,
		StripFields:      sf,
		ContentFields:    cf,
		MaxMessages:      maxMessages,
		MaxArrayItems:    maxArrayItems,
	}
}

// Compress applies field stripping, content capping, and array truncation to
// a JSON byte slice. Returns the modified JSON and compression stats.
func Compress(data []byte, cfg Config) ([]byte, Stats) {
	origSize := len(data)

	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return data, Stats{OriginalSize: origSize, CompressedSize: origSize}
	}

	v = processValue(v, cfg, "")
	out, err := json.Marshal(v)
	if err != nil {
		return data, Stats{OriginalSize: origSize, CompressedSize: origSize}
	}

	return out, Stats{OriginalSize: origSize, CompressedSize: len(out)}
}

// processValue recursively walks JSON values applying compression rules.
func processValue(v interface{}, cfg Config, fieldName string) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return processObject(val, cfg)
	case []interface{}:
		return processArray(val, cfg, fieldName)
	case string:
		return processString(val, cfg, fieldName)
	default:
		return v
	}
}

// processObject strips fields and recurses into remaining values.
func processObject(obj map[string]interface{}, cfg Config) map[string]interface{} {
	result := make(map[string]interface{}, len(obj))

	for k, v := range obj {
		if cfg.StripFields[k] {
			continue
		}
		result[k] = processValue(v, cfg, k)
	}

	return result
}

// processArray applies max_messages/max_array_items caps and recurses into elements.
func processArray(arr []interface{}, cfg Config, fieldName string) []interface{} {
	// Apply message-specific cap for known message array fields.
	if cfg.MaxMessages > 0 && isMessageField(fieldName) && len(arr) > cfg.MaxMessages {
		arr = arr[len(arr)-cfg.MaxMessages:]
	}

	// Generic array cap.
	if cfg.MaxArrayItems > 0 && len(arr) > cfg.MaxArrayItems {
		arr = arr[len(arr)-cfg.MaxArrayItems:]
	}

	result := make([]interface{}, len(arr))
	for i, v := range arr {
		result[i] = processValue(v, cfg, "")
	}

	return result
}

// processString truncates content fields to max_content_length.
func processString(s string, cfg Config, fieldName string) string {
	if cfg.MaxContentLength <= 0 {
		return s
	}

	if !cfg.ContentFields[fieldName] {
		return s
	}

	if len(s) <= cfg.MaxContentLength {
		return s
	}

	return s[:cfg.MaxContentLength] + fmt.Sprintf("...[truncated %d chars]", len(s)-cfg.MaxContentLength)
}

// isMessageField returns true if the field name looks like it holds messages.
func isMessageField(name string) bool {
	switch name {
	case "messages", "history", "results", "items", "entries":
		return true
	default:
		return false
	}
}
