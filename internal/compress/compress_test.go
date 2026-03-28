package compress

import (
	"encoding/json"
	"testing"
)

func TestStripFields(t *testing.T) {
	input := `{"name":"alice","avatar":"abc123","content":"hello world"}`
	cfg := NewConfig(0, []string{"avatar"}, []string{"content"}, 0, 0)

	out, stats := Compress([]byte(input), cfg)
	if stats.OriginalSize != len(input) {
		t.Errorf("original size: got %d, want %d", stats.OriginalSize, len(input))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}

	if _, ok := result["avatar"]; ok {
		t.Error("avatar field should have been stripped")
	}
	if result["name"] != "alice" {
		t.Error("name field should be preserved")
	}
}

func TestMaxContentLength(t *testing.T) {
	input := `{"content":"this is a very long message that should be truncated at some point"}`
	cfg := NewConfig(20, nil, []string{"content"}, 0, 0)

	out, _ := Compress([]byte(input), cfg)

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}

	content := result["content"].(string)
	if len(content) > 60 { // 20 + truncation suffix
		t.Errorf("content too long: %d chars: %s", len(content), content)
	}
	if content[:20] != "this is a very long " {
		t.Errorf("unexpected truncation: %s", content)
	}
}

func TestMaxMessages(t *testing.T) {
	input := `{"messages":[{"id":1},{"id":2},{"id":3},{"id":4},{"id":5}]}`
	cfg := NewConfig(0, nil, nil, 3, 0)

	out, _ := Compress([]byte(input), cfg)

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}

	msgs := result["messages"].([]interface{})
	if len(msgs) != 3 {
		t.Errorf("expected 3 messages, got %d", len(msgs))
	}
	// Should keep the last 3.
	first := msgs[0].(map[string]interface{})
	if first["id"].(float64) != 3 {
		t.Errorf("expected first remaining message id=3, got %v", first["id"])
	}
}

func TestMaxArrayItems(t *testing.T) {
	items := make([]int, 100)
	for i := range items {
		items[i] = i
	}
	input, _ := json.Marshal(map[string]interface{}{"data": items})
	cfg := NewConfig(0, nil, nil, 0, 10)

	out, _ := Compress(input, cfg)

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}

	data := result["data"].([]interface{})
	if len(data) != 10 {
		t.Errorf("expected 10 items, got %d", len(data))
	}
}

func TestNoConfig(t *testing.T) {
	input := `{"content":"hello","avatar":"xyz"}`
	cfg := NewConfig(0, nil, nil, 0, 0)

	out, stats := Compress([]byte(input), cfg)
	if stats.OriginalSize != stats.CompressedSize {
		t.Errorf("no-op config should not change size: %d vs %d", stats.OriginalSize, stats.CompressedSize)
	}

	// JSON marshalling may reorder keys but content should be equivalent.
	var orig, result map[string]interface{}
	json.Unmarshal([]byte(input), &orig)
	json.Unmarshal(out, &result)

	if result["content"] != orig["content"] || result["avatar"] != orig["avatar"] {
		t.Error("no-op config should preserve all fields")
	}
}
