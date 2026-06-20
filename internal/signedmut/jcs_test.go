package signedmut

import (
	"encoding/json"
	"os"
	"testing"
)

// TestJCSVectors runs the shared cross-language vectors. The same file is
// copied into obacht-webapp (src/lib/signed-mutations/jcs-vectors.json) —
// both suites passing is the byte-identity proof the protocol rests on.
// Never edit one copy without the other.
func TestJCSVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/jcs-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors []struct {
		Name     string          `json:"name"`
		Input    json.RawMessage `json:"input"`
		Expected string          `json:"expected"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			tree, err := decodeJSON(v.Input)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			got, err := canonicalize(tree)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(got) != v.Expected {
				t.Errorf("canonical mismatch\n got: %s\nwant: %s", got, v.Expected)
			}
		})
	}
}

func TestJCSRejectsFloats(t *testing.T) {
	tree, err := decodeJSON([]byte(`{"x": 1.5}`))
	if err == nil {
		_, err = canonicalize(tree)
	}
	if err == nil {
		t.Fatal("expected non-integer number to be rejected")
	}
}

func TestJCSRejectsUnsafeInteger(t *testing.T) {
	// 2^53 (one past MAX_SAFE_INTEGER) must be rejected, not silently
	// canonicalized differently than JS would.
	tree, err := decodeJSON([]byte(`{"x": 9007199254740992}`))
	if err == nil {
		_, err = canonicalize(tree)
	}
	if err == nil {
		t.Fatal("expected unsafe integer to be rejected")
	}
}
