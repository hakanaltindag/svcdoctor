package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNewEvidenceIDAccepts(t *testing.T) {
	// The identifier scheme is not fixed yet, so these only have to be shapes a
	// future scheme could plausibly produce.
	valid := []string{
		"target",
		"target/ep:kafka.internal:9092",
		"target/ep:kafka.internal:9092/dns",
		"target/ep:[2001:db8::1]:9092/tcp",
		"a",
		"node-1_step.2",
	}

	for _, s := range valid {
		t.Run(s, func(t *testing.T) {
			id, err := NewEvidenceID(s)
			if err != nil {
				t.Fatalf("NewEvidenceID(%q): %v", s, err)
			}
			if id.String() != s {
				t.Errorf("String() = %q, want %q", id.String(), s)
			}
			if !id.Valid() {
				t.Error("id should be valid")
			}
		})
	}
}

func TestNewEvidenceIDRejects(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"leading space", " target"},
		{"trailing space", "target "},
		{"trailing newline", "target\n"},
		{"embedded newline", "target\nid"},
		{"embedded tab", "target\tid"},
		{"null byte", "target\x00id"},
		{"invalid utf8", "target\xff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := NewEvidenceID(tt.id)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if id != "" {
				t.Errorf("a rejected id must be empty, got %q", id)
			}
			if EvidenceID(tt.id).Valid() {
				t.Error("Valid() should reject the same input")
			}
		})
	}
}

// TestEvidenceIDRejectsRatherThanTrims pins a determinism decision: trimming
// would silently map two different inputs onto one identifier.
func TestEvidenceIDRejectsRatherThanTrims(t *testing.T) {
	if _, err := NewEvidenceID(" target "); err == nil {
		t.Fatal("surrounding whitespace should be rejected, not trimmed")
	}
}

func TestEvidenceIDIsComparable(t *testing.T) {
	a, err := NewEvidenceID("target/dns")
	if err != nil {
		t.Fatalf("NewEvidenceID: %v", err)
	}
	b, err := NewEvidenceID("target/dns")
	if err != nil {
		t.Fatalf("NewEvidenceID: %v", err)
	}
	c, err := NewEvidenceID("target/tcp")
	if err != nil {
		t.Fatalf("NewEvidenceID: %v", err)
	}

	if a != b {
		t.Error("equal identifiers should compare equal")
	}
	if a == c {
		t.Error("different identifiers should not compare equal")
	}

	// Usable as a map key, which the graph will rely on.
	m := map[EvidenceID]int{a: 1}
	if m[b] != 1 {
		t.Error("EvidenceID should work as a map key")
	}
}

func TestEvidenceIDJSON(t *testing.T) {
	id, err := NewEvidenceID("target/ep:kafka.internal:9092/dns")
	if err != nil {
		t.Fatalf("NewEvidenceID: %v", err)
	}

	got, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	const want = `"target/ep:kafka.internal:9092/dns"`
	if string(got) != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}
}
