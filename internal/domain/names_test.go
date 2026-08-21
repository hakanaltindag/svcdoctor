package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNewStepAccepts(t *testing.T) {
	valid := []string{
		"dns.lookup",
		"tcp.connect",
		"tls.handshake",
		"protocol.capabilities",
		"auth.authenticate",
		"topology.discover",
		"config.normalize",
		"step",
		"a.b.c.d",
		"api_versions",
		"step2",
		// A service adapter can add its own steps without any core change.
		"kafka.api_versions",
		"kafka.metadata",
		"postgres.ssl_request",
	}

	for _, s := range valid {
		t.Run(s, func(t *testing.T) {
			step, err := NewStep(s)
			if err != nil {
				t.Fatalf("NewStep(%q): %v", s, err)
			}
			if step.String() != s {
				t.Errorf("String() = %q, want %q", step.String(), s)
			}
			if !step.Valid() {
				t.Error("step should be valid")
			}
		})
	}
}

func TestNewStepRejects(t *testing.T) {
	tests := []struct {
		name string
		step string
	}{
		{"empty", ""},
		{"uppercase", "DNS.lookup"},
		{"mixed case", "dns.Lookup"},
		{"leading dot", ".dns.lookup"},
		{"trailing dot", "dns.lookup."},
		{"double dot", "dns..lookup"},
		{"only a dot", "."},
		{"space", "dns lookup"},
		{"hyphen", "dns-lookup"},
		{"slash", "dns/lookup"},
		{"colon", "dns:lookup"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step, err := NewStep(tt.step)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if step != "" {
				t.Errorf("a rejected step must be empty, got %q", step)
			}
			if Step(tt.step).Valid() {
				t.Error("Valid() should reject the same input")
			}
		})
	}
}

// TestStepCaseIsFixed pins why the grammar is lowercase only: two spellings of
// one operation would split what should be a single step in every report.
func TestStepCaseIsFixed(t *testing.T) {
	if _, err := NewStep("DNS.LOOKUP"); err == nil {
		t.Error("uppercase steps must be rejected so one operation has one spelling")
	}
}

func TestNewAttributeKeyAccepts(t *testing.T) {
	valid := []string{
		"dns.rcode",
		"dns.addresses",
		"tcp.latency",
		"tls.negotiated_version",
		"rcode",
		"a.b.c",
	}

	for _, s := range valid {
		t.Run(s, func(t *testing.T) {
			key, err := NewAttributeKey(s)
			if err != nil {
				t.Fatalf("NewAttributeKey(%q): %v", s, err)
			}
			if key.String() != s {
				t.Errorf("String() = %q, want %q", key.String(), s)
			}
			if !key.Valid() {
				t.Error("key should be valid")
			}
		})
	}
}

func TestNewAttributeKeyRejects(t *testing.T) {
	invalid := []string{"", "TLS.version", "tls..version", ".tls", "tls.", "tls version", "tls-version"}

	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			key, err := NewAttributeKey(s)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if key != "" {
				t.Errorf("a rejected key must be empty, got %q", key)
			}
		})
	}
}

// TestNoServiceKeyRegistryExists guards the open ownership decision. This
// package defines the generic key type only. If a later change adds service
// key constants here, that silently closes a decision that is meant to stay
// open until a real adapter demonstrates the right home.
func TestNoServiceKeyRegistryExists(t *testing.T) {
	// A registry would need a lookup or an enumeration. Neither exists.
	var k any = AttributeKey("dns.rcode")

	if _, ok := k.(interface{ Service() string }); ok {
		t.Error("AttributeKey must not know which service owns it")
	}
	if _, ok := k.(interface{ Registered() bool }); ok {
		t.Error("AttributeKey must not consult a registry")
	}
}

func TestStepAndAttributeKeyJSON(t *testing.T) {
	step, err := NewStep("dns.lookup")
	if err != nil {
		t.Fatalf("NewStep: %v", err)
	}
	got, err := json.Marshal(step)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(got) != `"dns.lookup"` {
		t.Errorf("json.Marshal(Step) = %s, want \"dns.lookup\"", got)
	}

	key, err := NewAttributeKey("dns.rcode")
	if err != nil {
		t.Fatalf("NewAttributeKey: %v", err)
	}
	got, err = json.Marshal(key)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(got) != `"dns.rcode"` {
		t.Errorf("json.Marshal(AttributeKey) = %s, want \"dns.rcode\"", got)
	}
}

// TestStepAndAttributeKeyAreDistinctTypes prevents one from being passed where
// the other is expected, even though they share a grammar.
func TestStepAndAttributeKeyAreDistinctTypes(t *testing.T) {
	var s any = Step("dns.lookup")
	if _, ok := s.(AttributeKey); ok {
		t.Error("Step must not be assignable to AttributeKey")
	}

	var k any = AttributeKey("dns.rcode")
	if _, ok := k.(Step); ok {
		t.Error("AttributeKey must not be assignable to Step")
	}
}
