package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNewLocalVantage(t *testing.T) {
	v, err := NewLocalVantage("build-agent-07")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	if v.Source() != VantageSourceLocalHost {
		t.Errorf("Source() = %s, want LOCAL_HOST", v.Source())
	}
	if v.Host() != "build-agent-07" {
		t.Errorf("Host() = %q, want %q", v.Host(), "build-agent-07")
	}
	if v.IsZero() {
		t.Error("a constructed Vantage must not be zero")
	}
}

func TestNewLocalVantageRejectsEmptyHost(t *testing.T) {
	for _, host := range []string{"", "   ", "\t\n"} {
		v, err := NewLocalVantage(host)
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("NewLocalVantage(%q) error = %v, want ErrInvalidValue", host, err)
		}
		if !v.IsZero() {
			t.Errorf("NewLocalVantage(%q) must return the zero Vantage", host)
		}
	}
}

func TestVantageTrimsHost(t *testing.T) {
	v, err := NewLocalVantage("  build-agent-07  ")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	if v.Host() != "build-agent-07" {
		t.Errorf("Host() = %q, want the trimmed value", v.Host())
	}
}

func TestVantageString(t *testing.T) {
	v, err := NewLocalVantage("build-agent-07")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	const want = "LOCAL_HOST:build-agent-07"
	if got := v.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestVantageJSON(t *testing.T) {
	v, err := NewLocalVantage("build-agent-07")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	got, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	const want = `{"source":"LOCAL_HOST","host":"build-agent-07"}`
	if string(got) != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}
}

// TestVantageJSONCarriesSourceAndHost is the semantic guard. A connectivity
// result is valid only from the recorded vantage point, so a serialized vantage
// must always say both what kind of place it was and which one. If either
// disappears from the encoding, a shared report can be misread as a claim about
// the target itself.
func TestVantageJSONCarriesSourceAndHost(t *testing.T) {
	v, err := NewLocalVantage("build-agent-07")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded["source"] != "LOCAL_HOST" {
		t.Errorf("encoded source = %q, want LOCAL_HOST", decoded["source"])
	}
	if decoded["host"] != "build-agent-07" {
		t.Errorf("encoded host = %q, want the vantage host", decoded["host"])
	}
	if len(decoded) != 2 {
		t.Errorf("encoded vantage has %d fields, want exactly source and host", len(decoded))
	}
}

// TestZeroVantageIsInvalid pins that a missing vantage cannot slip into a
// report as an empty object.
func TestZeroVantageIsInvalid(t *testing.T) {
	var v Vantage

	if !v.IsZero() {
		t.Error("the zero Vantage should report IsZero")
	}
	if v.Source().Valid() {
		t.Error("the zero Vantage must not have a valid source")
	}
	if got := v.String(); got != "<invalid vantage>" {
		t.Errorf("String() = %q, want %q", got, "<invalid vantage>")
	}

	_, err := json.Marshal(v)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal error = %v, want ErrInvalidValue", err)
	}
}

// TestVantageIsComparable confirms value semantics, which lets evidence and
// reports hold a vantage without aliasing concerns.
func TestVantageIsComparable(t *testing.T) {
	a, err := NewLocalVantage("host-a")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	b, err := NewLocalVantage("host-a")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	c, err := NewLocalVantage("host-b")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	if a != b {
		t.Error("vantages describing the same place should compare equal")
	}
	if a == c {
		t.Error("vantages describing different places should not compare equal")
	}
}

// TestOnlyLocalHostIsSupported pins the v0.1 scope. Adding a source is a
// deliberate act, so this failing is the intended signal.
func TestOnlyLocalHostIsSupported(t *testing.T) {
	if VantageSourceLocalHost.String() != "LOCAL_HOST" {
		t.Errorf("LOCAL_HOST renders as %q", VantageSourceLocalHost)
	}
	if VantageSource(VantageSourceLocalHost + 1).Valid() {
		t.Error("v0.1 must not define a vantage source beyond LOCAL_HOST")
	}
}

func TestVantageSourceString(t *testing.T) {
	tests := []struct {
		source VantageSource
		want   string
	}{
		{VantageSourceUnspecified, "UNSPECIFIED"},
		{VantageSourceLocalHost, "LOCAL_HOST"},
		{VantageSource(99), "VantageSource(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.source.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}

	if _, err := json.Marshal(VantageSourceUnspecified); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("marshalling an unspecified source: err = %v, want ErrInvalidValue", err)
	}
}

// TestVantageSourceNamesCoverAllSources fails if a source is added without a name.
func TestVantageSourceNamesCoverAllSources(t *testing.T) {
	const wantCount = 2 // VantageSourceUnspecified plus LOCAL_HOST

	if len(vantageSourceNames) != wantCount {
		t.Fatalf("vantageSourceNames has %d entries, want %d", len(vantageSourceNames), wantCount)
	}
	for i, name := range vantageSourceNames {
		if name == "" {
			t.Errorf("VantageSource(%d) has no name", i)
		}
	}
}
