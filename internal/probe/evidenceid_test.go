package probe

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

func TestEvidenceIDJoinsComponents(t *testing.T) {
	tests := []struct {
		name       string
		step       domain.Step
		components []string
		want       domain.EvidenceID
	}{
		{
			name:       "one component",
			step:       "dns.lookup",
			components: []string{"primary.internal"},
			want:       "dns.lookup/primary.internal",
		},
		{
			name:       "two components, widest scope first",
			step:       "tcp.connect",
			components: []string{"primary.internal:9092", "10.0.0.1"},
			want:       "tcp.connect/primary.internal:9092/10.0.0.1",
		},
		{
			name:       "ipv6 needs no special handling: it has no separator",
			step:       "tcp.connect",
			components: []string{"[2001:db8::1]:9092", "2001:db8::1"},
			want:       "tcp.connect/[2001:db8::1]:9092/2001:db8::1",
		},
		{
			name:       "no components at all",
			step:       "dns.lookup",
			components: nil,
			want:       "dns.lookup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvidenceID(tt.step, tt.components...); got != tt.want {
				t.Errorf("EvidenceID = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestEvidenceIDEscapesSeparatorAndEscape is the reason input never has to be
// restricted. A component containing the separator is encoded, not refused.
func TestEvidenceIDEscapesSeparatorAndEscape(t *testing.T) {
	tests := []struct {
		component string
		want      domain.EvidenceID
	}{
		{"weird/name", "dns.lookup/weird%2Fname"},
		{"weird%2Fname", "dns.lookup/weird%252Fname"},
		{"100%", "dns.lookup/100%25"},
		{"a/b/c", "dns.lookup/a%2Fb%2Fc"},
	}

	for _, tt := range tests {
		t.Run(tt.component, func(t *testing.T) {
			if got := EvidenceID("dns.lookup", tt.component); got != tt.want {
				t.Errorf("EvidenceID = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestEvidenceIDIsInjective is the correctness argument for the encoding. Two
// different component lists must never produce one identifier, or two facts
// would silently become one node.
//
// The adversarial pairs are the ones a naive encoding gets wrong: a component
// containing the separator against a component containing its escape, and a
// split of the same text across a component boundary.
func TestEvidenceIDIsInjective(t *testing.T) {
	inputs := [][]string{
		{"a/b"},
		{"a%2Fb"},
		{"a", "b"},
		{"a%2F", "b"},
		{"a", "%2Fb"},
		{"a%25", "b"},
		{"a%", "b"},
		{"", "a"},
		{"a", ""},
		{"a"},
	}

	seen := make(map[domain.EvidenceID][]string, len(inputs))
	for _, components := range inputs {
		id := EvidenceID("step", components...)
		if previous, clash := seen[id]; clash {
			t.Errorf("components %q and %q both produce %q", previous, components, id)
		}
		seen[id] = components
	}
}

func TestEvidenceIDIsDeterministic(t *testing.T) {
	const runs = 100

	first := EvidenceID("tcp.connect", "primary.internal:9092", "10.0.0.1")
	for i := 0; i < runs; i++ {
		if got := EvidenceID("tcp.connect", "primary.internal:9092", "10.0.0.1"); got != first {
			t.Fatalf("run %d produced %q, want %q", i, got, first)
		}
	}
}

// TestEvidenceIDsAreValidIdentifiers keeps the encoding inside what the domain
// accepts. An identifier this package builds must never be rejected by
// domain.NewEvidence, which would turn an encoding detail into a probe failure.
func TestEvidenceIDsAreValidIdentifiers(t *testing.T) {
	components := []string{
		"primary.internal", "primary.internal:9092", "10.0.0.1", "[2001:db8::1]:9092",
		"weird/name", "100%", "name with spaces", "üñïçø∂é.internal",
	}

	for _, component := range components {
		id := EvidenceID("tcp.connect", component, "10.0.0.1")
		if !id.Valid() {
			t.Errorf("component %q produced invalid identifier %q", component, id)
		}
	}
}
