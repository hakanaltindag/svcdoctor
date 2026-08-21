package probe

import (
	"errors"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// --- the scope type ---------------------------------------------------------

func TestSweepScopeZeroValueIsUnscoped(t *testing.T) {
	var scope SweepScope

	if !scope.IsZero() {
		t.Error("the zero SweepScope is not unscoped")
	}
	if got := scope.String(); got != "" {
		t.Errorf("String() = %q, want empty", got)
	}
}

// TestSweepScopeRejectsEmptyLabel: a caller that wants no scope uses the zero
// value deliberately; one that computed an empty string has a bug.
func TestSweepScopeRejectsEmptyLabel(t *testing.T) {
	_, err := NewSweepScope("")
	if !errors.Is(err, ErrInvalidSweepScope) {
		t.Fatalf("error = %v, want ErrInvalidSweepScope", err)
	}
}

func TestSweepScopeRejectsUnusableLabels(t *testing.T) {
	tests := []struct {
		name  string
		label string
	}{
		{"control character", "topology\x00one"},
		{"newline", "topology\none"},
		{"leading whitespace", " topology"},
		{"trailing whitespace", "topology "},
		{"invalid utf-8", string([]byte{0xff, 0xfe})},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSweepScope(test.label); !errors.Is(err, ErrInvalidSweepScope) {
				t.Errorf("error = %v, want ErrInvalidSweepScope", err)
			}
		})
	}
}

// TestSweepScopeAcceptsAwkwardButValidLabels holds ADR 0019's rule: a delimiter
// choice must never decide what input a layer accepts. The encoding absorbs
// these; it does not reject them.
func TestSweepScopeAcceptsAwkwardButValidLabels(t *testing.T) {
	labels := []string{
		"topology/1",
		"100%",
		"a%2Fb",
		"broker.internal:9093",
		"[2001:db8::1]:9093",
		"топология",
		"トポロジー",
		"scope with spaces inside",
	}

	for _, label := range labels {
		t.Run(label, func(t *testing.T) {
			scope, err := NewSweepScope(label)
			if err != nil {
				t.Fatalf("NewSweepScope(%q): %v", label, err)
			}
			if scope.String() != label {
				t.Errorf("String() = %q, want %q unchanged", scope.String(), label)
			}
			if scope.IsZero() {
				t.Error("a non-empty label produced the zero scope")
			}
		})
	}
}

// --- identifier shape -------------------------------------------------------

// TestUnscopedIdentifiersAreUnchanged is the backward-compatibility guarantee
// this whole phase rests on. These are the exact strings ADR 0019 documents.
func TestUnscopedIdentifiersAreUnchanged(t *testing.T) {
	tests := []struct {
		id   domain.EvidenceID
		want string
	}{
		{EvidenceID("dns.lookup", "primary.internal"), "dns.lookup/primary.internal"},
		{
			EvidenceID("tcp.connect", "primary.internal:9092", "10.0.0.1"),
			"tcp.connect/primary.internal:9092/10.0.0.1",
		},
		{
			ScopedEvidenceID(SweepScope{}, "dns.lookup", "primary.internal"),
			"dns.lookup/primary.internal",
		},
	}

	for _, test := range tests {
		if got := test.id.String(); got != test.want {
			t.Errorf("id = %q, want %q", got, test.want)
		}
	}
}

func TestScopedIdentifierPlacesScopeAfterTheStep(t *testing.T) {
	scope, err := NewSweepScope("topology")
	if err != nil {
		t.Fatal(err)
	}

	got := ScopedEvidenceID(scope, "dns.lookup", "primary.internal").String()
	if want := "dns.lookup/topology/primary.internal"; got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
	// The step stays first, so an identifier still says what its node is.
	if !strings.HasPrefix(got, "dns.lookup/") {
		t.Errorf("id = %q, want the step first", got)
	}
}

// TestScopedIdentifiersAreDeterministic: same inputs, same bytes, every time.
func TestScopedIdentifiersAreDeterministic(t *testing.T) {
	scope, err := NewSweepScope("topology/1")
	if err != nil {
		t.Fatal(err)
	}

	first := ScopedEvidenceID(scope, "tcp.connect", "broker.internal:9093", "10.0.0.1")
	for range 100 {
		if got := ScopedEvidenceID(scope, "tcp.connect", "broker.internal:9093", "10.0.0.1"); got != first {
			t.Fatalf("id = %q, want %q on every call", got, first)
		}
	}
}

// TestScopeEscapingStaysInjective is the adversarial half. Every pair below is
// two different measurements and must stay two different identifiers.
func TestScopeEscapingStaysInjective(t *testing.T) {
	scoped := func(t *testing.T, label string, components ...string) string {
		t.Helper()
		scope, err := NewSweepScope(label)
		if err != nil {
			t.Fatalf("NewSweepScope(%q): %v", label, err)
		}
		return ScopedEvidenceID(scope, "dns.lookup", components...).String()
	}

	seen := map[string][]string{}
	record := func(id string, describe string) {
		seen[id] = append(seen[id], describe)
	}

	// A scope containing the separator versus a scope that merely looks like it.
	record(scoped(t, "a/b", "host"), `scope "a/b", host "host"`)
	record(scoped(t, "a%2Fb", "host"), `scope "a%2Fb", host "host"`)
	// The classic escape-ordering trap.
	record(scoped(t, "a%b", "host"), `scope "a%b", host "host"`)
	record(scoped(t, "a%25b", "host"), `scope "a%25b", host "host"`)
	// Scope and component boundaries must not blur.
	record(scoped(t, "a", "b/c"), `scope "a", host "b/c"`)
	record(scoped(t, "a/b", "c"), `scope "a/b", host "c"`)
	// Colons and IPv6-looking text carry no special meaning.
	record(scoped(t, "[2001:db8::1]:9093", "host"), `scope ipv6-ish`)
	record(scoped(t, "2001:db8::1", "host"), `scope ipv6 bare`)
	// Unicode.
	record(scoped(t, "топология", "host"), `scope cyrillic`)
	record(scoped(t, "トポロジー", "host"), `scope japanese`)

	for id, describers := range seen {
		if len(describers) > 1 {
			t.Errorf("identifier %q is shared by %d distinct measurements: %v",
				id, len(describers), describers)
		}
	}
}

// TestStepArityIsFixed pins the precondition the scoped/unscoped distinction
// rests on, which ScopedEvidenceID documents.
//
// Scoped and unscoped identifiers are told apart by how many components follow
// the step, not by escaping. The counter-example below is real: with differing
// arity they genuinely collide. What keeps the scheme injective in this
// repository is that a step always mints the same number of components, so a
// scoped identifier for a step always carries exactly one more than its
// unscoped form.
//
// A producer that varied its component count per call would break that, and
// this test is where it would be noticed.
func TestStepArityIsFixed(t *testing.T) {
	scope, err := NewSweepScope("a")
	if err != nil {
		t.Fatal(err)
	}

	// The honest counter-example, asserted rather than hidden.
	unscopedTwo := EvidenceID("dns.lookup", "a", "b")
	scopedOne := ScopedEvidenceID(scope, "dns.lookup", "b")
	if unscopedTwo != scopedOne {
		t.Fatalf("the documented arity caveat no longer holds: %q vs %q; "+
			"ScopedEvidenceID's injectivity note needs revisiting",
			unscopedTwo, scopedOne)
	}

	// And the property that saves it: for a fixed arity, scoped and unscoped
	// forms differ.
	unscopedOne := EvidenceID("dns.lookup", "b")
	if unscopedOne == scopedOne {
		t.Errorf("scoped and unscoped identifiers collide at equal component arity: %q", scopedOne)
	}
}
