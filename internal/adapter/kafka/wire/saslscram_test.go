package wire

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/sasl/scram"
)

// TestKafkaDerivationClosureCapturesOnlyThePassword guards the one authority
// Model D cannot remove.
//
// internal/sasl/scram invokes a callback this package supplies, and it cannot
// see what that callback closed over. A closure capturing the connection, the
// context or the secret would hand the shared core the ability to cause I/O or
// to reach a credential — not because the core asked, but because the caller
// passed it in. ADR 0056 section 11 records this as a residual risk with review
// as the primary control; this is the mechanical part of that control.
func TestKafkaDerivationClosureCapturesOnlyThePassword(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "saslscram.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing saslscram.go: %v", err)
	}

	forbidden := map[string]string{
		"conn":          "the connection would let the shared core cause I/O",
		"ctx":           "the context is the caller's execution budget, not the core's",
		"secret":        "the core receives derived material, never a security.Secret",
		"exchangeState": "the closure must not be able to re-enter the exchange",
		"first":         "the peer's server-first token has no business inside the derivation",
	}

	literals := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		literals++
		ast.Inspect(lit, func(inner ast.Node) bool {
			ident, ok := inner.(*ast.Ident)
			if !ok {
				return true
			}
			if reason, banned := forbidden[ident.Name]; banned {
				t.Errorf("the derivation closure names %q at line %d: %s",
					ident.Name, fset.Position(ident.Pos()).Line, reason)
			}
			return true
		})
		return true
	})

	if literals != 1 {
		t.Errorf("found %d function literal(s) in saslscram.go, want exactly 1 (the "+
			"derivation callback). A second one would not be covered by the check above.", literals)
	}
}

// TestKafkaWireRevealsOnceAndOnlyInAuthenticate pins this package's credential
// surface.
//
// Phase 6.2 first gave PLAIN and SCRAM an exported exchange each, and each
// revealed its own secret. That is an ordinary structure and it quietly took the
// repository from two production reveal sites to three, which every ADR from
// 0027 onward states as an invariant. Revealing once and dispatching on the
// plaintext is what keeps the count where it belongs; this fails if the split
// comes back.
func TestKafkaWireRevealsOnceAndOnlyInAuthenticate(t *testing.T) {
	counts := map[string]int{}

	for _, name := range []string{
		"authenticate.go", "saslauthenticate.go", "saslscram.go",
		"saslhandshake.go", "apiversions.go", "metadata.go", "exchange.go", "doc.go",
	} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "security" || sel.Sel.Name != "Reveal" {
				return true
			}
			counts[name]++
			return true
		})
	}

	for name, count := range counts {
		if name != "authenticate.go" {
			t.Errorf("%s calls security.Reveal %d time(s); Authenticate is this package's "+
				"single reveal boundary", name, count)
		}
	}
	if counts["authenticate.go"] != 1 {
		t.Errorf("authenticate.go calls security.Reveal %d times, want exactly 1",
			counts["authenticate.go"])
	}
}

// TestSCRAMSentinelsAliasTheSharedCore pins the identities the extraction
// preserved, and the ones it deliberately did not.
func TestSCRAMSentinelsAliasTheSharedCore(t *testing.T) {
	for _, tt := range []struct {
		name       string
		wire, core error
	}{
		{"iterations", ErrSCRAMIterationsUnsupported, scram.ErrIterationsUnsupported},
		{"signature mismatch", ErrSCRAMServerSignatureMismatch, scram.ErrServerSignatureMismatch},
		{"credential rejected", ErrSCRAMRejected, scram.ErrRejected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.wire, tt.core) || !errors.Is(tt.core, tt.wire) {
				t.Errorf("%v and %v are not the same error identity", tt.wire, tt.core)
			}
		})
	}

	// The Kafka framing sentinels must stay distinguishable from the core's.
	if errors.Is(ErrMalformedResponse, scram.ErrMalformedMessage) {
		t.Error("ErrMalformedResponse became an alias of the shared core's; Kafka framing " +
			"and SCRAM grammar must stay distinguishable")
	}
}

// TestTranslateSCRAMCoversEverySharedSentinel makes the boundary total.
//
// A core error with no translation would reach the adapter as itself, where the
// classifier has never heard of it and would map it to a protocol failure —
// blaming the broker for a value svcdoctor invented.
func TestTranslateSCRAMCoversEverySharedSentinel(t *testing.T) {
	for _, err := range []error{
		scram.ErrUsernameUnsupported,
	} {
		if got := translateSCRAM(err); !errors.Is(got, ErrSCRAMUsernameUnsupported) {
			t.Errorf("translateSCRAM(%v) = %v, want ErrSCRAMUsernameUnsupported", err, got)
		}
	}
	for _, err := range []error{
		scram.ErrNoDerivation,
		scram.ErrDerivationFailed,
		scram.ErrDerivedKeyLength,
		scram.ErrWrongStep,
	} {
		if got := translateSCRAM(err); !errors.Is(got, ErrSCRAMLocalDerivation) {
			t.Errorf("translateSCRAM(%v) = %v, want ErrSCRAMLocalDerivation: a fault in "+
				"svcdoctor must never be reported as one in the broker", err, got)
		}
	}
	for _, tt := range []struct{ in, want error }{
		{scram.ErrMalformedMessage, ErrMalformedResponse},
		{scram.ErrMessageTooLarge, ErrSCRAMParametersUnsupported},
		{scram.ErrUnexpectedResponse, ErrNotKafka},
		{scram.ErrIterationsUnsupported, ErrSCRAMIterationsUnsupported},
		{scram.ErrServerSignatureMismatch, ErrSCRAMServerSignatureMismatch},
		{scram.ErrRejected, ErrSCRAMRejected},
	} {
		if got := translateSCRAM(tt.in); !errors.Is(got, tt.want) {
			t.Errorf("translateSCRAM(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
	if translateSCRAM(nil) != nil {
		t.Error("translateSCRAM(nil) must stay nil")
	}
}

// TestSCRAMCapabilityRefusalsCarryNoCredential proves the refusals that happen
// before any I/O say nothing about the values that caused them.
func TestSCRAMCapabilityRefusalsCarryNoCredential(t *testing.T) {
	for _, err := range []error{ErrSCRAMUsernameUnsupported, ErrSCRAMPasswordUnsupported} {
		text := err.Error()
		for _, forbidden := range []string{"hunter", "canary", "@", "="} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%q looks like it could carry a value", text)
			}
		}
	}
}

// TestPrintableASCIIBoundaries pins the range, and that it is the same one
// PostgreSQL uses.
func TestPrintableASCIIBoundaries(t *testing.T) {
	for _, tt := range []struct {
		in    string
		valid bool
	}{
		{"", true},
		{"ordinary", true},
		{" leading space", true},
		{"~", true},
		{"a\x1fb", false},
		{"a\x7fb", false},
		{"a\x00b", false},
		{"a b", false},
		{"a\u00adb", false},
		{"a\xffb", false},
	} {
		if got := printableASCII(tt.in); got != tt.valid {
			t.Errorf("printableASCII(%q) = %v, want %v", tt.in, got, tt.valid)
		}
	}
}
