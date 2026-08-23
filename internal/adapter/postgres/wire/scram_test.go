package wire

import (
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/sasl/scram"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// What this file tests after the Phase 6.2 extraction.
//
// The RFC 5802 semantics moved to internal/sasl/scram, and the RFC 7677 vectors
// that prove them moved with them: the derivation, the server-first grammar,
// every bound, the nonce, the SASLname encoding and the mandatory
// server-signature check are pinned there, once, for both services.
//
// What stays here is what this package still owns — PostgreSQL framing, the
// plaintext password and its printable-ASCII policy, the boundary at
// AuthenticationOk, and the guarantee that the shared core is handed a callback
// and never a credential.

func TestPrintableASCIIBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		valid bool
	}{
		{"U+001F unit separator", "pa\x1fss", false},
		{"U+0020 space", "pa ss", true},
		{"ordinary ascii password", canaryASCIIPassword, true},
		{"every printable ascii code point", allPrintableASCII(), true},
		{"U+007E tilde", "pass~", true},
		{"U+007F delete", "pa\x7fss", false},
		{"U+0000 NUL", "pa\x00ss", false},
		{"U+00A0 no-break space", "pa\u00a0ss", false},
		{"U+00AD soft hyphen", "pa\u00adss", false},
		{"U+200B zero-width space", "pa\u200bss", false},
		{"Turkish dotless i", "parola\u0131", false},
		{"European sharp s", "pa\u00dfword", false},
		{"emoji", "pass\U0001F510", false},
		{"invalid UTF-8", "pa\xffss", false},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := printableASCII(tt.in); got != tt.valid {
				t.Errorf("printableASCII(%q) = %v, want %v", tt.in, got, tt.valid)
			}
		})
	}
}

//nolint:gosec // G101: a test canary, not a credential.
const canaryASCIIPassword = "Zx9-QUARK-pw-7Kv2wLpN4tRb"

func allPrintableASCII() string {
	var b strings.Builder
	for c := byte(0x20); c <= 0x7e; c++ {
		b.WriteByte(c)
	}
	return b.String()
}

// TestNonASCIIPasswordSendsNothing proves the refusal happens before a nonce
// exists, before any derivation, and before a byte reaches the socket.
func TestNonASCIIPasswordSendsNothing(t *testing.T) {
	p := scriptedPeer(t, func(conn net.Conn, peer *peer) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			peer.record(buf[:n])
		}
	})
	conn := p.dial(t)

	_, err := AuthenticateSCRAM(testContext(t), conn, security.NewSecret("pa\u00a0ss"))
	if !errors.Is(err, ErrPasswordUnsupported) {
		t.Fatalf("err = %v, want ErrPasswordUnsupported", err)
	}

	// The client returns as soon as it refuses, which can be before the peer's
	// goroutine has had a chance to read anything. Asserting zero immediately
	// would pass even for an implementation that wrote first and checked after,
	// so give a wrong implementation time to be caught.
	time.Sleep(250 * time.Millisecond)
	if got := p.bytesReceived(); len(got) != 0 {
		t.Fatalf("peer received %d bytes before the ASCII check, want 0: %q", len(got), got)
	}
}

// --- server-first parsing ---------------------------------------------------
// TestClientFirstMessageBytes pins the exact SASLInitialResponse svcdoctor
// writes, with a deterministic nonce.
//
// The username field is empty and that is the correct PostgreSQL form: the role
// travelled in the StartupMessage, and a real server ignores this attribute
// entirely. A regression that started sending it would change these bytes.
func TestClientFirstMessageBytes(t *testing.T) {
	const nonce = "FIXEDNONCEfixednonce0000"

	got, err := saslInitialResponse(scram.GS2Header + "n=,r=" + nonce)
	if err != nil {
		t.Fatalf("saslInitialResponse: %v", err)
	}

	payload := "n,,n=,r=" + nonce
	var want []byte
	want = append(want, 'p')
	body := append([]byte("SCRAM-SHA-256"), 0)
	//nolint:gosec // G115: a fixed test payload, far below any bound.
	body = binary.BigEndian.AppendUint32(body, uint32(len(payload)))
	body = append(body, payload...)
	//nolint:gosec // G115: bounded above.
	want = binary.BigEndian.AppendUint32(want, uint32(len(body)+4))
	want = append(want, body...)

	if string(got) != string(want) {
		t.Errorf("client-first frame:\n got %q\nwant %q", got, want)
	}
}

// TestClientFirstCarriesNoRoleName proves no identity reaches the SCRAM layer.
func TestClientFirstCarriesNoRoleName(t *testing.T) {
	frameBytes, err := saslInitialResponse(scram.GS2Header + "n=,r=NONCE")
	if err != nil {
		t.Fatalf("saslInitialResponse: %v", err)
	}
	for _, forbidden := range []string{"payments", "app", "postgres", "@"} {
		if strings.Contains(string(frameBytes), forbidden) {
			t.Errorf("client-first contains %q: %q", forbidden, frameBytes)
		}
	}
	if !strings.Contains(string(frameBytes), "n=,r=") {
		t.Errorf("client-first username field is not empty: %q", frameBytes)
	}
}

// TestWireNeverWritesAFrameItWouldRefuseToRead pins the encode/decode symmetry
// that makes the length conversion safe.
func TestWireNeverWritesAFrameItWouldRefuseToRead(t *testing.T) {
	if _, err := encodeMessage('p', make([]byte, MaxMessageSize+1)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("encodeMessage accepted an oversized body: %v", err)
	}
	if _, err := saslInitialResponse(strings.Repeat("x", MaxMessageSize+1)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("saslInitialResponse accepted an oversized payload: %v", err)
	}
}

// --- the extraction boundary ------------------------------------------------

// TestSCRAMSentinelsAliasTheSharedCore pins the identities Phase 6.2 preserved.
//
// internal/adapter/postgres/authenticate.go classifies with errors.Is against
// these three values. If an alias were replaced by a fresh errors.New with the
// same text, every classification would silently fall through to the default and
// a rejected credential would arrive as a protocol error. Same text, different
// identity, is exactly the failure this catches.
func TestSCRAMSentinelsAliasTheSharedCore(t *testing.T) {
	for _, tt := range []struct {
		name string
		wire error
		core error
	}{
		{"iterations", ErrIterationsUnsupported, scram.ErrIterationsUnsupported},
		{"signature mismatch", ErrServerSignatureMismatch, scram.ErrServerSignatureMismatch},
		{"credential rejected", ErrSCRAMRejected, scram.ErrRejected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.wire, tt.core) || !errors.Is(tt.core, tt.wire) {
				t.Errorf("%v and %v are not the same error identity; errors.Is in the "+
					"adapter's classifier depends on it", tt.wire, tt.core)
			}
		})
	}

	// The two framing sentinels are deliberately **not** aliases. Both already
	// mean something about PostgreSQL framing, and pointing them at the core's
	// equivalents would collapse two meanings onto one identity.
	if errors.Is(ErrMalformedMessage, scram.ErrMalformedMessage) {
		t.Error("ErrMalformedMessage became an alias of the shared core's; " +
			"PostgreSQL framing and SCRAM grammar must stay distinguishable")
	}
	if errors.Is(ErrUnexpectedResponse, scram.ErrUnexpectedResponse) {
		t.Error("ErrUnexpectedResponse became an alias of the shared core's")
	}
}

// TestTranslateSCRAMCoversEverySharedSentinel makes the boundary total.
//
// A core error with no translation would fall through the default and reach the
// adapter as itself, where the classifier has never heard of it and would map it
// to a protocol failure — blaming the target for a value svcdoctor invented.
func TestTranslateSCRAMCoversEverySharedSentinel(t *testing.T) {
	local := []error{
		scram.ErrUsernameUnsupported,
		scram.ErrNoDerivation,
		scram.ErrDerivationFailed,
		scram.ErrDerivedKeyLength,
		scram.ErrWrongStep,
	}
	for _, err := range local {
		if got := translateSCRAM(err); !errors.Is(got, ErrLocalDerivation) {
			t.Errorf("translateSCRAM(%v) = %v, want ErrLocalDerivation: a fault in "+
				"svcdoctor must never be reported as one in the target", err, got)
		}
	}

	for _, tt := range []struct{ in, want error }{
		{scram.ErrMalformedMessage, ErrMalformedMessage},
		{scram.ErrUnexpectedResponse, ErrUnexpectedResponse},
		{scram.ErrMessageTooLarge, ErrFrameTooLarge},
		{scram.ErrIterationsUnsupported, ErrIterationsUnsupported},
		{scram.ErrServerSignatureMismatch, ErrServerSignatureMismatch},
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

// TestDerivationClosureCapturesOnlyThePassword guards the one authority Model D
// cannot remove.
//
// The shared core invokes a callback this package supplies, and it cannot see
// what that callback closed over. A closure capturing the connection, the
// context or the secret would hand the core the ability to cause I/O or to reach
// a credential — not because the core asked, but because the caller passed it
// in. ADR 0056 section 11 records this as a residual risk with review as the
// primary control; this test is the mechanical part of that control.
//
// It is deliberately a *denylist* of the identifiers in scope at the call site,
// not an allowlist of what the closure may name: an allowlist would have to
// enumerate every package-level function the derivation legitimately calls, and
// would fail on the next harmless refactor while catching nothing extra.
func TestDerivationClosureCapturesOnlyThePassword(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "scram.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing scram.go: %v", err)
	}

	// Everything in scope at the call site that the closure must not reach.
	forbidden := map[string]string{
		"conn":     "the connection would let the shared core cause I/O",
		"ctx":      "the context is the caller's execution budget, not the core's",
		"secret":   "the core receives derived material, never a security.Secret",
		"release":  "the deadline's lifetime belongs to this function",
		"exchange": "the closure must not be able to re-enter the exchange",
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
		t.Errorf("found %d function literal(s) in scram.go, want exactly 1 (the derivation "+
			"callback). A second one would not be covered by the capture check above.", literals)
	}
}
