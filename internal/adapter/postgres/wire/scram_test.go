package wire

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// --- the external authority -----------------------------------------------

// RFC 7677 section 3 is the published SCRAM-SHA-256 test vector.
//
// It is the only test here that proves the derivation is *correct* rather than
// self-consistent: every value below was written by the RFC, not by this
// repository, so a mistake in PBKDF2, in the HMAC chain, in the auth-message
// construction or in the channel-binding value fails it.
const (
	rfcPassword        = "pencil"
	rfcClientNonce     = "rOprNGfwEbeRWgbNEkqO"
	rfcServerNonce     = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	rfcSaltBase64      = "W22ZaJ0SNY7soEsUEjb6gQ=="
	rfcIterations      = 4096
	rfcClientFirstBare = "n=user,r=" + rfcClientNonce
	rfcServerFirst     = "r=" + rfcServerNonce + ",s=" + rfcSaltBase64 + ",i=4096"
	rfcClientProof     = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	rfcServerSignature = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
)

func TestDeriveMatchesRFC7677Vector(t *testing.T) {
	salt, err := base64.StdEncoding.DecodeString(rfcSaltBase64)
	if err != nil {
		t.Fatalf("decoding vector salt: %v", err)
	}

	first := serverFirst{nonce: rfcServerNonce, salt: salt, iterations: rfcIterations}
	clientFinal, signature, err := derive(rfcPassword, rfcClientFirstBare, rfcServerFirst, first)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	wantFinal := "c=biws,r=" + rfcServerNonce + ",p=" + rfcClientProof
	if clientFinal != wantFinal {
		t.Errorf("client-final:\n got %q\nwant %q", clientFinal, wantFinal)
	}
	if got := base64.StdEncoding.EncodeToString(signature); got != rfcServerSignature {
		t.Errorf("server signature = %q, want %q", got, rfcServerSignature)
	}
}

// TestChannelBindingValueIsComputedNotHardcoded proves "biws" is base64 of the
// header actually sent, so the two cannot drift apart silently.
func TestChannelBindingValueIsComputedNotHardcoded(t *testing.T) {
	if got := base64.StdEncoding.EncodeToString([]byte(gs2Header)); got != "biws" {
		t.Fatalf("base64(%q) = %q, want biws", gs2Header, got)
	}
}

// TestGS2HeaderNeverClaimsChannelBindingSupport pins the one header PostgreSQL
// accepts from a client that does not implement channel binding.
//
// "y,," is a downgrade claim and a real server refuses it with 28000 when it
// does offer -PLUS; an authzid is refused outright with 0A000.
func TestGS2HeaderNeverClaimsChannelBindingSupport(t *testing.T) {
	if gs2Header != "n,," {
		t.Fatalf("gs2 header = %q, want %q", gs2Header, "n,,")
	}
}

// --- printable ASCII -------------------------------------------------------

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

func TestParseServerFirst(t *testing.T) {
	const clientNonce = "CLIENTNONCE"
	const goodSalt = "MDEyMzQ1Njc4OWFiY2RlZg=="

	tests := []struct {
		name string
		raw  string
		want error // nil means accepted
	}{
		{"well formed", "r=" + clientNonce + "XYZ,s=" + goodSalt + ",i=4096", nil},
		{"unknown extension ignored", "r=" + clientNonce + "XYZ,s=" + goodSalt + ",i=4096,x=whatever", nil},

		{"missing r", "s=" + goodSalt + ",i=4096", ErrMalformedMessage},
		{"missing s", "r=" + clientNonce + "XYZ,i=4096", ErrMalformedMessage},
		{"missing i", "r=" + clientNonce + "XYZ,s=" + goodSalt, ErrMalformedMessage},
		{"duplicate r", "r=" + clientNonce + "XYZ,r=" + clientNonce + "XYZ,s=" + goodSalt + ",i=4096", ErrMalformedMessage},
		{"duplicate s", "r=" + clientNonce + "XYZ,s=" + goodSalt + ",s=" + goodSalt + ",i=4096", ErrMalformedMessage},
		{"duplicate i", "r=" + clientNonce + "XYZ,s=" + goodSalt + ",i=4096,i=4096", ErrMalformedMessage},

		{"nonce does not extend", "r=OTHERNONCE,s=" + goodSalt + ",i=4096", ErrMalformedMessage},
		{"nonce equal to client nonce", "r=" + clientNonce + ",s=" + goodSalt + ",i=4096", ErrMalformedMessage},
		{"nonce is a prefix but shorter", "r=CLIENT,s=" + goodSalt + ",i=4096", ErrMalformedMessage},
		{"nonce empty", "r=,s=" + goodSalt + ",i=4096", ErrMalformedMessage},

		{"salt not base64", "r=" + clientNonce + "XYZ,s=!!!!,i=4096", ErrMalformedMessage},
		{"attribute without equals", "r=" + clientNonce + "XYZ,ssss,i=4096", ErrMalformedMessage},
		{"empty attribute", "r=" + clientNonce + "XYZ,,i=4096", ErrMalformedMessage},
		{"mandatory extension", "m=required,r=" + clientNonce + "XYZ,s=" + goodSalt + ",i=4096", ErrUnexpectedResponse},

		{"iterations zero", "r=" + clientNonce + "XYZ,s=" + goodSalt + ",i=0", ErrMalformedMessage},
		{"iterations negative", "r=" + clientNonce + "XYZ,s=" + goodSalt + ",i=-1", ErrMalformedMessage},
		{"iterations not a number", "r=" + clientNonce + "XYZ,s=" + goodSalt + ",i=4x", ErrMalformedMessage},
		{"iterations empty", "r=" + clientNonce + "XYZ,s=" + goodSalt + ",i=", ErrMalformedMessage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseServerFirst(tt.raw, clientNonce)
			switch {
			case tt.want == nil && err != nil:
				t.Fatalf("parseServerFirst = %v, want accepted", err)
			case tt.want != nil && !errors.Is(err, tt.want):
				t.Fatalf("parseServerFirst = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestServerNonceMustStrictlyExtend states the rule on its own, because it is
// two conditions and a mutation that drops either one is a real weakening.
//
// RFC 5802 section 5 requires the prefix check. The length check is separate: a
// nonce equal to the client's carries no server entropy and defeats the replay
// protection the nonce exists for.
func TestServerNonceMustStrictlyExtend(t *testing.T) {
	const nonce = "abcdefghijkl"
	const salt = ",s=MDEyMzQ1Njc4OWFiY2RlZg==,i=4096"

	if _, err := parseServerFirst("r="+nonce+"Q"+salt, nonce); err != nil {
		t.Fatalf("a strictly extending nonce was refused: %v", err)
	}
	if _, err := parseServerFirst("r="+nonce+salt, nonce); err == nil {
		t.Fatal("a server nonce equal to the client nonce was accepted")
	}
}

// --- iteration bounds -------------------------------------------------------

func TestParseIterations(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
		err  error
	}{
		{"one", "1", 1, nil},
		{"below the RFC floor", "4095", 4095, nil},
		{"the RFC floor", "4096", 4096, nil},
		{"postgresql default", "4096", 4096, nil},
		{"a real hardened value", "65536", 65536, nil},
		{"the ceiling", "1048576", MaxSCRAMIterations, nil},

		{"one above the ceiling", "1048577", 0, ErrIterationsUnsupported},
		{"postgresql's own maximum", "2147483647", 0, ErrIterationsUnsupported},
		{"beyond uint64", "99999999999999999999999999", 0, ErrIterationsUnsupported},

		{"zero", "0", 0, ErrMalformedMessage},
		{"negative", "-1", 0, ErrMalformedMessage},
		{"trailing garbage", "4096x", 0, ErrMalformedMessage},
		{"empty", "", 0, ErrMalformedMessage},
		{"whitespace", " 4096", 0, ErrMalformedMessage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIterations(tt.in)
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Fatalf("parseIterations(%q) err = %v, want %v", tt.in, err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseIterations(%q) = %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseIterations(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// TestExcessiveIterationsCostNothing proves the ceiling is enforced before any
// PBKDF2 work, not after it.
//
// PostgreSQL's own maximum would take minutes of CPU. If this test ever becomes
// slow, the check moved after the derivation and the guard is gone.
func TestExcessiveIterationsCostNothing(t *testing.T) {
	_, err := parseServerFirst(
		"r=CLIENTX,s=MDEyMzQ1Njc4OWFiY2RlZg==,i=2147483647", "CLIENT")
	if !errors.Is(err, ErrIterationsUnsupported) {
		t.Fatalf("err = %v, want ErrIterationsUnsupported", err)
	}
}

// TestLowIterationCountsAreAcceptedNotRefused pins a deliberate decision: RFC
// 7677 says SHOULD, PostgreSQL's minimum is 1, and refusing would make svcdoctor
// blind to the weak configuration it ought to be reporting.
func TestLowIterationCountsAreAcceptedNotRefused(t *testing.T) {
	first, err := parseServerFirst("r=CLIENTX,s=MDEyMzQ1Njc4OWFiY2RlZg==,i=1", "CLIENT")
	if err != nil {
		t.Fatalf("i=1 was refused: %v", err)
	}
	if first.iterations != 1 {
		t.Errorf("iterations = %d, want 1", first.iterations)
	}
}

// --- server-final -----------------------------------------------------------

func TestVerifyServerFinal(t *testing.T) {
	expected := []byte("0123456789abcdef0123456789abcdef")
	good := base64.StdEncoding.EncodeToString(expected)
	other := base64.StdEncoding.EncodeToString([]byte("ffffffffffffffffffffffffffffffff"))

	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"correct signature", "v=" + good, nil},
		{"correct signature with an extension", "v=" + good + ",x=ignored", nil},
		{"wrong signature", "v=" + other, ErrServerSignatureMismatch},
		{"truncated signature", "v=" + good[:20], ErrServerSignatureMismatch},
		{"signature not base64", "v=!!!!", ErrMalformedMessage},
		{"empty signature", "v=", ErrServerSignatureMismatch},

		{"invalid-proof", "e=invalid-proof", ErrSCRAMRejected},
		{"unknown-user", "e=unknown-user", ErrSCRAMRejected},
		// Not a credential refusal: an encoding fault in the username field.
		// Unreachable in practice — this client sends an empty username — and
		// classified conservatively rather than as a rejection.
		{"invalid-username-encoding", "e=invalid-username-encoding", ErrUnexpectedResponse},
		{"other-error", "e=other-error", ErrUnexpectedResponse},
		{"no-resources", "e=no-resources", ErrUnexpectedResponse},
		{"an extension token", "e=vendor-specific-thing", ErrUnexpectedResponse},

		{"neither v nor e", "x=something", ErrMalformedMessage},
		{"empty", "", ErrMalformedMessage},
		{"no equals", "vvvv", ErrMalformedMessage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyServerFinal(tt.raw, expected)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("verifyServerFinal = %v, want accepted", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("verifyServerFinal = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestServerErrorTokenIsNeverReturned proves the peer's SCRAM error token cannot
// reach a caller, since RFC 5802's extension production means it is not a closed
// set and a peer may put arbitrary text there.
func TestServerErrorTokenIsNeverReturned(t *testing.T) {
	const hostile = "role=admin@prod-db.internal 10.0.0.5"

	err := verifyServerFinal("e="+hostile, []byte("irrelevant"))
	if err == nil {
		t.Fatal("a hostile error token was accepted")
	}
	if strings.Contains(err.Error(), hostile) || strings.Contains(err.Error(), "prod-db") {
		t.Fatalf("the peer's token reached the error: %q", err)
	}
}

// --- nonce ------------------------------------------------------------------

// TestCryptoNonceShape pins the shape libpq uses: 18 raw bytes, base64-encoded
// to 24 characters with no padding.
func TestCryptoNonceShape(t *testing.T) {
	seen := make(map[string]struct{})
	for range 64 {
		nonce, err := cryptoNonce()
		if err != nil {
			t.Fatalf("cryptoNonce: %v", err)
		}
		if len(nonce) != 24 {
			t.Fatalf("nonce %q has length %d, want 24", nonce, len(nonce))
		}
		if strings.Contains(nonce, "=") {
			t.Fatalf("nonce %q carries base64 padding", nonce)
		}
		if strings.Contains(nonce, ",") {
			t.Fatalf("nonce %q contains a comma, which SCRAM forbids", nonce)
		}
		raw, err := base64.StdEncoding.DecodeString(nonce)
		if err != nil || len(raw) != scramRawNonceLen {
			t.Fatalf("nonce %q did not decode to %d bytes", nonce, scramRawNonceLen)
		}
		if _, repeat := seen[nonce]; repeat {
			t.Fatalf("cryptoNonce repeated %q", nonce)
		}
		seen[nonce] = struct{}{}
	}
}

// --- exact client bytes -----------------------------------------------------

// TestClientFirstMessageBytes pins the exact SASLInitialResponse svcdoctor
// writes, with a deterministic nonce.
//
// The username field is empty and that is the correct PostgreSQL form: the role
// travelled in the StartupMessage, and a real server ignores this attribute
// entirely. A regression that started sending it would change these bytes.
func TestClientFirstMessageBytes(t *testing.T) {
	const nonce = "FIXEDNONCEfixednonce0000"

	got, err := saslInitialResponse(gs2Header + "n=,r=" + nonce)
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
	frameBytes, err := saslInitialResponse(gs2Header + "n=,r=NONCE")
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
