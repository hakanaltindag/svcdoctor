package scram

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// RFC 7677 section 3 publishes a complete SCRAM-SHA-256 exchange. Everything
// below is **public specification material**, not a fixture secret: the
// username "user" and the password "pencil" appear verbatim in the RFC, and any
// scanner or reviewer should read them as the published vector they are.
//
// The proof and the server signature are the RFC's own values. The
// intermediates are not published by the RFC; they are pinned here so that a
// future refactor that changes one of them fails on the exact step rather than
// only on the final output.
const (
	rfcUsername    = Username("user")
	rfcPassword    = "pencil" // public RFC 7677 vector material, not a secret
	rfcClientNonce = "rOprNGfwEbeRWgbNEkqO"
	rfcServerNonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	rfcSaltBase64  = "W22ZaJ0SNY7soEsUEjb6gQ=="
	rfcIterations  = 4096

	rfcClientFirstBare = "n=user,r=" + rfcClientNonce
	rfcServerFirst     = "r=" + rfcServerNonce + ",s=" + rfcSaltBase64 + ",i=4096"
	rfcClientFinal     = "c=biws,r=" + rfcServerNonce + ",p=" + rfcClientProof

	// gosec reads the next line as a hardcoded credential, and in the sense it
	// checks it is one: it is the SaltedPassword for "pencil" under RFC 7677's
	// published salt. It is **public specification material**, reachable by
	// anyone with the RFC, and it authenticates nothing anywhere. The
	// suppression is single-line and named so that a real credential added
	// beside it would still be flagged.
	rfcSaltedPassword  = "xKSVEDI6tPlSysH6mUQZOeeOp01r6B3fcJbodRPcYV0=" //nolint:gosec // RFC 7677 public test vector, not a credential
	rfcClientKey       = "pg/JI9Z+hkSpLRa5btpe9GVrDHJcSEN0viVTVXaZbos="
	rfcStoredKey       = "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY="
	rfcClientSignature = "0nMSRnwopAqKfwXHPA3jPrPL+0qDeDtYFEzxmsa+G98="
	rfcClientProof     = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	rfcServerKey       = "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
	rfcServerSignature = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="

	rfcAuthMessage = rfcClientFirstBare + "," + rfcServerFirst + ",c=biws,r=" + rfcServerNonce
)

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding vector %q: %v", s, err)
	}
	return b
}

// fixedNonce is the deterministic seam this package's own tests use. It is
// unexported and unreachable from any other package, which is the whole reason
// Begin takes no nonce parameter.
func fixedNonce(n string) nonceSource {
	return func() (string, error) { return n, nil }
}

// counter records how many times a Derive callback ran. Every rejection test
// asserts it stayed at zero, which is the property the validation order exists
// to hold.
type counter struct {
	calls      int
	salt       []byte
	iterations int
	give       []byte
	giveErr    error
}

func (c *counter) derive(salt []byte, iterations int) ([]byte, error) {
	c.calls++
	c.salt = append([]byte(nil), salt...)
	c.iterations = iterations
	if c.giveErr != nil {
		return nil, c.giveErr
	}
	return c.give, nil
}

// --- derivation vectors -----------------------------------------------------

// TestRFC7677Exchange runs the published vector end to end through the real API.
func TestRFC7677Exchange(t *testing.T) {
	state, bare, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if bare != rfcClientFirstBare {
		t.Fatalf("client-first-bare = %q, want %q", bare, rfcClientFirstBare)
	}

	fake := &counter{give: decode(t, rfcSaltedPassword)}
	final, err := state.Continue(rfcServerFirst, fake.derive)
	if err != nil {
		t.Fatalf("continue: %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("derive called %d times, want exactly 1", fake.calls)
	}
	if fake.iterations != rfcIterations {
		t.Errorf("derive got iterations %d, want %d", fake.iterations, rfcIterations)
	}
	if got := base64.StdEncoding.EncodeToString(fake.salt); got != rfcSaltBase64 {
		t.Errorf("derive got salt %q, want %q", got, rfcSaltBase64)
	}
	if final != rfcClientFinal {
		t.Errorf("client-final:\n got %q\nwant %q", final, rfcClientFinal)
	}

	if err := state.Verify("v=" + rfcServerSignature); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestRFC7677Intermediates pins every derived value the exchange produces, so a
// refactor that breaks one fails on that step rather than only at the end.
func TestRFC7677Intermediates(t *testing.T) {
	salted := decode(t, rfcSaltedPassword)

	clientKey := mac(salted, []byte("Client Key"))
	if got := base64.StdEncoding.EncodeToString(clientKey); got != rfcClientKey {
		t.Errorf("ClientKey = %q, want %q", got, rfcClientKey)
	}

	state := &State{step: stepBegun, clientFirstBare: rfcClientFirstBare, clientNonce: rfcClientNonce}
	first := serverFirst{nonce: rfcServerNonce, salt: decode(t, rfcSaltBase64), iterations: rfcIterations}
	final, expected := state.finish(rfcServerFirst, first, salted)

	if final != rfcClientFinal {
		t.Errorf("client-final = %q, want %q", final, rfcClientFinal)
	}
	if got := base64.StdEncoding.EncodeToString(expected); got != rfcServerSignature {
		t.Errorf("ServerSignature = %q, want %q", got, rfcServerSignature)
	}

	// The AuthMessage is not returned by anything, on purpose. Rebuilding it
	// here from the same parts pins its exact shape.
	withoutProof := "c=biws,r=" + rfcServerNonce
	if got := rfcClientFirstBare + "," + rfcServerFirst + "," + withoutProof; got != rfcAuthMessage {
		t.Errorf("AuthMessage = %q, want %q", got, rfcAuthMessage)
	}
	storedKey := decode(t, rfcStoredKey)
	if got := base64.StdEncoding.EncodeToString(mac(storedKey, []byte(rfcAuthMessage))); got != rfcClientSignature {
		t.Errorf("ClientSignature = %q, want %q", got, rfcClientSignature)
	}
	if got := base64.StdEncoding.EncodeToString(mac(decode(t, rfcServerKey), []byte(rfcAuthMessage))); got != rfcServerSignature {
		t.Errorf("ServerSignature from ServerKey = %q, want %q", got, rfcServerSignature)
	}
}

// TestGS2HeaderAndChannelBinding pins the one header PostgreSQL accepts from a
// client with no channel binding, and proves "biws" is computed from it rather
// than written down twice.
func TestGS2HeaderAndChannelBinding(t *testing.T) {
	if GS2Header != "n,," {
		t.Fatalf("GS2Header = %q, want %q", GS2Header, "n,,")
	}
	if got := base64.StdEncoding.EncodeToString([]byte(GS2Header)); got != "biws" {
		t.Fatalf("base64(%q) = %q, want biws", GS2Header, got)
	}
}

// --- message-construction vectors -------------------------------------------

// TestSASLnameConstruction is the case the extracted PostgreSQL vector could not
// reach: it passed a literal client-first-bare into the derivation, so escaping
// was never exercised. Kafka reads the principal from this field.
func TestSASLnameConstruction(t *testing.T) {
	tests := []struct {
		name string
		user Username
		want string
	}{
		{"ordinary ascii", "alice", "n=alice,r=" + rfcClientNonce},
		{"empty, as PostgreSQL sends", "", "n=,r=" + rfcClientNonce},
		{"comma", "a,b", "n=a=2Cb,r=" + rfcClientNonce},
		{"equals", "a=b", "n=a=3Db,r=" + rfcClientNonce},
		{"comma and equals", "a,b=c", "n=a=2Cb=3Dc,r=" + rfcClientNonce},
		{"only separators", ",=", "n==2C=3D,r=" + rfcClientNonce},
		{"escape-looking input is escaped again", "=2C", "n==3D2C,r=" + rfcClientNonce},
		{"space is permitted", "a b", "n=a b,r=" + rfcClientNonce},
		{"max length", Username(strings.Repeat("u", maxUsernameLen)),
			"n=" + strings.Repeat("u", maxUsernameLen) + ",r=" + rfcClientNonce},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, bare, err := begin(tt.user, fixedNonce(rfcClientNonce))
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			if bare != tt.want {
				t.Errorf("client-first-bare = %q, want %q", bare, tt.want)
			}
		})
	}
}

// TestUsernameRefusals pins the printable-ASCII policy. Each is a statement
// about svcdoctor, and in each case nothing was produced to send.
func TestUsernameRefusals(t *testing.T) {
	tests := []struct {
		name string
		user Username
	}{
		{"non-breaking space", "a b"},
		{"soft hyphen", "a\u00adb"},
		{"cyrillic", "пользователь"},
		{"emoji", "a\U0001f600"},
		{"invalid utf-8", Username([]byte{0x41, 0xff, 0x42})},
		{"control character", "a\x01b"},
		{"delete", "a\x7fb"},
		{"newline", "a\nb"},
		{"too long", Username(strings.Repeat("u", maxUsernameLen+1))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, bare, err := begin(tt.user, fixedNonce(rfcClientNonce))
			if !errors.Is(err, ErrUsernameUnsupported) {
				t.Fatalf("begin = %v, want ErrUsernameUnsupported", err)
			}
			if state != nil || bare != "" {
				t.Errorf("a refused username produced state=%v bare=%q; nothing may be built", state, bare)
			}
		})
	}
}

// --- validation order: derive must be unreachable ---------------------------

// TestRejectedServerFirstNeverDerives is the core security property in
// executable form: every rejection path leaves the callback uncalled.
func TestRejectedServerFirstNeverDerives(t *testing.T) {
	const n = rfcClientNonce
	long := strings.Repeat("x", maxServerFirstLen+1)
	bigSalt := base64.StdEncoding.EncodeToString(make([]byte, maxSaltLen+8))

	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"oversized message", "r=" + n + "extra,s=" + rfcSaltBase64 + ",i=4096,x=" + long, ErrMessageTooLarge},
		{"missing r", "s=" + rfcSaltBase64 + ",i=4096", ErrMalformedMessage},
		{"missing s", "r=" + n + "extra,i=4096", ErrMalformedMessage},
		{"missing i", "r=" + n + "extra,s=" + rfcSaltBase64, ErrMalformedMessage},
		{"duplicate r", "r=" + n + "a,r=" + n + "b,s=" + rfcSaltBase64 + ",i=4096", ErrMalformedMessage},
		{"duplicate s", "r=" + n + "a,s=" + rfcSaltBase64 + ",s=" + rfcSaltBase64 + ",i=4096", ErrMalformedMessage},
		{"duplicate i", "r=" + n + "a,s=" + rfcSaltBase64 + ",i=4096,i=4096", ErrMalformedMessage},
		{"mandatory extension", "m=required,r=" + n + "a,s=" + rfcSaltBase64 + ",i=4096", ErrUnexpectedResponse},
		{"nonce not extended", "r=" + n + ",s=" + rfcSaltBase64 + ",i=4096", ErrMalformedMessage},
		{"nonce is a different value", "r=zzzz" + n + ",s=" + rfcSaltBase64 + ",i=4096", ErrMalformedMessage},
		{"nonce shorter than the client's", "r=rOpr,s=" + rfcSaltBase64 + ",i=4096", ErrMalformedMessage},
		{"nonce with a space", "r=" + n + " x,s=" + rfcSaltBase64 + ",i=4096", ErrMalformedMessage},
		{"nonce too long", "r=" + n + strings.Repeat("q", maxNonceLen) + ",s=" + rfcSaltBase64 + ",i=4096", ErrMessageTooLarge},
		{"salt not base64", "r=" + n + "a,s=!!!!,i=4096", ErrMalformedMessage},
		{"encoded salt too long", "r=" + n + "a,s=" + strings.Repeat("A", maxSaltEncodedLen+1) + ",i=4096", ErrMessageTooLarge},
		{"decoded salt too long", "r=" + n + "a,s=" + bigSalt + ",i=4096", ErrMessageTooLarge},
		{"iteration zero", "r=" + n + "a,s=" + rfcSaltBase64 + ",i=0", ErrMalformedMessage},
		{"iteration malformed", "r=" + n + "a,s=" + rfcSaltBase64 + ",i=40x96", ErrMalformedMessage},
		{"iteration empty", "r=" + n + "a,s=" + rfcSaltBase64 + ",i=", ErrMalformedMessage},
		{"iteration negative", "r=" + n + "a,s=" + rfcSaltBase64 + ",i=-1", ErrMalformedMessage},
		{"iteration overflow", "r=" + n + "a,s=" + rfcSaltBase64 + ",i=99999999999999999999999", ErrIterationsUnsupported},
		{"iteration above ceiling", "r=" + n + "a,s=" + rfcSaltBase64 + ",i=1048577", ErrIterationsUnsupported},
		{"no equals in an attribute", "rrrr,s=" + rfcSaltBase64 + ",i=4096", ErrMalformedMessage},
		{"empty attribute", ",r=" + n + "a", ErrMalformedMessage},
		{"empty message", "", ErrMalformedMessage},
		{"too many attributes", "r=" + n + "a,s=" + rfcSaltBase64 + ",i=4096" + strings.Repeat(",x=1", maxAttributes), ErrMalformedMessage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, _, err := begin(rfcUsername, fixedNonce(n))
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			fake := &counter{give: make([]byte, DerivedKeyLen)}

			final, err := state.Continue(tt.raw, fake.derive)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Continue = %v, want %v", err, tt.want)
			}
			if fake.calls != 0 {
				t.Errorf("derive ran %d times on a rejected server-first; it must never run", fake.calls)
			}
			if final != "" {
				t.Errorf("a rejected server-first produced %q; nothing may be built", final)
			}
		})
	}
}

// TestAcceptedIterationBoundaries pins both edges of the ceiling and the low end
// the RFC only SHOULDs.
func TestAcceptedIterationBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name string
		i    string
		want int
	}{
		{"one", "1", 1},
		{"postgres default", "4096", 4096},
		{"exactly the ceiling", "1048576", MaxIterations},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			fake := &counter{give: make([]byte, DerivedKeyLen)}
			raw := "r=" + rfcClientNonce + "x,s=" + rfcSaltBase64 + ",i=" + tt.i
			if _, err := state.Continue(raw, fake.derive); err != nil {
				t.Fatalf("Continue = %v, want accepted", err)
			}
			if fake.calls != 1 {
				t.Fatalf("derive ran %d times, want 1", fake.calls)
			}
			if fake.iterations != tt.want {
				t.Errorf("derive got %d iterations, want %d", fake.iterations, tt.want)
			}
		})
	}
}

// TestExcessiveIterationsCostNothing proves the ceiling is applied before any
// work rather than after: the largest value a uint64 holds returns immediately
// and the callback never runs.
func TestExcessiveIterationsCostNothing(t *testing.T) {
	state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	fake := &counter{give: make([]byte, DerivedKeyLen)}
	raw := "r=" + rfcClientNonce + "x,s=" + rfcSaltBase64 + ",i=18446744073709551615"

	if _, err := state.Continue(raw, fake.derive); !errors.Is(err, ErrIterationsUnsupported) {
		t.Fatalf("Continue = %v, want ErrIterationsUnsupported", err)
	}
	if fake.calls != 0 {
		t.Fatal("a peer set svcdoctor's PBKDF2 work above the ceiling and derivation still ran")
	}
}

// TestDerivedKeyLengthIsEnforced catches the concrete mistake it exists for: a
// caller wiring SHA-512 into PBKDF2 and returning 64 bytes.
func TestDerivedKeyLengthIsEnforced(t *testing.T) {
	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		fake := &counter{give: make([]byte, size)}
		final, err := state.Continue(rfcServerFirst, fake.derive)
		if !errors.Is(err, ErrDerivedKeyLength) {
			t.Errorf("a %d-byte derived key gave %v, want ErrDerivedKeyLength", size, err)
		}
		if final != "" {
			t.Errorf("a %d-byte derived key still produced a proof", size)
		}
	}
}

// TestDerivationErrorIsCollapsed proves a callback's error text cannot escape.
// The callback runs in a wire package with plaintext in scope, so its error is
// discarded rather than wrapped.
func TestDerivationErrorIsCollapsed(t *testing.T) {
	const hostile = "pbkdf2 failed for password hunter2 at db.internal"

	state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	fake := &counter{giveErr: errors.New(hostile)}

	_, err = state.Continue(rfcServerFirst, fake.derive)
	if !errors.Is(err, ErrDerivationFailed) {
		t.Fatalf("Continue = %v, want ErrDerivationFailed", err)
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "db.internal") {
		t.Fatalf("the callback's error reached the caller: %q", err)
	}
}

// TestNilDerivationIsRefused proves a missing callback is reported rather than
// panicking, which keeps the fuzz targets' never-panic property total.
func TestNilDerivationIsRefused(t *testing.T) {
	state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := state.Continue(rfcServerFirst, nil); !errors.Is(err, ErrNoDerivation) {
		t.Fatalf("Continue with a nil callback = %v, want ErrNoDerivation", err)
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

		{"invalid-proof", "e=invalid-proof", ErrRejected},
		{"unknown-user", "e=unknown-user", ErrRejected},
		{"invalid-username-encoding", "e=invalid-username-encoding", ErrUnexpectedResponse},
		{"other-error", "e=other-error", ErrUnexpectedResponse},
		{"an extension token", "e=vendor-specific-thing", ErrUnexpectedResponse},

		{"neither v nor e", "x=something", ErrMalformedMessage},
		{"empty", "", ErrMalformedMessage},
		{"no equals", "vvvv", ErrMalformedMessage},
		{"oversized", strings.Repeat("v", maxServerFinalLen+1), ErrMessageTooLarge},

		// The first attribute decides, and trailing content is ignored. This is
		// the behaviour extracted from PostgreSQL unchanged; ADR 0056 section 8
		// forbids altering it during extraction. Pinned so that a later change
		// is a deliberate decision rather than a drift.
		{"duplicate v, first wins", "v=" + good + ",v=" + other, nil},
		{"duplicate e, first wins", "e=invalid-proof,e=other-error", ErrRejected},
		{"v then e, v decides", "v=" + good + ",e=invalid-proof", nil},
		{"e then v, e decides", "e=invalid-proof,v=" + good, ErrRejected},
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
// reach a caller: RFC 5802's extension production means it is not a closed set
// and a peer may put arbitrary text there.
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

// --- state machine ----------------------------------------------------------

func TestStateMachine(t *testing.T) {
	salted := decode(t, rfcSaltedPassword)
	fresh := func(t *testing.T) *State {
		t.Helper()
		state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		return state
	}
	advanced := func(t *testing.T) *State {
		t.Helper()
		state := fresh(t)
		fake := &counter{give: salted}
		if _, err := state.Continue(rfcServerFirst, fake.derive); err != nil {
			t.Fatalf("continue: %v", err)
		}
		return state
	}

	t.Run("verify before continue", func(t *testing.T) {
		if err := fresh(t).Verify("v=" + rfcServerSignature); !errors.Is(err, ErrWrongStep) {
			t.Fatalf("Verify = %v, want ErrWrongStep", err)
		}
	})

	t.Run("continue twice", func(t *testing.T) {
		state := advanced(t)
		fake := &counter{give: salted}
		if _, err := state.Continue(rfcServerFirst, fake.derive); !errors.Is(err, ErrWrongStep) {
			t.Fatalf("second Continue = %v, want ErrWrongStep", err)
		}
		if fake.calls != 0 {
			t.Error("a second Continue derived again; one exchange derives once")
		}
	})

	t.Run("verify twice", func(t *testing.T) {
		state := advanced(t)
		if err := state.Verify("v=" + rfcServerSignature); err != nil {
			t.Fatalf("first Verify: %v", err)
		}
		if err := state.Verify("v=" + rfcServerSignature); !errors.Is(err, ErrWrongStep) {
			t.Fatalf("second Verify = %v, want ErrWrongStep", err)
		}
	})

	t.Run("continue after success", func(t *testing.T) {
		state := advanced(t)
		if err := state.Verify("v=" + rfcServerSignature); err != nil {
			t.Fatalf("verify: %v", err)
		}
		fake := &counter{give: salted}
		if _, err := state.Continue(rfcServerFirst, fake.derive); !errors.Is(err, ErrWrongStep) {
			t.Fatalf("Continue after success = %v, want ErrWrongStep", err)
		}
		if fake.calls != 0 {
			t.Error("derivation ran after a completed exchange")
		}
	})

	t.Run("after a continue failure", func(t *testing.T) {
		state := fresh(t)
		fake := &counter{give: salted}
		if _, err := state.Continue("r=nope,s=x,i=1", fake.derive); err == nil {
			t.Fatal("a malformed server-first was accepted")
		}
		if _, err := state.Continue(rfcServerFirst, fake.derive); !errors.Is(err, ErrWrongStep) {
			t.Fatalf("Continue after failure = %v, want ErrWrongStep", err)
		}
		if err := state.Verify("v=" + rfcServerSignature); !errors.Is(err, ErrWrongStep) {
			t.Fatalf("Verify after failure = %v, want ErrWrongStep", err)
		}
		if fake.calls != 0 {
			t.Error("derivation ran despite a failed exchange")
		}
	})

	t.Run("after a verify failure", func(t *testing.T) {
		state := advanced(t)
		if err := state.Verify("v=" + base64.StdEncoding.EncodeToString(make([]byte, 32))); !errors.Is(err, ErrServerSignatureMismatch) {
			t.Fatalf("Verify = %v, want ErrServerSignatureMismatch", err)
		}
		if err := state.Verify("v=" + rfcServerSignature); !errors.Is(err, ErrWrongStep) {
			t.Fatalf("Verify after failure = %v, want ErrWrongStep", err)
		}
	})

	// A wrong-step call is a pure rejection: it did nothing, so it changes
	// nothing. Escalating an API misuse into a failed exchange would be a bigger
	// consequence than the mistake.
	t.Run("a rejected call does not poison the state", func(t *testing.T) {
		state := fresh(t)
		if err := state.Verify("v=x"); !errors.Is(err, ErrWrongStep) {
			t.Fatalf("Verify = %v, want ErrWrongStep", err)
		}
		fake := &counter{give: salted}
		if _, err := state.Continue(rfcServerFirst, fake.derive); err != nil {
			t.Fatalf("Continue after a wrong-step Verify = %v, want it to still work", err)
		}
	})
}

// TestStateIsMinimizedAtEachStep proves the retained-material contract by
// reading the unexported fields directly.
func TestStateIsMinimizedAtEachStep(t *testing.T) {
	state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if state.clientFirstBare == "" || state.clientNonce == "" {
		t.Fatal("after Begin the state must hold the client-first-bare and the nonce")
	}
	if state.expectedServerSignature != nil {
		t.Error("after Begin there is no signature to expect yet")
	}

	fake := &counter{give: decode(t, rfcSaltedPassword)}
	if _, err := state.Continue(rfcServerFirst, fake.derive); err != nil {
		t.Fatalf("continue: %v", err)
	}
	if state.clientFirstBare != "" || state.clientNonce != "" {
		t.Error("after Continue the client-first-bare and nonce must be dropped")
	}
	if len(state.expectedServerSignature) != DerivedKeyLen {
		t.Fatalf("after Continue the expected signature must be %d bytes", DerivedKeyLen)
	}

	if err := state.Verify("v=" + rfcServerSignature); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if state.expectedServerSignature != nil {
		t.Error("after Verify nothing derived from the credential may remain")
	}
}

// --- nonce ------------------------------------------------------------------

// TestCryptoNonceShape pins the shape libpq uses: 18 raw bytes, base64-encoded
// to 24 characters with no padding, and RFC 5802 "printable" throughout.
//
// The printable check is the interoperability one. RFC 5802 admits every base64
// character and excludes only the comma that would forge an attribute boundary,
// and both PostgreSQL and Kafka were measured accepting nonces containing "+"
// and "/" — see rawNonceLen for the experiment that settled it.
func TestCryptoNonceShape(t *testing.T) {
	seen := make(map[string]struct{})
	for range 256 {
		nonce, err := cryptoNonce()
		if err != nil {
			t.Fatalf("cryptoNonce: %v", err)
		}
		if len(nonce) != 24 {
			t.Fatalf("nonce %q is %d characters, want 24", nonce, len(nonce))
		}
		if !printableRFC(nonce) {
			t.Fatalf("nonce %q is not RFC 5802 printable", nonce)
		}
		for i := 0; i < len(nonce); i++ {
			if nonce[i] == ',' {
				t.Fatalf("nonce %q contains a comma and could forge an attribute", nonce)
			}
		}
		if _, repeat := seen[nonce]; repeat {
			t.Fatalf("cryptoNonce repeated %q within 256 draws", nonce)
		}
		seen[nonce] = struct{}{}
	}
}
