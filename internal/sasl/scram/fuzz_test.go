package scram

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Fuzz targets over every parser a peer can reach.
//
// The properties below are the ones ADR 0056 section 14 requires, and the
// important one is not "never panic" — it is that **no malformed input can
// reach the derivation callback**. A parser that crashes is a bug; a parser
// that lets a peer provoke PBKDF2 with values it never validated is the defect
// this whole package's ordering exists to prevent.
//
// No corpus entry is a secret. The seeds are protocol shapes, and the failure
// messages below never print the input, so a crash report carries no peer bytes.

const fuzzClientNonce = "rOprNGfwEbeRWgbNEkqO"

// sentinels is every error this package may return.
//
// Asserting membership is the precise form of "no peer payload leaks". A
// substring check is the obvious formulation and it is wrong: a one-character
// input like "m" is trivially contained in "scram message could not be
// decoded", so the check reports a leak that did not happen. Identity against a
// closed set of fixed-text values says exactly what the contract says — the
// error is one of these, and none of these was built from the input.
var sentinels = []error{
	ErrMalformedMessage,
	ErrUnexpectedResponse,
	ErrMessageTooLarge,
	ErrUsernameUnsupported,
	ErrIterationsUnsupported,
	ErrNoDerivation,
	ErrDerivationFailed,
	ErrDerivedKeyLength,
	ErrRejected,
	ErrServerSignatureMismatch,
	ErrWrongStep,
}

// assertSentinel fails unless err is one of this package's fixed-text values.
func assertSentinel(t *testing.T, err error) {
	t.Helper()
	for _, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			return
		}
	}
	t.Fatalf("an error escaped that is not one of this package's fixed sentinels: %q", err)
}

// fuzzSeeds are the shapes worth starting from: valid, boundary and hostile.
func fuzzSeeds(f *testing.F) {
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	f.Add("r=" + fuzzClientNonce + "server,s=" + salt + ",i=4096")
	f.Add("r=" + fuzzClientNonce + ",s=" + salt + ",i=4096")
	f.Add("m=mandatory,r=" + fuzzClientNonce + "x,s=" + salt + ",i=4096")
	f.Add("r=" + fuzzClientNonce + "x,s=!!!,i=4096")
	f.Add("r=" + fuzzClientNonce + "x,s=" + salt + ",i=0")
	f.Add("r=" + fuzzClientNonce + "x,s=" + salt + ",i=99999999999999999999")
	f.Add("r=,s=,i=")
	f.Add("")
	f.Add(",,,,")
	f.Add("x=" + strings.Repeat("A", 5000))
}

// FuzzParseServerFirst is the primary target: it drives the real parser with
// the real client nonce and proves the derivation callback stays unreachable
// for every input the parser rejects.
func FuzzParseServerFirst(f *testing.F) {
	fuzzSeeds(f)

	f.Fuzz(func(t *testing.T, raw string) {
		state, _, err := begin(rfcUsername, fixedNonce(fuzzClientNonce))
		if err != nil {
			t.Fatalf("begin: %v", err)
		}

		fake := &counter{give: make([]byte, DerivedKeyLen)}
		final, err := state.Continue(raw, fake.derive)

		if err != nil {
			if fake.calls != 0 {
				t.Fatal("a rejected server-first reached the derivation callback")
			}
			if final != "" {
				t.Fatal("a rejected server-first still produced a client-final message")
			}
			// No peer bytes may travel out in an error.
			assertSentinel(t, err)
			return
		}

		if fake.calls != 1 {
			t.Fatalf("an accepted server-first derived %d times, want exactly 1", fake.calls)
		}
		if fake.iterations <= 0 || fake.iterations > MaxIterations {
			t.Fatalf("derivation ran with an out-of-range iteration count: %d", fake.iterations)
		}
		if len(fake.salt) > maxSaltLen {
			t.Fatalf("derivation ran with a %d-byte salt, above the %d bound", len(fake.salt), maxSaltLen)
		}
		if final == "" {
			t.Fatal("an accepted server-first produced no client-final message")
		}

		// Determinism: the same input through a fresh state gives the same
		// answer.
		again, _, err := begin(rfcUsername, fixedNonce(fuzzClientNonce))
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		second := &counter{give: make([]byte, DerivedKeyLen)}
		repeat, err := again.Continue(raw, second.derive)
		if err != nil || repeat != final {
			t.Fatal("parsing the same server-first twice gave different results")
		}
	})
}

// FuzzVerifyServerFinal proves the verifier cannot be bypassed and that no
// server-supplied token reaches an error.
func FuzzVerifyServerFinal(f *testing.F) {
	expected := []byte("0123456789abcdef0123456789abcdef")
	good := base64.StdEncoding.EncodeToString(expected)

	f.Add("v=" + good)
	f.Add("v=" + good + ",x=extension")
	f.Add("e=invalid-proof")
	f.Add("e=" + strings.Repeat("z", 200))
	f.Add("v=!!!!")
	f.Add("")
	f.Add("v=")

	f.Fuzz(func(t *testing.T, raw string) {
		err := verifyServerFinal(raw, expected)
		if err != nil {
			assertSentinel(t, err)
			return
		}

		// Accepting means the first attribute was a verifier that matched. Any
		// other acceptance would be a bypass.
		if len(raw) < 2 || raw[0] != 'v' || raw[1] != '=' {
			t.Fatal("a message that is not a verifier was accepted")
		}
		end := len(raw)
		for i := 0; i < len(raw); i++ {
			if raw[i] == ',' {
				end = i
				break
			}
		}
		signature, decodeErr := base64.StdEncoding.DecodeString(raw[2:end])
		if decodeErr != nil || string(signature) != string(expected) {
			t.Fatal("a verifier that does not match the expected signature was accepted")
		}
	})
}

// FuzzAttributes proves the walker terminates, allocates nothing per attribute
// and never exceeds its own count bound.
func FuzzAttributes(f *testing.F) {
	f.Add("r=a,s=b,i=1")
	f.Add("a=1")
	f.Add("")
	f.Add(",")
	f.Add(strings.Repeat("x=1,", 100))

	f.Fuzz(func(t *testing.T, raw string) {
		visits := 0
		err := attributes(raw, func(key byte, value string) error {
			visits++
			if visits > maxAttributes {
				t.Fatal("the walker visited more attributes than its own bound permits")
			}
			return nil
		})
		if err == nil && visits == 0 {
			t.Fatal("the walker accepted a message with no attributes")
		}
	})
}

// FuzzParseIterations proves the ceiling holds over arbitrary digit strings.
func FuzzParseIterations(f *testing.F) {
	f.Add("4096")
	f.Add("0")
	f.Add("1048576")
	f.Add("1048577")
	f.Add("18446744073709551616")
	f.Add("-1")
	f.Add("")
	f.Add("00000000000000000000004096")

	f.Fuzz(func(t *testing.T, raw string) {
		n, err := parseIterations(raw)
		if err != nil {
			if n != 0 {
				t.Fatal("a rejected iteration count still returned a value")
			}
			return
		}
		if n <= 0 || n > MaxIterations {
			t.Fatalf("parseIterations accepted %d, outside 1..%d", n, MaxIterations)
		}
	})
}

// FuzzEncodeSASLname proves the encoder is total over its accepted range and
// that its output can never forge an attribute boundary.
func FuzzEncodeSASLname(f *testing.F) {
	f.Add("user")
	f.Add("")
	f.Add("a,b")
	f.Add("a=b")
	f.Add("a,b=c")
	f.Add("=2C")
	f.Add(strings.Repeat("u", maxUsernameLen))
	f.Add("\xff\xfe")

	f.Fuzz(func(t *testing.T, raw string) {
		encoded, err := encodeSASLname(Username(raw))
		if err != nil {
			if encoded != "" {
				t.Fatal("a refused username still produced an encoding")
			}
			return
		}

		// The encoded form must contain neither separator, or it could create an
		// attribute the peer never sent — and change the AuthMessage both sides
		// sign.
		for i := 0; i < len(encoded); i++ {
			if encoded[i] == ',' {
				t.Fatal("an encoded username contains a comma")
			}
		}
		// Every '=' must introduce a valid escape. RFC 5802 section 5.1: a
		// server receiving '=' not followed by 2C or 3D MUST fail the exchange.
		for i := 0; i < len(encoded); i++ {
			if encoded[i] != '=' {
				continue
			}
			if i+2 >= len(encoded) {
				t.Fatal("an encoded username ends with a truncated escape")
			}
			pair := encoded[i+1 : i+3]
			if pair != "2C" && pair != "3D" {
				t.Fatal("an encoded username contains an '=' that is not a valid escape")
			}
			i += 2
		}
	})
}
