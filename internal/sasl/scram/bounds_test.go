package scram

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// The defensive resource policy, pinned by value.
//
// # Why by value, when boundary tests already exist
//
// Phase 7.0 measured the gap that makes this file necessary. Every bound test in
// this package was written *relative to its constant* — `maxSaltLen+8`,
// `maxSaltEncodedLen+1`, `maxNonceLen` — so each proves the mechanism and the
// validation order and none proves the number. The whole unit suite passed
// unchanged under four different experimental bound policies, including ones
// eight times looser than the accepted one. A silent edit from 1024 to 8192 was
// invisible to every test in the repository.
//
// These bounds are a security decision recorded in ADR 0061. Changing one must
// require editing a test that states the number, so the number appears in the
// diff and a reviewer sees it.
//
// **If you are here because this test failed after you changed a constant: that
// is the point.** Take the change through ADR 0061's reopen conditions rather
// than through this file.

// TestTheDefensiveResourcePolicyIsExactlyWhatWasAccepted pins all eight values.
func TestTheDefensiveResourcePolicyIsExactlyWhatWasAccepted(t *testing.T) {
	for _, tt := range []struct {
		name string
		got  int
		want int
	}{
		{"maxServerFirstLen", maxServerFirstLen, 8192},
		{"maxServerFinalLen", maxServerFinalLen, 8192},
		{"maxSaltLen", maxSaltLen, 1024},
		{"maxSaltEncodedLen", maxSaltEncodedLen, 1368},
		{"maxNonceLen", maxNonceLen, 1024},
		{"maxAttributes", maxAttributes, 32},
		{"MaxIterations", MaxIterations, 1 << 20},
		{"maxUsernameLen", maxUsernameLen, 256},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d.\n\n"+
				"This is svcdoctor's defensive resource policy against a hostile peer, "+
				"accepted in ADR 0061 from measured CPU and allocation cost. Changing it "+
				"is a security decision: take it through that record's reopen conditions, "+
				"and state the new number here so it appears in the diff.",
				tt.name, tt.got, tt.want)
		}
	}
}

// TestEncodedSaltBoundTracksTheDecodedBound proves the two salt constants cannot
// drift apart.
//
// maxSaltEncodedLen is written as a constant expression because a const block
// cannot call base64.StdEncoding.EncodedLen. That is the only reason it is
// spelled out, and this is what stops the spelling from becoming an independent
// number. A gap in either direction is a real defect: too large and an oversized
// salt reaches the decoder, too small and a salt inside the accepted policy is
// refused before anyone can decode it.
func TestEncodedSaltBoundTracksTheDecodedBound(t *testing.T) {
	if want := base64.StdEncoding.EncodedLen(maxSaltLen); maxSaltEncodedLen != want {
		t.Fatalf("maxSaltEncodedLen = %d, want base64.StdEncoding.EncodedLen(%d) = %d",
			maxSaltEncodedLen, maxSaltLen, want)
	}
	// And the property that actually matters: the largest salt the encoded
	// bound admits still decodes to no more than the decoded bound.
	if got := base64.StdEncoding.DecodedLen(maxSaltEncodedLen); got < maxSaltLen {
		t.Errorf("the encoded bound admits only %d decoded bytes, below maxSaltLen %d; "+
			"a legal salt inside the policy would be refused", got, maxSaltLen)
	}
}

// --- limit-1 / limit / limit+1 --------------------------------------------

// saltOf builds a server-first carrying a salt of exactly n decoded bytes.
func saltOf(clientNonce string, n int) string {
	salt := make([]byte, n)
	for i := range salt {
		salt[i] = byte(i % 251)
	}
	return "r=" + clientNonce + "x,s=" + base64.StdEncoding.EncodeToString(salt) + ",i=4096"
}

// TestEveryThresholdAcceptsItsLimitAndRefusesOneMore walks each defensive
// threshold across limit-1, limit and limit+1.
//
// The accepting cases matter as much as the refusing ones: a bound that refuses
// its own limit is off by one in the direction that breaks interoperability, and
// that is the class of defect ADR 0061 exists to correct.
func TestEveryThresholdAcceptsItsLimitAndRefusesOneMore(t *testing.T) {
	const n = rfcClientNonce

	// Server-first total length. Padded with an extension attribute so only the
	// length varies.
	t.Run("serverFirstLen", func(t *testing.T) {
		base := saltOf(n, 16)
		for _, tt := range []struct {
			total   int
			wantErr error
		}{
			{maxServerFirstLen - 1, nil},
			{maxServerFirstLen, nil},
			{maxServerFirstLen + 1, ErrMessageTooLarge},
		} {
			pad := tt.total - len(base) - len(",x=")
			if pad < 0 {
				t.Fatalf("fixture too short for total %d", tt.total)
			}
			msg := base + ",x=" + strings.Repeat("Z", pad)
			if len(msg) != tt.total {
				t.Fatalf("built %d bytes, want %d", len(msg), tt.total)
			}
			assertContinue(t, strconv.Itoa(tt.total), msg, tt.wantErr)
		}
	})

	// Decoded salt, and with it the encoded bound: a salt of maxSaltLen+1 bytes
	// also encodes above maxSaltEncodedLen, so the encoded check is what fires.
	t.Run("saltLen", func(t *testing.T) {
		for _, tt := range []struct {
			size    int
			wantErr error
		}{
			{maxSaltLen - 1, nil},
			{maxSaltLen, nil},
			{maxSaltLen + 1, ErrMessageTooLarge},
		} {
			assertContinue(t, strconv.Itoa(tt.size), saltOf(n, tt.size), tt.wantErr)
		}
	})

	// Server nonce. Length is measured over the whole nonce, client half included.
	t.Run("nonceLen", func(t *testing.T) {
		for _, tt := range []struct {
			total   int
			wantErr error
		}{
			{maxNonceLen - 1, nil},
			{maxNonceLen, nil},
			{maxNonceLen + 1, ErrMessageTooLarge},
		} {
			nonce := n + strings.Repeat("q", tt.total-len(n))
			msg := "r=" + nonce + ",s=" + rfcSaltBase64 + ",i=4096"
			assertContinue(t, strconv.Itoa(tt.total), msg, tt.wantErr)
		}
	})

	// Attribute count, including the three the message must already carry.
	t.Run("attributes", func(t *testing.T) {
		for _, tt := range []struct {
			count   int
			wantErr error
		}{
			{maxAttributes - 1, nil},
			{maxAttributes, nil},
			{maxAttributes + 1, ErrMessageTooLarge},
		} {
			msg := saltOf(n, 16) + strings.Repeat(",x=1", tt.count-3)
			assertContinue(t, strconv.Itoa(tt.count), msg, tt.wantErr)
		}
	})

	// Iteration count. The ceiling is the one bound that protects CPU.
	t.Run("iterations", func(t *testing.T) {
		for _, tt := range []struct {
			count   int
			wantErr error
		}{
			{MaxIterations - 1, nil},
			{MaxIterations, nil},
			{MaxIterations + 1, ErrIterationsUnsupported},
		} {
			msg := "r=" + n + "x,s=" + rfcSaltBase64 + ",i=" + strconv.Itoa(tt.count)
			assertContinue(t, strconv.Itoa(tt.count), msg, tt.wantErr)
		}
	})
}

// TestServerFinalAcceptsItsLimitAndRefusesOneMore is the same walk for the
// verifier message, which has its own bound and its own entry point.
func TestServerFinalAcceptsItsLimitAndRefusesOneMore(t *testing.T) {
	expected := []byte("0123456789abcdef0123456789abcdef")
	verifier := "v=" + base64.StdEncoding.EncodeToString(expected)

	for _, tt := range []struct {
		total   int
		wantErr error
	}{
		{maxServerFinalLen - 1, nil},
		{maxServerFinalLen, nil},
		{maxServerFinalLen + 1, ErrMessageTooLarge},
	} {
		// RFC 5802 permits trailing extensions after the verifier, so padding
		// keeps the message legal and varies only its length.
		pad := tt.total - len(verifier) - len(",x=")
		raw := verifier + ",x=" + strings.Repeat("Z", pad)
		if len(raw) != tt.total {
			t.Fatalf("built %d bytes, want %d", len(raw), tt.total)
		}
		err := verifyServerFinal(raw, expected)
		if tt.wantErr == nil && err != nil {
			t.Errorf("server-final of %d bytes: %v, want acceptance", tt.total, err)
		}
		if tt.wantErr != nil && err != tt.wantErr {
			t.Errorf("server-final of %d bytes = %v, want %v", tt.total, err, tt.wantErr)
		}
	}
}

// assertContinue drives one server-first through Continue and checks both the
// outcome and that derivation ran exactly when it should have.
//
// **The derivation count is the security assertion.** Every refusal above must
// happen before the callback is reachable, so a rejected message that still
// derived would mean a hostile peer had bought PBKDF2 work with a value
// svcdoctor claims to have refused.
func assertContinue(t *testing.T, name, serverFirst string, wantErr error) {
	t.Helper()

	state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	fake := &counter{give: make([]byte, DerivedKeyLen)}

	_, err = state.Continue(serverFirst, fake.derive)

	switch {
	case wantErr == nil && err != nil:
		t.Errorf("%s: Continue = %v, want acceptance", name, err)
	case wantErr != nil && err != wantErr:
		t.Errorf("%s: Continue = %v, want %v", name, err, wantErr)
	}

	wantCalls := 0
	if wantErr == nil {
		wantCalls = 1
	}
	if fake.calls != wantCalls {
		t.Errorf("%s: derive ran %d times, want %d", name, fake.calls, wantCalls)
	}
}

// TestAnOversizedEncodedSaltIsRefusedBeforeItIsDecoded pins the ordering that
// makes every oversized-salt refusal allocation-free.
//
// The encoded check precedes base64.DecodeString, so a peer cannot make
// svcdoctor allocate a decode buffer for a salt it is going to refuse. The
// property is asserted through allocation rather than through the error, because
// the error is identical either way and only the allocation tells the two orders
// apart.
func TestAnOversizedEncodedSaltIsRefusedBeforeItIsDecoded(t *testing.T) {
	// The largest salt the message bound admits, far above the salt bound.
	huge := saltOf(rfcClientNonce, 4096)
	if len(huge) > maxServerFirstLen {
		t.Fatalf("fixture is %d bytes, above maxServerFirstLen; the message bound "+
			"would fire first and this would prove nothing", len(huge))
	}

	allocs := testing.AllocsPerRun(50, func() {
		_, _ = parseServerFirst(huge, rfcClientNonce)
	})
	if allocs != 0 {
		t.Errorf("refusing an oversized salt allocated %v times, want 0.\n\n"+
			"maxSaltEncodedLen must be checked before base64.StdEncoding.DecodeString, "+
			"or a peer can force a decode allocation for a value svcdoctor then refuses.",
			allocs)
	}
}

// TestAnOversizedIterationCountNeverReachesDerivation is the same property for
// the bound that protects CPU rather than memory.
func TestAnOversizedIterationCountNeverReachesDerivation(t *testing.T) {
	for _, iters := range []string{
		strconv.Itoa(MaxIterations + 1),
		"99999999999999999999999",
	} {
		state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		fake := &counter{give: make([]byte, DerivedKeyLen)}
		msg := "r=" + rfcClientNonce + "x,s=" + rfcSaltBase64 + ",i=" + iters

		if _, err := state.Continue(msg, fake.derive); err != ErrIterationsUnsupported {
			t.Errorf("i=%s: Continue = %v, want ErrIterationsUnsupported", iters, err)
		}
		if fake.calls != 0 {
			t.Errorf("i=%s: PBKDF2 ran for a count above the ceiling", iters)
		}
	}
}

// --- the Redpanda shape ----------------------------------------------------

// Redpanda's SCRAM salt dimensions, measured against a real v25.1.9 instance and
// confirmed from its source, where `SaltSize` is hardcoded at 130 for both
// SCRAM-SHA-256 and SCRAM-SHA-512.
//
// The nonce length is deliberately *not* pinned: Phase 6.8 measured a total of
// 157 and Phase 7.0 measured 154, and the security property is not which it is
// but that both sit far below maxNonceLen. The salt dimensions are deterministic
// and are pinned exactly.
const (
	redpandaSaltDecoded = 130
	redpandaSaltEncoded = 176
)

// TestTheCoreAcceptsARedpandaShapedServerFirst is the permanent regression for
// the interoperability failure that produced ADR 0061.
//
// svcdoctor v0.2.0 refused this exact shape — at the encoded check, 176 > 172,
// before the decode — and reported it as a malformed broker response. It is
// legal RFC 5802 and Redpanda emits it on every exchange.
func TestTheCoreAcceptsARedpandaShapedServerFirst(t *testing.T) {
	salt := make([]byte, redpandaSaltDecoded)
	for i := range salt {
		salt[i] = byte(i % 251)
	}
	encoded := base64.StdEncoding.EncodeToString(salt)

	// The fixture is only meaningful if it really has the measured dimensions.
	if len(salt) != redpandaSaltDecoded || len(encoded) != redpandaSaltEncoded {
		t.Fatalf("fixture is %d decoded / %d encoded, want %d / %d",
			len(salt), len(encoded), redpandaSaltDecoded, redpandaSaltEncoded)
	}

	// Redpanda appends ~130 characters to the client nonce; three attributes;
	// 4096 iterations. Nothing here is a credential.
	nonce := rfcClientNonce + strings.Repeat("R", 130)
	serverFirst := "r=" + nonce + ",s=" + encoded + ",i=4096"

	state, _, err := begin(rfcUsername, fixedNonce(rfcClientNonce))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	fake := &counter{give: make([]byte, DerivedKeyLen)}

	if _, err := state.Continue(serverFirst, fake.derive); err != nil {
		t.Fatalf("the core refused a Redpanda-shaped server-first: %v\n\n"+
			"decoded salt %d, encoded salt %d, nonce %d, whole message %d. This is legal "+
			"RFC 5802 and a real broker emits it; refusing it is the defect ADR 0061 "+
			"corrected.", err, len(salt), len(encoded), len(nonce), len(serverFirst))
	}
	if fake.calls != 1 {
		t.Errorf("derive ran %d times, want 1", fake.calls)
	}
	if len(fake.salt) != redpandaSaltDecoded {
		t.Errorf("derivation received a %d-byte salt, want %d",
			len(fake.salt), redpandaSaltDecoded)
	}
	if fake.iterations != 4096 {
		t.Errorf("derivation received %d iterations, want 4096", fake.iterations)
	}
}

// TestTheRedpandaShapeWasRefusedByTheOldPolicy proves the regression above is
// not vacuous.
//
// If the accepted bounds are ever narrowed back below Redpanda's dimensions,
// this states which constant did it.
func TestTheRedpandaShapeWasRefusedByTheOldPolicy(t *testing.T) {
	if maxSaltEncodedLen < redpandaSaltEncoded {
		t.Errorf("maxSaltEncodedLen %d is below Redpanda's %d encoded characters; "+
			"the message is refused before it is decoded",
			maxSaltEncodedLen, redpandaSaltEncoded)
	}
	if maxSaltLen < redpandaSaltDecoded {
		t.Errorf("maxSaltLen %d is below Redpanda's %d decoded bytes",
			maxSaltLen, redpandaSaltDecoded)
	}
	// The historical values, stated so the regression records what it protects.
	if 172 >= redpandaSaltEncoded || 128 >= redpandaSaltDecoded {
		t.Error("the pre-ADR-0061 bounds no longer describe a refusal; " +
			"this test has stopped documenting anything")
	}
}

// --- leakage ---------------------------------------------------------------

// TestAnOversizedValueNeverReachesTheError proves a refused peer value does not
// travel out inside the error that refused it.
//
// Structural already — `fmt` is denied by this package's import allowlist, so
// there is no way to format a value into an error — but asserted anyway, because
// the allowlist is a build-time property and this is the behaviour an operator
// depends on. A canary is buried in the middle of each oversized field so a
// prefix or suffix truncation would still be caught.
func TestAnOversizedValueNeverReachesTheError(t *testing.T) {
	const canary = "CANARY-OVERSIZE-7f3b91"
	fill := strings.Repeat("A", 700)

	cases := map[string]string{
		"oversized nonce": "r=" + rfcClientNonce + fill + canary + fill +
			",s=" + rfcSaltBase64 + ",i=4096",
		"oversized encoded salt": "r=" + rfcClientNonce + "x,s=" +
			strings.Repeat("QQ", 900) + canary + ",i=4096",
		"oversized server-first": "r=" + rfcClientNonce + "x,s=" + rfcSaltBase64 +
			",i=4096,x=" + strings.Repeat("B", maxServerFirstLen) + canary,
		"too many attributes": "r=" + rfcClientNonce + "x,s=" + rfcSaltBase64 +
			",i=4096" + strings.Repeat(",x="+canary, maxAttributes+4),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseServerFirst(raw, rfcClientNonce)
			if err == nil {
				t.Fatal("the fixture was accepted; it proves nothing about refusals")
			}
			if strings.Contains(err.Error(), canary) {
				t.Errorf("the error echoes the peer's value: %q", err.Error())
			}
			assertSentinel(t, err)
		})
	}

	t.Run("oversized server-final", func(t *testing.T) {
		raw := "v=" + strings.Repeat("Q", maxServerFinalLen) + canary
		err := verifyServerFinal(raw, []byte("0123456789abcdef0123456789abcdef"))
		if err == nil {
			t.Fatal("the fixture was accepted")
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("the error echoes the peer's value: %q", err.Error())
		}
		assertSentinel(t, err)
	})
}
