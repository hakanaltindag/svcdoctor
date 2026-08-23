package scram

import "errors"

// Sentinel errors, every one of them fixed text.
//
// **No error this package produces contains a byte the peer chose**, and none
// contains a username, a nonce, a salt, a verifier or any derived material.
// That is structural rather than disciplined: fmt is not in this package's
// import allowlist, so there is no way to format a value into an error even by
// accident. internal/adapter/postgres/wire established that fixed-text sentinels
// are sufficient by importing fmt in no production file, and this package
// inherits the property.
//
// Each service's wire package translates or aliases these into its own
// vocabulary. See ADR 0056 section 8 for which are aliased and which are
// translated, and why the two framing errors are deliberately not aliased.
var (
	// ErrMalformedMessage means the peer's message did not follow the grammar
	// it announced: a missing separator, a missing required attribute, a
	// duplicate, or a value that is not what its attribute requires.
	ErrMalformedMessage = errors.New("scram message could not be decoded")

	// ErrUnexpectedResponse means the message was well-formed but says
	// something this implementation will not act on — a mandatory extension it
	// does not understand, or a server error token outside the set it maps.
	ErrUnexpectedResponse = errors.New("scram response is not valid at this step")

	// ErrMessageTooLarge means a peer-controlled field exceeded this package's
	// own bound.
	//
	// It is a statement about svcdoctor, not about the peer: the value may be
	// legal SCRAM. The bounds exist because the two wire packages that call
	// this one bound peer payloads eight times apart, so inheriting a caller's
	// limit would make this package safe only for the callers that exist today.
	ErrMessageTooLarge = errors.New("peer field exceeds the size svcdoctor reads")

	// ErrUsernameUnsupported means the username is outside the range svcdoctor
	// can prepare.
	//
	// A statement about svcdoctor. Nothing was sent, so the peer expressed no
	// opinion. See ADR 0056 section 5 for why the range is printable ASCII and
	// why implementing SASLprep would be a defect rather than an improvement.
	ErrUsernameUnsupported = errors.New("username is outside the range svcdoctor can prepare for SCRAM")

	// ErrIterationsUnsupported means the peer demanded more PBKDF2 work than
	// svcdoctor performs. Also a statement about svcdoctor: the count is legal,
	// and no derivation was attempted.
	ErrIterationsUnsupported = errors.New("peer demanded more SCRAM iterations than svcdoctor performs")

	// ErrNoDerivation means Continue was called with no Derive callback.
	//
	// A programming error rather than a protocol one, reported instead of
	// panicking so that a fuzz target's "never panic" property holds over every
	// input including a nil callback.
	ErrNoDerivation = errors.New("scram continue requires a derivation function")

	// ErrDerivationFailed means the caller's Derive callback returned an error.
	//
	// **The callback's error is discarded and never wrapped**, which is a
	// security decision rather than tidiness. The callback runs in a wire
	// package with the plaintext in scope, so any error it produces could carry
	// credential material; passing it through or wrapping it would move unknown
	// text out of this package and into an adapter's error chain. Collapsing to
	// one sentinel is the only handling that structurally cannot leak. See ADR
	// 0056 section 8.
	ErrDerivationFailed = errors.New("scram derivation did not produce a key")

	// ErrDerivedKeyLength means Derive returned material that is not
	// DerivedKeyLen bytes.
	//
	// It catches the concrete mistake it exists for — a caller wiring SHA-512
	// into PBKDF2 and returning 64 bytes — and it proves **nothing else**. It
	// does not prove PBKDF2 was used, that SHA-256 was the PRF, that the salt
	// was used, or that the iteration count was honoured. Those are pinned by
	// the RFC vectors each wire package runs end to end.
	ErrDerivedKeyLength = errors.New("scram derivation returned the wrong key length")

	// ErrRejected means the peer refused what it was presented: the proof did
	// not verify, or there is no such principal to verify it against. The two
	// are one outcome here and are not read for their cause.
	ErrRejected = errors.New("peer rejected the SCRAM credential")

	// ErrServerSignatureMismatch means the server's signature did not match the
	// one derived locally.
	//
	// This is **svcdoctor refusing the peer**, not the peer refusing svcdoctor,
	// and it is only reachable once the peer has accepted the client proof — a
	// peer that rejects the proof never sends a verifier at all. The two must
	// not be normalized together downstream. See ADR 0040 section 5.1.
	ErrServerSignatureMismatch = errors.New("server did not prove knowledge of the credential")

	// ErrWrongStep means the exchange was driven out of order: Continue twice,
	// Verify before Continue, Verify twice, or any call after a failure.
	ErrWrongStep = errors.New("scram exchange step called out of order")
)
