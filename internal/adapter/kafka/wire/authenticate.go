package wire

import (
	"context"
	"net"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// Authenticate performs the one SASL exchange the negotiated mechanism names.
//
// # This is where a secret becomes bytes, and there is exactly one of them
//
// It holds this package's only call to security.Reveal, and svcdoctor has
// exactly two such calls in total — one per service, each in its adapter's wire
// package. TestRevealHasExactlyTwoProductionCallSites pins that number
// repository-wide and forbidigo confines the call to wire packages.
//
// **That is why the dispatch lives here rather than in the adapter.** Phase 6.2
// first gave PLAIN and SCRAM an exported exchange each, and each revealed its
// own secret — which is a perfectly ordinary structure and quietly took the
// repository from two reveal sites to three. Revealing once and dispatching on
// the plaintext keeps the count where every guard and every ADR says it is, and
// it puts the framing choice in the package that owns framing.
//
// The connection is borrowed, not owned; see exchange. The caller obtains secret
// from Credential.SecretFor, so the endpoint binding has already been verified,
// and checks the channel policy and the mechanism guard before calling. **This
// function performs none of those checks**: duplicating them here would mean two
// places could disagree about whether a credential may be sent, and the wire
// boundary is the wrong one of the two to hold policy. See ADR 0027 for why the
// boundary is here and ADR 0030 for what the caller must have established.
//
// # No fallback, in either direction
//
// The mechanism arrived from the broker's SaslHandshake and was checked against
// the adapter's whitelist before any credential was resolved, so the switch has
// two reachable branches. **The default refuses rather than choosing.** Falling
// back to PLAIN would put a password on the wire in a framing the broker never
// agreed to receive, which is the Phase 6.1a defect re-created one layer down; a
// SCRAM failure never becomes a PLAIN attempt, and a PLAIN failure never becomes
// a SCRAM attempt.
func Authenticate(
	ctx context.Context, conn net.Conn, mechanism, identity string, secret security.Secret,
) (SASLAuthenticate, error) {
	// Revealed once, immediately before the framing that puts it on the socket.
	// It is not stored, not logged, not returned, and not placed in any error.
	//
	// **No erasure is claimed and none is performed.** kmsg copies these bytes
	// into the encoded frame, PBKDF2 copies the string internally, and Go
	// strings are immutable and may already have been moved by the collector.
	// internal/security/doc.go has said since Phase 1 that Go cannot guarantee
	// erasure; a Zero call here would be theatre that contradicts it.
	password := security.Reveal(secret)

	switch mechanism {
	case MechanismPLAIN:
		return exchangePLAIN(ctx, conn, identity, password)
	case MechanismSCRAMSHA256:
		return exchangeSCRAMSHA256(ctx, conn, identity, password)
	default:
		// Unreachable: the adapter's supportedMechanism gates this call.
		// Refusing rather than guessing is what keeps it unreachable.
		return SASLAuthenticate{}, ErrMechanismNotPerformable
	}
}

// ErrMechanismNotPerformable means Authenticate was given a mechanism this
// package frames no exchange for.
//
// Unreachable behind the adapter's whitelist, and present so that a future
// caller which forgets the whitelist gets a refusal instead of a guess.
var ErrMechanismNotPerformable = errNew("no kafka exchange performs the negotiated mechanism")
