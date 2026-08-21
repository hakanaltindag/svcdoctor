package kafka

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

// TransportPlan is how a caller says what "reach this advertised endpoint" means.
//
// # Why it is supplied rather than inferred
//
// A Metadata response gives a node identifier, a host and a port. It does not
// say whether that listener is PLAINTEXT, SSL, SASL_PLAINTEXT or SASL_SSL —
// Kafka does not put the security protocol on the wire at this version, and a
// cluster routinely runs several listeners at once. Every available shortcut is
// a guess dressed as a fact:
//
//   - **The port.** 9093 is a convention, not evidence. ADR 0011 already refuses
//     to infer a service from a port and ADR 0024 refuses to infer TLS from one;
//     doing it here would be the same mistake a third time.
//   - **The bootstrap connection.** That the operator reached *this* broker over
//     verified TLS says what one listener does, and the advertised endpoint may
//     be a different listener on a different port of a different machine.
//     Copying the bootstrap's TLS settings would silently turn "the run was
//     encrypted" into "the cluster is encrypted".
//   - **The node identifier, the hostname, or Kafka convention.** None of them
//     is a statement about a listener at all.
//
// So the plan is a parameter. A caller that wants TLS says so and supplies the
// trust material; a caller that does not gets TCP and stops there.
//
// # It is execution intent, and never an observed channel
//
// This type says what svcdoctor will attempt. `security.Channel` says what a
// connection turned out to prove, and only the transport chain that performed
// the handshake may state one (ADR 0029). The two are deliberately different
// types travelling in opposite directions, and this one is structurally unable
// to carry the other.
//
// # TLS is the transport chain's own type
//
// `TLS` is `*transport.TLSOptions` rather than a Kafka-shaped copy of it. A
// second TLS model in an adapter would drift from the one that performs the
// handshake, and the adapter would have started reimplementing transport — the
// boundary docs/ARCHITECTURE.md section 4 exists to keep. Nil means the sweep
// stops after TCP.
type TransportPlan struct {
	// Resolver and Dialer are the probes' seams, supplied by the caller so that
	// a test can measure a whole topology without a network. Required.
	//
	// They are the same seams the bootstrap sweep used, and passing the same
	// values is the normal case: svcdoctor must resolve an advertised name the
	// way the client would, from this vantage.
	Resolver dns.Resolver
	Dialer   tcp.Dialer

	// TLS asks for a handshake on each established connection. Nil stops each
	// sweep after TCP.
	//
	// When it is set and carries no ServerName, the transport chain verifies
	// against the advertised hostname — never against the address that name
	// resolved to. That is the identity a client would check, and substituting a
	// resolved address would verify a certificate nobody presents.
	TLS *transport.TLSOptions

	// StepTimeout optionally bounds each DNS, TCP and TLS call, derived from the
	// caller's context.
	//
	// Zero means only the caller's context bounds the work, which is the same
	// contract the transport chain has had since Phase 2. It is repeated here
	// rather than replaced by a per-advertisement budget because the chain's
	// bound already covers the case a topology sweep is exposed to: one
	// black-holed address consuming the budget every later address and every
	// later advertisement needs. A second budget on top would bound the same
	// work twice with two numbers that can disagree.
	StepTimeout time.Duration
}

// validate rejects a plan that cannot produce a meaningful sweep.
//
// It runs once, before the first advertisement, so an unusable plan is a failed
// call rather than a run that measures nothing and reports success.
func (p TransportPlan) validate() error {
	switch {
	case p.Resolver == nil:
		return fmt.Errorf("%w: resolver must not be nil", ErrInvalidInput)
	case p.Dialer == nil:
		return fmt.Errorf("%w: dialer must not be nil", ErrInvalidInput)
	case p.StepTimeout < 0:
		return fmt.Errorf(
			"%w: step timeout %s must not be negative", ErrInvalidInput, p.StepTimeout)
	}
	return nil
}

// advertisedScopePrefix names what kind of execution a sweep scope belongs to.
//
// It is the readable half of the label. The opaque half follows it; see
// advertisedScope.
const advertisedScopePrefix = "advertised."

// MeasureAdvertised measures the network endpoints a cluster advertised, using
// the generic transport chain and nothing else.
//
// For each usable advertisement it runs one scoped DNS → TCP → TLS sweep whose
// root DNS node derives from that advertisement, and it closes every connection
// the sweep produced. Evidence goes into builder. Nothing else happens.
//
//	kafka.broker_advertised
//	  └── dns.lookup    [scoped]
//	        └── tcp.connect   [same scope, one per resolved address]
//	              └── tls.handshake [same scope, when the plan asked for TLS]
//
// # It stops at transport, and the stop is the phase
//
// No ApiVersions, no SaslHandshake, no authentication and no Metadata is sent to
// a discovered endpoint. There is no retry, no reconnection, no recursion, no
// depth bound and no visited set, because nothing re-enters: an advertisement
// produces a transport sweep and a transport sweep produces evidence. A second
// hop would need a traversal bound, an execution-deduplication key and a view
// about what an unreachable broker means, and each of those belongs to a layer
// that still does not exist.
//
// # It sends no credential, and has nowhere to put one
//
// The guarantee is structural rather than promised. This function takes a graph
// builder, a list of advertisements and a transport plan; none of them can hold
// a credential, a secret, an identity, a SASL mechanism or an authenticated
// session. "Same cluster" is not credential authority, and a credential
// authorized for the bootstrap endpoint stays authorized for that endpoint alone
// (ADR 0028).
//
// # One advertisement, one sweep
//
// Two advertisements naming one endpoint produce two sweeps. That is deliberate
// redundancy: see the type documentation on MeasurementResult, and ADR 0033.
//
// # Ownership
//
// Every connection a sweep establishes is closed here, in every outcome. The
// caller receives no transport.Continuation and no socket, because measurement
// is the whole purpose and there is no protocol consumer waiting behind it. A
// discovered-broker connection pool would be a resource with no reader.
//
// # Errors
//
// An error means the call could not run: a nil builder, an unusable plan, an
// advertisement that is usable but names no evidence node, or an invariant
// failure such as a graph that rejected a node. Every transport outcome — an
// unresolvable name, a refused connection, a rejected certificate, an expired
// budget — is evidence, because those are facts about the target rather than
// defects in the caller.
//
// # Cancellation
//
// The caller's context is checked before each advertisement. When it is gone the
// loop stops, and the advertisements it never reached receive no evidence at
// all: nothing was measured about them, and a node claiming otherwise would be
// the local-timeout-as-remote-failure mistake the whole claim discipline exists
// to prevent. Sweeps already performed keep their evidence.
func MeasureAdvertised(
	ctx context.Context,
	builder *domain.GraphBuilder,
	brokers []DiscoveredBroker,
	plan TransportPlan,
) (*MeasurementResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: graph builder must not be nil", ErrInvalidInput)
	}
	if err := plan.validate(); err != nil {
		return nil, err
	}

	result := &MeasurementResult{}
	for _, broker := range brokers {
		// The budget is checked before the advertisement is examined, so an
		// advertisement nobody looked at is not counted as considered. Both are
		// small numbers; only one of them is true.
		if ctx.Err() != nil {
			break
		}
		result.considered++

		// An advertisement that names no usable endpoint is skipped without
		// evidence. Phase 3.3 already recorded the problem as a FAIL node
		// carrying what did arrive, and minting a SKIPPED transport node here
		// would need a subject — an endpoint — that was never advertised. See
		// ADR 0033.
		if _, usable := broker.Endpoint(); !usable {
			continue
		}
		if err := measureAdvertisement(ctx, builder, broker, plan); err != nil {
			return nil, err
		}
		result.measured++
	}
	return result, nil
}

// measureAdvertisement runs one sweep for one advertisement and releases
// everything it established.
func measureAdvertisement(
	ctx context.Context,
	builder *domain.GraphBuilder,
	broker DiscoveredBroker,
	plan TransportPlan,
) error {
	advertisement := broker.Evidence()
	if advertisement == "" {
		// Only Metadata constructs a usable DiscoveredBroker, and it always
		// records the node first, so this is unreachable from outside the
		// package. It is checked anyway because the alternative is a sweep whose
		// derivation edge is silently missing, and a missing edge is exactly
		// what a later rule would have needed.
		return fmt.Errorf(
			"%w: advertisement for node %d names no evidence node", ErrInvalidInput, broker.NodeID())
	}

	scope, err := advertisedScope(advertisement)
	if err != nil {
		return err
	}

	sweep, err := transport.Run(ctx, builder, transport.Params{
		Host:     broker.Host(),
		Port:     broker.Port(),
		Resolver: plan.Resolver,
		Dialer:   plan.Dialer,
		TLS:      plan.TLS,
		Scope:    scope,
		// The advertisement is the reason this measurement exists, and the edge
		// records exactly that. It is derivation, not provenance: it does not
		// say the endpoint entered the run by discovery, and it must not be read
		// that way — the same host:port can be the bootstrap target too, which
		// is why `Origin` stays deferred (ADR 0031 section 6, ADR 0033).
		Parent:      advertisement,
		StepTimeout: plan.StepTimeout,
	})
	if err != nil {
		return fmt.Errorf("measuring advertised endpoint %s: %w", broker.Host(), err)
	}

	// Everything the sweep established is released here, immediately, in every
	// outcome. Nothing downstream of transport exists in this phase, so a
	// connection kept open would be a socket with no reader and no owner.
	//
	// A close error is discarded rather than returned: it says the socket was
	// already gone, which is not a fact about the target and must not stop the
	// remaining advertisements from being measured.
	_ = sweep.Close()
	return nil
}

// advertisedScope derives the execution scope of one advertisement's sweep.
//
// # What it has to achieve
//
// A run may now measure one hostname several times — that is what Phase 3.3b
// built (ADR 0032) — and each measurement needs a label that no other
// measurement in the run shares. The label must be deterministic, independent of
// insertion order, of timing and of what DNS answered, and it must survive
// through NewSweepScope unchanged.
//
// # Uniqueness is inherited, not asserted
//
// The label is derived from the advertisement's own evidence identifier. That
// identifier is already unique per advertisement fact in the run, and it is
// unique for a reason this function does not have to re-derive: GraphBuilder
// rejects a repeated identifier outright, so two advertisements that reached the
// graph necessarily have different ones (ADR 0031 section 3).
//
// The identifier is used as **opaque input**. Nothing here decodes it, splits
// it, or reads a component out of it — ADR 0019 has no decoder and this function
// does not become one.
//
// # Why a digest rather than the identifier itself
//
// ADR 0032 considered and rejected a caller-supplied full identifier as a scope,
// because the result is unreadable: the whole of
// `kafka.broker_advertised/<endpoint>/<address>/<node>/<advertised>` would be
// escaped into the middle of every DNS, TCP and TLS identifier of the sweep. It
// is also **unbounded** — it grows with the bootstrap endpoint and the advertised
// hostname, reaching 143 characters for ordinary production names — and it would
// put identity-bearing text into an identifier twice over.
//
// A digest is bounded, fixed-width and opaque:
//
//	dns.lookup/advertised.7abb44c5…be914/broker-1.internal
//
// The prefix says what kind of execution this is; the digest says which one, and
// says nothing else. That opacity is a property rather than a compromise: a
// scope must never be parsed for meaning (ADR 0032 section 5), and there is no
// meaning here to parse. **Which** advertisement caused the sweep is answered
// precisely by the parent edge, which is the record that is allowed to answer it.
//
// # The digest is not truncated, and that is the point
//
// A truncated digest would make uniqueness *probabilistic*, and this scheme is
// the one part of the repository whose value rests on uniqueness being **proven**.
// ADR 0019 argues injectivity from escaping rather than asserting it, and ADR
// 0032 section 3 restates it "honestly", caveat included. A 64-bit prefix would
// have introduced the first probabilistic element into that contract.
//
// The probability was negligible — a birthday bound of about n²/2⁶⁵, roughly
// 3×10⁻¹⁴ at a thousand advertisements — but so is the cost of removing it. The
// full digest is already computed; not slicing it costs nothing but 48 characters
// of identifier. Paying a proven property for those characters is the wrong way
// round.
//
// **The failure mode a truncation would have had was not uniformly loud**, which
// is the argument that settles it. Two advertisements colliding on a scope *and*
// naming one hostname mint one identifier, and the graph rejects the second
// loudly — but as a false failure of a healthy run. Two colliding on a scope
// while naming different hostnames produce no identifier collision at all, so
// nothing fails and two unrelated measurements quietly share a label. A scheme
// with a silent failure mode has to justify it, and there was nothing to justify
// it with.
//
// SHA-256 does not make a collision impossible — no digest can. It moves the
// question from a probability this package would have to compute and defend at
// realistic scale to the collision resistance the rest of computing already
// assumes, with no adversary in the picture: the inputs are svcdoctor's own
// derived identifiers.
//
// # It is not provenance, and it never leaves the identifier
//
// A scope says which execution a measurement belongs to. It does not say how an
// endpoint entered the run, it is not `Origin`, and no later layer may read one
// out of it. It reaches the evidence identifier and nothing else — never a
// subject, never an attribute — so a shareable report drops it with the
// identifiers it is part of, and no new redaction rule is needed (ADR 0032
// sections 5 and 8).
func advertisedScope(advertisement domain.EvidenceID) (probe.SweepScope, error) {
	// The whole digest, deliberately not a prefix of it. See above.
	digest := sha256.Sum256([]byte(advertisement))
	label := advertisedScopePrefix + hex.EncodeToString(digest[:])

	scope, err := probe.NewSweepScope(label)
	if err != nil {
		// The label is hexadecimal after a constant prefix, so this cannot
		// happen without a defect here. It is an invocation error rather than
		// evidence, because a scope svcdoctor could not construct is svcdoctor's
		// problem and not the cluster's.
		return probe.SweepScope{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return scope, nil
}

// MeasurementResult is what a reachability run leaves the caller holding: two
// counts, and deliberately nothing else.
//
// # Why it is this small
//
// Everything the phase learned is in the graph, in the canonical form the report
// will serialize. A result that also carried DNS states, TCP outcomes, TLS
// verdicts or endpoint health would be a second copy of those facts, free to
// drift from the first and tempting to consume instead of it (ADR 0013, ADR
// 0016).
//
// So there is no `Reachable bool`, no per-endpoint status and no aggregate. "One
// advertised broker refused a connection and two accepted one" is the whole
// truth; what it means about the cluster needs Kafka semantics and a severity
// policy, which is diagnosis work over frozen evidence and is not this layer's
// to take. It creates no finding and assigns no severity.
//
// # It owns no connection, unlike every other result in this package
//
// Session, HandshakeResult, AuthResult and MetadataResult all exist to hand a
// live socket to the step after them. There is no step after this one, so this
// result has nothing to hand over and no Close to call.
type MeasurementResult struct {
	considered int
	measured   int
}

// Considered returns how many advertisements this call examined.
//
// It is smaller than the list it was given when the caller's context expired
// part-way through: an advertisement the loop never reached was not considered,
// and counting it would report work that did not happen.
func (r *MeasurementResult) Considered() int { return r.considered }

// Measured returns how many transport sweeps ran.
//
// It is one per usable advertisement, including advertisements that name an
// endpoint another advertisement already named — measurement identity is not
// subject identity, and nothing here deduplicates.
//
// The difference between this and Considered is the number of advertisements
// that named no usable endpoint. Whether the shortfall instead came from an
// expired budget is a question about the caller's own context, which the caller
// already holds and this type does not restate.
func (r *MeasurementResult) Measured() int { return r.measured }
