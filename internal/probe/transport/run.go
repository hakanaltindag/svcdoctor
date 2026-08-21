package transport

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tls"
)

// Run inspects one endpoint and records what happened at every layer it reached.
//
// It resolves the host, attempts a TCP connection to every resolved address in
// canonical order, and performs a TLS handshake on each established connection
// when params.TLS asks for one. Evidence goes into builder; the returned Result
// owns the connection of every path that completed.
//
// # What it returns, and what it refuses to return
//
// An error means the chain could not run: unusable input, or an invariant
// failure such as a graph that rejected a node. Every transport outcome —
// refused, unresolvable, rejected certificate, expired budget — is evidence, not
// an error, because those are facts about the target rather than defects in the
// caller.
//
// There is deliberately no overall status. "Two addresses worked and one did
// not" is the whole truth, and deciding what that means about the endpoint needs
// a severity policy this layer does not have.
//
// The Result carries every path that completed, and the chain picks none of
// them: choosing which working path a protocol should speak over belongs to the
// layer that knows what it is about to say (ADR 0024).
//
// # Cleanup
//
// On an error the chain closes anything it still owned, so a failed call leaks
// nothing. On success the caller owns the Result and closes it.
func Run(ctx context.Context, builder *domain.GraphBuilder, params Params) (*Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: graph builder must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	result := &Result{}
	completed := false
	defer func() {
		if !completed {
			_ = result.Close()
		}
	}()

	lookupCtx, cancel := stepContext(ctx, params.StepTimeout)
	lookup, err := dns.Lookup(lookupCtx, params.Resolver, params.Host)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("dns lookup: %w", err)
	}
	if err := builder.AddEvidence(lookup); err != nil {
		return nil, fmt.Errorf("recording dns evidence: %w", err)
	}

	for _, address := range resolvedAddresses(lookup) {
		addr := netip.AddrPortFrom(address, params.Port)
		if err := sweepAddress(ctx, builder, params, lookup.ID(), addr, result); err != nil {
			return nil, err
		}
	}

	completed = true
	return result, nil
}

// stepContext bounds one probe call, and is written as a closure so that Run
// reads as a sequence of steps rather than as context plumbing.
func stepContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

// resolvedAddresses reads the canonical answers back out of the lookup evidence.
//
// The evidence is the DNS probe's only output by design: ADR 0020 lets nothing
// else leave a probe, and the recorded answers are already sorted, deduplicated
// and canonical, which is exactly the iteration order this chain needs. Reading
// them back therefore costs a parse and buys one representation instead of two.
//
// A value that does not parse is skipped rather than guessed at. The probe
// produced these from netip.Addr, so this cannot happen without a defect there.
func resolvedAddresses(lookup domain.Evidence) []netip.Addr {
	value, ok := lookup.Attribute(dns.AttrAnswers)
	if !ok {
		return nil
	}
	answers, ok := value.HostList()
	if !ok {
		return nil
	}

	addresses := make([]netip.Addr, 0, len(answers))
	for _, answer := range answers {
		address, err := netip.ParseAddr(answer)
		if err != nil {
			continue
		}
		addresses = append(addresses, address)
	}
	return addresses
}

// sweepAddress runs the requested layers against one concrete address.
//
// It records evidence for whatever it reached and hands any surviving connection
// to result, which decides whether to keep it.
func sweepAddress(
	ctx context.Context,
	builder *domain.GraphBuilder,
	params Params,
	parent domain.EvidenceID,
	addr netip.AddrPort,
	result *Result,
) error {
	// The budget is checked before the attempt rather than inside it, so that an
	// address nobody tried is recorded as not attempted rather than as a
	// measurement that failed. Both are UNKNOWN-shaped claims, but only one of
	// them is true.
	if err := ctx.Err(); err != nil {
		return recordUnattempted(builder, params, parent, addr, budgetFailure(err))
	}

	stepCtx, cancel := stepContext(ctx, params.StepTimeout)
	connection, err := tcp.Connect(stepCtx, params.Dialer, params.endpoint(), addr)
	cancel()
	if err != nil {
		return fmt.Errorf("tcp connect: %w", err)
	}
	defer func() { _ = connection.Close() }()

	tcpEvidence := connection.Evidence()
	if err := add(builder, tcpEvidence, parent); err != nil {
		return err
	}

	if !connection.Connected() {
		if params.TLS == nil {
			return nil
		}
		return recordSkippedTLS(builder, params, tcpEvidence.ID(), addr)
	}

	if params.TLS == nil {
		conn, _ := connection.TakeConn()
		result.add(conn, params.endpoint(), addr, tcpEvidence.ID())
		return nil
	}

	return handshake(ctx, builder, params, connection, addr, result)
}

// handshake takes the established connection through TLS.
//
// Ownership moves in one direction and never forks: the TCP result hands the
// connection to tls.Handshake, which owns it in every outcome, and the TLS
// result hands it to this chain's Result only when the handshake completed.
func handshake(
	ctx context.Context,
	builder *domain.GraphBuilder,
	params Params,
	connection *tcp.Result,
	addr netip.AddrPort,
	result *Result,
) error {
	conn, ok := connection.TakeConn()
	if !ok {
		return fmt.Errorf("%w: established connection could not be taken", domain.ErrInvalidValue)
	}

	stepCtx, cancel := stepContext(ctx, params.StepTimeout)
	session, err := tls.Handshake(stepCtx, conn, params.tlsParams(addr))
	cancel()
	if err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer func() { _ = session.Close() }()

	tlsEvidence := session.Evidence()
	if err := add(builder, tlsEvidence, connection.Evidence().ID()); err != nil {
		return err
	}

	if !session.Connected() {
		return nil
	}

	wrapped, _ := session.TakeConn()
	result.add(wrapped, params.endpoint(), addr, tlsEvidence.ID())
	return nil
}

// recordUnattempted records that an address was never tried because the caller's
// budget was gone.
//
// The TCP node states why, and the TLS node — when one was requested — is
// blocked by it, so the graph reads the same way whether TCP failed or never
// ran: a TLS node that did not execute always points at the TCP node that did
// not hand it a connection.
func recordUnattempted(
	builder *domain.GraphBuilder,
	params Params,
	parent domain.EvidenceID,
	addr netip.AddrPort,
	failure domain.FailureClass,
) error {
	skipped, err := skippedEvidence(tcp.StepConnect, domain.LayerTCP, params.endpoint(), addr, failure)
	if err != nil {
		return err
	}
	if err := add(builder, skipped, parent); err != nil {
		return err
	}
	if params.TLS == nil {
		return nil
	}
	return recordSkippedTLS(builder, params, skipped.ID(), addr)
}

// recordSkippedTLS records that TLS was requested for an address but not
// attempted, because TCP produced no connection to run it over.
//
// The node is honest about what it is: a SKIPPED state, the classification that
// says a prerequisite did not deliver, no attributes, and a zero duration
// because nothing ran. Its subject is the address, which is the concrete thing
// the handshake would have used and which the run genuinely knows.
func recordSkippedTLS(
	builder *domain.GraphBuilder,
	params Params,
	blocker domain.EvidenceID,
	addr netip.AddrPort,
) error {
	skipped, err := skippedEvidence(
		tls.StepHandshake, domain.LayerTLS, params.endpoint(), addr,
		domain.FailureExecSkippedPrerequisiteFailed,
	)
	if err != nil {
		return err
	}
	if err := add(builder, skipped, blocker); err != nil {
		return err
	}
	if err := builder.AddBlockedBy(skipped.ID(), blocker); err != nil {
		return fmt.Errorf("recording blocked-by for %s: %w", skipped.ID(), err)
	}
	return nil
}

// skippedEvidence builds a node for a step that did not run.
//
// It uses the same identifier scheme and subject the probe itself would have
// used, so a skipped node sits exactly where the executed one would have, and a
// later run against a working target produces the same identifier for the same
// step.
func skippedEvidence(
	step domain.Step,
	layer domain.Layer,
	endpoint string,
	addr netip.AddrPort,
	failure domain.FailureClass,
) (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(addr.String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("subject for skipped %s: %w", step, err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           probe.EvidenceID(step, endpoint, addr.Addr().String()),
		Subject:      subject,
		Layer:        layer,
		Step:         step,
		State:        domain.StateSkipped,
		FailureClass: failure,
		StartedAt:    time.Now(),
		Duration:     0,
	})
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("building skipped %s evidence: %w", step, err)
	}
	return evidence, nil
}

// budgetFailure says whose budget ended the sweep.
//
// A cancelled run and an expired deadline are different facts, and neither is a
// claim about the target: both stay on svcdoctor's side of the line.
func budgetFailure(err error) domain.FailureClass {
	if errors.Is(err, context.DeadlineExceeded) {
		return domain.FailureExecLocalTimeout
	}
	return domain.FailureExecCancelled
}

// add records one node and its parent edge.
//
// Parent means derivation: a TCP attempt exists because the lookup produced that
// address, and a TLS handshake exists because that connection was established.
// It does not record how the endpoint entered the run, which is `Origin` and
// remains deferred (ADR 0013).
func add(builder *domain.GraphBuilder, evidence domain.Evidence, parent domain.EvidenceID) error {
	if err := builder.AddEvidence(evidence); err != nil {
		return fmt.Errorf("recording %s evidence: %w", evidence.Step(), err)
	}
	if err := builder.AddParent(evidence.ID(), parent); err != nil {
		return fmt.Errorf("recording parent of %s: %w", evidence.ID(), err)
	}
	return nil
}
