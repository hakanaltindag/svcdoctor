package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
)

// StepConnect names the operation this probe performs.
//
// It is exported because it is part of the report contract: the same string
// appears in every report and will be matched by automation, so a second copy of
// it as a literal elsewhere is a bug waiting to happen.
const StepConnect domain.Step = "tcp.connect"

// ErrInvalidInput reports that the probe was called with something it cannot
// use, such as an unspecified address or a nil dialer.
//
// It is the only error class this package returns. A connection that is refused
// is a diagnostic fact and comes back as evidence; a zero address is a defect in
// the caller and comes back as an error.
var ErrInvalidInput = errors.New("invalid tcp probe input")

// Connect attempts one TCP connection to addr and returns what happened.
//
// endpoint is the logical identity the attempt belongs to, such as
// "primary.internal:9092". It scopes the evidence identifier and nothing else:
// see the identifier section of ADR 0019 and Result.Evidence for why it is not
// part of what the evidence claims.
//
// On success the returned Result owns a live connection. The probe does not
// close it, so the next stage can use the connection that was actually measured
// rather than dialing a second one. Close the Result in every path; it does the
// right thing whether or not the connection was taken.
//
// An error is returned only for unusable input or for a failure to construct
// valid evidence, neither of which is a statement about the target. Every
// connection outcome, including every failure, is reported through the evidence.
func Connect(
	ctx context.Context, d Dialer, endpoint string, addr netip.AddrPort,
	scope probe.SweepScope,
) (*Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if d == nil {
		return nil, fmt.Errorf("%w: dialer must not be nil", ErrInvalidInput)
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	addr, err := normalizeAddr(addr)
	if err != nil {
		return nil, err
	}
	return newResult(observe(ctx, d, addr), endpoint, scope)
}

// validateEndpoint checks the scope label, and deliberately checks very little.
//
// The endpoint is an opaque identity supplied by the caller. This probe never
// resolves it, connects to it, or interprets it, so imposing a host:port grammar
// here would reject callers for no diagnostic benefit — and the identifier
// encoding already absorbs any character (ADR 0019). Only text that cannot
// travel through an identifier at all is refused.
//
// Inner spaces are accepted for the same reason: they are legal in an identifier
// and this probe has no business deciding what a caller may call its endpoint.
func validateEndpoint(endpoint string) error {
	switch {
	case endpoint == "":
		return fmt.Errorf("%w: endpoint must not be empty", ErrInvalidInput)
	case strings.TrimSpace(endpoint) != endpoint:
		return fmt.Errorf("%w: endpoint must not have leading or trailing whitespace", ErrInvalidInput)
	}
	for _, r := range endpoint {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: endpoint must not contain control characters", ErrInvalidInput)
		}
	}
	return nil
}

// normalizeAddr rejects an address that cannot be dialed and canonicalizes the
// rest.
//
// Unmapping matters for identity rather than for dialing: ::ffff:10.0.0.1 and
// 10.0.0.1 are one address, and leaving both spellings in play would produce two
// evidence nodes and two identifiers for one attempt. The DNS probe already
// unmaps, so this agrees with what it hands over.
//
// Port zero is refused. It means "any port" to the kernel, which is not
// something a diagnostic connection attempt can be about.
func normalizeAddr(addr netip.AddrPort) (netip.AddrPort, error) {
	if !addr.Addr().IsValid() {
		return netip.AddrPort{}, fmt.Errorf("%w: address must be specified", ErrInvalidInput)
	}
	if addr.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: port must not be zero", ErrInvalidInput)
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), nil
}

// observation is the producer-local record of one connection attempt.
//
// It holds the raw dial error and the live connection, which is exactly what
// must not reach the canonical model. Keeping it unexported is what guarantees
// they cannot: normalization happens inside this package, and what leaves it is
// evidence plus an explicitly owned resource.
type observation struct {
	addr netip.AddrPort
	conn net.Conn

	// err is what the dialer returned, and ctxErr is what the caller's context
	// reported at the same moment. Both are needed: a dial cut short by the
	// caller's deadline comes back as a *net.OpError whose Timeout reports true
	// and which does not wrap context.DeadlineExceeded, so the dial error alone
	// cannot say whose deadline expired.
	err    error
	ctxErr error

	startedAt time.Time
	duration  time.Duration
}

// observe performs the dial and records what happened.
//
// This is the only function in the package that touches the network or reads a
// clock. Everything after it is a pure transformation, which is what makes
// classification testable without dialing anything.
func observe(ctx context.Context, d Dialer, addr netip.AddrPort) observation {
	startedAt := time.Now()
	conn, err := d.DialTCP(ctx, addr)
	duration := time.Since(startedAt)

	return observation{
		addr:      addr,
		conn:      conn,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  duration,
	}
}

// newResult normalizes the observation and takes ownership of any connection.
//
// If evidence cannot be built the connection is closed here. That path should be
// unreachable — every input was validated — but a probe that returned an error
// while holding an open socket would leak one, and the guard costs a line.
func newResult(o observation, endpoint string, scope probe.SweepScope) (*Result, error) {
	evidence, err := o.evidence(endpoint, scope)
	if err != nil {
		if o.conn != nil {
			_ = o.conn.Close()
		}
		return nil, err
	}
	return &Result{evidence: evidence, conn: o.conn}, nil
}

// evidence normalizes the observation into the canonical model.
//
// This is the probe boundary. Above it there is a connection, an error and a
// dialer; below it there is a layer, a step, a state, a failure class and a
// canonical address.
func (o observation) evidence(
	endpoint string, scope probe.SweepScope,
) (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(o.addr.String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		// The endpoint scopes the identifier so that two names resolving to one
		// address stay two attempts. It is not part of the subject: the dial
		// never used a name. See ADR 0019.
		ID:           probe.ScopedEvidenceID(scope, StepConnect, endpoint, o.addr.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerTCP,
		Step:         StepConnect,
		State:        state,
		FailureClass: failureClass,
		StartedAt:    o.startedAt,
		Duration:     o.duration,
	})
}

// classify decides what the observation is allowed to claim.
//
// The order of the checks is the contract:
//
//  1. A dial that returned a connection is a completed measurement. A context
//     that expires immediately afterwards does not unmake it, and the connection
//     it produced is still usable.
//  2. Otherwise the caller's context is consulted first, because svcdoctor's own
//     deadline expiring means nothing was learned about the target.
//  3. Then the error number, which is the network stack's own account of what
//     happened.
//  4. Then any remaining timeout, which is attributed to svcdoctor rather than to
//     the target, because nothing identified it as the network's.
func (o observation) classify() (domain.State, domain.FailureClass) {
	if o.err == nil {
		if o.conn == nil {
			// A dialer that reports neither success nor failure has told us
			// nothing, and inventing an outcome for it would be a claim about
			// the target that no observation supports.
			return domain.StateUnknown, domain.FailureNone
		}
		return domain.StatePass, domain.FailureNone
	}

	switch {
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded), errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}

	if class, ok := classifyDialError(o.err); ok {
		return domain.StateFail, class
	}
	if isTimeout(o.err) {
		// A timeout that carries no error number is not the network stack's
		// report of an unanswered SYN; it is a deadline something on this side
		// imposed. Calling it TCP_CONNECTION_TIMEOUT would turn our own budget
		// into a claim about the peer.
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}
	return domain.StateFail, domain.FailureTCPConnectionFailed
}

// classifyDialError maps the network stack's error number onto the domain
// vocabulary, and reports whether it recognized one.
//
// Error numbers are the structured form of what happened, reached through
// errors.Is so that the *net.OpError and *os.SyscallError wrappers do not matter.
// Matching on error text was rejected: the text differs by platform and Go
// release, so a probe that matched it would make confident claims that quietly
// stop being true.
//
// ETIMEDOUT is deliberately here rather than with the generic timeout handling.
// It is the kernel reporting that a SYN went unanswered within its own limit,
// which is evidence about the network, and it is the one timeout this probe can
// attribute to the target rather than to itself.
//
// Recognition is best-effort by platform. Where a platform reports a refused
// connection in a form errors.Is does not match, the caller falls back to
// TCP_CONNECTION_FAILED, which is vaguer but never wrong.
func classifyDialError(err error) (domain.FailureClass, bool) {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return domain.FailureTCPConnectionRefused, true
	case errors.Is(err, syscall.ECONNRESET):
		return domain.FailureTCPConnectionReset, true
	case errors.Is(err, syscall.ENETUNREACH):
		return domain.FailureTCPNetworkUnreachable, true
	case errors.Is(err, syscall.EHOSTUNREACH):
		return domain.FailureTCPHostUnreachable, true
	case errors.Is(err, syscall.ETIMEDOUT):
		return domain.FailureTCPConnectionTimeout, true
	}
	return domain.FailureNone, false
}

// isTimeout reports whether err describes a deadline rather than a network
// condition, after error numbers have already been ruled out.
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}
