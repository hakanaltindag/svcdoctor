package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
)

// StepLookup names the operation this probe performs.
//
// It is exported because it is part of the report contract: the same string
// appears in every report and will be matched by automation, so a second copy of
// it as a literal elsewhere is a bug waiting to happen.
const StepLookup domain.Step = "dns.lookup"

// AttrAnswers holds the canonical addresses a lookup returned, one address per
// entry.
//
// It is recorded as a host list rather than a string list because the values
// identify network peers: the producer declares that, so structural redaction
// never has to infer it (ADR 0022).
//
// This is the only attribute the DNS probe records. Counts and family
// breakdowns are derivable from the list, and a derived attribute is a second
// copy of a fact that can drift from the first.
const AttrAnswers domain.AttributeKey = "dns.answers"

// ErrInvalidInput reports that the probe was called with something it cannot
// use, such as an empty hostname or a nil resolver.
//
// It is deliberately the only error class this package returns. A name that does
// not resolve is a diagnostic fact and comes back as evidence; an empty hostname
// is a defect in the caller and comes back as an error.
var ErrInvalidInput = errors.New("invalid dns probe input")

// Lookup resolves host through r and returns one normalized evidence node.
//
// It returns an error only for unusable input or for a failure to construct
// valid evidence. Every DNS outcome, including every failure, is reported
// through the returned evidence: see the state and failure classification table
// in the package documentation.
//
// The context is honoured by the resolver and is also what distinguishes a local
// budget expiry from a remote failure. Cancelling it does not discard the
// measurement; it changes what the evidence is allowed to claim.
func Lookup(
	ctx context.Context, r Resolver, host string, scope probe.SweepScope,
) (domain.Evidence, error) {
	if ctx == nil {
		return domain.Evidence{}, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if r == nil {
		return domain.Evidence{}, fmt.Errorf("%w: resolver must not be nil", ErrInvalidInput)
	}
	if err := validateHost(host); err != nil {
		return domain.Evidence{}, err
	}
	return observe(ctx, r, host, scope).evidence()
}

// validateHost rejects input the probe cannot turn into a meaningful query.
//
// It is deliberately not a hostname grammar. svcdoctor asks the resolver what
// the client would ask, and a name this code considers unusual may still be one
// the resolver answers; rejecting it here would produce no evidence at all about
// a question the user asked. So this checks only what would make the probe
// itself incoherent.
//
// It also performs no normalization. Lowercasing, trailing-dot handling and IDNA
// conversion all change what was queried, and evidence must record the question
// that was actually asked.
//
// A host containing the identifier separator is accepted. Phase 2.1 refused one,
// which was a bookkeeping constraint leaking into what svcdoctor would look at;
// the identifier encoding now escapes it instead (ADR 0019).
func validateHost(host string) error {
	switch {
	case host == "":
		return fmt.Errorf("%w: host must not be empty", ErrInvalidInput)
	case strings.TrimSpace(host) != host:
		return fmt.Errorf("%w: host must not have leading or trailing whitespace", ErrInvalidInput)
	}
	for _, r := range host {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: host must not contain control characters", ErrInvalidInput)
		}
		if unicode.IsSpace(r) {
			return fmt.Errorf("%w: host must not contain whitespace", ErrInvalidInput)
		}
	}
	return nil
}

// observation is the producer-local record of one lookup.
//
// It is what the architecture calls an observation, and it is deliberately
// shaped like DNS rather than like evidence: it holds the raw resolver error and
// the raw address values, which is exactly what must not reach the canonical
// model. Keeping it unexported is what guarantees they cannot: normalization
// happens inside this package, and only domain.Evidence leaves it.
//
// There is no domain.Observation and there should never be one. An observation
// is producer-shaped by definition, and a generic version could only duplicate
// Evidence or become the arbitrary payload ADR 0010 forbids.
type observation struct {
	host  string
	scope probe.SweepScope
	addrs []netip.Addr

	// err is what the resolver returned, and ctxErr is what the caller's context
	// reported at the same moment. Both are needed: the standard library does not
	// wrap context.DeadlineExceeded in the *net.DNSError it returns for a caller
	// deadline, so the resolver error alone cannot say whose deadline expired.
	err    error
	ctxErr error

	startedAt time.Time
	duration  time.Duration
}

// observe performs the lookup and records what happened.
//
// This is the only function in the package that performs I/O or reads a clock.
// Everything after it is a pure transformation, which is what makes
// classification testable without a resolver at all.
//
// time.Now carries a monotonic reading and time.Since uses it, so the duration is
// unaffected by wall-clock adjustment during the lookup. domain.Evidence
// normalizes the start instant to UTC and drops the monotonic part, which is
// meaningless once serialized.
func observe(
	ctx context.Context, r Resolver, host string, scope probe.SweepScope,
) observation {
	startedAt := time.Now()
	addrs, err := r.LookupAddresses(ctx, host)
	duration := time.Since(startedAt)

	return observation{
		host:      host,
		scope:     scope,
		addrs:     addrs,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  duration,
	}
}

// evidence normalizes the observation into the canonical model.
//
// This is the probe boundary. Above it there are addresses, errors and a
// resolver; below it there is a layer, a step, a state, a failure class and
// canonical strings.
func (o observation) evidence() (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(o.host)
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	answers := o.answers()
	state, failureClass := o.classify(len(answers))

	var attributes map[domain.AttributeKey]domain.AttrValue
	if len(answers) > 0 {
		attributes = map[domain.AttributeKey]domain.AttrValue{
			AttrAnswers: domain.HostListAttr(answers...),
		}
	}

	return domain.NewEvidence(domain.EvidenceInput{
		ID:           evidenceID(o.host, o.scope),
		Subject:      subject,
		Layer:        domain.LayerDNS,
		Step:         StepLookup,
		State:        state,
		FailureClass: failureClass,
		Attributes:   attributes,
		StartedAt:    o.startedAt,
		Duration:     o.duration,
	})
}

// answers returns the resolved addresses in canonical form.
//
// The resolver's order is discarded. It is not stable between calls or between
// resolvers, and a canonical report must be byte-identical for the same facts:
// two runs that learned the same three addresses must not differ because a
// resolver rotated them.
//
// Duplicates are removed because a repeated address is a property of the answer
// encoding rather than a diagnostic fact, and an IPv4-mapped IPv6 form is
// unmapped so that one address has one canonical spelling. An invalid address is
// dropped rather than recorded, since there is nothing a later layer could do
// with it; if that leaves nothing, the lookup is classified as having returned no
// usable address.
func (o observation) answers() []string {
	if len(o.addrs) == 0 {
		return nil
	}

	addrs := make([]netip.Addr, 0, len(o.addrs))
	for _, addr := range o.addrs {
		if !addr.IsValid() {
			continue
		}
		addrs = append(addrs, addr.Unmap())
	}

	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	addrs = slices.Compact(addrs)

	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, len(addrs))
	for i, addr := range addrs {
		out[i] = addr.String()
	}
	return out
}

// classify decides what the observation is allowed to claim.
//
// The order of the checks is the contract:
//
//  1. A lookup that returned without error is a completed measurement. Its
//     outcome is decided by what came back, and a context that expired
//     afterwards does not unmake it.
//  2. Otherwise the caller's context is consulted first, because svcdoctor's own
//     deadline expiring means nothing was learned about the target. Claiming a
//     remote failure there would be the false positive the whole claim discipline
//     exists to prevent.
//  3. Only then is the resolver's own error classified.
func (o observation) classify(answerCount int) (domain.State, domain.FailureClass) {
	if o.err == nil {
		if answerCount == 0 {
			return domain.StateFail, domain.FailureDNSNoAddress
		}
		return domain.StatePass, domain.FailureNone
	}

	switch {
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded), errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}

	return domain.StateFail, classifyResolverError(o.err)
}

// classifyResolverError normalizes a resolver error into the domain vocabulary.
//
// Only the classified facts survive; the error itself is discarded here. A
// resolver error string can name the resolver's own address, a search domain or
// the queried host, in prose that structural redaction cannot recognize, so it
// must not reach evidence.
//
// Not-found becomes DNS_NO_ADDRESS rather than DNS_NXDOMAIN on purpose. The
// standard library sets IsNotFound both when a name does not exist and when it
// exists with no address record, so NXDOMAIN would assert a non-existence the
// resolver never evidenced. DNS_NO_ADDRESS makes no claim about existence, which
// is what makes it true in both cases. DNS_NXDOMAIN stays reserved for a resolver
// that reports non-existence distinctly.
//
// Anything else the resolver returned is DNS_RESOLVER_FAILURE, which is the
// literal truth of the situation: the resolver reported a failure svcdoctor
// cannot classify further. That keeps an unrecognized error a recorded DNS-layer
// fact instead of silently becoming a stronger or weaker claim.
func classifyResolverError(err error) domain.FailureClass {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsTimeout:
			return domain.FailureDNSTimeout
		case dnsErr.IsNotFound:
			return domain.FailureDNSNoAddress
		}
	}
	return domain.FailureDNSResolverFailure
}

// evidenceID derives the identifier of one evidence node.
//
// A lookup is about a name and nothing else, so the queried name is the only
// component. The encoding, including what happens to a name containing the
// separator, belongs to internal/probe so that every probe agrees on it.
// See ADR 0019.
//
// The scope distinguishes two sweeps that queried the same name, and nothing
// else: it is not part of what was looked up, and it never reaches the subject.
// A zero scope reproduces the identifier this probe has minted since Phase 2.
// See ADR 0032.
func evidenceID(host string, scope probe.SweepScope) domain.EvidenceID {
	return probe.ScopedEvidenceID(scope, StepLookup, host)
}
