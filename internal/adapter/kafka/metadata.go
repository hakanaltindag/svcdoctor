package kafka

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// The two steps this file produces.
//
// StepMetadata is the exchange: one request, one response, one outcome.
// StepBrokerAdvertised is one fact carried by that response.
//
// They are separate steps rather than one node with a list, and the reason is
// what a later phase has to be able to say. A rule that concludes "the broker
// the cluster advertises as node 3 cannot be reached from here" must reference
// the exact evidence that produced it (ADR 0014), and a transport probe of that
// broker must parent to something. If every broker lived inside a string list on
// one node, both would have to point at the whole exchange, and "which entry
// caused this?" would be answerable only by parsing an attribute — which ADR
// 0019 forbids for identifiers and ADR 0018 forbids for redaction. See ADR 0031.
//
// # They live in internal/service/kafka now
//
// Phase 3.6 is the second consumer ADR 0031 section 9 named as the reopen
// condition: a diagnosis rule anchors at StepBrokerAdvertised and requires
// StepMetadata, and depguard denies diagnosis this package. The definitions
// moved to the leaf vocabulary package and are re-exported here, so every
// existing reference, evidence identifier and serialized report is unchanged —
// the move is a change of definition site and of nothing else. See ADR 0034
// section 19.
const (
	StepMetadata         = servicekafka.StepMetadata
	StepBrokerAdvertised = servicekafka.StepBrokerAdvertised
)

// The attributes topology discovery records.
//
// All but one live here, for the reason given on the ApiVersions keys: an
// attribute key belongs with the code that produces it until something outside
// this package genuinely reads it. AttrBrokerNodeID now is read outside, so it
// moved; the rest are not, so they did not. ADR 0034 section 19 fixed that split
// deliberately rather than moving the group for consistency — in particular the
// advertised host and port stay here, because they are already on the
// advertisement's subject and a second copy would create two sources for one
// fact.
const (
	// AttrMetadataControllerID is the node the cluster named as its controller.
	//
	// Kafka's own default is -1, meaning the responding broker knows of no
	// controller. That is a statement rather than an absence, so it is recorded
	// whenever the exchange completed.
	AttrMetadataControllerID domain.AttributeKey = "kafka.metadata.controller_id"

	// AttrMetadataBrokerCount is how many distinct advertisements were recorded.
	AttrMetadataBrokerCount domain.AttributeKey = "kafka.metadata.broker_count"

	// AttrMetadataAdvertisedEntryCount is how many broker entries the response
	// actually carried, before identical repetitions were collapsed.
	//
	// It exists so that the one collapse this step performs is visible. A
	// response listing the same broker twice differs from one listing it once,
	// and a reader can see the difference here rather than having to trust that
	// nothing was quietly merged.
	AttrMetadataAdvertisedEntryCount domain.AttributeKey = "kafka.metadata.advertised_entry_count"

	// AttrMetadataUnrepresentableCount is how many entries could not be recorded
	// as their own node at all, because the text they carried cannot be a
	// subject reference — a control character, for instance.
	//
	// Recorded only when it is non-zero. It closes the one hole through which an
	// entry could otherwise vanish without trace.
	AttrMetadataUnrepresentableCount domain.AttributeKey = "kafka.metadata.unrepresentable_entry_count"

	// AttrBrokerNodeID is the broker identity this Metadata response reported.
	//
	// An integer, and never an endpoint — which is the whole reason it is
	// recorded separately from the advertised host and port.
	//
	// It is what the responding broker said, and no more. A single response
	// does not prove the identifier is unique in the cluster or stable across
	// restarts, and this step deliberately preserves responses where it is
	// neither. Treating it as a durable cluster-wide identity would be a claim
	// the protocol does not make.
	//
	// It moved to internal/service/kafka with the two steps above and for the
	// same reason: a rule names the broker a finding is about. It is re-exported
	// here, so its value and every use of it are unchanged (ADR 0034 section 19).
	AttrBrokerNodeID = servicekafka.AttrBrokerNodeID

	// AttrBrokerAdvertisedHost is the host a broker was advertised at.
	//
	// It is a declared identity-bearing value (ADR 0022), not a plain string,
	// and that is load-bearing rather than tidy: an advertised broker hostname
	// is exactly the kind of internal name a shared report must not carry, and
	// redaction cannot recognize one by looking at it — "broker-7.prod.internal"
	// and "TLSv1.3" are the same shape. Declaring it makes the question
	// decidable instead of heuristic.
	AttrBrokerAdvertisedHost domain.AttributeKey = "kafka.broker.advertised_host"

	// AttrBrokerAdvertisedPort is the port a broker was advertised at, exactly
	// as it arrived. An impossible value is recorded rather than corrected,
	// because an impossible advertised port is a fact about the cluster.
	AttrBrokerAdvertisedPort domain.AttributeKey = "kafka.broker.advertised_port"
)

// MetadataParams carries what the exchange needs beyond the session.
type MetadataParams struct {
	// ExchangeTimeout optionally bounds the exchange, derived from the caller's
	// context. Zero means only the caller's context bounds the work.
	ExchangeTimeout time.Duration
}

// validate rejects input the step cannot turn into a meaningful exchange.
func (p MetadataParams) validate() error {
	if p.ExchangeTimeout < 0 {
		return fmt.Errorf(
			"%w: exchange timeout %s must not be negative", ErrInvalidInput, p.ExchangeTimeout)
	}
	return nil
}

// Metadata asks one broker to describe the cluster's brokers.
//
// Evidence goes into builder: one L6 exchange node parented to the session's
// authentication node, and one L6 node per advertised broker parented to the
// exchange. The returned MetadataResult owns the connection when the exchange
// completed.
//
// # It discovers, and it probes nothing
//
// This is the first step in svcdoctor that learns about endpoints the operator
// never named. It records them and stops. It does not resolve them, dial them,
// speak Kafka to them, or send any credential anywhere — and none of that is an
// oversight. Probing a discovered broker needs a credential-forwarding decision,
// an execution-deduplication key, a recursion bound and a view about what an
// unreachable advertised broker *means*; each belongs to a layer that does not
// exist, and bundling them here would settle four architectural questions as a
// side effect of a protocol exchange. The advertisement is already the useful
// fact. See ADR 0031.
//
// # It asks for no topics
//
// The request names zero topics, so the response describes brokers and nothing
// else. That is the smallest question that yields a cluster topology: topic
// metadata is orders of magnitude larger, needs describe authority on every
// topic, changes between runs, and says nothing about which brokers exist.
//
// # Authenticated sessions only, which is scope rather than protocol truth
//
// Kafka serves Metadata perfectly well on a PLAINTEXT or SSL listener with no
// SASL at all. svcdoctor cannot reach that path today, because the only session
// type that survives the adapter chain is an authenticated one, and inventing a
// common session abstraction to fix it would erase the compile-time ordering
// that makes "authenticate before the mechanism was agreed" impossible. The
// restriction is this repository's, not Kafka's, and it is recorded as such.
//
// # Errors
//
// An error means the step could not run: unusable input, or an invariant failure
// such as a graph that rejected a node. Every protocol outcome is evidence.
func Metadata(
	ctx context.Context,
	builder *domain.GraphBuilder,
	session *AuthenticatedSession,
	params MetadataParams,
) (*MetadataResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: graph builder must not be nil", ErrInvalidInput)
	}
	if session == nil {
		return nil, fmt.Errorf("%w: session must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	conn, ok := session.TakeConn()
	if !ok {
		return nil, fmt.Errorf(
			"%w: the session has no connection to describe the cluster over", ErrInvalidInput)
	}

	result := &MetadataResult{}
	transferred := false
	defer func() {
		if !transferred {
			_ = conn.Close()
		}
	}()

	observed := observeMetadata(ctx, conn, params)
	advertisements, unrepresentable := advertisementsOf(observed)

	evidence, err := observed.evidence(session, advertisements, unrepresentable)
	if err != nil {
		return nil, err
	}
	if err := record(builder, evidence, session.Evidence()); err != nil {
		return nil, err
	}
	result.evidenceID = evidence.ID()

	// An exchange that broke leaves a socket whose protocol state nobody knows,
	// and no topology to record. An exchange that completed leaves both.
	if observed.err != nil {
		return result, nil
	}

	if err := recordAdvertisements(
		builder, session, evidence.ID(), advertisements, observed.startedAt, result,
	); err != nil {
		return nil, err
	}

	// Metadata reads the cluster's description and changes no protocol state, so
	// the connection is exactly as usable afterwards as before: still
	// authenticated, and able to carry any request the broker offers. This is
	// the first Kafka step whose success hands back the same kind of session it
	// consumed rather than a stronger one, and the reason is that it asked a
	// question rather than advancing a handshake.
	result.continued(conn, session)
	transferred = true
	return result, nil
}

// metadataObservation is the producer-local record of one exchange.
type metadataObservation struct {
	response wire.Metadata

	// err is what the exchange returned, and ctxErr is what the caller's context
	// reported at the same moment. Both are needed for the reason every probe
	// needs them: a deadline that belongs to svcdoctor must never be reported as
	// a claim about the peer.
	err    error
	ctxErr error

	startedAt time.Time
	duration  time.Duration
}

// observeMetadata performs the exchange and records what happened.
//
// This is the only function here that performs I/O or reads a clock; everything
// after it is a pure transformation.
func observeMetadata(
	ctx context.Context, conn net.Conn, params MetadataParams,
) metadataObservation {
	exchangeCtx := ctx
	if params.ExchangeTimeout > 0 {
		var cancel context.CancelFunc
		exchangeCtx, cancel = context.WithTimeout(ctx, params.ExchangeTimeout)
		defer cancel()
	}

	startedAt := time.Now()
	response, err := wire.ExchangeMetadata(exchangeCtx, conn)
	duration := time.Since(startedAt)

	return metadataObservation{
		response:  response,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  duration,
	}
}

// advertisement is one normalized broker entry, before it becomes evidence.
type advertisement struct {
	nodeID int32

	// host is the normalized advertised host, which may be empty when the
	// broker advertised no host at all.
	host string

	// rawPort is what arrived. port is the validated form, and usable says
	// whether the pair names somewhere a client could actually connect.
	rawPort int32
	port    uint16
	usable  bool

	// ref is the advertised endpoint as text, and is what the node's subject and
	// identifier are built from.
	ref string

	// subject is built during normalization by the same constructor every other
	// producer uses, so "can this entry be a node?" is answered by the domain
	// model rather than by a second copy of its rules living here.
	subject domain.Subject
}

// advertisementsOf normalizes the response's broker list.
//
// It collapses byte-identical repetitions and nothing else. Two entries that
// disagree — one node identifier at two addresses, or two node identifiers at
// one address — stay two advertisements, because a diagnostic tool that tidied
// a contradiction away would be hiding the finding somebody ran it to get.
//
// The second return value counts entries whose text cannot be a subject
// reference at all, so that even those leave a trace.
func advertisementsOf(o metadataObservation) ([]advertisement, int) {
	if o.err != nil {
		return nil, 0
	}

	out := make([]advertisement, 0, len(o.response.Brokers))
	seen := make(map[string]struct{}, len(o.response.Brokers))
	unrepresentable := 0

	for _, broker := range o.response.Brokers {
		entry := normalizeAdvertisement(broker)

		subject, err := domain.NewEndpointSubject(entry.ref)
		if err != nil {
			// The text a broker advertised cannot be a subject reference — a
			// control character, for instance. There is no node to record it on,
			// so it is counted on the exchange instead of vanishing.
			unrepresentable++
			continue
		}
		entry.subject = subject

		// The key pairs the two identities rather than choosing between them, so
		// a repetition has to agree on both to be treated as one fact.
		key := strconv.FormatInt(int64(entry.nodeID), 10) + "\x00" + entry.ref
		if _, repeated := seen[key]; repeated {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, entry)
	}
	return out, unrepresentable
}

// normalizeAdvertisement applies the endpoint rules to one broker entry.
//
// # Normalization here is not credential normalization
//
// The rules match security.Endpoint's — ASCII-only lowercasing because DNS case
// insensitivity is defined for ASCII (RFC 4343), a single trailing dot removed,
// IP literals canonicalized through net/netip — but the type deliberately does
// not. A security.Endpoint exists to authorize a credential, and its Equal is a
// credential-authority decision. A discovered broker is an execution target that
// no credential has been authorized for, and handing one out as a
// security.Endpoint would put credential forwarding one function call away from
// a caller who merely wanted somewhere to connect. Same rules, different type,
// no conversion offered. See ADR 0031.
//
// Nothing is resolved. A hostname stays a hostname: turning it into an address
// here would make a DNS answer part of a topology fact, and the whole point of
// the later reachability phase is to measure that answer rather than assume it.
func normalizeAdvertisement(broker wire.MetadataBroker) advertisement {
	entry := advertisement{nodeID: broker.NodeID, rawPort: broker.Port}
	entry.host = normalizeAdvertisedHost(broker.Host)

	// A port is a uint16 on the wire in every protocol that has one; Kafka
	// carries it as int32, so anything outside the range is something the
	// cluster said that no client can act on. Port 0 is rejected with the rest:
	// nothing listens on it, and security.Endpoint refuses it for the same
	// reason.
	if entry.host != "" && broker.Port > 0 && broker.Port <= 65535 {
		entry.port = uint16(broker.Port)
		entry.usable = true
	}

	entry.ref = advertisedRef(entry.host, broker.Port)
	return entry
}

// normalizeAdvertisedHost applies the DNS rules, and only those.
func normalizeAdvertisedHost(host string) string {
	if host == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	if len(host) > 1 && strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}
	return asciiLower(host)
}

// asciiLower lowercases A-Z only, leaving every other byte untouched.
//
// Unicode case folding is deliberately not applied: DNS case insensitivity is
// an ASCII rule, and folding a non-ASCII label would make svcdoctor treat two
// distinct names as one.
func asciiLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// advertisedRef renders an advertisement as text.
//
// It renders what was advertised rather than what would work, so an unusable
// entry still reads as the endpoint the cluster named — ":9092" for a missing
// host, "broker:-1" for an impossible port. That is the fact, and inventing a
// plausible substitute would be inventing a target.
func advertisedRef(host string, port int32) string {
	return bracketed(host) + ":" + strconv.FormatInt(int64(port), 10)
}

// joinHostPort renders a usable endpoint.
func joinHostPort(host string, port uint16) string {
	return bracketed(host) + ":" + strconv.FormatUint(uint64(port), 10)
}

// bracketed wraps an IPv6 literal so that its colons cannot be mistaken for the
// port separator. A DNS name never contains a colon.
func bracketed(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// evidence normalizes the exchange into the canonical model.
//
// The subject is the concrete peer that answered, matching every node for the
// same path from L1 upward, so a reader can follow one address all the way to
// the topology it described.
func (o metadataObservation) evidence(
	session *AuthenticatedSession, advertisements []advertisement, unrepresentable int,
) (domain.Evidence, error) {
	address := session.Address()

	subject, err := domain.NewEndpointSubject(address.String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		ID:           probe.EvidenceID(StepMetadata, session.Endpoint(), address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerTopology,
		Step:         StepMetadata,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(advertisements, unrepresentable),
		StartedAt:    o.startedAt,
		Duration:     o.duration,
	})
}

// classify decides what the observation is allowed to claim.
//
// The order of the checks is the contract every producer here follows: a
// completed exchange is a fact, then the caller's context, then what the wire
// boundary observed.
//
// There is no broker error code to consult. Metadata carries a top-level error
// code only from v13, and svcdoctor sends v1, so a completed exchange is data
// rather than a verdict. Recording a zero error code would claim the broker
// stated something it was never asked to state.
func (o metadataObservation) classify() (domain.State, domain.FailureClass) {
	if o.err == nil {
		return domain.StatePass, domain.FailureNone
	}

	switch {
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded), errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}

	switch {
	case errors.Is(o.err, wire.ErrPeerClosed):
		return domain.StateFail, domain.FailureProtocolPeerClosed
	case errors.Is(o.err, wire.ErrNotKafka):
		return domain.StateFail, domain.FailureProtocolUnexpectedResponse
	case errors.Is(o.err, wire.ErrMalformedResponse):
		return domain.StateFail, domain.FailureProtocolMalformedResponse
	}

	if isTimeout(o.err) {
		// A deadline nothing identified as the network's is svcdoctor's own.
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}
	return domain.StateFail, domain.FailureProtocolUnexpectedResponse
}

// attributes records the facts the exchange yielded.
//
// # What is deliberately absent
//
// A cluster identifier, because the version svcdoctor sends does not carry one.
// A rack, because it is identity-ambiguous free text with no consumer. A topic
// count, because none were requested and reporting zero would describe a cluster
// nobody asked about. A broker error code, for the reason classify gives.
func (o metadataObservation) attributes(
	advertisements []advertisement, unrepresentable int,
) map[domain.AttributeKey]domain.AttrValue {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		AttrRequestAPIVersion: domain.IntAttr(int64(wire.MetadataVersion())),
	}
	if o.err != nil {
		return attributes
	}

	attributes[AttrMetadataControllerID] = domain.IntAttr(int64(o.response.ControllerID))
	attributes[AttrMetadataBrokerCount] = domain.IntAttr(int64(len(advertisements)))
	attributes[AttrMetadataAdvertisedEntryCount] = domain.IntAttr(int64(len(o.response.Brokers)))
	if unrepresentable > 0 {
		attributes[AttrMetadataUnrepresentableCount] = domain.IntAttr(int64(unrepresentable))
	}
	return attributes
}

// recordAdvertisements writes one node per advertisement and links it to the
// exchange that carried it.
//
// The parent edge records **derivation**: this fact was produced by that
// response. That is what a later reachability probe needs in order to name the
// advertisement it followed, and it is why no attribute duplicates it.
//
// It is deliberately *not* provenance. It says nothing about how the endpoint
// entered the run, and REPORT_SCHEMA.md forbids reading one from the other — the
// two come apart whenever a cluster advertises the bootstrap endpoint back, at
// which point one host:port has both a discovery-derived node here and a
// lookup-derived transport path elsewhere. `Origin` stays deferred. See ADR 0031
// section 6.
func recordAdvertisements(
	builder *domain.GraphBuilder,
	session *AuthenticatedSession,
	exchangeID domain.EvidenceID,
	advertisements []advertisement,
	observedAt time.Time,
	result *MetadataResult,
) error {
	for _, entry := range advertisements {
		evidence, err := entry.evidence(session, observedAt)
		if err != nil {
			return err
		}
		if err := record(builder, evidence, exchangeID); err != nil {
			return err
		}
		result.brokers = append(result.brokers, DiscoveredBroker{
			nodeID:     entry.nodeID,
			host:       entry.host,
			port:       entry.port,
			usable:     entry.usable,
			evidenceID: evidence.ID(),
		})
	}
	return nil
}

// evidence turns one advertisement into a node.
//
// # What PASS means here, and what it does not
//
// PASS says the advertisement was observed and names somewhere a client could
// connect. It says nothing about whether that broker is reachable, healthy, or
// even real — nothing has been probed. It is the same shape as a DNS lookup
// passing: the answer arrived, which is a different claim from the answer being
// good.
//
// FAIL says the cluster advertised something no client can act on: no host, or a
// port outside the range a port can occupy. That is a fact about the cluster's
// configuration, classified with the service-neutral class for a peer that
// answered but not as the protocol expects. It is recorded rather than dropped,
// because a broker advertising ":0" is precisely the misconfiguration somebody
// would run a diagnostic tool to find.
//
// # The identifier carries both identities
//
// A node identifier and an advertised endpoint are different things, and either
// alone would collide on a case this phase exists to keep visible: one node at
// two addresses, or two nodes at one address. Both components are present, so
// both cases produce two nodes. The exchange scope is present too, so the same
// broker seen by two Metadata responses stays two observations rather than one
// merged claim. See ADR 0031.
// The timestamp is the exchange's own start, shared by every node the response
// produced. A fact carried by one response was observed at one moment, and
// giving each broker its own clock reading would imply a measurement that never
// happened. The duration is zero for the same reason: recording a fact takes no
// time worth reporting.
func (a advertisement) evidence(
	session *AuthenticatedSession, observedAt time.Time,
) (domain.Evidence, error) {
	state := domain.StatePass
	failureClass := domain.FailureNone
	if !a.usable {
		state = domain.StateFail
		failureClass = domain.FailureProtocolUnexpectedResponse
	}

	return domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			StepBrokerAdvertised,
			session.Endpoint(),
			session.Address().Addr().String(),
			strconv.FormatInt(int64(a.nodeID), 10),
			a.ref,
		),
		Subject:      a.subject,
		Layer:        domain.LayerTopology,
		Step:         StepBrokerAdvertised,
		State:        state,
		FailureClass: failureClass,
		Attributes: map[domain.AttributeKey]domain.AttrValue{
			AttrBrokerNodeID:         domain.IntAttr(int64(a.nodeID)),
			AttrBrokerAdvertisedHost: domain.HostAttr(a.host),
			AttrBrokerAdvertisedPort: domain.IntAttr(int64(a.rawPort)),
		},
		StartedAt: observedAt,
		Duration:  0,
	})
}
