package rabbitmq

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// The connection-open findings.
const (
	// CodeVHostNotFound reports that the endpoint said the requested virtual
	// host was not found.
	//
	// **It is peer attribution, not an inventory claim.** The endpoint reported
	// the absence; svcdoctor did not look. It does not state that the virtual
	// host never existed, was deleted, or was renamed.
	CodeVHostNotFound domain.FindingCode = "RABBITMQ_VHOST_NOT_FOUND"

	// CodeVHostAccessRefused reports that the authenticated identity was denied
	// the requested virtual host.
	//
	// Distinct from a rejected credential in a way that matters: the credential
	// was accepted and the *operation* was denied, which sends a reader to a
	// permissions table rather than to a secret store.
	CodeVHostAccessRefused domain.FindingCode = "RABBITMQ_VHOST_ACCESS_REFUSED"

	// CodeConnectionNotPermitted reports that the endpoint refused the connection
	// for a reason that is neither a missing virtual host nor a permission
	// decision — a capacity ceiling it named, or a refusal svcdoctor did not
	// classify.
	CodeConnectionNotPermitted domain.FindingCode = "RABBITMQ_CONNECTION_NOT_PERMITTED"

	// CodeConnectionNotEstablished reports that the terminal exchange did not
	// settle at all: a peer close, a malformed frame, an unexpected method.
	CodeConnectionNotEstablished domain.FindingCode = "RABBITMQ_CONNECTION_NOT_ESTABLISHED"
)

const (
	summaryVHostNotFound = "This endpoint reported that the requested virtual host was not " +
		"found"

	detailVHostNotFound = "svcdoctor authenticated and asked to open a connection in the " +
		"requested virtual host, and the endpoint answered that it was not found.\n" +
		"That is the endpoint's own statement about the name it was given. svcdoctor did " +
		"not enumerate virtual hosts and makes no claim about which ones exist.\n" +
		"The credential was accepted before this point, so this is not an authentication " +
		"problem."

	detailVHostDefaultedSuffix = "\nThe run did not name a virtual host, so svcdoctor used " +
		"the default `/`. If your application connects to a different one, pass it with " +
		"--vhost."

	recommendVHostNotFound = "Confirm the virtual host name, including its exact case and " +
		"any leading slash, against the broker's own list"

	summaryVHostAccessRefused = "This identity was refused access to the requested virtual " +
		"host"

	detailVHostAccessRefused = "svcdoctor authenticated successfully and the endpoint then " +
		"refused to open a connection in the requested virtual host.\n" +
		"**The credential is not the problem** — it was accepted. What was denied is access " +
		"to this virtual host for this identity.\n" +
		"This says nothing about what the identity may do *inside* the virtual host. " +
		"RabbitMQ evaluates configure, write and read permissions at channel operations, " +
		"and svcdoctor opens no channel and names no resource."

	recommendVHostAccessRefused = "Grant this user permissions on the virtual host, for " +
		"example with rabbitmqctl set_permissions"

	summaryConnectionNotPermitted = "This endpoint refused to open the connection"

	detailConnectionNotPermitted = "svcdoctor authenticated successfully and the endpoint " +
		"refused the connection for a reason other than a missing virtual host or a " +
		"permission decision.\n" +
		"Where the endpoint named a capacity ceiling, that is recorded as what it said and " +
		"nothing more. It proves the endpoint refused at that moment; it proves nothing " +
		"about why, for how long, or what to change, and a second run a moment later may " +
		"succeed.\n" +
		"Where svcdoctor could not classify the refusal, it declines to guess rather than " +
		"naming a likely cause."

	recommendConnectionNotPermitted = "Check the broker's own log for this connection " +
		"attempt, and review any node, virtual host or user connection limits"

	// The capacity-scope details, one per closed outcome.
	//
	// # What changes and what does not
	//
	// Each replaces detailConnectionNotPermitted for exactly one outcome. The
	// first and last paragraphs are that constant's own, unchanged: the first
	// still says what was ruled out, and the last still refuses cause, duration
	// and remedy and still says a later run may succeed. Only the middle
	// sentence is new, and it states the one thing the generic text hedges as
	// *"Where the endpoint named a capacity ceiling"* — which of the three it
	// was.
	//
	// The fourth generic sentence — *"Where svcdoctor could not classify the
	// refusal, it declines to guess"* — is dropped here rather than carried,
	// because on these three outcomes svcdoctor did classify it and the sentence
	// would be describing a path this finding did not take.
	//
	// # The ceiling on what they may say (ADR 0091 section 8)
	//
	// They name **the scope of the limit the peer named**, and nothing else. Not
	// that the limit is reached everywhere, not that it is too low, not that
	// demand is abnormal, not that anything leaked, and not what to change. The
	// distinction is the one PostgreSQL settled for SQLSTATE 53300: an
	// authoritative refusal of *this* attempt is not proof of global capacity
	// state.
	//
	// They interpolate nothing. No endpoint, no user, no virtual host, no
	// product, no version, no numeric limit and no byte the peer sent. Each is a
	// constant, so the strongest thing a hostile peer can do is fail to be
	// classified — which yields the generic text.
	detailCapacityPrefix = "svcdoctor authenticated successfully and the endpoint " +
		"refused the connection for a reason other than a missing virtual host or a " +
		"permission decision.\n"

	detailCapacitySuffix = "\nThat is recorded as what it said and nothing more. It proves " +
		"the endpoint refused at that moment; it proves nothing about why, for how long, " +
		"or what to change, and a second run a moment later may succeed."

	detailCapacityNode = detailCapacityPrefix +
		"The endpoint named a connection limit scoped to the node." +
		detailCapacitySuffix

	detailCapacityVHost = detailCapacityPrefix +
		"The endpoint named a connection limit scoped to the virtual host." +
		detailCapacitySuffix

	detailCapacityUser = detailCapacityPrefix +
		"The endpoint named a connection limit scoped to the user." +
		detailCapacitySuffix

	summaryConnectionNotEstablished = "The connection could not be opened on this endpoint"

	detailConnectionNotEstablished = "svcdoctor authenticated successfully and the terminal " +
		"exchange did not settle into an answer.\n" +
		"A peer close at this point is also what an unacceptable negotiation produces: " +
		"RabbitMQ answers connection parameters it will not accept by closing the socket " +
		"silently rather than by sending a refusal, which was measured. svcdoctor does not " +
		"pretend a refusal frame arrived.\n" +
		"No claim is made about whether the virtual host exists or is permitted, because " +
		"neither was answered."

	recommendConnectionNotEstablished = "Check the broker's log for this connection, and " +
		"confirm no proxy between svcdoctor and the broker is terminating it"
)

// ConnectionOpen owns every outcome the terminal exchange can produce.
//
// It is a diagnosis.Rule. It keys on the node's failure class and, for the 530
// family, on the normalized close outcome the wire package produced from a
// byte-equality comparison against candidates svcdoctor rendered itself. No peer
// text reaches here, because none crossed the wire boundary.
func ConnectionOpen(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	var out []domain.Finding
	for _, node := range nodesAt(g, servicerabbitmq.StepConnectionOpen) {
		// A passing open is not a finding. Specifically it is not a claim that
		// the broker is healthy, that the virtual host is usable, or that any
		// message operation would succeed.
		if node.State() != domain.StateFail {
			continue
		}
		in, ok := connectionOpenFinding(node)
		if !ok {
			continue
		}
		in.Subject = node.Subject()
		in.EvidenceRefs = []domain.EvidenceID{node.ID()}
		finding, built := build(in)
		if !built {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func connectionOpenFinding(node domain.Evidence) (domain.FindingInput, bool) {
	switch node.FailureClass() {
	case domain.FailureResourceNotFound:
		return domain.FindingInput{
			Code:       CodeVHostNotFound,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Summary:    summaryVHostNotFound,
			Detail:     vhostNotFoundDetail(node),
			// A virtual host's existence does not vary by the source of the
			// connection.
			VantageDependent: false,
			Recommendations:  recommend(recommendVHostNotFound),
		}, true

	case domain.FailureAuthzDenied:
		return domain.FindingInput{
			Code:       CodeVHostAccessRefused,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Summary:    summaryVHostAccessRefused,
			Detail:     detailVHostAccessRefused,
			// Virtual host permissions are held per user, not per source address.
			VantageDependent: false,
			Recommendations:  recommend(recommendVHostAccessRefused),
		}, true

	case domain.FailureResourceLimitReached, domain.FailureAuthzNotPermitted:
		return domain.FindingInput{
			Code:       CodeConnectionNotPermitted,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerAuth,
			Summary:    summaryConnectionNotPermitted,
			Detail:     connectionNotPermittedDetail(node),
			// A capacity ceiling is a property of the endpoint at an instant, and
			// a node-wide one is reached by every client at once — but a
			// per-user ceiling is not, and svcdoctor does not separate them here.
			VantageDependent: true,
			Recommendations:  recommend(recommendConnectionNotPermitted),
		}, true

	default:
		return domain.FindingInput{
			Code:             CodeConnectionNotEstablished,
			Kind:             domain.FindingKindConfirmed,
			Severity:         domain.SeverityError,
			Confidence:       domain.ConfidenceHigh,
			Layer:            domain.LayerAuth,
			Summary:          summaryConnectionNotEstablished,
			Detail:           detailConnectionNotEstablished,
			VantageDependent: true,
			Recommendations:  recommend(recommendConnectionNotEstablished),
		}, true
	}
}

// capacityScopeDetail is the closed mapping from a capacity outcome to its
// explanation.
//
// **A map keyed on the constants, never a match on the text.** There is no
// prefix, no suffix, no trimming, no case folding and no fuzzy comparison: a
// value that is not byte-equal to one of these three keys is not in the map and
// gets nothing. That is what makes the mapping safe even if the closure upstream
// were ever to regress — the defence does not depend on the producer's
// invariant, it depends on this being a lookup.
//
// Only capacity outcomes appear. VHOST_NOT_FOUND and VHOST_ACCESS_REFUSED reach
// their own finding codes and never this one; UNSPECIFIED and
// UNSPECIFIED_TRUNCATED are svcdoctor saying it did not classify the refusal, and
// giving either a scope would be inventing the very specificity they record the
// absence of.
var capacityScopeDetail = map[servicerabbitmq.CloseOutcome]string{
	servicerabbitmq.CloseNodeConnectionLimit:  detailCapacityNode,
	servicerabbitmq.CloseVHostConnectionLimit: detailCapacityVHost,
	servicerabbitmq.CloseUserConnectionLimit:  detailCapacityUser,
}

// connectionNotPermittedDetail selects the explanation for one refusal.
//
// # It reads the node it is given, and no other
//
// The node is the one ConnectionOpen is building a finding for, and its
// identifier is the finding's only EvidenceRef. There is no graph here and no
// lookup by step, so another endpoint's outcome — or another target's — cannot
// reach this sentence. That is structural rather than checked: this function
// cannot see anything else.
//
// # Two gates, and the second is deliberately redundant
//
// The failure class must be RESOURCE_LIMIT_REACHED *and* the outcome must be one
// of the three. The adapter already guarantees the pairing — classify() returns
// that class for exactly these outcomes — so the first gate can never fail on
// evidence a producer made. It is here because the consequence of the pairing
// breaking is a specific sentence over a refusal that was never a capacity
// refusal, and falling back to the generic text is the safe direction.
//
// Anything else returns detailConnectionNotPermitted, byte for byte: an absent
// attribute, an empty value, an outcome svcdoctor does not map, and a value no
// version of svcdoctor ever produced.
func connectionNotPermittedDetail(node domain.Evidence) string {
	if node.FailureClass() != domain.FailureResourceLimitReached {
		return detailConnectionNotPermitted
	}
	value, ok := node.Attribute(servicerabbitmq.AttrCloseOutcome)
	if !ok {
		return detailConnectionNotPermitted
	}
	outcome, ok := value.Str()
	if !ok {
		return detailConnectionNotPermitted
	}
	detail, mapped := capacityScopeDetail[servicerabbitmq.CloseOutcome(outcome)]
	if !mapped {
		return detailConnectionNotPermitted
	}
	return detail
}

// vhostNotFoundDetail names the default when the run did not name a virtual
// host.
//
// ADR 0067 §3.1 makes this part of the decision to default `/` rather than
// require it: the one bad case a default produces is a refusal naming a virtual
// host the operator never chose, and saying so turns it into a self-explaining
// one.
func vhostNotFoundDetail(node domain.Evidence) string {
	if defaulted, ok := boolAttr(node, servicerabbitmq.AttrVHostDefaulted); ok && defaulted {
		return detailVHostNotFound + detailVHostDefaultedSuffix
	}
	return detailVHostNotFound
}
