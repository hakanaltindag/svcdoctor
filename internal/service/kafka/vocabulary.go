package kafka

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// The steps a Kafka Metadata exchange records.
//
// StepMetadata is the exchange itself: one request, one response, one outcome.
// StepBrokerAdvertised is one fact carried by that response — a broker, the node
// identifier the cluster gave it, and the endpoint the cluster published for it.
//
// The two are separate steps because they are separately true. The exchange
// succeeding says the cluster answered; an advertisement says what it answered
// with, and a rule anchors at the second while requiring the first (ADR 0034
// sections 2 and 5).
//
// The string values are part of the report contract and are matched by
// automation. They moved here from internal/adapter/kafka unchanged; see
// docs/FINDINGS.md section 2 on why a step name is not renamed casually.
const (
	StepMetadata         domain.Step = "kafka.metadata"
	StepBrokerAdvertised domain.Step = "kafka.broker_advertised"
)

// The three protocol steps a bootstrap path performs before Metadata.
//
// They moved here in Phase 6.1c-P2, on exactly the trigger the two above moved
// on and the one this package's doc comment names: a rule outside the producing
// package now reads them. `internal/diagnosis/kafka` owns every non-passing
// outcome of these steps, and depguard denies diagnosis the adapter import — so
// either the names live here or the two layers disagree about their spelling.
//
// The strings are unchanged and are part of the report contract; see
// docs/FINDINGS.md section 2 on why a step name is not renamed casually.
const (
	// StepAPIVersions is the L4 capability exchange: one request, one response,
	// one outcome.
	StepAPIVersions domain.Step = "kafka.api_versions"

	// StepSASLHandshake is the L5 mechanism negotiation. It names a mechanism
	// and learns whether the endpoint offers it.
	StepSASLHandshake domain.Step = "kafka.sasl_handshake"

	// StepSASLAuthenticate is the L5 authentication itself.
	//
	// It is the step with the widest outcome vocabulary in Kafka: it can pass,
	// fail with a rejected credential, fail on protocol grounds, report a
	// mechanism svcdoctor cannot perform, or record that nothing was presented —
	// either because a policy withheld a credential or because the run had none.
	// Those are five different facts and docs/ARCHITECTURE.md section 5.7c keeps
	// them apart.
	StepSASLAuthenticate domain.Step = "kafka.sasl_authenticate"
)

// The attributes a rule reads from those three steps.
//
// Each is a protocol fact drawn from a public registry or from svcdoctor's own
// request, never a value derived from a credential. All three survive a
// shareable report unchanged: none names a host, an address or a principal.
const (
	// AttrSASLMechanism is the mechanism a step concerned itself with.
	//
	// A rule reads it to say *which* authentication was declined, not offered or
	// left unattempted — the difference between "the endpoint did not offer what
	// was asked for" and a finding that names PLAIN.
	AttrSASLMechanism domain.AttributeKey = "kafka.sasl.mechanism"

	// AttrRequestAPIVersion is the request version svcdoctor sent.
	//
	// A rule reads it so that a version the endpoint rejected can be named. The
	// number is svcdoctor's own choice, so reporting it describes what was asked
	// rather than asserting anything about the endpoint.
	AttrRequestAPIVersion domain.AttributeKey = "kafka.request_api_version"

	// AttrErrorCode is the broker error code a completed exchange carried.
	//
	// Zero is recorded as a statement rather than an absence. A rule reads it
	// only to quote what the endpoint said; the normalized FailureClass is what
	// a claim is selected by.
	AttrErrorCode domain.AttributeKey = "kafka.error_code"
)

// AttrBrokerNodeID is the broker identity a Metadata response reported.
//
// It is the cluster's own node identifier, recorded as it arrived. It is not a
// subject: docs/REPORT_SCHEMA.md has no subject kind for a service-internal
// integer, and overloading the endpoint kind to carry one would misrepresent it
// (ADR 0034 section 12). It is not identity in the redaction sense either — it
// names a position in a cluster, not a host or a network address — so it
// survives a shareable report.
//
// Diagnosis reads it to say which broker a finding is about, in prose, beside a
// subject that names the endpoint.
const AttrBrokerNodeID domain.AttributeKey = "kafka.broker.node_id"
