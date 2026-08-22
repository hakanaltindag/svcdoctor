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
