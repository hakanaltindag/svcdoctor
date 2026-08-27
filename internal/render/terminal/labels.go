package terminal

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// labels maps a canonical step onto the words a person reads.
//
// # The canonical names are the machine contract and do not change
//
// `postgres.ssl_request` is what the report says and what a consumer matches on.
// "SSLRequest" is what a human reads. Renaming the evidence to look better in a
// terminal would make the presentation layer's convenience a schema decision, so
// the mapping lives here and nowhere else.
//
// # A step this table does not know still renders
//
// stepLabel falls back to the canonical name verbatim. That is deliberate: a
// stage added later shows up as `postgres.something` — slightly ugly and
// completely truthful — rather than vanishing from a diagnosis because a
// presentation table was not updated. Silently dropping evidence is the one
// failure mode a renderer must not have.
//
// It is also how a second service arrives without a service switch: Kafka's
// steps become rows in this table, not a branch in the renderer.
var labels = map[domain.Step]string{
	vocabulary.StepTargetRequested:     "Target",
	vocabulary.StepDNSLookup:           "DNS",
	vocabulary.StepTCPConnect:          "TCP",
	servicepostgres.StepSSLRequest:     "SSLRequest",
	vocabulary.StepTLSHandshake:        "TLS",
	servicepostgres.StepStartup:        "Startup",
	servicepostgres.StepAuthentication: "Authentication",
	servicepostgres.StepSession:        "Session",

	// RabbitMQ, per ADR 0067 §4. Each names the frame that had to arrive, and
	// claims nothing beyond it.
	//
	// "Connection.Start" rather than "capabilities": receipt of that frame is
	// what proves the peer speaks AMQP 0-9-1, and it arrives before any
	// credential — so it says something about the protocol and nothing about who
	// svcdoctor is.
	//
	// "Authentication" is the same word the other three services use, and it
	// carries the same meaning: a credential was presented and the endpoint took
	// a position. Its PASS is the arrival of Connection.Tune, because RabbitMQ
	// never acknowledges authentication any other way.
	//
	// "Connection.Open" rather than "Virtual host" or "Session": the frame is
	// what was sent, and naming the step after the vhost would invite a reader to
	// treat a PASS as a statement about the virtual host's health rather than
	// about one connection being allowed to open in it.
	servicerabbitmq.StepConnectionStart: "Connection.Start",
	servicerabbitmq.StepAuthentication:  "Authentication",
	servicerabbitmq.StepConnectionOpen:  "Connection.Open",

	// Kafka, per ADR 0052 section 5. Each names the exchange that happened and
	// claims nothing beyond it.
	//
	// "Kafka API versions" rather than "capabilities": the exchange returns the
	// broker's supported API key ranges, and a broker answers it *before*
	// authentication by design, so it proves that something here speaks the
	// Kafka protocol and nothing about who svcdoctor is.
	//
	// "SASL mechanism negotiation" rather than "SASL handshake": the request
	// proposes one mechanism and the answer says whether the endpoint offers it.
	// It carries no identity and no secret, and calling it a handshake invites a
	// reader to think authentication began.
	//
	// "Kafka metadata" rather than "Cluster metadata" or "Topology": the request
	// is Metadata v1 with `Topics = []`.
	servicekafka.StepAPIVersions:      "Kafka API versions",
	servicekafka.StepSASLHandshake:    "SASL mechanism negotiation",
	servicekafka.StepSASLAuthenticate: "Authentication",
	servicekafka.StepMetadata:         "Kafka metadata",
	servicekafka.StepBrokerAdvertised: "Broker advertisement",
}

// stepLabel returns the human label for a step, or the step itself.
func stepLabel(step domain.Step) string {
	if label, ok := labels[step]; ok {
		return label
	}
	return string(step)
}

// The state vocabulary.
//
// Every glyph is followed by its word, so the meaning survives a terminal that
// cannot draw the glyph, a font that renders it as a box, a copy-paste into a
// ticket, and a reader who has never seen the tool before. Nothing here is
// carried by the symbol alone — which is also why v0.1 needs no colour: there is
// nothing colour would have to say.
//
// UNKNOWN is `?` and never `✗`. It means svcdoctor could not determine the
// outcome, usually because its own budget ended, and rendering it as a failure
// would publish a claim about the endpoint that the evidence explicitly refuses
// to make.
func stateGlyph(state domain.State) string {
	switch state {
	case domain.StatePass:
		return "✓ PASS"
	case domain.StateFail:
		return "✗ FAIL"
	case domain.StateUnknown:
		return "? UNKNOWN"
	case domain.StateSkipped:
		return "· SKIPPED"
	case domain.StateDegraded:
		return "~ DEGRADED"
	default:
		return "· " + state.String()
	}
}

// severityGlyph labels a finding's severity.
func severityGlyph(severity domain.Severity) string {
	switch severity {
	case domain.SeverityCritical:
		return "✗ CRITICAL"
	case domain.SeverityError:
		return "✗ ERROR"
	case domain.SeverityWarn:
		return "⚠ WARN"
	case domain.SeverityInfo:
		return "· INFO"
	default:
		return "· " + severity.String()
	}
}
