package rabbitmq

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// CodeConnectionStartNotCompleted reports that the endpoint did not begin an
// AMQP 0-9-1 connection.
//
// It covers every way the first exchange can fail: a protocol header answered
// with a protocol header, an answer that is not AMQP at all, a peer close, and a
// frame svcdoctor's own bounds refused. What it never does is name a RabbitMQ
// version: the peer refused a *protocol version*, and no RabbitMQ release
// refuses the header svcdoctor sends, so a returned header means the peer is not
// a RabbitMQ AMQP 0-9-1 listener rather than that it is an old one.
const CodeConnectionStartNotCompleted domain.FindingCode = "RABBITMQ_CONNECTION_START_NOT_COMPLETED"

const (
	summaryStartNotCompleted = "This endpoint did not begin an AMQP 0-9-1 connection"

	detailStartNotCompleted = "svcdoctor sent the AMQP 0-9-1 protocol header and did not " +
		"receive a Connection.Start in reply.\n" +
		"That is as far as the run got, so nothing below it was measured: no " +
		"authentication was attempted, no credential was sent and no virtual host was " +
		"requested.\n" +
		"This is not a claim about which product is listening or which version it runs. A " +
		"peer that will not speak AMQP 0-9-1 answers with a protocol header of its own and " +
		"closes, and RabbitMQ sends the same eight bytes for input that is not AMQP at all."

	recommendStartNotCompleted = "Confirm the port carries AMQP 0-9-1 rather than the " +
		"management HTTP API, a TLS listener addressed as plaintext, or another protocol"
)

// ConnectionStart owns every outcome the first exchange can produce.
//
// It is a diagnosis.Rule. It anchors at the connection_start node and keys on
// the node's own state, so it cannot fire for a step that passed.
func ConnectionStart(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	for _, node := range nodesAt(g, servicerabbitmq.StepConnectionStart) {
		if node.State() != domain.StateFail {
			// A local timeout is UNKNOWN and is reported through the run's own
			// incompleteness rather than as a target-side failure.
			continue
		}
		finding, built := build(domain.FindingInput{
			Code:       CodeConnectionStartNotCompleted,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerProtocol,
			Subject:    node.Subject(),
			Summary:    summaryStartNotCompleted,
			Detail:     detailStartNotCompleted,
			// A peer that answers a different protocol answers the same way from
			// anywhere. What svcdoctor reached, however, is a routing question,
			// so a different vantage may reach a different listener.
			VantageDependent: true,
			EvidenceRefs:     []domain.EvidenceID{node.ID()},
			Recommendations:  recommend(recommendStartNotCompleted),
		})
		if !built {
			continue
		}
		out = append(out, finding)
	}
	return out
}
