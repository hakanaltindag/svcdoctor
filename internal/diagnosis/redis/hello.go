package redis

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// CodeProtocolNotEstablished is the L4 floor: the RESP exchange did not
// complete, and no stronger claim is justified.
//
// # Why NOT_ESTABLISHED and not REJECTED
//
// The trigger includes a peer that closed mid-exchange and a peer whose framing
// could not be decoded. Neither **rejected** anything, and a code claiming they
// did would attribute agency the evidence does not carry — in the identifier,
// where it is hardest to correct later. PostgreSQL's `POSTGRES_STARTUP_FAILED`
// was renamed away from `REJECTED` for the same reason before any rule existed.
//
// # It is where protected mode lands
//
// An endpoint in protected mode sends `-DENIED` and closes the connection
// unconditionally. That is a real, actionable configuration fact, and this
// finding deliberately does not name it as a cause: the failure class says the
// peer closed, and the endpoint's own logs are where the reason still exists.
const CodeProtocolNotEstablished domain.FindingCode = "REDIS_PROTOCOL_NOT_ESTABLISHED"

const (
	summaryProtocolNotEstablished = "The RESP exchange did not complete at this endpoint, " +
		"so svcdoctor learned nothing about what is listening there"

	detailProtocolNotEstablished = "svcdoctor sent a zero-argument HELLO after the transport " +
		"connection was established, and the exchange ended without a usable answer.\n" +
		"No credential was involved: HELLO carries no arguments at all, so nothing svcdoctor " +
		"sent could have been rejected."

	recommendProtocolNotEstablished = "Check whether this port serves the Redis protocol, and " +
		"review the endpoint's connection-level logs for this vantage's address"
)

// Hello reports RESP exchanges that did not complete.
//
// It is a diagnosis.Rule, and it is deliberately narrow. Three of the four
// non-passing HELLO outcomes produce nothing here:
//
//   - **NOAUTH is not a failure.** The endpoint answered, and the answer is that
//     it wants a credential first. The authentication rule owns what happens
//     next; a finding here would report a correctly configured endpoint as
//     broken.
//   - **An endpoint that does not implement HELLO is not a failure.** It is a
//     capability observation. The run continued to AUTH and PING, and what
//     svcdoctor lost is the identity — which the report shows as not measured
//     rather than as a problem.
//   - **UNKNOWN from svcdoctor's own budget or its own reply ceiling is not the
//     endpoint's fault.** `Result.Incomplete()` already reports that the run was
//     cut short, and a finding would dress svcdoctor's limit as a target defect.
//
// SKIPPED produces nothing either: its blocker owns that failure.
func Hello(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	for _, node := range nodesAt(g, serviceredis.StepHello) {
		if node.State() != domain.StateFail {
			continue
		}
		finding, built := build(domain.FindingInput{
			Code:       CodeProtocolNotEstablished,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerProtocol,
			Subject:    node.Subject(),
			Summary:    summaryProtocolNotEstablished,
			Detail:     detailProtocolNotEstablished,
			// A floor does not attribute a cause, so it cannot exclude a
			// source-keyed one: protected mode refuses by connecting address,
			// and a bind directive can make a port answer here and not there.
			// False would be a positive claim of position-independence this
			// finding has no basis for.
			VantageDependent: true,
			EvidenceRefs:     []domain.EvidenceID{node.ID()},
			Recommendations:  recommend(recommendProtocolNotEstablished),
		})
		if !built {
			continue
		}
		out = append(out, finding)
	}
	return out
}
