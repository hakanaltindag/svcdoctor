package redis

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// CodeCommandNotPermitted reports an authenticated identity that is not
// authorized to run the usability probe.
//
// # It is WARN and UNKNOWN, never a target failure
//
// The endpoint authenticated the connection and then declined to run this
// command for this identity. **The service did not fail; svcdoctor's measurement
// was blocked.** `ACL SETUSER app on >pw ~app:* +@read` is a correct,
// least-privilege configuration under which PING is denied and the application
// works perfectly, so reporting it as an ERROR would tell an operator their
// Redis is broken when their ACL is doing exactly what they wrote.
//
// It says nothing about whether the application's own commands would be
// permitted: svcdoctor issued one keyless command and learned about that one.
const CodeCommandNotPermitted domain.FindingCode = "REDIS_COMMAND_NOT_PERMITTED"

// CodeEndpointNotServing reports an endpoint that answered the probe by naming a
// condition that stopped it from serving.
//
// # The prefix is restated; no cause is inferred
//
// `LOADING` proves the endpoint said it is loading its dataset. It does not
// prove the server is down, that data was lost, that a disk is slow, or that the
// condition persists — a later run may well succeed. `MASTERDOWN` proves this
// replica said its primary link is unavailable and that it is configured to
// refuse stale reads; **it does not prove the primary is down**, because
// svcdoctor never observed the primary. `BUSY` proves the endpoint said it is
// executing something else.
//
// This is the discipline `internal/adapter/postgres` applies to `53300` and
// `57P03`, arriving here through one shared class with the endpoint's own
// normalized prefix recorded beside it.
//
// # Every non-PONG condition except NOPERM arrives here, and the prose says only
// what that supports
//
// The predicate is the failure class, not a list of prefixes, so `NOAUTH`, a
// generic `ERR`, `DENIED`, `WRONGPASS` and an unrecognized prefix reach this
// finding alongside `LOADING`, `MASTERDOWN` and `BUSY`. That is deliberate — a
// probe the endpoint refused for a reason svcdoctor did not anticipate is worth
// exactly as much attention as one it did — but it constrains the wording.
//
// Phase 7.6B corrected that wording. The detail previously said the refusal was
// "the endpoint's own statement about its readiness rather than a connectivity
// or credential problem", which is false for `NOAUTH`: that *is* a credential
// condition, and the sentence excluded the one cause it was most likely to be
// read against. The text now names the endpoint's condition without classifying
// it, which is true for every prefix that can arrive.
const CodeEndpointNotServing domain.FindingCode = "REDIS_ENDPOINT_NOT_SERVING"

// CodePingNotCompleted is the floor: the usability probe did not complete.
const CodePingNotCompleted domain.FindingCode = "REDIS_PING_NOT_COMPLETED"

const (
	summaryCommandNotPermitted = "The endpoint authenticated this identity and then refused to " +
		"run the usability probe for it, so usability was not measured"

	detailCommandNotPermitted = "Authentication succeeded and the endpoint answered the probe " +
		"with NOPERM.\n" +
		"This is an authorization decision about one command for one identity. It is not a " +
		"failure of the endpoint, and it says nothing about whether the commands your " +
		"application runs would be permitted: svcdoctor issued one keyless command and " +
		"learned about that one.\n" +
		"svcdoctor did not try a different command afterwards. Each attempt would be another " +
		"entry in the endpoint's ACL log and another guess."

	recommendCommandNotPermitted = "Grant the diagnostic identity permission to run PING, or " +
		"diagnose with an identity that already has it"

	summaryEndpointNotServing = "The endpoint refused the usability probe and named the " +
		"condition itself"

	detailEndpointNotServing = "The connection was established and the endpoint answered, so " +
		"the refusal is the endpoint's own statement about its condition rather than a " +
		"connectivity problem.\n" +
		"svcdoctor restates the condition the endpoint named and infers no cause from it."

	recommendEndpointNotServing = "Check this endpoint's own logs and current state for the " +
		"condition it named, and run again once it is serving"

	summaryPingNotCompleted = "The usability probe did not complete at this endpoint"

	detailPingNotCompleted = "The probe was sent on an established connection and the exchange " +
		"ended without an answer.\n" +
		"This is not a claim that the endpoint is down: the connection reached it, and " +
		"whatever ended the exchange happened after that."

	recommendPingNotCompleted = "Review this endpoint's connection-level logs for this " +
		"vantage's address around the time of this run"
)

// Ping reports what the terminal usability probe found.
//
// It is a diagnosis.Rule.
//
// # A PASS produces no finding, and that is the point
//
// `redis.ping` PASS means one thing: this endpoint answered PING with PONG on
// this connection. It is not a claim that Redis is healthy, that a backend is
// available, that a cluster is healthy, that replication is healthy, or that an
// application will work — so there is nothing to report, and the node itself
// carries the whole of the evidence.
//
// SKIPPED produces nothing: the authentication node that blocked it owns that
// failure, and the graph records the blocking edge.
func Ping(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	var out []domain.Finding
	for _, node := range nodesAt(g, serviceredis.StepPing) {
		finding, ok := evaluatePing(node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func evaluatePing(node domain.Evidence) (domain.Finding, bool) {
	refs := []domain.EvidenceID{node.ID()}

	switch node.State() {
	case domain.StateUnknown:
		switch node.FailureClass() {
		case domain.FailureAuthzDenied:
			return build(domain.FindingInput{
				Code:             CodeCommandNotPermitted,
				Kind:             domain.FindingKindConfirmed,
				Severity:         domain.SeverityWarn,
				Confidence:       domain.ConfidenceHigh,
				Layer:            domain.LayerAuth,
				Subject:          node.Subject(),
				Summary:          summaryCommandNotPermitted,
				Detail:           detailCommandNotPermitted,
				VantageDependent: false,
				EvidenceRefs:     refs,
				Recommendations:  recommend(recommendCommandNotPermitted),
			})
		case domain.FailureProtocolUnexpectedResponse:
			return build(domain.FindingInput{
				Code: CodeEndpointNotServing,
				Kind: domain.FindingKindConfirmed,
				// It stops the run proving usability, and it is the endpoint's
				// own statement about itself — but it is a transient class of
				// condition by nature, and calling it an ERROR would equate
				// "loading its dataset" with "cannot be used at all".
				Severity:         domain.SeverityWarn,
				Confidence:       domain.ConfidenceHigh,
				Layer:            domain.LayerAuth,
				Subject:          node.Subject(),
				Summary:          summaryEndpointNotServing,
				Detail:           detailWithNamedCondition(node),
				VantageDependent: false,
				EvidenceRefs:     refs,
				Recommendations:  recommend(recommendEndpointNotServing),
			})
		}
		// Everything else UNKNOWN at this step is svcdoctor's own budget or its
		// own reply ceiling. The report's incompleteness reports that already,
		// and a finding would dress a svcdoctor limit as a target defect.
		return domain.Finding{}, false

	case domain.StateFail:
		return build(domain.FindingInput{
			Code:             CodePingNotCompleted,
			Kind:             domain.FindingKindConfirmed,
			Severity:         domain.SeverityError,
			Confidence:       domain.ConfidenceHigh,
			Layer:            domain.LayerAuth,
			Subject:          node.Subject(),
			Summary:          summaryPingNotCompleted,
			Detail:           detailPingNotCompleted,
			VantageDependent: true,
			EvidenceRefs:     refs,
			Recommendations:  recommend(recommendPingNotCompleted),
		})
	}

	return domain.Finding{}, false
}

// detailWithNamedCondition appends the endpoint's own normalized condition.
//
// The value comes from the closed set in internal/adapter/redis/wire, so this
// renders a constant svcdoctor declared rather than a byte the peer chose. That
// is what lets the detail be specific without reading the message text ADR 0066
// forbids — and it is why a condition svcdoctor does not classify appears as
// UNRECOGNIZED rather than as whatever the peer sent.
func detailWithNamedCondition(node domain.Evidence) string {
	prefix, ok := stringAttr(node, serviceredis.AttrErrorPrefix)
	if !ok {
		return detailEndpointNotServing
	}
	return fmt.Sprintf("%s\nThe condition the endpoint named was %s.",
		detailEndpointNotServing, prefix)
}
