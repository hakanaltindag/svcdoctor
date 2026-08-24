package redis

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// CodeEndpointIsSentinel reports that the endpoint identified itself as a Redis
// Sentinel rather than a Redis or Valkey data endpoint.
//
// # It is the one finding in v1 whose contract is the operator's own invocation
//
// Every other Redis observation is barred from becoming a finding for want of an
// expected-state contract: `role=replica` would need an expected role,
// `mode=cluster` an expected topology, a version an expected version. This one
// is different, and the difference is precise — the operator typed
// `diagnose redis`, which names a data endpoint, and this endpoint provably is
// not one. The expectation was stated by the command that was run, so no
// external policy is required. ADR 0065 section 7.
//
// # Why it has to exist at all
//
// A Sentinel answers every command in the frozen allowlist. PING, HELLO and AUTH
// all carry CMD_SENTINEL, and redis/src/server.c:3501 hides only the commands
// that do not. So without this finding a Sentinel completes the whole journey,
// answers PONG, and is reported as a healthy endpoint — while holding no keys at
// all, and while the operator's real problem is the port in their configuration.
// A confident, specific, wrong answer is the worst kind this product can give.
const CodeEndpointIsSentinel domain.FindingCode = "REDIS_ENDPOINT_IS_SENTINEL"

const (
	summarySentinel = "This endpoint identified itself as a Redis Sentinel, not a Redis or " +
		"Valkey data endpoint"

	detailSentinel = "The endpoint answered HELLO with mode=sentinel, which is its own " +
		"description of what it is.\n" +
		"A Sentinel accepts connections, authenticates clients and answers PING, so reaching " +
		"it proves nothing about any data endpoint it monitors. svcdoctor stopped before " +
		"presenting a credential and did not probe usability here.\n" +
		"This is not a claim that the Sentinel is unhealthy, that its quorum is broken, or " +
		"that any port is misconfigured: svcdoctor measured none of those."

	recommendSentinel = "Point svcdoctor at the Redis or Valkey data endpoint this Sentinel " +
		"monitors, or at the address your application connects to"
)

// Sentinel reports an endpoint that described itself as a Sentinel.
//
// It is a diagnosis.Rule. It anchors at the HELLO node and reads one attribute
// on it, which the adapter took from a closed set — so the predicate cannot be
// satisfied by a string the peer chose.
func Sentinel(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	for _, node := range nodesAt(g, serviceredis.StepHello) {
		mode, ok := stringAttr(node, serviceredis.AttrMode)
		if !ok || mode != "sentinel" {
			continue
		}
		finding, built := build(domain.FindingInput{
			Code: CodeEndpointIsSentinel,
			// The endpoint asserted this about itself, in a field whose whole
			// purpose is to say what it is. Nothing is being inferred.
			Kind: domain.FindingKindConfirmed,
			// It prevents correct use: the operator asked to diagnose a data
			// endpoint and there is none here.
			Severity: domain.SeverityError,
			// Direct evidence for the claim the finding actually makes.
			Confidence: domain.ConfidenceHigh,
			Layer:      domain.LayerProtocol,
			Subject:    node.Subject(),
			Summary:    summarySentinel,
			Detail:     detailSentinel,
			// What the endpoint is does not depend on where svcdoctor stands. A
			// Sentinel is a Sentinel from every vantage, so marking this true
			// would invite a retry from elsewhere that cannot change the answer.
			VantageDependent: false,
			EvidenceRefs:     []domain.EvidenceID{node.ID()},
			Recommendations:  recommend(recommendSentinel),
		})
		if !built {
			continue
		}
		out = append(out, finding)
	}
	return out
}
