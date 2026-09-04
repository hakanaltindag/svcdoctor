package transport

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// CodeConnectionNotEstablished reports a requested endpoint no measured path
// connected to.
//
// # Why not "unreachable"
//
// Because one of its own triggers proves the opposite. A refused connection means
// a host answered and declined — it is reachable, and something is there. A code
// named TCP_ENDPOINT_UNREACHABLE would contradict itself on the single most
// common case it covers, and it would do so in the reports people read during an
// incident.
//
// What every failure shares is narrower and exactly true: no connection
// completed.
//
// # Why one code for six failure classes
//
// Refused and timed-out do suggest different remediation, and splitting them was
// the closest call in ADR 0043. It was rejected because the split is not stable
// across the thing the finding is about. One endpoint routinely produces
// ECONNREFUSED on one address family and ETIMEDOUT on another — a port with no
// listener on IPv4, a filtered route on IPv6 — and then the endpoint has no
// single code. Every resolution is worse than merging: two findings for one
// endpoint is per-address noise, choosing one by priority makes the machine
// contract depend on which family sorted first, and a third "mixed" code
// publishes only that the tool could not decide.
//
// The reason distribution is not lost. It stays in FailureClass on every cited
// node, which is the vocabulary that exists to carry it, and a consumer that
// needs refused-versus-timeout reads there rather than parsing a sentence.
//
// # Why the name avoids TCP_CONNECTION_FAILED
//
// That string is a FailureClass. A finding code spelled identically to an
// observation would be indistinguishable from it in any consumer matching on
// text, and would make the claim vocabulary a copy of the evidence vocabulary.
const CodeConnectionNotEstablished domain.FindingCode = "TCP_CONNECTION_NOT_ESTABLISHED"

// recommendConnectionNotEstablished names what to inspect and asserts no cause.
//
// The pointer to the evidence is the part that earns its place. The failure
// classes distinguish "a host declined" from "nothing answered", which is the
// distinction that decides where an operator looks next, and sending them there
// is honest where naming a firewall would not be.
const recommendConnectionNotEstablished = "Check that the endpoint accepts connections on " +
	"this port from this network position, and read the per-address outcomes recorded on " +
	"the referenced evidence"

const summaryConnectionNotEstablished = "No measured TCP connection to the requested " +
	"endpoint completed from this vantage point"

// detailConnectionNotEstablished explains the claim and its limits.
//
// It deliberately does not list the causes svcdoctor ruled out. Naming them, even
// to deny them, plants them: a reader who meets the word in a diagnosis reaches
// for it, and the tool observed none of them. The honest sentence is that the
// outcome of each attempt is known and the reason behind it is not.
const detailConnectionNotEstablished = "Every address the hostname resolved to was tried " +
	"and none accepted a connection. What each attempt observed is recorded as a failure " +
	"class on the referenced evidence.\n" +
	detailConnectionNotEstablishedShared

// detailConnectionNotEstablishedLiteral is the same claim about a run that
// resolved nothing.
//
// It exists because the sentence above is false for an address literal, and was
// printed for one: a run against `--host 127.0.0.1` told operators that "every
// address the hostname resolved to was tried" when there was no hostname in the
// run and no resolution had happened. The graph no longer contains a lookup node
// for such a run, so the rule can tell the two apart structurally and say the
// true sentence for each.
//
// It is a second detail rather than a second code. The claim is identical — no
// measured connection completed — and docs/FINDINGS.md section 3.1 item 11 makes
// "the first move differs" the test for splitting a code. It does not: an
// operator checks the same listener either way.
const detailConnectionNotEstablishedLiteral = "The address this run was given was tried " +
	"and did not accept a connection. No name was resolved, because the target was supplied " +
	"as an address. What the attempt observed is recorded as a failure class on the " +
	"referenced evidence.\n" +
	detailConnectionNotEstablishedShared

// detailConnectionNotEstablishedShared is the part of the explanation that does
// not depend on how the address was arrived at.
const detailConnectionNotEstablishedShared = "Those classes differ in what they establish, " +
	"and the difference decides where to look " +
	"next: some record that a host answered and declined the connection, others that " +
	"nothing answered at all. svcdoctor observed the outcome of each attempt and nothing " +
	"about what produced it.\n" +
	"Connectivity depends on this network position: the source address, the route taken and " +
	"anything inspecting traffic along it can all differ elsewhere."

// authorizedTCPFailures is the closed set of failure classes this rule was given
// a meaning for.
//
// A FAIL connection node carrying anything else records something the rule has
// not been told how to read, and the claim is withheld rather than widened
// silently. That is the same convention the Kafka rules use for an advertisement
// with an unexpected class.
var authorizedTCPFailures = map[domain.FailureClass]bool{
	domain.FailureTCPConnectionRefused:  true,
	domain.FailureTCPConnectionReset:    true,
	domain.FailureTCPConnectionTimeout:  true,
	domain.FailureTCPNetworkUnreachable: true,
	domain.FailureTCPHostUnreachable:    true,
	domain.FailureTCPConnectionFailed:   true,
}

// TCP diagnoses the connectivity of every requested target.
//
// It is a diagnosis.Rule. It enumerates requested-target anchors, descends to the
// connection nodes each one caused — through the single DNS node when a name was
// resolved, and directly when an address literal made resolution unnecessary —
// and decides once per target.
//
// # The aggregation rule, and why it is stated as "every node failed"
//
// A finding fires exactly when the sweep has at least one connection node and
// every one of them is FAIL. That single condition implements all four cases
// ADR 0043 section 6 pins:
//
//	any PASS            -> not every node failed -> withheld
//	any UNKNOWN         -> not every node failed -> withheld
//	any SKIPPED         -> not every node failed -> withheld
//	no connection nodes -> nothing to fail       -> withheld
//
// It holds identically for both sweep shapes. What changes between them is only
// where the set of attempted addresses came from; see evaluateTCP.
//
// Writing it as one universal quantifier rather than four branches is deliberate:
// there is no ordering between the cases to get wrong, and a state added to the
// domain later withholds by default instead of being silently counted as a
// failure.
//
// # Why a partial success withholds
//
// A client that selects the working path connects. Saying no connection completed
// would be false, and one usable address out of twenty is still a usable address.
// The failed paths remain in the graph either way — withholding a finding is not
// withholding information.
//
// # Why an incomplete sweep withholds rather than becoming a hypothesis
//
// The run did not establish that every path fails, so the claim is unproven.
// Result.Incomplete(), the exit-code contract and the report's
// unknownEvidenceCount already say the run was cut short; a HYPOTHESIS here would
// be a second, weaker copy of that fact pointed at a conclusion the evidence does
// not reach.
func TCP(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	var out []domain.Finding
	for _, s := range collectSweeps(g) {
		finding, ok := evaluateTCP(s)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// evaluateTCP decides what one sweep's connection attempts support.
func evaluateTCP(s sweep) (domain.Finding, bool) {
	if !s.wellFormed || len(s.connects) == 0 {
		return domain.Finding{}, false
	}

	// The denominator, and where it comes from in each shape.
	//
	// "Every path failed" is a universal claim and needs a set to be universal
	// over. When a name was resolved the lookup *is* that set: it establishes
	// which addresses existed to be tried, so it is cited as a conjunct and its
	// state is checked, because a sweep with connection nodes always has a
	// passing lookup — the chain mints no connection for an address it never
	// learned — and the reference must not be to a node that failed.
	//
	// When an address was supplied there is no lookup and none is needed. The
	// set is closed by the input itself: one literal is one address, the anchor
	// already records it, and the connection nodes beneath the anchor are
	// exhaustively what was attempted. Requiring a lookup here would have left
	// every FAIL on a literal target unowned — a reachable failing stage with no
	// finding, which is exactly what ADR 0054 forbids shipping.
	refs := make([]domain.EvidenceID, 0, len(s.connects)+1)
	detail := detailConnectionNotEstablishedLiteral
	if s.hasLookup() {
		if s.lookup.State() != domain.StatePass {
			return domain.Finding{}, false
		}
		refs = append(refs, s.lookup.ID())
		detail = detailConnectionNotEstablished
	}

	for _, connect := range s.connects {
		if connect.State() != domain.StateFail {
			return domain.Finding{}, false
		}
		if !authorizedTCPFailures[connect.FailureClass()] {
			return domain.Finding{}, false
		}
		refs = append(refs, connect.ID())
	}

	return build(buildInput{
		code:    CodeConnectionNotEstablished,
		layer:   domain.LayerTCP,
		subject: s.anchor.Subject(),
		// The lookup and every failed connection. Each is a conjunct of the
		// claim; no passing node is cited, because in an authorized case none
		// exists. Order follows the graph's canonical order and NewFinding sorts
		// again, so the same facts always produce the same references.
		refs:           refs,
		summary:        summaryConnectionNotEstablished,
		detail:         detail,
		recommendation: recommendConnectionNotEstablished,
	})
}
