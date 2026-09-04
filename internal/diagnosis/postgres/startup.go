package postgres

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// CodeStartupFailed is the L4 floor: the startup exchange did not complete, and
// no stronger claim is justified.
//
// # Why FAILED and not REJECTED
//
// The trigger includes `PROTOCOL_MALFORMED_RESPONSE` and
// `PROTOCOL_PEER_CLOSED`. A peer that emitted an undecodable frame or vanished
// mid-exchange **rejected nothing**, and a code claiming it did would attribute
// agency the evidence does not carry — in the identifier, where it is hardest to
// correct later. An earlier draft of ADR 0040 named this
// `POSTGRES_STARTUP_REJECTED` and was corrected before any rule existed.
//
// # This is where a pooler's collapsed failures land
//
// An unknown role, an unknown database and a revoked CONNECT privilege all
// arrive here as `08P01` before authentication when a connection pooler is in
// the path — six unrelated conditions behind one code, at a step that proves
// none of them. The finding says where the connection died and points at the one
// place the distinction still exists, which is the endpoint's own log.
const CodeStartupFailed domain.FindingCode = "POSTGRES_STARTUP_FAILED"

const (
	// Fixed by ADR 0040 section 8, word for word.
	//
	// "and no authentication was requested" is provable rather than agency: this
	// step ends at the peer's first decisive reply, and a failing one means no
	// authentication request was ever received.
	summaryStartupFailed = "The PostgreSQL startup exchange did not complete at this endpoint, " +
		"and no authentication was requested"

	detailStartupFailed = "The startup message reached this endpoint and the exchange ended " +
		"without an authentication request."

	recommendStartupFailed = "Review this endpoint's connection-level logs for the role and " +
		"database this run requested"
)

// Startup reports PostgreSQL startup exchanges that did not complete.
//
// It is a diagnosis.Rule. One escalation and one floor, disjoint on the failure
// class, so exactly one finding is produced for a failed node and never two.
//
// # It anchors at the startup node and reads only that node
//
// Both findings are about what happened at this step. Neither walks to the
// authentication node — on a failed startup there is none — and neither reads
// the transport nodes above.
//
// # SKIPPED and UNKNOWN produce nothing
//
// A SKIPPED startup was blocked by something earlier, and its blocker owns that
// failure (docs/FINDINGS.md section 3.1 item 11). An UNKNOWN one is svcdoctor's
// own budget expiring or its own cancellation; nothing was learned about the
// endpoint, and a finding would dress that as the endpoint's fault. The report's
// summary already reports unknown and skipped counts.
func Startup(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	var out []domain.Finding
	for _, node := range g.Nodes() {
		if node.Step() != servicepostgres.StepStartup {
			continue
		}
		finding, ok := evaluateStartup(node)
		if !ok {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// evaluateStartup applies ADR 0040 sections 8 and 9 to one startup node.
func evaluateStartup(node domain.Evidence) (domain.Finding, bool) {
	if node.State() != domain.StateFail {
		return domain.Finding{}, false
	}

	refs := []domain.EvidenceID{node.ID()}

	// The one escalation. It reads the class and never a SQLSTATE: the adapter
	// already decided, per step, what the code proved there.
	if node.FailureClass() == domain.FailureAuthzNotPermitted {
		return notPermitted(node, domain.LayerProtocol, refs)
	}

	return build(domain.FindingInput{
		Code: CodeStartupFailed,
		// The stated condition — this exchange did not complete — is directly
		// evidenced by a node whose state and class the producer committed to.
		// Not knowing why is not grounds for a hypothesis; it is grounds for the
		// narrow claim this finding already makes.
		Kind: domain.FindingKindConfirmed,
		// No session is possible at this endpoint for the role and database this
		// run named, which prevents correct use.
		Severity: domain.SeverityError,
		// Direct evidence for the claim itself. Confidence is epistemic strength
		// about the claim, never about a root cause the finding does not assert.
		Confidence: domain.ConfidenceHigh,
		Layer:      domain.LayerProtocol,
		Subject:    node.Subject(),
		Summary:    summaryStartupFailed,
		Detail:     floorDetail(detailStartupFailed, node),
		// A floor deliberately does not attribute a cause, so it cannot exclude
		// a source-keyed one — host-based access rules and a pooler's own
		// equivalent both decide on the connecting address. Marking this false
		// would assert a position-independence the finding has no basis for:
		// false is a positive claim, not an absence (ADR 0040 section 6.1).
		VantageDependent: true,
		EvidenceRefs:     refs,
		Recommendations:  recommend(recommendStartupFailed),
	})
}
