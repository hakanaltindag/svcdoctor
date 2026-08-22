package terminal

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// journey is the order a reader expects the stages in.
//
// It is the client journey, not the graph's own shape: a person reading a
// diagnosis follows *what svcdoctor tried to do*, and the graph's parent edges
// happen to agree because the run really did proceed in this order. The TLS
// handshake sits after the negotiation that caused it, which is the edge
// internal/adapter/postgres records and the reason ADR 0044 owns that node.
//
// The list contains only the per-path stages. `target.requested` is the header
// and `dns.lookup` belongs to the logical target, so both are rendered above the
// paths rather than inside one.
var journey = []domain.Step{
	vocabulary.StepTCPConnect,
	servicepostgres.StepSSLRequest,
	vocabulary.StepTLSHandshake,
	servicepostgres.StepStartup,
	servicepostgres.StepAuthentication,
	servicepostgres.StepSession,
}

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
