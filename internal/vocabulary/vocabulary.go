package vocabulary

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// The steps a requested-target transport chain records, in the order they
// happen.
//
// The string values are part of the report contract and are matched by
// automation. The three transport names moved here from internal/probe/dns,
// internal/probe/tcp and internal/probe/tls unchanged, and those packages now
// alias them; see docs/FINDINGS.md section 2 on why a step name is not renamed
// casually.
const (
	// StepTargetRequested names the L0 fact that a run accepted an operator's
	// logical endpoint as its input.
	//
	// It says that input normalization succeeded and what the target was. It
	// says nothing about DNS, TCP, TLS, the service, the credential or the
	// health of anything: it is the first fact of a run rather than a verdict
	// about one, and it is the only node in a graph that is not a measurement.
	//
	// A node with this step is always PASS. Unusable input fails before a graph
	// exists, so there is no FAIL form of it (ADR 0042 section 1).
	StepTargetRequested domain.Step = "target.requested"

	// StepDNSLookup names one hostname resolution.
	StepDNSLookup domain.Step = "dns.lookup"

	// StepTCPConnect names one connection attempt to one concrete address.
	StepTCPConnect domain.Step = "tcp.connect"

	// StepTLSHandshake names one TLS handshake.
	//
	// **The step alone does not say who owns the node.** PostgreSQL negotiates
	// encryption in band, so a handshake performed after `postgres.ssl_request`
	// records this same step while belonging to the service. What distinguishes
	// them is the parent edge, never the name: a generic transport handshake
	// hangs off a tcp.connect node, and PostgreSQL's hangs off the negotiation
	// that asked for it (ADR 0042 section 7).
	StepTLSHandshake domain.Step = "tls.handshake"
)
