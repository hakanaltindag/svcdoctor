package terminal

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// serviceView is everything this renderer knows that is specific to one service.
//
// # A table, not a branch
//
// ADR 0052 section 5 fixed the mechanism: a second service arrives as rows here,
// never as `if kafka` inside a rendering function. Everything else in this
// package — the glyphs, the absence wording, the findings block, the Result
// block's four lines, the duration column — is service-neutral and stays that
// way.
//
// # An unknown service still renders
//
// A ServiceID with no row gets the zero serviceView, and every consumer of it is
// written to be total on that: an empty journey renders whatever nodes a path
// actually holds, an empty outcomeStep renders no outcome line, and an empty
// advertisementStep means the graph has no topology level. That is the same
// discipline stepLabel already applies — an unrecognized step renders as its
// canonical name rather than vanishing — one level up.
type serviceView struct {
	// journey is the per-path stage order a reader expects.
	//
	// It is the client journey rather than the graph's shape, and the two agree
	// because the run really did proceed in this order.
	journey []domain.Step

	// narrowingSteps are the journey steps only the continued path can hold.
	//
	// A run measures every resolved address through discovery and then continues
	// exactly one (ADR 0028, ADR 0041). These are the stages that happen after
	// that narrowing, and holding one is what marks a path as the continued one.
	narrowingSteps []domain.Step

	// outcomeStep is the node whose state the Result block's `outcome` line
	// restates. It is the terminal fact of the core journey and nothing weaker.
	outcomeStep domain.Step

	// outcomeReached and outcomeNotReached are that line's two phrasings.
	//
	// They are written out rather than composed from the step name, because each
	// was argued over in the record that authorized it and a generated phrase
	// would be a claim nobody reviewed.
	outcomeReached    string
	outcomeNotReached string

	// advertisementStep names the node a discovered endpoint hangs from, or is
	// empty for a service whose runs discover no topology.
	//
	// Its presence is what gives the tree a third level: an advertisement, the
	// transport sweep beneath it, and that sweep's stages. A service without one
	// renders exactly the two levels it did before.
	advertisementStep domain.Step

	// advertisedJourney is the stage order for a path beneath an advertisement.
	//
	// **It is transport and nothing else, and that is a security property
	// rather than a presentation choice.** A discovered endpoint receives
	// credential-free DNS, TCP and TLS and no protocol exchange at all
	// (ADR 0050). Reusing the bootstrap journey here would print
	// `Authentication  not attempted on this path` beneath every advertised
	// broker — a row that says svcdoctor *could* have authenticated there and
	// happened not to, when the truth is that it must never.
	//
	// It is not a filter over the rendered rows. stageLines renders whatever the
	// path holds, so an authentication node that somehow appeared beneath an
	// advertisement would still be shown rather than hidden: concealing a
	// security failure is worse than reporting one, and a test asserts the graph
	// never holds it.
	advertisedJourney []domain.Step

	// advertisementLabel names one discovered endpoint in the tree and in the
	// topology line. Empty when advertisementStep is empty.
	advertisementLabel string

	// advertisementIdentity optionally names the attribute that identifies which
	// discovered peer an advertisement is about, so two advertisements are
	// distinguishable in a shareable report where the endpoints are pseudonyms.
	//
	// It must be an attribute that survives redaction. Kafka's broker node
	// identifier does: it names a position in a cluster rather than a host.
	advertisementIdentity domain.AttributeKey
}

// The services this renderer has words for.
//
// PostgreSQL's journey, labels and outcome phrasing are unchanged from Phase
// 5.3. Kafka's are ADR 0052's, verbatim.
var services = map[domain.ServiceID]serviceView{
	"postgres": {
		journey: []domain.Step{
			vocabulary.StepTCPConnect,
			servicepostgres.StepSSLRequest,
			vocabulary.StepTLSHandshake,
			servicepostgres.StepStartup,
			servicepostgres.StepAuthentication,
			servicepostgres.StepSession,
		},
		narrowingSteps: []domain.Step{
			servicepostgres.StepAuthentication,
			servicepostgres.StepSession,
		},
		outcomeStep: servicepostgres.StepSession,
		// ADR 0039 made `postgres.session` the boundary because AuthenticationOk
		// is not success: 3D000 and 42501 arrive after it and before
		// ReadyForQuery. A passing session node is the only evidence there was
		// one.
		outcomeReached:    "session established",
		outcomeNotReached: "session NOT established",
	},
	"kafka": {
		journey: []domain.Step{
			vocabulary.StepTCPConnect,
			vocabulary.StepTLSHandshake,
			servicekafka.StepAPIVersions,
			servicekafka.StepSASLHandshake,
			servicekafka.StepSASLAuthenticate,
			servicekafka.StepMetadata,
		},
		narrowingSteps: []domain.Step{
			servicekafka.StepSASLAuthenticate,
			servicekafka.StepMetadata,
		},
		outcomeStep: servicekafka.StepMetadata,
		// ADR 0052 section 2, word for word. **Not** "cluster metadata": the
		// request is Metadata v1 with `Topics = []`, which asks for metadata
		// about no topics, so the run obtains no topic, partition, leader,
		// replica or ISR state. And **not** "session established": Kafka has no
		// session-establishment handshake to have completed.
		outcomeReached:    "Kafka metadata obtained",
		outcomeNotReached: "Kafka metadata NOT obtained",

		advertisedJourney: []domain.Step{
			vocabulary.StepTCPConnect,
			vocabulary.StepTLSHandshake,
		},
		advertisementStep:     servicekafka.StepBrokerAdvertised,
		advertisementLabel:    "Advertised broker",
		advertisementIdentity: servicekafka.AttrBrokerNodeID,
	},
}

// viewFor returns the service's presentation vocabulary, or the zero view.
func viewFor(report domain.Report) serviceView {
	return services[report.Run().Service()]
}
