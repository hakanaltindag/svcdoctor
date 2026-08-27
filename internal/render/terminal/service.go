package terminal

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
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

	// observations are endpoint-reported facts a reader should see, in order.
	//
	// **They are observations and never findings.** Each is something the
	// endpoint said about itself — what it calls itself, what version it
	// reports, what mode it is in, what replication role it holds — and none of
	// them is a problem without an expected-state contract svcdoctor does not
	// have. Rendering them in the Result block rather than as findings is that
	// distinction made visible.
	//
	// An empty slice renders nothing, which is what PostgreSQL and Kafka get.
	observations []observationLine

	// notes are conditional statements the Result block prints when an
	// observation holds a particular value.
	//
	// They exist for the two cases where a *silence* would be misread. A
	// cluster-mode endpoint that produced no topology findings looks like a
	// healthy cluster unless the report says topology was not measured; and a
	// Sentinel that stopped the run looks like a run that simply ended.
	notes []conditionalNote
}

// observationLine names one endpoint-reported fact and how to print it.
type observationLine struct {
	// step is the node to read it from. The **last** node at that step wins,
	// which matters for Redis: an endpoint that demanded authentication answers
	// the first HELLO with a refusal and only the second one carries an
	// identity.
	step  domain.Step
	key   domain.AttributeKey
	label string

	// render optionally formats the value. Nil means the value's own string.
	render func(domain.AttrValue) string
}

// conditionalNote is a statement printed when one attribute holds one value.
//
// The lines are written out rather than composed, for the same reason
// outcomeReached is: each was argued over, and a generated sentence would be a
// claim nobody reviewed.
type conditionalNote struct {
	step  domain.Step
	key   domain.AttributeKey
	value string
	lines []string

	// replacesOutcome suppresses the outcome line entirely.
	//
	// A Sentinel stopped the journey before the probe, so printing
	// "did NOT answer PING" beside the stop would invite a reader to treat the
	// Sentinel as a data endpoint that failed rather than as the wrong kind of
	// endpoint.
	replacesOutcome bool
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
	// One row for both implementations. ADR 0066 section 6 freezes one adapter
	// and one command, and the implementation is an *observation* below rather
	// than a second row here — which is what stops the renderer from being the
	// place a vendor branch reappears.
	"redis": {
		journey: []domain.Step{
			vocabulary.StepTCPConnect,
			vocabulary.StepTLSHandshake,
			serviceredis.StepHello,
			serviceredis.StepAuthentication,
			serviceredis.StepPing,
		},
		narrowingSteps: []domain.Step{
			serviceredis.StepAuthentication,
			serviceredis.StepPing,
		},
		outcomeStep: serviceredis.StepPing,
		// ADR 0063 section 4, word for word, and deliberately endpoint-scoped.
		// **Not** "Redis is healthy", "the service is usable" or "the backend is
		// available": a proxy can answer PING while what is behind it cannot
		// serve anything, which is the pgBouncer lesson arriving in a third
		// service.
		outcomeReached:    "this endpoint answered PING on this connection",
		outcomeNotReached: "this endpoint did NOT answer PING on this connection",

		observations: []observationLine{
			{step: serviceredis.StepHello, key: serviceredis.AttrServer, label: "implementation"},
			{step: serviceredis.StepHello, key: serviceredis.AttrServerVersion, label: "version"},
			{
				step: serviceredis.StepHello, key: serviceredis.AttrProto, label: "protocol",
				// The value is the negotiated RESP version as an integer. It is
				// rendered rather than interpreted: nothing branches on it, and
				// svcdoctor never compares it.
				render: func(v domain.AttrValue) string {
					if n, ok := v.Int(); ok {
						return fmt.Sprintf("RESP%d", n)
					}
					return ""
				},
			},
			{step: serviceredis.StepHello, key: serviceredis.AttrMode, label: "mode"},
			{step: serviceredis.StepHello, key: serviceredis.AttrRole, label: "role"},
		},

		notes: []conditionalNote{
			{
				step: serviceredis.StepHello, key: serviceredis.AttrMode, value: "cluster",
				lines: []string{
					"Cluster mode was observed at this endpoint.",
					"Cluster topology was NOT measured: no node was discovered, no slot",
					"coverage was checked and no advertised address was probed.",
				},
			},
			{
				step: serviceredis.StepHello, key: serviceredis.AttrMode, value: "sentinel",
				lines: []string{
					"This endpoint identified itself as Redis Sentinel.",
					"Redis/Valkey data-endpoint diagnosis stopped here, before any",
					"credential was presented. The Sentinel itself was not diagnosed.",
				},
				replacesOutcome: true,
			},
		},
	},

	// Phase 8.2. A fourth service arrives as one more row, exactly as ADR 0052
	// §5 fixed: no rendering function in this package learned the word
	// "rabbitmq", and a structural guard fails the build if one does.
	"rabbitmq": {
		journey: []domain.Step{
			vocabulary.StepDNSLookup,
			vocabulary.StepTCPConnect,
			vocabulary.StepTLSHandshake,
			servicerabbitmq.StepConnectionStart,
			servicerabbitmq.StepAuthentication,
			servicerabbitmq.StepConnectionOpen,
		},
		narrowingSteps: []domain.Step{
			servicerabbitmq.StepAuthentication,
			servicerabbitmq.StepConnectionOpen,
		},
		outcomeStep: servicerabbitmq.StepConnectionOpen,
		// ADR 0067 §5.1, deliberately endpoint-scoped and deliberately naming
		// the frame rather than a state of the world.
		//
		// **Not** "RabbitMQ is healthy", "the broker is usable" or "the virtual
		// host is healthy". Open-Ok proves a real broker process authenticated
		// this identity and let it open a connection in this virtual host at
		// this instant — and behind a load balancer svcdoctor cannot even say
		// which node answered, because every node in a cluster reports the same
		// cluster_name.
		outcomeReached: "this endpoint answered Connection.Open-Ok for the requested " +
			"virtual host on this connection",
		outcomeNotReached: "this endpoint did NOT answer Connection.Open-Ok for the " +
			"requested virtual host on this connection",

		observations: []observationLine{
			{
				step:  servicerabbitmq.StepConnectionStart,
				key:   servicerabbitmq.AttrProduct,
				label: "implementation",
			},
			{
				step:  servicerabbitmq.StepConnectionStart,
				key:   servicerabbitmq.AttrVersion,
				label: "version",
			},
			{
				step:  servicerabbitmq.StepConnectionStart,
				key:   servicerabbitmq.AttrPlatform,
				label: "platform",
			},
			{
				step:  servicerabbitmq.StepConnectionStart,
				key:   servicerabbitmq.AttrClusterName,
				label: "cluster name",
			},
			{
				step:  servicerabbitmq.StepConnectionStart,
				key:   servicerabbitmq.AttrAMQPVersion,
				label: "protocol",
				// Rendered, never interpreted. Nothing branches on it and
				// svcdoctor never compares it.
				render: func(v domain.AttrValue) string {
					if s := v.String(); s != "" {
						return "AMQP " + s
					}
					return ""
				},
			},
			{
				step:  servicerabbitmq.StepConnectionStart,
				key:   servicerabbitmq.AttrMechanismsOffered,
				label: "mechanisms offered",
			},
			{
				step:  servicerabbitmq.StepAuthentication,
				key:   servicerabbitmq.AttrMechanismSelected,
				label: "mechanism used",
			},
			{
				step:  servicerabbitmq.StepConnectionOpen,
				key:   servicerabbitmq.AttrVHost,
				label: "virtual host",
			},
			{
				step:  servicerabbitmq.StepAuthentication,
				key:   servicerabbitmq.AttrChannelMaxOffered,
				label: "channel_max offered",
			},
			{
				step:  servicerabbitmq.StepAuthentication,
				key:   servicerabbitmq.AttrChannelMaxSelected,
				label: "channel_max selected",
			},
			{
				step:  servicerabbitmq.StepAuthentication,
				key:   servicerabbitmq.AttrFrameMaxOffered,
				label: "frame_max offered",
			},
			{
				step:  servicerabbitmq.StepAuthentication,
				key:   servicerabbitmq.AttrFrameMaxSelected,
				label: "frame_max selected",
			},
			{
				step:  servicerabbitmq.StepAuthentication,
				key:   servicerabbitmq.AttrHeartbeatOffered,
				label: "heartbeat offered",
			},
			{
				step:  servicerabbitmq.StepAuthentication,
				key:   servicerabbitmq.AttrHeartbeatSelected,
				label: "heartbeat selected",
			},
		},

		notes: []conditionalNote{
			{
				step:  servicerabbitmq.StepConnectionStart,
				key:   servicerabbitmq.AttrAnonymousOffered,
				value: "true",
				lines: []string{
					"This endpoint advertises SASL ANONYMOUS.",
					"svcdoctor never selects it. A remote client could attempt a login",
					"with no credential configured anywhere; whether that is intended is",
					"a configuration question svcdoctor does not answer.",
				},
			},
		},
	},
}

// viewFor returns the service's presentation vocabulary, or the zero view.
func viewFor(report domain.Report) serviceView {
	return services[report.Run().Service()]
}
