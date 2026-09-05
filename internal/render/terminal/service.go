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

		// Phase 10.3. Two endpoint-reported facts, and they are here rather than
		// in a finding on purpose — this is where ADR 0085 section 4 draws the
		// line between *what the endpoint said* and *what svcdoctor claims*.
		//
		// A run reaches at most one session node, so at most one of each line is
		// ever printed. Neither affects the outcome line, the summary status or
		// an exit code, and no rule reads either attribute — which
		// TestTheRulesReadOnlyTheAuthorizedAttributes and
		// TestSessionFactsStayEvidenceAndNeverBecomeFindings both enforce, and
		// which is why "svcdoctor connected to a standby" cannot become a
		// problem here without somebody deciding it should be.
		// **`server_version` is deliberately not among them.**
		//
		// PostgreSQL's ParameterStatus values are unbounded: `wire.SessionParameters`
		// allowlists four *keys* and retains each one's value as the server's own
		// string, with no length or character bound. A verbatim version line would
		// therefore put peer-chosen bytes on an operator's terminal.
		//
		// Redis and RabbitMQ already render a verbatim version, and that is a
		// pre-existing cross-service question rather than this phase's to answer —
		// it needs one decision about sanitizing observation values at the renderer
		// boundary, for every service at once. Phase 10.3 declines to widen the
		// surface while that decision is outstanding, and the version is in the
		// report's evidence either way.
		//
		// **The second line arrived in Phase 10.7B, and the two stay independent.**
		// ADR 0089 selected it as a Class 1 activation: `default_transaction_read_only`
		// has been recorded on every passing session since Phase 4.5 and was read by
		// nothing. Neither line is derived from the other and neither may be — the
		// adapter measured a real standby reporting `in_hot_standby=on` while
		// `default_transaction_read_only=off`, so a reader that collapsed them would
		// publish a mode nobody reported.
		observations: []observationLine{
			{
				step:  servicepostgres.StepSession,
				key:   servicepostgres.AttrInHotStandby,
				label: "recovery",
				// A closed two-value map, and the closure is the point twice
				// over. It renders the GUC's "on"/"off" as the English an
				// operator can read without knowing the parameter's name; and
				// because anything else yields the empty string that drops the
				// line, a peer cannot put a value of its own choosing on a
				// terminal through this path. That is the same discipline the
				// Redis and RabbitMQ render functions follow, tightened,
				// because this value is the one that would be misread as a
				// verdict.
				render: func(v domain.AttrValue) string {
					switch v.String() {
					case "on":
						return "in recovery"
					case "off":
						return "not in recovery"
					default:
						return ""
					}
				},
			},
			{
				step:  servicepostgres.StepSession,
				key:   servicepostgres.AttrDefaultTransactionReadOnly,
				label: "default transaction read-only",
				// **The parameter's own two values, and no third concept.**
				//
				// The sibling above translates, because "in recovery" is English
				// an operator can read and `in_hot_standby` is not. This one must
				// not, and the reason is asymmetric: `on` has a faithful English
				// form, and `off` does not. Every candidate for it — "read
				// write", "writable", "writes enabled" — is a *positive* claim
				// about what this session can do, and the parameter says only
				// that one default is not set. Object, database and row-level
				// privileges are untouched by it, a transaction may override it,
				// and behind a pooler the next one may reach a different backend.
				//
				// So the label carries the meaning and the value stays the
				// endpoint's own token. `off` renders `off`, which is exactly
				// what was reported and nothing more.
				//
				// Closed all the same, for the reason the sibling is closed: the
				// returned strings are this package's constants rather than the
				// peer's bytes, and anything outside the two yields the empty
				// string that drops the line.
				// TestPGP13ServerControlledTextNeverReachesTrustedProse drives
				// this key with hostile values, including one beginning "on".
				render: func(v domain.AttrValue) string {
					switch v.String() {
					case "on":
						return "on"
					case "off":
						return "off"
					default:
						return ""
					}
				},
			},
		},

		notes: []conditionalNote{
			{
				step:  servicepostgres.StepSession,
				key:   servicepostgres.AttrInHotStandby,
				value: "on",
				// It exists because the *silence* beside this line would be
				// misread. An operator who sees "recovery: in recovery" and no
				// finding has to be told that the absence of a finding is
				// deliberate, and told what the observation is worth: it is what
				// the endpoint reported about this session, it is not an
				// identity, it is not a fault, and svcdoctor has no expectation
				// to compare it against (ADR 0083 section 2.6, ADR 0085
				// section 4).
				//
				// There is deliberately no matching note for "off". "Not in
				// recovery" invites no action and no alarm, and a note beside it
				// would be svcdoctor reassuring a reader about something it did
				// not measure.
				lines: []string{
					"This endpoint reported the session as being in recovery.",
					"That is what the endpoint said about this session and nothing more:",
					"svcdoctor ran no query, and it holds no expectation about which role",
					"this target should have, so this is neither a finding nor a fault.",
				},
			},
			{
				step:  servicepostgres.StepSession,
				key:   servicepostgres.AttrDefaultTransactionReadOnly,
				value: "on",
				// The same silence problem as the recovery note, and the same
				// answer — with one addition, because this is the note that has
				// to refuse the strongest available sentence. An operator reading
				// it wants to be told their writes will fail, and svcdoctor did
				// not measure that.
				//
				// The subject is **this session**, not the endpoint: the value is
				// a session parameter, a pooler may hand the next transaction to
				// a different backend, and saying "endpoint" would attribute to a
				// server what only one session reported.
				//
				// Deliberately no matching note for "off". Reassurance is the
				// failure mode on that side, and a note there would be svcdoctor
				// commenting on something it did not measure.
				lines: []string{
					"This session reported that its transactions default to read-only.",
					"That is what it reported and nothing more: it describes no other",
					"session, it does not say whether any particular write would succeed,",
					"and svcdoctor ran no query and holds no expectation about it. It is",
					"neither a finding nor a fault.",
				},
			},
		},
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
