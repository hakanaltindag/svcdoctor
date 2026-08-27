package rabbitmq

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// The steps one RabbitMQ connection records, in the order they happen.
//
// Three, because three things are separately true, and AMQP 0-9-1 separates them
// into distinct method exchanges on one connection. `Connection.Start` arriving
// says the endpoint speaks AMQP 0-9-1 and says what it calls itself.
// `Connection.Tune` arriving says a credential was presented and the endpoint
// accepted it. `Connection.Open-Ok` arriving says the authenticated identity was
// allowed to open a connection in the requested virtual host.
//
// **There is no `rabbitmq.tune` step, and that is measured rather than chosen.**
// Nothing is sent in reply to `Connection.Tune-Ok`, so such a node could never
// observe its own PASS; and Tune's *arrival* is authentication's success signal,
// so its values belong on the node whose PASS it establishes. ADR 0067 §4.1.
//
// **There is no `rabbitmq.vhost` step either.** There is no vhost measurement
// separate from opening a connection in it, so a fourth node would re-project the
// third one's outcome — which ADR 0013 puts in the graph rather than in
// duplicated evidence.
//
// The string values are part of the report contract and are matched by
// automation; see docs/FINDINGS.md section 2 on why a step name is not renamed
// casually.
const (
	StepConnectionStart domain.Step = "rabbitmq.connection_start"
	StepAuthentication  domain.Step = "rabbitmq.authentication"
	StepConnectionOpen  domain.Step = "rabbitmq.connection_open"
)

// AttrProduct is the product name the endpoint reported in `server-properties`.
//
// It is what the endpoint **said**, never what it is. Phase 8.0C measured
// RabbitMQ reporting "RabbitMQ" and LavinMQ reporting "LavinMQ" from the same
// field, and a proxy may report anything at all. The renderer reads it so that an
// operator who typed `diagnose rabbitmq` against a LavinMQ endpoint sees LavinMQ;
// nothing derives behaviour from it, and a guard fails the build if anything does.
const AttrProduct domain.AttributeKey = "rabbitmq.product"

// AttrVersion is the version string the endpoint reported.
//
// **It is opaque.** Not parsed, not compared, not ordered, and never used to
// infer a capability. Capability is established by asking — the offered mechanism
// set is the capability evidence — which is the discipline Kafka applies through
// ApiVersions and Redis through HELLO rather than through version strings.
const AttrVersion domain.AttributeKey = "rabbitmq.version"

// AttrPlatform is the runtime the endpoint reported, such as an Erlang or
// Crystal version. Observation only.
const AttrPlatform domain.AttributeKey = "rabbitmq.platform"

// AttrClusterName is the cluster name the endpoint reported.
//
// **It carries a hostname.** RabbitMQ defaults it to its own Erlang node name,
// which is `rabbit@<hostname>`, so it is declared with AttrKindIdentity and is
// pseudonymized by redaction exactly as a peer hostname is (ADR 0037).
//
// It does **not** identify which node answered. Every node in a cluster reports
// the same value, so it cannot disambiguate an endpoint behind a load balancer —
// which is one of the two reasons ADR 0067 §5.2 keeps the terminal claim
// endpoint-scoped.
const AttrClusterName domain.AttributeKey = "rabbitmq.cluster_name"

// AttrAMQPVersion is the protocol version the peer named in `Connection.Start`,
// rendered as "major-minor".
//
// Recorded as the measured fact rather than assumed, so a mutation that starts
// sending a different protocol header is visible in the report rather than only
// in the code.
const AttrAMQPVersion domain.AttributeKey = "rabbitmq.amqp_version"

// AttrMechanismsOffered is the **normalized set of recognized** authentication
// mechanisms the endpoint advertised, sorted and space-joined.
//
// It is never the peer's own bytes. `Connection.Start.mechanisms` is a
// peer-controlled long string bounded only by the frame ceiling, so copying it
// would admit kilobytes of peer-chosen text into a report for a field whose only
// diagnostic content is which mechanisms svcdoctor could have used. The wire
// package matches against a closed set and records svcdoctor's own constants.
// ADR 0067 §4.2.
const AttrMechanismsOffered domain.AttributeKey = "rabbitmq.mechanisms_offered"

// AttrMechanismSelected is the mechanism svcdoctor used. Always PLAIN when
// authentication was attempted at all (ADR 0068 §2).
const AttrMechanismSelected domain.AttributeKey = "rabbitmq.mechanism_selected"

// AttrIdentity is the identity svcdoctor presented, or absent when it presented
// none.
//
// It is the operator's own input rather than anything the peer said, and it is
// declared with AttrKindIdentity because a username is exactly the value a
// shareable report must not carry (ADR 0037).
//
// One rule reads it, for one narrow purpose: the credential-rejection finding
// appends a sentence about RabbitMQ's default `guest` loopback restriction when
// the identity is exactly `guest`. That sentence is gated on the username and on
// **nothing else** — RabbitMQ evaluates the restriction against the broker's view
// of the client's source address, which svcdoctor cannot observe, so gating on
// any address would build a claim on evidence it does not have (ADR 0068 §4.1).
const AttrIdentity domain.AttributeKey = "rabbitmq.identity"

// AttrAnonymousOffered reports that the endpoint advertised SASL ANONYMOUS.
//
// **Observation only, permanently.** An endpoint advertising it will let a remote
// client attempt a login as RabbitMQ's `anonymous_login_user` — `guest` by
// default — with no credential configured anywhere. That is a hardening
// judgement about the operator's configuration, and BASIC diagnoses reachability
// rather than posture (ADR 0069 §8). svcdoctor never selects it.
const AttrAnonymousOffered domain.AttributeKey = "rabbitmq.anonymous_offered"

// The negotiation window, offered by the peer and selected by svcdoctor.
//
// All six are observations. There is no threshold svcdoctor could apply to any of
// them that would not be a policy invention, so no rule reads them and a guard
// fails the build if one does (ADR 0069 §8).
const (
	AttrChannelMaxOffered  domain.AttributeKey = "rabbitmq.channel_max_offered"
	AttrChannelMaxSelected domain.AttributeKey = "rabbitmq.channel_max_selected"
	AttrFrameMaxOffered    domain.AttributeKey = "rabbitmq.frame_max_offered"
	AttrFrameMaxSelected   domain.AttributeKey = "rabbitmq.frame_max_selected"
	AttrHeartbeatOffered   domain.AttributeKey = "rabbitmq.heartbeat_offered"
	AttrHeartbeatSelected  domain.AttributeKey = "rabbitmq.heartbeat_selected"
)

// AttrVHost is the virtual host the run asked for.
//
// It is the operator's own input rather than anything the peer said, and it is
// declared with AttrKindIdentity: a virtual host name is a tenant name in a
// multi-tenant deployment and is exactly the kind of value a shareable report
// must not carry (ADR 0037).
const AttrVHost domain.AttributeKey = "rabbitmq.vhost"

// AttrVHostDefaulted reports that the run used the default `/` because the
// operator named no virtual host.
//
// ADR 0067 §3.1 makes this part of the decision to default rather than require:
// a vhost-scoped refusal must be able to say that the default was used, which
// turns the one bad case into a self-explaining one.
const AttrVHostDefaulted domain.AttributeKey = "rabbitmq.vhost_defaulted"

// AttrCloseOutcome is the normalized classification of a `Connection.Close`.
//
// It is a value from the closed set in internal/adapter/rabbitmq/wire, never a
// slice of the peer's bytes. RabbitMQ interpolates the virtual host and the
// username into its reply text and an authorization backend may append arbitrary
// bytes to it, so the normalized outcome is the only part that is both stable and
// free of peer-chosen content. ADR 0069 §2 and §3.
//
// Rules read it to state what the endpoint named — never to infer why. A
// connection-limit outcome proves the endpoint said a ceiling was reached; it
// does not prove the ceiling is too low, that demand is abnormal, or that the
// condition still holds.
const AttrCloseOutcome domain.AttributeKey = "rabbitmq.close_outcome"

// AttrReplyCode is the numeric AMQP reply code the endpoint sent.
//
// The peer's own structured field rather than prose, so it is safe to carry
// verbatim — the same reasoning under which PostgreSQL renders a SQLSTATE.
const AttrReplyCode domain.AttributeKey = "rabbitmq.reply_code"

// AttrPeerCloseMethod is the class and method id the peer attributed its own
// `Connection.Close` to, rendered as "class/method".
//
// **Corroboration only.** Attribution authority is svcdoctor's own handshake
// state, which a peer cannot forge. Phase 8.0C measured RabbitMQ sending 0/0 for
// an authentication refusal and LavinMQ sending 10/11 for the same condition,
// which is exactly why neither may drive a conclusion (ADR 0069 §1).
const AttrPeerCloseMethod domain.AttributeKey = "rabbitmq.peer_close_method"

// AttrGracefulClose reports whether the polite `Connection.Close`/`Close-Ok`
// epilogue completed after a successful open.
//
// It can never change a verdict. Evidence is immutable and `Open-Ok` was recorded
// when it arrived, so a failure here is an attribute rather than a finding — and
// the AMQP specification agrees that a peer detecting socket closure without
// `Close-Ok` should log the error rather than fail (ADR 0067 §9).
const AttrGracefulClose domain.AttributeKey = "rabbitmq.graceful_close"
