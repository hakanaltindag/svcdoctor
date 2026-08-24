package redis

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// The steps one Redis or Valkey connection records, in the order they happen.
//
// Three, because three things are separately true. HELLO answering says the
// endpoint speaks RESP and says what it calls itself; authentication settling
// says a credential was presented and the endpoint took a position on it; and
// PING answering says a command that is gated on authentication, authorization,
// dataset-loading state and stale-replica state was executed there.
//
// **There is no `redis.session` step, and that is deliberate.** Redis has no
// session boundary — no ReadyForQuery, no negotiated state to be in — so a step
// named after one would import a PostgreSQL concept this protocol does not have.
// The terminal step is named after the command it runs, which is also what keeps
// the claim honest: `redis.ping` PASS says PING was answered, and a reader
// cannot mistake it for "a session was established". ADR 0063 section 5.
//
// The string values are part of the report contract and are matched by
// automation; see docs/FINDINGS.md section 2 on why a step name is not renamed
// casually.
const (
	StepHello          domain.Step = "redis.hello"
	StepAuthentication domain.Step = "redis.authentication"
	StepPing           domain.Step = "redis.ping"
)

// AttrMode is the server mode the endpoint reported: "standalone", "cluster" or
// "sentinel".
//
// It is here rather than in the adapter because two packages outside the adapter
// read it. The Sentinel guard rule anchors on it — it is the whole predicate of
// the one finding ADR 0065 authorizes — and the terminal renderer prints it,
// including the "topology not measured" line a cluster-mode endpoint requires.
//
// **The value is always one svcdoctor declared.** The adapter matches the peer's
// bytes against a closed set and records its own constant, so a peer cannot put
// a string of its choosing here.
const AttrMode domain.AttributeKey = "redis.mode"

// AttrRole is the replication role the endpoint reported: "master" or "replica".
//
// **Observation only, permanently.** Without an expected-role contract, "this
// endpoint reports itself a replica" is a fact of exactly the same kind as
// PostgreSQL's `in_hot_standby`, which the frozen PostgreSQL BASIC already
// refuses to turn into a finding. It is recorded and rendered; no rule reads it,
// and `TestNoRedisFindingAssertsAnExpectation` fails the build if one does.
//
// Absence is meaningful rather than missing: Redis omits the field entirely in
// sentinel mode, so a node carrying a mode and no role is corroborating the
// Sentinel guard rather than lacking data.
const AttrRole domain.AttributeKey = "redis.role"

// AttrServer is the implementation name the endpoint reported, normally "redis"
// or "valkey".
//
// It is what the endpoint **said**, never what it is. Valkey reports "valkey" by
// default and "redis" with a Redis version number when extended-redis-compat is
// enabled, so this is an observation about a configurable self-description. The
// renderer reads it so that an operator who typed `diagnose redis` against a
// Valkey endpoint sees `valkey`; nothing derives behaviour from it, and
// `TestNoProductionCodeBranchesOnImplementationName` enforces that.
const AttrServer domain.AttributeKey = "redis.server"

// AttrServerVersion is the version string the endpoint reported.
//
// **It is opaque.** Not parsed, not compared, not ordered, and never used to
// infer a capability: Valkey's version numbers are on an unrelated line from
// Redis's, and either can be made to report the other's. Capability is
// established by asking — the HELLO outcome is the capability evidence — which
// is the same discipline Kafka applies through ApiVersions rather than through
// broker version strings. ADR 0066 section 5, enforced by
// `TestNoProductionCodeDoesVersionArithmetic`.
const AttrServerVersion domain.AttributeKey = "redis.server_version"

// AttrProto is the RESP protocol version the connection is on.
//
// Always 2 on a svcdoctor connection, because a zero-argument HELLO does not
// switch protocol. It is recorded as the measured fact rather than assumed, so a
// mutation that starts negotiating RESP3 is visible in the report rather than
// only in the code.
const AttrProto domain.AttributeKey = "redis.proto"

// AttrErrorPrefix is the normalized condition an endpoint named when it refused
// a command.
//
// It is a value from the closed set in internal/adapter/redis/wire, never a
// slice of the peer's bytes. Redis interpolates caller-supplied arguments and
// the username into error text, and Valkey parameterizes the shared strings by
// server name, so the prefix is the only part that is both stable across
// implementations and free of peer-chosen content. ADR 0066 section 3.
//
// Rules read it to state what the endpoint named — never to infer why. `LOADING`
// proves the endpoint said it is loading its dataset; it does not prove the
// server is down, that data was lost, or that a disk is slow.
const AttrErrorPrefix domain.AttributeKey = "redis.error_prefix"

// AttrAuthRequired reports that the endpoint demanded authentication before it
// would answer.
//
// Recorded only on a HELLO node that was refused with NOAUTH or answered
// outright, so it distinguishes "the endpoint requires a credential" from "the
// endpoint does not" — and never claims either when HELLO itself did not
// complete. The composition root reads the adapter's own answer rather than this
// key; the renderer reads this one.
const AttrAuthRequired domain.AttributeKey = "redis.auth_required"
