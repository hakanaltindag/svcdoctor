package postgres

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// The steps one PostgreSQL connection records, in the order they happen.
//
// Each is a separate step because each is separately true. The negotiation
// answering says what the endpoint will do about encryption; startup succeeding
// says the endpoint accepted the connection far enough to demand credentials;
// authentication passing says a credential was presented and settled; and the
// session reaching ReadyForQuery says a protocol session was established. A rule
// anchors at one of them and may require another.
//
// The string values are part of the report contract and are matched by
// automation. They moved here from internal/adapter/postgres unchanged; see
// docs/FINDINGS.md section 2 on why a step name is not renamed casually.
const (
	StepSSLRequest     domain.Step = "postgres.ssl_request"
	StepStartup        domain.Step = "postgres.startup"
	StepAuthentication domain.Step = "postgres.authentication"
	StepSession        domain.Step = "postgres.session"
)

// AttrSSLOffered is whether the endpoint agreed to encrypt this connection.
//
// It is recorded only when a real answer arrived, which is what makes it
// load-bearing rather than decorative: a failed negotiation that never got an
// answer carries no value here, so requiring the attribute distinguishes "the
// endpoint said no" from "svcdoctor never found out". Those are different
// claims, and only the first is a finding.
const AttrSSLOffered domain.AttributeKey = "postgres.ssl.offered"

// AttrAuthMethod is the authentication the endpoint demanded, normalized:
// "ok", "cleartext", "md5", "sasl", "gss", "sspi", "kerberos", or "unknown".
//
// "ok" is an endpoint stating it wants no authentication at all, and that value
// is why this key is read outside the adapter. On such a path no authentication
// node exists — svcdoctor presented nothing, so claiming a passing
// authentication would be an overclaim (ADR 0038 section 12) — and a session
// node's parent is the startup node instead. A rule that required an
// authentication parent would silently stop firing on every `trust` deployment.
const AttrAuthMethod domain.AttributeKey = "postgres.auth_method"

// AttrSQLState is the endpoint's SQLSTATE when it rejected an exchange.
//
// Five characters, machine-readable, carrying no identity. **It is rendered
// verbatim and never translated.** The adapter classifies it per step, because
// the only answerable question is what a code proves *there* (ADR 0039 section
// 7.1); a rule that translated one here would be building the shared dictionary
// that decision forbids.
const AttrSQLState domain.AttributeKey = "postgres.sqlstate"

// AttrErrorIsNative reports whether a rejection carried the non-localized
// severity field.
//
// Every genuine PostgreSQL backend since 9.6 sends it and pgBouncer does not, so
// it is the one structural, non-prose signal about the responder svcdoctor has.
//
// **It is an observation and never an input.** A rule may state its absence as
// the fact it is; it may not conclude a peer implementation from it, and it must
// not affect a finding's code, kind, severity or confidence. Its absence is
// equally consistent with a pooler, a proxy and a pre-9.6 server. Normative in
// ADR 0040 section 18.1.
const AttrErrorIsNative domain.AttributeKey = "postgres.error_is_native"

// AttrServerVersion is the server's own version string, as it reported it.
//
// It carries whatever packaging suffix a distribution adds — "18.6 (Debian
// 18.6-1.pgdg13+2)" — because that is what arrives on the wire. It is not a
// number, `server_version_num` is not sent by any version in the support window,
// and **nothing in this repository parses or compares it**.
//
// It is read outside the adapter by the terminal renderer, as one of the
// endpoint-reported observation lines every other service already has. It is
// never read by a rule: a version is not a problem without an expected-state
// contract, and `TestNoPostgresFindingAssertsAnExpectation` keeps a code from
// claiming otherwise.
const AttrServerVersion domain.AttributeKey = "postgres.server_version"

// AttrInHotStandby is "on" when the endpoint reported this session as attached
// to a server in recovery, and "off" when it reported the opposite.
//
// # It is an observation, and Phase 10.3 deliberately left it one
//
// It is the closest thing svcdoctor has to `pg_is_in_recovery()` without
// executing SQL, and against a real three-node Patroni cluster it tracked that
// function exactly, through a failover and a rejoin. That makes it *authoritative
// about what the endpoint said* and about nothing else:
//
//   - it is not an endpoint identity. A pooler forwards a cached value, so
//     nothing here distinguishes a replica from a primary that was in recovery
//     when the pooler cached (POSTGRES_PHASE46_DIAGNOSIS_STUDY.md section 5).
//   - it is not a writability answer. On a real standby this was "on" while
//     `default_transaction_read_only` was "off"; the parameter that settles
//     writability is session-local and needs SQL (ADR 0040 section 20).
//   - it is not a fault. During etcd quorum loss every node in that cluster
//     reported "on" and svcdoctor correctly produced no finding on any of them.
//
// **No rule reads it and none may**, which
// `TestSessionFactsStayEvidenceAndNeverBecomeFindings` and
// `TestTheRulesReadOnlyTheAuthorizedAttributes` both enforce. It earned a place
// here because the terminal renderer reads it — presenting an endpoint-reported
// fact in the result block is exactly the mechanism that keeps it from becoming
// a claim (ADR 0085 section 4).
const AttrInHotStandby domain.AttributeKey = "postgres.in_hot_standby"
