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
