package postgres

import (
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// A graph builder for PostgreSQL shapes, kept deliberately close to what the
// adapter actually emits.
//
// Every fixture below was written from the producers in internal/adapter/postgres
// rather than from the ADR's prose, so a test that passes here is a test against
// a shape the chain can really produce. Where a fixture is a shape no producer
// emits, it says so.

type builder struct {
	t  *testing.T
	b  *domain.GraphBuilder
	at time.Time
}

func newBuilder(t *testing.T) *builder {
	t.Helper()
	return &builder{
		t: t,
		b: domain.NewGraphBuilder(),
		// A fixed instant: a rule must never consult the clock, and a fixture
		// that used time.Now would make byte-stability tests lie.
		at: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC),
	}
}

type nodeSpec struct {
	id      string
	subject string
	layer   domain.Layer
	step    domain.Step
	state   domain.State
	class   domain.FailureClass
	attrs   map[domain.AttributeKey]domain.AttrValue
	parent  string
	blocker string
}

func (b *builder) add(spec nodeSpec) domain.EvidenceID {
	b.t.Helper()

	subject, err := domain.NewEndpointSubject(spec.subject)
	if err != nil {
		b.t.Fatalf("subject %q: %v", spec.subject, err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           domain.EvidenceID(spec.id),
		Subject:      subject,
		Layer:        spec.layer,
		Step:         spec.step,
		State:        spec.state,
		FailureClass: spec.class,
		Attributes:   spec.attrs,
		StartedAt:    b.at,
		Duration:     time.Millisecond,
	})
	if err != nil {
		b.t.Fatalf("evidence %q: %v", spec.id, err)
	}
	if err := b.b.AddEvidence(evidence); err != nil {
		b.t.Fatalf("adding %q: %v", spec.id, err)
	}
	if spec.parent != "" {
		if err := b.b.AddParent(evidence.ID(), domain.EvidenceID(spec.parent)); err != nil {
			b.t.Fatalf("parent of %q: %v", spec.id, err)
		}
	}
	if spec.blocker != "" {
		if err := b.b.AddBlockedBy(evidence.ID(), domain.EvidenceID(spec.blocker)); err != nil {
			b.t.Fatalf("blocker of %q: %v", spec.id, err)
		}
	}
	return evidence.ID()
}

func (b *builder) freeze() domain.Graph {
	b.t.Helper()
	g, err := b.b.Freeze()
	if err != nil {
		b.t.Fatalf("freeze: %v", err)
	}
	return g
}

// The identifiers the fixtures use. Shaped like the real ones — scope, step,
// endpoint, address — without being parsed by anything, because no rule parses
// an identifier.
const (
	idTCP     = "tcp.connect/db.internal:5432/10.0.0.5"
	idSSL     = "postgres.ssl_request/db.internal:5432/10.0.0.5"
	idTLS     = "tls.handshake/db.internal:5432/10.0.0.5"
	idStartup = "postgres.startup/db.internal:5432/10.0.0.5"
	idAuth    = "postgres.authentication/db.internal:5432/10.0.0.5"
	idSession = "postgres.session/db.internal:5432/10.0.0.5"

	addr = "10.0.0.5:5432"
)

// sslNode adds a negotiation node.
func (b *builder) sslNode(state domain.State, class domain.FailureClass, offered *bool) domain.EvidenceID {
	attrs := map[domain.AttributeKey]domain.AttrValue{}
	if offered != nil {
		attrs[servicepostgres.AttrSSLOffered] = domain.BoolAttr(*offered)
	}
	return b.add(nodeSpec{
		id: idSSL, subject: addr, layer: domain.LayerTLS,
		step: servicepostgres.StepSSLRequest, state: state, class: class, attrs: attrs,
	})
}

// startupNode adds a startup node carrying the identity attributes the adapter
// records, plus whatever error facts a rejection produced.
func (b *builder) startupNode(
	state domain.State, class domain.FailureClass, sqlState string, native *bool, authMethod string,
) domain.EvidenceID {
	attrs := map[domain.AttributeKey]domain.AttrValue{
		"postgres.protocol_version": domain.StringAttr("3.0"),
		"postgres.role":             domain.IdentityAttr("tenantrole"),
		"postgres.database":         domain.IdentityAttr("tenantcatalog"),
	}
	if authMethod != "" {
		attrs[servicepostgres.AttrAuthMethod] = domain.StringAttr(authMethod)
	}
	if sqlState != "" {
		attrs[servicepostgres.AttrSQLState] = domain.StringAttr(sqlState)
	}
	if native != nil {
		attrs[servicepostgres.AttrErrorIsNative] = domain.BoolAttr(*native)
	}
	return b.add(nodeSpec{
		id: idStartup, subject: addr, layer: domain.LayerProtocol,
		step: servicepostgres.StepStartup, state: state, class: class, attrs: attrs,
	})
}

// authNode adds an authentication node parented to the startup node.
func (b *builder) authNode(
	state domain.State, class domain.FailureClass, sqlState string, native *bool, blocker string,
) domain.EvidenceID {
	attrs := map[domain.AttributeKey]domain.AttrValue{
		"postgres.sasl_mechanism": domain.StringAttr("SCRAM-SHA-256"),
	}
	if sqlState != "" {
		attrs[servicepostgres.AttrSQLState] = domain.StringAttr(sqlState)
	}
	if native != nil {
		attrs[servicepostgres.AttrErrorIsNative] = domain.BoolAttr(*native)
	}
	return b.add(nodeSpec{
		id: idAuth, subject: addr, layer: domain.LayerAuth,
		step: servicepostgres.StepAuthentication, state: state, class: class,
		attrs: attrs, parent: idStartup, blocker: blocker,
	})
}

// sessionNode adds a session node parented to whatever proved authentication.
func (b *builder) sessionNode(
	state domain.State, class domain.FailureClass, sqlState string, native *bool, parent string,
) domain.EvidenceID {
	attrs := map[domain.AttributeKey]domain.AttrValue{}
	if sqlState != "" {
		attrs[servicepostgres.AttrSQLState] = domain.StringAttr(sqlState)
	}
	if native != nil {
		attrs[servicepostgres.AttrErrorIsNative] = domain.BoolAttr(*native)
	}
	if state == domain.StatePass {
		attrs["postgres.transaction_status"] = domain.StringAttr("idle")
		attrs["postgres.in_hot_standby"] = domain.StringAttr("off")
		attrs["postgres.default_transaction_read_only"] = domain.StringAttr("off")
		attrs["postgres.server_version"] = domain.StringAttr("18.6 (Debian 18.6-1.pgdg13+2)")
	}
	return b.add(nodeSpec{
		id: idSession, subject: addr, layer: domain.LayerAuth,
		step: servicepostgres.StepSession, state: state, class: class,
		attrs: attrs, parent: parent,
	})
}

func boolPtr(v bool) *bool { return &v }

// rules is the wiring a caller would use, and the order is deliberately not the
// anchor order: the engine sorts, so wiring order must not reach the output.
func allFindings(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	out = append(out, Session(g)...)
	out = append(out, Authentication(g)...)
	out = append(out, Startup(g)...)
	out = append(out, TLS(g)...)
	out = append(out, SSLRequest(g)...)
	domain.SortFindings(out)
	return out
}

// tlsNode adds a handshake node beneath a negotiation, in the shape
// internal/adapter/postgres records: the generic step, L3, the same concrete
// subject as its parent, and the negotiation as its single parent.
func (b *builder) tlsNode(state domain.State, class domain.FailureClass) domain.EvidenceID {
	return b.add(nodeSpec{
		id: idTLS, subject: addr, layer: domain.LayerTLS,
		step: vocabulary.StepTLSHandshake, state: state, class: class, parent: idSSL,
	})
}

// inBandTLS is the common shape: a negotiation that succeeded, and a handshake
// beneath it with the given outcome.
func inBandTLS(t *testing.T, state domain.State, class domain.FailureClass) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
	b.tlsNode(state, class)
	return b.freeze()
}

// only asserts exactly one finding and returns it.
func only(t *testing.T, findings []domain.Finding) domain.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly 1: %v", len(findings), codesOf(findings))
	}
	return findings[0]
}

func codesOf(findings []domain.Finding) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Code())
	}
	return out
}
