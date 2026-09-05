package postgres

import (
	"fmt"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Fixtures for the multi-address shapes the admission-scope rule reads.
//
// The single-address `builder` above cannot express them: its identifiers and
// its subject are constants, because every other PostgreSQL rule anchors at one
// node and reads upward. This one is the first that is about a *set*, so the
// fixtures here mint one anchor and one startup node per address, exactly as
// `internal/app/postgres.go` does when a name resolves to several.

// admissionShape names one address's outcome at the startup stage.
type admissionShape uint8

const (
	shapeAdmitted admissionShape = iota
	shapeRefused
	shapeOtherFailure
	shapeTimedOut
	shapeBlocked
)

// The two multi-address scenarios the contract table needs by name.
var (
	admissionContrast = []admissionShape{shapeRefused, shapeAdmitted}
	admissionUniform  = []admissionShape{shapeRefused, shapeRefused}
)

// targetRef is the logical endpoint every fixture here is about. It is the
// anchor's subject and therefore the admission-scope finding's subject.
const targetRef = "db.internal:5432"

// twoAddressAdmission builds a requested-target anchor and one startup node per
// shape, in the graph shape the composition root produces.
//
// Each address gets its own address-shaped subject, its own TCP node parented to
// the anchor, and its own startup node parented to that. The anchor carries a
// *target* subject and the startup nodes carry *endpoint* subjects, which is the
// distinction that keeps a set-level claim from colliding with a per-address one.
func twoAddressAdmission(b *builder, shapes []admissionShape) {
	b.t.Helper()

	anchorSubject, err := domain.NewTargetSubject(targetRef)
	if err != nil {
		b.t.Fatalf("NewTargetSubject(%q): %v", targetRef, err)
	}
	anchor, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           domain.EvidenceID("target.requested/" + targetRef),
		Subject:      anchorSubject,
		Layer:        domain.LayerInput,
		Step:         vocabulary.StepTargetRequested,
		State:        domain.StatePass,
		FailureClass: domain.FailureNone,
		StartedAt:    b.at,
		Elapsed:      domain.Unmeasured(),
	})
	if err != nil {
		b.t.Fatalf("anchor evidence: %v", err)
	}
	if err := b.b.AddEvidence(anchor); err != nil {
		b.t.Fatalf("adding anchor: %v", err)
	}

	for i, shape := range shapes {
		address := fmt.Sprintf("10.0.0.%d:5432", i+1)
		tcpID := fmt.Sprintf("tcp.connect/%s/10.0.0.%d", targetRef, i+1)
		startupID := fmt.Sprintf("postgres.startup/%s/10.0.0.%d", targetRef, i+1)

		b.add(nodeSpec{
			id: tcpID, subject: address, layer: domain.LayerTCP,
			step: vocabulary.StepTCPConnect, state: domain.StatePass,
			class: domain.FailureNone, parent: string(anchor.ID()),
		})

		spec := nodeSpec{
			id: startupID, subject: address, layer: domain.LayerProtocol,
			step: servicepostgres.StepStartup, parent: tcpID,
			attrs: map[domain.AttributeKey]domain.AttrValue{
				"postgres.protocol_version": domain.StringAttr("3.0"),
				"postgres.role":             domain.IdentityAttr("tenantrole"),
				"postgres.database":         domain.IdentityAttr("tenantcatalog"),
			},
		}
		switch shape {
		case shapeAdmitted:
			spec.state, spec.class = domain.StatePass, domain.FailureNone
			spec.attrs[servicepostgres.AttrAuthMethod] = domain.StringAttr("sasl")
		case shapeRefused:
			spec.state, spec.class = domain.StateFail, domain.FailureAuthzNotPermitted
			spec.attrs[servicepostgres.AttrSQLState] = domain.StringAttr("28000")
			spec.attrs[servicepostgres.AttrErrorIsNative] = domain.BoolAttr(true)
		case shapeOtherFailure:
			spec.state, spec.class = domain.StateFail, domain.FailureProtocolUnexpectedResponse
			spec.attrs[servicepostgres.AttrSQLState] = domain.StringAttr("08P01")
			spec.attrs[servicepostgres.AttrErrorIsNative] = domain.BoolAttr(false)
		case shapeTimedOut:
			spec.state, spec.class = domain.StateUnknown, domain.FailureExecLocalTimeout
		case shapeBlocked:
			spec.state, spec.class = domain.StateSkipped, domain.FailureExecSkippedPrerequisiteFailed
			spec.blocker = tcpID
		}
		b.add(spec)
	}
}

// admissionGraph is the whole fixture in one call.
func admissionGraph(t *testing.T, shapes ...admissionShape) domain.Graph {
	t.Helper()
	b := newBuilder(t)
	twoAddressAdmission(b, shapes)
	return b.freeze()
}

// admissionFindings runs only the admission-scope rule, for the tests that are
// about it alone.
func admissionFindings(g domain.Graph, incomplete bool) []domain.Finding {
	return AdmissionScope(diagnosis.RuleContext{Graph: g, Incomplete: incomplete})
}
