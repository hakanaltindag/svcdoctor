package app

import (
	"context"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The report's `tlsVerificationDisabled` describes what the run did, not what it
// was configured with.
//
// ADR 0058 section 14.3 recorded the defect these pin: `DiagnosePostgres` passed
// `TLSOptions.InsecureSkipVerify` straight through, so a plaintext run handed
// that option reported that verification was disabled on a handshake it never
// attempted. `DiagnoseKafka` already gated the same boolean on a plan existing.
// ADR 0060 closed the gap by making PostgreSQL do what Kafka does.
//
// # Why these live at internal/app and not only at internal/cli
//
// The CLI now refuses `--tls disable --tls-insecure` outright, which makes the
// combination unreachable from the command line — so a test only at that layer
// would pass for the wrong reason and keep passing if this gate were deleted.
// internal/app is its own boundary and a truthful report is its contract, not a
// consequence of who called it.

// TestAPlaintextPostgresRunClaimsNoTLSVerificationState is ADR 0058 section
// 14.3, reproduced and then closed.
//
// The option is set and the plan is disabled — precisely the combination the CLI
// refuses — and the report must still describe the run that happened.
func TestAPlaintextPostgresRunClaimsNoTLSVerificationState(t *testing.T) {
	report := plaintextRun(t, postgres.TLSOptions{InsecureSkipVerify: true})

	if report.Security().TLSVerificationDisabled() {
		t.Error("a run that planned no TLS reports tlsVerificationDisabled: true; " +
			"that is a TLS fact about a handshake that never existed (ADR 0060 section 5)")
	}

	// The other half of the claim, and the reason `false` is not a second lie:
	// there is no handshake node either, so the report says "no TLS happened"
	// rather than "TLS happened and was verified". The two facts together are
	// what make the three-way distinction without a schema change.
	for _, node := range report.Graph().Nodes() {
		if node.Step() == vocabulary.StepTLSHandshake {
			t.Fatalf("a plaintext run recorded a %s node", node.Step())
		}
	}
}

// TestAPlaintextPostgresRunWithoutTheOptionIsUnchanged is the control.
//
// Both plaintext runs must report the same thing, because both did the same
// thing. If only the first passed, the gate would be reading the option rather
// than the plan.
func TestAPlaintextPostgresRunWithoutTheOptionIsUnchanged(t *testing.T) {
	if plaintextRun(t, postgres.TLSOptions{}).Security().TLSVerificationDisabled() {
		t.Error("tlsVerificationDisabled = true on an ordinary plaintext run")
	}
}

// TestARequiredTLSPostgresRunStillReportsDisabledVerification is the clause the
// gate must not over-reach.
//
// Narrowing a security signal is the dangerous direction of this change: a gate
// that suppressed the fact on a run that *did* disable verification would hide
// exactly what ADR 0060 set out to surface. The plan is `require` here, so the
// boolean must survive — even though the TCP attempt fails and no handshake is
// ever reached, because the run planned one and planned it unverified.
func TestARequiredTLSPostgresRunStillReportsDisabledVerification(t *testing.T) {
	report := unreachableRun(t, postgres.TLSRequired,
		postgres.TLSOptions{InsecureSkipVerify: true})

	if !report.Security().TLSVerificationDisabled() {
		t.Error("tlsVerificationDisabled = false on a run that asked for TLS " +
			"with verification off; the gate is suppressing a real security fact")
	}
}

// TestPostgresAndKafkaGateTheSameBooleanTheSameWay is the anti-drift assertion.
//
// The defect ADR 0060 closed was two composition roots deciding one thing
// differently, so the fix is only durable if a divergence fails. Both services
// are driven with a plan that performs no handshake and an option that asks for
// no verification, and both must answer the same.
func TestPostgresAndKafkaGateTheSameBooleanTheSameWay(t *testing.T) {
	pg := plaintextRun(t, postgres.TLSOptions{InsecureSkipVerify: true})

	kafka, err := DiagnoseKafka(context.Background(), KafkaParams{
		Host: "10.255.255.1", Port: 9092, Mechanism: "PLAIN",
		Resolver: stubResolver{}, Dialer: refusingDialer{}, TLS: nil,
		StepTimeout: 150 * time.Millisecond,
		Vantage:     vantage(t), Version: "0.0.0-test",
	})
	if err != nil {
		t.Fatalf("DiagnoseKafka: %v", err)
	}

	if got, want := pg.Security().TLSVerificationDisabled(),
		kafka.Report().Security().TLSVerificationDisabled(); got != want {
		t.Errorf("postgres reports %v and kafka reports %v for the same situation "+
			"— a plan with no handshake; the two composition roots have drifted "+
			"apart again (ADR 0060 section 5)", got, want)
	}
}

// TestKafkaRequiredTLSStillReportsDisabledVerification is Kafka's half of the
// clause above, so the two services are pinned symmetrically rather than one
// being asserted only against the other.
func TestKafkaRequiredTLSStillReportsDisabledVerification(t *testing.T) {
	result, err := DiagnoseKafka(context.Background(), KafkaParams{
		Host: "10.255.255.1", Port: 9093, Mechanism: "PLAIN",
		Resolver: stubResolver{},
		Dialer:   refusingDialer{},
		//nolint:gosec // G402: this is the fixture for the security fact being asserted.
		TLS:         &transport.TLSOptions{InsecureSkipVerify: true},
		StepTimeout: 150 * time.Millisecond,
		Vantage:     vantage(t), Version: "0.0.0-test",
	})
	if err != nil {
		t.Fatalf("DiagnoseKafka: %v", err)
	}
	if !result.Report().Security().TLSVerificationDisabled() {
		t.Error("tlsVerificationDisabled = false on a Kafka run that asked for TLS " +
			"with verification off")
	}
}

// plaintextRun performs a PostgreSQL run with the TLS plan disabled.
//
// The endpoint is unreachable on purpose. What is under test is the report's
// security metadata, which is assembled from the run's parameters whatever the
// transport did, so the cheapest possible run is the clearest fixture.
func plaintextRun(t *testing.T, options postgres.TLSOptions) domain.Report {
	t.Helper()
	return unreachableRun(t, postgres.TLSDisabled, options)
}

func unreachableRun(
	t *testing.T, plan postgres.TLSPlan, options postgres.TLSOptions,
) domain.Report {
	t.Helper()
	result, err := DiagnosePostgres(context.Background(), PostgresParams{
		Host: "10.255.255.1", Port: 5432, Role: "svcdoctor",
		Resolver:    stubResolver{},
		Dialer:      refusingDialer{},
		TLS:         plan,
		TLSOptions:  options,
		StepTimeout: 150 * time.Millisecond,
		Vantage:     vantage(t), Version: "0.0.0-test",
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	return result.Report()
}
