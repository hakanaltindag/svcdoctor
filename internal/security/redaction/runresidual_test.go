package redaction

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 9.2B: the aggregate residual check, tested from inside the package.
//
// # Why this cannot be a black-box test
//
// verifyNoRunResidual is a **safety net**. Everything upstream of it — the
// pseudonym table, the per-report transformation, the class-derived execution
// message — is supposed to make it unnecessary, and when they all work it is
// unreachable from outside: no input to RedactRun produces a document with a
// residual in it.
//
// That is exactly the property that makes the net worth having and impossible to
// prove externally. The Phase 9.2B mutation run measured it: deleting the call
// entirely broke no black-box test, because with the transformation intact there
// was nothing left for it to catch.
//
// A net nobody can show working is a net nobody knows is there. So these hand a
// residual straight to the function, which is the only way to see it fail.

func TestTheAggregateResidualCheckCatchesASurvivingHost(t *testing.T) {
	values := runValues{
		hosts:     []string{"orders-db.prod.corp.internal"},
		targetIDs: []string{"orders-db"},
	}
	aliases := map[string]string{"orders-db": "target-001"}

	// A result whose execution message still carries the host. This is the shape
	// UX-B01 had before the message was replaced, reconstructed deliberately.
	out := residualAggregate(t, "target-001",
		"could not reach orders-db.prod.corp.internal during setup")

	err := verifyNoRunResidual(values, aliases, out)
	if err == nil {
		t.Fatal("a surviving hostname was certified as redacted.\n\n" +
			"This is the net. If it does not fire here it fires nowhere, because " +
			"every path that reaches it in production is a path the transformation " +
			"upstream already handled.")
	}
	if !errors.Is(err, ErrRedaction) {
		t.Errorf("the failure is %v, not an ErrRedaction", err)
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Errorf("the failure does not say what survived: %v", err)
	}
}

func TestTheAggregateResidualCheckCatchesEachCategory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values runValues
		want   string
	}{
		{
			"an IP address",
			runValues{ips: []string{"10.20.30.40"}, targetIDs: []string{"t"}},
			"IP address",
		},
		{
			"a logical identity",
			runValues{identities: []string{"svcdoctor_probe"}, targetIDs: []string{"t"}},
			"logical identity",
		},
		{
			"an evidence identifier",
			runValues{
				ids:       []domain.EvidenceID{"tcp.connect/10.20.30.40:5432"},
				targetIDs: []string{"t"},
			},
			"evidence identifier",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The message carries whichever value this case planted.
			var planted string
			switch {
			case len(tc.values.ips) > 0:
				planted = tc.values.ips[0]
			case len(tc.values.identities) > 0:
				planted = tc.values.identities[0]
			default:
				planted = string(tc.values.ids[0])
			}

			out := residualAggregate(t, "target-001", "setup failed at "+planted)

			err := verifyNoRunResidual(tc.values, map[string]string{"t": "target-001"}, out)
			if err == nil {
				t.Fatalf("a surviving %s was certified as redacted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the failure %q does not name a %s", err, tc.want)
			}
		})
	}
}

// TestTheAggregateResidualCheckCatchesAnUnredactedIdentifier is the target-ID
// half.
//
// Checked by exact equality rather than containment, deliberately: a target
// named `db` is a substring of half the words in a finding's detail, and a
// containment rule would make redaction fail closed on almost every real
// configuration. That is a worse failure than the one it prevents.
func TestTheAggregateResidualCheckCatchesAnUnredactedIdentifier(t *testing.T) {
	values := runValues{targetIDs: []string{"orders-db"}}
	aliases := map[string]string{"orders-db": "target-001"}

	// The result still addressed by the operator's own name.
	out := residualAggregate(t, "orders-db", "setup failed")

	err := verifyNoRunResidual(values, aliases, out)
	if err == nil {
		t.Fatal("a result still identified as \"orders-db\" was certified as redacted")
	}
	if !strings.Contains(err.Error(), "target identifier") {
		t.Errorf("the failure does not say an identifier survived: %v", err)
	}
}

// TestTheAggregateResidualCheckRequiresCompleteCollection is the U01 guard.
//
// Every absence assertion in this file rests on one premise: that collection saw
// every result. A collector which visits only the targets that produced a report
// cannot say anything about the ones that did not — and a check running on a
// partial set reports "clean" for exactly the results it never looked at.
//
// The Phase 9.2A leak was a collector doing precisely that. So the premise is
// asserted rather than assumed.
func TestTheAggregateResidualCheckRequiresCompleteCollection(t *testing.T) {
	// Two results, one collected: the shape a `if !result.HasReport() { continue }`
	// in the collector produces.
	out := residualAggregatePair(t)
	values := runValues{targetIDs: []string{"reporting"}}
	aliases := map[string]string{"reporting": "target-001", "failing": "target-002"}

	err := verifyNoRunResidual(values, aliases, out)
	if err == nil {
		t.Fatal("a partial collection was accepted.\n\n" +
			"UX-B01: collectRun skipped every result without a report, so a failed " +
			"target's identifiers were never collected and could not be looked for. " +
			"The check has to notice that it was handed less than the document holds.")
	}
	if !strings.Contains(err.Error(), "collection saw") {
		t.Errorf("the failure does not say collection was incomplete: %v", err)
	}
}

// TestTheAggregateResidualCheckPassesACleanDocument is the non-vacuity proof.
//
// Every test above asserts a failure. A verifyNoRunResidual that returned an
// error unconditionally would satisfy all of them and make every shareable
// report impossible to produce.
func TestTheAggregateResidualCheckPassesACleanDocument(t *testing.T) {
	values := runValues{
		hosts:     []string{"orders-db.prod.corp.internal"},
		ips:       []string{"10.20.30.40"},
		targetIDs: []string{"orders-db"},
	}
	aliases := map[string]string{"orders-db": "target-001"}

	out := residualAggregate(t, "target-001",
		"the reason is local detail and is withheld from a shareable report")

	if err := verifyNoRunResidual(values, aliases, out); err != nil {
		t.Fatalf("a correctly redacted aggregate was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------

func residualAggregate(t *testing.T, id, message string) domain.RunReport {
	t.Helper()

	result, err := domain.FailedTarget(id, domain.ServiceID("postgres"),
		domain.ExecutionErrorInternal, message)
	if err != nil {
		t.Fatalf("FailedTarget: %v", err)
	}
	return residualRunReport(t, result)
}

func residualAggregatePair(t *testing.T) domain.RunReport {
	t.Helper()

	first, err := domain.FailedTarget("target-001", domain.ServiceID("postgres"),
		domain.ExecutionErrorInternal, "withheld")
	if err != nil {
		t.Fatalf("FailedTarget: %v", err)
	}
	second, err := domain.FailedTarget("target-002", domain.ServiceID("redis"),
		domain.ExecutionErrorInternal, "withheld")
	if err != nil {
		t.Fatalf("FailedTarget: %v", err)
	}
	return residualRunReport(t, first, second)
}

func residualRunReport(t *testing.T, results ...domain.TargetResult) domain.RunReport {
	t.Helper()

	report, err := domain.NewRunReport(domain.RunReportInput{
		SvcdoctorVersion: "0.4.0",
		StartedAt:        time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		Duration:         time.Second,
		Concurrency:      4,
		OutputMode:       domain.OutputModeShareableRedacted,
		Targets:          results,
	})
	if err != nil {
		t.Fatalf("NewRunReport: %v", err)
	}
	return report
}
