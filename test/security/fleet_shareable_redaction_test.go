package security_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	renderjson "github.com/hakanaltindag/svcdoctor/internal/render/json"
	renderterminal "github.com/hakanaltindag/svcdoctor/internal/render/terminal"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 9.2B, UX-B01: the aggregate shareable report fails closed.
//
// # What Phase 9.2A measured
//
// `svcdoctor run --config … --shareable` pseudonymized a failed target's
// identifier to `target-001` and then printed, in the same object:
//
//	"message": "invalid run input: unsupported host: fe80::1%en0 carries an …"
//	"message": "loading the trust source: stat /etc/svcdoctor/pki/corp-root-ca.pem: …"
//
// A raw address and the on-disk location of an organisation's private CA, in the
// one document whose entire purpose is that those have been removed. The
// document *looked* redacted, because the parts with a checker were.
//
// Two things were missing and both are structural. collectRun skipped every
// result without a report, so a failed target's identifiers were never collected
// and could not be looked for. And RedactRun ran no residual verification at
// all — verifyNoResidual lives inside redactWith and therefore only ever saw an
// embedded report, never the aggregate's own strings.
//
// # What these tests hold
//
// The invariant is not "those two messages do not appear". It is:
//
//	A shareable aggregate applies the same fail-closed residual contract that
//	shareable single-target output has always applied.
//
// So the corpus below is adversarial rather than illustrative: every message
// shape a local failure could plausibly carry, proved absent from all three
// shareable surfaces — the canonical RunReport, its JSON, and the terminal.

// sensitiveMessages is the UX-B01 corpus.
//
// Each entry is a message a local execution failure could carry, and each
// contains at least one thing a shareable report must not disclose. They are
// deliberately not the two Phase 9.2A found: those two are now unreachable
// (Phase 9.2B's preflight refuses both before execution), and a corpus made of
// the cases already fixed proves only that they are fixed.
var sensitiveMessages = []struct {
	name    string
	message string
	// probes are the substrings that must not survive. Every one is a value a
	// reader could act on: an address to scan, a path to look for, a name to
	// resolve.
	probes []string
}{
	{
		"IPv4 address",
		"dialling 10.20.30.40:5432 failed before the journey began",
		[]string{"10.20.30.40"},
	},
	{
		"IPv6 address",
		"dialling [2001:db8::4a]:5432 failed before the journey began",
		[]string{"2001:db8::4a"},
	},
	{
		"zoned IPv6 address",
		"unsupported host: fe80::1%en0 carries an IPv6 zone identifier",
		[]string{"fe80::1%en0", "fe80::1"},
	},
	{
		"hostname",
		"resolving orders-db.prod.corp.internal produced no usable address",
		[]string{"orders-db.prod.corp.internal"},
	},
	{
		"logical identity",
		"the role svcdoctor_probe could not be used for this target",
		[]string{"svcdoctor_probe"},
	},
	{
		"Unix absolute path",
		"loading the trust source: stat /etc/svcdoctor/pki/corp-root-ca.pem: " +
			"no such file or directory",
		[]string{"/etc/svcdoctor/pki/corp-root-ca.pem", "corp-root-ca"},
	},
	{
		"relative path",
		"loading the trust source: open ./secrets/corp-ca.pem: permission denied",
		[]string{"./secrets/corp-ca.pem", "secrets/corp-ca.pem"},
	},
	{
		"Windows path",
		`loading the trust source: open C:\ProgramData\svcdoctor\corp-ca.pem: ` +
			"The system cannot find the file specified.",
		[]string{`C:\ProgramData\svcdoctor\corp-ca.pem`, "ProgramData"},
	},
	{
		"path with spaces",
		"loading the trust source: open /Users/ops lead/pki/corp ca.pem: no such file",
		[]string{"/Users/ops lead/pki/corp ca.pem", "ops lead"},
	},
	{
		"quoted path",
		`loading the trust source: open "/etc/pki/corp-ca.pem": no such file`,
		[]string{"/etc/pki/corp-ca.pem"},
	},
	{
		"escaped path",
		`loading the trust source: open /etc/pki/corp\ ca.pem: no such file`,
		[]string{`/etc/pki/corp\ ca.pem`},
	},
	{
		"credential file path",
		"the credential named by a file reference could not be resolved: " +
			"/run/secrets/orders-db-password: no such file",
		[]string{"/run/secrets/orders-db-password"},
	},
	{
		"environment variable name",
		"the credential named by a env reference could not be resolved: " +
			"ORDERS_DB_PROD_PASSWORD is not set",
		[]string{"ORDERS_DB_PROD_PASSWORD"},
	},
	{
		"several sensitive values in one message",
		"target orders-db.prod.corp.internal at 10.20.30.40:5432 could not load " +
			"/etc/svcdoctor/pki/corp-root-ca.pem for role svcdoctor_probe",
		[]string{
			"orders-db.prod.corp.internal", "10.20.30.40",
			"/etc/svcdoctor/pki/corp-root-ca.pem", "svcdoctor_probe",
		},
	},
	{
		"a Go type name and a wrapped runtime error",
		"postgres runner received redis.Config, which is not a PostgreSQL configuration",
		[]string{"redis.Config"},
	},
}

// TestUX12NoSensitiveValueSurvivesAggregateRedaction is the corpus, on all three
// shareable surfaces.
//
// # Why all three and not just the canonical document
//
// ADR 0018's rule is that redaction transforms domain values *before*
// serialization, so a correct transformation is necessarily correct in every
// projection of it. Checking all three is how that stops being an argument: a
// renderer that reached around the domain value — reading the LOCAL_FULL result
// it was handed rather than the redacted one — would pass a canonical-only test
// and fail here.
func TestUX12NoSensitiveValueSurvivesAggregateRedaction(t *testing.T) {
	for _, tc := range sensitiveMessages {
		t.Run(tc.name, func(t *testing.T) {
			local := shareableCorpusRun(t, tc.message)

			redacted, err := redaction.RedactRun(local)
			if err != nil {
				t.Fatalf("RedactRun: %v", err)
			}
			if redacted.OutputMode() != domain.OutputModeShareableRedacted {
				t.Fatalf("output mode is %s, want SHAREABLE_REDACTED", redacted.OutputMode())
			}

			for surface, text := range shareableSurfaces(t, redacted) {
				for _, probe := range tc.probes {
					if strings.Contains(text, probe) {
						t.Errorf("the shareable %s discloses %q.\n\n"+
							"UX-B01. A shareable aggregate carries no host, address, "+
							"identity or local filesystem path. An execution message is "+
							"replaced by a class-derived sentence rather than filtered, "+
							"because filtering prose fails open on the first shape nobody "+
							"anticipated (ADR 0077 §2.6).\n\nsurface:\n%s", surface, probe, text)
					}
				}
			}
		})
	}
}

// TestUX12TheLocalReportKeepsWhatTheOperatorNeeds is the other half.
//
// Redaction that removed the locator from LOCAL_FULL too would pass every
// assertion above and make the product unusable: the operator fixing a missing
// CA file has to be told which file. ADR 0049 §3 is explicit about this, and
// ADR 0077 §2.6 keeps the split — locator-bearing locally, locator-free when
// shared.
//
// Without this test the corpus above is satisfiable by deleting the message.
func TestUX12TheLocalReportKeepsWhatTheOperatorNeeds(t *testing.T) {
	for _, tc := range sensitiveMessages {
		t.Run(tc.name, func(t *testing.T) {
			local := shareableCorpusRun(t, tc.message)

			var found bool
			for _, result := range local.Targets() {
				if result.ExecutionState() == domain.ExecutionStateExecutionFailed {
					found = true
					if result.ExecutionErrorMessage() != tc.message {
						t.Errorf("the LOCAL_FULL message is %q, want the original %q.\n\n"+
							"Redaction must not reach back into its input, and the local "+
							"report is what the operator fixes the problem from.",
							result.ExecutionErrorMessage(), tc.message)
					}
				}
			}
			if !found {
				t.Fatal("no execution failure was built; this guard would pass vacuously")
			}
		})
	}
}

// TestUX12EveryExecutionStateIsCoveredByAggregateRedaction walks the four states.
//
// A mixed run is the case that matters, and it is the one Phase 9.2A used: some
// targets have reports and some do not. A collection pass that visits only the
// first kind cannot see the second, which is precisely how the leak survived.
func TestUX12EveryExecutionStateIsCoveredByAggregateRedaction(t *testing.T) {
	local := corpusAggregate(t, domain.StoppedReasonCancelled,
		corpusCompleted(t, "orders-db.prod.corp.internal", "postgres",
			"orders-db.prod.corp.internal:5432"),
		corpusCancelled(t, "events.prod.corp.internal", "kafka",
			"events.prod.corp.internal:9093"),
		corpusNotStarted(t, "cache.prod.corp.internal", "redis"),
		corpusFailed(t, "queue.prod.corp.internal", "rabbitmq",
			domain.ExecutionErrorInternal,
			"loading the trust source: stat /etc/svcdoctor/pki/corp-root-ca.pem: no such file"),
	)

	redacted, err := redaction.RedactRun(local)
	if err != nil {
		t.Fatalf("RedactRun: %v", err)
	}

	if got := len(redacted.Targets()); got != 4 {
		t.Fatalf("%d results survived redaction, want 4", got)
	}

	states := map[domain.ExecutionState]bool{}
	for _, result := range redacted.Targets() {
		states[result.ExecutionState()] = true

		if !strings.HasPrefix(result.TargetID(), "target-") {
			t.Errorf("a %s result is still identified as %q; every result is "+
				"pseudonymized, including the ones that produced no report",
				result.ExecutionState(), result.TargetID())
		}
	}
	for _, want := range []domain.ExecutionState{
		domain.ExecutionStateCompleted,
		domain.ExecutionStateCancelled,
		domain.ExecutionStateNotStarted,
		domain.ExecutionStateExecutionFailed,
	} {
		if !states[want] {
			t.Errorf("no %s result reached the redacted aggregate", want)
		}
	}

	for surface, text := range shareableSurfaces(t, redacted) {
		for _, probe := range []string{
			"orders-db.prod.corp.internal", "events.prod.corp.internal",
			"cache.prod.corp.internal", "queue.prod.corp.internal",
			"/etc/svcdoctor/pki/corp-root-ca.pem",
		} {
			if strings.Contains(text, probe) {
				t.Errorf("the shareable %s discloses %q from a mixed run.\n\n%s",
					surface, probe, text)
			}
		}
	}
}

// TestUX12ACrossTargetHostInAnExecutionMessageIsCaught is the case containment
// exists for.
//
// Target A produces a report naming a host. Target B fails to execute and its
// message happens to name the *same* host. A per-target check would clear both:
// A's host is replaced inside A's report, and B has no report to check. Only a
// run-level check that looks for A's collected values across the whole finished
// document catches it.
func TestUX12ACrossTargetHostInAnExecutionMessageIsCaught(t *testing.T) {
	const shared = "orders-db.prod.corp.internal"

	local := corpusAggregate(t, domain.StoppedReasonNone,
		corpusCompleted(t, "reporting-target", "postgres", shared+":5432"),
		corpusFailed(t, "failing-target", "postgres", domain.ExecutionErrorInternal,
			"could not reach "+shared+" during setup"),
	)

	redacted, err := redaction.RedactRun(local)
	if err != nil {
		t.Fatalf("RedactRun: %v", err)
	}

	for surface, text := range shareableSurfaces(t, redacted) {
		if strings.Contains(text, shared) {
			t.Errorf("a host collected from one target's report survived inside "+
				"another target's execution message, in the shareable %s.\n\n%s",
				surface, text)
		}
	}
}

// TestUX12AggregateRedactionFailsClosed is the fail-closed proof.
//
// A residual value must stop the document being produced, not be tolerated in
// it. The README's promise is exactly this — "svcdoctor emits no report at all
// and exits 3 rather than writing a partially redacted artifact" — and Phase
// 9.2A found the aggregate had no mechanism that could keep it.
//
// The residual is planted the only way it can be from outside the package: a
// target identifier so short that the pseudonym check cannot clear it. That
// exercises the same code path a genuine survivor would.
func TestUX12AggregateRedactionFailsClosed(t *testing.T) {
	// A host that is a substring of its own pseudonym namespace. "host" appears
	// in "host-001", so the containment check must refuse to certify the
	// document. Fails closed, exactly as the single-report check does for a host
	// literally named "0".
	local := corpusAggregate(t, domain.StoppedReasonNone,
		corpusCompleted(t, "t1", "postgres", "host:5432"),
	)

	_, err := redaction.RedactRun(local)
	if err == nil {
		t.Fatal("RedactRun certified a document whose residual check cannot clear.\n\n" +
			"Redaction fails closed: when the check cannot confirm a covered value " +
			"was replaced, no report is emitted. A shareable artifact that might " +
			"carry an identity is worse than no artifact.")
	}
	if !errors.Is(err, redaction.ErrRedaction) {
		t.Errorf("RedactRun returned %v, want an ErrRedaction", err)
	}
}

// TestUX12TheAggregateGuardsCanFail is the non-vacuity proof for this file.
//
// Every assertion above is "this string is absent". A helper that silently
// produced an empty surface, or a corpus that built no failed target, would make
// all of them pass forever and read exactly like a clean build. Each sub-test
// checks that the machinery can still find something it is supposed to find.
func TestUX12TheAggregateGuardsCanFail(t *testing.T) {
	t.Run("the corpus is not empty", func(t *testing.T) {
		if len(sensitiveMessages) < 12 {
			t.Fatalf("the corpus holds %d messages; it is meant to be adversarial",
				len(sensitiveMessages))
		}
		for _, tc := range sensitiveMessages {
			if len(tc.probes) == 0 {
				t.Errorf("%q declares no probe, so it asserts nothing", tc.name)
			}
			for _, probe := range tc.probes {
				if !strings.Contains(tc.message, probe) {
					t.Errorf("%q probes for %q, which its own message does not contain; "+
						"the case would pass without redaction doing anything",
						tc.name, probe)
				}
			}
		}
	})

	t.Run("the surfaces are non-empty and really carry the values", func(t *testing.T) {
		local := corpusAggregate(t, domain.StoppedReasonNone,
			corpusCompleted(t, "orders-db", "postgres", "orders-db.prod.corp.internal:5432"),
			corpusFailed(t, "queue", "rabbitmq", domain.ExecutionErrorInternal,
				"loading the trust source: stat /etc/svcdoctor/pki/corp-root-ca.pem: no such file"),
		)

		for surface, text := range shareableSurfaces(t, local) {
			if strings.TrimSpace(text) == "" {
				t.Fatalf("the %s surface is empty; every absence assertion using it "+
					"would pass vacuously", surface)
			}
			for _, probe := range []string{
				"orders-db.prod.corp.internal", "/etc/svcdoctor/pki/corp-root-ca.pem",
			} {
				if !strings.Contains(text, probe) {
					t.Errorf("the LOCAL_FULL %s does not contain %q, so proving its "+
						"absence after redaction proves nothing", surface, probe)
				}
			}
		}
	})

	t.Run("a redacted aggregate still says something", func(t *testing.T) {
		local := corpusAggregate(t, domain.StoppedReasonNone,
			corpusFailed(t, "queue", "rabbitmq", domain.ExecutionErrorCredentialResolution,
				"the credential named by a env reference could not be resolved: "+
					"ORDERS_DB_PROD_PASSWORD is not set"),
		)
		redacted, err := redaction.RedactRun(local)
		if err != nil {
			t.Fatalf("RedactRun: %v", err)
		}

		result := redacted.Targets()[0]
		if result.ExecutionErrorClass() != domain.ExecutionErrorCredentialResolution {
			t.Errorf("the failure class became %s; the class is a closed vocabulary and "+
				"survives redaction — it is what tells a reader which half of the "+
				"configuration to look at", result.ExecutionErrorClass())
		}
		if strings.TrimSpace(result.ExecutionErrorMessage()) == "" {
			t.Error("the shareable execution message is empty.\n\n" +
				"Redaction replaces the message; it does not delete it. A reader has to " +
				"be told that something was withheld, or the absence reads as an absence " +
				"of information rather than a deliberate one.")
		}
	})

	t.Run("each class produces its own withheld sentence", func(t *testing.T) {
		// Pinned exactly rather than by a "withheld" substring. A substring check
		// is satisfiable by the single word, which is how the Phase 9.2B mutation
		// run first passed a message that had thrown away everything useful.
		//
		// Each reads as a reason clause rather than a sentence, because the
		// terminal renderer supplies the subject — it prints "svcdoctor could not
		// run this target · <message>" — and a second subject says it twice.
		for _, tc := range []struct {
			class domain.ExecutionErrorClass
			want  string
		}{
			{
				domain.ExecutionErrorCredentialResolution,
				"the credential reference this target names could not be resolved; " +
					"the reference is local detail and is withheld from a shareable report",
			},
			{
				domain.ExecutionErrorInternal,
				"the reason is local detail and is withheld from a shareable report",
			},
		} {
			local := corpusAggregate(t, domain.StoppedReasonNone,
				corpusFailed(t, "queue", "rabbitmq", tc.class,
					"loading /etc/svcdoctor/pki/corp-root-ca.pem failed"))

			redacted, err := redaction.RedactRun(local)
			if err != nil {
				t.Fatalf("RedactRun: %v", err)
			}
			if got := redacted.Targets()[0].ExecutionErrorMessage(); got != tc.want {
				t.Errorf("the %s message is\n  %q\nwant\n  %q", tc.class, got, tc.want)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// shareableSurfaces renders an aggregate every way an operator can share it.
func shareableSurfaces(t *testing.T, report domain.RunReport) map[string]string {
	t.Helper()

	canonical, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshalling the aggregate: %v", err)
	}

	var jsonOut, terminalOut strings.Builder
	if err := renderjson.WriteRun(&jsonOut, report); err != nil {
		t.Fatalf("WriteRun (json): %v", err)
	}
	if err := renderterminal.WriteRun(&terminalOut, report); err != nil {
		t.Fatalf("WriteRun (terminal): %v", err)
	}

	return map[string]string{
		"canonical RunReport": string(canonical),
		"JSON output":         jsonOut.String(),
		"terminal output":     terminalOut.String(),
	}
}

// shareableCorpusRun builds a mixed run whose second target failed with message.
//
// Mixed on purpose: one target with a report and one without is the shape that
// exposed UX-B01, and a single-target aggregate would not exercise the
// cross-target containment the run-level check exists for.
func shareableCorpusRun(t *testing.T, message string) domain.RunReport {
	t.Helper()
	return corpusAggregate(t, domain.StoppedReasonNone,
		corpusCompleted(t, "reporting-target", "postgres", "measured.corp.internal:5432"),
		corpusFailed(t, "failing-target", "postgres", domain.ExecutionErrorInternal, message),
	)
}

func corpusAggregate(
	t *testing.T, stopped domain.StoppedReason, results ...domain.TargetResult,
) domain.RunReport {
	t.Helper()
	report, err := domain.NewRunReport(domain.RunReportInput{
		SvcdoctorVersion: "0.4.0",
		StartedAt:        time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		Duration:         1500 * time.Millisecond,
		Concurrency:      4,
		OutputMode:       domain.OutputModeLocalFull,
		StoppedReason:    stopped,
		Targets:          results,
	})
	if err != nil {
		t.Fatalf("NewRunReport: %v", err)
	}
	return report
}

func corpusCompleted(t *testing.T, id, service, endpoint string) domain.TargetResult {
	t.Helper()
	result, err := domain.CompletedTarget(id, domain.ServiceID(service),
		corpusReport(t, endpoint), false)
	if err != nil {
		t.Fatalf("CompletedTarget: %v", err)
	}
	return result
}

func corpusCancelled(t *testing.T, id, service, endpoint string) domain.TargetResult {
	t.Helper()
	result, err := domain.CancelledTarget(id, domain.ServiceID(service),
		corpusReport(t, endpoint), true)
	if err != nil {
		t.Fatalf("CancelledTarget: %v", err)
	}
	return result
}

func corpusNotStarted(t *testing.T, id, service string) domain.TargetResult {
	t.Helper()
	result, err := domain.NotStartedTarget(id, domain.ServiceID(service))
	if err != nil {
		t.Fatalf("NotStartedTarget: %v", err)
	}
	return result
}

func corpusFailed(
	t *testing.T, id, service string, class domain.ExecutionErrorClass, message string,
) domain.TargetResult {
	t.Helper()
	result, err := domain.FailedTarget(id, domain.ServiceID(service), class, message)
	if err != nil {
		t.Fatalf("FailedTarget: %v", err)
	}
	return result
}

// corpusReport is the smallest report that carries an endpoint identity.
func corpusReport(t *testing.T, endpoint string) domain.Report {
	t.Helper()

	subject, err := domain.NewTargetSubject(endpoint)
	if err != nil {
		t.Fatalf("NewTargetSubject: %v", err)
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:        domain.EvidenceID(string(vocabulary.StepTCPConnect) + "/" + endpoint),
		Subject:   subject,
		Layer:     domain.LayerTCP,
		Step:      vocabulary.StepTCPConnect,
		State:     domain.StatePass,
		StartedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		Elapsed:   domain.Measured(12 * time.Millisecond),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	target, err := domain.NewTarget(endpoint)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	runMeta, err := domain.NewRunMetadata("0.4.0",
		time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), 12*time.Millisecond,
		domain.ServiceID("postgres"))
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	vantage, err := domain.NewLocalVantage("runner.corp.internal")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run:      runMeta,
		Target:   target,
		Vantage:  vantage,
		Graph:    graph,
		Security: reportSecurity,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

// TestUX12RedactRunActuallyCallsTheResidualCheck closes the last gap.
//
// # Why a structural test and not a behavioural one
//
// The in-package tests in internal/security/redaction prove that
// verifyNoRunResidual works. None of them proves that RedactRun *calls* it — and
// the Phase 9.2B mutation run measured exactly that hole: deleting the call
// broke nothing, because with the transformation upstream intact there is no
// input that would have made the net fire anyway.
//
// That is the permanent shape of this problem rather than a gap in the corpus. A
// safety net's whole purpose is to catch what the mechanism above it missed, so
// while the mechanism is correct the net is unreachable from outside, and its
// removal is invisible to every black-box test that could be written.
//
// So the call is asserted structurally, by reading the function. Same device as
// this package's import guards, for the same reason: some properties are about
// the shape of the code rather than about any value it produces.
//
// # Why it lives here and not beside the code it reads
//
// internal/security/redaction may not import `os` — a depguard rule enforces
// that redaction "must not read files, the environment, or process state". A
// test in that package inherits the restriction, and weakening a real
// architectural boundary to make a test convenient is the wrong trade. This
// package already reads source for its import guards.
func TestUX12RedactRunActuallyCallsTheResidualCheck(t *testing.T) {
	const (
		function = "func RedactRun("
		call     = "verifyNoRunResidual("
	)

	source := readSourceFile(t, "internal/security/redaction/run.go")

	start := strings.Index(source, function)
	if start < 0 {
		t.Fatalf("%s was not found; this guard would pass vacuously", function)
	}
	body := source[start:]
	if end := strings.Index(body[1:], "\nfunc "); end >= 0 {
		body = body[:end+1]
	}

	if !strings.Contains(body, call) {
		t.Errorf("RedactRun does not call %s.\n\n"+
			"Redaction fails closed: after the transformation, the finished aggregate "+
			"is re-read and refused if any value known to be identifying is still in "+
			"it. Without this call the aggregate has no net at all — which is the "+
			"state Phase 9.2A found it in, and the state in which UX-B01 was "+
			"invisible.", call)
	}
	if !strings.Contains(body, "if err := "+call) {
		t.Error("RedactRun calls the residual check without acting on its result")
	}
}

// TestUX12TheStructuralCallGuardCanFail proves the reader is not vacuous.
func TestUX12TheStructuralCallGuardCanFail(t *testing.T) {
	source := readSourceFile(t, "internal/security/redaction/run.go")

	for _, present := range []string{
		"func RedactRun(", "verifyNoRunResidual(", "func collectRun(",
	} {
		if !strings.Contains(source, present) {
			t.Errorf("run.go does not contain %q, so reading it proves nothing", present)
		}
	}
	if strings.Contains(source, "func ThisFunctionDoesNotExist(") {
		t.Error("the reader found a function that is not there")
	}
}

// readSourceFile reads one production file, relative to the repository root.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()

	contents, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", name)))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(contents)
}
