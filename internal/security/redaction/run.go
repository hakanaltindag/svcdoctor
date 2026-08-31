package redaction

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// RedactRun returns a shareable form of an aggregate run report.
//
// The input is not modified and remains LOCAL_FULL. Every embedded report is
// rebuilt through the ordinary domain constructors, so each satisfies every
// report invariant and each summary is re-derived rather than copied. The
// aggregate's own summary is re-derived too.
//
// # One pseudonym table for the whole run
//
// ADR 0074 section 8.1. Redaction's principle is *preserve correlation, remove
// identity*, and across a run that means a host appearing in two targets gets
// **one** pseudonym.
//
// Redacting each target independently was rejected for a reason stronger than
// tidiness: it would give one real host two different pseudonyms in one
// document, and — worse — could give two different real hosts the same pseudonym
// in different targets. For a document whose purpose is to be shared and
// reasoned about, inventing a correlation is worse than preserving one.
//
// The cost is stated rather than hidden: a redacted aggregate does reveal that
// two targets share infrastructure. That is the same class of structural
// information a single redacted Kafka report already reveals about a bootstrap
// and its advertised brokers, and it is what makes the document useful.
//
// # Target identifiers are pseudonymized
//
// `orders-db-prod-eu-west-1` is operator-chosen text that can carry deployment
// structure, tenancy and geography (ADR 0074 section 8.2). Under
// SHAREABLE_REDACTED it becomes `target-001`, numbered in **declared
// configuration order** — never in sorted order, which would encode the lexical
// ordering of the real names into the pseudonyms and leak exactly what this is
// removing.
//
// Identifiers are deliberately **not** added to the prose replacement list. A
// target named `orders` would otherwise rewrite the word "orders" wherever it
// appeared in a finding's detail, mangling report text to hide a value that is
// not in report text.
//
// Idempotent: an aggregate that is already SHAREABLE_REDACTED is returned
// unchanged, so pseudonyms are never pseudonymized again.
func RedactRun(report domain.RunReport) (domain.RunReport, error) {
	if report.IsZero() {
		return domain.RunReport{}, fmt.Errorf("%w: cannot redact the zero RunReport", ErrRedaction)
	}
	if report.OutputMode() == domain.OutputModeShareableRedacted {
		return report, nil
	}

	results := report.Targets()
	t := newTable(collectRun(results))
	aliases := targetAliases(results)

	redacted := make([]domain.TargetResult, 0, len(results))
	for _, result := range results {
		// Assignments are shared; counters are not. Each embedded report's
		// security metadata must describe its own transformation rather than
		// everything the run had replaced so far.
		t.resetUsage()

		next, err := redactTargetResult(t, result, aliases[result.TargetID()])
		if err != nil {
			return domain.RunReport{}, err
		}
		redacted = append(redacted, next)
	}

	out, err := domain.NewRunReport(domain.RunReportInput{
		SvcdoctorVersion: report.SvcdoctorVersion(),
		StartedAt:        report.StartedAt(),
		Duration:         report.Duration(),
		Concurrency:      report.Concurrency(),
		OutputMode:       domain.OutputModeShareableRedacted,
		StoppedReason:    report.StoppedReason(),
		Targets:          redacted,
	})
	if err != nil {
		return domain.RunReport{}, fmt.Errorf("%w: %w", ErrRedaction, err)
	}
	return out, nil
}

// redactTargetResult rebuilds one result under its pseudonym.
//
// Rebuilt through the exported constructors rather than by copying fields, so a
// redacted result satisfies the same presence invariants as a local one: a
// never-started target still carries no report, and a failed one still carries
// an error.
func redactTargetResult(
	t *table, result domain.TargetResult, alias string,
) (domain.TargetResult, error) {
	switch result.ExecutionState() {
	case domain.ExecutionStateCompleted, domain.ExecutionStateCancelled:
		report, err := redactWith(t, result.Report())
		if err != nil {
			return domain.TargetResult{}, err
		}
		if result.ExecutionState() == domain.ExecutionStateCancelled {
			return domain.CancelledTarget(alias, result.Service(), report, result.Incomplete())
		}
		return domain.CompletedTarget(alias, result.Service(), report, result.Incomplete())

	case domain.ExecutionStateNotStarted:
		return domain.NotStartedTarget(alias, result.Service())

	case domain.ExecutionStateExecutionFailed:
		// The message is svcdoctor's own prose and already carries no credential
		// reference — ADR 0074 §4.2, enforced where it is built. It still passes
		// through prose replacement, because an internal error can legitimately
		// name a host, and a host is exactly what this is removing.
		return domain.FailedTarget(alias, result.Service(), result.ExecutionErrorClass(),
			t.text(result.ExecutionErrorMessage()))

	case domain.ExecutionStateUnspecified:
		return domain.TargetResult{}, fmt.Errorf(
			"%w: a target result has no execution state", ErrRedaction)
	default:
		return domain.TargetResult{}, fmt.Errorf(
			"%w: unknown execution state %s", ErrRedaction, result.ExecutionState())
	}
}

// collectRun gathers every identifying value the whole run carries.
//
// Collection is separate from assignment so that pseudonym numbering depends on
// the set of values across the run, not on which target happened to be measured
// first — which is what makes the numbering stable under concurrency.
func collectRun(results []domain.TargetResult) (
	hosts, ips, identities []string, ids []domain.EvidenceID,
) {
	for _, result := range results {
		if !result.HasReport() {
			continue
		}
		h, i, dent, evidence := collect(result.Report())
		hosts = append(hosts, h...)
		ips = append(ips, i...)
		identities = append(identities, dent...)
		ids = append(ids, evidence...)
	}
	return hosts, ips, identities, ids
}

// targetAliases assigns each identifier its pseudonym, in declared order.
//
// Declared order rather than sorted order, and the difference is a leak: sorting
// the real identifiers before numbering would make `target-001 … target-00n`
// encode their lexical ordering, which is information about the names this
// function exists to remove.
func targetAliases(results []domain.TargetResult) map[string]string {
	aliases := make(map[string]string, len(results))
	for i, result := range results {
		aliases[result.TargetID()] = fmt.Sprintf("target-%03d", i+1)
	}
	return aliases
}
