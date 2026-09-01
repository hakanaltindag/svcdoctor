package redaction

import (
	"fmt"
	"slices"

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
	values := collectRun(results)
	t := newTable(values.hosts, values.ips, values.identities, values.ids)
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

	if err := verifyNoRunResidual(values, aliases, out); err != nil {
		return domain.RunReport{}, err
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
		return domain.FailedTarget(alias, result.Service(), result.ExecutionErrorClass(),
			redactedExecutionMessage(result.ExecutionErrorClass()))

	case domain.ExecutionStateUnspecified:
		return domain.TargetResult{}, fmt.Errorf(
			"%w: a target result has no execution state", ErrRedaction)
	default:
		return domain.TargetResult{}, fmt.Errorf(
			"%w: unknown execution state %s", ErrRedaction, result.ExecutionState())
	}
}

// runValues is everything one run carries that redaction must account for.
//
// A struct rather than five return values, because Phase 9.2B added the fifth
// and a five-value signature is where a caller starts transposing arguments.
type runValues struct {
	hosts      []string
	ips        []string
	identities []string
	ids        []domain.EvidenceID

	// targetIDs are the operator-chosen identifiers of **every** result,
	// including the ones that produced no report. They are not prose
	// replacements — see RedactRun's note on why identifiers stay out of that
	// list — and they exist so the aggregate residual check can prove that each
	// one was replaced by its pseudonym.
	targetIDs []string
}

// collectRun gathers every identifying value the whole run carries.
//
// Collection is separate from assignment so that pseudonym numbering depends on
// the set of values across the run, not on which target happened to be measured
// first — which is what makes the numbering stable under concurrency.
//
// # Every result is visited, including the ones with no report
//
// This skipped report-less results until Phase 9.2B, and the skip was the defect
// recorded as UX-B01. A target that failed to execute still carries an
// operator-chosen identifier, and it still contributes a string to the output —
// so a collection pass that never saw it could not prove anything about it, and
// the aggregate had no residual check that would have noticed.
//
// What a report-less result contributes is deliberately narrow: its identifier,
// and nothing else. Its execution message is **not** mined for hosts or paths.
// Inferring a target's identities by reading prose is the pattern ADR 0018
// forbids — it is a regular expression wearing a different hat, and it fails
// open on the first message nobody anticipated. The message is handled by
// replacing it, in redactedExecutionMessage, rather than by searching it.
func collectRun(results []domain.TargetResult) runValues {
	var out runValues
	for _, result := range results {
		out.targetIDs = append(out.targetIDs, result.TargetID())

		if !result.HasReport() {
			continue
		}
		h, i, dent, evidence := collect(result.Report())
		out.hosts = append(out.hosts, h...)
		out.ips = append(out.ips, i...)
		out.identities = append(out.identities, dent...)
		out.ids = append(out.ids, evidence...)
	}
	return out
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

// redactedExecutionMessage is the shareable form of an execution failure's
// message.
//
// # Why the message is replaced rather than filtered
//
// A LOCAL_FULL execution message is written for the operator who has to fix it,
// so it names the local thing that failed: a trust file's path, a credential
// reference's source kind, a wrapped filesystem error. That is correct there and
// it is ADR 0049 §3's rule — a file svcdoctor cannot read has to be nameable to
// the person fixing it.
//
// It is wrong in a shareable report, and Phase 9.2A measured both halves of the
// wrongness. `stat /etc/svcdoctor/pki/corp-root-ca.pem: no such file or
// directory` tells a reader where an organisation keeps its private CA. `invalid
// run input: unsupported host: fe80::1%en0 …` put a raw address into the one
// document whose whole purpose is that addresses have been removed.
//
// Three ways to fix it were available and two are worse:
//
//   - Search the message for host-shaped and path-shaped substrings. This is the
//     pattern-matching ADR 0018 refuses. verifyNoResidual's own comment says why:
//     it checks exact known values rather than patterns, "so it cannot be
//     satisfied by output that merely looks clean". A message nobody anticipated
//     fails open.
//   - Add a structured locator field beside the message, and drop that field in
//     shareable output. That is a report-schema change, and RunSchemaVersion is
//     frozen at 1.
//
// What is left is to replace the message with one svcdoctor authored, chosen by
// the failure's class. Each reads as a reason clause rather than a sentence,
// because the terminal renderer already supplies the subject — it prints
// "svcdoctor could not run this target · <message>" — and a second subject there
// would say the same thing twice. It is chosen by — which is already a separate, closed, machine-readable
// field. The class survives, the reason's category survives, and the locator is
// gone because it was never assembled rather than because it was filtered out.
//
// # What is given up, stated rather than glossed
//
// A shareable report no longer says *which* environment variable was missing or
// *which* file could not be read. That is the point: those are the local
// locators. The class tells a reader which half of the configuration to look at,
// the LOCAL_FULL report the operator still holds says exactly which entry, and
// nothing about the diagnosis changes — an execution failure carries no report
// and made no claim about any endpoint either way.
func redactedExecutionMessage(class domain.ExecutionErrorClass) string {
	switch class {
	case domain.ExecutionErrorCredentialResolution:
		return "the credential reference this target names could not be resolved; " +
			"the reference is local detail and is withheld from a shareable report"
	case domain.ExecutionErrorInternal:
		return "the reason is local detail and is withheld from a shareable report"
	case domain.ExecutionErrorUnspecified:
		// Unreachable through domain.FailedTarget, which rejects it. Handled
		// rather than defaulted, so a class added later is an exhaustiveness
		// question somebody has to answer rather than a silent fall-through to
		// prose that was assumed safe.
		return "the reason is local detail and is withheld from a shareable report"
	default:
		return "the reason is local detail and is withheld from a shareable report"
	}
}

// verifyNoRunResidual is the aggregate's fail-closed safety net.
//
// # Why the aggregate needed its own
//
// verifyNoResidual runs inside redactWith, once per embedded report. Phase 9.2A
// found that RedactRun never ran anything equivalent, so every string the
// aggregate holds *outside* an embedded report — a target identifier, an
// execution message, a stopped reason — was covered by no check at all. The
// document looked redacted, because the parts that had a checker were.
//
// This closes that. It is the same mechanism, at the level above: re-read the
// finished document, and fail if a value known to be identifying is still in it.
//
// # Two kinds of check, because there are two kinds of value
//
// Hosts, addresses, identities and evidence identifiers are checked by
// **containment**, exactly as verifyNoResidual checks them, because they can
// legitimately appear inside longer strings — an endpoint reference, a finding's
// prose, an execution message. Containment is why a cross-target leak is caught:
// a host collected from target A's report is looked for in target B's execution
// message too.
//
// Target identifiers are checked by **exact equality**, against the one field
// that carries them. Containment would be wrong here and not merely imprecise: a
// target named `db` is a substring of `db-001`, of `postgres` is a substring of
// nothing useful, and of countless legitimate words in a finding's detail. Short
// identifiers are ordinary — `db`, `mq`, `api` — so a containment rule would
// make redaction fail closed on almost every real configuration, which is a
// worse failure than the one it prevents. RedactRun's own note records the
// matching decision on the replacement side: identifiers are deliberately not
// prose replacements, for the same reason.
//
// # What it still cannot distinguish
//
// The same containment ambiguity verifyNoResidual documents. A host literally
// named "0" is a substring of the pseudonym "host-001" and of a port number, and
// is reported as surviving when it has not. That fails closed, is recorded in
// docs/SECURITY.md, and no shape-based rule settles it.
//
// The identifier check has a narrower version of it, found by reading rather
// than by measurement: a target an operator literally named `target-001` is
// equal to the pseudonym it would be given, so the exact-equality test cannot
// tell a surviving identifier from a correctly assigned one and refuses the
// document. That is the right direction to be wrong in — no shareable report is
// produced, rather than one that might carry a name — and the operator can
// rename the target. It is not worth a special case: recognizing
// "identifiers that look like pseudonyms" would mean trusting a shape, which is
// the thing this function exists not to do.
func verifyNoRunResidual(
	values runValues, aliases map[string]string, out domain.RunReport,
) error {
	text, err := stringPositionsOf(out, "run report")
	if err != nil {
		return err
	}

	for _, original := range slices.Sorted(slices.Values(values.hosts)) {
		if containsAny(text, original) {
			return fmt.Errorf("%w: a hostname survived aggregate redaction", ErrRedaction)
		}
	}
	for _, original := range slices.Sorted(slices.Values(values.ips)) {
		if containsAny(text, original) {
			return fmt.Errorf("%w: an IP address survived aggregate redaction", ErrRedaction)
		}
	}
	for _, original := range slices.Sorted(slices.Values(values.identities)) {
		if containsAny(text, original) {
			return fmt.Errorf("%w: a logical identity survived aggregate redaction", ErrRedaction)
		}
	}
	for _, original := range slices.Sorted(slices.Values(values.ids)) {
		if containsAny(text, string(original)) {
			return fmt.Errorf(
				"%w: an evidence identifier survived aggregate redaction", ErrRedaction)
		}
	}

	// Collection must have seen every result. This is the check U01 exists for:
	// a collector that visits only the targets with reports cannot make any
	// statement about the ones without, and "we looked at all of them" is the
	// premise every assertion above rests on. Asserting the premise is what makes
	// the conclusions worth anything.
	if len(values.targetIDs) != len(out.Targets()) {
		return fmt.Errorf(
			"%w: collection saw %d of %d results, so the residual check is incomplete",
			ErrRedaction, len(values.targetIDs), len(out.Targets()))
	}

	// No collected identifier may still address a result. Checked against the
	// **collected originals** rather than against the alias map, so that a
	// collection pass which missed a result and an assignment which skipped one
	// are both visible: the first fails the length check above, the second fails
	// this one.
	original := make(map[string]struct{}, len(values.targetIDs))
	for _, id := range values.targetIDs {
		original[id] = struct{}{}
	}
	assigned := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		assigned[alias] = struct{}{}
	}
	for _, result := range out.Targets() {
		if _, ok := original[result.TargetID()]; ok {
			return fmt.Errorf(
				"%w: a target identifier survived aggregate redaction", ErrRedaction)
		}
		if _, ok := assigned[result.TargetID()]; !ok {
			return fmt.Errorf(
				"%w: a result is addressed by neither its identifier nor a pseudonym",
				ErrRedaction)
		}
	}
	return nil
}
