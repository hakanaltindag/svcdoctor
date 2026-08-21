# ADR 0015: The report derives its summary

## Status

Accepted.

## Decision

`Summary` is computed by the report from the evidence graph and the findings it
was given. A caller cannot supply one: `ReportInput` has no summary field and
`Summary` has no exported constructor.

The aggregation rules are fixed and narrow:

- **status** is `PROBLEMS_FOUND` when any finding is `ERROR` or `CRITICAL`,
  otherwise `OK`. This is exactly the exit-code 0/1 boundary in `docs/SCOPE.md`.
- **firstBrokenLayer** is the lowest layer holding evidence in state `FAIL`.
  `UNKNOWN` and `SKIPPED` are not failures, and a blocked-by reference is not one
  either. Absent when nothing failed.
- **findingCountsBySeverity** counts findings at each severity.
- **skippedEvidenceCount** and **unknownEvidenceCount** count evidence nodes.

The summary aggregates; it does not infer. Every value is a count or a selection
over data the report already holds.

## Context

A summary could have been part of the report's input. Diagnosis knows what it
found, so it could hand over both the findings and a summary of them.

That creates two sources of truth for the same facts. A report could then state
two findings while its summary counted five, or report `OK` while carrying a
`CRITICAL` finding, and nothing in the model would say which was correct. The
failure would be silent and would reach whoever read the report.

Deriving it makes disagreement impossible rather than merely discouraged. It is
the same reasoning ADR 0013 applies to the graph's child index, which is computed
during `Freeze` instead of maintained beside the parent edges.

The narrow status vocabulary is a separate restraint. `docs/REPORT_SCHEMA.md`
asks for an overall status and points at the exit-code contract as its basis. That
contract distinguishes only "no ERROR/CRITICAL finding" from "ERROR/CRITICAL
findings exist", so the status has two values. A richer health taxonomy would be
invented business semantics no document defines.

## Consequences

- A summary cannot contradict the report that contains it.
- `OK` means "no ERROR or CRITICAL finding" and is not a claim of health. A run
  where most checks were skipped produces no errors, which is why the skipped and
  unknown counts sit beside the status and must be read with it.
- Exit codes 2, 3 and 4 stay outside the summary. They describe usage errors,
  internal failures and partial runs, none of which a report can observe about
  itself.
- Adding a summary field means adding a derivation rule here, not a new input.
