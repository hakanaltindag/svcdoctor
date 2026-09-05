#!/usr/bin/env bash
# Phase 10.3 mutation closure — PostgreSQL server-authoritative diagnosis.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is restored and verified byte-for-byte against sha256 checksums
# taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it.
#
# # What this covers
#
# The three things Phase 10.3 added and the many things it deliberately did not:
#
#   PG-M01  transport failure creates a connection-limit diagnosis
#   PG-M02  an arbitrary SQLSTATE is treated as a connection-limit refusal
#   PG-M03  the connection-limit claim names a cause
#   PG-M04  the connection-limit claim recommends raising the limit
#   PG-M05  the admission scope calls the policy misconfigured
#   PG-M06  the admission scope recommends widening access
#   PG-M07  an admission refusal is reported as a credential rejection
#   PG-M08  a reported recovery state becomes a finding
#   PG-M09  a reported recovery state becomes a failover claim
#   PG-M10  two addresses both admitted become a topology claim
#   PG-M11  an incomplete address set is treated as complete
#   PG-M12  an undetermined admission decision is counted as a refusal
#   PG-M13  a blocked startup node is counted as a refusal
#   PG-M14  a withheld credential is reported as an authentication failure
#   PG-M15  a raw server parameter enters the summary
#   PG-M16  a raw SQLSTATE enters a recommendation
#   PG-M17  deleting evidence strengthens the claim
#   PG-M18  an absent recovery parameter is read as "off"
#   PG-M19  rule identity chooses the published prose
#   PG-M20  incompatible prose converges
#   PG-M21  two address subjects are deduplicated
#   PG-M22  diagnosis edits the evidence it read
#   PG-M23  a PostgreSQL branch appears in the generic core
#   PG-M24  a role observation moves the exit code
#   PG-M25  the connection-limit claim asserts an endpoint-wide shortage
#   PG-M26  the floor restatement asserts an endpoint-wide shortage
#   PG-M27  the connection-limit recommendation names one applicable limit
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/diagnosis/postgres/session.go
  internal/diagnosis/postgres/admission.go
  internal/diagnosis/postgres/shared.go
  internal/diagnosis/postgres/authentication.go
  internal/diagnosis/converge.go
  internal/diagnosis/graphquery.go
  internal/render/terminal/service.go
)

for f in "${FILES[@]}"; do
  mkdir -p "$BACKUP/$(dirname "$f")"
  cp "$f" "$BACKUP/$f"
done

BEFORE="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
restore() { for f in "${FILES[@]}"; do cp "$BACKUP/$f" "$f"; done; }

# An interrupted harness must not leave a mutation planted.
on_interrupt() {
  if [ -d "$BACKUP" ]; then
    restore
    rm -rf "$BACKUP"
    echo
    echo "interrupted: the tree was restored from the backup before exiting."
  fi
}
trap on_interrupt EXIT
trap 'on_interrupt; exit 130' INT
trap 'on_interrupt; exit 143' TERM HUP

PASS=0
FAIL=0
SURVIVORS=()

# mutate <id> <description> <file> <python-replacement> <test-package> <test-regex>
mutate() {
  local id="$1" desc="$2" file="$3" script="$4" pkg="$5" regex="$6"

  # A -run regex that selects no test makes `go test` exit 0, which this harness
  # would read as a pass. Checked on the pristine tree, before planting.
  local selected
  selected="$(go test "$pkg" -run "$regex" -count=1 -timeout 600s -v 2>/dev/null || true)"
  # A here-string rather than a pipe: `grep -q` exits at its first match, and
  # under `pipefail` the SIGPIPE that sends `printf` becomes the pipeline's
  # status, so a large selection was reported as no selection at all. Phase 10.2
  # measured that in every harness in this directory.
  if ! grep -q '^=== RUN' <<<"$selected"; then
    echo "  $id  NO MATCHING TEST — the -run regex selects nothing: $regex"
    FAIL=$((FAIL + 1)); SURVIVORS+=("$id (no matching test: $regex)"); return
  fi

  if ! python3 - "$file" <<PY
import sys
path = sys.argv[1]
s = open(path).read()
$script
open(path, 'w').write(s)
PY
  then
    echo "  $id  COULD NOT PLANT — the anchor text is gone: $desc"
    FAIL=$((FAIL + 1)); SURVIVORS+=("$id (unplantable)"); restore; return
  fi

  if go test "$pkg" -run "$regex" -count=1 -timeout 600s >/dev/null 2>&1; then
    echo "  $id  SURVIVOR — $desc"
    SURVIVORS+=("$id $desc"); FAIL=$((FAIL + 1))
  else
    echo "  $id  caught    — $desc"
    PASS=$((PASS + 1))
  fi
  restore
}

echo "Phase 10.3 mutation closure — PostgreSQL server-authoritative diagnosis"
echo
echo "--- the connection-limit claim (ADR 0085 section 3) ---"

# The claim's whole precondition is *this endpoint completed authentication and
# then refused the session*, and the first half is established by the session
# node's parent. Dropping the gate lets the claim be made where nothing
# established it.
#
# Two earlier versions of this plant were equivalent mutations and are worth
# recording. Pointing the gate's removal at TestAcceptanceMatrix survived,
# because every row there has a proper parent. Removing the `if !ok` gate
# survived too, for a subtler reason: authenticationProof returns the zero
# Evidence, whose empty identifier domain.NewFinding rejects, so the finding
# still did not appear — the same outcome by a different route.
#
# What is planted now is the check that decides *whether a parent proves
# anything*: a non-passing authentication node becomes a proof. That produces a
# claim, and TestEverySessionClaimRequiresItsAuthenticationProof drives exactly
# the shapes where it must not.
mutate PG-M01 "transport failure creates a connection-limit diagnosis" \
  internal/diagnosis/postgres/session.go \
  's = s.replace("""		parent, ok := g.Node(id)
		if !ok || parent.State() != domain.StatePass {
			continue
		}""", """		parent, ok := g.Node(id)
		if !ok {
			continue
		}""", 1)
assert """		parent, ok := g.Node(id)
		if !ok {
			continue
		}""" in s' \
  ./internal/diagnosis/postgres 'TestEverySessionClaimRequiresItsAuthenticationProof'

mutate PG-M02 "an arbitrary SQLSTATE is treated as a connection-limit refusal" \
  internal/diagnosis/postgres/session.go \
  's = s.replace("""	case domain.FailureResourceLimitReached:""",
"""	case domain.FailureResourceLimitReached, domain.FailureProtocolUnexpectedResponse:""", 1)
assert "domain.FailureResourceLimitReached, domain.FailureProtocolUnexpectedResponse:" in s' \
  ./test/diagnosis 'TestPGP02NoOtherSQLStateBecomesAConnectionLimit'

mutate PG-M03 "the connection-limit claim names a cause" \
  internal/diagnosis/postgres/session.go \
  's = s.replace("""		"The response also carries nothing about why that limit was reached""",
"""		"The endpoint is likely leaking connections from a misconfigured pool. " +
		"The response also carries nothing about why that limit was reached""", 1)
assert "likely leaking connections" in s' \
  ./internal/diagnosis/postgres 'TestSQLState53300NamesTheConditionAndInventsNoCause'

mutate PG-M04 "the connection-limit claim recommends raising the limit" \
  internal/diagnosis/postgres/session.go \
  's = s.replace("""	recommendConnectionLimitReached = "Identify the connection limits applicable to this " +
		"attempted session and compare their current usage with their configured limits\"""",
"""	recommendConnectionLimitReached = "Increase the number of connections this endpoint " +
		"is configured to allow\"""", 1)
assert "Increase the number of connections" in s' \
  ./internal/diagnosis/postgres 'TestSQLState53300NamesTheConditionAndInventsNoCause'

# PG-M25 is the scope overclaim, and it is the defect the first cut of this
# candidate carried: 53300 restated as a property of the endpoint rather than of
# the session that was refused. Nothing shipped with it — Phase 10.3 is
# uncommitted and unreleased — and this plant is what keeps it that way. `CONNECTION LIMIT 0` in the integration fixture is
# the standing counterexample.
mutate PG-M25 "the connection-limit claim asserts an endpoint-wide shortage" \
  internal/diagnosis/postgres/session.go \
  's = s.replace("""		"a connection limit that applied to this attempted session had been reached.""",
"""		"no connection slot was available to it at that moment.""", 1)
assert "no connection slot was available" in s' \
  ./internal/diagnosis/postgres 'TestTheConnectionLimitClaimIsScopedToTheAttemptedSession'

# PG-M26 is the same overclaim in the floor's restatement, which serves the two
# windows where 53300 is not escalated. One SQLSTATE may not acquire two
# meanings depending on which window observed it.
mutate PG-M26 "the floor restatement asserts an endpoint-wide shortage" \
  internal/diagnosis/postgres/shared.go \
  's = s.replace("""		"condition: a connection limit that applied to the attempted session had been " +
		"reached. The response does not say which limit.\"""",
"""		"condition: it refused because no connection slot was available to it at that " +
		"moment.\"""", 1)
assert "no connection slot was available" in s' \
  ./internal/diagnosis/postgres 'TestTheSessionStepIsTheOnlyProducerOfTheResourceLimitClass'

# PG-M27 is the softer form of PG-M04. Rather than recommending a remedy, it
# sends the operator to one named limit — which asserts by implication the thing
# the response does not say, and is why the recommendation is held to a stricter
# vocabulary than the detail.
mutate PG-M27 "the connection-limit recommendation names one applicable limit" \
  internal/diagnosis/postgres/session.go \
  's = s.replace("""	recommendConnectionLimitReached = "Identify the connection limits applicable to this " +
		"attempted session and compare their current usage with their configured limits\"""",
"""	recommendConnectionLimitReached = "Compare the number of connections in use at this " +
		"endpoint with its configured max_connections\"""", 1)
assert "its configured max_connections" in s' \
  ./internal/diagnosis/postgres 'TestTheConnectionLimitClaimIsScopedToTheAttemptedSession'

echo
echo "--- the admission scope (ADR 0085 section 2) ---"

mutate PG-M05 "the admission scope calls the policy misconfigured" \
  internal/diagnosis/postgres/admission.go \
  's = s.replace("""	detailAdmissionContrast = "\\nThe addresses did not answer alike.""",
"""	detailAdmissionContrast = "\\nThe addresses did not answer alike, so pg_hba.conf is " +
		"misconfigured for one of them.""", 1)
assert "misconfigured for one of them" in s' \
  ./internal/diagnosis/postgres 'TestTheAdmissionScopeNamesNoConfigurationAndNoCause'

mutate PG-M06 "the admission scope recommends widening access" \
  internal/diagnosis/postgres/admission.go \
  's = s.replace("""	recommendAdmissionContrast = "Compare this endpoint""",
"""	recommendAdmissionContrast = "Add a host-based access rule permitting this endpoint""", 1)
assert "Add a host-based access rule" in s' \
  ./internal/diagnosis/postgres 'TestTheAdmissionScopeRecommendsOnlyObservations'

mutate PG-M07 "an admission refusal is reported as a credential rejection" \
  internal/diagnosis/postgres/authentication.go \
  's = s.replace("""	case domain.FailureAuthzNotPermitted:""",
"""	case domain.FailureAuthCredentialsRejected:""", 1)
assert "case domain.FailureAuthCredentialsRejected:" in s' \
  ./test/diagnosis 'TestPGP05AdmissionRefusalIsNeverACredentialClaim'

echo
echo "--- the role observation stays an observation (ADR 0085 section 4) ---"

# The renderer is where the observation lives. A note that graded it, or a line
# that claimed an identity, is the drift this phase exists to prevent.
mutate PG-M08 "a reported recovery state is graded as a problem" \
  internal/render/terminal/service.go \
  's = s.replace("""					"This endpoint reported the session as being in recovery.",""",
"""					"Warning: this endpoint is a standby and is the wrong server.",""", 1)
assert "is the wrong server" in s' \
  ./test/diagnosis 'TestPGP06AndP07RoleObservationIsNeitherIncidentNorAssurance|TestThePostgresGoldenIncidentCorpus'

mutate PG-M09 "a reported recovery state becomes a failover claim" \
  internal/render/terminal/service.go \
  's = s.replace("""					"this target should have, so this is neither a finding nor a fault.",""",
"""					"this target should have; failover has probably failed here.",""", 1)
assert "failover has probably failed" in s' \
  ./test/diagnosis 'TestThePostgresGoldenIncidentCorpus'

mutate PG-M10 "two addresses both admitted become a topology claim" \
  internal/diagnosis/postgres/admission.go \
  's = s.replace("""	scope, ok := admissionScopeOf(ctx)
	if !ok || len(scope.refused) == 0 {
		return nil
	}""", """	scope, ok := admissionScopeOf(ctx)
	if !ok {
		return nil
	}""", 1)
assert """	if !ok {
		return nil
	}""" in s' \
  ./internal/diagnosis/postgres 'TestTheAdmissionScopeIsSilentWhereItWouldOnlyDuplicate'

echo
echo "--- completeness is three categories and never two ---"

mutate PG-M11 "an incomplete address set is treated as complete" \
  internal/diagnosis/postgres/admission.go \
  's = s.replace("""	scope.complete = len(scope.undetermined) == 0 && !ctx.Incomplete""",
"""	scope.complete = true""", 1)
assert "scope.complete = true" in s' \
  ./test/diagnosis 'TestPGP11AnIncompleteSetSupportsNoExclusiveClaim'

mutate PG-M12 "an undetermined admission decision is counted as a refusal" \
  internal/diagnosis/postgres/admission.go \
  's = s.replace("""	default:
		return admissionUndetermined
	}""", """	default:
		return admissionRefused
	}""", 1)
assert """	default:
		return admissionRefused
	}""" in s' \
  ./internal/diagnosis/postgres 'TestTheAdmissionScopeCountsThreeCategoriesAndNeverTwo|TestTheAdmissionScopeIsSilentWhereItWouldOnlyDuplicate'

mutate PG-M13 "a blocked startup node is counted as a refusal" \
  internal/diagnosis/postgres/admission.go \
  's = s.replace("""	case node.State() == domain.StateFail &&
		node.FailureClass() == domain.FailureAuthzNotPermitted:""",
"""	case node.State() == domain.StateFail || node.State() == domain.StateSkipped:""", 1)
assert "node.State() == domain.StateSkipped:" in s' \
  ./internal/diagnosis/postgres 'TestTheAdmissionScopeCountsThreeCategoriesAndNeverTwo'

echo
echo "--- credentials stay endpoint-bound ---"

mutate PG-M14 "a withheld credential is reported as an authentication failure" \
  internal/diagnosis/postgres/authentication.go \
  's = s.replace("""	case domain.FailureExecSkippedByPolicy:""",
"""	case domain.FailureAuthMechanismUnsupported:""", 1)
assert "case domain.FailureAuthMechanismUnsupported:" in s' \
  ./test/diagnosis 'TestPGP12WithheldCredentialsAreNeverARejection'

echo
echo "--- peer-controlled text never becomes prose (ADR 0081 section 2.7) ---"

mutate PG-M15 "a raw server parameter enters the summary" \
  internal/diagnosis/postgres/session.go \
  's = s.replace("""			Summary:    summaryConnectionLimitReached,""",
"""			Summary:    summaryConnectionLimitReached + func() string {
				if v, ok := stringAttr(node, servicepostgres.AttrInHotStandby); ok {
					return " (" + v + ")"
				}
				return ""
			}(),""", 1)
assert "AttrInHotStandby" in s' \
  ./test/diagnosis 'TestPGP13ServerControlledTextNeverReachesTrustedProse'

mutate PG-M16 "a raw SQLSTATE enters a recommendation" \
  internal/diagnosis/postgres/session.go \
  's = s.replace("""				Action:    recommendConnectionLimitReached,""",
"""				Action:    recommendConnectionLimitReached + " for " + func() string {
					v, _ := stringAttr(node, servicepostgres.AttrSQLState)
					return v
				}(),""", 1)
assert "AttrSQLState" in s' \
  ./test/diagnosis 'TestPGP13bTheSQLStateDetailIsTheOneVerbatimField'

echo
echo "--- monotonicity: less evidence never says more ---"

mutate PG-M17 "deleting evidence strengthens the claim" \
  internal/diagnosis/postgres/admission.go \
  's = s.replace("""	if scope.total() < 2 {
		return admissionScope{}, false
	}""", """	if scope.total() < 1 {
		return admissionScope{}, false
	}""", 1)
assert "scope.total() < 1" in s' \
  ./internal/diagnosis/postgres 'TestTheAdmissionScopeIsSilentWhereItWouldOnlyDuplicate'

mutate PG-M18 "an absent recovery parameter is read as not-in-recovery" \
  internal/render/terminal/service.go \
  's = s.replace("""					default:
						return ""
					}""", """					default:
						return "not in recovery"
					}""", 1)
assert """						return "not in recovery"
					}""" in s' \
  ./test/diagnosis 'TestPGP09AndP10AnAbsentRoleIsNotAReportedRole'

echo
echo "--- convergence (ADR 0081 sections 2.2b and 2.6a) ---"
# These two plants are caught by the generic closure suite rather than by a
# PostgreSQL guard, and the reason is a Phase 10.3 result worth recording: **no
# two PostgreSQL findings can share (Code, Subject, Layer) while saying different
# things.** The admission scope produces at most one finding per run, every other
# code is one claim per node, and the one code two rules reach —
# POSTGRES_CONNECTION_NOT_PERMITTED — is separated by layer.
#
# So a PostgreSQL-scoped guard for these would be vacuous. The invariant is real
# and is not deleted; it is held where it is reachable.

mutate PG-M19 "rule identity chooses the published prose" \
  internal/diagnosis/converge.go \
  's = s.replace("""		summary:       f.Summary(),""", """		summary:       "",""", 1)
assert """		summary:       "",""" in s' \
  ./internal/diagnosis 'TestC03SameIdentityMateriallyDifferentSummaryDoesNotConverge|TestC05RegistrationOrderCannotChooseProse'

mutate PG-M20 "incompatible prose converges" \
  internal/diagnosis/converge.go \
  's = s.replace("""		detail:        f.Detail(),""", """		detail:        "",""", 1)
assert """		detail:        "",""" in s' \
  ./internal/diagnosis 'TestC04SameIdentityMateriallyDifferentDetailDoesNotConverge|TestC06ARuleIDRenameCannotChangeAnything'

mutate PG-M21 "two address subjects are deduplicated" \
  internal/diagnosis/converge.go \
  's = s.replace("""	return SemanticIdentity{code: f.Code(), subject: f.Subject()}""",
"""	return SemanticIdentity{code: f.Code()}""", 1)
assert "SemanticIdentity{code: f.Code()}" in s' \
  ./test/diagnosis 'TestPGP18DifferentSubjectsNeverConverge'

echo
echo "--- the boundaries the phase must not cross ---"

mutate PG-M22 "the admission scope reads a session parameter" \
  internal/diagnosis/postgres/admission.go \
  's = s.replace("""func classifyAdmission(node domain.Evidence) admissionVerdict {
	switch {""", """func classifyAdmission(node domain.Evidence) admissionVerdict {
	if v, ok := node.Attribute(servicepostgres.AttrInHotStandby); ok && v.String() == "on" {
		return admissionRefused
	}
	switch {""", 1)
assert "AttrInHotStandby" in s' \
  ./internal/diagnosis/postgres 'TestTheAdmissionRuleReadsNoAttribute|TestTheRulesReadOnlyTheAuthorizedAttributes'

mutate PG-M23 "a PostgreSQL branch appears in the generic core" \
  internal/diagnosis/graphquery.go \
  's = s.replace("""func classifySubject(nodes []domain.Evidence) domain.State {""",
"""func classifySubject(nodes []domain.Evidence) domain.State {
	for _, node := range nodes {
		if node.Step() == "postgres.session" {
			return domain.StatePass
		}
	}""", 1)
assert "postgres.session" in s' \
  ./test/diagnosis 'TestPGP20TheGenericCoreStaysPostgreSQLUnaware'

mutate PG-M24 "a role observation moves the exit code" \
  internal/diagnosis/postgres/admission.go \
  's = s.replace("""		Severity:   domain.SeverityInfo,""",
"""		Severity:   domain.SeverityError,""", 1)
assert "Severity:   domain.SeverityError," in s' \
  ./internal/diagnosis/postgres 'TestTheAdmissionScopeIsInfoAndMovesNoExitCode'

echo
echo "--- restoration ---"

AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "TREE NOT RESTORED — the working tree differs from the pre-run state."
  diff <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") || true
  FAIL=$((FAIL + 1))
else
  echo "  tree restored byte-for-byte"
fi

rm -rf "$BACKUP"
trap - EXIT INT TERM HUP

echo
echo "planted $((PASS + ${#SURVIVORS[@]}))  caught $PASS  survivors ${#SURVIVORS[@]}"
if [ "${#SURVIVORS[@]}" -ne 0 ]; then
  printf '  %s\n' "${SURVIVORS[@]}"
  echo
  echo "PHASE 10.3 MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 10.3 MUTATION CLOSURE: 0 survivors"
