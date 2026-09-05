#!/usr/bin/env bash
# Phase 10.1B mutation closure — the activated diagnostic pipeline.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is restored and verified byte-for-byte against sha256 checksums
# taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it.
#
# # What this covers, and how it differs from phase101a
#
# Phase 10.1A mutated machinery nothing consumed. Phase 10.1B activated it, so
# every plant below changes a **published report**: a boundary that names the
# wrong stage, a merge that collapses two endpoints, an INFO finding that turns
# a clean run into exit 1. The guards are correspondingly in test/diagnosis,
# which drives the real pipeline, rather than in the engine's own unit tests.
#
#   B01-B03  not measured is not failed: UNKNOWN, SKIPPED, blocked
#   B04-B05  the boundary: graph order, and one boundary per subject
#   B06      incomplete is not complete
#   B07-B09  confidence: voting, contradiction, absence
#   B10-B11  convergence: duplicates merge, distinct subjects do not
#   B12-B13  recommendation safety
#   B14      peer text in the one place Phase 10.1B added prose
#   B15-B16  the renderer, and the exit contract
#   B17-B18  rule failure and canonical ordering
#   B19-B20  monotonicity: invented evidence, and an incomplete sibling set
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/diagnosis/engine.go
  internal/diagnosis/basis.go
  internal/diagnosis/confidence.go
  internal/diagnosis/converge.go
  internal/diagnosis/boundary.go
  internal/diagnosis/failureboundary.go
  internal/diagnosis/graphquery.go
  internal/diagnosis/advice.go
  internal/render/terminal/report.go
)

for f in "${FILES[@]}"; do
  mkdir -p "$BACKUP/$(dirname "$f")"
  cp "$f" "$BACKUP/$f"
done

BEFORE="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
restore() { for f in "${FILES[@]}"; do cp "$BACKUP/$f" "$f"; done; }

# An interrupted harness must not leave a mutation planted.
#
# Phase 9.3A measured why this is not hypothetical: a run killed by a command
# timeout left a mutation in the tree, and the next run took that tree as its
# pristine baseline and reported a survivor that was an artefact of the leftover.
# The BEFORE/AFTER checksums cannot catch it — they prove the run put back what
# it found, not that what it found was the committed tree.
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

  # A -run regex that selects **no test** makes `go test` exit 0, which this
  # harness would read as a survivor. Twenty mutations sat "surviving" across
  # phase91a and phase91b for exactly that reason until the v0.4.0 release gate
  # measured them. An empty selection is a harness failure, not a finding about
  # the product, and the two need opposite fixes.
  #
  # Checked on the **pristine** tree, before planting: after planting, a mutation
  # that breaks the build produces no `=== RUN` either, and a check placed later
  # could not tell the two apart.
  local selected
  selected="$(go test "$pkg" -run "$regex" -count=1 -timeout 600s -v 2>/dev/null || true)"
  # A here-string rather than a pipe. `grep -q` exits at its first match, and
  # under `pipefail` that closes the pipe under `printf`, whose SIGPIPE then
  # becomes the pipeline's status — so a **large** selection was reported as no
  # selection at all. Phase 10.2 measured it: a -run regex selecting 200 KB of
  # verbose output was called "no matching test" while the same regex matched
  # 1026 tests when run by hand. Small outputs fit the pipe buffer and never
  # showed it. The failure direction is loud rather than silent, but it is still
  # wrong, and it is wrong in the check that exists to make a wrong regex loud.
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

echo "Phase 10.1B mutation closure — the activated diagnostic pipeline"
echo
echo "--- not measured is not failed ---"

mutate B01 "UNKNOWN is accepted as the first definitive failure" \
  internal/diagnosis/boundary.go \
  's = s.replace("""		if node.State() == domain.StateFail || node.State() == domain.StateDegraded {""",
"""		if node.State() == domain.StateFail || node.State() == domain.StateDegraded ||
			node.State() == domain.StateUnknown {""", 1)
assert "domain.StateUnknown {" in s' \
  ./test/diagnosis 'TestS05AnUnknownProducesNoDefinitiveBoundary|TestMonotonicEpistemicProperty'

mutate B02 "SKIPPED is accepted as the first definitive failure" \
  internal/diagnosis/boundary.go \
  's = s.replace("""		if node.State() == domain.StateFail || node.State() == domain.StateDegraded {""",
"""		if node.State() == domain.StateFail || node.State() == domain.StateDegraded ||
			node.State() == domain.StateSkipped {""", 1)
assert "domain.StateSkipped {" in s' \
  ./test/diagnosis 'TestS11ASkippedStageAboveTheFailureIsNotTheBoundary'

mutate B03 "a blocked descendant is cited by the boundary" \
  internal/diagnosis/failureboundary.go \
  's = s.replace("""	refs := []domain.EvidenceID{failing.ID()}""",
"""	refs := append([]domain.EvidenceID{failing.ID()}, b.Blocked()...)""", 1)
assert "b.Blocked()...)" in s' \
  ./test/diagnosis 'TestS01BoundaryAtTCPWithTLSBlocked'

echo
echo "--- the failure boundary ---"

mutate B04 "the boundary walks identifier order instead of layer order" \
  internal/diagnosis/graphquery.go \
  's = s.replace("""	sortByLayer(out)
	return out
}""", """	return out
}""", 1)
assert "sortByLayer(out)\n\treturn out" not in s' \
  ./internal/diagnosis 'TestTheBoundaryFollowsLayerOrderNotIdentifierOrder'

mutate B05 "per-subject boundaries collapse into one" \
  internal/diagnosis/boundary.go \
  's = s.replace("""		if boundary, ok := boundaryFor(g, subject); ok {
			out = append(out, boundary)
		}""", """		if boundary, ok := boundaryFor(g, subject); ok && len(out) == 0 {
			out = append(out, boundary)
		}""", 1)
assert "ok && len(out) == 0 {" in s' \
  ./test/diagnosis 'TestS03TwoBranchesFailingAtDifferentLayers|TestTheActivatedPipelineIsDeterministic'

echo
echo "--- incomplete is not complete ---"

mutate B06 "complete contrast is admitted while a discriminating observation is missing" \
  internal/diagnosis/confidence.go \
  's = s.replace("""	if authority == AuthorityCompleteContrast && len(basis.missing) > 0 {""",
"""	if false && authority == AuthorityCompleteContrast && len(basis.missing) > 0 {""", 1)
assert "if false && authority == AuthorityCompleteContrast" in s' \
  ./internal/diagnosis 'TestCompleteContrastIsRefusedWhileSomethingIsMissing'

echo
echo "--- confidence ---"

mutate B07 "weak convergence votes itself up to HIGH" \
  internal/diagnosis/confidence.go \
  's = s.replace("""		if len(basis.supporting) >= 2 {
			return domain.ConfidenceMedium, nil
		}""",
"""		if len(basis.supporting) >= 2 {
			return domain.ConfidenceHigh, nil
		}""", 1)
assert "if len(basis.supporting) >= 2 {\n\t\t\treturn domain.ConfidenceHigh" in s' \
  ./internal/diagnosis 'TestP09MultipleWeakSupportsCannotVoteToHigh|TestDIAG027TheLadder'

mutate B08 "contradicting evidence raises confidence" \
  internal/diagnosis/confidence.go \
  's = s.replace("""	if len(basis.contradicting) > 0 {
		return domain.ConfidenceLow, nil
	}""",
"""	if len(basis.contradicting) > 0 {
		return domain.ConfidenceHigh, nil
	}""", 1)
assert "return domain.ConfidenceHigh, nil\n	}" in s' \
  ./test/diagnosis 'TestS10ContradictionDoesNotRaiseConfidence|TestContradictionMonotonicity'

mutate B09 "a missing observation is recorded as contradicting evidence" \
  internal/diagnosis/basis.go \
  's = s.replace("""func (b *BasisBuilder) Miss(steps ...domain.Step) *BasisBuilder {
	b.missing = append(b.missing, steps...)""",
"""func (b *BasisBuilder) Miss(steps ...domain.Step) *BasisBuilder {
	for range steps {
		b.contradicting = append(b.contradicting, b.supporting...)
	}
	b.missing = append(b.missing, steps...)""", 1)
assert "b.contradicting = append(b.contradicting, b.supporting...)" in s' \
  ./internal/diagnosis 'TestP05MissingIsNotContradiction|TestP08MissingEvidenceCannotRaiseConfidence'

echo
echo "--- convergence ---"

mutate B10 "the engine stops merging, so one conclusion is published twice" \
  internal/diagnosis/engine.go \
  's = s.replace("""	merged, err := Converge(produced)""",
"""	merged, err := func() ([]domain.Finding, error) {
		out := make([]domain.Finding, 0, len(produced))
		for _, af := range produced {
			out = append(out, af.Finding)
		}
		return out, nil
	}()""", 1)
assert "out = append(out, af.Finding)" in s' \
  ./test/diagnosis 'TestS08TwoRulesOneConclusionConverge'

mutate B11 "semantic identity drops the subject, so two endpoints merge into one" \
  internal/diagnosis/converge.go \
  's = s.replace("""	return SemanticIdentity{code: f.Code(), subject: f.Subject()}""",
"""	return SemanticIdentity{code: f.Code()}""", 1)
assert "SemanticIdentity{code: f.Code()}" in s' \
  ./test/diagnosis 'TestS09SameCodeDifferentSubjectStaysTwoResults|TestS03TwoBranchesFailingAtDifferentLayers'

# B11b was re-anchored in Phase 10.2A and made stronger.
#
# The mergeKey it edited was a one-line struct literal of (layer, discriminator);
# 10.2A widened it to (layer, summary, detail, discriminator) and added a
# belt-and-braces recheck inside mergeGroup, so the original single replacement
# no longer matched and the plant reported itself unplantable. Deleting it would
# have removed a live guard because an implementation changed shape.
#
# The plant now removes **both** halves of the layer precondition — the key and
# the recheck — which is a strictly harder mutation to catch than the original,
# since either alone would still refuse the merge.
mutate B11b "a differing Layer no longer prevents convergence" \
  internal/diagnosis/converge.go \
  's = s.replace("""		layer:         f.Layer(),""", """		layer:         domain.LayerUnspecified,""", 1)
assert "layer:         domain.LayerUnspecified," in s
s = s.replace("""		if af.Finding.Layer() != rep.Finding.Layer() {""",
"""		if false && af.Finding.Layer() != rep.Finding.Layer() {""", 1)
assert "if false && af.Finding.Layer()" in s' \
  ./internal/diagnosis 'TestMC02DifferentLayerMustNotConverge'

echo
echo "--- recommendation safety ---"

mutate B12 "a LOW hypothesis may carry a remediation" \
  internal/diagnosis/advice.go \
  's = s.replace("""	if kind != domain.FindingKindConfirmed || confidence != domain.ConfidenceHigh {""",
"""	if false {""", 1)
assert "\tif false {" in s' \
  ./test/diagnosis 'TestRecommendationMonotonicity'

mutate B13 "security-weakening advice becomes producible" \
  internal/diagnosis/advice.go \
  's = s.replace("""	case SafetyUnspecified, SafetyRestart, SafetyDisruptive, SafetySecurityWeakening:
		return false""",
"""	case SafetyRestart, SafetyDisruptive, SafetySecurityWeakening:
		return true
	case SafetyUnspecified:
		return false""", 1)
assert "SafetySecurityWeakening:\n\t\treturn true" in s' \
  ./internal/diagnosis 'TestDIAG034ThreeClassesAreUnreachable'

echo
echo "--- peer text, the renderer, and the exit contract ---"

mutate B14 "a peer-supplied evidence attribute is interpolated into the boundary prose" \
  internal/diagnosis/failureboundary.go \
  's = s.replace("""	detail := detailBoundaryMeaning""",
"""	detail := detailBoundaryMeaning
	for _, key := range []domain.AttributeKey{"peer.message"} {
		if v, ok := failing.Attribute(key); ok {
			detail += " " + v.String()
		}
	}""", 1)
assert "detail += \" \" + v.String()" in s' \
  ./test/diagnosis 'TestTheBoundaryProseIsIndependentOfEvidenceAttributes'

mutate B15 "the renderer computes a boundary for itself" \
  internal/render/terminal/report.go \
  's = s.replace("""func Write(w io.Writer, in render.Input) error {""",
"""func Write(w io.Writer, in render.Input) error {
	_ = LastConfirmedGood()""", 1)
assert "_ = LastConfirmedGood()" in s' \
  ./test/security 'TestDIAG014ARendererComputesNoBoundary'

mutate B16 "the boundary is ERROR, so it turns a clean run into a problem" \
  internal/diagnosis/failureboundary.go \
  's = s.replace("""		Severity:   domain.SeverityInfo,""",
"""		Severity:   domain.SeverityError,""", 1)
assert "Severity:   domain.SeverityError," in s' \
  ./test/diagnosis 'TestABoundaryDoesNotChangeAHealthyExitCode'

echo
echo "--- rule failure, ordering and monotonicity ---"

mutate B17 "a panicking rule is not recorded, so the run looks complete" \
  internal/diagnosis/engine.go \
  's = s.replace("""			out.failures = append(out.failures, RuleFailure{rule: rule.id})
			continue""", """			continue""", 1)
assert "out.failures = append(out.failures, RuleFailure{rule: rule.id})\n\t\t\tcontinue" not in s' \
  ./test/diagnosis 'TestARulePanicLosesOnlyThatRulesOutput'

# Canonical ordering is applied twice — once at the end of Converge and once by
# Evaluate. Removing either alone is an equivalent mutant, which the first run of
# this suite proved by leaving it standing. This plant removes both, because
# "canonical ordering is dropped" is one semantic change expressed at two call
# sites, and mutating half of a redundancy measures the redundancy rather than
# the contract.
mutate B18 "canonical ordering is dropped, so wiring order reaches the report" \
  internal/diagnosis/engine.go \
  's = s.replace("""	out.findings = merged
	domain.SortFindings(out.findings)
	return out""", """	out.findings = merged
	return out""", 1)
assert "out.findings = merged\n\treturn out" in s
other = "internal/diagnosis/converge.go"
c = open(other).read()
c = c.replace("""	domain.SortFindings(out)
	return out, nil""", """	return out, nil""", 1)
assert "domain.SortFindings(out)" not in c
open(other, "w").write(c)' \
  ./internal/diagnosis 'TestMC04RegistrationOrderCannotReachAnyCanonicalField|TestFindingOrderIsCanonicalNotRuleOrder'

mutate B19 "a boundary with no confirmed-good half invents one" \
  internal/diagnosis/boundary.go \
  's = s.replace("""		if nodes[i].State() == domain.StatePass && nodes[i].Layer() < failureLayer {""",
"""		if nodes[i].Layer() < failureLayer {""", 1)
assert "if nodes[i].Layer() < failureLayer {" in s' \
  ./test/diagnosis 'TestS06FirstMeasuredNodeFailingLeavesNoFabricatedLastGood|TestMonotonicEpistemicProperty'

mutate B20 "an unmeasured sibling is counted as one that passed" \
  internal/diagnosis/graphquery.go \
  's = s.replace("""		default:
			counts.notMeasured = append(counts.notMeasured, subject)""",
"""		default:
			counts.passed = append(counts.passed, subject)""", 1)
assert "counts.passed = append(counts.passed, subject)\n\t\t}" in s' \
  ./internal/diagnosis 'TestDIAG015SiblingCountingIsGeneric|TestNotMeasuredIsNeverFoldedIntoFailed'

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
  echo "PHASE 10.1B MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 10.1B MUTATION CLOSURE: 0 survivors"
