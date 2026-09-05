#!/usr/bin/env bash
# Phase 10.1A mutation closure — the diagnostic reasoning core.
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
# The fifteen load-bearing contracts of ADRs 0078-0083, chosen because each is a
# claim the product makes that nothing downstream would notice going wrong. A
# rule that reads UNKNOWN as FAIL produces a well-formed report, a valid exit
# code, and a lie.
#
#   M01-M04  the epistemic contracts: UNKNOWN, SKIPPED, missing, blocked
#   M05-M06  confidence: contradiction lowers, convergence does not accumulate
#   M07-M08  determinism and identity: sorting, duplicate rule identities
#   M09-M10  validation and merge: dangling references, distinct subjects
#   M11-M12  the failure boundary: graph order, blocked descendants
#   M13-M14  immutability and recommendation safety
#   M15      the architectural boundary: a service name in the generic core
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/diagnosis/engine.go
  internal/diagnosis/outcome.go
  internal/diagnosis/registry.go
  internal/diagnosis/basis.go
  internal/diagnosis/confidence.go
  internal/diagnosis/converge.go
  internal/diagnosis/boundary.go
  internal/diagnosis/graphquery.go
  internal/diagnosis/validate.go
  internal/diagnosis/advice.go
  internal/diagnosis/rulecontext.go
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

echo "Phase 10.1A mutation closure — the diagnostic reasoning core"
echo
echo "--- the epistemic contracts: not measured is not failed ---"

# M01/M02 are planted in the boundary, because that is the one place in this
# phase where a state is *interpreted* rather than transcribed. A rule that
# upgraded a state would be a defect in that rule; the boundary doing it would be
# a defect in the model.
mutate M01 "UNKNOWN is treated as an evidenced failure" \
  internal/diagnosis/boundary.go \
  's = s.replace("""		if node.State() == domain.StateFail || node.State() == domain.StateDegraded {""",
"""		if node.State() == domain.StateFail || node.State() == domain.StateDegraded ||
			node.State() == domain.StateUnknown {""", 1)
assert "node.State() == domain.StateUnknown {" in s' \
  ./internal/diagnosis 'TestDIAG012AnUnknownIsNeitherHalf|TestP13CancellationFabricatesNoBoundary'

mutate M02 "SKIPPED is treated as an evidenced failure" \
  internal/diagnosis/boundary.go \
  's = s.replace("""		if node.State() == domain.StateFail || node.State() == domain.StateDegraded {""",
"""		if node.State() == domain.StateFail || node.State() == domain.StateDegraded ||
			node.State() == domain.StateSkipped {""", 1)
assert "node.State() == domain.StateSkipped {" in s' \
  ./internal/diagnosis 'TestASkippedStepAboveTheFailureIsNotTheFailure'

mutate M03 "a missing observation is recorded as contradicting evidence" \
  internal/diagnosis/basis.go \
  's = s.replace("""// Miss records an observation that was never made and would discriminate.
func (b *BasisBuilder) Miss(steps ...domain.Step) *BasisBuilder {
	b.missing = append(b.missing, steps...)""",
"""// Miss records an observation that was never made and would discriminate.
func (b *BasisBuilder) Miss(steps ...domain.Step) *BasisBuilder {
	for range steps {
		b.contradicting = append(b.contradicting, b.supporting...)
	}
	b.missing = append(b.missing, steps...)""", 1)
assert "b.contradicting = append(b.contradicting, b.supporting...)" in s' \
  ./internal/diagnosis 'TestP05MissingIsNotContradiction|TestP08MissingEvidenceCannotRaiseConfidence'

mutate M04 "a blocked step may be cited as evidence for or against a claim" \
  internal/diagnosis/basis.go \
  's = s.replace("""			if len(g.BlockedBy(id)) > 0 {
				return EvidenceBasis{}, fmt.Errorf(""",
"""			if false && len(g.BlockedBy(id)) > 0 {
				return EvidenceBasis{}, fmt.Errorf(""", 1)
assert "if false && len(g.BlockedBy(id)) > 0 {" in s' \
  ./internal/diagnosis 'TestP06BlockedEvidenceIsNotSupportOrContradiction'

echo
echo "--- confidence: ordinal, never a score ---"

mutate M05 "contradicting evidence raises confidence instead of capping it" \
  internal/diagnosis/confidence.go \
  's = s.replace("""	if len(basis.contradicting) > 0 {
		return domain.ConfidenceLow, nil
	}""",
"""	if len(basis.contradicting) > 0 {
		return domain.ConfidenceHigh, nil
	}""", 1)
assert "return domain.ConfidenceHigh, nil\n	}" in s' \
  ./internal/diagnosis 'TestP07ContradictionCannotRaiseConfidence'

mutate M06a "weak convergence votes itself up to HIGH" \
  internal/diagnosis/confidence.go \
  's = s.replace("""		if len(basis.supporting) >= 2 {
			return domain.ConfidenceMedium, nil
		}""",
"""		if len(basis.supporting) >= 3 {
			return domain.ConfidenceHigh, nil
		}
		if len(basis.supporting) >= 2 {
			return domain.ConfidenceMedium, nil
		}""", 1)
assert "if len(basis.supporting) >= 3 {" in s' \
  ./internal/diagnosis 'TestP09MultipleWeakSupportsCannotVoteToHigh'

mutate M06b "convergence accumulates confidence on merge" \
  internal/diagnosis/converge.go \
  's = s.replace("""		in.Confidence = max(in.Confidence, f.Confidence())""",
"""		if in.Confidence < domain.ConfidenceHigh {
			in.Confidence++
		}""", 1)
assert "in.Confidence++" in s' \
  ./internal/diagnosis 'TestDIAG026ConfidenceDoesNotAccumulate'

echo
echo "--- determinism and identity ---"

# Canonical ordering is applied twice as of Phase 10.1b: once at the end of
# Converge, which Evaluate now calls, and once by Evaluate itself. Removing
# either alone became an equivalent mutant the day convergence was activated, and
# this suite caught the regression by leaving M07 standing. The plant removes
# both, because "canonical ordering is dropped" is one semantic change expressed
# at two call sites.
mutate M07 "the canonical sort is removed, so wiring order reaches the report" \
  internal/diagnosis/engine.go \
  's = s.replace("""	domain.SortFindings(out.findings)
	return out""", """	return out""", 1)
assert "domain.SortFindings(out.findings)" not in s
other = "internal/diagnosis/converge.go"
c = open(other).read()
c = c.replace("""	domain.SortFindings(out)
	return out, nil""", """	return out, nil""", 1)
assert "domain.SortFindings(out)" not in c
open(other, "w").write(c)' \
  ./internal/diagnosis 'TestFindingOrderIsCanonicalNotRuleOrder|TestP02RuleRegistrationPermutationDoesNotChangeResult'

mutate M08 "a duplicate rule identity is accepted, so one rule shadows another" \
  internal/diagnosis/registry.go \
  's = s.replace("""	if _, exists := s.seen[ruleID]; exists {
		s.err = fmt.Errorf("%w: rule %q is already registered", ErrInvalidRuleSet, ruleID)
		return s
	}""", """	_ = s.seen""", 1)
s = s.replace("""		if _, dup := seen[r.id]; dup {
			return Registry{}, fmt.Errorf(
				"%w: rule %q is registered twice", ErrInvalidRuleSet, r.id)
		}""", """		_ = seen""", 1)
assert "is already registered" not in s and "is registered twice" not in s' \
  ./internal/diagnosis 'TestDIAG021DuplicateRuleIDIsRejected|TestDuplicateIsRejectedEvenWhenTheRuleIsTheSameFunction'

echo
echo "--- validation and merge ---"

mutate M09 "a finding citing evidence that is not in the graph is accepted" \
  internal/diagnosis/validate.go \
  's = s.replace("""		if _, ok := g.Node(ref); !ok {""", """		if _, ok := g.Node(ref); false && !ok {""", 1)
assert "if _, ok := g.Node(ref); false && !ok {" in s' \
  ./internal/diagnosis 'TestDIAG042InvalidRuleOutputIsRejectedNotRepaired'

mutate M09b "the basis accepts a citation the graph does not contain" \
  internal/diagnosis/basis.go \
  's = s.replace("""		if _, ok := g.Node(id); !ok {""", """		if _, ok := g.Node(id); false && !ok {""", 1)
assert "if _, ok := g.Node(id); false && !ok {" in s' \
  ./internal/diagnosis 'TestP14EveryCitedNodeMustResolve'

mutate M10 "semantic identity drops the subject, so different subjects merge" \
  internal/diagnosis/converge.go \
  's = s.replace("""func IdentityOf(f domain.Finding) SemanticIdentity {
	return SemanticIdentity{code: f.Code(), subject: f.Subject()}
}""",
"""func IdentityOf(f domain.Finding) SemanticIdentity {
	return SemanticIdentity{code: f.Code()}
}""", 1)
assert "SemanticIdentity{code: f.Code()}" in s' \
  ./internal/diagnosis 'TestP11SeparateSubjectsRemainSeparate|TestDIAG024IdentityIsCodeAndSubject'

mutate M10b "identity is derived from the summary, so a reworded claim splits" \
  internal/diagnosis/converge.go \
  's = s.replace("""	return SemanticIdentity{code: f.Code(), subject: f.Subject()}""",
"""	return SemanticIdentity{code: domain.FindingCode(f.Summary()), subject: f.Subject()}""", 1)
assert "domain.FindingCode(f.Summary())" in s' \
  ./internal/diagnosis 'TestDIAG024IdentityIsCodeAndSubject'

echo
echo "--- the failure boundary ---"

mutate M11 "the boundary is computed from insertion order rather than layer order" \
  internal/diagnosis/graphquery.go \
  's = s.replace("""	sortByLayer(out)
	return out
}""", """	return out
}""", 1)
assert "sortByLayer(out)\n\treturn out" not in s' \
  ./internal/diagnosis 'TestNodesForSubjectIsInLayerOrder|TestTheBoundaryFollowsLayerOrderNotIdentifierOrder'

mutate M11b "the confirmed-good half may sit below the failure" \
  internal/diagnosis/boundary.go \
  's = s.replace("""		if nodes[i].State() == domain.StatePass && nodes[i].Layer() < failureLayer {""",
"""		if nodes[i].State() == domain.StatePass {""", 1)
s = s.replace("""	failureLayer := nodes[failureIndex].Layer()
	for i := failureIndex - 1; i >= 0; i-- {""",
"""	_ = nodes[failureIndex].Layer()
	for i := len(nodes) - 1; i >= 0; i-- {""", 1)
assert "for i := len(nodes) - 1; i >= 0; i-- {" in s' \
  ./internal/diagnosis 'TestAPassBelowTheFailureIsNotTheLastConfirmedGood'

mutate M12 "a blocked descendant is folded into the failed sibling count" \
  internal/diagnosis/graphquery.go \
  's = s.replace("""		case domain.StatePass:
			counts.passed = append(counts.passed, subject)
		default:
			counts.notMeasured = append(counts.notMeasured, subject)""",
"""		case domain.StatePass:
			counts.passed = append(counts.passed, subject)
		default:
			counts.failed = append(counts.failed, subject)""", 1)
assert "counts.failed = append(counts.failed, subject)\n		}" in s' \
  ./internal/diagnosis 'TestNotMeasuredIsNeverFoldedIntoFailed|TestDIAG015SiblingCountingIsGeneric'

echo
echo "--- immutability, advice safety, and the architectural boundary ---"

# The first version of M13 replaced `slices.Clip(out)` with the builder's own
# slice in Freeze, and it survived. That was not a gap in the guards: it is an
# **equivalent mutant**. A slice header is copied by value, so a later Add cannot
# change the registry's length, and every accessor either clones or reads — no
# path appends into the shared spare capacity. The Clip is defensive and its
# removal is unobservable, so a test could only "catch" it by asserting an
# implementation detail. It was replaced by the mutation below, which targets the
# same contract at the place the aliasing is actually reachable.
mutate M13 "an outcome hands out its own findings slice" \
  internal/diagnosis/outcome.go \
  's = s.replace("""	return slices.Clone(o.findings)
}""", """	return o.findings
}""", 1)
assert "return o.findings\n}" in s' \
  ./internal/diagnosis 'TestAnOutcomeHandsOutCopies'

mutate M13b "a registry hands out its own slice instead of a copy" \
  internal/diagnosis/registry.go \
  's = s.replace("""	return slices.Clone(r.rules)
}""", """	return r.rules
}""", 1)
assert "return r.rules\n}" in s' \
  ./internal/diagnosis 'TestP16AFrozenRegistryIsImmutable'

mutate M14 "the confidence gate on remediation is dropped" \
  internal/diagnosis/advice.go \
  's = s.replace("""	if kind != domain.FindingKindConfirmed || confidence != domain.ConfidenceHigh {""",
"""	if false {""", 1)
assert "\tif false {" in s' \
  ./internal/diagnosis 'TestDIAG035RemediationRequiresConfirmedAndHigh'

mutate M14b "an unreachable safety class becomes producible" \
  internal/diagnosis/advice.go \
  's = s.replace("""	case SafetyUnspecified, SafetyRestart, SafetyDisruptive, SafetySecurityWeakening:
		return false""",
"""	case SafetyRestart, SafetyDisruptive, SafetySecurityWeakening:
		return true
	case SafetyUnspecified:
		return false""", 1)
assert "SafetySecurityWeakening:\n\t\treturn true" in s' \
  ./internal/diagnosis 'TestDIAG034ThreeClassesAreUnreachable'

mutate M14c "an executable command is accepted as a recommendation" \
  internal/diagnosis/advice.go \
  's = s.replace("""	if idx := strings.IndexAny(action, shellMetacharacters); idx >= 0 {""",
"""	if idx := strings.IndexAny(action, shellMetacharacters); false && idx >= 0 {""", 1)
s = s.replace("""	if _, banned := commandWords[lowered]; banned {""",
"""	if _, banned := commandWords[lowered]; false && banned {""", 1)
assert "false && idx >= 0 {" in s and "false && banned {" in s' \
  ./internal/diagnosis 'TestDIAG036NoRecommendationIsAnExecutableCommand'

mutate M15 "a service name is planted in the generic core" \
  internal/diagnosis/graphquery.go \
  's = s.replace("""func Subjects(g domain.Graph) []domain.Subject {""",
"""const kafkaDiscoveryStep = "kafka.broker_advertised"

func Subjects(g domain.Graph) []domain.Subject {""", 1)
assert "kafkaDiscoveryStep" in s' \
  ./test/security 'TestDIAG019TheGenericCoreNamesNoService'

mutate M15b "the generic core reaches into a service rule package" \
  internal/diagnosis/rulecontext.go \
  's = s.replace("""import "github.com/hakanaltindag/svcdoctor/internal/domain\"""",
"""import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

var _ = servicekafka.StepMetadata""", 1)
assert "servicekafka" in s' \
  ./test/security 'TestDIAG019TheGenericCoreNamesNoService|TestDIAG023AddingAServiceEditsNoGenericFile'

mutate M16 "RuleContext grows a field that would let a rule reach a clock" \
  internal/diagnosis/rulecontext.go \
  's = s.replace("""	Incomplete bool
}""", """	Incomplete bool

	// Now is the wall-clock instant the run started.
	Now int64
}""", 1)
assert "Now int64" in s' \
  ./test/security 'TestDIAG017RuleContextCarriesExactlyThreeFields'

mutate M17 "production drops the rule-failure list by calling Diagnose" \
  internal/diagnosis/engine.go \
  's = s.replace("""func (e Engine) Evaluate(ctx RuleContext) Outcome {""",
"""func (e Engine) EvaluateUnused(ctx RuleContext) Outcome {""", 1)
s = s.replace("""func (e Engine) Diagnose(ctx RuleContext) []domain.Finding {
	return e.Evaluate(ctx).findings
}""",
"""func (e Engine) Diagnose(ctx RuleContext) []domain.Finding {
	return e.EvaluateUnused(ctx).findings
}

// Evaluate is retained so the composition roots still compile.
func (e Engine) Evaluate(ctx RuleContext) Outcome {
	return Outcome{findings: e.Diagnose(ctx)}
}""", 1)
assert "EvaluateUnused" in s' \
  ./internal/diagnosis 'TestDIAG041APanickingRuleLosesItsOutputAndTheRunContinues|TestARuleFailureNeverBecomesAFinding'

mutate M18 "a panicking rule takes the whole run down instead of losing its output" \
  internal/diagnosis/engine.go \
  's = s.replace("""	defer func() {
		if r := recover(); r != nil {
			findings, ok = nil, false
		}
	}()""", """	// no recovery""", 1)
assert "recover()" not in s' \
  ./internal/diagnosis 'TestDIAG041APanickingRuleLosesItsOutputAndTheRunContinues'

mutate M19 "a panicking rule keeps the findings it produced before failing" \
  internal/diagnosis/engine.go \
  's = s.replace("""		if r := recover(); r != nil {
			findings, ok = nil, false
		}""", """		if r := recover(); r != nil {
			ok = true
		}""", 1)
assert "ok = true\n		}" in s' \
  ./internal/diagnosis 'TestDIAG041APanickingRuleLosesItsOutputAndTheRunContinues|TestARuleFailureNeverBecomesAFinding'

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
  echo "PHASE 10.1A MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 10.1A MUTATION CLOSURE: 0 survivors"
