#!/usr/bin/env bash
# Phase 10.4B mutation closure — structured next-evidence plumbing.
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
# The phase carried four semantic fields from diagnosis.Advice into the canonical
# report. Every plant below is a way of losing one of them, of losing the
# guardrails that protect them, or of building the thing Phase 10.4A forbade.
#
#   NBE-M01  the projection drops kind
#   NBE-M02  the projection drops safety
#   NBE-M03  the projection drops rationale
#   NBE-M04  the projection forces selfCollectable false
#   NBE-M05  the projection forces selfCollectable true
#   NBE-M06  NEXT_EVIDENCE and REMEDIATION are swapped
#   NBE-M07  two safety classes are swapped in the wire vocabulary
#   NBE-M08  redaction skips the rationale
#   NBE-M09  redaction drops the classification
#   NBE-M10  convergence collapses recommendations by action alone
#   NBE-M11  content ordering ignores the four new fields
#   NBE-M12  a half-classified recommendation is accepted
#   NBE-M13  an unreachable safety class reaches the report
#   NBE-M14  a refused suggestion is downgraded instead of dropped
#   NBE-M15  the renderer classifies an unclassified recommendation
#   NBE-M16  a hypothesis-grouping engine appears
#   NBE-M17  a service-local lossy projection helper returns
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/diagnosis/postgres/shared.go
  internal/domain/recommendation.go
  internal/domain/recommendationkind.go
  internal/diagnosis/advice.go
  internal/diagnosis/converge.go
  internal/security/redaction/redact.go
  internal/render/terminal/findings.go
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


echo "Phase 10.4B mutation closure — structured next-evidence plumbing"
echo
echo "--- the projection preserves every field (ADR 0082 section 2.1) ---"

# The four ways to lose a field on the way to the report. Each is exactly the
# defect Phase 10.4A measured: a projection that carries the action and drops
# the rest.
mutate NBE-M01 "the projection drops kind" \
  internal/diagnosis/advice.go \
  's = s.replace("""		Kind:            a.kind,""", """		Kind:            domain.RecommendationKindNextEvidence,""", 1)
assert "Kind:            domain.RecommendationKindNextEvidence," in s' \
  ./internal/diagnosis 'TestAdviceProjectionPreservesEveryField'

mutate NBE-M02 "the projection drops safety" \
  internal/diagnosis/advice.go \
  's = s.replace("""		Safety:          a.safety,""", """		Safety:          domain.SafetyObserve,""", 1)
assert "Safety:          domain.SafetyObserve," in s' \
  ./internal/diagnosis 'TestAdviceProjectionPreservesEveryField'

mutate NBE-M03 "the projection drops rationale" \
  internal/diagnosis/advice.go \
  's = s.replace("""		Rationale:       a.rationale,""", """		Rationale:       "unspecified",""", 1)
assert "Rationale:       \"unspecified\"," in s' \
  ./internal/diagnosis 'TestAdviceProjectionPreservesEveryField'

mutate NBE-M04 "the projection forces selfCollectable false" \
  internal/diagnosis/advice.go \
  's = s.replace("""		SelfCollectable: a.selfCollectable,""", """		SelfCollectable: false,""", 1)
assert "SelfCollectable: false," in s' \
  ./internal/diagnosis 'TestAdviceProjectionPreservesEveryField'

mutate NBE-M05 "the projection forces selfCollectable true" \
  internal/diagnosis/advice.go \
  's = s.replace("""		SelfCollectable: a.selfCollectable,""", """		SelfCollectable: a.kind == domain.RecommendationKindNextEvidence,""", 1)
assert "SelfCollectable: a.kind ==" in s' \
  ./internal/diagnosis 'TestAdviceProjectionPreservesEveryField'

echo
echo "--- the serialized vocabulary means what it says ---"

# A swapped wire name is invisible to every Go-level assertion that compares
# enum values, and is exactly what a consumer reads.
mutate NBE-M06 "NEXT_EVIDENCE and REMEDIATION are swapped" \
  internal/domain/recommendationkind.go \
  's = s.replace("""	RecommendationKindNextEvidence: "NEXT_EVIDENCE",
	RecommendationKindRemediation:  "REMEDIATION",""",
"""	RecommendationKindNextEvidence: "REMEDIATION",
	RecommendationKindRemediation:  "NEXT_EVIDENCE",""", 1)
assert "RecommendationKindNextEvidence: \"REMEDIATION\"," in s' \
  ./internal/domain 'TestAClassifiedRecommendationEncodesEveryField'

mutate NBE-M07 "two safety classes are swapped in the wire vocabulary" \
  internal/domain/recommendationkind.go \
  's = s.replace("""	SafetyObserve:           "OBSERVE",
	SafetyVerify:            "VERIFY",""",
"""	SafetyObserve:           "VERIFY",
	SafetyVerify:            "OBSERVE",""", 1)
assert "SafetyObserve:           \"VERIFY\"," in s' \
  ./internal/domain 'TestAClassifiedRecommendationEncodesEveryField'

echo
echo "--- redaction (ADR 0018) ---"

mutate NBE-M08 "redaction skips the rationale" \
  internal/security/redaction/redact.go \
  's = s.replace("""					Rationale:       t.text(r.Rationale()),""", """					Rationale:       r.Rationale(),""", 1)
assert "Rationale:       r.Rationale()," in s' \
  ./internal/security/redaction 'TestTheRationaleIsRedactedLikeEveryOtherProseField'

mutate NBE-M09 "redaction drops the classification" \
  internal/security/redaction/redact.go \
  's = s.replace("""			if r.Classified() {""", """			if false {""", 1)
assert "if false {" in s' \
  ./internal/security/redaction 'TestRedactionPreservesTheClassification'

echo
echo "--- convergence (ADR 0081 sections 2.2b and 2.6a) ---"

# The regression this phase existed to avoid: a five-field value deduplicated on
# one of its fields, publishing a classification no rule attached to that
# sentence.
mutate NBE-M10 "convergence collapses recommendations by action alone" \
  internal/diagnosis/converge.go \
  's = s.replace("""	seen := make(map[domain.Recommendation]struct{}, len(group))""",
"""	seen := make(map[string]struct{}, len(group))""", 1)
s = s.replace("""			if _, dup := seen[r]; dup {
				continue
			}
			seen[r] = struct{}{}""",
"""			if _, dup := seen[r.Action()]; dup {
				continue
			}
			seen[r.Action()] = struct{}{}""", 1)
assert "seen[r.Action()] = struct{}{}" in s' \
  ./internal/diagnosis 'TestRecommendationsCollapseOnlyOnFullSemanticEquality'

mutate NBE-M11 "content ordering ignores the four new fields" \
  internal/diagnosis/converge.go \
  's = s.replace("""		b.WriteString(r.Kind().String())""", """		b.WriteString("")""", 1)
assert "b.WriteString(\"\")" in s' \
  ./internal/diagnosis 'TestTheRecommendationUnionIsOrderInvariant'

echo
echo "--- the report-boundary guardrails (ADR 0082 section 2.3) ---"

mutate NBE-M12 "a half-classified recommendation is accepted" \
  internal/domain/recommendation.go \
  's = s.replace("""	if !in.Kind.Valid() {
		return Recommendation{}, fmt.Errorf(
			"%w: recommendation kind %s; a classified recommendation states its kind, "+
				"and an unclassified one is built with NewRecommendation",
			ErrInvalidValue, in.Kind)
	}""", """	if false {
		return Recommendation{}, nil
	}""", 1)
assert "if false {" in s' \
  ./internal/domain 'TestClassificationIsAllOrNothing'

mutate NBE-M13 "an unreachable safety class reaches the report" \
  internal/domain/recommendation.go \
  's = s.replace("""	if !in.Safety.Producible() {""", """	if false {""", 1)
assert "if false {" in s' \
  ./internal/domain 'TestTheThreeUnreachableClassesAreUnreachableAtTheReportBoundary'

mutate NBE-M14 "a refused suggestion is downgraded instead of dropped" \
  internal/diagnosis/advice.go \
  's = s.replace("""	if err := AdmitAdvice(kind, confidence, advice); err != nil {
		return nil
	}""", """	if err := AdmitAdvice(kind, confidence, advice); err != nil {
		r, rerr := domain.NewRecommendation(in.Action)
		if rerr != nil {
			return nil
		}
		return []domain.Recommendation{r}
	}""", 1)
assert "rerr != nil" in s' \
  ./internal/diagnosis 'TestRecommendRefusesRatherThanDowngrading'

echo
echo "--- the renderer explains and does not diagnose ---"

mutate NBE-M15 "the renderer classifies an unclassified recommendation" \
  internal/render/terminal/findings.go \
  's = s.replace("""	if !r.Classified() {
		return ""
	}""", """	if !r.Classified() {
		return "  [NEXT_EVIDENCE / OBSERVE]"
	}""", 1)
assert "[NEXT_EVIDENCE / OBSERVE]" in s' \
  ./internal/render/terminal 'TestTheRendererShowsClassificationWithoutDeciding'

echo
echo "--- what Phase 10.4A forbade (ADR 0086 sections 2.2a and 2.11) ---"

# NBE-044. The absence of a grouping engine is the phase's defining constraint,
# and an absence is exactly what gets filled in by accident.
mutate NBE-M16 "a hypothesis-grouping engine appears" \
  internal/diagnosis/converge.go \
  's = s.replace("""// ErrCannotConverge reports that a set of findings cannot be merged.""",
"""// IndistinguishableSets groups hypotheses by their discriminator.
func IndistinguishableSets(in []domain.Finding) map[string][]domain.Finding {
	out := map[string][]domain.Finding{}
	for _, f := range in {
		if f.Discriminator() != "" {
			out[f.Discriminator()] = append(out[f.Discriminator()], f)
		}
	}
	return out
}

// ErrCannotConverge reports that a set of findings cannot be merged.""", 1)
assert "func IndistinguishableSets" in s' \
  ./test/security 'TestNoHypothesisGroupingEngineExists|TestTheDiscriminatorIsNotAGroupingKey'

# Planted where it was deleted from, which is where a service author would put it
# back: a local helper that quietly returns to the action-only shape.
mutate NBE-M17 "a service-local lossy projection helper returns" \
  internal/diagnosis/postgres/shared.go \
  's = s.replace("""// recommend wraps one action""",
"""// projectAdvice is the helper Phase 10.4B deleted.
func projectAdvice(action string) []domain.Recommendation {
	r, err := domain.NewRecommendation(action)
	if err != nil {
		return nil
	}
	return []domain.Recommendation{r}
}

// recommend wraps one action""", 1)
assert "func projectAdvice" in s' \
  ./test/security 'TestNoServiceLocalAdviceProjectionHelperExists'

echo
echo "--- restoration ---"
AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "  TREE NOT RESTORED — refusing to report success"
  diff <(echo "$BEFORE") <(echo "$AFTER") || true
  exit 1
fi
echo "  tree restored byte-for-byte"

rm -rf "$BACKUP"
trap - EXIT

echo
echo "planted $((PASS + FAIL))  caught $PASS  survivors $FAIL"
if [ "$FAIL" -ne 0 ]; then
  for s in "${SURVIVORS[@]}"; do echo "  $s"; done
  echo
  echo "PHASE 10.4B MUTATION CLOSURE: FAILED"
  exit 1
fi
echo
echo "PHASE 10.4B MUTATION CLOSURE: 0 survivors"
