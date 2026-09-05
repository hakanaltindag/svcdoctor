#!/usr/bin/env bash
# Phase 10.2A mutation closure — convergence semantic safety.
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
# Phase 10.2A removed the RuleID tie-break from every merged field. These plants
# put each way back and require it to be caught:
#
#   C-M01  a differing layer merges
#   C-M02  a summary is chosen by rule identity
#   C-M03  a detail is chosen by rule identity
#   C-M04  a rename reaches the output through the recommendation union
#   C-M05  the Kafka mutual-exclusivity gate is removed
#   C-M06  incompatible discriminators merge
#   C-M07  different semantic subjects merge
#   C-M08  convergence loses evidence references
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/diagnosis/converge.go
  internal/diagnosis/kafka/topology.go
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

echo "Phase 10.2A mutation closure — convergence semantic safety"
echo
echo "--- the merge preconditions ---"

mutate C-M01 "a differing layer merges" \
  internal/diagnosis/converge.go \
  's = s.replace("""	return mergeKey{
		layer:         f.Layer(),""", """	return mergeKey{
		layer:         domain.LayerUnspecified,""", 1)
assert "layer:         domain.LayerUnspecified," in s
s = s.replace("""		if af.Finding.Layer() != rep.Finding.Layer() {""",
"""		if false && af.Finding.Layer() != rep.Finding.Layer() {""", 1)
assert "if false && af.Finding.Layer()" in s' \
  ./internal/diagnosis 'TestC02SameIdentityDifferentLayerDoesNotConverge|TestMC02'

mutate C-M02 "a summary is chosen by rule identity" \
  internal/diagnosis/converge.go \
  's = s.replace("""		summary:       f.Summary(),""", """		summary:       "",""", 1)
assert """summary:       "",""" in s
s = s.replace("""		if af.Finding.Summary() != rep.Finding.Summary() ||
			af.Finding.Detail() != rep.Finding.Detail() {""",
"""		if false {""", 1)
assert "if false {" in s
s = s.replace("""	rep := group[0]""",
"""	rep := slices.MinFunc(group, func(a, b AttributedFinding) int {
		return cmp.Compare(a.Rule, b.Rule)
	})""", 1)
assert "slices.MinFunc(group" in s' \
  ./internal/diagnosis 'TestC03SameIdentityMateriallyDifferentSummaryDoesNotConverge'

mutate C-M03 "a detail is chosen by rule identity" \
  internal/diagnosis/converge.go \
  's = s.replace("""		detail:        f.Detail(),""", """		detail:        "",""", 1)
assert """detail:        "",""" in s
s = s.replace("""		if af.Finding.Summary() != rep.Finding.Summary() ||
			af.Finding.Detail() != rep.Finding.Detail() {""",
"""		if false {""", 1)
assert "if false {" in s
s = s.replace("""	rep := group[0]""",
"""	rep := slices.MinFunc(group, func(a, b AttributedFinding) int {
		return cmp.Compare(a.Rule, b.Rule)
	})""", 1)
assert "slices.MinFunc(group" in s' \
  ./internal/diagnosis 'TestC04SameIdentityMateriallyDifferentDetailDoesNotConverge'

echo
echo "--- the rename property ---"

mutate C-M04 "a rename reaches the output through the recommendation union" \
  internal/diagnosis/converge.go \
  's = s.replace("""	slices.SortFunc(rest, func(a, b AttributedFinding) int {
		return compareByContent(a.Finding, b.Finding)
	})""",
"""	slices.SortFunc(rest, func(a, b AttributedFinding) int {
		return cmp.Compare(a.Rule, b.Rule)
	})""", 1)
assert "return cmp.Compare(a.Rule, b.Rule)" in s' \
  ./internal/diagnosis 'TestC06TheRenamePropertyHoldsForRecommendationOrderToo|TestC06ARuleIDRenameCannotChangeAnything'

echo
echo "--- the Kafka gate, and the net beneath it ---"

mutate C-M05 "the Kafka mutual-exclusivity gate is removed" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		if bySubject[exchange.Subject()] != 1 {
			continue
		}""", """		if bySubject[exchange.Subject()] < 1 {
			continue
		}""", 1)
assert "bySubject[exchange.Subject()] < 1 {" in s' \
  ./internal/diagnosis/kafka 'TestTwoExchangesSharingASubjectNeverConverge|TestTwoExchangesSharingOneSubjectProduceNothing'

echo
echo "--- the remaining canonical fields ---"

mutate C-M06 "incompatible discriminators merge" \
  internal/diagnosis/converge.go \
  's = s.replace("""		discriminator: f.Discriminator(),""", """		discriminator: "",""", 1)
assert """discriminator: "",""" in s
s = s.replace("""			if discriminator != "" && discriminator != got {""",
"""			if false {""", 1)
assert "if false {" in s' \
  ./internal/diagnosis 'TestMC05DifferingDiscriminatorsMustNotConverge'

mutate C-M07 "different semantic subjects merge" \
  internal/diagnosis/converge.go \
  's = s.replace("""func IdentityOf(f domain.Finding) SemanticIdentity {
	return SemanticIdentity{code: f.Code(), subject: f.Subject()}
}""",
"""func IdentityOf(f domain.Finding) SemanticIdentity {
	return SemanticIdentity{code: f.Code()}
}""", 1)
assert "SemanticIdentity{code: f.Code()}" in s' \
  ./test/diagnosis 'TestS09SameCodeDifferentSubjectStaysTwoResults'

mutate C-M08 "convergence loses evidence references" \
  internal/diagnosis/converge.go \
  's = s.replace("""		refs = append(refs, f.EvidenceRefs()...)""",
"""		if len(refs) == 0 {
			refs = append(refs, f.EvidenceRefs()...)
		}""", 1)
assert "if len(refs) == 0 {" in s' \
  ./internal/diagnosis 'TestC09TheEvidenceUnionIsDeterministicAndComplete|TestC01SameIdentityAndIdenticalProseConverges'

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
  echo "PHASE 10.2A MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 10.2A MUTATION CLOSURE: 0 survivors"
