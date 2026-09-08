#!/usr/bin/env bash
# Phase 12.1D mutation closure — the inert `step_timeout` refusal.
#
# # Why this suite is small, and why that is correct
#
# Phase 12.1D is a validation phase. Its output is an integration suite,
# documentation and a compatibility grade, none of which is production
# behaviour — and manufacturing production mutations for a phase that changed
# almost none would measure nothing.
#
# **One production change was made**: a Kubernetes fleet target now refuses a
# written `step_timeout` instead of accepting an inert one, which needed a
# "was it declared" signal on the generic Common. That change, and only that
# change, is mutated here. The behaviour every other phase guards is still
# guarded by that phase's own suite, and §43's historical re-runs cover the
# generic fleet code this touched.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is restored and verified byte-for-byte against sha256 checksums.
#
#   KD-M01  the refusal is removed entirely
#   KD-M02  the refusal reads the resolved value, so every target is refused
#   KD-M03  the declaration signal is hard-wired false, so nothing is refused
#   KD-M04  the declaration signal is hard-wired true, so every target is refused
#   KD-M05  the refusal is not a configuration error, so it would exit 3 not 2
#   KD-M06  the refusal is applied to every service rather than to this one
#   KD-M07  the refusal names no field, so an operator cannot find it
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/fleet/services/kubernetes/kubernetes.go
  internal/fleet/config/registry.go
  internal/fleet/config/load.go
)

for f in "${FILES[@]}"; do
  mkdir -p "$BACKUP/$(dirname "$f")"
  cp "$f" "$BACKUP/$f"
done

BEFORE="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
restore() { for f in "${FILES[@]}"; do cp "$BACKUP/$f" "$f"; done; }

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
SURVIVORS=()

mutate() {
  local id="$1" desc="$2" file="$3" script="$4" pkg="$5" regex="$6"

  local selected
  selected="$(go test "$pkg" -run "$regex" -count=1 -timeout 600s -v 2>/dev/null || true)"
  if ! grep -q '^=== RUN' <<<"$selected"; then
    echo "  $id  NO MATCHING TEST — the -run regex selects nothing: $regex"
    SURVIVORS+=("$id (no matching test: $regex)"); return
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
    SURVIVORS+=("$id (unplantable)"); restore; return
  fi

  if go test "$pkg" -run "$regex" -count=1 -timeout 600s >/dev/null 2>&1; then
    echo "  $id  SURVIVOR — $desc"
    SURVIVORS+=("$id $desc")
  else
    echo "  $id  caught    — $desc"
    PASS=$((PASS + 1))
  fi
  restore
}

echo "Phase 12.1D mutation closure — the inert step_timeout refusal"
echo

mutate KD-M01 "the refusal is removed entirely" \
  internal/fleet/services/kubernetes/kubernetes.go \
  's = s.replace("""	if err := checkInertStepTimeout(common); err != nil {
		return nil, err
	}
""", "", 1)
assert "checkInertStepTimeout(common)" not in s' \
  ./internal/fleet/services/kubernetes 'TestAWrittenStepTimeoutIsRefused'

mutate KD-M02 "the refusal reads the resolved value, so every target is refused" \
  internal/fleet/services/kubernetes/kubernetes.go \
  's = s.replace("	if !common.StepTimeoutDeclared {", "	if common.StepTimeout == 0 {", 1)
assert "common.StepTimeout == 0" in s' \
  ./internal/fleet/services/kubernetes 'TestTheDefaultStepTimeoutIsNotRefused'

mutate KD-M03 "the declaration signal is hard-wired false, so nothing is refused" \
  internal/fleet/config/load.go \
  's = s.replace("		StepTimeoutDeclared: block.StepTimeout != 0,",
                 "		StepTimeoutDeclared: false,", 1)
assert "StepTimeoutDeclared: false," in s' \
  ./internal/fleet/services/kubernetes 'TestAWrittenStepTimeoutIsRefused'

mutate KD-M04 "the declaration signal is hard-wired true, so every target is refused" \
  internal/fleet/config/load.go \
  's = s.replace("		StepTimeoutDeclared: block.StepTimeout != 0,",
                 "		StepTimeoutDeclared: true,", 1)
assert "StepTimeoutDeclared: true," in s' \
  ./internal/fleet/services/kubernetes 'TestTheDefaultStepTimeoutIsNotRefused'

mutate KD-M05 "the refusal is not a configuration error, so it would exit 3 not 2" \
  internal/fleet/services/kubernetes/kubernetes.go \
  's = s.replace("""	return config.InvalidField("step_timeout",
		"a Kubernetes target has no per-step budget""",
"""	return fmt.Errorf("%s", "step_timeout: " +
		"a Kubernetes target has no per-step budget""", 1)
s = s.replace("""			"the target%s own timeout, so this value would change nothing. Remove it, "+
			"and use timeout to bound the run")""" % chr(39),
"""			"the target%s own timeout, so this value would change nothing. Remove it, "+
			"and use timeout to bound the run")""" % chr(39), 1)
assert "fmt.Errorf" in s' \
  ./internal/fleet/services/kubernetes 'TestAWrittenStepTimeoutIsRefused'

mutate KD-M06 "the refusal is applied to every service rather than to this one" \
  internal/fleet/config/load.go \
  's = s.replace("""	common := Common{""",
"""	if block.StepTimeout != 0 {
		return Target{}, newError(CategoryInvalidField,
			"no service has a per-step budget").at("step_timeout")
	}

	common := Common{""", 1)
assert "no service has a per-step budget" in s' \
  ./internal/fleet/services/kubernetes 'TestTheOtherServicesStillAcceptAStepTimeout'

mutate KD-M07 "the refusal names no field, so an operator cannot find it" \
  internal/fleet/services/kubernetes/kubernetes.go \
  's = s.replace("	return config.InvalidField(\"step_timeout\",",
                 "	return config.InvalidField(\"config\",", 1)
assert "config.InvalidField(\"config\"," in s' \
  ./internal/fleet/services/kubernetes 'TestAWrittenStepTimeoutIsRefused'

echo
echo "--- restoration ---"
AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "  TREE NOT RESTORED"
  diff <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") || true
  SURVIVORS+=("tree not restored")
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
  echo "PHASE 12.1D MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 12.1D MUTATION CLOSURE: 0 survivors"
