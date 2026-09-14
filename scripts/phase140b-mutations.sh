#!/usr/bin/env bash
# Phase 14.0B mutation closure — hosted integration CI and release gates.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is restored and verified byte-for-byte against sha256 checksums
# taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it.
#
# # What this phase's mutations are actually about
#
# Every other harness in this directory plants in production Go and asks whether
# a test notices. Most of this one plants in *workflow configuration* and asks
# whether the release gate still exists — because ADR 0098 §2.3 defines "gates
# release publication" as a property of the `needs:` graph, and a gate that can
# be removed without a red test is a gate nobody is keeping.
#
# The exception is the break-it proof (Phase 14.0A §29), which plants in
# production wire code and asks whether the *integration lane itself* fails.
# A workflow that runs a suite which cannot fail is decoration, so three families
# are required:
#
#   FAMILY A  Redis/Valkey        a broken RESP PING must fail integration-valkey
#   FAMILY B  RabbitMQ/LavinMQ    a broken AMQP header must fail integration-lavinmq
#   FAMILY C  Multi-target        the gate's removal and bypass must be caught
#
# Family C is proved through its guards rather than through its suite. The
# multi-target suite cannot run on this machine — an unrelated developer
# container holds host port 55434, which the PostgreSQL fixture binds — and
# Phase 14.0A §29 admits the guard half ("and/or the relevant workflow contract
# test catches removal/bypass of the target") for exactly this reason. MC-05,
# MC-06 and MC-08 are that proof: the lane cannot be dropped from main, cannot be
# smuggled onto pull requests, and cannot leave the release matrix.
#
# # Restoration is verified three ways, and the last two are the point
#
# Phase 13.1B's harness kept a FILES list by hand, backed up from it, restored
# from it — and verified from it. Two plants touched files absent from that list,
# so `restore()` never saw them and the harness still reported "all files
# restored byte-for-byte", because it only ever checked what it already knew
# about.
#
# So this script proves restoration three independent ways:
#
#   1. FILES, the declared write-set, compared before and after.
#   2. **Every tracked file**, enumerated by `git ls-files`, which knows nothing
#      about FILES. This is the definition of repository state.
#   3. **Every path in the worktree**, enumerated by `find`. A plant that creates
#      a new file is invisible to (1) and (2) and caught by (3).
#
# It also asserts that every file a plant names is in FILES, so the two cannot
# drift apart silently in the first place.
#
# Check (2) hashes content; check (3) compares the set of paths. Neither hashes
# the gitignored `test/integration/*/env/certs/` directories: that is throwaway
# TLS material the fixtures regenerate on expiry, it is never tracked, and it is
# never restored — so hashing it would report a false mutation on the day a
# certificate rolls over. Nothing is planted there.
#
# No git stash, reset, checkout or restore is used anywhere: the user owns the
# history and a harness that reaches for it can destroy uncommitted work.
#
# # What this covers
#
#   MC-01  Redis loses its hosted lane
#   MC-02  Valkey loses its hosted lane
#   MC-03  RabbitMQ loses its hosted lane
#   MC-04  LavinMQ loses its hosted lane
#   MC-05  multi-target loses its main/schedule/dispatch lane
#   MC-06  multi-target is smuggled onto pull requests
#   MC-07  Redis leaves the release matrix
#   MC-08  multi-target leaves the release matrix
#   MC-09  the integration -> stage-and-verify edge is cut
#   MC-10  continue-on-error is added to a required lane
#   MC-11  workflow permissions are escalated
#   MC-12  a path filter is added
#   MC-13  the runner changes away from ubuntu-24.04
#   MC-14  a lane's required timeout is removed
#   MC-15  pull_request_target is introduced
#   MC-16  a repository secret is referenced
#   MC-17  the canonical make target is replaced by inline YAML
#   MC-18  an image pin loses its digest
#   MC-19  the weekly schedule changes
#   MC-20  unconditional teardown is dropped
#   MC-21  an action is unpinned
#   MC-22  the frozen check identity changes
#   MC-23  concurrency cancels scheduled and main runs
#   MC-24  the RabbitMQ bytecode guard is reverted
#   MC-25  the generated-bytecode ignore rule is removed
#   MC-26  the release matrix becomes fail-fast
#   MC-27  FAMILY A — a broken RESP PING must fail integration-valkey
#   MC-28  FAMILY B — a broken AMQP header must fail integration-lavinmq
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  .github/workflows/integration.yml
  .github/workflows/release-oci.yml
  .gitignore
  test/integration/rabbitmq/env/probe.py
  test/integration/redis/env/compose.yaml
  internal/adapter/redis/wire/conn.go
  internal/adapter/rabbitmq/wire/frame.go
)

for f in "${FILES[@]}"; do
  mkdir -p "$BACKUP/$(dirname "$f")"
  cp "$f" "$BACKUP/$f"
done

# (1) the declared write-set.
BEFORE="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"

# (2) every tracked file, from git rather than from FILES.
tracked_hash() { git ls-files -z | xargs -0 shasum -a 256 2>/dev/null | sort; }
TRACKED_BEFORE="$BACKUP/.tracked-before"
tracked_hash > "$TRACKED_BEFORE"

# (3) every path in the worktree, from the filesystem rather than from FILES.
tree_paths() {
  find . -type f -not -path './.git/*' -not -path './bin/*' \
    -not -path '*/env/certs/*' -print | LC_ALL=C sort
}
TREE_BEFORE="$BACKUP/.tree-before"
tree_paths > "$TREE_BEFORE"

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
SURVIVORS=()

declared() {
  local file="$1" f
  for f in "${FILES[@]}"; do [ "$f" = "$file" ] && return 0; done
  return 1
}

plant() {
  local file="$1" script="$2"
  python3 - "$file" <<PY
import sys
path = sys.argv[1]
s = open(path).read()
$script
open(path, 'w').write(s)
PY
}

# mutate <id> <description> <file> <python-replacement> <test-package> <test-regex>
mutate() {
  local id="$1" desc="$2" file="$3" script="$4" pkg="$5" regex="$6"

  # The declared write-set must contain every file a plant names. This is what
  # keeps check (1) honest; checks (2) and (3) catch it anyway, but later and
  # with less to say about which plant did it.
  if ! declared "$file"; then
    echo "  $id  UNDECLARED TARGET — $file is not in FILES, so restoration is unproven"
    SURVIVORS+=("$id (undeclared target: $file)"); return
  fi

  # A -run regex that selects no test makes `go test` exit 0, which this harness
  # would read as a pass. Checked on the pristine tree, before planting.
  #
  # A here-string rather than a pipe: `grep -q` exits at its first match, and
  # under `pipefail` the SIGPIPE that sends `printf` becomes the pipeline's
  # status, so a large selection was reported as no selection at all. Phase 10.2
  # measured that in every harness in this directory.
  local selected
  selected="$(go test "$pkg" -run "$regex" -count=1 -timeout 600s -v 2>/dev/null || true)"
  if ! grep -q '^=== RUN' <<<"$selected"; then
    echo "  $id  NO MATCHING TEST — the -run regex selects nothing: $regex"
    SURVIVORS+=("$id (no matching test: $regex)"); return
  fi

  # And it must pass on the pristine tree, or "it failed after the plant" says
  # nothing about the plant.
  if ! go test "$pkg" -run "$regex" -count=1 -timeout 600s >/dev/null 2>&1; then
    echo "  $id  ALREADY RED — the guard fails before the plant: $regex"
    SURVIVORS+=("$id (already red: $regex)"); return
  fi

  if ! plant "$file" "$script"; then
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

# breakit <id> <description> <file> <python-replacement> <make-target>
#
# The Phase 14.0A §29 proof. Unlike `mutate`, the thing that must turn red is the
# integration lane itself: this is what distinguishes a lane that executes
# meaningful work from one that merely exits 0.
breakit() {
  local id="$1" desc="$2" file="$3" script="$4" target="$5"

  if ! declared "$file"; then
    echo "  $id  UNDECLARED TARGET — $file is not in FILES, so restoration is unproven"
    SURVIVORS+=("$id (undeclared target: $file)"); return
  fi

  # Non-vacuity: the lane must be green on the pristine tree first. A lane that
  # was already failing proves nothing when it fails again.
  if ! make "$target" >/dev/null 2>&1; then
    echo "  $id  ALREADY RED — $target fails before the plant"
    SURVIVORS+=("$id (already red: $target)"); return
  fi

  if ! plant "$file" "$script"; then
    echo "  $id  COULD NOT PLANT — the anchor text is gone: $desc"
    SURVIVORS+=("$id (unplantable)"); restore; return
  fi

  if make "$target" >/dev/null 2>&1; then
    echo "  $id  SURVIVOR — $desc"
    SURVIVORS+=("$id $desc")
  else
    echo "  $id  caught    — $desc"
    PASS=$((PASS + 1))
  fi
  restore

  # The lane left a fixture running when it failed, because `make` stops at the
  # failing target. This is the same teardown the workflow's `if: always()` step
  # performs, and it is why that step exists.
  make "${target#integration-}-down" >/dev/null 2>&1 || true
}

CLI=./internal/cli

echo "Phase 14.0B mutation closure — hosted integration CI and release gates"
echo
echo "--- the hosted lanes (Phase 14.0A section 10) ---"

mutate MC-01 "Redis loses its hosted lane" \
  .github/workflows/integration.yml \
  's = s.replace(chr(123)+chr(34)+"suite"+chr(34)+":"+chr(34)+"redis"+chr(34)+","+chr(34)+"timeout"+chr(34)+":25"+chr(125)+",", "", 2)
assert chr(34)+"redis"+chr(34) not in s' \
  "$CLI" 'TestTheIntegrationMatrixIsEventDependentExactlyAsFrozen'

mutate MC-02 "Valkey loses its hosted lane" \
  .github/workflows/integration.yml \
  's = s.replace(chr(123)+chr(34)+"suite"+chr(34)+":"+chr(34)+"valkey"+chr(34)+","+chr(34)+"timeout"+chr(34)+":25"+chr(125)+",", "", 2)
assert chr(34)+"valkey"+chr(34) not in s' \
  "$CLI" 'TestTheIntegrationMatrixIsEventDependentExactlyAsFrozen'

mutate MC-03 "RabbitMQ loses its hosted lane" \
  .github/workflows/integration.yml \
  's = s.replace(chr(123)+chr(34)+"suite"+chr(34)+":"+chr(34)+"rabbitmq"+chr(34)+","+chr(34)+"timeout"+chr(34)+":30"+chr(125)+",", "", 2)
assert chr(34)+"rabbitmq"+chr(34) not in s' \
  "$CLI" 'TestTheIntegrationMatrixIsEventDependentExactlyAsFrozen'

mutate MC-04 "LavinMQ loses its hosted lane" \
  .github/workflows/integration.yml \
  's = s.replace(","+chr(123)+chr(34)+"suite"+chr(34)+":"+chr(34)+"lavinmq"+chr(34)+","+chr(34)+"timeout"+chr(34)+":25"+chr(125), "", 2)
assert chr(34)+"lavinmq"+chr(34) not in s' \
  "$CLI" 'TestTheIntegrationMatrixIsEventDependentExactlyAsFrozen'

echo
echo "--- FAMILY C: the multi-target gate (Phase 14.0A sections 10 and 23) ---"

mutate MC-05 "multi-target loses its main/schedule/dispatch lane" \
  .github/workflows/integration.yml \
  's = s.replace(","+chr(123)+chr(34)+"suite"+chr(34)+":"+chr(34)+"multitarget"+chr(34)+","+chr(34)+"timeout"+chr(34)+":40"+chr(125), "", 1)
assert chr(34)+"multitarget"+chr(34) not in s' \
  "$CLI" 'TestTheIntegrationMatrixIsEventDependentExactlyAsFrozen'

mutate MC-06 "multi-target is smuggled onto pull requests" \
  .github/workflows/integration.yml \
  'old = chr(34)+"suite"+chr(34)+":"+chr(34)+"lavinmq"+chr(34)+","+chr(34)+"timeout"+chr(34)+":25"+chr(125)+chr(93)
new = chr(34)+"suite"+chr(34)+":"+chr(34)+"lavinmq"+chr(34)+","+chr(34)+"timeout"+chr(34)+":25"+chr(125)+","+chr(123)+chr(34)+"suite"+chr(34)+":"+chr(34)+"multitarget"+chr(34)+","+chr(34)+"timeout"+chr(34)+":40"+chr(125)+chr(93)
assert s.count(old) == 1
s = s.replace(old, new, 1)' \
  "$CLI" 'TestTheIntegrationMatrixIsEventDependentExactlyAsFrozen'

mutate MC-08 "multi-target leaves the release matrix" \
  .github/workflows/release-oci.yml \
  's = s.replace(", multitarget]", "]", 1)
assert "multitarget]" not in s' \
  "$CLI" 'TestEveryGatedSuiteBlocksPublication|TestOCIPublicationCannotStartBeforeLinuxIntegration'

echo
echo "--- the release gate (ADR 0098 section 2.3) ---"

mutate MC-07 "Redis leaves the release matrix" \
  .github/workflows/release-oci.yml \
  'old = "suite: [postgres, kafka, redpanda, redis, valkey, rabbitmq, lavinmq, multitarget]"
assert s.count(old) == 1
s = s.replace(old, "suite: [postgres, kafka, redpanda, valkey, rabbitmq, lavinmq, multitarget]", 1)' \
  "$CLI" 'TestEveryGatedSuiteBlocksPublication|TestOCIPublicationCannotStartBeforeLinuxIntegration'

mutate MC-09 "the integration -> stage-and-verify edge is cut" \
  .github/workflows/release-oci.yml \
  's = s.replace("needs: [identity, source, integration, kubernetes]", "needs: [identity, source, kubernetes]", 1)
assert "source, integration" not in s' \
  "$CLI" 'TestEveryGatedSuiteBlocksPublication|TestOCIPublicationCannotStartBeforeLinuxIntegration'

mutate MC-26 "the release matrix becomes fail-fast" \
  .github/workflows/release-oci.yml \
  'old = "    strategy:\n      fail-fast: false\n      matrix:\n        suite: ["
assert s.count(old) == 1
s = s.replace(old, "    strategy:\n      fail-fast: true\n      matrix:\n        suite: [", 1)' \
  "$CLI" 'TestEveryGatedSuiteBlocksPublication'

echo
echo "--- the properties a gate has to keep to be one ---"

mutate MC-10 "continue-on-error is added to a required lane" \
  .github/workflows/integration.yml \
  's = s.replace("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    continue-on-error: true\n", 1)
assert "continue-on-error" in s' \
  "$CLI" 'TestTheIntegrationWorkflowDelegatesToTheHarness'

mutate MC-11 "workflow permissions are escalated" \
  .github/workflows/integration.yml \
  's = s.replace("permissions:\n  contents: read", "permissions:\n  contents: write", 1)
assert "contents: write" in s' \
  "$CLI" 'TestTheIntegrationWorkflowHoldsNoAuthorityItDoesNotNeed'

mutate MC-12 "a path filter is added" \
  .github/workflows/integration.yml \
  's = s.replace("on:\n  pull_request:\n", "on:\n  pull_request:\n    paths:\n      - internal/adapter/**\n", 1)
assert "paths:" in s' \
  "$CLI" 'TestTheIntegrationWorkflowTriggersOnExactlyTheFrozenEvents'

mutate MC-13 "the runner changes away from ubuntu-24.04" \
  .github/workflows/integration.yml \
  's = s.replace("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest", 1)
assert "ubuntu-24.04" not in s' \
  "$CLI" 'TestTheIntegrationLanesRunOnTheFrozenRunnerAndBudget'

mutate MC-14 "a lane required timeout is removed" \
  .github/workflows/integration.yml \
  's = s.replace("    timeout-minutes: ${{ matrix.timeout }}\n", "", 1)
assert "matrix.timeout" not in s' \
  "$CLI" 'TestTheIntegrationLanesRunOnTheFrozenRunnerAndBudget'

mutate MC-15 "pull_request_target is introduced" \
  .github/workflows/integration.yml \
  's = s.replace("on:\n  pull_request:\n", "on:\n  pull_request_target:\n", 1)
assert "pull_request_target" in s' \
  "$CLI" 'TestTheIntegrationWorkflowTriggersOnExactlyTheFrozenEvents'

mutate MC-16 "a repository secret is referenced" \
  .github/workflows/integration.yml \
  's = s.replace("      - name: Run the integration gate\n", "      - name: Run the integration gate\n        env:\n          TOKEN: ${{ secrets.FIXTURE_TOKEN }}\n", 1)
assert "secrets." in s' \
  "$CLI" 'TestTheIntegrationWorkflowHoldsNoAuthorityItDoesNotNeed'

mutate MC-17 "the canonical make target is replaced by inline YAML" \
  .github/workflows/integration.yml \
  's = s.replace("        run: make integration-${{ matrix.suite }}", "        run: docker compose -f test/integration/${{ matrix.suite }}/env/compose.yaml up -d", 1)
assert "make integration-" not in s' \
  "$CLI" 'TestTheIntegrationWorkflowDelegatesToTheHarness'

mutate MC-19 "the weekly schedule changes" \
  .github/workflows/integration.yml \
  "s = s.replace(\"- cron: '37 4 * * 2'\", \"- cron: '0 0 * * 0'\", 1)
assert \"37 4\" not in s" \
  "$CLI" 'TestTheIntegrationWorkflowTriggersOnExactlyTheFrozenEvents'

mutate MC-20 "unconditional teardown is dropped" \
  .github/workflows/integration.yml \
  'old = "      - name: Tear down the fixtures\n        if: always()\n"
assert s.count(old) == 1
s = s.replace(old, "      - name: Tear down the fixtures\n", 1)
assert "if: always()" not in s' \
  "$CLI" 'TestTheIntegrationWorkflowDelegatesToTheHarness'

mutate MC-21 "an action is unpinned" \
  .github/workflows/integration.yml \
  's = s.replace("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v7", 1)
assert "actions/checkout@v7" in s' \
  "$CLI" 'TestTheIntegrationWorkflowHoldsNoAuthorityItDoesNotNeed'

mutate MC-22 "the frozen check identity changes" \
  .github/workflows/integration.yml \
  's = s.replace("    name: Integration (${{ matrix.suite }})", "    name: ${{ matrix.suite }}", 1)
assert "name: Integration (" not in s' \
  "$CLI" 'TestTheIntegrationLanesRunOnTheFrozenRunnerAndBudget'

mutate MC-23 "concurrency cancels scheduled and main runs" \
  .github/workflows/integration.yml \
  'old = "cancel-in-progress: " + chr(36) + chr(123) + chr(123) + " github.event_name == " + chr(39) + "pull_request" + chr(39) + " " + chr(125) + chr(125)
assert s.count(old) == 1
s = s.replace(old, "cancel-in-progress: true", 1)' \
  "$CLI" 'TestTheIntegrationConcurrencyCancelsOnlyPullRequests'

echo
echo "--- the pins and the fixture hygiene prerequisite ---"

mutate MC-18 "an image pin loses its digest" \
  test/integration/redis/env/compose.yaml \
  's = s.replace("redis:8.2.1-alpine@sha256:987c376c727652f99625c7d205a1cba3cb2c53b92b0b62aade2bd48ee1593232", "redis:8.2.1-alpine", 1)
assert "image: redis:8.2.1-alpine\n" in s' \
  "$CLI" 'TestTheGatedServiceImagesArePinnedByDigest'

mutate MC-24 "the RabbitMQ bytecode guard is reverted" \
  test/integration/rabbitmq/env/probe.py \
  's = s.replace("sys.dont_write_bytecode = True\n", "", 1)
assert "dont_write_bytecode" not in s' \
  "$CLI" 'TestTheRabbitMQFixtureWritesNoBytecode'

mutate MC-25 "the generated-bytecode ignore rule is removed" \
  .gitignore \
  's = s.replace("__pycache__/\n*.pyc", "")
assert "__pycache__/" not in s' \
  "$CLI" 'TestTheRabbitMQFixtureWritesNoBytecode'

echo
echo "--- FAMILY A and FAMILY B: the lanes must be able to fail (section 29) ---"

breakit MC-27 "a broken RESP PING must fail integration-valkey" \
  internal/adapter/redis/wire/conn.go \
  'bs = chr(92)
frame = "*1" + bs + "r" + bs + "n" + chr(36) + "4" + bs + "r" + bs + "n" + "PING" + bs + "r" + bs + "n"
assert s.count(frame) == 1
s = s.replace(frame, frame.replace("PING", "PANG"), 1)
assert "PANG" in s' \
  integration-valkey

breakit MC-28 "a broken AMQP header must fail integration-lavinmq" \
  internal/adapter/rabbitmq/wire/frame.go \
  "s = s.replace(chr(123)+chr(39)+'A'+chr(39)+', '+chr(39)+'M'+chr(39)+', '+chr(39)+'Q'+chr(39)+', '+chr(39)+'P'+chr(39)+', 0x00, 0x00, 0x09, 0x01'+chr(125), chr(123)+chr(39)+'A'+chr(39)+', '+chr(39)+'M'+chr(39)+', '+chr(39)+'Q'+chr(39)+', '+chr(39)+'P'+chr(39)+', 0x00, 0x00, 0x08, 0x01'+chr(125), 1)
assert '0x08, 0x01' in s" \
  integration-lavinmq

# --- restoration, proved three ways -----------------------------------------

restore
trap - EXIT INT TERM HUP

echo
echo "--- restoration ---"

RESTORE_OK=1

AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" = "$AFTER" ]; then
  echo "  (1) declared write-set      ${#FILES[@]} files restored byte-for-byte"
else
  echo "  (1) declared write-set      MISMATCH"
  diff <(echo "$BEFORE") <(echo "$AFTER") || true
  RESTORE_OK=0
fi

if diff -q "$TRACKED_BEFORE" <(tracked_hash) >/dev/null; then
  echo "  (2) every tracked file      identical (git ls-files, independent of FILES)"
else
  echo "  (2) every tracked file      MISMATCH"
  diff "$TRACKED_BEFORE" <(tracked_hash) || true
  RESTORE_OK=0
fi

if diff -q "$TREE_BEFORE" <(tree_paths) >/dev/null; then
  echo "  (3) every worktree path     identical (find, independent of FILES)"
else
  echo "  (3) every worktree path     MISMATCH"
  diff "$TREE_BEFORE" <(tree_paths) || true
  RESTORE_OK=0
fi

rm -rf "$BACKUP"

TOTAL=$((PASS + ${#SURVIVORS[@]}))
echo
echo "--- result ---"
echo "  planted    $TOTAL"
echo "  caught     $PASS"
echo "  survivors  ${#SURVIVORS[@]}"

if [ ${#SURVIVORS[@]} -gt 0 ]; then
  echo
  echo "SURVIVORS:"
  for s in "${SURVIVORS[@]}"; do echo "  - $s"; done
fi

if [ ${#SURVIVORS[@]} -gt 0 ] || [ "$RESTORE_OK" -eq 0 ]; then
  echo
  echo "PHASE 14.0B MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 14.0B MUTATION CLOSURE: 0 survivors, tree restored and independently verified"
