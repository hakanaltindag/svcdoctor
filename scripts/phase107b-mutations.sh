#!/usr/bin/env bash
# Phase 10.7B mutation closure — the PostgreSQL session read-only observation.
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
# Phase 10.7B presents one already-recorded fact and claims nothing with it. The
# mutations are the sentences it must never produce and the derivations it must
# never make:
#
#   PSRO-M01  an absent parameter is defaulted to "off"
#   PSRO-M02  an absent parameter is defaulted to "on"
#   PSRO-M03  the session observation becomes a server-wide read-only claim
#   PSRO-M04  "off" becomes writability reassurance
#   PSRO-M04b "off" is inverted into the positive concept "read write"
#   PSRO-M05  recovery drives the transaction-mode line
#   PSRO-M06  the transaction mode drives the recovery line
#   PSRO-M07  the two facts are merged into one synthetic verdict
#   PSRO-M08  an arbitrary peer value is rendered verbatim
#   PSRO-M09  the mode line is graded as a fault
#   PSRO-M10  a read-only default is called a misconfiguration
#   PSRO-M11  the observation is deleted entirely
#   PSRO-M12  the render map admits a near-miss value
#   PSRO-M13  the note attributes the parameter to the endpoint rather than the session
#
# Two contract mutations are deliberately **not** planted here, because the
# architecture makes them unplantable rather than merely wrong, and saying so is
# more useful than a green line:
#
#   a diagnosis rule reading postgres.default_transaction_read_only, and a
#   FindingCode for the observation. `internal/diagnosis/postgres` cannot import
#   the renderer, `TestTheRulesReadOnlyTheAuthorizedAttributes` scans the rule
#   package's source for any attribute outside a four-key allowlist, and the
#   finding-code count is pinned by attribution. Those guards are exercised by
#   the frozen-inventory run rather than by a plant here.
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/render/terminal/service.go
  internal/render/terminal/report.go
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

PKG=./internal/render/terminal
RUN='TestPSRO'

# The three literal fragments the plants rewrite, kept here so a wording change
# breaks the harness loudly at "COULD NOT PLANT" rather than quietly passing.
ON='					case "on":
						return "on"'
OFF='					case "off":
						return "off"'

echo "Phase 10.7B mutation closure — the PostgreSQL session read-only observation"
echo

echo "--- absence must stay silence (ADR 0089 section 7.1) ---"

mutate PSRO-M01 "an absent parameter is defaulted to off" \
  internal/render/terminal/report.go \
  's = s.replace("""		value, ok := node.Attribute(observation.key)
		if !ok {
			continue
		}""", """		value, ok := node.Attribute(observation.key)
		if !ok {
			value = domain.StringAttr("off")
		}""", 1)' \
  "$PKG" "$RUN"

mutate PSRO-M02 "an absent parameter is defaulted to on" \
  internal/render/terminal/report.go \
  's = s.replace("""		value, ok := node.Attribute(observation.key)
		if !ok {
			continue
		}""", """		value, ok := node.Attribute(observation.key)
		if !ok {
			value = domain.StringAttr("on")
		}""", 1)' \
  "$PKG" "$RUN"

echo
echo "--- the claim boundary: a session, never a server ---"

mutate PSRO-M03 "the session observation becomes a server-wide read-only claim" \
  internal/render/terminal/service.go \
  's = s.replace("""					case "on":
						return "on"
					case "off":
						return "off\"""", """					case "on":
						return "the server is read-only"
					case "off":
						return "off\"""", 1)' \
  "$PKG" "$RUN"

mutate PSRO-M04 "off becomes writability reassurance" \
  internal/render/terminal/service.go \
  's = s.replace("""					case "off":
						return "off\"""", """					case "off":
						return "writable; writes will work\"""", 1)' \
  "$PKG" "$RUN"

# The revision this phase exists for. "off" says one default is not set; "read
# write" is a positive concept about what the session can do, and the parameter
# does not carry it.
mutate PSRO-M04b "off is inverted into the positive concept read write" \
  internal/render/terminal/service.go \
  's = s.replace("""					case "on":
						return "on"
					case "off":
						return "off\"""", """					case "on":
						return "read only"
					case "off":
						return "read write\"""", 1)' \
  "$PKG" "$RUN"

echo
echo "--- the two facts are independent (ADR 0040 section 20) ---"

mutate PSRO-M05 "recovery drives the transaction-mode line" \
  internal/render/terminal/service.go \
  's = s.replace("""				key:   servicepostgres.AttrDefaultTransactionReadOnly,
				label: "default transaction read-only",""", """				key:   servicepostgres.AttrInHotStandby,
				label: "default transaction read-only",""", 1)' \
  "$PKG" "$RUN"

mutate PSRO-M06 "the transaction mode drives the recovery line" \
  internal/render/terminal/service.go \
  's = s.replace("""				key:   servicepostgres.AttrInHotStandby,
				label: "recovery",""", """				key:   servicepostgres.AttrDefaultTransactionReadOnly,
				label: "recovery",""", 1)' \
  "$PKG" "$RUN"

mutate PSRO-M07 "the two facts are merged into one synthetic verdict" \
  internal/render/terminal/service.go \
  's = s.replace("""					case "on":
						return "on"
					case "off":
						return "off\"""", """					case "on":
						return "on"
					case "off":
						return "on\"""", 1)' \
  "$PKG" "$RUN"

echo
echo "--- the render map is closed (ADR 0081 section 2.7) ---"

mutate PSRO-M08 "an arbitrary peer value is rendered verbatim" \
  internal/render/terminal/service.go \
  's = s.replace("""					case "off":
						return "off"
					default:
						return ""
					}""", """					case "off":
						return "off"
					default:
						return v.String()
					}""", 1)' \
  "$PKG" "$RUN"

mutate PSRO-M12 "the render map admits a near-miss value" \
  internal/render/terminal/service.go \
  's = s.replace("""					case "on":
						return "on"
					case "off":
						return "off"
					default:""", """					case "on", "ON":
						return "on"
					case "off":
						return "off"
					default:""", 1)' \
  "$PKG" "$RUN"

echo
echo "--- a fact is not a fault (ADR 0083 section 2.6) ---"

mutate PSRO-M09 "the observation is graded as a fault" \
  internal/render/terminal/service.go \
  's = s.replace("""					case "on":
						return "on"
					case "off":
						return "off\"""", """					case "on":
						return "on (WARNING: unexpected)"
					case "off":
						return "off\"""", 1)' \
  "$PKG" "$RUN"

mutate PSRO-M10 "a read-only default is called a misconfiguration" \
  internal/render/terminal/service.go \
  's = s.replace("""					"This session reported that its transactions default to read-only.",""", """					"This endpoint is misconfigured: writes will fail on it.",""", 1)' \
  "$PKG" "$RUN"

# The subject is the session, not the endpoint. A pooler may hand the next
# transaction to a different backend, so "this endpoint" attributes to a server
# what only one session reported.
mutate PSRO-M13 "the note attributes the parameter to the endpoint" \
  internal/render/terminal/service.go \
  's = s.replace("""					"This session reported that its transactions default to read-only.",""", """					"This endpoint reports that its transactions default to read-only.",""", 1)' \
  "$PKG" "$RUN"

echo
echo "--- non-vacuity ---"

mutate PSRO-M11 "the observation is deleted entirely" \
  internal/render/terminal/service.go \
  's_i = s.index("""			{
				step:  servicepostgres.StepSession,
				key:   servicepostgres.AttrDefaultTransactionReadOnly,""")
s_j = s.index("""		},

		notes: []conditionalNote{""", s_i)
s = s[:s_i] + s[s_j:]' \
  "$PKG" "$RUN"

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
  echo "PHASE 10.7B MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 10.7B MUTATION CLOSURE: 0 survivors"
