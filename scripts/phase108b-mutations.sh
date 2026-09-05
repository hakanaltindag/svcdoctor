#!/usr/bin/env bash
# Phase 10.8B mutation closure — the RabbitMQ capacity-scope canonical explanation.
#
# Each mutation is planted in production code, the guard that should notice it is
# run and must FAIL, and the tree is restored and verified byte-for-byte against
# sha256 checksums taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it.
#
# # What this covers
#
# Phase 10.8B preserves specificity the evidence already earned and claims
# nothing new with it. The mutations are the wrong scopes it must never name, the
# values that must never activate it, the fields it must never touch, and the
# sentences it must never produce:
#
#   RCCE-M01  a node ceiling is explained as a user ceiling
#   RCCE-M02  a virtual-host ceiling is explained as a node ceiling
#   RCCE-M03  a user ceiling is explained as a virtual-host ceiling
#   RCCE-M04  an unrecognized outcome receives the node explanation
#   RCCE-M05  a non-capacity known outcome receives a capacity explanation
#   RCCE-M06  an absent attribute receives a capacity explanation
#   RCCE-M07  the lookup matches on a prefix rather than on the exact value
#   RCCE-M08  the lookup folds case
#   RCCE-M09  the lookup trims the value before comparing
#   RCCE-M10  the raw close_outcome is interpolated into the explanation
#   RCCE-M11  the node explanation claims exhaustion
#   RCCE-M12  the virtual-host explanation claims misconfiguration
#   RCCE-M13  the user explanation infers a connection leak
#   RCCE-M14  the explanation drops the no-cause sentence
#   RCCE-M15  the explanation drops the impermanence sentence
#   RCCE-M16  a capacity outcome changes the recommendation
#   RCCE-M17  a capacity outcome changes the FindingCode
#   RCCE-M18  a capacity outcome changes the severity
#   RCCE-M19  a capacity outcome changes the confidence
#   RCCE-M20  the failure-class gate is removed, so any class may enrich
#   RCCE-M21  the mapping admits a fourth, non-capacity outcome
#   RCCE-M22  a capacity outcome suppresses the finding entirely
#
# # Three contract mutations are deliberately not planted, and saying so is more
# # useful than a green line
#
# **A product-name branch (`if LavinMQ`).** Unplantable: `internal/diagnosis`
# cannot import an adapter, no product attribute exists on the connection-open
# node, and `TestNoVendorBranchExistsInTheJourney` and
# `TestVendorDifferencesLiveOnlyInTheCloseNormalizer` in the LavinMQ suite
# already scan for it. There is nothing in this package to mutate.
#
# **A graph-wide outcome lookup.** `connectionNotPermittedDetail` takes a
# `domain.Evidence`, not a `domain.Graph`. Planting a graph search means writing a
# different function with a different signature, which is a rewrite rather than a
# mutation. `TestAnotherNodesOutcomeCannotEnrichThisFinding` covers the
# behaviour.
#
# **A schema or FindingCode-count change.** Pinned by attribution in
# `test/security/convergenceinventory_test.go` and by `domain.SchemaVersion`,
# both exercised by the frozen-inventory run rather than by a plant here.
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/diagnosis/rabbitmq/connectionopen.go
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
before = s
$script
if s == before:
    raise SystemExit(1)
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

PKG=./internal/diagnosis/rabbitmq
RUN='TestCapacity|TestNonCapacity|TestHostileOutcome|TestOnlyDetail|TestCanonicalJSON|TestTheMappingIsKeyed|TestConvergence|TestAnotherNode'

echo "Phase 10.8B mutation closure — the RabbitMQ capacity-scope canonical explanation"
echo

echo "--- the wrong scope is the failure mode this phase created ---"

mutate RCCE-M01 "a node ceiling is explained as a user ceiling" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	servicerabbitmq.CloseNodeConnectionLimit:  detailCapacityNode,""", """	servicerabbitmq.CloseNodeConnectionLimit:  detailCapacityUser,""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M02 "a virtual-host ceiling is explained as a node ceiling" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	servicerabbitmq.CloseVHostConnectionLimit: detailCapacityVHost,""", """	servicerabbitmq.CloseVHostConnectionLimit: detailCapacityNode,""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M03 "a user ceiling is explained as a virtual-host ceiling" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	servicerabbitmq.CloseUserConnectionLimit:  detailCapacityUser,""", """	servicerabbitmq.CloseUserConnectionLimit:  detailCapacityVHost,""", 1)' \
  "$PKG" "$RUN"

echo
echo "--- only the three closed capacity values may activate it ---"

mutate RCCE-M04 "an unrecognized outcome receives the node explanation" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	detail, mapped := capacityScopeDetail[servicerabbitmq.CloseOutcome(outcome)]
	if !mapped {
		return detailConnectionNotPermitted
	}""", """	detail, mapped := capacityScopeDetail[servicerabbitmq.CloseOutcome(outcome)]
	if !mapped {
		return detailCapacityNode
	}""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M05 "a non-capacity known outcome receives a capacity explanation" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	servicerabbitmq.CloseUserConnectionLimit:  detailCapacityUser,
}""", """	servicerabbitmq.CloseUserConnectionLimit:  detailCapacityUser,
	servicerabbitmq.CloseVHostNotFound:        detailCapacityVHost,
	servicerabbitmq.CloseUnspecified:          detailCapacityNode,
}""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M06 "an absent attribute receives a capacity explanation" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	value, ok := node.Attribute(servicerabbitmq.AttrCloseOutcome)
	if !ok {
		return detailConnectionNotPermitted
	}""", """	value, ok := node.Attribute(servicerabbitmq.AttrCloseOutcome)
	if !ok {
		return detailCapacityNode
	}""", 1)' \
  "$PKG" "$RUN"

echo
echo "--- the comparison is exact, and stays exact ---"

mutate RCCE-M07 "the lookup matches on a prefix rather than on the exact value" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	detail, mapped := capacityScopeDetail[servicerabbitmq.CloseOutcome(outcome)]
	if !mapped {
		return detailConnectionNotPermitted
	}
	return detail""", """	for key, candidate := range capacityScopeDetail {
		if strings.HasPrefix(outcome, string(key)) {
			return candidate
		}
	}
	return detailConnectionNotPermitted""", 1)
s = s.replace("""import (""", """import (
	"strings"
""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M08 "the lookup folds case" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	detail, mapped := capacityScopeDetail[servicerabbitmq.CloseOutcome(outcome)]""", """	detail, mapped := capacityScopeDetail[servicerabbitmq.CloseOutcome(strings.ToUpper(outcome))]""", 1)
s = s.replace("""import (""", """import (
	"strings"
""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M09 "the lookup trims the value before comparing" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	detail, mapped := capacityScopeDetail[servicerabbitmq.CloseOutcome(outcome)]""", """	detail, mapped := capacityScopeDetail[servicerabbitmq.CloseOutcome(strings.TrimSpace(outcome))]""", 1)
s = s.replace("""import (""", """import (
	"strings"
""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M10 "the raw close_outcome is interpolated into the explanation" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	return detail""", """	return detail + " (" + outcome + ")\"""", 1)' \
  "$PKG" "$RUN"

echo
echo "--- the claim ceiling (ADR 0091 section 8) ---"

mutate RCCE-M11 "the node explanation claims exhaustion" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""		"The endpoint named a connection limit scoped to the node." +""", """		"The node has exhausted its connection capacity." +""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M12 "the virtual-host explanation claims misconfiguration" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""		"The endpoint named a connection limit scoped to the virtual host." +""", """		"The virtual host is misconfigured: its connection limit is too low." +""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M13 "the user explanation infers a connection leak" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""		"The endpoint named a connection limit scoped to the user." +""", """		"This user is leaking connections and has used all slots." +""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M14 "the explanation drops the no-cause sentence" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace(chr(34) + "or what to change, and a second run a moment later may succeed." + chr(34), chr(34) + "and nothing else is claimed." + chr(34), 1)' \
  "$PKG" "$RUN"

mutate RCCE-M15 "the explanation drops the impermanence sentence" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace(chr(34) + "or what to change, and a second run a moment later may succeed." + chr(34), chr(34) + "or what to change." + chr(34), 1)' \
  "$PKG" "$RUN"

echo
echo "--- nothing but Detail may move ---"

mutate RCCE-M16 "a capacity outcome changes the recommendation" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""			Recommendations:  recommend(recommendConnectionNotPermitted),
		}, true

	default:""", """			Recommendations:  recommend("Raise the connection limit on the named scope"),
		}, true

	default:""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M17 "a capacity outcome changes the FindingCode" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	case domain.FailureResourceLimitReached, domain.FailureAuthzNotPermitted:
		return domain.FindingInput{
			Code:       CodeConnectionNotPermitted,""", """	case domain.FailureResourceLimitReached, domain.FailureAuthzNotPermitted:
		return domain.FindingInput{
			Code:       CodeConnectionNotEstablished,""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M18 "a capacity outcome changes the severity" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""			Code:       CodeConnectionNotPermitted,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,""", """			Code:       CodeConnectionNotPermitted,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityCritical,""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M19 "a capacity outcome changes the confidence" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""			Code:       CodeConnectionNotPermitted,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceHigh,""", """			Code:       CodeConnectionNotPermitted,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,
			Confidence: domain.ConfidenceMedium,""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M20 "the failure-class gate is removed, so any class may enrich" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	if node.FailureClass() != domain.FailureResourceLimitReached {
		return detailConnectionNotPermitted
	}
""", "", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M21 "the mapping admits a fourth, non-capacity outcome" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	servicerabbitmq.CloseNodeConnectionLimit:  detailCapacityNode,""", """	servicerabbitmq.CloseUnspecifiedTruncated: detailCapacityNode,
	servicerabbitmq.CloseNodeConnectionLimit:  detailCapacityNode,""", 1)' \
  "$PKG" "$RUN"

mutate RCCE-M22 "a capacity outcome suppresses the finding entirely" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""		in, ok := connectionOpenFinding(node)
		if !ok {
			continue
		}""", """		in, ok := connectionOpenFinding(node)
		if !ok || node.FailureClass() == domain.FailureResourceLimitReached {
			continue
		}""", 1)' \
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
  echo "PHASE 10.8B MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 10.8B MUTATION CLOSURE: 0 survivors"
