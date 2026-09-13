#!/usr/bin/env bash
# Phase 13.1C mutation closure — semantic and high-risk recommendation closure.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is restored and verified byte-for-byte against sha256 checksums
# taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it.
#
# # Restoration is verified twice, and the second way is the point
#
# Phase 13.1B's harness kept a FILES list by hand, backed up from it, restored
# from it — and verified from it. Two plants touched files absent from that list,
# so `restore()` never saw them and the harness still reported "all files
# restored byte-for-byte", because it only ever checked what it already knew
# about. That is the fourth time this repository has lost a run to a harness
# measuring less than it claimed (docs/BACKLOG.md).
#
# So this script proves restoration two independent ways:
#
#   1. FILES, the declared write-set, compared before and after — the check the
#      13.1B harness had.
#   2. **The whole working tree**, hashed with a `find` that knows nothing about
#      FILES. A plant in a file nobody declared is invisible to (1) and caught by
#      (2).
#
# It also asserts that every file a plant names is in FILES, so the two cannot
# drift apart silently in the first place.
#
# No git stash, reset, checkout or restore is used anywhere: the user owns the
# history and a harness that reaches for it can destroy uncommitted work.
#
# # What this covers
#
#   MC-01  a production rule builds an unclassified recommendation again
#   MC-02  a retained NEXT_EVIDENCE becomes a REMEDIATION
#   MC-03  a retained safety class becomes CONFIG_CHANGE
#   MC-04  the one frozen SelfCollectable:true is dropped
#   MC-05  a rewritten recommendation loses its rationale
#   MC-06  a retired target-mutating action comes back
#   MC-07  one of the 64 mechanically frozen actions changes
#   MC-08  a helper wraps the unclassified constructor under another name
#   MC-09  a classification is invalid, so the recommendation is silently dropped
#   MC-10  a Phase 13.1C action changes without its pin
#   MC-11  SECURITY_WEAKENING reaches a production rule
#   MC-12  a production call site stops passing its classification
#   MC-13  redaction stops transforming the rationale
#   MC-14  the unclassified constructor is reached through an aliased import
#   MC-15  one constant is given two classifications
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/diagnosis/kafka/protocol.go
  internal/diagnosis/kafka/recommendation.go
  internal/diagnosis/kafka/topology.go
  internal/diagnosis/postgres/authentication.go
  internal/diagnosis/postgres/tls.go
  internal/diagnosis/redis/authentication.go
  internal/diagnosis/redis/ping.go
  internal/diagnosis/rabbitmq/authentication.go
  internal/diagnosis/rabbitmq/connectionopen.go
  internal/diagnosis/transport/dns.go
  internal/security/redaction/redact.go
)

for f in "${FILES[@]}"; do
  mkdir -p "$BACKUP/$(dirname "$f")"
  cp "$f" "$BACKUP/$f"
done

# (1) the declared write-set.
BEFORE="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"

# (2) the whole tree, derived from the filesystem and not from FILES.
TREE_MANIFEST="$BACKUP/.tree-before"
tree_hash() {
  find . -type f -not -path './.git/*' -not -path './bin/*' -print0 \
    | sort -z | xargs -0 shasum -a 256
}
tree_hash > "$TREE_MANIFEST"

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

# mutate <id> <description> <file> <python-replacement> <test-package> <test-regex>
mutate() {
  local id="$1" desc="$2" file="$3" script="$4" pkg="$5" regex="$6"

  # The declared write-set must contain every file a plant names. This is what
  # keeps check (1) honest; check (2) catches it anyway, but later and with less
  # to say about which plant did it.
  local declared=0 f
  for f in "${FILES[@]}"; do [ "$f" = "$file" ] && declared=1; done
  if [ "$declared" -eq 0 ]; then
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

echo "Phase 13.1C mutation closure — semantic and high-risk recommendation closure"
echo
echo "--- the zero-legacy invariant (ADR 0097 section 2.1) ---"

mutate MC-01 "a production rule builds an unclassified recommendation again" \
  internal/diagnosis/redis/ping.go \
  's = s.replace("""func evaluatePing(""",
"""func legacyAdvice(action string) []domain.Recommendation {
	r, err := domain.NewRecommendation(action)
	if err != nil {
		return nil
	}
	return []domain.Recommendation{r}
}

func evaluatePing(""", 1)
assert "func legacyAdvice" in s' \
  ./test/security 'TestNoProductionRuleBuildsAnUnclassifiedRecommendation'

mutate MC-08 "a helper wraps the unclassified constructor under another name" \
  internal/diagnosis/rabbitmq/authentication.go \
  's = s.replace("""// Authentication owns every outcome the credential step can produce.""",
"""// unclassified is the legacy path under a name that does not say so.
func unclassified(action string) []domain.Recommendation {
	out, err := domain.NewRecommendation(action)
	if err != nil {
		return nil
	}
	return []domain.Recommendation{out}
}

// Authentication owns every outcome the credential step can produce.""", 1)
assert "func unclassified" in s' \
  ./test/security 'TestNoProductionRuleBuildsAnUnclassifiedRecommendation'

mutate MC-14 "the unclassified constructor is reached through an aliased import" \
  internal/diagnosis/redis/authentication.go \
  's = s.replace("""	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis\"""",
"""	dom "github.com/hakanaltindag/svcdoctor/internal/domain"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis\"""", 1)
s = s.replace("""func evaluateAuthentication(""",
"""func aliasedLegacy(action string) []dom.Recommendation {
	r, err := dom.NewRecommendation(action)
	if err != nil {
		return nil
	}
	return []dom.Recommendation{r}
}

func evaluateAuthentication(""", 1)
assert "dom.NewRecommendation" in s' \
  ./test/security 'TestNoProductionRuleBuildsAnUnclassifiedRecommendation'

echo
echo "--- the closed kinds and safety classes (ADR 0097 section 2.2) ---"

mutate MC-02 "a retained NEXT_EVIDENCE becomes a REMEDIATION" \
  internal/diagnosis/redis/authentication.go \
  's = s.replace("""advise(diagnosis.SafetyObserve, recommendCredentialWithheld,""",
"""adviseRemediation(diagnosis.SafetyObserve, recommendCredentialWithheld,""", 1)
s = s.replace("""func evaluateAuthentication(""",
"""func adviseRemediation(
	safety diagnosis.SafetyClass, action, rationale string,
) []domain.Recommendation {
	return diagnosis.Recommend(diagnosis.AdviceInput{
		Kind:      diagnosis.AdviceKindRemediation,
		Safety:    safety,
		Action:    action,
		Rationale: rationale,
	}, domain.FindingKindConfirmed, domain.ConfidenceHigh)
}

func evaluateAuthentication(""", 1)
assert "AdviceKindRemediation" in s' \
  ./test/security 'TestNoProductionRecommendationIsARemediation'

mutate MC-03 "a retained safety class becomes CONFIG_CHANGE" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""advise(diagnosis.SafetyVerify, recommendVHostAccessRefused,""",
"""advise(diagnosis.SafetyConfigChange, recommendVHostAccessRefused,""", 1)
assert "SafetyConfigChange" in s' \
  ./internal/diagnosis/rabbitmq 'TestEveryProducedRecommendationCarriesItsFrozenClassification'

mutate MC-11 "SECURITY_WEAKENING reaches a production rule" \
  internal/diagnosis/redis/authentication.go \
  's = s.replace("""advise(diagnosis.SafetyObserve, recommendCredentialWithheld,""",
"""advise(diagnosis.SafetySecurityWeakening, recommendCredentialWithheld,""", 1)
assert "SafetySecurityWeakening" in s' \
  ./internal/diagnosis/redis 'TestEveryProducedRecommendationCarriesItsFrozenClassification'

echo
echo "--- the classification actually reaching the report ---"

mutate MC-04 "the one frozen SelfCollectable:true is dropped" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		SelfCollectable: true,
""", "", 1)
assert "SelfCollectable: true," not in s' \
  ./internal/diagnosis/kafka 'TestEveryProducedRecommendationCarriesItsFrozenClassification'

mutate MC-05 "a rewritten recommendation loses its rationale" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""advise(diagnosis.SafetyVerify, recommendVHostAccessRefused,
				rationaleVHostAccessRefused)""",
"""advise(diagnosis.SafetyVerify, recommendVHostAccessRefused, blankRationale)""", 1)
s = s.replace("""const (""", """const blankRationale = ""

const (""", 1)
assert "blankRationale" in s' \
  ./internal/diagnosis/rabbitmq 'TestEveryProducedRecommendationCarriesItsFrozenClassification'

mutate MC-09 "a classification is invalid, so the recommendation is silently dropped" \
  internal/diagnosis/postgres/authentication.go \
  's = s.replace("""advise(diagnosis.SafetyObserve, recommendCredentialWithheld,""",
"""advise(diagnosis.SafetyRestart, recommendCredentialWithheld,""", 1)
assert "SafetyRestart" in s' \
  ./internal/diagnosis/postgres 'TestEveryProducedRecommendationCarriesItsFrozenClassification'

mutate MC-12 "a production call site stops passing its classification" \
  internal/diagnosis/kafka/recommendation.go \
  's = s.replace("""		return recommendDNS, diagnosis.SafetyCompare, rationaleDNS, true""",
"""		return recommendDNS, diagnosis.SafetyUnspecified, rationaleDNS, true""", 1)
assert "recommendDNS, diagnosis.SafetyUnspecified" in s' \
  ./internal/diagnosis/kafka 'TestEveryProducedRecommendationCarriesItsFrozenClassification'

mutate MC-15 "one constant is given two classifications" \
  internal/diagnosis/postgres/tls.go \
  's = s.replace("""		safety:         diagnosis.SafetyCompare,""",
"""		safety:         diagnosis.SafetyObserve,""", 1)
assert s.count("safety:         diagnosis.SafetyCompare,") == 3' \
  ./internal/diagnosis/postgres 'TestEveryProducedRecommendationCarriesItsFrozenClassification'

echo
echo "--- the action text, frozen two different ways ---"

mutate MC-06 "a retired target-mutating action comes back" \
  internal/diagnosis/rabbitmq/connectionopen.go \
  's = s.replace("""	recommendVHostAccessRefused = "Verify whether this identity is intended to have access to " +
		"this virtual host, in the broker\x27s own permissions configuration\"""",
"""	recommendVHostAccessRefused = "Grant this user permissions on the virtual host, for " +
		"example with rabbitmqctl set_permissions\"""", 1)
assert "Grant this user permissions" in s' \
  ./test/security 'TestNoProductionRecommendationInstructsATargetMutation'

mutate MC-07 "one of the 64 mechanically frozen actions changes" \
  internal/diagnosis/transport/dns.go \
  's = s.replace("""		"has an address record visible to the resolver this host is configured to use\"""",
"""		"has an address record visible to the resolver this host is configured to use.\"""", 1)
assert "configured to use." in s' \
  ./test/security 'TestMigratedRecommendationActionTextIsFrozen'

mutate MC-10 "a Phase 13.1C action changes without its pin" \
  internal/diagnosis/kafka/recommendation.go \
  's = s.replace("""	recommendDNS = "Compare the name this broker publishes in advertised.listeners with the " +
		"names resolvable from this network position\"""",
"""	recommendDNS = "Compare the name this broker publishes in advertised.listeners with what " +
		"this network position can resolve\"""", 1)
assert "with what" in s' \
  ./test/security 'TestTheRewrittenRecommendationsAreTheFrozenOnes'

echo
echo "--- redaction (ADR 0018) ---"

mutate MC-13 "redaction stops transforming the rationale" \
  internal/security/redaction/redact.go \
  's = s.replace("""					Rationale:       t.text(r.Rationale()),""",
"""					Rationale:       r.Rationale(),""", 1)
assert "Rationale:       r.Rationale()," in s' \
  ./internal/security/redaction 'TestTheRationaleIsRedactedLikeEveryOtherProseField'

echo
echo "--- restoration ---"

AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "  the declared write-set did NOT restore byte-for-byte"
  diff <(echo "$BEFORE") <(echo "$AFTER")
  SURVIVORS+=("declared write-set not restored")
else
  echo "  declared write-set restored byte-for-byte (${#FILES[@]} files)"
fi

# The independent check. It knows nothing about FILES, so a plant in an
# undeclared file shows up here and only here.
TREE_AFTER="$BACKUP/.tree-after"
tree_hash > "$TREE_AFTER"
if ! diff -q "$TREE_MANIFEST" "$TREE_AFTER" >/dev/null; then
  echo "  the WORKING TREE did NOT restore — a file outside FILES was modified:"
  diff "$TREE_MANIFEST" "$TREE_AFTER" | head -40
  SURVIVORS+=("working tree not restored")
else
  echo "  working tree restored byte-for-byte ($(wc -l < "$TREE_MANIFEST" | tr -d ' ') files, verified independently of FILES)"
fi

echo
PLANNED=15
echo "planted $PLANNED  caught $PASS  survivors ${#SURVIVORS[@]}"
if [ "${#SURVIVORS[@]}" -ne 0 ]; then
  printf '  %s\n' "${SURVIVORS[@]}"
  echo
  echo "PHASE 13.1C MUTATION CLOSURE: ${#SURVIVORS[@]} survivors"
  exit 1
fi
if [ "$PASS" -ne "$PLANNED" ]; then
  echo "PHASE 13.1C MUTATION CLOSURE: $PASS of $PLANNED caught, which is not closure"
  exit 1
fi
echo
echo "PHASE 13.1C MUTATION CLOSURE: 0 survivors"
