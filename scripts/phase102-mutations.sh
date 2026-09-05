#!/usr/bin/env bash
# Phase 10.2 mutation closure — Kafka topology-scoped diagnostic intelligence.
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
# Phase 10.1B mutated the generic engine. Phase 10.2 added the first service
# intelligence, so every plant below changes a **claim about a Kafka cluster**:
# a topology count that treats an unmeasured endpoint as a refused one, a
# hypothesis that survives the evidence contradicting it, prose that names a
# cause nobody observed.
#
#   K-M01-K-M02  bootstrap and metadata gate the whole topology surface
#   K-M03-K-M05  three categories, never two; completeness needs both halves
#   K-M06-K-M07  one failure is not all of them; a failure is not a configuration
#   K-M08-K-M11  the forbidden causes: firewall, password, expiry, withheld
#   K-M12-K-M13  address shape is not an incident
#   K-M14-K-M16  the confidence ladder and its ceiling
#   K-M17        an incomplete run cannot isolate a single endpoint
#   K-M18-K-M20  ownership, ordering and subject identity
#   K-M21        peer text never becomes prose
#   K-M22-K-M24  cluster verdicts, implementation identity, unsafe advice
#   K-M25        both halves of the contrast are cited
#
# K-M25 exists because the first run of this suite had ten survivors and four of
# them were the suite's own fault rather than the product's. Fixing them added
# four guards that had not existed, and the reference set was the one nothing
# pinned exactly. A mutation suite that only confirms the tests you already wrote
# has measured the tests.
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/diagnosis/kafka/topology.go
  internal/diagnosis/kafka/sweep.go
  internal/diagnosis/kafka/recommendation.go
  internal/diagnosis/advice.go
  internal/diagnosis/confidence.go
  internal/app/kafka.go
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
  # harness would read as a pass. Checked on the pristine tree, before planting:
  # after planting, a mutation that breaks the build produces no `=== RUN`
  # either, and a check placed later could not tell the two apart.
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

echo "Phase 10.2 mutation closure — Kafka topology-scoped diagnosis"
echo
echo "--- the bootstrap and metadata gate ---"

mutate K-M01 "a bootstrap that never reached Metadata still permits topology diagnosis" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		if node.Step() != servicekafka.StepMetadata || node.State() != domain.StatePass {""",
"""		if node.Step() != servicekafka.StepMetadata {""", 1)
assert "if node.Step() != servicekafka.StepMetadata {" in s' \
  ./internal/diagnosis/kafka 'TestNoTopologyClaimSurvivesTheBootstrapNotReachingMetadata'

mutate K-M02 "a failed Metadata exchange is treated as successful discovery" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		if node.Step() != servicekafka.StepMetadata || node.State() != domain.StatePass {""",
"""		if node.Step() != servicekafka.StepMetadata || node.State() == domain.StateSkipped {""", 1)
assert "node.State() == domain.StateSkipped {" in s' \
  ./internal/diagnosis/kafka 'TestNoTopologyClaimSurvivesTheBootstrapNotReachingMetadata'

echo
echo "--- three categories, never two ---"

mutate K-M03 "an UNKNOWN endpoint is counted as one that refused" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		if unknownLocal(p.tcp) {
			return reachNotMeasured
		}""", """		if unknownLocal(p.tcp) {
			return reachNotReached
		}""", 1)
assert "if unknownLocal(p.tcp) {\n\t\t\treturn reachNotReached" in s' \
  ./test/diagnosis 'TestKP03AndKP04UnmeasuredEndpointsAreNeverCountedAsFailures|TestTheTopologyCountsMatchTheRenderedTopologyLine'

mutate K-M04 "a sweep the chain does not produce is counted as one that refused" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	s := collectSweep(g, advertisement.ID())
	if !s.wellFormed {
		// A shape the transport chain does not produce.""",
"""	s := collectSweep(g, advertisement.ID())
	if !s.wellFormed {
		return reachNotReached
		// A shape the transport chain does not produce.""", 1)
assert "if !s.wellFormed {\n\t\treturn reachNotReached" in s' \
  ./internal/diagnosis/kafka 'TestASweepShapeTheChainDoesNotProduceIsNotMeasured'

mutate K-M05 "an incomplete run is treated as a complete measurement" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		t.complete = len(t.notMeasured) == 0 && !ctx.Incomplete""",
"""		t.complete = len(t.notMeasured) == 0""", 1)
assert "t.complete = len(t.notMeasured) == 0\n" in s' \
  ./internal/diagnosis/kafka 'TestAnIncompleteRunCannotProduceACompleteCount'

echo
echo "--- one failure is not all of them ---"

mutate K-M06 "one failed endpoint is reported as the whole advertised set" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	if len(t.reached) == 0 {
		if t.total() == 1 {""",
"""	if len(t.notReached) > 0 {
		if t.total() == 1 {""", 1)
assert "if len(t.notReached) > 0 {\n\t\tif t.total() == 1 {" in s' \
  ./test/diagnosis 'TestTheKafkaGoldenIncidentCorpus|TestKP03AndKP04UnmeasuredEndpointsAreNeverCountedAsFailures'

mutate K-M07 "a failed advertised endpoint is declared a definitely wrong advertisement" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	summaryUnsuitable = "The broker endpoints this cluster advertised may not be usable from " +
		"this client'"'"'s network position\"""",
"""	summaryUnsuitable = "The advertised.listeners configuration of this cluster is misconfigured\"""", 1)
assert "advertised.listeners configuration" in s' \
  ./test/diagnosis 'TestTheKafkaGoldenIncidentCorpus'

echo
echo "--- the causes svcdoctor did not observe ---"

mutate K-M08 "a TCP failure is reported as a firewall blocking the endpoint" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	detailTopologyMeaning = "This counts what was measured about the endpoints one Metadata " +""",
"""	detailTopologyMeaning = "A firewall is blocking these endpoints. " +
		"This counts what was measured about the endpoints one Metadata " +""", 1)
assert "A firewall is blocking" in s' \
  ./test/diagnosis 'TestTheKafkaGoldenIncidentCorpus'

mutate K-M09 "a rejected credential is reported as a wrong password" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	summaryTopologyNoneReached = "None of the %d broker endpoints this cluster advertised " +
		"could be reached from this vantage point\"""",
"""	summaryTopologyNoneReached = "None of the %d broker endpoints could be reached; the " +
		"configured password is wrong\"""", 1)
assert "password is wrong" in s' \
  ./test/diagnosis 'TestTheKafkaGoldenIncidentCorpus'

mutate K-M10 "a TLS identity mismatch is reported as an expired certificate" \
  internal/diagnosis/kafka/recommendation.go \
  's = s.replace("""	recommendTLS = "Check whether the broker certificate names the advertised host, and " +
		"whether its issuer is trusted at this vantage point\"""",
"""	recommendTLS = "The broker certificate is expired; issue a new one\"""", 1)
assert "certificate is expired" in s' \
  ./test/diagnosis 'TestTheKafkaGoldenIncidentCorpus'

mutate K-M11 "a credential svcdoctor withheld is reported as one the endpoint refused" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	summaryUnsuitable = "The broker endpoints this cluster advertised may not be usable from " +
		"this client'"'"'s network position\"""",
"""	summaryUnsuitable = "The Kafka endpoint rejected the credential it was presented\"""", 1)
assert "rejected the credential" in s' \
  ./internal/diagnosis/kafka 'TestNoTopologyClaimSpeaksAboutACredential'

echo
echo "--- address shape is not an incident ---"

mutate K-M12 "a loopback advertisement is an incident whether or not it was reached" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		if len(t.notReached) == 0 {
			continue
		}""",
"""		if len(t.notReached) == 0 && !t.anyLoopback() {
			continue
		}""", 1)
s = s.replace("""// total returns how many advertisements this exchange carried.""",
"""// anyLoopback is the address-shape heuristic ADR 0084 section 7 forbids.
func (t advertisedTopology) anyLoopback() bool {
	for _, group := range [][]domain.Evidence{t.reached, t.notReached, t.notMeasured} {
		for _, a := range group {
			if len(a.Subject().Ref()) >= 4 && a.Subject().Ref()[:4] == "127." {
				return true
			}
		}
	}
	return false
}

// total returns how many advertisements this exchange carried.""", 1)
assert "anyLoopback" in s' \
  ./test/diagnosis 'TestKP08AndKP09AReachableAddressIsNeverAConfigurationClaim|TestTheKafkaGoldenIncidentCorpus'

mutate K-M13 "a private-range advertisement is an incident whether or not it was reached" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		if len(t.notReached) == 0 {
			continue
		}""",
"""		if len(t.notReached) == 0 && !t.anyPrivate() {
			continue
		}""", 1)
s = s.replace("""// total returns how many advertisements this exchange carried.""",
"""// anyPrivate is the address-shape heuristic ADR 0084 section 7 forbids.
func (t advertisedTopology) anyPrivate() bool {
	for _, group := range [][]domain.Evidence{t.reached, t.notReached, t.notMeasured} {
		for _, a := range group {
			if len(a.Subject().Ref()) >= 3 && a.Subject().Ref()[:3] == "10." {
				return true
			}
		}
	}
	return false
}

// total returns how many advertisements this exchange carried.""", 1)
assert "anyPrivate" in s' \
  ./test/diagnosis 'TestKP08AndKP09AReachableAddressIsNeverAConfigurationClaim'

echo
echo "--- the confidence ladder and its ceiling ---"

mutate K-M14 "contradicting evidence raises confidence instead of capping it" \
  internal/diagnosis/confidence.go \
  's = s.replace("""	if len(basis.contradicting) > 0 {
		return domain.ConfidenceLow, nil
	}""",
"""	if len(basis.contradicting) > 0 {
		return domain.ConfidenceHigh, nil
	}""", 1)
assert "return domain.ConfidenceHigh, nil\n\t}" in s' \
  ./internal/diagnosis 'TestP07ContradictionCannotRaiseConfidence'

mutate K-M15 "removing supporting evidence raises confidence" \
  internal/diagnosis/confidence.go \
  's = s.replace("""		if len(basis.supporting) >= 2 {
			return domain.ConfidenceMedium, nil
		}
		return domain.ConfidenceLow, nil""",
"""		if len(basis.supporting) >= 2 {
			return domain.ConfidenceLow, nil
		}
		return domain.ConfidenceMedium, nil""", 1)
assert "return domain.ConfidenceMedium, nil\n\n\t}" in s or "return domain.ConfidenceMedium, nil\n\t}" in s' \
  ./internal/diagnosis/kafka 'TestTheSuitabilityHypothesisCanNeverBeHigh'

mutate K-M16 "the suitability hypothesis declares an authority it does not have" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		domain.FindingKindHypothesis, diagnosis.AuthorityNone, basis)""",
"""		domain.FindingKindHypothesis, diagnosis.AuthorityDirect, basis)""", 1)
assert "diagnosis.AuthorityDirect, basis)" in s' \
  ./internal/diagnosis/kafka 'TestTheSuitabilityHypothesisCanNeverBeHigh|FuzzAdvertisedTopology'

echo
echo "--- an incomplete run cannot isolate a single endpoint ---"

mutate K-M17 "a partial set still names the endpoints that were not the problem" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	detail := detailTopologyMeaning
	if !t.complete {""",
"""	detail := detailTopologyMeaning
	if false && !t.complete {""", 1)
assert "if false && !t.complete {" in s' \
  ./test/diagnosis 'TestKP06AndKP07APartialSetProducesNoTotalAndNoIsolation|TestTheKafkaGoldenIncidentCorpus'

echo
echo "--- ownership, ordering and identity ---"

mutate K-M18 "the service rules are dropped from the composition root" \
  internal/app/kafka.go \
  's = s.replace("""		Add("kafka/advertised-topology", diagnosiskafka.AdvertisedTopologyReachability).
		Add("kafka/advertised-suitability", diagnosiskafka.AdvertisedTopologyUnsuitable).""",
"""""", 1)
assert "kafka/advertised-topology" not in s' \
  ./test/security 'TestTheCompositionWiresEveryOwnerOfWhatItCanProduce'

mutate K-M19 "two exchanges sharing a subject converge, so a tie-break picks a count" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		if bySubject[exchange.Subject()] != 1 {
			continue
		}""", """		if bySubject[exchange.Subject()] < 1 {
			continue
		}""", 1)
assert "bySubject[exchange.Subject()] < 1 {" in s' \
  ./internal/diagnosis/kafka 'TestTwoExchangesSharingASubjectNeverConverge|TestTwoExchangesSharingOneSubjectProduceNothing'

mutate K-M20 "the topology claim borrows an advertised endpoint as its subject" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		Subject:          t.exchange.Subject(),
		Summary:          summary,""",
"""		Subject:          t.notReached[0].Subject(),
		Summary:          summary,""", 1)
assert "t.notReached[0].Subject()" in s' \
  ./internal/diagnosis/kafka 'TestTheTopologyObservationStatesTheContrastOverACompleteSet'

echo
echo "--- peer text, cluster verdicts and unsafe advice ---"

mutate K-M21 "the advertised hostname is interpolated into the claim's prose" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""		Summary:          summary,
		Detail:           detail,""",
"""		Summary:          summary,
		Detail:           detail + "\\nendpoints: " + t.notReached[0].Subject().Ref(),""", 1)
assert "endpoints: " in s' \
  ./internal/diagnosis/kafka 'FuzzAdvertisedTopology'

mutate K-M22 "one unreachable broker endpoint becomes a cluster outage" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	summaryTopologySomeReached = "%d of the %d broker endpoints this cluster advertised could " +
		"not be reached from this vantage point; the other %d %s reached\"""",
"""	summaryTopologySomeReached = "The cluster is down: %d of %d broker endpoints, %d %s " +
		"reached\"""", 1)
assert "The cluster is down" in s' \
  ./test/diagnosis 'TestTheKafkaGoldenIncidentCorpus'

mutate K-M23 "a Kafka-protocol endpoint is claimed to be an Apache Kafka broker process" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	detailTopologyComplete = "\\nEach endpoint that response advertised was measured for " +
		"reachability, so the counts above account for the whole advertised set.\"""",
"""	detailTopologyComplete = "\\nEach Apache Kafka broker process was measured, so the counts " +
		"above account for the whole advertised set.\"""", 1)
assert "Apache Kafka broker process" in s' \
  ./test/diagnosis 'TestKP15NoClaimNamesAKafkaImplementation|TestTheKafkaGoldenIncidentCorpus'

mutate K-M24 "the next-evidence recommendation becomes an instruction to restart a broker" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""			Kind:      diagnosis.AdviceKindNextEvidence,
			Safety:    diagnosis.SafetyCompare,
			Action:    recommendUnsuitable,""",
"""			Kind:      diagnosis.AdviceKindRemediation,
			Safety:    diagnosis.SafetyRestart,
			Action:    "Restart the unreachable brokers",""", 1)
assert "SafetyRestart" in s' \
  ./internal/diagnosis/kafka 'FuzzAdvertisedTopology|TestTheSuitabilityHypothesisNamesTheObservationThatWouldSettleIt'

mutate K-M25 "the positive half of the contrast is dropped from the evidence" \
  internal/diagnosis/kafka/topology.go \
  's = s.replace("""	for _, advertisement := range t.reached {
		if node, ok := t.reachingNode(advertisement); ok {
			refs = append(refs, node.ID())
		}
	}""", """""", 1)
assert "t.reachingNode(advertisement)" not in s' \
  ./internal/diagnosis/kafka 'TestTheTopologyReferencesCiteBothSidesOfTheContrast'

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
  echo "PHASE 10.2 MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 10.2 MUTATION CLOSURE: 0 survivors"
