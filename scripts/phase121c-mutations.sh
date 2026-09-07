#!/usr/bin/env bash
# Phase 12.1C mutation closure — Kubernetes Service findings and diagnosis.
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
# The four findings, the two rules, and the many things Phase 12.1C deliberately
# did not build:
#
#   KC-M01  a 404 on any operation becomes the Service-absence claim
#   KC-M02  the Service-absence predicate accepts any failure class
#   KC-M03  the Service-absence claim survives into the semantic branch
#   KC-M04  the absence claim states that the Service does not exist
#   KC-M05  the absence recommendation tells the operator to create the Service
#   KC-M06  a 401 becomes an authorization refusal
#   KC-M07  a refusal is admitted from FAIL as well as UNKNOWN
#   KC-M08  the denied operation loses its identity
#   KC-M09  an unrepresentable operation is published as its raw step name
#   KC-M10  a refusal claims the objects are absent
#   KC-M11  a refusal names RBAC
#   KC-M12  a refusal recommends cluster-admin
#   KC-M13  a refusal is published as CONFIRMED/ERROR
#   KC-M14  a refusal is published as a HYPOTHESIS
#   KC-M15  only the first denied read is reported
#   KC-M16  the selector claim drops its completeness requirement
#   KC-M17  the selector claim accepts an absent completeness flag
#   KC-M18  the selector claim accepts a non-passing Pod node
#   KC-M19  the selector claim fires at one Pod as well as zero
#   KC-M20  a selector-less Service produces the selector claim
#   KC-M21  an unrecognized Service type produces a semantic claim
#   KC-M22  ExternalName produces a semantic claim
#   KC-M23  the selector claim says the selector is wrong
#   KC-M24  the selector claim recommends changing the selector
#   KC-M25  the publication claim drops its completeness requirement
#   KC-M26  the publication claim fires at one ready endpoint
#   KC-M27  the terminating count is used as readiness
#   KC-M28  the endpoint count is used as readiness
#   KC-M29  the two publication detail variants are merged
#   KC-M30  the all-terminating note is emitted for a partly terminating set
#   KC-M31  the publication claim says the Service is unreachable
#   KC-M32  the publication claim says the Pods are unhealthy
#   KC-M33  the two semantic claims stop being disjoint
#   KC-M34  a finding drops its evidence references
#   KC-M35  a finding cites the branch it is not about
#   KC-M36  a claim's layer is written as a constant instead of read from its node
#   KC-M37  a Kubernetes rule reads the run-level incompleteness flag
#   KC-M38  a fifth Kubernetes finding code appears
#   KC-M39  a Kubernetes rule reaches for the evidence-relation machinery
#   KC-M40  the composition root wires a transport rule
#   KC-M41  the composition root stops wiring a Kubernetes rule
#   KC-M42  a Kubernetes finding names a count in its prose
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/diagnosis/kubernetes/acquisition.go
  internal/diagnosis/kubernetes/backends.go
  internal/diagnosis/kubernetes/shared.go
  internal/app/kubernetes.go
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
SURVIVORS=()

# mutate <id> <description> <file> <python-replacement> <test-package> <test-regex>
mutate() {
  local id="$1" desc="$2" file="$3" script="$4" pkg="$5" regex="$6"

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

echo "Phase 12.1C mutation closure — Kubernetes Service findings and diagnosis"
echo
echo "--- F1, the Service-absence claim (ADR 0094 section 10.3) ---"

# The step scope is what stops a Pod or EndpointSlice list answered 404 — the
# ordinary way a namespace that does not exist reports itself — becoming a claim
# about the Service.
mutate KC-M01 "a 404 on any operation becomes the Service-absence claim" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("""	node, ok := nodeAt(g, servicekubernetes.StepService)
	if !ok {
		return domain.Finding{}, false
	}
	if node.State() != domain.StateFail ||""",
"""	node, ok := nodeAt(g, servicekubernetes.StepPodSet)
	if !ok {
		node, ok = nodeAt(g, servicekubernetes.StepService)
	}
	if !ok {
		return domain.Finding{}, false
	}
	if node.State() != domain.StateFail ||""", 1)
assert "nodeAt(g, servicekubernetes.StepPodSet)" in s' \
  ./internal/diagnosis/kubernetes 'TestKP04OnlyAStructuredNotFoundOnTheServiceReadProducesTheAbsenceClaim'

mutate KC-M02 "the Service-absence predicate accepts any failure class" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("""	if node.State() != domain.StateFail ||
		node.FailureClass() != domain.FailureResourceNotFound {""",
"""	if node.State() != domain.StateFail {""", 1)
assert "node.FailureClass() != domain.FailureResourceNotFound" not in s' \
  ./internal/diagnosis/kubernetes 'TestKP04OnlyAStructuredNotFoundOnTheServiceReadProducesTheAbsenceClaim'

# The short circuit is the adapter's, but a rule that read a skipped node's
# absent attributes as zeros would undo it. This plants the reading.
mutate KC-M03 "an absent Service still produces a semantic claim" \
  internal/diagnosis/kubernetes/shared.go \
  's = s.replace("""	if node.State() != domain.StatePass {
		return false
	}""",
"""	if node.State() == domain.StateDegraded {
		return false
	}""", 1)
assert "node.State() == domain.StateDegraded" in s' \
  ./internal/diagnosis/kubernetes 'TestTheShortCircuitMatrixProducesExactlyTheseFindings'

mutate KC-M04 "the absence claim states that the Service does not exist" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("	summaryServiceNotFound = \"The Kubernetes API reported that no Service of this name exists \" +",
"	summaryServiceNotFound = \"This Service does not exist \" +", 1)
assert "This Service does not exist" in s' \
  ./internal/diagnosis/kubernetes 'TestNoKubernetesFindingEverExceedsItsClaimCeiling|TestTheClaimProseSaysWhatTheEvidenceCarries'

mutate KC-M05 "the absence recommendation tells the operator to create the Service" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("	recommendServiceNotFound = \"Verify the namespace and Service name this run declared \" +\n\t\t\"against the cluster it was pointed at\"",
"	recommendServiceNotFound = \"Create the Service in this namespace\"", 1)
assert "Create the Service in this namespace" in s' \
  ./internal/diagnosis/kubernetes 'TestNoKubernetesFindingEverExceedsItsClaimCeiling'

echo
echo "--- F2, the refusal claim (ADR 0094 sections 2.8 and 10.3) ---"

# **401 is not 403.** Collapsing them is svcdoctor inventing a distinction the API
# server did not make, in the direction that names an innocent policy.
mutate KC-M06 "a 401 becomes an authorization refusal" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("""		if node.State() != domain.StateUnknown ||
			node.FailureClass() != domain.FailureAuthzNotPermitted {
			continue
		}""",
"""		if node.FailureClass() != domain.FailureAuthzNotPermitted &&
			node.FailureClass() != domain.FailureAuthCredentialsRejected {
			continue
		}""", 1)
assert "domain.FailureAuthCredentialsRejected" in s' \
  ./internal/diagnosis/kubernetes 'TestKP03AuthenticationFailureNeverBecomesAnAuthorizationClaim'

# KC-M07 and KC-M18 point at the matrix rather than at the property that names
# them, and the reason is worth recording: the properties fix one variable each,
# so with the completeness flag held false KC-M18 is caught by the *completeness*
# check rather than by the state check, and with the class held to
# AUTH_CREDENTIALS_REJECTED KC-M07 never reaches AUTHZ_NOT_PERMITTED at all. Both
# survived the first run against those regexes. The matrix rows that catch them —
# "refusal class carried as a failure" and "unfinished pod node claiming
# completeness" — were added because these two plants showed the state halves
# were equivalent to nothing without them.
mutate KC-M07 "a refusal is admitted from FAIL as well as UNKNOWN" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("""		if node.State() != domain.StateUnknown ||
			node.FailureClass() != domain.FailureAuthzNotPermitted {""",
"""		if node.FailureClass() != domain.FailureAuthzNotPermitted {""", 1)
assert "node.State() != domain.StateUnknown ||\n\t\t\tnode.FailureClass()" not in s' \
  ./internal/diagnosis/kubernetes 'TestTheShortCircuitMatrixProducesExactlyTheseFindings'

# Without the operation the two refusals become byte-identical and convergence
# merges them into one claim naming one read while citing two.
mutate KC-M08 "the denied operation loses its identity" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("		operation, named := deniedOperations[step]",
"		operation, named := \"READ\", true\n		_ = deniedOperations", 1)
assert "operation, named := \"READ\", true" in s' \
  ./internal/diagnosis/kubernetes 'TestEachDeniedReadIsNamedByItsBoundedOperation|TestTwoDeniedReadsProduceTwoDistinguishableFindings'

# KC-M09 widens the scan to a step with no bounded operation **and** falls back to
# the raw step name, which is what an author reaching for "just print something"
# would write.
#
# The two halves have to be planted together, and that is the finding rather than
# an inconvenience: with the order fixed to the map's own keys the fallback branch
# is unreachable, so planting it alone is an equivalent mutation. Widening the
# order alone is caught by the `continue` — which is the fail-closed behaviour
# working. Planting both is the only shape that reaches the defect, and the
# matrix's "refusal on a node with no bounded operation" row is what sees it.
mutate KC-M09 "an unrepresentable operation is published as its raw step name" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("""var deniedOperationOrder = []domain.Step{
	servicekubernetes.StepService,""",
"""var deniedOperationOrder = []domain.Step{
	servicekubernetes.StepAPIAccess,
	servicekubernetes.StepService,""", 1)
s = s.replace("""		operation, named := deniedOperations[step]
		if !named {
			continue
		}""",
"""		operation, named := deniedOperations[step]
		if !named {
			operation = string(step)
		}""", 1)
assert "operation = string(step)" in s and "StepAPIAccess,\n\tservicekubernetes.StepService," in s' \
  ./internal/diagnosis/kubernetes 'TestTheShortCircuitMatrixProducesExactlyTheseFindings|TestEachDeniedReadIsNamedByItsBoundedOperation'

mutate KC-M10 "a refusal claims the objects are absent" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("		\"The read that was denied was %s.\"",
"		\"There are no Pods and no endpoints for this Service. The read that was denied was %s.\"", 1)
assert "There are no Pods and no endpoints" in s' \
  ./internal/diagnosis/kubernetes 'TestNoKubernetesFindingEverExceedsItsClaimCeiling'

mutate KC-M11 "a refusal names RBAC" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("	summaryAPIAccessDenied = \"The Kubernetes API denied this run\x27s identity the %s read, so \" +",
"	summaryAPIAccessDenied = \"RBAC is misconfigured for the %s read, so \" +", 1)
assert "RBAC is misconfigured" in s' \
  ./internal/diagnosis/kubernetes 'TestNoKubernetesFindingEverExceedsItsClaimCeiling'

mutate KC-M12 "a refusal recommends cluster-admin" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("	recommendAPIAccessDenied = \"Verify whether the identity this run used is authorized to \" +\n\t\t\"perform this read in this namespace\"",
"	recommendAPIAccessDenied = \"Bind the cluster-admin role to the identity this run used\"", 1)
assert "cluster-admin" in s' \
  ./internal/diagnosis/kubernetes 'TestNoKubernetesFindingEverExceedsItsClaimCeiling'

mutate KC-M13 "a refusal is published as an ERROR" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("""			Code:       CodeAPIAccessDenied,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityWarn,""",
"""			Code:       CodeAPIAccessDenied,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityError,""", 1)
assert "CodeAPIAccessDenied,\n\t\t\tKind:       domain.FindingKindConfirmed,\n\t\t\tSeverity:   domain.SeverityError," in s' \
  ./internal/diagnosis/kubernetes 'TestEveryProducedFindingMatchesItsFrozenContract'

mutate KC-M14 "a refusal is published as a HYPOTHESIS" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("""			Code:       CodeAPIAccessDenied,
			Kind:       domain.FindingKindConfirmed,""",
"""			Code:       CodeAPIAccessDenied,
			Kind:       domain.FindingKindHypothesis,""", 1)
assert "domain.FindingKindHypothesis" in s' \
  ./internal/diagnosis/kubernetes 'TestEveryProducedFindingMatchesItsFrozenContract'

# The two list reads are siblings, not a chain. Reporting only the first erases
# the second, and the second is what withholds the other semantic finding.
mutate KC-M15 "only the first denied read is reported" \
  internal/diagnosis/kubernetes/acquisition.go \
  's = s.replace("""		out = append(out, finding)
	}
	return out
}""",
"""		out = append(out, finding)
		return out
	}
	return out
}""", 1)
assert "		out = append(out, finding)\n		return out" in s' \
  ./internal/diagnosis/kubernetes 'TestTwoDeniedReadsProduceTwoDistinguishableFindings|TestTheShortCircuitMatrixProducesExactlyTheseFindings'

echo
echo "--- F3, the selector claim (ADR 0094 sections 2.5 and 10.3) ---"

# **An incomplete set is incomplete and never empty.** This is the single most
# important property in the phase.
mutate KC-M16 "the selector claim drops its completeness requirement" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	complete, ok := boolAttr(pods, servicekubernetes.AttrPodSetComplete)
	if !ok || !complete {
		return domain.Finding{}, false
	}""", "", 1)
assert "AttrPodSetComplete" not in s' \
  ./internal/diagnosis/kubernetes 'TestKP01AnIncompletePodSetNeverProducesASelectorClaim'

mutate KC-M17 "the selector claim reads an absent completeness flag as complete" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	complete, ok := boolAttr(pods, servicekubernetes.AttrPodSetComplete)
	if !ok || !complete {""",
"""	complete, ok := boolAttr(pods, servicekubernetes.AttrPodSetComplete)
	if ok && !complete {""", 1)
assert "	if ok && !complete {" in s' \
  ./internal/diagnosis/kubernetes 'TestTheShortCircuitMatrixProducesExactlyTheseFindings'

mutate KC-M18 "the selector claim accepts a non-passing Pod node" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	pods, ok := nodeAt(g, servicekubernetes.StepPodSet)
	if !ok || pods.State() != domain.StatePass {""",
"""	pods, ok := nodeAt(g, servicekubernetes.StepPodSet)
	if !ok {""", 1)
assert "pods.State() != domain.StatePass" not in s' \
  ./internal/diagnosis/kubernetes 'TestTheShortCircuitMatrixProducesExactlyTheseFindings'

mutate KC-M19 "the selector claim fires at one Pod as well as zero" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	observed, ok := intAttr(pods, servicekubernetes.AttrPodObservedCount)
	if !ok || observed != 0 {""",
"""	observed, ok := intAttr(pods, servicekubernetes.AttrPodObservedCount)
	if !ok || observed > 1 {""", 1)
assert "observed > 1" in s' \
  ./internal/diagnosis/kubernetes 'TestKP08AnyMatchingPodSuppressesTheSelectorClaim'

# **An empty selector map is selector-less, not match-all.** The one misreading
# that would turn a correctly configured Service into a claim that its backends
# vanished.
mutate KC-M20 "a selector-less Service produces the selector claim" \
  internal/diagnosis/kubernetes/shared.go \
  's = s.replace("""	selectorPresent, ok := boolAttr(node, servicekubernetes.AttrSelectorPresent)
	return ok && selectorPresent""",
"""	_, _ = boolAttr(node, servicekubernetes.AttrSelectorPresent)
	return true""", 1)
assert "	_, _ = boolAttr(node, servicekubernetes.AttrSelectorPresent)" in s' \
  ./internal/diagnosis/kubernetes 'TestKP05ASelectorLessServiceNeverProducesEitherSemanticClaim'

mutate KC-M21 "an unrecognized Service type produces a semantic claim" \
  internal/diagnosis/kubernetes/shared.go \
  's = s.replace("""	case servicekubernetes.ServiceTypeClusterIP,
		servicekubernetes.ServiceTypeNodePort,
		servicekubernetes.ServiceTypeLoadBalancer:
		return true
	default:
		return false
	}""",
"""	case servicekubernetes.ServiceTypeExternalName:
		return false
	default:
		return true
	}""", 1)
assert "case servicekubernetes.ServiceTypeExternalName:\n\t\treturn false" in s' \
  ./internal/diagnosis/kubernetes 'TestKP06AnUnsupportedServiceTypeNeverProducesEitherSemanticClaim'

mutate KC-M22 "ExternalName produces a semantic claim" \
  internal/diagnosis/kubernetes/shared.go \
  's = s.replace("""	serviceType, ok := stringAttr(node, servicekubernetes.AttrServiceType)
	if !ok || !supportsBackendPublication(serviceType) {
		return false
	}""", "", 1)
assert "supportsBackendPublication(serviceType)" not in s' \
  ./internal/diagnosis/kubernetes 'TestKP06AnUnsupportedServiceTypeNeverProducesEitherSemanticClaim'

mutate KC-M23 "the selector claim says the selector is wrong" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("	summarySelectsNoPods = \"This Service\x27s selector matched no Pod in its namespace at the \" +",
"	summarySelectsNoPods = \"This Service\x27s selector is wrong and matched no Pod at the \" +", 1)
assert "selector is wrong" in s' \
  ./internal/diagnosis/kubernetes 'TestNoKubernetesFindingEverExceedsItsClaimCeiling'

# KC-M24 is the one that survived the first run, and it is the most instructive.
#
# *"Change this Service's selector to match the intended workload"* is a
# well-formed NEXT_EVIDENCE/COMPARE recommendation with SelfCollectable false. It
# passes every structural check there is — and it is a remediation in the only
# sense that matters to the operator reading it. The guards that catch it now are
# the byte-for-byte text pin and the imperative refusal, both added because of
# this plant.
mutate KC-M24 "the selector claim recommends changing the selector" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("	recommendSelectsNoPods = \"Compare this Service\x27s selector with the labels on the Pods \" +\n\t\t\"intended to back it\"",
"	recommendSelectsNoPods = \"Change this Service\x27s selector to match the intended workload\"", 1)
assert "Change this Service" in s' \
  ./internal/diagnosis/kubernetes 'TestEveryRecommendationTextIsTheFrozenOne|TestNoRecommendationTellsAnOperatorToChangeAnything'

echo
echo "--- F4, the publication claim (ADR 0094 sections 2.6 and 10.3) ---"

mutate KC-M25 "the publication claim drops its completeness requirement" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	complete, ok := boolAttr(publication, servicekubernetes.AttrSliceSetComplete)
	if !ok || !complete {
		return domain.Finding{}, false
	}""", "", 1)
assert "AttrSliceSetComplete" not in s' \
  ./internal/diagnosis/kubernetes 'TestKP02AnIncompleteSliceSetNeverProducesAPublicationClaim'

mutate KC-M26 "the publication claim fires at one ready endpoint" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	ready, ok := intAttr(publication, servicekubernetes.AttrReadyEndpointCount)
	if !ok || ready != 0 {""",
"""	ready, ok := intAttr(publication, servicekubernetes.AttrReadyEndpointCount)
	if !ok || ready > 1 {""", 1)
assert "ready > 1" in s' \
  ./internal/diagnosis/kubernetes 'TestKP07AnyReadyEndpointSuppressesThePublicationClaim'

# `ready` already *is* Kubernetes' shortcut for "serving and not terminating".
# Substituting either of the other two silently changes meaning for a Service
# with publishNotReadyAddresses.
mutate KC-M27 "the terminating count is used as readiness" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("	ready, ok := intAttr(publication, servicekubernetes.AttrReadyEndpointCount)",
"	ready, ok := intAttr(publication, servicekubernetes.AttrTerminatingEndpointCount)", 1)
assert "ready, ok := intAttr(publication, servicekubernetes.AttrTerminatingEndpointCount)" in s' \
  ./internal/diagnosis/kubernetes 'TestKP07AnyReadyEndpointSuppressesThePublicationClaim|TestTheShortCircuitMatrixProducesExactlyTheseFindings'

mutate KC-M28 "the endpoint count is used as readiness" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("	ready, ok := intAttr(publication, servicekubernetes.AttrReadyEndpointCount)",
"	ready, ok := intAttr(publication, servicekubernetes.AttrEndpointCount)", 1)
assert "ready, ok := intAttr(publication, servicekubernetes.AttrEndpointCount)" in s' \
  ./internal/diagnosis/kubernetes 'TestTheShortCircuitMatrixProducesExactlyTheseFindings'

mutate KC-M29 "the two publication detail variants are merged" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	if slices == 0 {
		return detailNoReadyEndpointNoSlice, true
	}""", "", 1)
assert "return detailNoReadyEndpointNoSlice, true" not in s' \
  ./internal/diagnosis/kubernetes 'TestTheTwoPublicationDetailVariantsAreExactAndExclusive'

mutate KC-M30 "the all-terminating note is emitted for a partly terminating set" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("	return terminating == endpoints", "	return terminating > 0", 1)
assert "	return terminating > 0" in s' \
  ./internal/diagnosis/kubernetes 'TestTheTwoPublicationDetailVariantsAreExactAndExclusive'

mutate KC-M31 "the publication claim says the Service is unreachable" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("	summaryNoReadyEndpoint = \"Kubernetes published no ready endpoint for this Service at the \" +",
"	summaryNoReadyEndpoint = \"This Service is unreachable and has no ready endpoint at the \" +", 1)
assert "is unreachable" in s' \
  ./internal/diagnosis/kubernetes 'TestNoKubernetesFindingEverExceedsItsClaimCeiling'

mutate KC-M32 "the publication claim says the Pods are unhealthy" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("		\"published and no endpoint among them reports itself ready. The enumeration was \" +",
"		\"published and the Pods behind them are unhealthy. The enumeration was \" +", 1)
assert "are unhealthy" in s' \
  ./internal/diagnosis/kubernetes 'TestNoKubernetesFindingEverExceedsItsClaimCeiling'

echo
echo "--- the two rules together ---"

# ADR 0094 section 10.3 makes the two semantic claims disjoint, so one impact is
# never described twice at one severity.
mutate KC-M33 "the two semantic claims stop being disjoint" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	if selectsNothing {
		return domain.Finding{}, false
	}""", "", 1)
assert "	if selectsNothing {" not in s' \
  ./internal/diagnosis/kubernetes 'TestTestKP09TheTwoSemanticClaimsAreDisjoint|TestTheShortCircuitMatrixProducesExactlyTheseFindings'

mutate KC-M34 "the selector claim drops one of its evidence references" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("		EvidenceRefs: []domain.EvidenceID{service.ID(), pods.ID()},",
"		EvidenceRefs: []domain.EvidenceID{pods.ID()},", 1)
assert "EvidenceRefs: []domain.EvidenceID{pods.ID()}," in s' \
  ./internal/diagnosis/kubernetes 'TestEveryFindingCitesExactlyTheFrozenEvidence'

mutate KC-M35 "the publication claim cites the Pod branch it is not about" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("		EvidenceRefs: []domain.EvidenceID{service.ID(), publication.ID()},",
"		EvidenceRefs: []domain.EvidenceID{service.ID(), publication.ID(), pods.ID()},", 1)
s = s.replace("""func noReadyEndpoint(
	g domain.Graph, service domain.Evidence, selectsNothing bool,
) (domain.Finding, bool) {
	if selectsNothing {""",
"""func noReadyEndpoint(
	g domain.Graph, service domain.Evidence, selectsNothing bool,
) (domain.Finding, bool) {
	pods, _ := nodeAt(g, servicekubernetes.StepPodSet)
	if selectsNothing {""", 1)
assert "publication.ID(), pods.ID()}" in s' \
  ./internal/diagnosis/kubernetes 'TestNoFindingCitesANodeThatIsNotAboutIt|TestEveryFindingCitesExactlyTheFrozenEvidence'

# A claim whose layer is a constant can disagree with the node it cites. Phase
# 10.1B measured the other shape in PostgreSQL: a finding published at L5 while
# citing an L4 node, decided by an alphabet.
mutate KC-M36 "a claim's layer is written as a constant instead of read from its node" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("		Layer:   pods.Layer(),", "		Layer:   domain.LayerAuth,", 1)
assert "		Layer:   domain.LayerAuth," in s' \
  ./internal/diagnosis/kubernetes 'TestEveryProducedFindingMatchesItsFrozenContract'

# `RuleContext.Incomplete` is svcdoctor's statement about its **own execution**.
# A rule that consulted it would decide a per-set question from a run-level fact,
# where the per-set answer is on the node and is strictly more precise.
mutate KC-M37 "a Kubernetes rule reads the run-level incompleteness flag" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	service, ok := nodeAt(g, servicekubernetes.StepService)
	if !ok || !serviceGate(service) {
		return nil
	}""",
"""	service, ok := nodeAt(g, servicekubernetes.StepService)
	if !ok || !serviceGate(service) || ctx.Incomplete {
		return nil
	}""", 1)
assert "|| ctx.Incomplete {" in s' \
  ./internal/diagnosis/kubernetes 'TestNoKubernetesRuleReadsTheRuleContextBeyondItsGraph'

echo
echo "--- the phase boundary and the architecture ---"

mutate KC-M38 "a fifth Kubernetes finding code appears" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("const CodeNoReadyEndpoint domain.FindingCode = \"KUBERNETES_SERVICE_NO_READY_ENDPOINT\"",
"const CodeNoReadyEndpoint domain.FindingCode = \"KUBERNETES_SERVICE_NO_READY_ENDPOINT\"\n\n// CodeUnhealthy is a fifth code nobody decided.\nconst CodeUnhealthy domain.FindingCode = \"KUBERNETES_SERVICE_UNAVAILABLE\"", 1)
assert "KUBERNETES_SERVICE_UNAVAILABLE" in s' \
  ./test/security 'TestTheKubernetesFindingCodesAreExactlyTheFourFrozenOnes|TestMTG05TheFindingCodeCountIsUnchanged'

# ADR 0087's outcome is DEFER: the three relations have zero producers, and two
# AdmitConfidence guards are vacuous in a way that is safe only while
# AuthorityCompleteContrast has none either.
mutate KC-M39 "a Kubernetes rule reaches for the evidence-relation machinery" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("func Backends(ctx diagnosis.RuleContext) []domain.Finding {",
"var _ = diagnosis.AuthorityCompleteContrast\n\nfunc Backends(ctx diagnosis.RuleContext) []domain.Finding {", 1)
assert "AuthorityCompleteContrast" in s' \
  ./test/security 'TestNoKubernetesRuleActivatesAnEvidenceRelation'

# A Kubernetes graph holds no dns.lookup, tcp.connect or tls.handshake node, so a
# transport rule wired here would be silent by construction rather than by
# measurement — and would say the run measured something it did not.
mutate KC-M40 "the composition root wires a transport rule" \
  internal/app/kubernetes.go \
  's = s.replace("		Add(\"kubernetes/acquisition\", diagnosiskubernetes.Acquisition).",
"		Add(\"transport/dns\", diagnosistransport.DNS).\n		Add(\"kubernetes/acquisition\", diagnosiskubernetes.Acquisition).", 1)
s = s.replace("	\"github.com/hakanaltindag/svcdoctor/internal/diagnosis\"",
"	\"github.com/hakanaltindag/svcdoctor/internal/diagnosis\"\n	diagnosistransport \"github.com/hakanaltindag/svcdoctor/internal/diagnosis/transport\"", 1)
assert "transport/dns" in s' \
  ./test/security 'TestTheKubernetesCompositionRootWiresExactlyThreeRules'

mutate KC-M41 "the composition root stops wiring a Kubernetes rule" \
  internal/app/kubernetes.go \
  's = s.replace("		Add(\"kubernetes/backends\", diagnosiskubernetes.Backends).\n", "", 1)
assert "kubernetes/backends" not in s' \
  ./test/security 'TestTheKubernetesCompositionRootWiresExactlyThreeRules'

# A count in prose is a cluster'"'"'s cardinality in a document that may be shared,
# and it makes every sentence unpinnable.
mutate KC-M42 "a Kubernetes finding names a count in its prose" \
  internal/diagnosis/kubernetes/backends.go \
  's = s.replace("""	detail, ok := publicationDetail(publication)
	if !ok {
		return domain.Finding{}, false
	}""",
"""	detail, ok := publicationDetail(publication)
	if !ok {
		return domain.Finding{}, false
	}
	if slices, present := intAttr(publication, servicekubernetes.AttrSliceCount); present {
		detail += fmt.Sprintf("\\nSlices: %d.", slices)
	}""", 1)
s = s.replace("""import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis\"""",
"""import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis\"""", 1)
assert "Slices: %d." in s' \
  ./internal/diagnosis/kubernetes 'TestNoCountEverReachesAnyFindingsProse'

echo
echo "--- restoration ---"

AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "TREE NOT RESTORED — the working tree differs from the pre-run state."
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
  echo "PHASE 12.1C MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 12.1C MUTATION CLOSURE: 0 survivors"
