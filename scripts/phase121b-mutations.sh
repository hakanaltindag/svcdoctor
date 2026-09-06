#!/usr/bin/env bash
# Phase 12.1B mutation closure — Kubernetes client, authentication and acquisition.
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
# ADR 0094 section 2.11 named twenty-four plants for the Kubernetes work as a
# whole. The ones below are every one of them that Phase 12.1B can reach — the
# acquisition half — plus the plants this phase's own decisions earned. The four
# findings, their severities and their claim ceilings are Phase 12.1C's, and the
# plants for those belong to that phase's suite rather than to a stub here.
#
#   K-M01  an exec kubeconfig is accepted
#   K-M02  Connect trusts an earlier inspection instead of re-validating
#   K-M03  auth-provider is accepted
#   K-M04  impersonation is accepted
#   K-M05  proxy-url is accepted
#   K-M06  the ambient environment proxy is inherited
#   K-M07  insecure-skip-tls-verify is accepted
#   K-M08  a plaintext API server URL is accepted
#   K-M09  anonymous access is accepted
#   K-M10  two declared credentials are ranked instead of refused
#   K-M11  a credential bound elsewhere is silently rebound
#   K-M12  an empty selector is treated as match-all
#   K-M13  the Pod list omits its server-side selector
#   K-M14  the EndpointSlice list omits the service-name selector
#   K-M15  the owner-UID association check is removed
#   K-M16  a slice is associated by owner name instead of UID
#   K-M17  ready nil is read as false
#   K-M18  readiness is derived from serving instead of ready
#   K-M19  terminating nil is read as true
#   K-M20  an incomplete Pod set is reported complete
#   K-M21  an incomplete EndpointSlice set is reported complete
#   K-M22  a 410 restarts the enumeration
#   K-M23  cancellation is ignored mid-pagination
#   K-M24  the page ceiling is ignored
#   K-M25  the object budget is ignored
#   K-M26  the endpoint budget is ignored
#   K-M27  the explicit page limit is dropped
#   K-M28  a denied read becomes an empty set
#   K-M29  a denied read is reported as a target failure
#   K-M30  the API error classifier reads Status.Message
#   K-M31  a raw label value enters evidence
#   K-M32  an endpoint address enters evidence
#   K-M33  a per-Pod evidence node is created
#   K-M34  a selector-less Service still issues a Pod list
#   K-M35  ExternalName enters the publication path
#   K-M36  an unrecognized Service type unlocks behaviour
#   K-M37  API list order reaches a normalized value
#   K-M38  the report schema version moves
#   K-M39  a Kubernetes branch appears in the generic core
#   K-M40  the target's kubeconfig path enters evidence
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/adapter/kubernetes/client/kubeconfig.go
  internal/adapter/kubernetes/client/authority.go
  internal/adapter/kubernetes/client/acquire.go
  internal/adapter/kubernetes/client/paginate.go
  internal/adapter/kubernetes/client/apierror.go
  internal/adapter/kubernetes/client/budgets.go
  internal/adapter/kubernetes/client/result.go
  internal/adapter/kubernetes/evidence.go
  internal/app/kubernetes.go
  internal/fleet/config/load.go
  internal/domain/report.go
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
  #
  # A here-string rather than a pipe: `grep -q` exits at its first match, and
  # under `pipefail` the SIGPIPE that sends `printf` becomes the pipeline's
  # status, so a large selection was reported as no selection at all. Phase 10.2
  # measured that in every harness in this directory.
  local selected
  selected="$(go test "$pkg" -run "$regex" -count=1 -timeout 600s -v 2>/dev/null || true)"
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

echo "Phase 12.1B mutation closure — Kubernetes client, authentication and acquisition"
echo
echo "--- the refusals (ADR 0094 sections 2.2 and 5.3) ---"

# K-M01 is the release gate's own mutation. The guard is a sentinel file, so a
# build that refuses the target *after* invoking the plugin still fails it.
mutate K-M01 "an exec kubeconfig is accepted" \
  internal/adapter/kubernetes/client/kubeconfig.go \
  's = s.replace("	if authInfo.Exec != nil {", "	if false && authInfo.Exec != nil {", 1)
assert "if false && authInfo.Exec != nil {" in s' \
  ./internal/adapter/kubernetes/client 'TestAnExecKubeconfigNeverExecutesAnything'

# K-M02 makes Connect trust whatever Inspect concluded earlier.
#
# The refusal is repeated on purpose: Inspect runs at configuration time, possibly
# minutes earlier and possibly in a different process, and a kubeconfig that
# gained an `exec` stanza in between must not be reachable because an earlier pass
# said it was clean. Removing the re-validation is the time-of-check/time-of-use
# hole in the one check that matters most.
#
# An earlier version of this plant suppressed loadKubeconfig's error instead, and
# it is worth recording why it was replaced: it reached kubeconfigView.endpoint
# with a zero view and produced a nil dereference rather than the acceptance the
# plant was supposed to create — so it measured a crash, not the property. The
# nil path it exposed is now guarded in production.
mutate K-M02 "Connect trusts an earlier inspection instead of re-validating" \
  internal/adapter/kubernetes/client/authority.go \
  's = s.replace("""	if err := target.Validate(); err != nil {
		return nil, err
	}

	supplied := !credential.IsZero()""", """	supplied := !credential.IsZero()""", 1)
assert "	supplied := !credential.IsZero()" in s
assert "if err := target.Validate(); err != nil {\n\t\treturn nil, err\n\t}\n\n\tsupplied" not in s' \
  ./internal/adapter/kubernetes/client 'TestConnectRevalidatesRatherThanTrustingAnEarlierInspection'

mutate K-M03 "auth-provider is accepted" \
  internal/adapter/kubernetes/client/kubeconfig.go \
  's = s.replace("	if authInfo.AuthProvider != nil {", "	if false && authInfo.AuthProvider != nil {", 1)
assert "if false && authInfo.AuthProvider != nil {" in s' \
  ./internal/adapter/kubernetes/client 'TestEveryProhibitedConstructIsRefusedBeforeAnyRequest'

mutate K-M04 "impersonation is accepted" \
  internal/adapter/kubernetes/client/kubeconfig.go \
  's = s.replace("""	if authInfo.Impersonate != "" || authInfo.ImpersonateUID != "" ||
		len(authInfo.ImpersonateGroups) > 0 || len(authInfo.ImpersonateUserExtra) > 0 {""",
"""	if false {""", 1)
assert "	if false {" in s' \
  ./internal/adapter/kubernetes/client 'TestEveryProhibitedConstructIsRefusedBeforeAnyRequest'

mutate K-M05 "proxy-url is accepted" \
  internal/adapter/kubernetes/client/kubeconfig.go \
  's = s.replace("	if cluster.ProxyURL != \"\" {", "	if false && cluster.ProxyURL != \"\" {", 1)
assert "if false && cluster.ProxyURL" in s' \
  ./internal/adapter/kubernetes/client 'TestProxyURLIsRefusedAndItsValueNeverAppears'

# K-M06 is the vantage mutation: leaving Proxy nil hands routing to net/http's
# environment support, so HTTP_PROXY silently decides what the report measured.
#
# The guard is the **structural** test, not the behavioural one, and the reason is
# a measurement: this plant survived TestAnAmbientProxyCannotChangeTheAPIRoute,
# because net/http never proxies a loopback address whatever HTTP_PROXY says — so
# the hermetic fixture cannot observe the difference. The behavioural test stays
# (it proves the run works with hostile variables set); this points at the one
# that asserts rest.Config.Proxy is set at all.
mutate K-M06 "the ambient environment proxy is inherited" \
  internal/adapter/kubernetes/client/authority.go \
  's = s.replace("		Proxy: directDial,", "", 1)
assert "Proxy: directDial," not in s' \
  ./internal/adapter/kubernetes/client 'TestTheRESTConfigAlwaysSetsAnExplicitDirectProxy'

mutate K-M07 "insecure-skip-tls-verify is accepted" \
  internal/adapter/kubernetes/client/kubeconfig.go \
  's = s.replace("	if cluster.InsecureSkipTLSVerify {", "	if false && cluster.InsecureSkipTLSVerify {", 1)
assert "if false && cluster.InsecureSkipTLSVerify {" in s' \
  ./internal/adapter/kubernetes/client 'TestInsecureSkipTLSVerifyIsRefused'

mutate K-M08 "a plaintext API server URL is accepted" \
  internal/adapter/kubernetes/client/kubeconfig.go \
  's = s.replace("	if parsed.Scheme != \"https\" {", "	if false && parsed.Scheme != \"https\" {", 1)
assert "if false && parsed.Scheme" in s' \
  ./internal/adapter/kubernetes/client 'TestAPlaintextAPIServerIsRefused'

mutate K-M09 "anonymous access is accepted" \
  internal/adapter/kubernetes/client/kubeconfig.go \
  's = s.replace("""	default:
		return fmt.Errorf("%w: neither the target nor the selected kubeconfig user declares a "+""",
"""	default:
		view.mode = servicekubernetes.AuthModeToken
		view.token = "anonymous"
		return nil
	case false:
		return fmt.Errorf("%w: neither the target nor the selected kubeconfig user declares a "+""", 1)
assert "view.token = \"anonymous\"" in s' \
  ./internal/adapter/kubernetes/client 'TestEveryProhibitedConstructIsRefusedBeforeAnyRequest'

mutate K-M10 "two declared credentials are ranked instead of refused" \
  internal/adapter/kubernetes/client/kubeconfig.go \
  's = s.replace("	if declared > 1 {", "	if false && declared > 1 {", 1)
assert "if false && declared > 1 {" in s' \
  ./internal/adapter/kubernetes/client 'TestTwoCredentialsAreRefusedRatherThanRankedByPrecedence'

# K-M11 is ADR 0050 section 4: a composition root may not rebind a credential.
#
# It survived a first version of the guard that matched "bound to", because
# security.Credential.SecretFor refuses the mismatch too and its message contains
# the same words. Two independent mechanisms is the right design; matching the
# weaker one hid the stronger. The guard now asserts svcdoctor's own sentence,
# which only the check that runs **before a rest.Config is built** produces.
mutate K-M11 "a credential bound elsewhere is silently rebound" \
  internal/adapter/kubernetes/client/authority.go \
  's = s.replace("""		if !supplied.Endpoint().Equal(endpoint) {""",
"""		if false && !supplied.Endpoint().Equal(endpoint) {""", 1)
assert "if false && !supplied.Endpoint()" in s' \
  ./internal/adapter/kubernetes/client 'TestACredentialBoundElsewhereIsRefusedRatherThanRebound'

echo
echo "--- selection and association (ADR 0094 sections 2.4, 2.6 and 9.1) ---"

# K-M12 is the single mistake that would turn a correctly configured
# selector-less Service into a claim that its backends vanished.
#
# The guard is the direct normalizer test rather than the end-to-end one, and that
# is forced by serialization: `Selector` carries `json:"selector,omitempty"`, so an
# empty map is omitted on the wire and decodes as nil. The hermetic server cannot
# deliver the empty-map case at all, and this plant survived every test that went
# through it.
mutate K-M12 "an empty selector is treated as match-all" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("		SelectorPresent:  len(service.Spec.Selector) > 0,",
"		SelectorPresent:  service.Spec.Selector != nil,", 1)
assert "service.Spec.Selector != nil," in s' \
  ./internal/adapter/kubernetes/client 'TestNormalizeServiceReadsAnEmptyMapAsSelectorLess'

# K-M13 turns exact Kubernetes selection into a namespace-wide list. It is the
# mutation that makes "a complete server-filtered list was empty" mean something
# else entirely.
mutate K-M13 "the Pod list omits its server-side selector" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("		ctx, OperationListPods, budgets, labels.Set(selector).String(), budgets.MaxPods,",
"		ctx, OperationListPods, budgets, \"\", budgets.MaxPods,", 1)
assert "OperationListPods, budgets, \"\", budgets.MaxPods," in s' \
  ./internal/adapter/kubernetes/client 'TestEachRequestHasTheExactShapeTheContractFroze'

mutate K-M14 "the EndpointSlice list omits the service-name selector" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("	selector := labels.Set{discoveryv1.LabelServiceName: target.ServiceName}.String()",
"	selector := \"\"", 1)
assert "	selector := \"\"" in s' \
  ./internal/adapter/kubernetes/client 'TestEachRequestHasTheExactShapeTheContractFroze'

# K-M15 removes the delete-and-recreate guard, so a slice from the previous
# generation of the Service is counted as this one's backend.
mutate K-M15 "the owner-UID association check is removed" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("		return string(owner.UID) == a.serviceUID", "		return true", 1)
assert "		return true\n	}\n	return true" in s' \
  ./internal/adapter/kubernetes/client 'TestServiceAssociationIsByLabelAndOwnerUID'

# K-M16 is the same guard weakened rather than removed: matching on the owner's
# name, which is exactly the value that survives a delete and recreate.
mutate K-M16 "a slice is associated by owner name instead of UID" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("		return string(owner.UID) == a.serviceUID",
"		return owner.Name != \"\"", 1)
assert "return owner.Name != \"\"" in s' \
  ./internal/adapter/kubernetes/client 'TestServiceAssociationIsByLabelAndOwnerUID'

echo
echo "--- endpoint semantics (ADR 0094 section 2.6) ---"

mutate K-M17 "ready nil is read as false" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("func EffectiveReady(ready *bool) bool { return ready == nil || *ready }",
"func EffectiveReady(ready *bool) bool { return ready != nil && *ready }", 1)
assert "return ready != nil && *ready" in s' \
  ./internal/adapter/kubernetes/client 'TestTheNilConditionSemanticsAreExactlyTheFrozenOnes'

# K-M18 substitutes serving for ready, which silently changes meaning for a
# Service with publishNotReadyAddresses and counts a draining endpoint as ready.
mutate K-M18 "readiness is derived from serving instead of ready" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("		if EffectiveReady(endpoint.Conditions.Ready) {",
"		if EffectiveServing(endpoint.Conditions.Serving) {", 1)
assert "if EffectiveServing(endpoint.Conditions.Serving) {" in s' \
  ./internal/adapter/kubernetes/client 'TestEffectiveReadyConsultsReadyAndNothingElse'

mutate K-M19 "terminating nil is read as true" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("	return terminating != nil && *terminating", "	return terminating == nil || *terminating", 1)
assert "return terminating == nil || *terminating" in s' \
  ./internal/adapter/kubernetes/client 'TestTheNilConditionSemanticsAreExactlyTheFrozenOnes'

echo
echo "--- completeness and budgets (ADR 0094 section 2.5) ---"

mutate K-M20 "an incomplete Pod set is reported complete" \
  internal/adapter/kubernetes/client/result.go \
  's = s.replace("func (e Enumeration) Complete() bool { return e.Attempted && e.Stop == StopComplete }",
"func (e Enumeration) Complete() bool { return e.Attempted }", 1)
assert "func (e Enumeration) Complete() bool { return e.Attempted }" in s' \
  ./internal/adapter/kubernetes/client 'TestEveryWayAnEnumerationCanStop|TestOnlyACompleteEnumerationAdmitsAUniversalClaim'

mutate K-M21 "a skipped enumeration is reported complete" \
  internal/adapter/kubernetes/client/result.go \
  's = s.replace("func (e Enumeration) Complete() bool { return e.Attempted && e.Stop == StopComplete }",
"func (e Enumeration) Complete() bool { return e.Stop == StopComplete }", 1)
assert "func (e Enumeration) Complete() bool { return e.Stop == StopComplete }" in s' \
  ./internal/adapter/kubernetes/client 'TestOnlyACompleteEnumerationAdmitsAUniversalClaim|TestASelectorLessServiceIssuesNeitherListAndIsNeverMatchAll'

# K-M22 restarts the enumeration from page one, which samples a different moment
# and presents two reads as one.
mutate K-M22 "a 410 restarts the enumeration" \
  internal/adapter/kubernetes/client/paginate.go \
  's = s.replace("""			case FailureResourceExpired:
				out.Stop = StopResourceExpired""",
"""			case FailureResourceExpired:
				options.Continue = ""
				out.Stop = StopComplete
				continue""", 1)
assert "out.Stop = StopComplete\n\t\t\t\tcontinue" in s' \
  ./internal/adapter/kubernetes/client 'TestA410IsNeverSilentlyRestarted'

# K-M23's guard counts **fetch calls**, not outcomes. The end-to-end cancellation
# test proves the set is incomplete, but a request issued on a dead context fails
# at the transport and reaches the same outcome by a different route — so the
# plant survived it. What the pre-request check buys is that no further round trip
# is attempted at all, and only a counter can see that.
mutate K-M23 "cancellation is ignored mid-pagination" \
  internal/adapter/kubernetes/client/paginate.go \
  's = s.replace("""		if err := ctx.Err(); err != nil {
			out.Stop = StopCancelled""",
"""		if err := ctx.Err(); false {
			out.Stop = StopCancelled""", 1)
assert "if err := ctx.Err(); false {" in s' \
  ./internal/adapter/kubernetes/client 'TestPaginationIssuesNoRequestOnADeadContext|TestPaginationStopsBetweenPagesWhenTheBudgetEnds'

mutate K-M24 "the page ceiling is ignored" \
  internal/adapter/kubernetes/client/paginate.go \
  's = s.replace("	for out.Pages < budgets.MaxPages {", "	for out.Pages < 1000 {", 1)
assert "for out.Pages < 1000 {" in s' \
  ./internal/adapter/kubernetes/client 'TestPaginationIsBoundedEvenWhenTheServerNeverStops|TestEveryWayAnEnumerationCanStop'

mutate K-M25 "the object budget is ignored" \
  internal/adapter/kubernetes/client/paginate.go \
  's = s.replace("		if maxObjects > 0 && out.Observed >= maxObjects {",
"		if false && maxObjects > 0 && out.Observed >= maxObjects {", 1)
assert "if false && maxObjects > 0" in s' \
  ./internal/adapter/kubernetes/client 'TestEveryWayAnEnumerationCanStop|TestTheSliceBudgetMakesTheSetIncomplete'

mutate K-M26 "the endpoint budget is ignored" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("		if a.facts.Endpoints >= a.maxEndpoints {",
"		if false && a.facts.Endpoints >= a.maxEndpoints {", 1)
assert "if false && a.facts.Endpoints >= a.maxEndpoints {" in s' \
  ./internal/adapter/kubernetes/client 'TestTheEndpointBudgetStopsBeforeCountingPastIt'

# K-M27 drops the explicit limit, so the server chooses the page size and the
# object bound stops being svcdoctor's.
mutate K-M27 "the explicit page limit is dropped" \
  internal/adapter/kubernetes/client/paginate.go \
  's = s.replace("	options := metav1.ListOptions{Limit: budgets.PageSize, LabelSelector: selector}",
"	options := metav1.ListOptions{LabelSelector: selector}", 1)
assert "options := metav1.ListOptions{LabelSelector: selector}" in s' \
  ./internal/adapter/kubernetes/client 'TestEachRequestHasTheExactShapeTheContractFroze'

echo
echo "--- denial is never emptiness (ADR 0094 section 8.3) ---"

mutate K-M28 "a denied read becomes an empty set" \
  internal/adapter/kubernetes/client/paginate.go \
  's = s.replace("""			default:
				out.Stop = StopRequestFailed
			}""", """			default:
				out.Stop = StopComplete
			}""", 1)
assert "out.Stop = StopComplete\n			}" in s' \
  ./internal/adapter/kubernetes/client 'TestAnIncompleteEnumerationIsNeverZero|TestEveryWayAnEnumerationCanStop'

# K-M29 makes a denial a statement about the target rather than about the
# measurement, which is the difference between "not allowed to look" and
# "there is nothing there".
mutate K-M29 "a denied read is reported as a target failure" \
  internal/adapter/kubernetes/evidence.go \
  's = s.replace("""	case client.FailureForbidden:
		// UNKNOWN, not FAIL. The target did not fail; svcdoctor'"'"'s measurement was
		// blocked, and every universal claim over the set it would have produced
		// is withheld.
		return domain.StateUnknown, domain.FailureAuthzNotPermitted""",
"""	case client.FailureForbidden:
		return domain.StateFail, domain.FailureAuthzNotPermitted""", 1)
assert "return domain.StateFail, domain.FailureAuthzNotPermitted" in s' \
  ./internal/adapter/kubernetes 'TestTheStateMappingKeepsDeniedApartFromAbsent'

echo
echo "--- data minimization (ADR 0094 section 11.2) ---"

# K-M30's guard is **structural**, and that is the finding rather than a
# convenience. A first version planted a classifier that branched on the message
# and it survived every behavioural test, because the branch it added was
# unreachable for the inputs those tests supply — and once the normalized values
# are enums, a message has no room to reach the output at all. The contract is
# about the source ("never read, never matched, never parsed"), so the guard reads
# the source.
mutate K-M30 "the API error classifier reads Status.Message" \
  internal/adapter/kubernetes/client/apierror.go \
  's = s.replace("	return classifyStatus(status.ErrStatus.Code, status.ErrStatus.Reason)",
"""	if len(status.ErrStatus.Message) > 4096 {
		return FailureAPIError
	}
	return classifyStatus(status.ErrStatus.Code, status.ErrStatus.Reason)""", 1)
assert "status.ErrStatus.Message" in s' \
  ./test/security 'TestNoKubernetesSourceReadsAStatusMessage'

mutate K-M31 "a raw selector value enters evidence" \
  internal/adapter/kubernetes/evidence.go \
  's = s.replace("""		attributes[servicekubernetes.AttrSelectorKeyCount] =
			domain.IntAttr(int64(facts.SelectorKeyCount))""",
"""		attributes[servicekubernetes.AttrSelectorKeyCount] =
			domain.IntAttr(int64(facts.SelectorKeyCount))
		attributes["k8s.selector_raw"] = domain.StringAttr("app=payments")""", 1)
assert "k8s.selector_raw" in s' \
  ./internal/adapter/kubernetes 'TestTheAttributeSetIsExactlyWhatWasFrozen'

mutate K-M32 "an endpoint address enters evidence" \
  internal/adapter/kubernetes/evidence.go \
  's = s.replace("""		attributes[servicekubernetes.AttrEndpointCount] =
			domain.IntAttr(int64(facts.Endpoints))""",
"""		attributes[servicekubernetes.AttrEndpointCount] =
			domain.IntAttr(int64(facts.Endpoints))
		attributes["k8s.endpoint_addresses"] = domain.HostListAttr("10.244.0.1")""", 1)
assert "k8s.endpoint_addresses" in s' \
  ./internal/adapter/kubernetes 'TestTheAttributeSetIsExactlyWhatWasFrozen'

# K-M33 is the cardinality explosion: one node per Pod turns a five-node report
# into a cluster inventory and makes every renderer scale with the environment.
mutate K-M33 "a per-Pod evidence node is created" \
  internal/adapter/kubernetes/evidence.go \
  's = s.replace("""	if err := recordPublication(""",
"""	for i := 0; i < result.Pods.Observed; i++ {
		perPod, podErr := add(builder, domain.EvidenceInput{
			ID:        domain.EvidenceID(fmt.Sprintf("k8s.pod/%s/%d", label, i)),
			Subject:   subject,
			Layer:     domain.LayerTopology,
			Step:      "k8s.pod",
			State:     domain.StatePass,
			StartedAt: startedAt,
			Elapsed:   domain.Unmeasured(),
		})
		if podErr != nil {
			return "", podErr
		}
		_ = perPod
	}
	if err := recordPublication(""", 1)
assert "k8s.pod/%s/%d" in s' \
  ./internal/adapter/kubernetes 'TestNoPerPodOrPerEndpointNodeExists|TestTheGraphIsAlwaysFiveNodesInTheFrozenShape'

# K-M40's anchor sits on `k8s.service`, where ADR 0094 §11.1 places the two
# identity keys. It was on `k8s.target` until the Phase 12.1B review pass moved
# them to the node the frozen table names, and the harness reported the plant as
# **unplantable** rather than as caught — which is the zero-match guard doing its
# job on the mutation side as well as on the test side.
mutate K-M40 "the target's kubeconfig path enters evidence" \
  internal/adapter/kubernetes/evidence.go \
  's = s.replace("""		servicekubernetes.AttrServiceName: domain.IdentityAttr(result.Target.ServiceName),""",
"""		servicekubernetes.AttrServiceName: domain.IdentityAttr(result.Target.ServiceName),
		"k8s.kubeconfig_path":              domain.IdentityAttr(result.Target.Kubeconfig),""", 1)
assert "k8s.kubeconfig_path" in s' \
  ./internal/adapter/kubernetes 'TestNoFilesystemPathOrAPIServerAddressReachesEvidence|TestTheAttributeSetIsExactlyWhatWasFrozen'

echo
echo "--- request planning (ADR 0094 sections 7.4 and 10.8) ---"

mutate K-M34 "a selector-less Service still issues a Pod list" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("""	if !facts.SelectorPresent {
		return false, false
	}""", """	if false {
		return false, false
	}""", 1)
assert "	if false {\n		return false, false\n	}" in s' \
  ./internal/adapter/kubernetes/client 'TestASelectorLessServiceIssuesNeitherListAndIsNeverMatchAll'

mutate K-M35 "ExternalName enters the publication path" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("""	case servicekubernetes.ServiceTypeClusterIP,
		servicekubernetes.ServiceTypeNodePort,
		servicekubernetes.ServiceTypeLoadBalancer:
	default:
		return false, false
	}""", """	case servicekubernetes.ServiceTypeClusterIP,
		servicekubernetes.ServiceTypeNodePort,
		servicekubernetes.ServiceTypeLoadBalancer,
		servicekubernetes.ServiceTypeExternalName:
	default:
		return false, false
	}""", 1)
assert "servicekubernetes.ServiceTypeExternalName:\n	default:" in s' \
  ./internal/adapter/kubernetes/client 'TestAnExternalNameServiceIsUnsupportedAndNotAFailure|TestTheServiceTypeMatrixIsExactlyTheFrozenOne'

# K-M36 makes an unrecognized `spec.type` unlock behaviour, which is the wrong
# direction for a value svcdoctor did not write.
mutate K-M36 "an unrecognized Service type unlocks behaviour" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("""	default:
		return servicekubernetes.ServiceTypeUnknown
	}""", """	default:
		return servicekubernetes.ServiceTypeClusterIP
	}""", 1)
assert "	default:\n		return servicekubernetes.ServiceTypeClusterIP\n	}" in s' \
  ./internal/adapter/kubernetes/client 'TestTheServiceTypeMatrixIsExactlyTheFrozenOne'

echo
echo "--- determinism and the frozen counts ---"

# K-M37 removes the **endpoint** sort, so which endpoints a truncated enumeration
# counted depends on the order the API returned them in.
#
# It survived a guard that permuted slices, which exercises the slice sort and
# leaves this one untouched. Endpoints inside one slice are a second ordering, and
# only a permutation of them under the endpoint ceiling can see it.
mutate K-M37 "API list order reaches a normalized value" \
  internal/adapter/kubernetes/client/acquire.go \
  's = s.replace("""	ordered := slices.Clone(slice.Endpoints)
	slices.SortStableFunc(ordered, func(x, y discoveryv1.Endpoint) int {
		return strings.Compare(endpointOrderKey(x), endpointOrderKey(y))
	})""", """	ordered := slices.Clone(slice.Endpoints)""", 1)
assert "endpointOrderKey(x), endpointOrderKey(y)" not in s' \
  ./internal/adapter/kubernetes/client 'TestEndpointOrderWithinASliceNeverReachesANormalizedValue'

mutate K-M38 "the report schema version moves" \
  internal/domain/report.go \
  's = s.replace("const SchemaVersion = 1", "const SchemaVersion = 2", 1)
assert "const SchemaVersion = 2" in s' \
  ./internal/app 'TestTheSchemaVersionsDoNotMove'

# K-M39 is ADR 0071 section 6.3, measured for a fifth service: a service name in
# the generic configuration core is the first line of the central branching the
# extensibility rule forbids.
mutate K-M39 "a Kubernetes branch appears in the generic core" \
  internal/fleet/config/load.go \
  's = s.replace("""	deriver, derives := factory.(EndpointDeriver)""",
"""	deriver, derives := factory.(EndpointDeriver)
	if block.Type == "kubernetes" {
		derives = true
	}""", 1)
assert "block.Type == \"kubernetes\"" in s' \
  ./test/security 'TestNoKubernetesSpecialCaseExistsInAnyGenericPackage|TestTheGenericCoreNamesNoService'

echo
echo "--- the phase boundary ---"

# K-M41 is Phase 12.1B's own boundary: a finding produced here would carry none
# of the claim ceilings ADR 0094 section 2.7 froze for Phase 12.1C.
mutate K-M41 "the acquisition layer produces a finding" \
  internal/adapter/kubernetes/evidence.go \
  's = s.replace("// Record writes one acquisition", "// FindingCode leaks in early.\n// Record writes one acquisition", 1)
s = s.replace("	servicekubernetes \"github.com/hakanaltindag/svcdoctor/internal/service/kubernetes\"",
"	servicekubernetes \"github.com/hakanaltindag/svcdoctor/internal/service/kubernetes\"\n)\n\nvar _ = domain.NewFinding\n\nvar (", 1)
assert "domain.NewFinding" in s' \
  ./test/security 'TestTheKubernetesAdapterNeverProducesAFinding'

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
  echo "PHASE 12.1B MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 12.1B MUTATION CLOSURE: 0 survivors"
