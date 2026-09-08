#!/usr/bin/env bash
# Phase 12.1C.2 mutation closure — the Kubernetes leaf CLI.
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
# The public surface Phase 12.1C.1 froze, the credential rules that surface
# carries, and the wiring that keeps the leaf a composition rather than a second
# implementation:
#
#   KL-M01  the command is not registered under diagnose
#   KL-M02  the command is registered under a second spelling
#   KL-M03  a frozen flag disappears
#   KL-M04  a frozen flag is renamed
#   KL-M05  an eleventh flag appears
#   KL-M06  --step-timeout is added back out of habit
#   KL-M07  an acquisition budget becomes a flag
#   KL-M08  the acquisition budgets are set to something other than the frozen defaults
#   KL-M09  --timeout stops defaulting to 30s
#   KL-M10  --output stops defaulting to text
#   KL-M11  --shareable defaults to true
#   KL-M12  a non-positive timeout is accepted
#   KL-M13  the output format is not checked
#   KL-M14  the two token sources stop being exclusive
#   KL-M15  a declared token source is not reported to Inspect
#   KL-M16  an empty declared token source is treated as no credential
#   KL-M17  an empty declared token source falls back to the kubeconfig identity
#   KL-M18  the credential is bound to something other than the derived API server
#   KL-M19  the credential is given an identity
#   KL-M20  the target's shape is not validated at all
#   KL-M21  a target refusal is reported as an internal failure
#   KL-M22  the CLI restates a target rule instead of asking the adapter
#   KL-M23  the generic secret helper hard-codes one command's flag names
#   KL-M24  the generic secret helper's file message loses the caller's flag
#   KL-M25  a positional argument is accepted
#   KL-M26  the command bypasses the generic exit mapping
#   KL-M27  the command bypasses the shareable projection
#   KL-M28  the command renders in a format it did not validate
#
# Every mutation is planted in production code, never in a test. A suite that
# mutates its own assertions measures nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/cli/kubernetes.go
  internal/cli/root.go
  internal/cli/secret.go
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
  # would read as a pass. Checked on the pristine tree, before planting. A
  # here-string rather than a pipe, for the SIGPIPE reason Phase 10.2 measured.
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

echo "Phase 12.1C.2 mutation closure — the Kubernetes leaf CLI"
echo
echo "--- registration (ADR 0041, PHASE121C1 section 5) ---"

mutate KL-M01 "the command is not registered under diagnose" \
  internal/cli/root.go \
  's = s.replace("""	case "kubernetes":
		return a.diagnoseKubernetesCommand(ctx, args[1:])""",
"""	case "kubernetes-disabled":
		return a.diagnoseKubernetesCommand(ctx, args[1:])""", 1)
assert "kubernetes-disabled" in s' \
  ./internal/cli 'TestTheKubernetesCommandIsRoutedUnderDiagnose'

mutate KL-M02 "the command is registered under a second spelling" \
  internal/cli/root.go \
  's = s.replace("""	case "kubernetes":
		return a.diagnoseKubernetesCommand(ctx, args[1:])""",
"""	case "kubernetes", "k8s":
		return a.diagnoseKubernetesCommand(ctx, args[1:])""", 1)
assert chr(34) + "k8s" + chr(34) in s' \
  ./internal/cli 'TestTheKubernetesCommandIsRoutedUnderDiagnose'

echo
echo "--- the ten frozen flags (PHASE121C1 section 5) ---"

mutate KL-M03 "a frozen flag disappears" \
  internal/cli/kubernetes.go \
  's = s.replace("""		serviceName = fs.String("service-name", "", "the Service to diagnose")""",
"""		serviceName = new(string)""", 1)
assert "serviceName = new(string)" in s' \
  ./internal/cli 'TestTheKubernetesFlagSurfaceIsExact'

mutate KL-M04 "a frozen flag is renamed" \
  internal/cli/kubernetes.go \
  's = s.replace(chr(34) + "service-name" + chr(34) + ", " + chr(34) + chr(34),
                 chr(34) + "service" + chr(34) + ", " + chr(34) + chr(34), 1)
assert "fs.String(" + chr(34) + "service" + chr(34) in s' \
  ./internal/cli 'TestTheKubernetesFlagSurfaceIsExact'

mutate KL-M05 "an eleventh flag appears" \
  internal/cli/kubernetes.go \
  's = s.replace("""		shareable = fs.Bool("shareable", false, "produce the shareable redacted report")""",
"""		shareable = fs.Bool("shareable", false, "produce the shareable redacted report")
		_         = fs.Bool("verbose", false, "an eleventh flag nobody authorized")""", 1)
assert "verbose" in s' \
  ./internal/cli 'TestTheKubernetesFlagSurfaceIsExact'

mutate KL-M06 "--step-timeout is added back out of habit" \
  internal/cli/kubernetes.go \
  's = s.replace("""		output      = fs.String("output", "text", `"text" or "json"`)""",
"""		output      = fs.String("output", "text", `"text" or "json"`)
		_           = fs.Duration("step-timeout", 0, "a bound with nothing to bound")""", 1)
assert "step-timeout" in s' \
  ./internal/cli 'TestTheKubernetesFlagSurfaceIsExact|TestTheKubernetesCommandRejectsForbiddenFlags'

mutate KL-M07 "an acquisition budget becomes a flag" \
  internal/cli/kubernetes.go \
  's = s.replace("""		output      = fs.String("output", "text", `"text" or "json"`)""",
"""		output      = fs.String("output", "text", `"text" or "json"`)
		_           = fs.Int("max-pods", 4000, "an internal safety limit as a knob")""", 1)
assert "max-pods" in s' \
  ./internal/cli 'TestTheKubernetesFlagSurfaceIsExact|TestTheKubernetesCommandRejectsForbiddenFlags'

mutate KL-M08 "the acquisition budgets are set to something other than the frozen defaults" \
  internal/cli/kubernetes.go \
  's = s.replace("""			Target:     target,
			Credential: credential,""",
"""			Target:     target,
			Credential: credential,
			Budgets:    client.Budgets{MaxPods: 1},""", 1)
s = s.replace("""	"github.com/hakanaltindag/svcdoctor/internal/app" """.strip(),
"""	"github.com/hakanaltindag/svcdoctor/internal/adapter/kubernetes/client"
	"github.com/hakanaltindag/svcdoctor/internal/app" """.strip(), 1)
assert "MaxPods: 1" in s' \
  ./internal/cli 'TestTheKubernetesAcquisitionBudgetsAreNotReachable'

echo
echo "--- defaults (PHASE121C1 sections 9.1 and 9.4) ---"

mutate KL-M09 "--timeout stops defaulting to 30s" \
  internal/cli/kubernetes.go \
  's = s.replace("""fs.Duration("timeout", 30*time.Second""",
"""fs.Duration("timeout", 10*time.Second""", 1)
assert "10*time.Second" in s' \
  ./internal/cli 'TestTheKubernetesDefaultsAreTheFrozenOnes'

mutate KL-M10 "--output stops defaulting to text" \
  internal/cli/kubernetes.go \
  's = s.replace("""fs.String("output", "text" """.strip(),
"""fs.String("output", "json" """.strip(), 1)
assert chr(34) + "output" + chr(34) + ", " + chr(34) + "json" + chr(34) in s' \
  ./internal/cli 'TestTheKubernetesDefaultsAreTheFrozenOnes'

mutate KL-M11 "--shareable defaults to true" \
  internal/cli/kubernetes.go \
  's = s.replace("""fs.Bool("shareable", false""", """fs.Bool("shareable", true""", 1)
assert chr(34) + "shareable" + chr(34) + ", true" in s' \
  ./internal/cli 'TestTheKubernetesDefaultsAreTheFrozenOnes'

mutate KL-M12 "a non-positive timeout is accepted" \
  internal/cli/kubernetes.go \
  's = s.replace("""	if *timeout <= 0 {
		return kubernetesCommand{}, usagef("--timeout %s must be positive", *timeout)
	}""", "", 1)
assert "must be positive" not in s' \
  ./internal/cli 'TestKP03AnInvalidInvocationNeverStartsARun'

mutate KL-M13 "the output format is not checked" \
  internal/cli/kubernetes.go \
  's = s.replace("""	if err := checkOutput(*output); err != nil {
		return kubernetesCommand{}, err
	}""", "", 1)
assert "checkOutput" not in s' \
  ./internal/cli 'TestKP03AnInvalidInvocationNeverStartsARun'

echo
echo "--- the credential (PHASE121C1 sections 7 and 13) ---"

mutate KL-M14 "the two token sources stop being exclusive" \
  internal/cli/kubernetes.go \
  's = s.replace("""	if err := sources.validate(); err != nil {
		return kubernetesCommand{}, err
	}

	target := app.KubernetesTarget{""", """	target := app.KubernetesTarget{""", 1)
assert "sources.validate()" not in s' \
  ./internal/cli 'TestTheKubernetesTokenSourcesAreExclusiveAndNamed'

mutate KL-M15 "a declared token source is not reported to Inspect" \
  internal/cli/kubernetes.go \
  's = s.replace("app.InspectKubernetesTarget(target, sources.declared())",
                 "app.InspectKubernetesTarget(target, false)", 1)
assert "InspectKubernetesTarget(target, false)" in s' \
  ./internal/cli 'TestTheKubernetesCommandRefusesAKubeconfigCredentialAmbiguity|TestATokenSourceIsRefusedInClusterMode'

mutate KL-M16 "an empty declared token source is treated as no credential" \
  internal/cli/kubernetes.go \
  's = s.replace("	if sources.declared() && secret.IsEmpty() {",
                 "	if false && sources.declared() && secret.IsEmpty() {", 1)
assert "if false && sources.declared()" in s' \
  ./internal/cli 'TestAnEmptyDeclaredTokenSourceIsAUsageError'

mutate KL-M17 "an empty declared token source falls back to the kubeconfig identity" \
  internal/cli/kubernetes.go \
  's = s.replace("	if sources.declared() && secret.IsEmpty() {",
                 "	if sources.declared() && secret.IsEmpty() && false {", 1)
assert "secret.IsEmpty() && false" in s' \
  ./internal/cli 'TestAnEmptyDeclaredTokenSourceIsAUsageError'

mutate KL-M18 "the credential is bound to something other than the derived API server" \
  internal/cli/kubernetes.go \
  's = s.replace("credentialFor(host, port, \"\", secret)",
                 "credentialFor(\"localhost\", port, \"\", secret)", 1)
assert "credentialFor(\"localhost\"" in s' \
  ./internal/cli 'TestADeclaredTokenBindsToTheDerivedAPIServer'

mutate KL-M19 "the credential is given an identity" \
  internal/cli/kubernetes.go \
  's = s.replace("credentialFor(host, port, \"\", secret)",
                 "credentialFor(host, port, target.Namespace, secret)", 1)
assert "target.Namespace, secret" in s' \
  ./internal/cli 'TestADeclaredTokenBindsToTheDerivedAPIServer'

echo
echo "--- validation ownership (PHASE121C1 section 6) ---"

mutate KL-M20 "the target's shape is not validated at all" \
  internal/cli/kubernetes.go \
  's = s.replace("""	host, port, err := app.InspectKubernetesTarget(target, sources.declared())
	if err != nil {
		return kubernetesCommand{}, usagef("%v", err)
	}""",
"""	host, port, _ := app.InspectKubernetesTarget(target, sources.declared())""", 1)
assert "host, port, _ :=" in s' \
  ./internal/cli 'TestTheKubernetesTargetRulesAreTheAdapters'

mutate KL-M21 "a target refusal is reported as an internal failure" \
  internal/cli/kubernetes.go \
  's = s.replace("""		return kubernetesCommand{}, usagef("%v", err)
	}

	secret, err := a.readSecret(sources)""",
"""		return kubernetesCommand{}, err
	}

	secret, err := a.readSecret(sources)""", 1)
assert "return kubernetesCommand{}, err\n	}\n\n	secret, err := a.readSecret(sources)" in s' \
  ./internal/cli 'TestTheKubernetesTargetRulesAreTheAdapters'

mutate KL-M22 "the CLI restates a target rule instead of asking the adapter" \
  internal/cli/kubernetes.go \
  's = s.replace("""	target := app.KubernetesTarget{""",
"""	if *namespace == "" {
		return kubernetesCommand{}, usagef("--namespace is required")
	}

	target := app.KubernetesTarget{""", 1)
assert "--namespace is required" in s' \
  ./internal/cli 'TestTheKubernetesTargetRulesAreTheAdapters'

echo
echo "--- the generic secret helper stayed generic (PHASE121C1 section 7.1) ---"

mutate KL-M23 "the generic secret helper hard-codes one command's flag names" \
  internal/cli/secret.go \
  's = s.replace("""		return usagef("--%s and --%s are mutually exclusive", c.fileFlag, c.stdinFlag)""",
"""		return usagef("--password-file and --password-stdin are mutually exclusive")""", 1)
assert "c.fileFlag" not in s.split("func (c credentialSources) validate")[1].split("}")[0]' \
  ./internal/cli 'TestTheKubernetesTokenSourcesAreExclusiveAndNamed|TestTheCredentialSourceHelperNamesTheCallersFlags'

mutate KL-M24 "the generic secret helper's file message loses the caller's flag" \
  internal/cli/secret.go \
  's = s.replace("""		return security.Secret{}, usagef("--%s %s is a directory", flagName, path)""",
"""		return security.Secret{}, usagef("--password-file %s is a directory", path)""", 1)
assert "--password-file %s is a directory" in s' \
  ./internal/cli 'TestTheKubernetesTokenFileMessagesNameTheKubernetesFlag'

echo
echo "--- the command composes and does not conclude (PHASE121C1 section 14) ---"

mutate KL-M25 "a positional argument is accepted" \
  internal/cli/kubernetes.go \
  's = s.replace("""	if fs.NArg() > 0 {
		return kubernetesCommand{}, usagef("unexpected argument %q", fs.Arg(0))
	}""", "", 1)
assert "unexpected argument" not in s' \
  ./internal/cli 'TestKP03AnInvalidInvocationNeverStartsARun'

mutate KL-M26 "the command bypasses the generic exit mapping" \
  internal/cli/kubernetes.go \
  's = s.replace("""	result, runErr := a.diagnoseKubernetes(runCtx, command.params)
	code := ExitCode(result, runErr)""",
"""	result, runErr := a.diagnoseKubernetes(runCtx, command.params)
	code := ExitOK""", 1)
assert "code := ExitOK" in s' \
  ./test/fleet 'TestTheLeafCommandReachesEveryKubernetesFinding'

mutate KL-M27 "the command bypasses the shareable projection" \
  internal/cli/kubernetes.go \
  's = s.replace("	report, err := project(result.Report(), command.shareable)",
                 "	report, err := project(result.Report(), false)", 1)
assert "project(result.Report(), false)" in s' \
  ./test/fleet 'TestTheLeafOutputFlagsActuallyReachTheRenderer'

mutate KL-M28 "the command renders in a format it did not validate" \
  internal/cli/kubernetes.go \
  's = s.replace("""	if err := a.render(command.output,""",
"""	if err := a.render("json",""", 1)
assert "a.render(" + chr(34) + "json" + chr(34) in s' \
  ./test/fleet 'TestTheLeafOutputFlagsActuallyReachTheRenderer'

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
  echo "PHASE 12.1C.2 MUTATION CLOSURE: FAILED"
  exit 1
fi

echo
echo "PHASE 12.1C.2 MUTATION CLOSURE: 0 survivors"
