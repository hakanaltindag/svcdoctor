#!/usr/bin/env bash
# Phase 9.2B mutation closure — the release-blocker fixes and the doc guards.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is restored and verified byte-for-byte against sha256 checksums
# taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it.
#
# # What this covers that earlier scripts do not
#
# 9.1C mutated the multi-target chain from a YAML byte to an exit code. This
# mutates the four things Phase 9.2A found broken and the guards written to keep
# them fixed:
#
#   U01-U06  UX-B01, the aggregate shareable leak
#   U07-U10  UX-B03, a configuration error reaching execution
#   U11-U13  UX-B02, the README's stale and contradictory claims
#   U14-U16  the shareable wording, and the example guards
#   U17-U18  the help surfaces and the exit-code documentation
#   U19-U20  the CI examples and the security policy
#
# Documentation mutations are as real as code ones here: Phase 9.2A's finding was
# that a false sentence in a README survived a full `make check`, which is a
# defect in the *guards*, and the only way to know a guard works is to break what
# it guards.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/security/redaction/run.go
  internal/render/json/run.go
  internal/render/terminal/run.go
  internal/fleet/services/preflight.go
  internal/cli/run.go
  internal/cli/exit.go
  internal/cli/usage.go
  README.md
  SECURITY.md
  docs/OUTPUT.md
  docs/CI.md
  docs/CONFIGURATION.md
  examples/services.yaml
)

for f in "${FILES[@]}"; do
  mkdir -p "$BACKUP/$(dirname "$f")"
  cp "$f" "$BACKUP/$f"
done

BEFORE="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
restore() { for f in "${FILES[@]}"; do cp "$BACKUP/$f" "$f"; done; }

PASS=0
FAIL=0
SURVIVORS=()

# mutate <id> <description> <file> <python-replacement> <test-package> <test-regex>
mutate() {
  local id="$1" desc="$2" file="$3" script="$4" pkg="$5" regex="$6"

  # A -run regex that selects **no test** makes `go test` exit 0, which this
  # harness would read as a survivor. That is exactly how twenty mutations across
  # phase91a and phase91b sat "surviving" from Phase 9.1C — which renamed 28 test
  # functions — until the v0.4.0 release gate measured them: every one was caught
  # by its package's full suite, and only the narrow regex had gone stale.
  #
  # An empty selection is a harness failure rather than a finding about the
  # product; the two need opposite fixes and look identical without this.
  #
  # Checked on the **pristine** tree, before planting. After planting, a mutation
  # that deliberately breaks the build produces no `=== RUN` either, and a check
  # placed later cannot tell "the regex matches nothing" from "the mutation did
  # its job" — which is the same conflation this guard exists to remove.
  # The output is captured before being searched, deliberately. Piping into
  # `grep -q` makes grep exit at the first match, `go test` take SIGPIPE, and the
  # pipeline report failure under `set -o pipefail` — so every regex, including
  # the ones that match nine tests, looked like it matched none.
  local selected
  selected="$(go test "$pkg" -run "$regex" -count=1 -timeout 120s -v 2>/dev/null || true)"
  if ! printf '%s' "$selected" | grep -q '^=== RUN'; then
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

  if go test "$pkg" -run "$regex" -count=1 -timeout 180s >/dev/null 2>&1; then
    echo "  $id  SURVIVOR — $desc"
    SURVIVORS+=("$id $desc"); FAIL=$((FAIL + 1))
  else
    echo "  $id  caught    — $desc"
    PASS=$((PASS + 1))
  fi
  restore
}

echo "Phase 9.2B mutation closure — release blockers and documentation guards"
echo
echo "--- UX-B01: the aggregate shareable leak ---"

mutate U01 "the aggregate collector skips execution-only targets" \
  internal/security/redaction/run.go \
  's = s.replace("""	for _, result := range results {
		out.targetIDs = append(out.targetIDs, result.TargetID())

		if !result.HasReport() {
			continue
		}""", """	for _, result := range results {
		if !result.HasReport() {
			continue
		}
		out.targetIDs = append(out.targetIDs, result.TargetID())""", 1)
assert "out.targetIDs = append(out.targetIDs, result.TargetID())\n\t\tif" not in s' \
  ./test/security 'TestUX12'

mutate U02 "aggregate residual verification is removed" \
  internal/security/redaction/run.go \
  's = s.replace("""	if err := verifyNoRunResidual(values, aliases, out); err != nil {
		return domain.RunReport{}, err
	}""", """	_ = values""", 1)
assert "verifyNoRunResidual(values" not in s' \
  ./test/security 'TestUX12RedactRunActuallyCallsTheResidualCheck'

mutate U03 "a filesystem path is left in the shareable execution message" \
  internal/security/redaction/run.go \
  's = s.replace("redactedExecutionMessage(result.ExecutionErrorClass())", "result.ExecutionErrorMessage()", 1)
assert "redactedExecutionMessage(result" not in s' \
  ./test/security 'TestUX12'

mutate U04 "a zoned IPv6 address is left in the shareable execution message" \
  internal/security/redaction/run.go \
  's = s.replace("redactedExecutionMessage(result.ExecutionErrorClass())", "t.text(result.ExecutionErrorMessage())", 1)
assert "t.text(result.ExecutionErrorMessage())" in s' \
  ./test/security 'TestUX12'

mutate U05 "the command skips redaction when --shareable is given" \
  internal/cli/run.go \
  's = s.replace("""	if !shareable {
		return report, nil
	}""", """	if true {
		return report, nil
	}""", 1)
assert "if true {" in s' \
  ./internal/cli 'TestMTS15ShareableNeverExposesWhatLocalAlreadyHid|TestUX20'

mutate U06b "the shareable execution message loses its explanation" \
  internal/security/redaction/run.go \
  's = s.replace("""		return "the reason is local detail and is withheld from a shareable report\"""",
"""		return "withheld\"""", 1)
assert "return \"withheld\"" in s' \
  ./test/security 'TestUX12TheAggregateGuardsCanFail'

mutate U06 "the shareable terminal renderer is handed the local report" \
  internal/cli/run.go \
  's = s.replace("""	if err := a.renderRun(command.output, projected); err != nil {""",
"""	_ = projected
	if err := a.renderRun(command.output, report); err != nil {""", 1)
assert "a.renderRun(command.output, report)" in s' \
  ./internal/cli 'TestMTS15ShareableNeverExposesWhatLocalAlreadyHid'

echo
echo "--- UX-B03: a configuration error reaching execution ---"

mutate U07 "a preflight config error becomes an EXECUTION_FAILED result" \
  internal/cli/run.go \
  's = s.replace("""	if err := services.PreflightAll(cfg); err != nil {
		return domain.RunReport{}, err
	}""", """	_ = services.PreflightAll""", 1)
assert "services.PreflightAll(cfg)" not in s' \
  ./internal/cli 'TestUX08APreflightDefectExitsTwoAndDialsNothing'

mutate U08 "a preflight config error exits 4 instead of 2" \
  internal/cli/exit.go \
  's = s.replace("		errors.Is(err, services.ErrPreflight):", "		false:", 1)
assert "\t\terrors.Is(err, services.ErrPreflight):" not in s' \
  ./internal/cli 'TestUX08APreflightDefectExitsTwoAndDialsNothing'

mutate U09 "a preflight config error still invokes the runner" \
  internal/fleet/services/preflight.go \
  's = s.replace("""		if err := PreflightTarget(target); err != nil {
			return err
		}""", """		_ = target""", 1)
assert "PreflightTarget(target)" not in s' \
  ./internal/cli 'TestUX08APreflightDefectExitsTwoAndDialsNothing'

mutate U10 "preflight stops validating the trust source, duplicating the leaf rule" \
  internal/fleet/services/preflight.go \
  's = s.replace("	if _, err := trustsource.Load(target.TLS.CAFile); err != nil {", "	if false {\n\t\terr := error(nil)\n\t\t_ = err", 1)
s = s.replace("""			cause:    errors.New(trustsource.Reason(err)),""", """			cause:    errors.New("unreachable"),""", 1)
assert "if false {" in s' \
  ./internal/cli 'TestUX08APreflightDefectExitsTwoAndDialsNothing|TestUX08PreflightAndTheLeafCommandsAgree'

echo
echo "--- UX-B02: the README's stale and contradictory claims ---"

mutate U11 "the README says only two services are supported" README.md \
  's = s.replace("**Four services are supported: PostgreSQL, Apache Kafka, Redis/Valkey and RabbitMQ/LavinMQ.**",
"**PostgreSQL BASIC and Kafka BASIC are supported today.**", 1)
assert "PostgreSQL BASIC and Kafka BASIC are supported today" in s' \
  ./internal/cli 'TestUX15TheREADMECountsServicesCorrectly|TestUX15TheDocumentedServicesAreTheRegisteredServices'

mutate U12 "the README says production never reads an environment variable" README.md \
  's = s.replace("**The four `diagnose` commands read no environment variable at all.**",
"**There is no environment-variable secret source** — svcdoctor\x27s production code reads no environment variable at all.", 1)
assert "production code reads no environment variable at all" in s' \
  ./internal/cli 'TestUX15TheCredentialDocumentationCoversEverySource'

mutate U13 "the README says no image is published" README.md \
  's = s.replace("Published images are on GHCR", "**No image is published.** Nothing has been pushed to GHCR", 1)
s = s.replace("docker run --rm ghcr.io/hakanaltindag/svcdoctor:v0.3.3", "docker run --rm svcdoctor:local", 1)
s = s.replace("  ghcr.io/hakanaltindag/svcdoctor:v0.3.3", "  svcdoctor:local", 1)
assert "Nothing has been pushed to GHCR" in s' \
  ./internal/cli 'TestTheDocsTellTheReaderHowToRunThePublishedImage'

echo
echo "--- documentation and example guards ---"

mutate U14 "the shareable documentation claims anonymity" docs/OUTPUT.md \
  's = s.replace("It is **pseudonymization**, not anonymization.", "A shareable report is fully anonymized.", 1)
assert "fully anonymized" in s' \
  ./internal/cli 'TestUX20TheShareableWordingStaysHonest'

mutate U15 "a plaintext password is added to the canonical example" examples/services.yaml \
  's = s.replace("""      password:
        env: ORDERS_DB_PASSWORD""", """      password: hunter2""", 1)
assert "password: hunter2" in s' \
  ./internal/cli 'TestUX0405EveryDocumentedConfigurationParses'

mutate U16 "an invalid field is accepted by the example guard" examples/services.yaml \
  's = s.replace("    host: orders-db.internal.example.com", "    hostname: orders-db.internal.example.com", 1)
assert "hostname:" in s' \
  ./internal/cli 'TestUX0405EveryDocumentedConfigurationParses'

mutate U17 "the help surface loses run" internal/cli/usage.go \
  's = s.replace("""  run         measure every target in a configuration file\n""", "", 1)
assert "run         measure every target" not in s' \
  ./internal/cli 'TestUX0102030TheHelpSurfacesMatchTheirGoldens|TestUX01TheHelpGoldensCoverEveryCommand'

mutate U18 "the exit-code documentation swaps 1 and 4" docs/CI.md \
  's = s.replace("Precedence, when more than one applies: **`3` > `2` > `4` > `1` > `0`**.",
"Precedence, when more than one applies: **`3` > `2` > `1` > `4` > `0`**.", 1)
s = s.replace("**Exit 4 outranks exit 1.**", "**Exit 1 outranks exit 4.**", 1)
assert "`1` > `4`" in s' \
  ./internal/cli 'TestUX13TheDocumentedExitCodesMatchTheImplementation'

mutate U19 "a CI example discards the exit code with || true" docs/CI.md \
  's = s.replace("""```sh
set +e
svcdoctor run --config services.yaml --output json > report.json
rc=$?
set -e

# upload report.json here, before deciding anything

exit "$rc"
```""", """```sh
svcdoctor run --config services.yaml --output json > report.json || true
```""", 1)
assert "> report.json || true" in s' \
  ./internal/cli 'TestUX14NoDocumentedShellExampleDiscardsTheExitCode'

mutate U20 "the private security reporting channel is removed" SECURITY.md \
  's = s.replace("https://github.com/hakanaltindag/svcdoctor/security/advisories/new", "the issue tracker", 1)
s = s.replace("[github.com/hakanaltindag/svcdoctor/security/advisories/new](the issue tracker)", "the issue tracker", 1)
assert "security/advisories/new" not in s' \
  ./internal/cli 'TestUX2123TheRepositoryHygieneFilesExist'

echo
echo "--- restoration ---"

AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "  TREE NOT RESTORED — checksums differ:"
  diff <(echo "$BEFORE") <(echo "$AFTER")
  FAIL=$((FAIL + 1))
else
  echo "  tree restored byte-for-byte (sha256)"
fi

rm -rf "$BACKUP"

echo
echo "caught: $PASS   survivors: ${#SURVIVORS[@]}"
if [ ${#SURVIVORS[@]} -gt 0 ]; then
  printf '  %s\n' "${SURVIVORS[@]}"
  exit 1
fi
[ "$FAIL" -eq 0 ] || exit 1
echo "0 survivors"
