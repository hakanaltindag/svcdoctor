#!/usr/bin/env bash
# Phase 9.1B mutation closure.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is restored and verified byte-for-byte against sha256 checksums
# taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/domain/runreport.go
  internal/domain/executionstate.go
  internal/fleet/run/run.go
  internal/fleet/run/execute.go
  internal/fleet/secret/secret.go
  internal/render/terminal/run.go
  internal/render/json/run.go
  internal/cli/run.go
  internal/cli/exit.go
  internal/security/redaction/run.go
)

for f in "${FILES[@]}"; do
  mkdir -p "$BACKUP/$(dirname "$f")"
  cp "$f" "$BACKUP/$f"
done

BEFORE="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
restore() { for f in "${FILES[@]}"; do cp "$BACKUP/$f" "$f"; done; }

# An interrupted harness must not leave a mutation planted.
#
# Phase 9.3A measured why this is not hypothetical. A run of this suite was
# killed by a ten-minute command timeout part-way through, leaving one planted
# mutation in the working tree. The next run took *that* tree as its pristine
# baseline, restored to it byte-for-byte at the end, truthfully reported "tree
# restored" — and reported a survivor that was an artefact of the leftover
# rather than a gap in any guard.
#
# The BEFORE/AFTER checksums cannot catch this: they prove the run put back what
# it found, not that what it found was the committed tree. A trap can, because
# the failure is a script that stops between planting and restoring.
#
# Guarded on the backup still existing, so the ordinary exit path — which
# restores and removes the backup itself — is not a double restore from a
# directory that is gone.
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

  # -timeout is short on purpose: several mutations make a target hang, and
  # without a bound the default 10 minutes is spent waiting to learn what a
  # few seconds already prove.
  if go test "$pkg" -run "$regex" -count=1 -timeout 90s >/dev/null 2>&1; then
    echo "  $id  SURVIVOR — $desc"
    SURVIVORS+=("$id $desc"); FAIL=$((FAIL + 1))
  else
    echo "  $id  caught    — $desc"
    PASS=$((PASS + 1))
  fi
  restore
}

echo "Phase 9.1B mutation closure"
echo

# --- boundary -------------------------------------------------------------

mutate B01 "scheduler imports a protocol wire package" internal/fleet/run/execute.go \
  's = s.replace("import (\n\t\"context\"", "import (\n\t_ \"github.com/hakanaltindag/svcdoctor/internal/adapter/rabbitmq/wire\"\n\n\t\"context\"", 1)
assert "adapter/rabbitmq/wire" in s' \
  ./test/security 'TestTheFleetCoreReachesNoProtocol'

mutate B02 "scheduler imports a diagnosis package" internal/fleet/run/execute.go \
  's = s.replace("import (\n\t\"context\"", "import (\n\t_ \"github.com/hakanaltindag/svcdoctor/internal/diagnosis/redis\"\n\n\t\"context\"", 1)
assert "diagnosis/redis" in s' \
  ./test/security 'TestNoRunSurfaceComparesTwoTargetReports'

mutate B03 "scheduler calls security.Reveal" internal/fleet/run/execute.go \
  's = s.replace("	targetCtx, cancel := context.WithTimeout", "	_ = security.Reveal(security.Secret{})\n	targetCtx, cancel := context.WithTimeout", 1)
assert "security.Reveal(" in s' \
  ./test/security 'TestTheSchedulerPerformsNoCredentialOperation'

mutate B04 "scheduler calls Credential.SecretFor" internal/fleet/run/execute.go \
  's = s.replace("	targetCtx, cancel := context.WithTimeout", "	_, _ = credential.SecretFor(security.Endpoint{})\n	targetCtx, cancel := context.WithTimeout", 1)
assert ".SecretFor(" in s' \
  ./test/security 'TestTheSchedulerPerformsNoCredentialOperation'

mutate B19 "renderer computes the exit code" internal/render/terminal/run.go \
  's = s.replace("func WriteRun(w io.Writer, report domain.RunReport) error {", "func ExitCode(report domain.RunReport) int { return 0 }\n\nfunc WriteRun(w io.Writer, report domain.RunReport) error {", 1)
assert "func ExitCode(" in s' \
  ./test/security 'TestTheRendererDoesNotDecideTheExitCode'

mutate B20 "renderer reaches a diagnosis package" internal/render/terminal/run.go \
  's = s.replace("import (\n\t\"fmt\"", "import (\n\t_ \"github.com/hakanaltindag/svcdoctor/internal/diagnosis/redis\"\n\n\t\"fmt\"", 1)
assert "diagnosis/redis" in s' \
  ./test/security 'TestNoRunSurfaceComparesTwoTargetReports'

mutate B24 "the scheduler retains the raw configuration" internal/fleet/run/run.go \
  's = s.replace("type Params struct {", "type Params struct {\n\tRaw []byte\n", 1)
s = s.replace("import (\n\t\"context\"", "import (\n\t_ \"go.yaml.in/yaml/v3\"\n\n\t\"context\"", 1)
assert "yaml/v3" in s' \
  ./test/security 'TestTheSchedulerParsesNoConfiguration'

mutate B_SVC "a service name appears in the scheduler" internal/fleet/run/execute.go \
  's = s.replace("	runner, _ := e.params.Registry.lookup(target.Service)", "	if target.Service == \"postgres\" {\n		_ = target\n	}\n	runner, _ := e.params.Registry.lookup(target.Service)", 1)
assert "postgres" in s' \
  ./test/security 'TestTheSchedulerNamesNoService'

# --- credentials ----------------------------------------------------------

mutate B05 "one resolved credential is shared by every target" internal/fleet/run/execute.go \
  's = s.replace("""	credential, err := e.params.Resolver.CredentialFor(e.runCtx, target)""", """	credential, err := e.params.Resolver.CredentialFor(e.runCtx, e.params.Config.Targets[0])""", 1)
assert "Config.Targets[0])" in s' \
  ./internal/fleet/run 'TestMTE10SameReferenceResolvesIndependently'

mutate B06 "resolved credentials are cached by reference" internal/fleet/run/run.go \
  's = s.replace("type Params struct {", "var credentialCache sync.Map\n\ntype Params struct {", 1)
s = s.replace("import (\n\t\"context\"", "import (\n\t\"context\"\n\t\"sync\"", 1)
assert "sync.Map" in s' \
  ./test/security 'TestTheFleetLayerHasNoSecretCache'

mutate B28 "the same reference reuses one credential object" internal/fleet/run/execute.go \
  's = s.replace("""type executor struct {
	params  Params
	runCtx  context.Context
	results []domain.TargetResult
}""", """type executor struct {
	params  Params
	runCtx  context.Context
	results []domain.TargetResult
	shared  map[string]security.Credential
	mu      sync.Mutex
}""", 1)
s = s.replace("""	credential, err := e.params.Resolver.CredentialFor(e.runCtx, target)
	if err != nil {""", """	e.mu.Lock()
	if e.shared == nil {
		e.shared = map[string]security.Credential{}
	}
	key := target.Credentials.Password.Name()
	hit, cached := e.shared[key]
	e.mu.Unlock()
	credential, err := hit, error(nil)
	if !cached {
		credential, err = e.params.Resolver.CredentialFor(e.runCtx, target)
		if err == nil {
			e.mu.Lock()
			e.shared[key] = credential
			e.mu.Unlock()
		}
	}
	if err != nil {""", 1)
assert "e.shared" in s' \
  ./internal/fleet/run 'TestMTE10SameReferenceResolvesIndependently'

mutate B13 "a credential resolution failure becomes an authentication failure" internal/fleet/run/execute.go \
  's = s.replace("""		e.results[index] = mustFailed(id, service,
			domain.ExecutionErrorCredentialResolution, safeMessage(err))
		return""", """		outcome := Outcome{Report: domain.Report{}, Incomplete: false}
		_ = outcome
		e.results[index] = mustFailed(id, service,
			domain.ExecutionErrorInternal, safeMessage(err))
		return""", 1)
assert "ExecutionErrorInternal, safeMessage" in s' \
  ./internal/fleet/run 'TestMTE04CredentialResolutionFailure'

mutate B22 "an execution error echoes the credential reference" internal/fleet/run/execute.go \
  's = s.replace("""	var messenger safeMessenger
	if errors.As(err, &messenger) {
		return messenger.SafeMessage()
	}
	return "the credential could not be resolved\"""", """	return err.Error()""", 1)
assert "return err.Error()" in s' \
  ./internal/fleet/run 'TestAnExecutionErrorMessageNamesNoCredentialReference|TestAnErrorWithNoSafeForm'

mutate B21 "the resolver error carries the reference into its safe form" internal/fleet/secret/secret.go \
  's = s.replace("""func (e *ResolutionError) SafeMessage() string {
	return fmt.Sprintf("the credential named by a %s reference could not be resolved: %s",
		e.kind, e.reason)
}""", """func (e *ResolutionError) SafeMessage() string {
	return e.Error()
}""", 1)
assert "return e.Error()" in s' \
  ./internal/fleet/secret 'TestTheSafeMessageNamesNoReference'

mutate B23 "a credential file path reaches the aggregate" internal/fleet/secret/secret.go \
  's = s.replace("""func (e *ResolutionError) SafeMessage() string {""", """func (e *ResolutionError) SafeMessage() string {
	if e.kind == config.SourceFile {
		return "could not read " + e.name
	}""", 1)
assert "could not read" in s' \
  ./internal/fleet/secret 'TestTheSafeMessageNamesNoReference'

# --- ordering and determinism --------------------------------------------

mutate B07 "completion order becomes report order" internal/fleet/run/execute.go \
  's = s.replace("""	results := make([]domain.TargetResult, len(targets))""", """	results := make([]domain.TargetResult, len(targets))
	_ = results""", 1)
s = s.replace("""	e.results[index] = e.classify(id, service, outcome)""", """	e.appendCompletion(e.classify(id, service, outcome))""", 1)
s = s.replace("""type executor struct {
	params  Params
	runCtx  context.Context
	results []domain.TargetResult
}""", """type executor struct {
	params   Params
	runCtx   context.Context
	results  []domain.TargetResult
	ordered  []domain.TargetResult
	mu       sync.Mutex
	nextFree int
}

func (e *executor) appendCompletion(r domain.TargetResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.results[e.nextFree] = r
	e.nextFree++
}""", 1)
assert "appendCompletion" in s' \
  ./internal/fleet/run 'TestMTE08AndD02CompletionOrderNeverReachesTheReport'

mutate B08 "target results are sorted by status" internal/fleet/run/execute.go \
  's = s.replace("""	report, err := domain.NewRunReport(domain.RunReportInput{""", """	sort.SliceStable(results, func(i, j int) bool {
		return results[i].ExecutionState() < results[j].ExecutionState()
	})
	report, err := domain.NewRunReport(domain.RunReportInput{""", 1)
s = s.replace("import (\n\t\"context\"", "import (\n\t\"context\"\n\t\"sort\"", 1)
assert "sort.SliceStable" in s' \
  ./internal/fleet/run 'TestDeclaredOrderSurvivesMixedExecutionStates|TestMTD01'

# --- fail-fast ------------------------------------------------------------

mutate B09 "a diagnostic failure stops the run" internal/fleet/run/execute.go \
  's = s.replace("""			for index := range next {
				e.runOne(index)
			}""", """			for index := range next {
				e.runOne(index)
				if e.results[index].HasProblems() {
					return
				}
			}""", 1)
assert "HasProblems() {" in s' \
  ./internal/fleet/run 'TestMTE02NoFailFastOnDiagnosticOrExecutionFailure'

mutate B10 "an execution failure stops the run" internal/fleet/run/execute.go \
  's = s.replace("""			for index := range next {
				e.runOne(index)
			}""", """			for index := range next {
				e.runOne(index)
				if e.results[index].ExecutionState() == domain.ExecutionStateExecutionFailed {
					return
				}
			}""", 1)
assert "ExecutionStateExecutionFailed {" in s' \
  ./internal/fleet/run 'TestMTE02NoFailFastOnDiagnosticOrExecutionFailure'

mutate B26 "a resolution failure stops unrelated targets" internal/fleet/run/execute.go \
  's = s.replace("""		e.results[index] = mustFailed(id, service,
			domain.ExecutionErrorCredentialResolution, safeMessage(err))
		return""", """		e.results[index] = mustFailed(id, service,
			domain.ExecutionErrorCredentialResolution, safeMessage(err))
		panic("stop the run")""", 1)
assert "panic(\"stop the run\")" in s' \
  ./internal/fleet/run 'TestMTE02NoFailFastOnDiagnosticOrExecutionFailure'

# --- truthfulness ---------------------------------------------------------

mutate B11 "cancellation produces a target-side problem" internal/domain/runreport.go \
  's = s.replace("""		if result.HasProblems() {
			s.withProblems++
			s.status = SummaryStatusProblemsFound
		}""", """		if result.HasProblems() || result.ExecutionState() == ExecutionStateCancelled {
			s.withProblems++
			s.status = SummaryStatusProblemsFound
		}""", 1)
assert "ExecutionStateCancelled {" in s' \
  ./internal/fleet/run 'TestMTE06CancellationWithCompletedActiveAndQueued'

mutate B12 "a never-started target is given another target's report" internal/fleet/run/execute.go \
  's = s.replace("""		result, err := domain.NotStartedTarget(target.ID.String(), serviceID(target))
		if err != nil {
			return domain.RunReport{}, err
		}
		results[i] = result""", """		var borrowed domain.Report
		var borrowedIncomplete bool
		for _, other := range results {
			if other.HasReport() {
				borrowed, borrowedIncomplete = other.Report(), other.Incomplete()
				break
			}
		}
		if !borrowed.IsZero() {
			fabricated, ferr := domain.CompletedTarget(
				target.ID.String(), serviceID(target), borrowed, borrowedIncomplete)
			if ferr == nil {
				results[i] = fabricated
				continue
			}
		}
		result, err := domain.NotStartedTarget(target.ID.String(), serviceID(target))
		if err != nil {
			return domain.RunReport{}, err
		}
		results[i] = result""", 1)
assert "borrowed" in s' \
  ./internal/fleet/run 'TestMTE05RunBudgetExhaustedBeforeAllTargetsStart|TestMTE17'

mutate B30 "an execution failure counts as a diagnostic problem" internal/domain/runreport.go \
  's = s.replace("""func (r TargetResult) HasProblems() bool {
	return r.HasReport() && r.report.Summary().Status() == SummaryStatusProblemsFound
}""", """func (r TargetResult) HasProblems() bool {
	if r.state == ExecutionStateExecutionFailed {
		return true
	}
	return r.HasReport() && r.report.Summary().Status() == SummaryStatusProblemsFound
}""", 1)
assert "ExecutionStateExecutionFailed {" in s' \
  ./internal/fleet/run 'TestMTE04CredentialResolutionFailure'

mutate B29 "the run summary describes targets as healthy" internal/render/terminal/run.go \
  's = s.replace("""	return "OK  no target-side error was proven\"""", """	return fmt.Sprintf("OK  %d targets healthy", s.Targets())""", 1)
assert "targets healthy" in s' \
  ./internal/cli 'TestNeitherRunSummaryBranchDescribesTargetsAsHealthy'

# --- budgets --------------------------------------------------------------

mutate B14 "a target deadline extends the global deadline" internal/fleet/run/execute.go \
  's = s.replace("""	targetCtx, cancel := context.WithTimeout(e.runCtx, target.Timeout)""", """	targetCtx, cancel := context.WithTimeout(context.Background(), target.Timeout)""", 1)
assert "context.Background(), target.Timeout" in s' \
  ./internal/fleet/run 'TestMTE17RunDeadlineDominatesTargetDeadline'

mutate B15 "a target timeout cancels its siblings" internal/fleet/run/execute.go \
  's = s.replace("""	targetCtx, cancel := context.WithTimeout(e.runCtx, target.Timeout)
	defer cancel()""", """	runCtx, runCancel := context.WithTimeout(e.runCtx, target.Timeout)
	e.runCtx = runCtx
	targetCtx, cancel := runCtx, runCancel
	defer cancel()""", 1)
assert "e.runCtx = runCtx" in s' \
  ./internal/fleet/run 'TestMTE16ATargetTimeoutDoesNotCancelASibling'

# --- concurrency ----------------------------------------------------------

mutate B16 "the concurrency ceiling is removed" internal/fleet/run/run.go \
  's = s.replace("""	case p.Config.Run.Concurrency > config.MaxConcurrency:
		return fmt.Errorf("%w: concurrency %d is above the maximum of %d",
			ErrRun, p.Config.Run.Concurrency, config.MaxConcurrency)""", """	case false:
		return nil""", 1)
assert "	case false:" in s' \
  ./internal/fleet/run 'TestMTE11AndE13AndE14Concurrency'

mutate B17 "concurrency zero is accepted" internal/fleet/run/run.go \
  's = s.replace("""	case p.Config.Run.Concurrency < 1:
		return fmt.Errorf("%w: concurrency %d must be at least 1",
			ErrRun, p.Config.Run.Concurrency)""", """	case false:
		return nil""", 1)
assert "	case false:" in s' \
  ./internal/fleet/run 'TestMTE11AndE13AndE14Concurrency'

mutate B18 "the worker count exceeds the configured concurrency" internal/fleet/run/execute.go \
  's = s.replace("	for range workers {", "	for range workers * 4 {", 1)
assert "workers * 4" in s' \
  ./internal/fleet/run 'TestMTE12MaxConcurrencyIsObserved'

# --- configuration --------------------------------------------------------

mutate B25 "a configuration error still executes earlier targets" internal/cli/run.go \
  's = s.replace("""	cfg, err := config.LoadFile(*path, fleetConfigRegistry())
	if err != nil {
		return runCommand{}, err
	}""", """	cfg, _ := config.LoadFile(*path, fleetConfigRegistry())""", 1)
assert "cfg, _ := config.LoadFile" in s' \
  ./internal/cli 'TestAConfigurationErrorDialsNothing'

mutate B27 "duplicate endpoints are deduplicated" internal/fleet/run/execute.go \
  's = s.replace("""	targets := params.Config.Targets""", """	targets := params.Config.Targets
	{
		seen := map[string]bool{}
		var unique []config.Target
		for _, t := range targets {
			key := t.Host
			if seen[key] {
				continue
			}
			seen[key] = true
			unique = append(unique, t)
		}
		targets = unique
	}""", 1)
assert "unique = append" in s' \
  ./internal/fleet/run 'TestMTE09DuplicateEndpointsAreDistinctExecutions'

echo
AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "RESTORE FAILED — the tree does not match its pre-mutation checksums"
  diff <(echo "$BEFORE") <(echo "$AFTER")
  rm -rf "$BACKUP"; exit 1
fi
echo "tree restored byte-for-byte (${#FILES[@]} files verified by sha256)"
rm -rf "$BACKUP"

echo
echo "caught: $PASS   survivors: $FAIL"
if [ "$FAIL" -ne 0 ]; then
  printf 'SURVIVOR: %s\n' "${SURVIVORS[@]}"
  exit 1
fi
echo "no survivors"
