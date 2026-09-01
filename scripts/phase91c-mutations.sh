#!/usr/bin/env bash
# Phase 9.1C mutation closure — the whole multi-target chain.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is restored and verified byte-for-byte against sha256 checksums
# taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it.
#
# # What this adds over phase91b-mutations.sh
#
# 9.1B mutated the scheduler and the aggregate — the code it had just written.
# This mutates the *chain*: the parser, the credential resolver, the scheduler,
# the domain, redaction, both renderers and the command, so that a defect
# introduced anywhere between a YAML byte and an exit code has to be caught by
# something.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  internal/domain/runreport.go
  internal/fleet/config/document.go
  internal/fleet/config/credential.go
  internal/fleet/config/load.go
  internal/fleet/config/schema.go
  internal/fleet/run/run.go
  internal/fleet/run/execute.go
  internal/fleet/secret/secret.go
  internal/render/terminal/run.go
  internal/render/json/run.go
  internal/cli/run.go
  internal/cli/exit.go
  internal/cli/interrupt.go
  internal/security/redaction/run.go
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

  # -timeout is short on purpose: several mutations make a target hang, and
  # without a bound the default ten minutes is spent waiting to learn what a few
  # seconds already prove.
  if go test "$pkg" -run "$regex" -count=1 -timeout 120s >/dev/null 2>&1; then
    echo "  $id  SURVIVOR — $desc"
    SURVIVORS+=("$id $desc"); FAIL=$((FAIL + 1))
  else
    echo "  $id  caught    — $desc"
    PASS=$((PASS + 1))
  fi
  restore
}

echo "Phase 9.1C mutation closure — the full multi-target chain"
echo
echo "--- configuration boundary ---"

mutate C01 "a plaintext credential is admitted" internal/fleet/config/credential.go \
  's = s.replace("""	if value.Kind != yaml.MappingNode {""", """	if value.Kind == yaml.ScalarNode {
		r.kind, r.name = SourceEnv, value.Value
		return nil
	}
	if value.Kind != yaml.MappingNode {""", 1)
assert "SourceEnv, value.Value" in s' \
  ./internal/fleet/config 'TestMTC06AndS08APlaintextPasswordIsRefusedStructurally'

mutate C02 "an unknown YAML field is admitted" internal/fleet/config/document.go \
  's = s.replace("decoder.KnownFields(true)", "decoder.KnownFields(false)", 1)
assert "KnownFields(false)" in s' \
  ./internal/fleet/config 'TestMTC04AndC05UnknownFieldIsRejectedAtEveryLevel'

mutate C03 "a merge key is admitted" internal/fleet/config/document.go \
  's = s.replace("\"!!seq\":  true,", "\"!!seq\":  true,\n\t\"!!merge\": true,", 1)
s = s.replace("""	if node.Tag == \"!!merge\" {""", """	if false {""", 1)
assert "!!merge\": true" in s' \
  ./internal/fleet/config 'TestMTC18MergeKeyIsRejected'

mutate C04 "a second YAML document is admitted" internal/fleet/config/document.go \
  's = s.replace("	var extra yaml.Node\n	switch err := decoder.Decode(&extra); {", "	var extra yaml.Node\n	_ = extra\n	switch err := error(io.EOF); {", 1)
assert "err := error(io.EOF)" in s' \
  ./internal/fleet/config 'TestMTC20OnlyOneDocumentIsAccepted'

mutate C05 "the validated configuration retains the raw bytes" internal/fleet/config/schema.go \
  's = s.replace("""type Config struct {""", """type Config struct {
	// Raw is the document this configuration was decoded from.
	Raw []byte
""", 1)
assert "Raw []byte" in s' \
  ./test/security 'TestAValidatedConfigRetainsNoRawBytes'

mutate C38 "a configuration error still lets earlier targets execute" internal/fleet/config/load.go \
  's = s.replace("""		target, err := validateTarget(block, registry)
		if err != nil {
			return nil, withTarget(withPath(err, path), block.ID.String())
		}
		targets = append(targets, target)""", """		target, err := validateTarget(block, registry)
		if err != nil {
			continue
		}
		targets = append(targets, target)""", 1)
assert "			continue" in s' \
  ./internal/cli 'TestMTE20AConfigurationErrorDialsNothing'

echo
echo "--- credential reference and secret containment ---"

mutate C06 "a credential surface is serialized into the aggregate" internal/domain/runreport.go \
  'bt = chr(96)
s = s.replace("	ExecutionState ExecutionState      " + bt + "json:\"executionState\"" + bt,
              "	ExecutionState ExecutionState      " + bt + "json:\"executionState\"" + bt +
              "\n	Password       string              " + bt + "json:\"password\"" + bt, 1)
s = s.replace("""		ExecutionState: r.state,
	}""", """		ExecutionState: r.state,
		Password:       "redacted-but-present",
	}""", 1)
assert "Password       string" in s' \
  ./internal/cli 'TestMTD07TheAggregateJSONIsValidAndRoundTrips'

mutate C07 "the environment variable name reaches the report" internal/fleet/run/execute.go \
  's = s.replace("domain.ExecutionErrorCredentialResolution, safeMessage(err))", "domain.ExecutionErrorCredentialResolution, err.Error())", 1)
assert "CredentialResolution, err.Error())" in s' \
  ./internal/fleet/run 'TestAnExecutionErrorMessageNamesNoCredentialReference'

mutate C08 "the credential file path reaches the safe message" internal/fleet/secret/secret.go \
  's = s.replace("""	return fmt.Sprintf(\"the credential named by a %s reference could not be resolved: %s\",
		e.kind, e.reason)""", """	return fmt.Sprintf(\"the credential named by a %s reference %s could not be resolved: %s\",
		e.kind, e.name, e.reason)""", 1)
assert "e.kind, e.name, e.reason" in s' \
  ./internal/fleet/secret 'TestTheSafeMessageNamesNoReference'

mutate C09 "the resolver echoes the resolved value" internal/fleet/secret/secret.go \
  's = s.replace("		return security.NewSecret(value), nil", "		return security.Secret{}, refErrorf(ref, \"could not use the value \"+value)", 1)
assert "could not use the value" in s' \
  ./internal/fleet/secret 'TestMTS04NoSecretValueReachesAnError'

mutate C10 "the scheduler serializes the resolver unsafe message" internal/fleet/run/execute.go \
  's = s.replace("""func safeMessage(err error) string {
	var messenger safeMessenger
	if errors.As(err, &messenger) {
		return messenger.SafeMessage()
	}""", """func safeMessage(err error) string {
	var messenger safeMessenger
	if errors.As(err, &messenger) {
		return err.Error()
	}""", 1)
assert "return err.Error()" in s' \
  ./internal/fleet/run 'TestAnExecutionErrorMessageNamesNoCredentialReference|TestAnErrorWithNoSafeFormIsNotEchoed'

mutate C11 "preflight echoes the secret, reaching JSON" internal/fleet/secret/secret.go \
  's = s.replace("""		// The value goes out of scope here, unread and uncopied. Nothing below
		// this line can see it.
		return nil""", """		return refErrorf(ref, \"the value \"+value+\" was rejected\")""", 1)
assert "was rejected" in s' \
  ./internal/cli 'TestMTS01ToS04TheAdversarialSecretCorpusNeverEscapes'

mutate C12 "preflight echoes the secret, reaching the terminal" internal/fleet/secret/secret.go \
  's = s.replace("""		// The value goes out of scope here, unread and uncopied. Nothing below
		// this line can see it.
		return nil""", """		return refErrorf(ref, \"the value \"+value+\" was rejected\")""", 1)
assert "was rejected" in s' \
  ./internal/cli 'TestMTS01ToS04NoSecretReachesAnyRunSurface'

mutate C13 "the resolution error carries the value under every verb" internal/fleet/secret/secret.go \
  's = s.replace("""func (e *ResolutionError) GoString() string {
	return fmt.Sprintf(\"secret.ResolutionError{kind: %s, reason: %q}\", e.kind, e.reason)
}""", """func (e *ResolutionError) GoString() string {
	return fmt.Sprintf(\"secret.ResolutionError{kind: %s, name: %q, reason: %q}\",
		e.kind, e.name, e.reason)
}""", 1)
assert "name: %q, reason" in s' \
  ./internal/fleet/secret 'TestReferenceFormattingCannotLeak|TestTheSafeMessageIsAlsoSafeUnderEveryFormattingVerb'

echo
echo "--- credential authority ---"

mutate C14 "the resolver caches secrets" internal/fleet/secret/secret.go \
  's = s.replace("type Resolver struct{}", "type Resolver struct{ cache map[string]security.Secret }", 1)
assert "cache map[string]security.Secret" in s' \
  ./test/security 'TestTheFleetLayerHasNoSecretCache|TestTheResolverHoldsNoState'

mutate C15 "one reference reuses one credential object" internal/fleet/secret/secret.go \
  's = s.replace("""	endpoint, err := security.NewEndpoint(target.Host, target.Port)""", """	if cached, ok := credentialCache[ref.Name()]; ok {
		return cached, nil
	}
	endpoint, err := security.NewEndpoint(target.Host, target.Port)""", 1)
s = s.replace("""// ResolutionError is a credential that could not be obtained.""", """var credentialCache = map[string]security.Credential{}

// ResolutionError is a credential that could not be obtained.""", 1)
s = s.replace("""	return credential, nil
}""", """	credentialCache[ref.Name()] = credential
	return credential, nil
}""", 1)
assert "credentialCache" in s' \
  ./internal/fleet/run 'TestMTS05OneReferenceProducesTwoIndependentCredentials'

mutate C16 "the target identifier becomes the credential authority" internal/fleet/secret/secret.go \
  's = s.replace("security.NewEndpoint(target.Host, target.Port)", "security.NewEndpoint(target.ID.String(), target.Port)", 1)
assert "target.ID.String(), target.Port" in s' \
  ./test/security 'TestTheResolverBindsAuthorityToTheEndpointAndNotTheIdentifier'

mutate C36 "the scheduler calls security.Reveal" internal/fleet/run/execute.go \
  's = s.replace("	targetCtx, cancel := context.WithTimeout", "	_ = security.Reveal(security.Secret{})\n	targetCtx, cancel := context.WithTimeout", 1)
assert "security.Reveal(" in s' \
  ./test/security 'TestTheSchedulerPerformsNoCredentialOperation'

mutate C37 "the scheduler calls Credential.SecretFor" internal/fleet/run/execute.go \
  's = s.replace("	targetCtx, cancel := context.WithTimeout", "	_, _ = credential.SecretFor(security.Endpoint{})\n	targetCtx, cancel := context.WithTimeout", 1)
assert ".SecretFor(" in s' \
  ./test/security 'TestTheSchedulerPerformsNoCredentialOperation'

echo
echo "--- execution semantics ---"

mutate C17 "duplicate endpoints are deduplicated" internal/fleet/run/execute.go \
  's = s.replace("""	target := e.params.Config.Targets[index]
	id := target.ID.String()""", """	target := e.params.Config.Targets[index]
	for j := 0; j < index; j++ {
		other := e.params.Config.Targets[j]
		if other.Host == target.Host && other.Port == target.Port {
			e.results[index] = mustNotStarted(target.ID.String(), serviceID(target))
			return
		}
	}
	id := target.ID.String()""", 1)
assert "other.Host == target.Host" in s' \
  ./internal/fleet/run 'TestMTE09TheSameEndpointWithDifferentAuthorityIsTwoTargets'

mutate C18 "a diagnostic failure becomes an execution failure" internal/fleet/run/execute.go \
  's = s.replace("""	result, err := domain.CompletedTarget(id, service, outcome.Report, outcome.Incomplete)""", """	if outcome.Report.Summary().Status() == domain.SummaryStatusProblemsFound {
		return mustFailed(id, service, domain.ExecutionErrorInternal, \"the target failed\")
	}
	result, err := domain.CompletedTarget(id, service, outcome.Report, outcome.Incomplete)""", 1)
assert "the target failed" in s' \
  ./internal/fleet/run 'TestMTE02RemoteAuthFailureIsACompletedExecution'

mutate C19 "a credential resolution failure fabricates a report" internal/fleet/run/execute.go \
  's = s.replace("""		e.results[index] = mustFailed(id, service,
			domain.ExecutionErrorCredentialResolution, safeMessage(err))
		return""", """		other := domain.Report{}
		for _, r := range e.results {
			if r.HasReport() {
				other = r.Report()
			}
		}
		if result, cerr := domain.CompletedTarget(id, service, other, false); cerr == nil {
			e.results[index] = result
			return
		}
		e.results[index] = mustFailed(id, service,
			domain.ExecutionErrorCredentialResolution, safeMessage(err))
		return""", 1)
assert "if r.HasReport()" in s' \
  ./internal/fleet/run 'TestMTE04CredentialResolutionFailure'

mutate C20 "a never-started target is given another target report" internal/fleet/run/execute.go \
  's = s.replace("""		result, err := domain.NotStartedTarget(target.ID.String(), serviceID(target))
		if err != nil {
			return domain.RunReport{}, err
		}
		results[i] = result""", """		var borrowed domain.Report
		for _, r := range results {
			if r.HasReport() {
				borrowed = r.Report()
			}
		}
		result, err := domain.CompletedTarget(target.ID.String(), serviceID(target), borrowed, true)
		if err != nil {
			result, err = domain.NotStartedTarget(target.ID.String(), serviceID(target))
		}
		if err != nil {
			return domain.RunReport{}, err
		}
		results[i] = result""", 1)
assert "borrowed" in s' \
  ./internal/fleet/run 'TestMTE06CancellationLifecycleMatrix'

mutate C21 "a never-started target resolves its credential anyway" internal/fleet/run/execute.go \
  's = s.replace("""	if e.runCtx.Err() != nil {
		e.results[index] = mustNotStarted(id, service)
		return
	}""", """	if e.runCtx.Err() != nil {
		_, _ = e.params.Resolver.CredentialFor(context.Background(), target)
		e.results[index] = mustNotStarted(id, service)
		return
	}""", 1)
assert "context.Background(), target" in s' \
  ./test/security 'TestTheSchedulerChecksTheRunContextBeforeSpendingAnything'

mutate C22 "a never-started target reaches the runner anyway" internal/fleet/run/execute.go \
  's = s.replace("""	if e.runCtx.Err() != nil {
		e.results[index] = mustNotStarted(id, service)
		return
	}""", """	if false {
		e.results[index] = mustNotStarted(id, service)
		return
	}""", 1)
assert "	if false {" in s' \
  ./test/security 'TestTheSchedulerChecksTheRunContextBeforeSpendingAnything'

mutate C30 "a diagnostic failure stops the run" internal/fleet/run/execute.go \
  's = s.replace("""	e.results[index] = e.classify(id, service, outcome)""", """	e.results[index] = e.classify(id, service, outcome)
	if e.results[index].HasProblems() {
		e.failFast()
	}""", 1)
s = s.replace("""type executor struct {""", """func (e *executor) failFast() { e.stop() }

type executor struct {
	stop context.CancelFunc
""", 1)
s = s.replace("""	e := &executor{params: params, runCtx: runCtx, results: results}""", """	stopCtx, stopAll := context.WithCancel(runCtx)
	defer stopAll()
	runCtx = stopCtx
	e := &executor{params: params, runCtx: runCtx, results: results, stop: stopAll}""", 1)
assert "failFast" in s' \
  ./internal/fleet/run 'TestMTE02NoFailFastOnDiagnosticOrExecutionFailure'

mutate C31 "an execution failure stops the run" internal/fleet/run/execute.go \
  's = s.replace("""		e.results[index] = mustFailed(id, service,
			domain.ExecutionErrorCredentialResolution, safeMessage(err))
		return""", """		e.results[index] = mustFailed(id, service,
			domain.ExecutionErrorCredentialResolution, safeMessage(err))
		e.stop()
		return""", 1)
s = s.replace("""		e.results[index] = mustFailed(id, service, domain.ExecutionErrorInternal, err.Error())
		return""", """		e.results[index] = mustFailed(id, service, domain.ExecutionErrorInternal, err.Error())
		e.stop()
		return""", 1)
s = s.replace("""type executor struct {""", """type executor struct {
	stop context.CancelFunc
""", 1)
s = s.replace("""	e := &executor{params: params, runCtx: runCtx, results: results}""", """	stopCtx, stopAll := context.WithCancel(runCtx)
	defer stopAll()
	runCtx = stopCtx
	e := &executor{params: params, runCtx: runCtx, results: results, stop: stopAll}""", 1)
assert s.count("e.stop()") == 2' \
  ./internal/fleet/run 'TestMTE02NoFailFastOnDiagnosticOrExecutionFailure'

echo
echo "--- budgets and concurrency ---"

mutate C25 "the worker limit is removed" internal/fleet/run/execute.go \
  's = s.replace("""	next := make(chan int)""", """	workers = len(targets)
	next := make(chan int)""", 1)
assert "workers = len(targets)" in s' \
  ./internal/fleet/run 'TestMTE11AndE12ConcurrencyIsBoundedAtEveryPoolSize'

mutate C26 "concurrency above the maximum is accepted" internal/fleet/run/run.go \
  's = s.replace("""	case p.Config.Run.Concurrency > config.MaxConcurrency:""", """	case false:""", 1)
assert "	case false:" in s' \
  ./internal/fleet/run 'TestMTE11AndE13AndE14Concurrency|TestParamsAreValidatedBeforeAnythingRuns'

mutate C27 "a target budget is derived from the root rather than the run" internal/fleet/run/execute.go \
  's = s.replace("""	targetCtx, cancel := context.WithTimeout(e.runCtx, target.Timeout)""", """	targetCtx, cancel := context.WithTimeout(context.Background(), target.Timeout)""", 1)
assert "context.WithTimeout(context.Background(), target.Timeout)" in s' \
  ./internal/fleet/run 'TestMTE17RunDeadlineDominatesTargetDeadline'

mutate C28 "a target timeout cancels its siblings" internal/fleet/run/execute.go \
  's = s.replace("""	outcome, err := runner.Run(targetCtx, target, credential)""", """	outcome, err := runner.Run(targetCtx, target, credential)
	if targetCtx.Err() != nil {
		e.cancelRun()
	}""", 1)
s = s.replace("""type executor struct {""", """type executor struct {
	cancelRun context.CancelFunc
""", 1)
s = s.replace("""	e := &executor{params: params, runCtx: runCtx, results: results}""", """	stopCtx, stopAll := context.WithCancel(runCtx)
	defer stopAll()
	runCtx = stopCtx
	e := &executor{params: params, runCtx: runCtx, results: results, cancelRun: stopAll}""", 1)
assert "e.cancelRun()" in s' \
  ./internal/fleet/run 'TestMTE16ATargetTimeoutDoesNotCancelASibling'

mutate C29 "cancellation is reported as a target-side problem" internal/domain/runreport.go \
  's = s.replace("""	s := RunSummary{targets: len(results), status: SummaryStatusOK}""", """	s := RunSummary{targets: len(results), status: SummaryStatusOK}
	for _, r := range results {
		if r.ExecutionState() == ExecutionStateCancelled {
			s.status = SummaryStatusProblemsFound
		}
	}""", 1)
assert "ExecutionStateCancelled {" in s' \
  ./internal/fleet/run 'TestMTE06CancellationLifecycleMatrix'

echo
echo "--- ordering and determinism ---"

mutate C23 "results are sorted by execution state" internal/domain/runreport.go \
  's = s.replace("""	targets := slices.Clone(in.Targets)""", """	targets := slices.Clone(in.Targets)
	slices.SortStableFunc(targets, func(a, b TargetResult) int {
		return int(a.state) - int(b.state)
	})""", 1)
assert "SortStableFunc" in s' \
  ./internal/fleet/run 'TestDeclaredOrderSurvivesMixedExecutionStates'

mutate C24 "results follow completion order" internal/fleet/run/execute.go \
  's = s.replace("""	report, err := domain.NewRunReport(domain.RunReportInput{""", """	slices.Reverse(results)
	report, err := domain.NewRunReport(domain.RunReportInput{""", 1)
s = s.replace("""import (
	\"context\"""", """import (
	\"slices\"

	\"context\"""", 1)
assert "slices.Reverse" in s' \
  ./internal/fleet/run 'TestMTD01DeclaredOrderIsPreservedThroughExecution'

echo
echo "--- report, redaction and presentation ---"

mutate C39 "the pseudonym table becomes per target" internal/security/redaction/run.go \
  's = s.replace("""	t := newTable(collectRun(results))""", """	t := newTable(collectRun(results))
	_ = t""", 1)
s = s.replace("""		t.resetUsage()""", """		t = newTable(collectRun([]domain.TargetResult{result}))""", 1)
assert "collectRun([]domain.TargetResult{result})" in s' \
  ./internal/cli 'TestMTS16OnePseudonymTablePerRun|TestShareableUsesOnePseudonymTableForTheWholeRun'

mutate C40 "the aggregate emits the raw service configuration" internal/domain/runreport.go \
  'bt = chr(96)
s = s.replace("	Targets       []TargetResult   " + bt + "json:\"targets\"" + bt,
              "	RawConfig     string           " + bt + "json:\"config\"" + bt +
              "\n	Targets       []TargetResult   " + bt + "json:\"targets\"" + bt, 1)
s = s.replace("""		Targets:       r.targets,""", """		RawConfig:     "version: 1",
		Targets:       r.targets,""", 1)
assert "RawConfig" in s' \
  ./internal/cli 'TestTheAggregateSerializesNoConfigurationSurface'

mutate C32 "the renderer computes the exit code" internal/render/terminal/run.go \
  's = s.replace("""func WriteRun(w io.Writer, report domain.RunReport) error {""", """func RunExitCode(report domain.RunReport) int { return 0 }

func WriteRun(w io.Writer, report domain.RunReport) error {""", 1)
assert "func RunExitCode(" in s' \
  ./test/security 'TestTheRendererDoesNotDecideTheExitCode'

mutate C33 "the renderer adds a cross-target diagnosis" internal/render/terminal/run.go \
  's = s.replace("""	return writeRunSummary(w, report)""", """	if report.Summary().WithProblems() > 1 {
		if _, err := io.WriteString(w, \"the root cause is shared between these targets\\n\"); err != nil {
			return err
		}
	}
	return writeRunSummary(w, report)""", 1)
assert "root cause is shared" in s' \
  ./test/security 'TestNoAggregateSurfaceCombinesTwoTargetsOutcomes'

mutate C34 "the scheduler imports a diagnosis package" internal/fleet/run/execute.go \
  's = s.replace("""import (
	\"context\"""", """import (
	_ \"github.com/hakanaltindag/svcdoctor/internal/diagnosis/redis\"

	\"context\"""", 1)
assert "diagnosis/redis" in s' \
  ./test/security 'TestNoRunSurfaceComparesTwoTargetReports'

mutate C35 "the scheduler imports a wire package" internal/fleet/run/execute.go \
  's = s.replace("""import (
	\"context\"""", """import (
	_ \"github.com/hakanaltindag/svcdoctor/internal/adapter/rabbitmq/wire\"

	\"context\"""", 1)
assert "adapter/rabbitmq/wire" in s' \
  ./test/security 'TestTheFleetCoreReachesNoProtocol'

echo
echo "--- exit contract ---"

mutate CEX1 "exit 1 outranks exit 4" internal/cli/exit.go \
  's = s.replace("""	if report.Summary().Incomplete() {
		return ExitIncomplete
	}
	if report.Summary().Status() == domain.SummaryStatusProblemsFound {
		return ExitProblemsFound
	}""", """	if report.Summary().Status() == domain.SummaryStatusProblemsFound {
		return ExitProblemsFound
	}
	if report.Summary().Incomplete() {
		return ExitIncomplete
	}""", 1)
tail = s.split("func RunExitCode")[1]
assert tail.index("ExitProblemsFound\n") < tail.index("ExitIncomplete\n")' \
  ./internal/cli 'TestRunExitCodeMatrix|TestExitFourOutranksOneThroughTheRealSurface'

mutate CEX2 "EXECUTION_FAILED maps to exit 3" internal/cli/exit.go \
  's = s.replace("""	if report.Summary().Incomplete() {
		return ExitIncomplete
	}""", """	if report.Summary().ExecutionFailed() > 0 {
		return ExitInternal
	}
	if report.Summary().Incomplete() {
		return ExitIncomplete
	}""", 1)
assert "ExecutionFailed() > 0" in s' \
  ./internal/cli 'TestRunExitCodeMatrix'

# The anchor moved in Phase 9.2B, which added services.ErrPreflight to the same
# branch. The mutation is unchanged in intent — disable the credential-resolution
# classification and require the exit-2 guards to notice — and is expressed as a
# `&& false` so the `secret` import stays used and the file still compiles.
mutate CEX3 "a preflight credential failure is reported as a svcdoctor failure" internal/cli/exit.go \
  's = s.replace("errors.Is(err, secret.ErrResolution),", "errors.Is(err, secret.ErrResolution) \u0026\u0026 false,", 1)
assert "secret.ErrResolution) \u0026\u0026 false," in s' \
  ./internal/cli 'TestMTS11NoCredentialReferenceReachesTheReport|TestMTR03BlackBoxExitTwo'

mutate CEX4 "run gains a --password-file flag" internal/cli/run.go \
  's = s.replace("""		shareable   = fs.Bool(\"shareable\", false, \"produce the shareable redacted report\")""", """		shareable   = fs.Bool(\"shareable\", false, \"produce the shareable redacted report\")
		_           = fs.String(\"password-file\", \"\", \"a shared password file\")""", 1)
assert "password-file" in s' \
  ./internal/cli 'TestTheRunCommandExposesOnlyRunGlobalFlags'

echo
echo "--- interrupt contract ---"

mutate CEX5 "the second interrupt is swallowed" internal/cli/interrupt.go \
  's = s.replace("""	select {
	case <-done:
		// The run observed the cancellation, wrote its aggregate and returned an
		// exit code. Nothing further to do.
		return
	case <-signals:
		_, _ = fmt.Fprintln(a.Stderr, abortMessage)
		abort(ExitInternal)
	}""", "	_ = abort\n	_ = abortMessage", 1)
assert "abort(ExitInternal)" not in s' \
  ./internal/cli 'TestMTE07AFirstInterruptCancelsAndASecondAborts'

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
