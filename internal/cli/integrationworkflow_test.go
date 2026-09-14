package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Structural guards for the hosted service-integration CI and release gate.
//
// The Phase 14.0A contract and ADR 0098 are the authority. These tests protect
// the architecture rather than the bytes: which events run which lanes, what
// authority the workflow holds, what it is pinned to, and that publication
// cannot start without it. A guard that compared the file to a golden copy would
// fail on every comment edit and catch nothing a reviewer would not already see.
//
// # What ADR 0098 actually requires, and why it is checked here
//
// "Gates release publication" is defined in ADR 0098 §2.3 as a property of the
// `needs:` graph — the publication DAG cannot reach the publication operation
// when the required result fails. It explicitly does **not** mean that a workflow
// contains a job with a plausible name. So the release half of this file reads
// edges, never strings, and `TestOCIPublicationCannotStartBeforeLinuxIntegration`
// in validateworkflow_test.go carries the suite list that must ride those edges.
//
// # Why the file is inspected as text
//
// Every workflow guard in this repository reads its workflow as a string, and
// these join them rather than introducing a second convention — and a YAML
// decoder in this package would put the module ADR 0071 §3.3 confines to
// `internal/fleet/config` one import away from the CLI.
//
// # The two things text cannot prove
//
// GitHub renders a matrix job's status check from the job's `name`, and it
// expands `include:` from an expression at scheduling time. Both are statements
// about GitHub's runtime rather than about this file, and both are recorded as
// hosted-run assertions in the Phase 14.0B validation record. What is asserted
// here is everything that determines them.
const integrationWorkflow = ".github/workflows/integration.yml"

// The frozen lane set, with the per-lane job timeouts of Phase 14.0A §16.
//
// Each timeout sits deliberately above its suite's own `go test -timeout` so a
// hung test is reported by the harness — with its goroutine dump — rather than
// killed by the runner. They detect a hang; they do not bound a slow run.
var (
	integrationPullRequestLanes = map[string]int{
		"redis": 25, "valkey": 25, "rabbitmq": 30, "lavinmq": 25,
	}
	integrationFullLanes = map[string]int{
		"redis": 25, "valkey": 25, "rabbitmq": 30, "lavinmq": 25, "multitarget": 40,
	}
)

// releaseIntegrationSuites is the release matrix after Phase 14.0B: the three
// that were already gated, plus the four ADR 0098 obliges and multi-target,
// which ADR 0098 §2.8 deliberately excludes from the Level-3 model and Phase
// 14.0A §23 gates for its own reason.
var releaseIntegrationSuites = []string{
	"postgres", "kafka", "redpanda",
	"redis", "valkey", "rabbitmq", "lavinmq", "multitarget",
}

// The six image references the gated suites resolve to, pinned by tag **and**
// digest. Each digest is a multi-architecture index digest, confirmed in Phase
// 14.0B against both the Docker Hub registry API and Docker's own RepoDigests
// for the images the graded suites ran against — so it resolves on the hosted
// amd64 runner and on an arm64 developer machine alike.
//
// A tag is mutable, and a graded row that silently changes what it was graded
// against is not repeatable (ADR 0095 §2.4, generalized by ADR 0098 §2.4).
var gatedServiceImages = map[string]string{
	"test/integration/redis/env/compose.yaml": "redis:8.2.1-alpine@sha256:" +
		"987c376c727652f99625c7d205a1cba3cb2c53b92b0b62aade2bd48ee1593232",
	"test/integration/valkey/env/compose.yaml": "valkey/valkey:8.1.1-alpine@sha256:" +
		"6a57d58c0a37cf7acc3045ac0fd6dd91be339774106ab4d9ca088013a096a99f",
	"test/integration/lavinmq/env/compose.yaml": "cloudamqp/lavinmq:2.3.0@sha256:" +
		"3dd7f348e5ef59dc62d4a9b0216e7f980f98afa7aee718e1c7226e7997c14da3",
}

// RabbitMQ runs three broker versions in one lane, so its compose file carries
// three references rather than one.
var rabbitmqImages = []string{
	"rabbitmq:3.13.7@sha256:" +
		"87178a0ee3e2f52980ba356d38646ed1056705ff2d5ff281f8965456eaa0c1e3",
	"rabbitmq:4.0.9@sha256:" +
		"ac54b28e5fafef680274661eb0011bd6d9801e12c51ccbb0e19e57281b2654f2",
	"rabbitmq:4.2.0@sha256:" +
		"8b31dd492c1f97d48127326dd07519f8aa854b6e75cb7ebf76878daba1c57259",
}

const rabbitmqCompose = "test/integration/rabbitmq/env/compose.yaml"

// --- triggers ---------------------------------------------------------------

// TestTheIntegrationWorkflowTriggersOnExactlyTheFrozenEvents covers the trigger
// half of Phase 14.0A §10, §25, §26 and §18.
//
// The trust boundary is the half that matters most. `pull_request_target` would
// run a fork's own code with the base repository's token and secret access, and
// these lanes execute repository code inside a container runtime — the worst
// possible place for it.
func TestTheIntegrationWorkflowTriggersOnExactlyTheFrozenEvents(t *testing.T) {
	raw := readRepoFile(t, integrationWorkflow)
	wf := withoutComments(raw)

	header, _, found := strings.Cut(wf, "\njobs:")
	if !found {
		t.Fatal("the integration workflow has no jobs block")
	}

	for _, want := range []struct{ directive, why string }{
		{"\n  pull_request:", "the four cheap service lanes run on pull requests"},
		{"\n  push:", "post-merge confirmation on main, which is where multi-target is first caught"},
		{"branches: [main]", "push is scoped to main"},
		{"- cron: '37 4 * * 2'", "the weekly full run, off the hour and off kubernetes.yml's weekday"},
		{"\n  workflow_dispatch:", "on-demand full matrix"},
	} {
		if !strings.Contains(header, want.directive) {
			t.Errorf("the integration workflow header is missing %q (%s)", want.directive, want.why)
		}
	}

	// Checked against the comment-stripped document: a directive hiding inside a
	// commented-out block someone meant to restore is not active, and a guard
	// that flagged prose would fire on the comment explaining the refusal.
	if strings.Contains(wf, "pull_request_target") {
		t.Error("the integration workflow uses pull_request_target.\n\n" +
			"Phase 14.0A §15 refuses it outright. These lanes run the pull request's own " +
			"code inside a container runtime; pull_request_target would hand that code " +
			"the base repository's token and secrets.")
	}

	// A dispatch input could name an image or a version, which would let a manual
	// run manufacture evidence for a product nobody graded (ADR 0095 §2.3,
	// ADR 0098 §2.4).
	if strings.Contains(header, "workflow_dispatch:\n    inputs:") {
		t.Error("workflow_dispatch declares inputs.\n\n" +
			"Phase 14.0A §26: a dispatched run selects lanes from the frozen matrix and " +
			"accepts no image reference, so it cannot create a compatibility claim.")
	}

	// Phase 14.0A §18. Shared code breaks a service without touching its
	// directory: internal/domain, internal/diagnosis, internal/render,
	// internal/security, internal/cli, internal/fleet and go.mod all reach every
	// suite. A filter that excluded any of them would be wrong, and one that
	// included all of them excludes nothing — and a required check that does not
	// run reports pending forever rather than green.
	for _, filter := range []string{"paths:", "paths-ignore:"} {
		if strings.Contains(header, filter) {
			t.Errorf("the integration workflow declares %q.\n\n"+
				"Phase 14.0A §18 refused path filtering: a change in shared code can break "+
				"any adapter without touching its service directory.", filter)
		}
	}
}

// --- authority --------------------------------------------------------------

// TestTheIntegrationWorkflowHoldsNoAuthorityItDoesNotNeed covers Phase 14.0A
// §15, §19 and §21.
//
// The fixtures are created on the runner and destroyed there. Nothing in these
// lanes writes to the repository, publishes a package, holds a signing identity
// or needs a secret — and a lane that ever needs one has stopped being
// self-contained, which is a new decision rather than an edit.
func TestTheIntegrationWorkflowHoldsNoAuthorityItDoesNotNeed(t *testing.T) {
	wf := withoutComments(readRepoFile(t, integrationWorkflow))
	header, _, _ := strings.Cut(wf, "\njobs:")

	if !strings.Contains(header, "permissions:\n  contents: read") {
		t.Error("the integration workflow does not default to contents: read")
	}
	for _, escalation := range []string{
		"contents: write", "packages: write", "id-token: write",
		"actions: write", "pull-requests: write", "attestations: write",
	} {
		if strings.Contains(wf, escalation) {
			t.Errorf("the integration workflow requests %q; nothing in these lanes needs it.\n\n"+
				"Publication permissions stay isolated to release-oci.yml's publication jobs.",
				escalation)
		}
	}

	// `secrets.` is the whole context, so this catches an inherited secret as
	// well as a named one. Phase 14.0A §15 froze the count at zero: every
	// credential these lanes touch is a committed, non-sensitive fixture value
	// (`s3cr3t-pw`, `tls-pw`, `guest:guest`) or a certificate minted per run by
	// gen-certs.sh. Needing a repository secret voids the design.
	if strings.Contains(wf, "secrets.") || strings.Contains(wf, "secrets:") {
		t.Error("the integration workflow references a repository secret.\n\n" +
			"Phase 14.0A §15: required repository secrets are ZERO, and a lane that " +
			"needs one is a new decision rather than an edit.")
	}

	// Phase 14.0A §21 admits none. The failure diagnostics these lanes need are
	// already in the job log: every `*-up` target prints `compose ps` and the last
	// 30-40 log lines of each service on a readiness failure.
	if strings.Contains(wf, "upload-artifact") {
		t.Error("the integration workflow uploads an artifact; Phase 14.0A §21 admits none")
	}

	// Nothing is fetched and executed. These lanes install no tool at all.
	if pipeIntoShell.MatchString(wf) {
		t.Error("the integration workflow pipes a download into a shell")
	}

	// Phase 14.0A §19. Only the two actions this repository already carries, each
	// by the digest it already carries — so no digest had to be invented for this
	// file, which is the trap UX-S16-b recorded.
	uses := regexp.MustCompile(`uses:\s*(\S+)`).FindAllStringSubmatch(wf, -1)
	if len(uses) == 0 {
		t.Fatal("the integration workflow references no action; this guard would pass vacuously")
	}
	allowed := map[string]bool{
		"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1": true,
		"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e": true,
	}
	for _, u := range uses {
		if !allowed[u[1]] {
			t.Errorf("the integration workflow uses %q.\n\n"+
				"Phase 14.0A §19 authorizes no new third-party action; these two are all "+
				"the lanes need.", u[1])
		}
	}
}

// --- runner, budget and toolchain -------------------------------------------

// TestTheIntegrationLanesRunOnTheFrozenRunnerAndBudget covers Phase 14.0A §14,
// §16 and the file's half of §13.
func TestTheIntegrationLanesRunOnTheFrozenRunnerAndBudget(t *testing.T) {
	wf := withoutComments(readRepoFile(t, integrationWorkflow))
	suite := workflowJobBlock(t, wf, "suite")

	// An explicit generation pin. `ubuntu-latest` rolls to the next LTS on its
	// own, and this is a release-gating lane rather than a convenience.
	if !strings.Contains(suite, "runs-on: ubuntu-24.04") {
		t.Error("the integration lane does not run on ubuntu-24.04")
	}
	// Linux only. macOS bind mounts mask container ownership, which is how the
	// v0.3.1 defect survived every local run; hosted execution on Linux/amd64 is
	// the evidence these lanes exist to add.
	for _, wrong := range []string{"ubuntu-latest", "macos-", "windows-"} {
		if strings.Contains(suite, wrong) {
			t.Errorf("the integration lane runs on %q; Phase 14.0A §14 pins ubuntu-24.04 "+
				"and admits no non-Linux runner", wrong)
		}
	}

	// The timeout is per-lane, so the job takes it from the matrix. A literal
	// here would silently apply one budget to all five.
	if !strings.Contains(suite, "timeout-minutes: ${{ matrix.timeout }}") {
		t.Error("the integration lane does not take its timeout from the matrix.\n\n" +
			"Phase 14.0A §16 froze five different budgets (25/25/25/30/40); a single " +
			"literal would apply one of them to every lane.")
	}
	if regexp.MustCompile(`timeout-minutes:\s*\d`).MatchString(suite) {
		t.Error("the integration lane hardcodes a job timeout beside the matrix one")
	}

	// Each frozen job budget must exceed its suite's own `go test -timeout`, or
	// the runner kills the job before the harness can report the hang.
	makefile := readRepoFile(t, "Makefile")
	for _, want := range []struct {
		target      string
		goTimeout   string
		jobBudget   int
		description string
	}{
		{"redis-test", "-timeout 15m", 25, "redis"},
		{"valkey-test", "-timeout 15m", 25, "valkey"},
		{"rabbitmq-test", "-timeout 20m", 30, "rabbitmq"},
		{"lavinmq-test", "-timeout 15m", 25, "lavinmq"},
		{"multitarget-test", "-timeout 15m", 40, "multitarget"},
	} {
		_, body, found := strings.Cut(makefile, "\n"+want.target+":")
		if !found {
			t.Errorf("the Makefile declares no %s target", want.target)
			continue
		}
		body, _, _ = strings.Cut(body, "\n\n")
		if !strings.Contains(body, want.goTimeout) {
			t.Errorf("the %s suite no longer runs under a %q go test timeout; the "+
				"%d-minute job budget was chosen to sit above it and must be re-derived",
				want.description, want.goTimeout, want.jobBudget)
		}
	}

	// go.mod is the single source of truth for the toolchain.
	if !strings.Contains(suite, "go-version-file: go.mod") {
		t.Error("the integration lane does not take its Go version from go.mod")
	}
	if regexp.MustCompile(`go-version:\s*'?1\.\d`).MatchString(suite) {
		t.Error("the integration lane hardcodes a Go version.\n\n" +
			"go.mod is authoritative. A second version here is a second authority " +
			"that drifts from it the first time either is edited.")
	}

	// Phase 14.0A §13. GitHub composes the check from the workflow name and the
	// job name; that it renders exactly is a hosted-run assertion, but everything
	// that determines it lives here.
	if !strings.HasPrefix(strings.TrimSpace(wf), "name: Integration\n") {
		t.Error("the workflow is not named `Integration`; the required-check identity " +
			"is composed from it")
	}
	if !strings.Contains(suite, "name: Integration (${{ matrix.suite }})") {
		t.Error("the integration lane does not name itself from the matrix.\n\n" +
			"Phase 14.0A §13 froze `Integration (<suite>)`, the convention " +
			"release-oci.yml already declares verbatim. Without an explicit name " +
			"GitHub appends the matrix values in its own format and a failure stops " +
			"naming the product that failed.")
	}
}

// --- the event-dependent matrix ---------------------------------------------

// integrationMatrixExpression returns the matrix expression the suite job
// declares.
func integrationMatrixExpression(t *testing.T, suite string) string {
	t.Helper()

	m := regexp.MustCompile(`(?m)^\s*include:\s*(\$\{\{.*\}\})\s*$`).FindStringSubmatch(suite)
	if m == nil {
		t.Fatal("the integration lane declares no matrix expression on a single line.\n\n" +
			"A folded block scalar keeps the newlines of its continuation lines, so the " +
			"expression would reach GitHub with line breaks inside it.")
	}
	return m[1]
}

// resolveIntegrationLanes evaluates the frozen matrix expression for one event.
//
// It implements exactly one expression shape — `COND && fromJSON(A) || fromJSON(B)`
// where COND is a disjunction of `github.event_name == '...'` — and fails on
// anything else, so a rewritten expression is a failing test rather than a
// silently unevaluated one.
//
// The semantics it assumes are GitHub's documented ones: `&&` yields its right
// operand when the left is truthy, `||` yields its left operand when that is
// truthy, and a non-empty array is truthy. That the runtime agrees, and that it
// expands an `include:` expression into one job per object, is confirmed by the
// hosted run rather than by this test.
func resolveIntegrationLanes(t *testing.T, expression, event string) map[string]int {
	t.Helper()

	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expression, "${{"), "}}"))

	cond, rest, ok := strings.Cut(body, "&&")
	if !ok {
		t.Fatalf("matrix expression is not the frozen `COND && A || B` shape: %s", expression)
	}
	whenTrue, whenFalse, ok := strings.Cut(rest, "||")
	if !ok {
		t.Fatalf("matrix expression has no fallback branch: %s", expression)
	}

	events := map[string]bool{}
	for _, term := range regexp.MustCompile(
		`github\.event_name\s*==\s*'([a-z_]+)'`).FindAllStringSubmatch(cond, -1) {
		events[term[1]] = true
	}
	if len(events) == 0 {
		t.Fatalf("the matrix condition names no event: %s", cond)
	}

	branch := whenFalse
	if events[event] {
		branch = whenTrue
	}

	m := regexp.MustCompile(`fromJSON\('(.*)'\)`).FindStringSubmatch(branch)
	if m == nil {
		t.Fatalf("branch %q for event %q carries no fromJSON array", strings.TrimSpace(branch), event)
	}
	var entries []struct {
		Suite   string `json:"suite"`
		Timeout int    `json:"timeout"`
	}
	if err := json.Unmarshal([]byte(m[1]), &entries); err != nil {
		t.Fatalf("branch for event %q is not a JSON array of {suite,timeout}: %v", event, err)
	}
	if len(entries) == 0 {
		t.Fatalf("branch for event %q names no lane", event)
	}

	lanes := map[string]int{}
	for _, e := range entries {
		if e.Suite == "" {
			t.Fatalf("branch for event %q carries an entry with no suite", event)
		}
		if e.Timeout == 0 {
			t.Fatalf("lane %q for event %q declares no timeout; the job would fall back "+
				"to GitHub's 360-minute default and stop detecting a hang", e.Suite, event)
		}
		lanes[e.Suite] = e.Timeout
	}
	return lanes
}

// TestTheIntegrationMatrixIsEventDependentExactlyAsFrozen is the property most
// easily broken by a well-meaning edit and the one a reviewer is least likely to
// evaluate in their head.
//
// Phase 14.0A §10: multi-target is the heaviest lane by roughly an order of
// magnitude, it starts four fixture sets at once, and its unique content is the
// part most thoroughly covered hermetically inside `make check`. So it runs on
// main, on the schedule, on demand and at release — and not on a pull request.
// Promoting it is a recorded condition, not a casual edit.
func TestTheIntegrationMatrixIsEventDependentExactlyAsFrozen(t *testing.T) {
	wf := withoutComments(readRepoFile(t, integrationWorkflow))
	expression := integrationMatrixExpression(t, workflowJobBlock(t, wf, "suite"))

	for _, tc := range []struct {
		event string
		want  map[string]int
	}{
		{"pull_request", integrationPullRequestLanes},
		{"push", integrationFullLanes},
		{"schedule", integrationFullLanes},
		{"workflow_dispatch", integrationFullLanes},
	} {
		t.Run(tc.event, func(t *testing.T) {
			got := resolveIntegrationLanes(t, expression, tc.event)
			if len(got) != len(tc.want) {
				t.Errorf("event %q resolves to %d lanes %v, want %d %v",
					tc.event, len(got), got, len(tc.want), tc.want)
			}
			for suite, timeout := range tc.want {
				switch actual, ok := got[suite]; {
				case !ok:
					t.Errorf("event %q does not run the %q lane.\n\n"+
						"ADR 0098 §2.1 requires every Level-3 claim to be backed by a "+
						"lane that gates release publication, and Phase 14.0A §10 froze "+
						"this event's lane set.", tc.event, suite)
				case actual != timeout:
					t.Errorf("event %q runs %q with timeout-minutes %d, want %d "+
						"(Phase 14.0A §16)", tc.event, suite, actual, timeout)
				}
			}
			for suite := range got {
				if _, ok := tc.want[suite]; !ok {
					t.Errorf("event %q runs an unfrozen lane %q", tc.event, suite)
				}
			}
		})
	}

	// The two halves of the multi-target exclusion, stated as their own
	// assertions so a failure says which direction broke.
	pr := resolveIntegrationLanes(t, expression, "pull_request")
	if _, ok := pr["multitarget"]; ok {
		t.Error("multi-target runs on pull requests.\n\n" +
			"Phase 14.0A §10 and freeze-table row 3 refuse it: it is the heaviest lane " +
			"and the largest flake surface, and Phase 14.0B was told not to promote it. " +
			"Promotion is a recorded condition — four consecutive weeks of green hosted " +
			"main and scheduled runs — not an edit.")
	}
	for _, event := range []string{"push", "schedule", "workflow_dispatch"} {
		if _, ok := resolveIntegrationLanes(t, expression, event)["multitarget"]; !ok {
			t.Errorf("multi-target does not run on %q.\n\n"+
				"Phase 14.0A §23: `svcdoctor run --config` is a released CLI surface whose "+
				"only end-to-end validation is this suite. Excluding it from pull requests "+
				"is the whole of its exclusion; the exposure window is one merge, and the "+
				"`push: main` run is what closes it.", event)
		}
	}

	// The lane names carry the images; nothing here may name one. A second place
	// a version can be advanced from is a second place a compatibility claim can
	// silently change.
	for _, floating := range []string{":latest", "@latest", "redis:", "rabbitmq:", "valkey/"} {
		if strings.Contains(wf, floating) {
			t.Errorf("the integration workflow names an image or a tag (%q).\n\n"+
				"A lane name resolves to a digest-pinned image in a compose file the Make "+
				"target reads.", floating)
		}
	}
}

// --- delegation to the harness ----------------------------------------------

// TestTheIntegrationWorkflowDelegatesToTheHarness covers Phase 14.0A §17 and the
// "no inline YAML fixture logic" half of §12, for the hosted lanes and the
// release legs alike.
//
// The workflow owns the runner and the lane. The harness owns the fixtures, the
// certificates, the readiness loop, the principals, the assertions and the
// failure dump. A `docker run` in YAML would be a second fixture recipe that no
// local gate exercises and that drifts on its first edit.
func TestTheIntegrationWorkflowDelegatesToTheHarness(t *testing.T) {
	for _, target := range []struct{ file, job string }{
		{integrationWorkflow, "suite"},
		{releaseWorkflow, "integration"},
	} {
		t.Run(target.file, func(t *testing.T) {
			block := workflowJobBlock(t, withoutComments(readRepoFile(t, target.file)), target.job)

			// The canonical Make target, not a copy of what it does.
			if !strings.Contains(block, "run: make integration-${{ matrix.suite }}") {
				t.Error("the job does not run the canonical `make integration-<suite>`.\n\n" +
					"Phase 14.0A §12 and §7 of the phase brief: the Make targets remain the " +
					"canonical execution entry points, and the integration implementation is " +
					"never copied into YAML.")
			}

			// `make` stops at a failing target, so `integration-<suite>` does not
			// reach `<suite>-down` when the suite fails — which is exactly when a
			// fixture was left behind.
			down := strings.Index(block, "run: make ${{ matrix.suite }}-down")
			if down < 0 {
				t.Fatal("the job never tears the fixtures down")
			}
			if !strings.Contains(block[:down], "if: always()") {
				t.Error("teardown is not unconditional.\n\n" +
					"`make` stops at a failing target, so the gate's own teardown is " +
					"skipped exactly when a fixture was left running.")
			}

			// No fixture logic in YAML.
			for _, leak := range []string{"docker run", "docker compose", "gen-certs",
				"rabbitmqctl", "redis-cli", "valkey-cli", "add_user", "set_permissions"} {
				if strings.Contains(strings.ToLower(block), leak) {
					t.Errorf("the job contains fixture logic (%q); the harness owns it", leak)
				}
			}

			// Phase 14.0A §17 and ADR 0098 §2.5. A flaky suite now blocks
			// publication, and the retry that would hide it is forbidden rather
			// than discouraged: retry-to-green converts an absence of evidence
			// into an appearance of it.
			//
			// The bounded readiness loop inside each `*-up` target is explicitly
			// not a retry — it is a deterministic wait for a declared condition —
			// and it lives in the Makefile, not here.
			for _, retry := range []string{"nick-fields/retry", "for attempt in", "until make",
				"retry-on", "max_attempts", "retries:"} {
				if strings.Contains(block, retry) {
					t.Errorf("the job retries (%q); Phase 14.0A §17 and ADR 0098 §2.5 admit none", retry)
				}
			}

			// A required lane that cannot fail is decoration. ADR 0098 §2.3: the
			// gate is the dependency graph, and `continue-on-error` severs it
			// without touching an edge.
			if strings.Contains(block, "continue-on-error") {
				t.Error("the job declares continue-on-error.\n\n" +
					"ADR 0098 §2.5 forbids it outright: a lane that cannot fail blocks " +
					"nothing, and the compatibility row still claims Level 3 while a green " +
					"check appears to support it.")
			}
			if strings.Contains(block, "|| true") {
				t.Error("the job discards a failure with `|| true`")
			}
		})
	}
}

// --- concurrency ------------------------------------------------------------

// TestTheIntegrationConcurrencyCancelsOnlyPullRequests is Phase 14.0A §20.
//
// The event is in the group on purpose: without it a scheduled run on main and a
// push to main share a group and one cancels the other. And release validation
// must not be cancellable at all, which it is not because it lives in
// `release-oci.yml` under that workflow's own never-cancel group.
func TestTheIntegrationConcurrencyCancelsOnlyPullRequests(t *testing.T) {
	wf := withoutComments(readRepoFile(t, integrationWorkflow))

	if !strings.Contains(wf, "group: integration-${{ github.event_name }}-${{ github.ref }}") {
		t.Error("the integration concurrency group does not include the event.\n\n" +
			"A scheduled run on main and a push to main would share a group and cancel " +
			"each other.")
	}
	if !strings.Contains(wf, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}") {
		t.Error("cancellation is not scoped to pull requests.\n\n" +
			"A superseded commit should not keep four broker fixtures alive; a scheduled " +
			"or dispatched run should not vanish because another run started.")
	}
	if strings.Contains(wf, "cancel-in-progress: true") {
		t.Error("the integration workflow cancels unconditionally, including scheduled runs")
	}

	// Phase 14.0A §43 of the brief: a pull-request cancellation policy must never
	// reach release validation. It cannot, because release validation is a
	// different workflow with its own never-cancel group — so this asserts the
	// thing that separation is inherited from.
	release := withoutComments(readRepoFile(t, releaseWorkflow))
	header, _, _ := strings.Cut(release, "\njobs:")
	if !strings.Contains(header, "cancel-in-progress: false") {
		t.Error("release-oci.yml no longer refuses cancellation.\n\n" +
			"The release integration legs hold no concurrency group of their own and rely " +
			"on the workflow's. A release validation must not disappear because an " +
			"unrelated run started.")
	}
	if strings.Contains(workflowJobBlock(t, release, "integration"), "concurrency:") {
		t.Error("the release integration job declares its own concurrency group; " +
			"it would escape the release workflow's never-cancel guarantee")
	}
}

// --- the release gate -------------------------------------------------------

// TestEveryGatedSuiteBlocksPublication is ADR 0098 §2.3 read as a graph rather
// than as a list of names.
//
// "Gates release publication" means the publication DAG cannot reach the
// publication operation when the required result fails. A job that runs beside
// publication and blocks nothing is decoration, and the only way to tell the two
// apart is the `needs:` edges.
//
// Phase 14.0A §24 chose matrix growth over five new jobs precisely for this: the
// gate changed by one line, and the edge that carries it already existed.
func TestEveryGatedSuiteBlocksPublication(t *testing.T) {
	wf := withoutComments(readRepoFile(t, releaseWorkflow))
	needs := jobNeeds(wf)

	// Non-vacuity first: a graph this guard could not parse would pass every
	// assertion below by finding nothing to contradict.
	if len(needs) < 5 {
		t.Fatalf("parsed only %d jobs from the release workflow; this guard would be "+
			"vacuous: %v", len(needs), needs)
	}
	for _, job := range []string{"integration", "stage-and-verify", "publish", "release"} {
		if _, ok := needs[job]; !ok {
			t.Fatalf("the release workflow declares no job %q; the reachability assertions "+
				"below would be vacuous", job)
		}
	}

	// The direct edge, and the transitive one. Phase 14.0A §24 records exactly
	// which is which: the five new suites reach `stage-and-verify` directly
	// through the `integration` matrix job, and `publish` transitively via it.
	if !containsString(needs["stage-and-verify"], "integration") {
		t.Error("stage-and-verify does not name the integration matrix in `needs:`.\n\n" +
			"That edge is the whole gate. Phase 14.0A §24 added no new edge precisely " +
			"because this one already carries every matrix leg.")
	}
	for _, job := range []string{"stage-and-verify", "publish", "release"} {
		if !reaches(needs, job, "integration") {
			t.Errorf("job %q cannot be blocked by the integration suites.\n\n"+
				"ADR 0098 §2.3 defines gating as a property of this graph: publication "+
				"must be unreachable when a required compatibility result fails.", job)
		}
	}

	// The matrix that rides those edges. Read positionally, from the integration
	// job's own block, rather than from the document's first `suite:` — so a
	// future job that happens to declare a `suite:` key cannot be mistaken for
	// this one.
	integration := workflowJobBlock(t, wf, "integration")
	m := regexp.MustCompile(`(?m)^\s*suite:\s*\[(.*)\]\s*$`).FindStringSubmatch(integration)
	if m == nil {
		t.Fatal("the release integration job declares no suite matrix; every suite " +
			"assertion below would be vacuous")
	}
	got := map[string]bool{}
	for _, s := range strings.Split(m[1], ",") {
		got[strings.TrimSpace(s)] = true
	}
	for _, suite := range releaseIntegrationSuites {
		if !got[suite] {
			t.Errorf("the release integration matrix no longer runs %q (matrix: %s).\n\n"+
				"ADR 0098 §2.1: a Level-3 claim must be backed by a repeatable real-product "+
				"integration path that gates release publication. Dropping the suite that "+
				"blocked a release is the specific temptation this guard exists to refuse — "+
				"§2.5 names the four permitted responses, and removing the gate is not "+
				"among them.", suite, m[1])
		}
	}
	if len(got) != len(releaseIntegrationSuites) {
		t.Errorf("the release integration matrix runs %d suites, want exactly %d: %v",
			len(got), len(releaseIntegrationSuites), m[1])
	}

	// `fail-fast: false`, so one broken product does not hide the state of the
	// other seven. Publication is blocked either way — the job fails if any leg
	// fails — but the evidence the other legs produce is what makes a failure
	// diagnosable.
	if !strings.Contains(integration, "fail-fast: false") {
		t.Error("the release integration matrix is fail-fast.\n\n" +
			"One failing service would cancel the remaining compatibility lanes and " +
			"destroy the evidence that says whether they would have passed.")
	}

	// Linux. macOS bind mounts mask container ownership, which is how the v0.3.1
	// defect survived every local run.
	if !strings.Contains(integration, "ubuntu") {
		t.Error("the release integration suites no longer run on a Linux runner")
	}
}

// --- image pinning ----------------------------------------------------------

// TestTheGatedServiceImagesArePinnedByDigest is Phase 14.0A §7 and freeze-table
// row 13, whose digest derivation was deferred to Phase 14.0B.
//
// A tag is mutable. A Level-3 row that silently changes what it was graded
// against is not repeatable, which is the property ADR 0098 §2.1 requires and
// ADR 0095 §2.4 already stated for Kubernetes node images.
func TestTheGatedServiceImagesArePinnedByDigest(t *testing.T) {
	files := map[string][]string{
		rabbitmqCompose: rabbitmqImages,
	}
	for file, image := range gatedServiceImages {
		files[file] = []string{image}
	}

	imageLine := regexp.MustCompile(`(?m)^\s*image:\s*(\S+)\s*$`)

	for file, want := range files {
		t.Run(file, func(t *testing.T) {
			doc := readRepoFile(t, file)

			refs := imageLine.FindAllStringSubmatch(doc, -1)
			if len(refs) == 0 {
				t.Fatalf("%s declares no image; this guard would pass vacuously", file)
			}

			// Every reference, not merely the frozen ones: a service added to the
			// fixture without a digest is the gap this closes.
			seen := map[string]bool{}
			for _, ref := range refs {
				if !strings.Contains(ref[1], "@sha256:") {
					t.Errorf("%s references %q without a digest.\n\n"+
						"Phase 14.0A §7: a tag is mutable, and a graded row that silently "+
						"changes what it was graded against is not repeatable.", file, ref[1])
				}
				seen[ref[1]] = true
			}
			for _, w := range want {
				if !seen[w] {
					t.Errorf("%s no longer pins %s.\n\n"+
						"Phase 14.0A freeze-table row 14 refuses a product upgrade in Phase "+
						"14.0. Advancing a pin is a pull request that moves it, re-runs the "+
						"lane and updates docs/COMPATIBILITY.md in the same change "+
						"(ADR 0098 §2.4).", file, w)
				}
			}
		})
	}
}

// --- RabbitMQ tree neutrality -----------------------------------------------

// TestTheRabbitMQFixtureWritesNoBytecode is the Phase 14.0A.1 §4 prerequisite,
// pinned so it cannot regress.
//
// Phase 14.0A measured `make integration-rabbitmq` rewriting a *committed*
// `__pycache__` artifact — same length, different bytes, because the cache header
// carries source metadata. A gate whose own execution dirties the repository
// cannot support the cleanliness or reproducibility assertion a release gate
// exists to make, which is why RabbitMQ hosted gating was blocked on it.
//
// The fix is to stop producing the file. The cache is not test evidence and
// nothing reads it; `env/groundtruth.py`, which is the evidence, stays tracked.
func TestTheRabbitMQFixtureWritesNoBytecode(t *testing.T) {
	probe := readRepoFile(t, "test/integration/rabbitmq/env/probe.py")

	// Non-vacuity: the guard is about an import, so the import must be there.
	importAt := strings.Index(probe, "import groundtruth")
	if importAt < 0 {
		t.Fatal("probe.py no longer imports groundtruth; this guard would be vacuous " +
			"and the ground-truth fixture would no longer be consulted at all")
	}

	guardAt := strings.Index(probe, "sys.dont_write_bytecode = True")
	if guardAt < 0 {
		t.Fatal("probe.py does not disable bytecode caching.\n\n" +
			"Phase 14.0A.1 §4: RabbitMQ hosted gating is not complete until " +
			"`make integration-rabbitmq` is tree-neutral — clean tree before the suite, " +
			"clean tree after it, with no Git restoration required.")
	}
	// CPython consults the flag when the source loader would write the cache, so
	// setting it after the import would be inert.
	if guardAt > importAt {
		t.Error("probe.py sets sys.dont_write_bytecode after importing groundtruth.\n\n" +
			"CPython consults the flag at the point the loader would write the cache, " +
			"so a setting that follows the import writes the .pyc anyway.")
	}

	// The second line of defence, for an invocation path or interpreter that
	// writes one regardless.
	ignore := readRepoFile(t, ".gitignore")
	for _, rule := range []string{"__pycache__/", "*.pyc"} {
		if !strings.Contains(ignore, rule) {
			t.Errorf(".gitignore does not carry %q.\n\n"+
				"Generated bytecode is not test evidence, and one tracked copy is what "+
				"made the RabbitMQ gate dirty the repository it gates.", rule)
		}
	}
}

// --- non-vacuity ------------------------------------------------------------

// TestTheIntegrationWorkflowGuardsCanFail proves the guards above are
// load-bearing.
//
// The repository's convention: a structural guard that scans for something comes
// with a companion proving it can still fail, because a guard that silently stops
// matching looks exactly like one that passes correctly. Every detector whose
// assertion is an *absence* is exercised here against synthetic text that
// violates it.
func TestTheIntegrationWorkflowGuardsCanFail(t *testing.T) {
	t.Run("the real matrix expression is the one under test", func(t *testing.T) {
		wf := withoutComments(readRepoFile(t, integrationWorkflow))
		expression := integrationMatrixExpression(t, workflowJobBlock(t, wf, "suite"))
		if !strings.Contains(expression, "github.event_name") {
			t.Fatalf("the matrix expression names no event: %s", expression)
		}
		if !strings.Contains(expression, "fromJSON") {
			t.Fatalf("the matrix expression carries no lane set: %s", expression)
		}
	})

	t.Run("multi-target leaking onto pull requests is detected", func(t *testing.T) {
		leaked := `${{ github.event_name == 'pull_request' && ` +
			`fromJSON('[{"suite":"redis","timeout":25},{"suite":"multitarget","timeout":40}]') || ` +
			`fromJSON('[{"suite":"redis","timeout":25}]') }}`
		if _, ok := resolveIntegrationLanes(t, leaked, "pull_request")["multitarget"]; !ok {
			t.Error("the resolver did not see multi-target on a pull request; the " +
				"exclusion guard would pass on a workflow that ran it")
		}
	})

	t.Run("multi-target dropped from main is detected", func(t *testing.T) {
		dropped := `${{ github.event_name == 'pull_request' && ` +
			`fromJSON('[{"suite":"redis","timeout":25}]') || ` +
			`fromJSON('[{"suite":"redis","timeout":25}]') }}`
		if _, ok := resolveIntegrationLanes(t, dropped, "push")["multitarget"]; ok {
			t.Error("the resolver invented a multi-target lane that the expression does not declare")
		}
	})

	t.Run("a dropped service lane is detected", func(t *testing.T) {
		short := `${{ github.event_name == 'pull_request' && ` +
			`fromJSON('[{"suite":"redis","timeout":25}]') || ` +
			`fromJSON('[{"suite":"redis","timeout":25},{"suite":"multitarget","timeout":40}]') }}`
		got := resolveIntegrationLanes(t, short, "pull_request")
		if len(got) != 1 {
			t.Errorf("a pull request reduced to one lane resolved to %v; the lane-set "+
				"assertion would not have caught it", got)
		}
	})

	t.Run("a changed timeout is detected", func(t *testing.T) {
		inflated := `${{ github.event_name == 'pull_request' && ` +
			`fromJSON('[{"suite":"redis","timeout":90}]') || ` +
			`fromJSON('[{"suite":"redis","timeout":25}]') }}`
		if got := resolveIntegrationLanes(t, inflated, "pull_request")["redis"]; got != 90 {
			t.Errorf("the resolver read timeout %d from an inflated lane; the frozen "+
				"budget assertion would not have caught it", got)
		}
	})

	t.Run("a missing timeout is a failure rather than a default", func(t *testing.T) {
		// A lane with no timeout would silently inherit GitHub's 360-minute
		// default and stop detecting a hang. resolveIntegrationLanes calls
		// t.Fatalf on it, so this asserts the shape the parser refuses rather
		// than calling it — a t.Fatalf here would fail this test.
		var entries []struct {
			Suite   string `json:"suite"`
			Timeout int    `json:"timeout"`
		}
		if err := json.Unmarshal([]byte(`[{"suite":"redis"}]`), &entries); err != nil {
			t.Fatalf("fixture did not parse: %v", err)
		}
		if entries[0].Timeout != 0 {
			t.Error("a lane with no timeout did not decode as zero, so the parser's " +
				"refusal would never fire")
		}
	})

	t.Run("the job-block extractor is positional", func(t *testing.T) {
		doc := "jobs:\n  first:\n    runs-on: a\n  second:\n    runs-on: b\n"
		if got := workflowJobBlock(t, doc, "second"); !strings.Contains(got, "runs-on: b") ||
			strings.Contains(got, "runs-on: a") {
			t.Errorf("extractor returned the wrong block: %q", got)
		}
	})

	t.Run("a severed release edge is detected", func(t *testing.T) {
		// The leading newline is load-bearing: jobNeeds cuts the document at
		// "\njobs:\n", so a fixture that begins at "jobs:" parses to an empty
		// graph and every reachability assertion below it passes vacuously.
		doc := "\njobs:\n  integration:\n    runs-on: a\n  publish:\n    needs: [identity, archives]\n"
		if len(jobNeeds(doc)) != 2 {
			t.Fatalf("the fixture did not parse into two jobs: %v", jobNeeds(doc))
		}
		if reaches(jobNeeds(doc), "publish", "integration") {
			t.Error("reaches() reports a dependency that is not declared")
		}
	})

	t.Run("a transitive-only release edge is distinguished from a direct one", func(t *testing.T) {
		doc := "\njobs:\n  integration:\n    runs-on: a\n  stage-and-verify:\n" +
			"    needs: [integration]\n  publish:\n    needs: [stage-and-verify]\n"
		needs := jobNeeds(doc)
		if len(needs) != 3 {
			t.Fatalf("the fixture did not parse into three jobs: %v", needs)
		}
		if !reaches(needs, "publish", "integration") {
			t.Error("reaches() missed a transitive dependency")
		}
		if containsString(needs["publish"], "integration") {
			t.Error("containsString reported a direct edge that is only transitive; " +
				"the direct-edge assertion would pass on a severed graph")
		}
	})

	t.Run("the release suite matrix regex reads a list", func(t *testing.T) {
		m := regexp.MustCompile(`(?m)^\s*suite:\s*\[(.*)\]\s*$`).
			FindStringSubmatch("      matrix:\n        suite: [postgres, kafka]\n")
		if m == nil || strings.TrimSpace(m[1]) != "postgres, kafka" {
			t.Errorf("the matrix regex did not read the list: %v", m)
		}
	})

	t.Run("an undigested image is detected", func(t *testing.T) {
		refs := regexp.MustCompile(`(?m)^\s*image:\s*(\S+)\s*$`).
			FindAllStringSubmatch("services:\n  a:\n    image: redis:8.2.1-alpine\n", -1)
		if len(refs) != 1 {
			t.Fatalf("the image regex found %d references, want 1", len(refs))
		}
		if strings.Contains(refs[0][1], "@sha256:") {
			t.Error("the digest check would accept a bare tag")
		}
	})

	t.Run("the supply-chain glob covers this workflow", func(t *testing.T) {
		// TestUX22TheSupplyChainPinningIsRecorded globs .github/workflows/*.yml,
		// so the file's location is what puts it under that guard. If it ever
		// moves, this says so.
		if !strings.HasPrefix(integrationWorkflow, ".github/workflows/") ||
			!strings.HasSuffix(integrationWorkflow, ".yml") {
			t.Errorf("%s is outside the glob TestUX22TheSupplyChainPinningIsRecorded "+
				"scans, so its actions would be unpinned and unnoticed", integrationWorkflow)
		}
	})

	t.Run("every frozen release suite has a Make target", func(t *testing.T) {
		// The matrix maps `suite` onto `make integration-<suite>` and
		// `make <suite>-down`. A matrix entry naming a target that does not exist
		// would fail only on a release tag, which is the worst place to find out.
		makefile := readRepoFile(t, "Makefile")
		for _, suite := range releaseIntegrationSuites {
			for _, target := range []string{
				fmt.Sprintf("\nintegration-%s:", suite),
				fmt.Sprintf("\n%s-down:", suite),
			} {
				if !strings.Contains(makefile, target) {
					t.Errorf("the Makefile declares no %q target, but the release matrix "+
						"names suite %q", strings.TrimSpace(target), suite)
				}
			}
		}
	})
}
