package cli

import (
	"regexp"
	"strings"
	"testing"
)

// Structural guards for the Kubernetes CI and release gate.
//
// ADR 0095 is the contract. These tests protect its architecture rather than its
// bytes: which events run which lanes, what authority the workflow holds, what it
// is pinned to, and that publication cannot start without it. A guard that
// compared the file to a golden copy would fail on every comment edit and catch
// nothing a reviewer would not already see.
//
// # Why the file is inspected as text
//
// Every other workflow guard in this repository reads its workflow as a string,
// and these join them rather than introducing a second convention — and a YAML
// decoder in this package would put the module ADR 0071 §3.3 confines to
// `internal/fleet/config` one import away from the CLI.
//
// # The one thing text cannot prove
//
// GitHub renders a matrix job's status check from the job's `name`. That
// `name: ${{ matrix.lane }}` under `name: Kubernetes` produces the check
// `Kubernetes / current` is a statement about GitHub's runtime, not about this
// file, and it is recorded as a hosted-run assertion (Phase 12.2B H2) rather than
// asserted here. What is asserted here is everything that determines it.
const (
	kubernetesWorkflow = ".github/workflows/kubernetes.yml"
	kubeToolsScript    = "scripts/install-kube-tools.sh"
)

// The two frozen lanes, by immutable digest. ADR 0095 §2.4 and §4 of the Phase
// 12.2A record. They live in the Makefile, which is what the harness reads; the
// workflow names a lane and never an image, so these guard the values the lane
// name resolves to.
const (
	currentNodeImage = "kindest/node:v1.34.0@sha256:" +
		"7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a"
	olderNodeImage = "kindest/node:v1.31.12@sha256:" +
		"0f5cc49c5e73c0c2bb6e2df56e7df189240d83cf94edfa30946482eb08ec57d2"

	frozenKindVersion    = "v0.30.0"
	frozenKubectlVersion = "v1.34.0"
	frozenKubectlSHA256  = "cfda68cba5848bc3b6c6135ae2f20ba2c78de20059f68789c090166d6abc3e2c"
)

// workflowJobBlock returns one top-level job's block: everything from its
// two-space key to the next one.
//
// Positional, because every job's inner keys look alike and searching the whole
// document for `runs-on` always finds the first job's.
func workflowJobBlock(t *testing.T, doc, job string) string {
	t.Helper()

	_, block, found := strings.Cut(doc, "\n  "+job+":\n")
	if !found {
		t.Fatalf("workflow declares no job %q", job)
	}
	if end := regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:`).FindStringIndex(block); end != nil {
		block = block[:end[0]]
	}
	return block
}

// --- triggers ---------------------------------------------------------------

// TestTheKubernetesWorkflowTriggersOnExactlyTheFrozenEvents is KWF-01 to KWF-06
// and KWF-26.
//
// The trust boundary is the half of this that matters most. `pull_request_target`
// would run a fork's own code with the base repository's token and secret access,
// and this lane executes repository code inside a container runtime — the worst
// possible place for it.
func TestTheKubernetesWorkflowTriggersOnExactlyTheFrozenEvents(t *testing.T) {
	raw := readRepoFile(t, kubernetesWorkflow) // KWF-01
	wf := withoutComments(raw)

	header, _, found := strings.Cut(wf, "\njobs:")
	if !found {
		t.Fatal("the Kubernetes workflow has no jobs block")
	}

	for _, want := range []struct{ directive, why string }{
		{"\n  pull_request:", "KWF-02: the regression gate runs on pull requests"},
		{"\n  push:", "KWF-03: post-merge confirmation on main"},
		{"branches: [main]", "KWF-03: push is scoped to main"},
		{"- cron: '17 4 * * 1'", "KWF-04: the weekly compatibility lane"},
		{"\n  workflow_dispatch:", "KWF-05: on-demand full matrix"},
	} {
		if !strings.Contains(header, want.directive) {
			t.Errorf("the Kubernetes workflow header is missing %q (%s)", want.directive, want.why)
		}
	}

	// KWF-06. Checked against the raw file, not the comment-stripped one: the
	// prose above the triggers explains why the trigger is refused, and a guard
	// that only read directives would pass while the directive was present in a
	// commented-out block someone meant to restore.
	if strings.Contains(wf, "pull_request_target") {
		t.Error("the Kubernetes workflow uses pull_request_target.\n\n" +
			"ADR 0095 §2.5 refuses it outright. This lane runs the pull request's own " +
			"code inside a container runtime; pull_request_target would hand that code " +
			"the base repository's token and secrets.")
	}

	// KWF-05, the other half: a dispatch input could name a Kubernetes version or
	// an image, which would let a manual run manufacture evidence for a version
	// nobody graded (ADR 0095 §2.3).
	if strings.Contains(header, "workflow_dispatch:\n    inputs:") {
		t.Error("workflow_dispatch declares inputs.\n\n" +
			"ADR 0095 §2.3: a dispatched run selects lanes from the frozen matrix and " +
			"accepts no image reference, so it cannot create a compatibility claim.")
	}

	// KWF-26. Path filtering was refused in Phase 12.2A §12 — a required check
	// that does not run leaves a pull request pending rather than green.
	for _, filter := range []string{"paths:", "paths-ignore:"} {
		if strings.Contains(header, filter) {
			t.Errorf("the Kubernetes workflow declares %q.\n\n"+
				"Phase 12.2A §12 refused path filtering: Kubernetes diagnosis sits on the "+
				"generic core, so a safe allowlist would name nearly the whole tree, and a "+
				"skipped required check leaves a pull request pending.", filter)
		}
	}
}

// --- authority -------------------------------------------------------------

// TestTheKubernetesWorkflowHoldsNoAuthorityItDoesNotNeed is KWF-07, KWF-19 to
// KWF-22.
//
// The cluster is created on the runner and destroyed there. Nothing in this lane
// writes to the repository, publishes a package, holds a signing identity or
// needs a secret — and a lane that ever needs one has stopped being
// self-contained, which ADR 0095 §2.5 makes a new decision rather than an edit.
func TestTheKubernetesWorkflowHoldsNoAuthorityItDoesNotNeed(t *testing.T) {
	wf := withoutComments(readRepoFile(t, kubernetesWorkflow))
	header, _, _ := strings.Cut(wf, "\njobs:")

	// KWF-07.
	if !strings.Contains(header, "permissions:\n  contents: read") {
		t.Error("the Kubernetes workflow does not default to contents: read")
	}
	for _, escalation := range []string{
		"contents: write", "packages: write", "id-token: write",
		"actions: write", "pull-requests: write", "attestations: write",
	} {
		if strings.Contains(wf, escalation) {
			t.Errorf("the Kubernetes workflow requests %q; nothing in this lane needs it", escalation)
		}
	}

	// KWF-19. `secrets.` is the whole context, so this catches an inherited
	// secret as well as a named one.
	if strings.Contains(wf, "secrets.") || strings.Contains(wf, "secrets:") {
		t.Error("the Kubernetes workflow references a repository secret.\n\n" +
			"ADR 0095 §2.5: none is used and none is needed. Every credential this lane " +
			"touches is generated on the runner and destroyed with the cluster.")
	}

	// KWF-20. The lane handles kubeconfigs, ServiceAccount tokens and client
	// keys; an upload step is a second exfiltration surface for information the
	// log already carries.
	if strings.Contains(wf, "upload-artifact") {
		t.Error("the Kubernetes workflow uploads an artifact; ADR 0095 §2.7 admits none")
	}

	// KWF-21. Tool installation goes through the Go module proxy and a recorded
	// checksum, never a piped shell script.
	//
	// Matched as a pipeline rather than as the literal `curl | sh`: a real one
	// carries flags and a URL in between, so the idiom everyone quotes is the one
	// form that never appears. Found by mutation — the first version of this
	// guard let `curl -sSL https://… | sh` through.
	if pipeIntoShell.MatchString(wf) {
		t.Error("the Kubernetes workflow pipes a download into a shell.\n\n" +
			"ADR 0095 §2.6: kind comes from the Go module proxy and kubectl from a " +
			"recorded checksum, because this lane is a release gate.")
	}

	// KWF-22 and KWF-30. Only the two actions this repository already carries,
	// each by the digest it already carries — so no digest had to be invented for
	// this file, which is the trap UX-S16-b recorded. The repository-wide
	// TestUX22TheSupplyChainPinningIsRecorded globs every workflow and therefore
	// already covers this one; this is the narrower statement that it introduces
	// no new action at all.
	uses := regexp.MustCompile(`uses:\s*(\S+)`).FindAllStringSubmatch(wf, -1)
	if len(uses) == 0 {
		t.Fatal("the Kubernetes workflow references no action; this guard would pass vacuously")
	}
	allowed := map[string]bool{
		"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1": true,
		"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e": true,
	}
	for _, u := range uses {
		if !allowed[u[1]] {
			t.Errorf("the Kubernetes workflow uses %q.\n\n"+
				"ADR 0095 §2.6 admits only the two actions this repository already pins. "+
				"kind is installed through the Go module proxy and kubectl by recorded "+
				"checksum, so no setup-kind action and no new digest is needed.", u[1])
		}
	}
}

// --- runner, budget and toolchain -------------------------------------------

// TestTheKubernetesLaneRunsOnTheFrozenRunnerAndBudget is KWF-08 to KWF-10 and
// KWF-23.
func TestTheKubernetesLaneRunsOnTheFrozenRunnerAndBudget(t *testing.T) {
	wf := withoutComments(readRepoFile(t, kubernetesWorkflow))
	lane := workflowJobBlock(t, wf, "lane")

	// KWF-08. An explicit generation pin: this is the repository's most
	// environment-sensitive lane, and ubuntu-latest rolls to the next LTS on its
	// own. It is not supply-chain immutable and no document may say it is.
	if !strings.Contains(lane, "runs-on: ubuntu-24.04") {
		t.Error("the Kubernetes lane does not run on ubuntu-24.04")
	}
	if strings.Contains(lane, "ubuntu-latest") {
		t.Error("the Kubernetes lane runs on ubuntu-latest; ADR 0095 §2.6 pins the runner generation")
	}

	// KWF-09. Deliberately above the harness's own `go test -timeout 30m`: a
	// shorter job budget would kill the job before the Go test timeout fires and
	// destroy the goroutine dump, which is the most useful thing a hang produces.
	if !strings.Contains(lane, "timeout-minutes: 40") {
		t.Error("the Kubernetes lane does not declare timeout-minutes: 40")
	}
	makefile := readRepoFile(t, "Makefile")
	if !strings.Contains(makefile, "-timeout 30m") {
		t.Error("the Kubernetes suite no longer runs under a 30m go test timeout; " +
			"the 40-minute job budget was chosen to sit above it and must be re-derived")
	}

	// KWF-10. go.mod is the single source of truth for the toolchain.
	if !strings.Contains(lane, "go-version-file: go.mod") {
		t.Error("the Kubernetes lane does not take its Go version from go.mod")
	}
	if regexp.MustCompile(`go-version:\s*'?1\.\d`).MatchString(lane) {
		t.Error("the Kubernetes lane hardcodes a Go version.\n\n" +
			"go.mod is authoritative. A second version here is a second authority " +
			"that drifts from it the first time either is edited.")
	}

	// KWF-23. The two halves of the stable check identity that live in this file.
	// GitHub composes `<workflow name> / <job name>`; that it renders exactly
	// `Kubernetes / current` is a hosted-run assertion.
	if !strings.HasPrefix(strings.TrimSpace(wf), "name: Kubernetes\n") {
		t.Error("the workflow is not named `Kubernetes`; the required-check identity " +
			"`Kubernetes / current` is composed from it")
	}
	if !strings.Contains(lane, "name: ${{ matrix.lane }}") {
		t.Error("the Kubernetes lane does not name itself from the matrix.\n\n" +
			"Without an explicit name GitHub appends the matrix values in its own " +
			"format, and the required-check identity stops being predictable.")
	}
	// No version in the job name: a check called `Kubernetes (v1.34.0)` would
	// have to be reconfigured in branch protection every time the lane advanced.
	if regexp.MustCompile(`name:.*v1\.\d+\.\d+`).MatchString(lane) {
		t.Error("the Kubernetes job name carries a Kubernetes version; " +
			"branch protection would need reconfiguring on every version bump")
	}
}

// --- the event-dependent matrix ---------------------------------------------

// laneMatrixExpression returns the matrix expression the lane job declares.
func laneMatrixExpression(t *testing.T, lane string) string {
	t.Helper()

	m := regexp.MustCompile(`(?m)^\s*lane:\s*(\$\{\{.*\}\})\s*$`).FindStringSubmatch(lane)
	if m == nil {
		t.Fatal("the Kubernetes lane declares no matrix expression on a single line.\n\n" +
			"A folded block scalar keeps the newlines of its continuation lines, so the " +
			"expression would reach GitHub with line breaks inside it.")
	}
	return m[1]
}

// resolveLanes evaluates the frozen matrix expression for one event name.
//
// It implements exactly one expression shape — `COND && fromJSON(A) || fromJSON(B)`
// where COND is a disjunction of `github.event_name == '...'` — and fails on
// anything else, so a rewritten expression is a failing test rather than a
// silently unevaluated one.
//
// The semantics it assumes are GitHub's documented ones: `&&` yields its right
// operand when the left is truthy, `||` yields its left operand when that is
// truthy, and a non-empty array is truthy. That the runtime agrees is confirmed
// by the hosted run, not by this test.
func resolveLanes(t *testing.T, expression, event string) []string {
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
	lanes := regexp.MustCompile(`"([a-z]+)"`).FindAllStringSubmatch(branch, -1)
	if len(lanes) == 0 {
		t.Fatalf("branch %q for event %q names no lane", strings.TrimSpace(branch), event)
	}
	out := make([]string, 0, len(lanes))
	for _, l := range lanes {
		out = append(out, l[1])
	}
	return out
}

// TestTheKubernetesMatrixIsEventDependentExactlyAsFrozen is KWF-12, KWF-15 and
// KWF-16.
//
// This is the property most easily broken by a well-meaning edit, and the one a
// reviewer is least likely to evaluate in their head. ADR 0095 §2.1: both 12.1D
// lanes ran the identical binary and produced identical results, so the older
// lane carries compatibility signal rather than regression signal — which is why
// it belongs on the schedule and the release, and not on every pull request.
func TestTheKubernetesMatrixIsEventDependentExactlyAsFrozen(t *testing.T) {
	wf := withoutComments(readRepoFile(t, kubernetesWorkflow))
	expression := laneMatrixExpression(t, workflowJobBlock(t, wf, "lane"))

	for _, tc := range []struct {
		event string
		want  []string
	}{
		{"pull_request", []string{"current"}},               // KWF-15
		{"push", []string{"current"}},                       // KWF-15
		{"schedule", []string{"current", "older"}},          // KWF-16
		{"workflow_dispatch", []string{"current", "older"}}, // KWF-16
	} {
		t.Run(tc.event, func(t *testing.T) {
			got := resolveLanes(t, expression, tc.event)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("event %q resolves to lanes %v, want %v", tc.event, got, tc.want)
			}
		})
	}

	// KWF-12. The lane names carry the images; nothing here may name one.
	if strings.Contains(wf, "kindest/node") {
		t.Error("the Kubernetes workflow names a node image.\n\n" +
			"A lane name resolves to a digest-pinned image in the Makefile. Naming one " +
			"here creates a second place a version can be advanced from.")
	}
	if strings.Contains(wf, ":latest") || strings.Contains(wf, "@latest") {
		t.Error("the Kubernetes workflow references a floating `latest`")
	}
}

// --- the pins ---------------------------------------------------------------

// TestTheKubernetesLanesArePinnedByDigest is KWF-11, KWF-13, KWF-14 and KWF-29.
//
// Every input to this gate is pinned, and the two that are not pinned in the
// workflow are pinned in the two files it calls: the Makefile holds the node
// images and the installer holds the tools.
func TestTheKubernetesLanesArePinnedByDigest(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")

	// KWF-13 and KWF-14. The assignments are column-aligned in the Makefile, so
	// the separator is matched rather than spelled.
	for _, want := range []struct{ lane, image string }{
		{"current", currentNodeImage},
		{"older", olderNodeImage},
	} {
		assignment := regexp.MustCompile(
			`(?m)^KIND_NODE_` + want.lane + `\s*:=\s*` + regexp.QuoteMeta(want.image) + `\s*$`)
		if !assignment.MatchString(makefile) {
			t.Errorf("the %s lane is not pinned to %s.\n\n"+
				"ADR 0095 §2.4: both lanes are pinned by image digest, taken from the "+
				"pinned kind release's own notes. Advancing one is a pull request that "+
				"re-runs both lanes and updates docs/COMPATIBILITY.md in the same change.",
				want.lane, want.image)
		}
	}

	script := readRepoFile(t, kubeToolsScript)

	// KWF-11, and the drift guard between the installer and the Makefile's own
	// "kind is not installed" hint. Two files naming a version is fine; two files
	// naming *different* versions is the defect.
	if !strings.Contains(script, "KIND_VERSION='"+frozenKindVersion+"'") {
		t.Errorf("%s does not pin kind to %s", kubeToolsScript, frozenKindVersion)
	}
	if !strings.Contains(makefile, "sigs.k8s.io/kind@"+frozenKindVersion) {
		t.Errorf("the Makefile's kind install hint no longer names %s; it and %s must "+
			"advance together", frozenKindVersion, kubeToolsScript)
	}

	// KWF-29. The version and the digest, and the digest is the point: Phase
	// 12.2A refused to write one it could not verify, and 12.2B obtained the
	// artifact and compared its SHA-256 and SHA-512 against the publisher's own.
	if !strings.Contains(script, "KUBECTL_VERSION='"+frozenKubectlVersion+"'") {
		t.Errorf("%s does not pin kubectl to %s", kubeToolsScript, frozenKubectlVersion)
	}
	if !strings.Contains(script, "KUBECTL_SHA256='"+frozenKubectlSHA256+"'") {
		t.Errorf("%s does not carry the verified kubectl SHA-256.\n\n"+
			"want %s\n\nADR 0095 §2.6: kubectl is pinned by version AND digest, and the "+
			"runner's ambient copy is refused because it is an unpinned input to a "+
			"release gate.", kubeToolsScript, frozenKubectlSHA256)
	}
}

// TestTheKubeToolInstallerFailsClosed is the rest of KWF-29 and KWF-21.
//
// A checksum that is computed and then ignored is worse than no checksum, so the
// comparison has to reject rather than warn — and the script must not trace,
// because the gate it bootstraps handles kubeconfigs and tokens.
func TestTheKubeToolInstallerFailsClosed(t *testing.T) {
	raw := readRepoFile(t, kubeToolsScript)

	// Directives only. The script explains at length why it does not trace, and
	// the sentence that says so contains the very string a naive scan looks for —
	// so a guard reading the whole file reports tracing on a script that has
	// none, and then reports nothing when tracing is added. That is the same
	// defect TestTheReleaseWorkflowUsesMinimalPermissions records finding "by
	// mutation, not by review", and it was found here the same way.
	script := withoutShellComments(raw)

	if !strings.Contains(script, "set -eu") {
		t.Errorf("%s does not use strict shell mode", kubeToolsScript)
	}
	if regexp.MustCompile(`(?m)^\s*set\s+-\S*x`).MatchString(script) {
		t.Errorf("%s enables shell tracing.\n\n"+
			"ADR 0095 §2.7 forbids it around anything credential-adjacent, and this "+
			"script bootstraps the gate that mints ServiceAccount tokens.", kubeToolsScript)
	}

	// The verification must guard an exit, not a message.
	if !strings.Contains(script, `if [ "$actual" != "$KUBECTL_SHA256" ]; then`) {
		t.Errorf("%s does not compare the computed digest against the pinned one "+
			"in a form that can refuse", kubeToolsScript)
	}
	if !strings.Contains(script, "refusing to install") {
		t.Errorf("%s does not refuse on a checksum mismatch", kubeToolsScript)
	}

	// The download must precede the comparison, and the install must follow it.
	// Matched on the operands rather than on a fragment of the `if` line, which
	// is how the first version of this check compared two indexes of which one
	// was always -1 and therefore always "passed" the wrong way.
	download := strings.Index(script, `--output "$tmp/kubectl"`)
	verify := strings.Index(script, `!= "$KUBECTL_SHA256"`)
	install := strings.Index(script, `mv "$tmp/kubectl"`)
	switch {
	case download < 0 || verify < 0 || install < 0:
		t.Errorf("%s no longer downloads, verifies and installs kubectl in three "+
			"identifiable steps (download=%d verify=%d install=%d)",
			kubeToolsScript, download, verify, install)
	case download >= verify || verify >= install:
		t.Errorf("%s does not download, then verify, then install: "+
			"download=%d verify=%d install=%d", kubeToolsScript, download, verify, install)
	}

	// KWF-21, in the file that actually downloads something.
	if pipeIntoShell.MatchString(script) {
		t.Errorf("%s pipes a download into a shell", kubeToolsScript)
	}

	// The ambient kubectl is refused by never being consulted: the script always
	// installs its own. A `command -v kubectl` short-circuit would silently
	// accept whatever the runner image ships.
	if regexp.MustCompile(`command -v kubectl.*(&&|\|\|)\s*(exit|return)`).MatchString(script) {
		t.Errorf("%s short-circuits on an existing kubectl; ADR 0095 §2.6 refuses the "+
			"runner's ambient copy", kubeToolsScript)
	}
}

// pipeIntoShell matches a pipeline whose right-hand side is a shell.
//
// The literal `curl | sh` is the idiom people write about and almost never the
// one they write: a real one carries flags and a URL in between. The first
// version of this guard looked for the idiom and let
// `curl -sSL https://… | sh` through, which is the form that would actually
// appear. The word boundary keeps `| shasum` from matching.
var pipeIntoShell = regexp.MustCompile(`\|\s*(sh|bash|zsh|dash)\b`)

// withoutShellComments drops whole-line shell comments.
//
// Line-leading only: that is every comment in the scripts this file reads, and a
// naive trailing-comment strip would cut inside a quoted `#`.
func withoutShellComments(doc string) string {
	var out []string
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// --- delegation to the harness ----------------------------------------------

// TestTheKubernetesWorkflowDelegatesToTheHarness is KWF-17, KWF-18, KWF-27 and
// KWF-28.
//
// The workflow owns the runner and the lane. The harness owns the cluster, the
// binaries, the fixtures, the waits, the assertions and the failure dump. A
// `kubectl apply` in YAML would be a second fixture recipe that no local gate
// exercises.
func TestTheKubernetesWorkflowDelegatesToTheHarness(t *testing.T) {
	for _, target := range []struct{ file, job string }{
		{kubernetesWorkflow, "lane"},
		{releaseWorkflow, "kubernetes"},
	} {
		t.Run(target.file, func(t *testing.T) {
			block := workflowJobBlock(t, withoutComments(readRepoFile(t, target.file)), target.job)

			// KWF-17.
			if !strings.Contains(block, "run: make integration-kubernetes") {
				t.Error("the job does not run the canonical `make integration-kubernetes`")
			}
			if !strings.Contains(block, "KUBERNETES_LANE: ${{ matrix.lane }}") {
				t.Error("the job does not select its lane through KUBERNETES_LANE")
			}

			// KWF-18. `make` stops at a failing target, so integration-kubernetes
			// does not reach kubernetes-down when the suite fails.
			down := strings.Index(block, "run: make kubernetes-down")
			if down < 0 {
				t.Fatal("the job never tears the cluster down")
			}
			if !strings.Contains(block[:down], "if: always()") {
				t.Error("teardown is not unconditional.\n\n" +
					"ADR 0095 §2.9: `make` stops at a failing target, so the gate's own " +
					"teardown is skipped exactly when a cluster was left behind.")
			}

			// No fixture logic in YAML.
			for _, leak := range []string{"kubectl apply", "kubectl create", "kind create cluster",
				"serviceaccount", "endpointslice"} {
				if strings.Contains(strings.ToLower(block), leak) {
					t.Errorf("the job contains fixture logic (%q); the harness owns it", leak)
				}
			}

			// KWF-27. A repeatable infrastructure failure is classified and fixed
			// in the harness. A retry loop over an RBAC, EndpointSlice, readiness
			// or pagination race makes that class of bug permanently invisible.
			for _, retry := range []string{"nick-fields/retry", "for attempt in", "until make",
				"retry-on", "max_attempts"} {
				if strings.Contains(block, retry) {
					t.Errorf("the job retries (%q); ADR 0095 §2.8 admits none", retry)
				}
			}

			// KWF-28. A missing prerequisite fails. `continue-on-error` on the gate
			// would turn an unusable runtime into a green run.
			if strings.Contains(block, "continue-on-error") {
				t.Error("the job declares continue-on-error; a skipped mandatory gate is not a pass")
			}
			if strings.Contains(block, "|| true") {
				t.Error("the job discards a failure with `|| true`")
			}
		})
	}
}

// --- concurrency ------------------------------------------------------------

// TestTheKubernetesConcurrencyCancelsOnlyPullRequests is KWF-24 and KWF-25.
//
// The event is in the group on purpose: without it a scheduled run on main and a
// push to main share a group and one cancels the other. And the release gate must
// not be cancellable at all, which it is not because it lives in `release-oci.yml`
// under that workflow's own never-cancel group.
func TestTheKubernetesConcurrencyCancelsOnlyPullRequests(t *testing.T) {
	wf := withoutComments(readRepoFile(t, kubernetesWorkflow))

	if !strings.Contains(wf, "group: kubernetes-${{ github.event_name }}-${{ github.ref }}") {
		t.Error("the Kubernetes concurrency group does not include the event.\n\n" +
			"A scheduled run on main and a push to main would share a group and cancel " +
			"each other.")
	}
	// KWF-24 and KWF-25 in one directive: cancellation is an expression that is
	// true for exactly one event.
	if !strings.Contains(wf, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}") {
		t.Error("cancellation is not scoped to pull requests.\n\n" +
			"A superseded commit should not keep a cluster alive; a scheduled or " +
			"dispatched compatibility run should not vanish because another run started.")
	}
	if strings.Contains(wf, "cancel-in-progress: true") {
		t.Error("the Kubernetes workflow cancels unconditionally, including scheduled runs")
	}

	// The release gate's non-cancellability, stated where a future edit would
	// look for it. It is inherited rather than declared, so this asserts the
	// thing it is inherited from.
	release := withoutComments(readRepoFile(t, releaseWorkflow))
	header, _, _ := strings.Cut(release, "\njobs:")
	if !strings.Contains(header, "cancel-in-progress: false") {
		t.Error("release-oci.yml no longer refuses cancellation.\n\n" +
			"The Kubernetes release gate holds no concurrency group of its own and " +
			"relies on the workflow's. A release validation must not disappear because " +
			"an unrelated run started.")
	}
	if strings.Contains(workflowJobBlock(t, release, "kubernetes"), "concurrency:") {
		t.Error("the Kubernetes release job declares its own concurrency group; " +
			"it would escape the release workflow's never-cancel guarantee")
	}
}

// --- the release gate -------------------------------------------------------

// TestKubernetesPublicationCannotStartBeforeBothLanes is the release half of
// ADR 0095 §2.2, and the reason the gate is a job rather than a workflow.
//
// GitHub cannot make one workflow depend on another's recent green run, and
// "green last Tuesday" is a statement about a different commit. `job.needs` is
// the only enforcement there is.
func TestKubernetesPublicationCannotStartBeforeBothLanes(t *testing.T) {
	wf := withoutComments(readRepoFile(t, releaseWorkflow))

	needs := jobNeeds(wf)
	for _, job := range []string{"stage-and-verify", "publish"} {
		if !reaches(needs, job, "kubernetes") {
			t.Errorf("job %q does not depend on the Kubernetes gate.\n\n"+
				"ADR 0095 §2.2: a release makes a compatibility claim, so publication "+
				"must not be able to start until both graded Kubernetes versions have "+
				"passed on this commit.", job)
		}
		// Directly, not only transitively. Phase 12.2A froze both edges so that
		// re-ordering the graph cannot quietly drop one.
		if !containsString(needs[job], "kubernetes") {
			t.Errorf("job %q reaches the Kubernetes gate only transitively; "+
				"Phase 12.2A froze the direct edge on both jobs", job)
		}
	}

	// A release re-proves both graded versions, not just the current one.
	kubernetes := workflowJobBlock(t, wf, "kubernetes")
	if !strings.Contains(kubernetes, "lane: [current, older]") {
		t.Error("the release Kubernetes matrix does not run both lanes")
	}
	// The matrix key is `lane` and this job follows `integration`, because
	// TestOCIPublicationCannotStartBeforeLinuxIntegration finds the suite matrix
	// with the document's first `suite:`. Phase 12.2A measured this and froze it.
	if strings.Contains(kubernetes, "suite:") {
		t.Error("the Kubernetes release job uses the key `suite:`.\n\n" +
			"TestOCIPublicationCannotStartBeforeLinuxIntegration cuts the document at " +
			"its first `suite:` to find the integration matrix. The key must be `lane`.")
	}
	if strings.Index(wf, "\n  kubernetes:") < strings.Index(wf, "\n  integration:") {
		t.Error("the Kubernetes job precedes the integration job.\n\n" +
			"The same guard would then read this job's matrix as the integration matrix.")
	}

	// The existing gate is untouched. Adding a gate must never relax one.
	for _, job := range []string{"stage-and-verify", "publish"} {
		if !reaches(needs, job, "integration") {
			t.Errorf("job %q no longer depends on the integration suites; "+
				"the Kubernetes gate is an addition, not a replacement", job)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// --- non-vacuity ------------------------------------------------------------

// TestTheKubernetesWorkflowGuardsCanFail proves the guards above are
// load-bearing.
//
// The repository's convention: a structural guard that scans for something comes
// with a companion proving it can still fail, because a guard that silently stops
// matching looks exactly like one that passes correctly.
func TestTheKubernetesWorkflowGuardsCanFail(t *testing.T) {
	t.Run("the job-block extractor is positional", func(t *testing.T) {
		doc := "jobs:\n  first:\n    runs-on: a\n  second:\n    runs-on: b\n"
		if got := workflowJobBlock(t, doc, "second"); !strings.Contains(got, "runs-on: b") ||
			strings.Contains(got, "runs-on: a") {
			t.Errorf("extractor returned the wrong block: %q", got)
		}
	})

	t.Run("a widened condition is detected", func(t *testing.T) {
		widened := "${{ (github.event_name == 'schedule' || github.event_name == 'pull_request')" +
			` && fromJSON('["current","older"]') || fromJSON('["current"]') }}`
		if got := resolveLanes(t, widened, "pull_request"); len(got) != 2 {
			t.Errorf("a pull request widened to both lanes resolved to %v; the evaluator "+
				"would not have caught it", got)
		}
	})

	t.Run("a narrowed schedule is detected", func(t *testing.T) {
		narrowed := "${{ (github.event_name == 'workflow_dispatch')" +
			` && fromJSON('["current","older"]') || fromJSON('["current"]') }}`
		if got := resolveLanes(t, narrowed, "schedule"); len(got) != 1 {
			t.Errorf("a schedule dropped to one lane resolved to %v", got)
		}
	})

	t.Run("the real expression is the one under test", func(t *testing.T) {
		wf := withoutComments(readRepoFile(t, kubernetesWorkflow))
		expression := laneMatrixExpression(t, workflowJobBlock(t, wf, "lane"))
		if !strings.Contains(expression, "github.event_name") {
			t.Fatalf("the matrix expression names no event: %s", expression)
		}
	})

	t.Run("a missing release edge is detected", func(t *testing.T) {
		doc := "jobs:\n  publish:\n    needs: [identity, archives]\n"
		if reaches(jobNeeds(doc), "publish", "kubernetes") {
			t.Error("reaches() reports a dependency that is not declared")
		}
	})

	t.Run("the supply-chain glob covers this workflow", func(t *testing.T) {
		// KWF-30. TestUX22TheSupplyChainPinningIsRecorded globs
		// .github/workflows/*.yml, so the file's location is what puts it under
		// that guard. If it ever moves, this says so.
		if !strings.HasPrefix(kubernetesWorkflow, ".github/workflows/") ||
			!strings.HasSuffix(kubernetesWorkflow, ".yml") {
			t.Errorf("%s is outside the glob TestUX22TheSupplyChainPinningIsRecorded "+
				"scans, so its actions would be unpinned and unnoticed", kubernetesWorkflow)
		}
	})
}
