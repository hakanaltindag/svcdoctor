package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The container-runtime audit: the structural facts about the OCI image that a
// reader of the Dockerfile and the Kubernetes examples is entitled to rely on.
//
// # Why this exists
//
// Phase 7.1's mutation matrix is a list of ways the image can quietly stop being
// the thing ADR 0062 describes, and almost none of them are reachable from a
// test that reads Go. A `USER` line deleted during a rebase, a `latest` base
// tag that looked harmless, an `ENV SVCDOCTOR_PASSWORD` added to make a CI job
// simpler, a `COPY . .` that seemed equivalent — each is a one-line edit, each
// passes every existing test, and each changes what the product is.
//
// The asymmetry is the same one docsclaims_test.go was written for. A wrong
// `USER` costs a Kubernetes pod that will not start, which is loud. A dropped
// `.dockerignore` allowlist entry costs a private key in a published image,
// which is silent, and the fixture CA keys under test/integration are real
// private keys sitting in exactly the tree an image gets built from.
//
// # What these do not do
//
// They do not build an image and they do not run Docker, so they are ordinary
// unit tests that run in `make check`. They read the Dockerfile, the
// .dockerignore and the example manifests as text and pin one checkable
// structural fact each. Ordinary editing stays free; the specific reversals do
// not.
//
// Every guard below has a companion that proves it can fail, because a guard
// that cannot fail is decoration.

// readRepoFileOptional is readRepoFile without the fatal, for the guard-can-fail
// tests that need to know whether a path exists before asserting about it.
func readRepoFileOptional(t *testing.T, name string) (string, bool) {
	t.Helper()
	path := filepath.Join("..", "..", name)
	contents, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // G304: a fixed repository path.
	if err != nil {
		return "", false
	}
	return string(contents), true
}

// dockerfileDirectives returns the Dockerfile's instruction lines, stripped of
// comments and blanks.
//
// Comments are dropped rather than searched because the Dockerfile explains its
// own reasoning at length, and that prose legitimately names the things these
// guards forbid — "no wrapper shell", "no HEALTHCHECK". Matching against the
// comments would fail on the explanation of the rule rather than on a breach of
// it.
func dockerfileDirectives(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(readRepoFile(t, "Dockerfile"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// TestTheImageRunsAsANumericNonRootUser pins ADR 0062 section 6.
//
// Numeric, not the name "nonroot": Kubernetes verifies `runAsNonRoot: true`
// against the image's configured user without resolving /etc/passwd, so a name
// makes the pod fail to start with CreateContainerConfigError. Measured in both
// directions in Phase 7.1.
func TestTheImageRunsAsANumericNonRootUser(t *testing.T) {
	var user string
	for _, directive := range dockerfileDirectives(t) {
		if strings.HasPrefix(directive, "USER ") {
			user = strings.TrimSpace(strings.TrimPrefix(directive, "USER "))
		}
	}
	if user == "" {
		t.Fatal("the Dockerfile sets no USER: the image would run as root")
	}
	if user == "0" || user == "0:0" || user == "root" || strings.HasPrefix(user, "root:") {
		t.Fatalf("the image runs as root (USER %s); ADR 0062 section 6 requires 65532:65532", user)
	}
	uid, _, _ := strings.Cut(user, ":")
	for _, r := range uid {
		if r < '0' || r > '9' {
			t.Fatalf("USER %s is not numeric; Kubernetes cannot verify runAsNonRoot "+
				"against a user name and the pod fails with CreateContainerConfigError", user)
		}
	}
}

// TestTheFinalStageCarriesNoSecretEnvironment pins ADR 0062 section 8.
//
// The rule is not "do not hardcode a password" — nobody does that on purpose.
// It is that no environment variable may become a *credential source*, because
// production code contains zero os.Getenv call sites and that is what makes
// SVCDOCTOR_PASSWORD structurally impossible rather than merely absent.
func TestTheFinalStageCarriesNoSecretEnvironment(t *testing.T) {
	forbidden := []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL", "APIKEY", "API_KEY"}
	for _, directive := range dockerfileDirectives(t) {
		if !strings.HasPrefix(directive, "ENV ") && !strings.HasPrefix(directive, "ARG ") {
			continue
		}
		upper := strings.ToUpper(directive)
		for _, word := range forbidden {
			if strings.Contains(upper, word) {
				t.Errorf("the Dockerfile declares a credential-shaped build variable:\n  %s\n\n"+
					"svcdoctor reads credentials from --password-file or --password-stdin only. "+
					"A build ARG is also visible in `docker history`.", directive)
			}
		}
	}
}

// TestTheImageHasNoShellEntrypointOrWrapper pins ADR 0062 section 7.
//
// A wrapper needs a shell in the final image, interposes itself between the
// runtime and the process that handles SIGTERM, and adds quoting surface around
// operator arguments. The exec form is the whole guard.
func TestTheImageHasNoShellEntrypointOrWrapper(t *testing.T) {
	var entrypoint string
	for _, directive := range dockerfileDirectives(t) {
		if strings.HasPrefix(directive, "ENTRYPOINT") {
			entrypoint = directive
		}
	}
	if entrypoint == "" {
		t.Fatal("the Dockerfile declares no ENTRYPOINT")
	}
	if !strings.Contains(entrypoint, "[") {
		t.Fatalf("ENTRYPOINT uses shell form, which requires a shell in the final "+
			"image and breaks direct signal delivery:\n  %s", entrypoint)
	}
	for _, shell := range []string{"/bin/sh", "/bin/bash", "sh -c", "bash -c", "entrypoint.sh"} {
		if strings.Contains(entrypoint, shell) {
			t.Fatalf("ENTRYPOINT invokes a shell or wrapper (%s):\n  %s", shell, entrypoint)
		}
	}
	if !strings.Contains(entrypoint, "svcdoctor") {
		t.Fatalf("ENTRYPOINT does not exec the svcdoctor binary directly:\n  %s", entrypoint)
	}
}

// TestTheImageDeclaresNoHealthcheckOrPort pins ADR 0062 section 7.
//
// svcdoctor terminates and listens on nothing. Either directive would describe
// a daemon, and a renderer of the image's own metadata would be lying.
func TestTheImageDeclaresNoHealthcheckOrPort(t *testing.T) {
	for _, directive := range dockerfileDirectives(t) {
		if strings.HasPrefix(strings.ToUpper(directive), "HEALTHCHECK") {
			t.Errorf("the image declares a HEALTHCHECK; svcdoctor is not a daemon:\n  %s", directive)
		}
		if strings.HasPrefix(strings.ToUpper(directive), "EXPOSE") {
			t.Errorf("the image declares EXPOSE; svcdoctor is a client and listens on no port:\n  %s", directive)
		}
	}
}

// TestEveryBaseImageIsPinnedByDigest pins ADR 0062 section 4.
//
// A floating tag makes the compiler that produced a released artifact, and the
// trust store that artifact ships with, both silently mutable.
func TestEveryBaseImageIsPinnedByDigest(t *testing.T) {
	found := 0
	for _, directive := range dockerfileDirectives(t) {
		if !strings.HasPrefix(strings.ToUpper(directive), "FROM ") {
			continue
		}
		found++
		image, _, _ := strings.Cut(strings.TrimSpace(directive[len("FROM "):]), " AS ")
		image = strings.TrimSpace(image)
		// A stage may build FROM an earlier named stage, which carries no digest.
		if !strings.Contains(image, "/") && !strings.Contains(image, ":") {
			continue
		}
		if !strings.Contains(image, "@sha256:") {
			t.Errorf("base image is not pinned by digest:\n  %s\n\n"+
				"A floating tag makes the toolchain and the shipped CA bundle mutable.", directive)
		}
	}
	if found == 0 {
		t.Fatal("the Dockerfile contains no FROM instruction")
	}
}

// TestTheBuildContextExcludesSecretsByDefault pins ADR 0062 section 13.
//
// The allowlist direction is the guard. An ignore list has to predict every
// secret-bearing path that might appear and fails silently the day an
// unpredicted one does — and `test/integration/*/env/certs/` holds real
// generated CA private keys in any tree that has run `make integration-*`.
func TestTheBuildContextExcludesSecretsByDefault(t *testing.T) {
	ignore := readRepoFile(t, ".dockerignore")

	denyAll := false
	for _, line := range strings.Split(ignore, "\n") {
		if strings.TrimSpace(line) == "*" {
			denyAll = true
		}
	}
	if !denyAll {
		t.Fatal(".dockerignore does not deny by default (no bare `*` rule).\n\n" +
			"Without it, a new secret-bearing path enters the build context " +
			"unless someone remembers to exclude it. test/integration/*/env/certs/ " +
			"contains real CA private keys.")
	}

	// The allowlist must not re-admit the repository wholesale.
	for _, line := range strings.Split(ignore, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "!*" || trimmed == "!." || trimmed == "!/" {
			t.Errorf(".dockerignore re-admits the whole build context:\n  %s", trimmed)
		}
		for _, path := range []string{"!test", "!.git", "!docs"} {
			if strings.HasPrefix(trimmed, path) {
				t.Errorf(".dockerignore re-admits %s, which is not needed to build "+
					"and carries fixture keys or history:\n  %s", path, trimmed)
			}
		}
	}
}

// TestTheDockerfileNeverCopiesTheWholeContext pins ADR 0062 section 13.
//
// `COPY . .` is only as safe as .dockerignore, and it makes the two files
// impossible to review independently. Naming the two source trees keeps the
// build's inputs legible in the Dockerfile itself.
func TestTheDockerfileNeverCopiesTheWholeContext(t *testing.T) {
	for _, directive := range dockerfileDirectives(t) {
		if !strings.HasPrefix(directive, "COPY ") || strings.Contains(directive, "--from=") {
			continue
		}
		fields := strings.Fields(directive)
		if len(fields) >= 2 && (fields[1] == "." || fields[1] == "./") {
			t.Errorf("the Dockerfile copies the entire build context:\n  %s\n\n"+
				"Name the paths the build needs instead.", directive)
		}
	}
}

// TestTheKubernetesExamplesAreHardened pins ADR 0062 section 9.
//
// Every one of these is a field whose absence is invisible in a diff of a
// working manifest: it still runs, it just runs with more privilege or more
// access than svcdoctor has any use for.
func TestTheKubernetesExamplesAreHardened(t *testing.T) {
	examples := []string{
		"examples/kubernetes/job-postgres.yaml",
		"examples/kubernetes/job-kafka.yaml",
	}
	required := []string{
		"runAsNonRoot: true",
		"readOnlyRootFilesystem: true",
		"allowPrivilegeEscalation: false",
		"automountServiceAccountToken: false",
		"restartPolicy: Never",
		"activeDeadlineSeconds:",
		`drop: ["ALL"]`,
		"type: RuntimeDefault",
	}
	// A slice of named fields rather than a map. The phrases below include
	// credential-shaped strings, and as map *keys* gosec reads them as hardcoded
	// credentials (G101). They are the opposite: the list of things a manifest
	// may not contain.
	forbidden := []struct {
		phrase string
		why    string
	}{
		{"hostNetwork: true", "svcdoctor diagnoses from the pod network namespace by design"},
		{"hostPID: true", "svcdoctor spawns no processes"},
		{"hostIPC: true", "svcdoctor shares no memory"},
		{"privileged: true", "svcdoctor opens ordinary client sockets"},
		{"NET_ADMIN", "svcdoctor does not configure networking"},
		{"NET_RAW", "svcdoctor does not craft packets"},
		{"SYS_ADMIN", "svcdoctor needs no administrative capability"},
		{"cluster-admin", "svcdoctor never calls the Kubernetes API"},
		{"SVCDOCTOR_PASSWORD", "there is no environment-variable secret source"},
		{"--password=", "there is no plaintext password flag"},
	}

	for _, example := range examples {
		manifest, ok := readRepoFileOptional(t, example)
		if !ok {
			t.Errorf("%s is missing", example)
			continue
		}
		for _, field := range required {
			if !strings.Contains(manifest, field) {
				t.Errorf("%s does not set %q (ADR 0062 section 9)", example, field)
			}
		}
		for _, rule := range forbidden {
			if strings.Contains(manifest, rule.phrase) {
				t.Errorf("%s contains %q: %s", example, rule.phrase, rule.why)
			}
		}
		if strings.Contains(manifest, ":latest") {
			t.Errorf("%s references a mutable :latest image tag; "+
				"use an immutable semver tag or a digest", example)
		}
	}
}

// TestTheJobDeadlineOutlivesTheRunTimeout pins ADR 0062 section 9.
//
// Reversing these is the subtlest error in the whole phase, because the
// manifest still works: the Job runs, the Pod is killed, and the operator gets
// a terminated container instead of the incomplete report svcdoctor was about
// to write. Ordering them correctly is what makes exit code 4 reachable.
func TestTheJobDeadlineOutlivesTheRunTimeout(t *testing.T) {
	for _, example := range []string{
		"examples/kubernetes/job-postgres.yaml",
		"examples/kubernetes/job-kafka.yaml",
	} {
		manifest, ok := readRepoFileOptional(t, example)
		if !ok {
			t.Errorf("%s is missing", example)
			continue
		}
		deadline := intAfter(manifest, "activeDeadlineSeconds:")
		timeout := secondsAfter(manifest, "--timeout=")
		switch {
		case deadline == 0:
			t.Errorf("%s sets no activeDeadlineSeconds", example)
		case timeout == 0:
			t.Errorf("%s sets no --timeout", example)
		case deadline <= timeout:
			t.Errorf("%s: activeDeadlineSeconds (%d) does not exceed --timeout (%ds).\n\n"+
				"Kubernetes would kill the Pod before svcdoctor could write its "+
				"incomplete report, and exit code 4 becomes unreachable.",
				example, deadline, timeout)
		}
	}
}

// intAfter reads the first integer following marker.
func intAfter(text, marker string) int {
	_, rest, found := strings.Cut(text, marker)
	if !found {
		return 0
	}
	return leadingInt(strings.TrimSpace(rest))
}

// secondsAfter reads the first "<n>s" duration following marker.
func secondsAfter(text, marker string) int {
	_, rest, found := strings.Cut(text, marker)
	if !found {
		return 0
	}
	return leadingInt(strings.TrimSpace(rest))
}

// leadingInt reads the leading run of ASCII digits, or 0.
func leadingInt(s string) int {
	value, digits := 0, 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		value = value*10 + int(r-'0')
		digits++
	}
	if digits == 0 {
		return 0
	}
	return value
}

// TestTheContainerGuardsCanFail proves every guard above is load-bearing.
//
// Each case is a real mutation from the Phase 7.1 matrix applied to a synthetic
// input. A guard that cannot fail is decoration, and this repository has
// already had one planted claim survive a full phase.
func TestTheContainerGuardsCanFail(t *testing.T) {
	t.Run("root user is rejected", func(t *testing.T) {
		if !userIsRoot("USER 0:0") || !userIsRoot("USER root") {
			t.Error("the root-user check would not catch USER 0:0 or USER root")
		}
		if userIsRoot("USER 65532:65532") {
			t.Error("the root-user check rejects the correct user")
		}
	})

	t.Run("non-numeric user is rejected", func(t *testing.T) {
		if numericUID("nonroot") {
			t.Error("a named user would pass the numeric check; Kubernetes cannot " +
				"verify runAsNonRoot against a name")
		}
		if !numericUID("65532") {
			t.Error("the numeric check rejects a numeric uid")
		}
	})

	t.Run("shell entrypoint is rejected", func(t *testing.T) {
		for _, bad := range []string{
			`ENTRYPOINT /bin/sh -c "/svcdoctor $@"`,
			`ENTRYPOINT ["/bin/sh", "-c", "/svcdoctor"]`,
			`ENTRYPOINT ["/entrypoint.sh"]`,
		} {
			if entrypointIsDirect(bad) {
				t.Errorf("a wrapper entrypoint would pass: %s", bad)
			}
		}
		if !entrypointIsDirect(`ENTRYPOINT ["/svcdoctor"]`) {
			t.Error("the direct entrypoint is rejected")
		}
	})

	t.Run("floating base tag is rejected", func(t *testing.T) {
		if pinnedByDigest("FROM golang:1.26-bookworm AS builder") {
			t.Error("a floating tag would pass the digest-pin check")
		}
		if !pinnedByDigest("FROM golang:1.26.6-bookworm@sha256:abc AS builder") {
			t.Error("a digest-pinned image is rejected")
		}
	})

	t.Run("deadline ordering is checked", func(t *testing.T) {
		reversed := "activeDeadlineSeconds: 15\n--timeout=30s"
		if intAfter(reversed, "activeDeadlineSeconds:") > secondsAfter(reversed, "--timeout=") {
			t.Error("a reversed deadline/timeout pair would pass")
		}
		correct := "activeDeadlineSeconds: 60\n--timeout=30s"
		if intAfter(correct, "activeDeadlineSeconds:") <= secondsAfter(correct, "--timeout=") {
			t.Error("a correct deadline/timeout pair is rejected")
		}
	})

	t.Run("whole-context copy is detected", func(t *testing.T) {
		if !copiesWholeContext("COPY . .") || !copiesWholeContext("COPY ./ /src") {
			t.Error("a whole-context COPY would pass")
		}
		if copiesWholeContext("COPY cmd/ ./cmd/") {
			t.Error("a named-path COPY is rejected")
		}
	})
}

// The predicates the guard-can-fail cases exercise. They are the same decisions
// the guards above make, named so both can use them.

func userIsRoot(directive string) bool {
	user := strings.TrimSpace(strings.TrimPrefix(directive, "USER "))
	return user == "0" || user == "0:0" || user == "root" || strings.HasPrefix(user, "root:")
}

func numericUID(uid string) bool {
	if uid == "" {
		return false
	}
	for _, r := range uid {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func entrypointIsDirect(directive string) bool {
	if !strings.Contains(directive, "[") {
		return false
	}
	for _, shell := range []string{"/bin/sh", "/bin/bash", "sh -c", "bash -c", "entrypoint.sh"} {
		if strings.Contains(directive, shell) {
			return false
		}
	}
	return strings.Contains(directive, "svcdoctor")
}

func pinnedByDigest(directive string) bool {
	image, _, _ := strings.Cut(strings.TrimSpace(directive[len("FROM "):]), " AS ")
	return strings.Contains(strings.TrimSpace(image), "@sha256:")
}

func copiesWholeContext(directive string) bool {
	fields := strings.Fields(directive)
	return len(fields) >= 2 && (fields[1] == "." || fields[1] == "./")
}

// TestTheDocsTellTheReaderHowToRunThePublishedImage replaces the guard that
// refused every pull instruction while nothing was published.
//
// That rule was correct and is now spent: v0.3.2 exists on GHCR, signed and
// attested. Its comment said what to do at this moment — publish first, then
// update the guard in the same change — so the rule changes sides rather than
// being deleted. What it protects is unchanged: the README must state the truth
// about publication, and the failure it now catches is a README still insisting
// nothing is published while an image is.
func TestTheDocsTellTheReaderHowToRunThePublishedImage(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	// The stale denials, each of which was true and is no longer.
	for _, stale := range []string{
		"no container image is published to any registry",
		"no container image is\npublished to any registry",
		"**No image is published.**",
		"Nothing has been pushed to GHCR",
	} {
		if strings.Contains(readme, stale) {
			t.Errorf("the README still says %q.\n\n"+
				"ghcr.io/hakanaltindag/svcdoctor:v0.3.2 is published, signed and "+
				"attested. A reader following this would build an image they did "+
				"not need to.", stale)
		}
	}

	// And it must give the operational instruction, so the guard cannot be
	// satisfied by removing the subject entirely. Matched with flags allowed
	// between the verb and the reference: the README writes `docker run --rm …`,
	// and a literal check for "docker run ghcr.io" missed it.
	if !regexp.MustCompile(`docker\s+(run|pull)[^\n]*ghcr\.io/hakanaltindag/svcdoctor:v`).
		MatchString(readme) {
		t.Error("the README does not tell the reader how to run the published image")
	}

	// The one thing that stays forbidden. A moving tag is not published and
	// never will be, so an instruction to pull one is a command that fails.
	for _, name := range []string{"README.md", "examples/kubernetes/README.md", releaseNotes} {
		doc, ok := readRepoFileOptional(t, name)
		if !ok {
			continue
		}
		for _, moving := range []string{"svcdoctor:latest", "svcdoctor:v0\n", "svcdoctor:v0.3\n"} {
			if strings.Contains(doc, moving) {
				t.Errorf("%s names the moving tag %q, which is deliberately never published",
					name, strings.TrimSuffix(moving, "\n"))
			}
		}
	}
}

// TestThePublicationGuardCanFail proves the guard above is load-bearing.
func TestThePublicationGuardCanFail(t *testing.T) {
	planted := "install it with docker pull ghcr.io/hakanaltindag/svcdoctor:v0.3.0"
	found := false
	for _, claim := range []string{"docker pull ghcr.io", "docker run ghcr.io"} {
		if strings.Contains(planted, claim) {
			found = true
		}
	}
	if !found {
		t.Error("a planted `docker pull ghcr.io` instruction would not be caught")
	}
	// And the inverse: a build instruction naming the future name is allowed.
	allowed := "docker build -t ghcr.io/hakanaltindag/svcdoctor:v0.3.0 ."
	for _, claim := range []string{"docker pull ghcr.io", "docker run ghcr.io"} {
		if strings.Contains(allowed, claim) {
			t.Error("a `docker build` instruction is wrongly treated as a publication claim")
		}
	}
}
