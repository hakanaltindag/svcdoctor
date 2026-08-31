package run_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/run"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/secret"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// Phase 9.1C sections 8 and 9: target isolation where it is most tempting to
// share.
//
// # Why these use the real resolver
//
// The scheduler tests beside this one use a fake resolver, correctly: they are
// about scheduling, and a fake makes failure injection trivial. But the property
// here is *"one reference in two targets produces two independent credentials"*,
// and a fake resolver that hands out a distinct secret per target proves that by
// construction — it would pass against a production resolver that cached.
//
// So these wire `*secret.Resolver` in, which is the type the CLI actually uses,
// and read real environment variables and real files.

// isolationTarget describes one target for a two-target isolation run.
type isolationTarget struct {
	id       string
	service  string
	host     string
	port     uint16
	username string
	// credentialRef is a YAML credential *reference* block body such as
	// "env: NAME", or "" for a target with no credential. It never holds a
	// password: the schema has no field that could.
	credentialRef string
	extra         string // additional target lines
}

// envRef and fileRef build a credential reference block body.
//
// Functions rather than string literals so that a test declaring
// `env: DB_PASSWORD` does not read to a static analyser as a hardcoded
// credential. The value is an environment variable *name*; there is no schema
// field that could hold a password, which is the whole of ADR 0072 section 3.
func envRef(name string) string  { return "env: " + name }
func fileRef(path string) string { return "file: " + path }

// buildIsolationConfig writes and loads a real configuration.
//
// Real, because a hand-built config.Config could hold a Reference the decoder
// would never produce, and the closed union is half of what is being tested.
func buildIsolationConfig(t *testing.T, targets ...isolationTarget) config.Config {
	t.Helper()

	doc := "version: 1\ntargets:\n"
	for _, target := range targets {
		doc += fmt.Sprintf("  - id: %s\n    type: %s\n    host: %s\n",
			target.id, target.service, target.host)
		if target.port != 0 {
			doc += fmt.Sprintf("    port: %d\n", target.port)
		}
		if target.username != "" || target.credentialRef != "" {
			doc += "    credentials:\n"
			if target.username != "" {
				doc += "      username: " + target.username + "\n"
			}
			if target.credentialRef != "" {
				doc += "      password:\n        " + target.credentialRef + "\n"
			}
		}
		doc += target.extra
	}

	cfg, err := config.Load([]byte(doc), "isolation.yaml", credentialRegistry(t))
	if err != nil {
		t.Fatalf("Load:\n%s\n%v", doc, err)
	}
	return cfg
}

// executeWithRealResolver runs a configuration through the scheduler with the
// production credential resolver.
func executeWithRealResolver(
	t *testing.T, cfg config.Config, workers int,
) (*fakeRunner, domain.RunReport) {
	t.Helper()

	cfg.Run.Concurrency = workers
	runner := newFakeRunner(testServiceKind)

	registry, err := run.NewRegistry(runner)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	resolver := secret.NewResolver()
	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight: %v", err)
	}

	report, err := run.Execute(context.Background(), run.Params{
		Config:   cfg,
		Registry: registry,
		Resolver: resolver,
		Version:  "test",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return runner, report
}

// TestMTS05OneReferenceProducesTwoIndependentCredentials is section 8.
//
// Two targets naming one environment variable, at both a sequential and a
// concurrent pool size. What must hold is not merely that both got *a*
// credential, but that each got one bound to its **own** endpoint — which is
// what makes a shared cache detectable, because a cached credential would carry
// the endpoint of whichever target resolved first.
func TestMTS05OneReferenceProducesTwoIndependentCredentials(t *testing.T) {
	const shared = "shared-password-value"
	t.Setenv("SVCDOCTOR_SHARED_PASSWORD", shared)

	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprintf("concurrency %d", workers), func(t *testing.T) {
			cfg := buildIsolationConfig(t,
				isolationTarget{
					id: "alpha", service: testServiceKind, host: "alpha.example.com",
					port: 5432, username: "u", credentialRef: envRef("SVCDOCTOR_SHARED_PASSWORD"),
				},
				isolationTarget{
					id: "beta", service: testServiceKind, host: "beta.example.com",
					port: 5433, username: "u", credentialRef: envRef("SVCDOCTOR_SHARED_PASSWORD"),
				},
			)

			runner, report := executeWithRealResolver(t, cfg, workers)
			if len(report.Targets()) != 2 {
				t.Fatalf("%d results, want 2", len(report.Targets()))
			}

			alpha := credentialOf(t, runner, "alpha")
			beta := credentialOf(t, runner, "beta")

			// Each credential opens at its own endpoint and nowhere else. This
			// is the authority property: a reference names where material lives,
			// and the endpoint is what authorizes its use.
			assertOpensOnlyAt(t, alpha, "alpha.example.com", 5432, shared)
			assertOpensOnlyAt(t, beta, "beta.example.com", 5433, shared)

			// And they are not the same object. Equal secrets, different
			// authorities — which is exactly what "no cache" means here.
			if alpha == beta {
				t.Error("both targets received the identical credential value; one " +
					"reference produced one shared object")
			}
		})
	}
}

// TestOneReferenceAcrossDifferentServiceKinds is the same property where the
// two targets are not even the same service.
//
// A cache keyed by reference would be at its most plausible here, because
// nothing about the two targets looks related except the variable name.
func TestOneReferenceAcrossDifferentServiceKinds(t *testing.T) {
	const shared = "shared-across-kinds"
	t.Setenv("SVCDOCTOR_SHARED_PASSWORD", shared)

	// Two registered kinds, one runner each, so the scheduler dispatches on kind
	// while the credential path stays identical.
	first := newFakeRunner("kind-one")
	second := newFakeRunner("kind-two")

	registry, err := config.NewRegistry(
		kindFactory{kind: "kind-one", port: 1111},
		kindFactory{kind: "kind-two", port: 2222},
	)
	if err != nil {
		t.Fatalf("config.NewRegistry: %v", err)
	}

	doc := "version: 1\ntargets:\n" +
		"  - id: one\n    type: kind-one\n    host: one.example.com\n" +
		"    credentials:\n      username: u\n      password:\n        env: SVCDOCTOR_SHARED_PASSWORD\n" +
		"  - id: two\n    type: kind-two\n    host: two.example.com\n" +
		"    credentials:\n      username: u\n      password:\n        env: SVCDOCTOR_SHARED_PASSWORD\n"

	cfg, err := config.Load([]byte(doc), "kinds.yaml", registry)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Run.Concurrency = 2

	runnerRegistry, err := run.NewRegistry(first, second)
	if err != nil {
		t.Fatalf("run.NewRegistry: %v", err)
	}
	resolver := secret.NewResolver()
	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if _, err := run.Execute(context.Background(), run.Params{
		Config: cfg, Registry: runnerRegistry, Resolver: resolver, Version: "test",
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	assertOpensOnlyAt(t, credentialOf(t, first, "one"), "one.example.com", 1111, shared)
	assertOpensOnlyAt(t, credentialOf(t, second, "two"), "two.example.com", 2222, shared)
}

// TestOneFileReferenceProducesTwoReads proves the file source is read per target
// rather than once.
//
// The file is rewritten between the two resolutions, so a second read returns a
// different value. Two distinct values arriving is proof that two reads
// happened; one value arriving twice would be a cache.
//
// Sequential on purpose: the property is about *how many reads*, and a
// concurrent run could interleave the rewrite unpredictably.
func TestOneFileReferenceProducesTwoReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-secret")
	if err := os.WriteFile(path, []byte("first-value"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := buildIsolationConfig(t,
		isolationTarget{
			id: "alpha", service: testServiceKind, host: "alpha.example.com",
			port: 5432, username: "u", credentialRef: fileRef(path),
		},
		isolationTarget{
			id: "beta", service: testServiceKind, host: "beta.example.com",
			port: 5433, username: "u", credentialRef: fileRef(path),
		},
	)
	cfg.Run.Concurrency = 1

	runner := newFakeRunner(testServiceKind)
	runner.gate = map[string]chan struct{}{
		"alpha": make(chan struct{}),
		"beta":  make(chan struct{}),
	}

	registry, err := run.NewRegistry(runner)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	resolver := secret.NewResolver()
	if err := resolver.PreflightAll(cfg); err != nil {
		t.Fatalf("preflight: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := run.ExecuteSequential(context.Background(), run.Params{
			Config: cfg, Registry: registry, Resolver: resolver, Version: "test",
		}); err != nil {
			t.Errorf("ExecuteSequential: %v", err)
		}
	}()

	// alpha has resolved and is inside Run. Rewrite the file before releasing it,
	// so beta's resolution — which has not happened yet — sees new contents.
	waitFor(t, func() bool { return len(runner.starts()) == 1 })
	if err := os.WriteFile(path, []byte("second-value"), 0o600); err != nil {
		t.Fatalf("rewriting: %v", err)
	}
	close(runner.gate["alpha"])

	waitFor(t, func() bool { return len(runner.starts()) == 2 })
	close(runner.gate["beta"])
	<-done

	assertOpensOnlyAt(t, credentialOf(t, runner, "alpha"), "alpha.example.com", 5432, "first-value")
	assertOpensOnlyAt(t, credentialOf(t, runner, "beta"), "beta.example.com", 5433, "second-value")
}

// TestMTE09TheSameEndpointWithDifferentAuthorityIsTwoTargets is section 9.
//
// Four targets on one host and port, differing only in identity, credential
// reference and service configuration. None of them may be deduplicated, share a
// report, or share a credential — because "same server, different database" and
// "same server, different user" are the cases the endpoint-is-not-identity rule
// exists for.
func TestMTE09TheSameEndpointWithDifferentAuthorityIsTwoTargets(t *testing.T) {
	t.Setenv("SVCDOCTOR_PASSWORD_A", "password-a")
	t.Setenv("SVCDOCTOR_PASSWORD_B", "password-b")

	const host = "shared.example.com"
	cfg := buildIsolationConfig(t,
		isolationTarget{
			id: "same-a", service: testServiceKind, host: host, port: 5432,
			username: "alice", credentialRef: envRef("SVCDOCTOR_PASSWORD_A"),
		},
		isolationTarget{
			id: "same-b", service: testServiceKind, host: host, port: 5432,
			username: "bob", credentialRef: envRef("SVCDOCTOR_PASSWORD_B"),
		},
		isolationTarget{
			id: "same-c", service: testServiceKind, host: host, port: 5432,
			username: "alice", credentialRef: envRef("SVCDOCTOR_PASSWORD_B"),
		},
		isolationTarget{
			id: "same-d", service: testServiceKind, host: host, port: 5432,
		},
	)

	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprintf("concurrency %d", workers), func(t *testing.T) {
			runner, report := executeWithRealResolver(t, cfg, workers)

			results := report.Targets()
			if len(results) != 4 {
				t.Fatalf("%d results for four targets sharing an endpoint, want 4; "+
					"endpoints must never be deduplicated", len(results))
			}

			// Declared order, not endpoint order or completion order.
			want := []string{"same-a", "same-b", "same-c", "same-d"}
			for i, result := range results {
				if result.TargetID() != want[i] {
					t.Fatalf("result %d is %q, want %q", i, result.TargetID(), want[i])
				}
			}

			// Four runner invocations, not one.
			if got := len(runner.starts()); got != 4 {
				t.Errorf("the runner was invoked %d times for four targets", got)
			}

			// Each report is its own document.
			seen := map[string]bool{}
			for _, result := range results {
				if !result.HasReport() {
					t.Fatalf("target %q has no report", result.TargetID())
				}
				encoded := canonicalJSON(t, mustSingle(t, result))
				if seen[encoded] {
					t.Errorf("target %q shares a report document with another target",
						result.TargetID())
				}
				seen[encoded] = true
			}

			// The credentials differ where the references differ, and the
			// target with no reference received none at all.
			assertOpensOnlyAt(t, credentialOf(t, runner, "same-a"), host, 5432, "password-a")
			assertOpensOnlyAt(t, credentialOf(t, runner, "same-b"), host, 5432, "password-b")
			assertOpensOnlyAt(t, credentialOf(t, runner, "same-c"), host, 5432, "password-b")

			if credential, ok := runner.credentialFor("same-d"); ok && !credential.IsZero() {
				t.Error("a target with no credential reference received a credential; " +
					"a sibling on the same endpoint is not authority to present one")
			}
		})
	}
}

// mustSingle wraps one result in a one-target aggregate so canonicalJSON can
// normalize it. Comparing whole documents is what makes "no sharing" observable.
func mustSingle(t *testing.T, result domain.TargetResult) domain.RunReport {
	t.Helper()
	// The identifier is neutralized so that two otherwise-identical documents
	// compare equal; the test is looking for *shared* reports, not distinct ids.
	rebuilt, err := domain.CompletedTarget("x", result.Service(), result.Report(),
		result.Incomplete())
	if err != nil {
		t.Fatalf("rebuilding a result: %v", err)
	}
	report, err := domain.NewRunReport(domain.RunReportInput{
		SvcdoctorVersion: "test",
		StartedAt:        result.Report().Run().StartedAt(),
		Concurrency:      1,
		OutputMode:       domain.OutputModeLocalFull,
		Targets:          []domain.TargetResult{rebuilt},
	})
	if err != nil {
		t.Fatalf("wrapping a result: %v", err)
	}
	return report
}

// credentialOf returns the credential a target was handed, failing if none was.
func credentialOf(t *testing.T, runner *fakeRunner, id string) security.Credential {
	t.Helper()
	credential, ok := runner.credentialFor(id)
	if !ok {
		t.Fatalf("target %q never reached the runner", id)
	}
	if credential.IsZero() {
		t.Fatalf("target %q received no credential", id)
	}
	return credential
}

// assertOpensOnlyAt proves a credential's authority is exactly one endpoint.
//
// Both halves matter. Opening at its own endpoint proves the right material
// arrived; being refused everywhere else proves the binding is real rather than
// decorative, and is what a shared or cached credential would fail.
func assertOpensOnlyAt(
	t *testing.T, credential security.Credential, host string, port uint16, want string,
) {
	t.Helper()

	own, err := security.NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	plaintext, err := credential.SecretFor(own)
	if err != nil {
		t.Fatalf("SecretFor at %s:%d, the credential's own endpoint: %v", host, port, err)
	}
	if got := security.Reveal(plaintext); got != want {
		t.Errorf("the credential at %s:%d holds the wrong value", host, port)
	}

	elsewhere := []struct {
		host string
		port uint16
	}{
		{"somewhere-else.example.com", uint16(port)},
		{host, uint16(port) + 1},
	}
	for _, other := range elsewhere {
		endpoint, err := security.NewEndpoint(other.host, other.port)
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		if _, err := credential.SecretFor(endpoint); err == nil {
			t.Errorf("the credential bound to %s:%d also opened at %s:%d",
				host, port, other.host, other.port)
		}
	}
}

// kindFactory is a neutral configuration factory for an arbitrary service kind.
type kindFactory struct {
	kind string
	port uint16
}

func (f kindFactory) Kind() string        { return f.kind }
func (f kindFactory) DefaultPort() uint16 { return f.port }
func (f kindFactory) Decode(*config.ServiceNode, config.Common) (config.ServiceConfig, error) {
	return kindConfig{kind: f.kind}, nil
}

type kindConfig struct{ kind string }

func (c kindConfig) Kind() string { return c.kind }
