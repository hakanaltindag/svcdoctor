package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The `diagnose redis` flag-surface guard.
//
// # Why absence is asserted from the source rather than from behaviour
//
// A test that ran `--db 3` and expected exit 2 would pass for the wrong reason
// the moment somebody added the flag with a default: the flag would parse, the
// run would proceed, and the test would still see a non-zero exit from something
// else. What has to be pinned is that the flag **is not defined**, which is a
// property of the flag set rather than of one invocation.

// redisFlagSurface parses internal/cli/redis.go and returns every flag name it
// defines.
func redisFlagSurface(t *testing.T) map[string]bool {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "redis.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing redis.go: %v", err)
	}

	flags := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := sel.X.(*ast.Ident)
		if !ok || receiver.Name != "fs" {
			return true
		}
		switch sel.Sel.Name {
		case "String", "Bool", "Uint", "Int", "Duration", "Float64", "Var":
		default:
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		flags[strings.Trim(lit.Value, `"`)] = true
		return true
	})

	if len(flags) == 0 {
		t.Fatal("no flags found; this guard would pass vacuously")
	}
	return flags
}

// TestRedisFlagSurfaceIsExactlyTheAuthorizedSet pins both halves at once.
//
// Present-and-absent in one list, because the two failures mean different things
// and both matter: a missing flag breaks the product, and an extra one is scope
// that nobody argued for.
func TestRedisFlagSurfaceIsExactlyTheAuthorizedSet(t *testing.T) {
	authorized := map[string]bool{
		"host": true, "port": true, "username": true,
		"timeout": true, "step-timeout": true,
		"tls": true, "tls-ca-file": true, "tls-server-name": true, "tls-insecure": true,
		"output": true, "shareable": true,
		"password-file": true, "password-stdin": true,
	}

	flags := redisFlagSurface(t)
	for name := range flags {
		if !authorized[name] {
			t.Errorf("`diagnose redis` defines --%s, which Phase 7.5 does not authorize", name)
		}
	}
	for name := range authorized {
		if !flags[name] {
			t.Errorf("`diagnose redis` no longer defines --%s", name)
		}
	}
}

// TestRedisRefusesTheFlagsThatWouldBeScope names each absence and why.
//
// The list is not a duplicate of the one above. That one pins the set; this one
// records the reasoning, so a future author who wants one of these reads why it
// is missing rather than assuming it was an oversight.
func TestRedisRefusesTheFlagsThatWouldBeScope(t *testing.T) {
	flags := redisFlagSurface(t)

	for name, why := range map[string]string{
		"password": "a credential in an argument is visible to every process on the host; " +
			"ADR 0049 fixes the file and stdin sources and admits no third",
		"db": "BASIC names no key, so a database index is unobservable; the flag would " +
			"imply a keyspace scope svcdoctor does not have",
		"cluster": "service behaviour is discovered from the endpoint's own HELLO reply, " +
			"never declared by the operator",
		"sentinel": "same, and a Sentinel is a different target type rather than a flag",
		"expected-role": "BASIC has no expected-state contract; this flag would be the " +
			"first half of one",
		"expected-server": "same",
		"resp-version":    "v1 speaks RESP2; the flag would be a knob for a capability that does not exist",
		"probe-command": "the terminal step is named after the command it runs, and a flag " +
			"would make that name lie",
		"unix-socket": "a filesystem socket is a transport security.Channel cannot classify " +
			"(ADR 0064 section 8)",
		"uri":       "a URI smuggles TLS inference from its scheme, which ADR 0024 forbids",
		"insecure":  "the TLS surface is --tls-insecure, shared with every other service",
		"no-verify": "same",
	} {
		if flags[name] {
			t.Errorf("`diagnose redis` defines --%s.\n\nIt must not: %s", name, why)
		}
	}
}

// TestRedisHelpStatesTheProductBoundary pins the six things an operator has to
// be told.
//
// Help text is where a boundary is either communicated or quietly lost. Each
// clause below corresponds to a limit the report itself cannot restate on every
// line.
func TestRedisHelpStatesTheProductBoundary(t *testing.T) {
	app := &App{Version: "test"}
	var sb strings.Builder
	app.Stdout = &sb
	app.usageRedis(&sb)
	help := strings.ToLower(sb.String())

	for _, required := range []struct{ phrase, why string }{
		{"valkey", "one command diagnoses both implementations"},
		{"names no key", "the zero-keyspace contract"},
		{"topology is not measured", "cluster mode is observed, never traversed"},
		{"sentinel", "detection only, and the run stops"},
		{"at most once", "the credential-attempt invariant"},
		{"answered ping on this connection", "the endpoint-scoped claim"},
	} {
		if !strings.Contains(help, required.phrase) {
			t.Errorf("the help text does not state %q (%s)", required.phrase, required.why)
		}
	}

	// The help text names "redis is healthy" in order to say the probe does not
	// mean it. That is the honest thing for it to do, so the assertion is that
	// the phrase is disclaimed rather than that it is absent — the same
	// distinction the diagnosis and integration suites draw. A blunt ban here
	// would push the boundary out of the help text instead of into it.
	for _, phrase := range []string{"redis is healthy", "cluster is healthy"} {
		if !strings.Contains(help, phrase) {
			continue
		}
		before := help[:strings.Index(help, phrase)]
		if !strings.Contains(before, "does not mean") && !strings.Contains(before, "never render") {
			t.Errorf("the help text mentions %q without disclaiming it", phrase)
		}
	}
	for _, forbidden := range []string{"wrong password", "guarantees", "proves your application"} {
		if strings.Contains(help, forbidden) {
			t.Errorf("the help text claims %q", forbidden)
		}
	}
}

// --- the command boundary reaches no wire package ---------------------------

// TestTheCommandBoundaryReachesNoWirePackage states the CLI layering rule the
// way the rule is actually meant, rather than one service at a time.
//
// # Why this exists beside depguard
//
// `.golangci.yml`'s `cli-composes-and-does-not-conclude` enumerates packages,
// and an enumeration only protects what somebody remembered to enumerate. Phase
// 7.5 added Redis; nobody added the entry; Phase 7.6A measured the consequence
// and found `internal/cli` could import `internal/adapter/redis/wire` — the
// package holding the third authorized `security.Reveal` — with zero lint
// issues, while the identical PostgreSQL import was rejected.
//
// The depguard entry is the fix for Redis and it is what produces the message a
// developer sees. This is the fix for the *class*: it names no service, so a
// fourth adapter's wire package is denied on the day it is created.
//
// The rule: a wire package is the last layer before the socket. It holds the
// protocol encoding and the one authorized call that turns a masked secret into
// bytes. The command boundary composes a run and renders its report; it has no
// business holding either, and `forbidigo` already bans the call itself. This
// bans the import that would put it in reach.
func TestTheCommandBoundaryReachesNoWirePackage(t *testing.T) {
	const modulePath = "github.com/hakanaltindag/svcdoctor/"

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading internal/cli: %v", err)
	}

	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		checked++

		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if !strings.HasPrefix(path, modulePath) {
				continue
			}
			// Two shapes, and the second is why Phase 12.1C.2 revisited this.
			//
			// A wire package is any package named `wire` under an adapter, and
			// the shape is matched rather than the service, deliberately. That
			// covered four services and would have covered a fifth — except
			// that Kubernetes' authorized `security.Reveal` is **not** in a
			// wire package. It cannot be: client-go owns the transport, so the
			// last layer svcdoctor controls is the one that assembles the
			// connection, which is exactly what
			// TestRevealHasOneProductionCallSitePerService already records.
			//
			// A guard that matched only the name would therefore have said
			// nothing about the one package a Kubernetes leaf command was most
			// likely to reach for — the identical shape of the Phase 7.6A
			// defect this test was written to close. So the property is now
			// computed: **any adapter package that opens a secret is out of
			// reach**, whatever it is called.
			trimmed := strings.TrimPrefix(path, modulePath)
			if !strings.HasPrefix(trimmed, "internal/adapter/") {
				continue
			}
			switch {
			case trimmed == "internal/adapter/wire" || strings.HasSuffix(trimmed, "/wire"):
				t.Errorf("%s imports %s.\n\n"+
					"A wire package holds the protocol and the authorized "+
					"security.Reveal; the command boundary reaches neither. Compose "+
					"the run through internal/app instead.", name, path)
			case packageOpensASecret(t, trimmed):
				t.Errorf("%s imports %s, which holds an authorized security.Reveal.\n\n"+
					"The command boundary composes a run and renders its report; a "+
					"package that can turn a masked secret into bytes is not something "+
					"it may hold a reference to. Compose the run through internal/app "+
					"instead — app.KubernetesTarget is a type alias precisely so that "+
					"no adapter import is needed.", name, path)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no Go files were parsed; this guard would pass vacuously")
	}
}

// packageOpensASecret reports whether a package's production sources contain an
// authorized security.Reveal call.
//
// It reads the package rather than a list of names, which is the whole point:
// an enumeration protects what somebody remembered to enumerate, and the fifth
// service was the one nobody would have remembered, because its authorized site
// is not in a package called `wire`.
//
// dir is repository-relative, as an import path under internal/ already is.
func packageOpensASecret(t *testing.T, dir string) bool {
	t.Helper()

	entries, err := os.ReadDir(filepath.Join("..", "..", dir))
	if err != nil {
		// A package this repository does not have cannot hold a Reveal. An
		// import of it would not compile, so there is nothing to report.
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join("..", "..", dir, name))
		if err != nil {
			t.Fatalf("reading %s/%s: %v", dir, name, err)
		}
		if strings.Contains(string(body), "security.Reveal(") {
			return true
		}
	}
	return false
}

// TestTheSecretOpeningPackageGuardIsLive proves the computed half is not
// vacuous: the Kubernetes client really is detected as a package that opens a
// secret, and an ordinary adapter package really is not.
func TestTheSecretOpeningPackageGuardIsLive(t *testing.T) {
	if !packageOpensASecret(t, "internal/adapter/kubernetes/client") {
		t.Error("internal/adapter/kubernetes/client is not detected as opening a secret.\n\n" +
			"It holds the fifth authorized security.Reveal, and it is the one such " +
			"package that is not named `wire` — so if this predicate stops seeing it, " +
			"the command boundary is unguarded against exactly the import Phase 12.1C.2 " +
			"had to avoid.")
	}
	if packageOpensASecret(t, "internal/adapter/kubernetes") {
		t.Error("internal/adapter/kubernetes is detected as opening a secret; it " +
			"normalizes evidence and holds no credential, so the predicate is matching " +
			"something other than a Reveal call")
	}
}
