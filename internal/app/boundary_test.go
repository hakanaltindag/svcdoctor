package app

import (
	"go/ast"
	gobuild "go/build"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Boundary tests for the composition root.
//
// This package sits above every other layer and can therefore reach anything.
// That is precisely why its restraint has to be checked rather than trusted: the
// cheapest way to lose this architecture is for orchestration to start doing a
// little protocol work, a little rendering, or a little diagnosis.

func productionFiles(t *testing.T) []string {
	t.Helper()

	pkg, err := gobuild.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("describing the package: %v", err)
	}
	if len(pkg.GoFiles) == 0 {
		t.Fatal("no production sources found")
	}
	return pkg.GoFiles
}

func parse(t *testing.T, name string) *ast.File {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return file
}

// TestTheRunImportsOnlyTheLayersItComposes pins the dependency boundary.
//
// The composition root may reach the layers it sequences and nothing else. Two
// absences matter most:
//
//   - **internal/security/redaction.** The run produces a LOCAL_FULL report and
//     stops. Redaction is a derivative the output boundary requests, after
//     diagnosis has run on truthful evidence (ADR 0018, ADR 0041 section 18). If
//     this package could redact, "diagnosis sees unredacted evidence" would
//     become a convention rather than a structure.
//   - **internal/adapter/postgres/wire.** Protocol framing belongs to the
//     adapter. Orchestration sequences steps; it does not speak the protocol.
func TestTheRunImportsOnlyTheLayersItComposes(t *testing.T) {
	allowed := map[string]bool{
		"github.com/hakanaltindag/svcdoctor/internal/domain":             true,
		"github.com/hakanaltindag/svcdoctor/internal/probe/dns":          true,
		"github.com/hakanaltindag/svcdoctor/internal/probe/tcp":          true,
		"github.com/hakanaltindag/svcdoctor/internal/probe/transport":    true,
		"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres":   true,
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis":          true,
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres": true,
		"github.com/hakanaltindag/svcdoctor/internal/security":           true,
	}

	for _, name := range productionFiles(t) {
		for _, imported := range parse(t, name).Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if !strings.Contains(path, "/") || !strings.Contains(path, ".") {
				continue // standard library, checked separately
			}
			if !allowed[path] {
				t.Errorf("%s imports %s, which the composition root does not compose", name, path)
			}
		}
	}
}

// TestTheRunPerformsNoIOOfItsOwn restates what orchestration is not.
//
// It composes probes and an adapter that own the network. A direct dial, a
// direct handshake or a direct query here would mean the boundary had been
// bypassed rather than sequenced.
func TestTheRunPerformsNoIOOfItsOwn(t *testing.T) {
	forbidden := map[string]string{
		"net/http":     "orchestration performs no I/O of its own",
		"crypto/tls":   "the TLS probe owns handshakes; orchestration must not perform one",
		"database/sql": "svcdoctor executes no SQL",
		"os":           "orchestration reads no files, environment or process state",
		"os/exec":      "orchestration runs no commands",
		"math/rand":    "a run must be deterministic",
		"math/rand/v2": "a run must be deterministic",
		"regexp":       "orchestration reads typed values, not patterns",
	}

	for _, name := range productionFiles(t) {
		for _, imported := range parse(t, name).Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if why, banned := forbidden[path]; banned {
				t.Errorf("%s imports %s: %s", name, path, why)
			}
		}
	}
}

// TestTheRunOpensNoSocket allows net for its pure helpers and bans the parts
// that touch a network.
//
// `net.JoinHostPort` is string formatting and is the correct way to render an
// endpoint label that may be IPv6. `net.Dial`, `net.Listen` and the resolver are
// the probes' job, and a call to one here would be this package doing transport
// work it is supposed to be composing.
func TestTheRunOpensNoSocket(t *testing.T) {
	banned := map[string]bool{
		"Dial": true, "DialTimeout": true, "DialIP": true, "DialTCP": true, "DialUDP": true,
		"Listen": true, "ListenTCP": true, "ListenPacket": true,
		"LookupHost": true, "LookupIP": true, "LookupAddr": true, "LookupCNAME": true,
		"Resolver": true, "Dialer": true,
	}

	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "net" {
				return true
			}
			if banned[sel.Sel.Name] {
				t.Errorf("%s calls net.%s; transport owns the network", name, sel.Sel.Name)
			}
			return true
		})
	}
}

// TestTheRunExecutesNoSQL widens the adapter's own no-SQL guard to the layer
// most likely to add a health query.
func TestTheRunExecutesNoSQL(t *testing.T) {
	fragments := []string{"SELECT ", "select 1", "pg_is_in_recovery", "current_database",
		"SHOW ", "INSERT ", "UPDATE ", "DELETE "}

	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			for _, f := range fragments {
				if strings.Contains(lit.Value, f) {
					t.Errorf("%s contains a SQL-shaped literal %s", name, lit.Value)
				}
			}
			return true
		})
	}
}

// TestTheRunNeverParsesAnEvidenceIdentifier pins ADR 0041 section 14.
//
// Which path was authenticated is readable from the authentication node's own
// Subject and from its parent chain. Recovering it from an identifier's text
// would make graph shape a function of a naming convention, and would be the
// provenance inference ADR 0034 section 4 forbids.
//
// Orchestration reads addresses off the adapter's own result instead, which is
// why the selector takes a netip.AddrPort and never an EvidenceID.
func TestTheRunNeverParsesAnEvidenceIdentifier(t *testing.T) {
	banned := map[string]bool{
		"Split": true, "SplitN": true, "Cut": true, "HasPrefix": true, "TrimPrefix": true,
		"Contains": true, "Index": true, "Fields": true,
	}

	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "strings" || !banned[sel.Sel.Name] {
				return true
			}
			// strings is not banned outright; parsing an identifier with it is.
			// The whole argument subtree is searched, because the identifier
			// usually arrives through a conversion — string(x.Evidence()) — and
			// matching only the outermost expression would miss every real case.
			for _, arg := range call.Args {
				if mentionsEvidence(arg) {
					t.Errorf("%s parses an evidence identifier with strings.%s",
						name, sel.Sel.Name)
				}
			}
			return true
		})
	}
}

// mentionsEvidence reports whether any identifier in an expression subtree names
// evidence, however deeply it is wrapped.
func mentionsEvidence(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok {
			if strings.Contains(strings.ToLower(ident.Name), "evidence") {
				found = true
			}
		}
		if sel, ok := node.(*ast.SelectorExpr); ok {
			if strings.Contains(strings.ToLower(sel.Sel.Name), "evidence") {
				found = true
			}
		}
		return !found
	})
	return found
}

// render is a minimal expression renderer for the guard above.
func render(n ast.Node) string {
	switch v := n.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return render(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return render(v.Fun)
	}
	return ""
}

// TestTheRunCreatesNoSelectionEvidence pins that orchestration records nothing.
//
// The run sequences stages that record their own evidence. It must not add a
// node, an attribute or a step of its own — "which path was selected" is already
// carried by the authentication node's Subject and parent chain, and a second
// representation is what ADR 0013 refuses.
func TestTheRunCreatesNoSelectionEvidence(t *testing.T) {
	banned := map[string]bool{
		"NewEvidence": true, "AddEvidence": true, "AddParent": true, "AddBlockedBy": true,
		"NewFinding": true, "StringAttr": true, "BoolAttr": true, "IntAttr": true,
		"IdentityAttr": true, "HostAttr": true, "StringListAttr": true,
	}

	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !banned[sel.Sel.Name] {
				return true
			}
			t.Errorf("%s calls %s; stages record their own evidence and orchestration adds none",
				name, render(sel))
			return true
		})
	}
}

// TestNoServiceRegistryOrGenericAdapterExists pins ADR 0041 section 19.
//
// The composition root is explicit PostgreSQL composition. A registry or a
// shared Adapter interface would be the speculative abstraction ADR 0009
// declines, and Kafka and PostgreSQL do not in fact share an orchestration
// contract — one has topology discovery and advertised-endpoint sweeps, the
// other has a single credentialed continuation.
func TestNoServiceRegistryOrGenericAdapterExists(t *testing.T) {
	banned := map[string]bool{
		"Adapter": true, "ServiceAdapter": true, "Runner": true, "ServiceRegistry": true,
		"AdapterRegistry": true, "PluginRegistry": true, "Workflow": true, "RunPlan": true,
		"ExecutionPlan": true,
	}

	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if ok && banned[spec.Name.Name] {
				t.Errorf("%s declares %s; service composition stays explicit", name, spec.Name.Name)
			}
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
				t.Errorf("%s declares init(); registration is explicit, never a side effect", name)
			}
			return true
		})
	}
}

// TestTheRunOwnsNoExitCode pins that the product boundary keeps its own job.
//
// docs/SCOPE.md defines the exit-code contract, and mapping a report to a
// process status is the CLI's. A run reports what it concluded and whether it
// got to conclude it; turning that into a number is somebody else's decision.
func TestTheRunOwnsNoExitCode(t *testing.T) {
	for _, name := range productionFiles(t) {
		src := parse(t, name)
		ast.Inspect(src, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			lowered := strings.ToLower(ident.Name)
			if strings.Contains(lowered, "exitcode") || lowered == "exit" {
				t.Errorf("%s names %s; exit-code mapping belongs to the CLI", name, ident.Name)
			}
			return true
		})
	}
}

// TestTheCandidateClassComesFromTheAdapter pins the derivation an integration
// test cannot reach in this environment.
//
// ADR 0041 section 8.1 partitions candidates by whether the endpoint demanded
// credential-based authentication, and that fact must come from the adapter's
// own normalized answer — never from a guess, a constant, or the graph. An
// end-to-end test would need an endpoint whose method differs by address family,
// which Docker's port translation makes unreproducible here, so the invariant is
// pinned structurally instead.
func TestTheCandidateClassComesFromTheAdapter(t *testing.T) {
	assigned := false

	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "authRequired" {
				return true
			}
			assigned = true
			if !mentionsAuthMethod(kv.Value) {
				t.Errorf("%s sets authRequired from %s; it must come from the adapter's "+
					"AuthMethod()", name, render(kv.Value))
			}
			return true
		})
	}

	if !assigned {
		t.Error("no candidate assigns authRequired; the class partition has no source")
	}
}

// mentionsAuthMethod reports whether an expression subtree reads the adapter's
// normalized authentication method.
func mentionsAuthMethod(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok && sel.Sel.Name == "AuthMethod" {
			found = true
		}
		return !found
	})
	return found
}
