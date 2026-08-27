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
//   - **internal/adapter/postgres/wire** and **internal/adapter/kafka/wire.**
//     Protocol framing belongs to the adapter, and a wire package additionally
//     holds the only authorized security.Reveal. Orchestration sequences steps;
//     it does not speak the protocol and it cannot reveal a secret.
//
// The Kafka entries arrived in Phase 6.1c, and each is one of the four things a
// second service adds: its adapter, its diagnosis rules, its shared vocabulary,
// and nothing else. The list is per-package rather than per-prefix precisely so
// that `internal/adapter/kafka/wire` is still denied while
// `internal/adapter/kafka` is allowed.
//
// The Redis entries arrived in Phase 7.5 and are two rather than three: the
// Redis composition never reads internal/service/redis, because every fact it
// branches on — whether the endpoint demanded authentication, whether it
// identified itself as a Sentinel — comes from the adapter's own normalized
// answer rather than from an attribute on the graph. A composition root that
// read the vocabulary would be reading evidence it had just written.
func TestTheRunImportsOnlyTheLayersItComposes(t *testing.T) {
	allowed := map[string]bool{
		"github.com/hakanaltindag/svcdoctor/internal/domain":              true,
		"github.com/hakanaltindag/svcdoctor/internal/probe":               true,
		"github.com/hakanaltindag/svcdoctor/internal/probe/dns":           true,
		"github.com/hakanaltindag/svcdoctor/internal/probe/tcp":           true,
		"github.com/hakanaltindag/svcdoctor/internal/probe/transport":     true,
		"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres":    true,
		"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka":       true,
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis":           true,
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres":  true,
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka":     true,
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis/transport": true,
		"github.com/hakanaltindag/svcdoctor/internal/security":            true,
		"github.com/hakanaltindag/svcdoctor/internal/vocabulary":          true,
		"github.com/hakanaltindag/svcdoctor/internal/service/kafka":       true,
		// Phase 7.5. A third service adds its adapter and its diagnosis rules
		// and nothing else: internal/service/redis is absent because the Redis
		// composition reads the adapter's own answers rather than the graph, and
		// internal/adapter/redis/wire stays denied for the same reason the other
		// two wire packages are -- it holds this service's only Reveal.
		"github.com/hakanaltindag/svcdoctor/internal/adapter/redis":   true,
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis/redis": true,
		// Phase 8.2. A fourth service adds the same two layers and nothing else.
		// internal/service/rabbitmq is absent for the reason Redis's is: the
		// composition reads the adapter's own answers rather than the graph. And
		// internal/adapter/rabbitmq/wire stays denied for the reason all four
		// wire packages are -- it holds this service's only Reveal.
		"github.com/hakanaltindag/svcdoctor/internal/adapter/rabbitmq":   true,
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq": true,
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
		// `.ID()` counts, and it was the hole. This guard originally matched
		// only names containing "evidence", which covers `x.Evidence()` and the
		// `domain.EvidenceID` conversion but misses the spelling a graph walk
		// actually uses:
		//
		//	strings.HasPrefix(string(node.ID()), "kafka.broker_advertised")
		//
		// Neither `node` nor `ID` contains the word, so topology inference by
		// identifier prefix — which ADR 0019 forbids and ADR 0051 section 4
		// rules out — passed this test. Found by mutating the composition, not
		// by reading it, which is the argument for running the mutation at all.
		//
		// `ID` is matched as a selector name rather than as a substring, so a
		// field called `identity` does not trip it.
		if sel, ok := node.(*ast.SelectorExpr); ok && sel.Sel.Name == "ID" {
			found = true
		}
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

// TestTheRunCreatesExactlyOneKindOfEvidence pins the narrowed authority of
// ADR 0042 section 3.
//
// Phase 4.8b banned evidence construction here outright, and that guard was right
// about everything it defended: stages record their own observations, and a
// second representation of which path was selected is what ADR 0013 refuses.
//
// ADR 0042 opens exactly one hole in it. The run may create the L0
// requested-target anchor, because it is the only layer holding the operator's
// logical endpoint, and without it a generic transport rule can neither identify
// the operator's sweep nor name its subject. Everything else stays banned:
//
//   - no finding, ever. Orchestration that diagnoses is not orchestration.
//   - no attribute of any kind. The anchor's subject is the whole fact.
//   - no parent or blockedBy edge. The run declares a cause through
//     transport.Params.Parent and the producer records the edge.
//   - no second evidence node, not even another anchor.
//
// The hole is an allowlist of one function in one file, checked structurally, so
// widening it means editing this test — which is the point.
func TestTheRunCreatesExactlyOneKindOfEvidence(t *testing.T) {
	// Banned everywhere, with no exception anywhere.
	banned := map[string]bool{
		"AddParent": true, "AddBlockedBy": true, "NewFinding": true,
		"StringAttr": true, "BoolAttr": true, "IntAttr": true,
		"IdentityAttr": true, "HostAttr": true, "StringListAttr": true,
	}
	// Banned everywhere except the one authorized site below.
	restricted := map[string]bool{"NewEvidence": true, "AddEvidence": true}

	const (
		authorizedFile = "target.go"
		authorizedFunc = "recordRequestedTarget"
	)

	counts := map[string]int{}

	for _, name := range productionFiles(t) {
		file := parse(t, name)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			authorized := name == authorizedFile && fn.Name.Name == authorizedFunc

			ast.Inspect(fn, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch {
				case banned[sel.Sel.Name]:
					t.Errorf("%s: %s calls %s; orchestration records no relationship, "+
						"attribute or finding", name, fn.Name.Name, render(sel))
				case restricted[sel.Sel.Name] && !authorized:
					t.Errorf("%s: %s calls %s; only %s in %s may construct evidence "+
						"(ADR 0042 section 3)",
						name, fn.Name.Name, render(sel), authorizedFunc, authorizedFile)
				case restricted[sel.Sel.Name]:
					counts[sel.Sel.Name]++
				}
				return true
			})
		}
	}

	// The allowlist is one *site*, not one function that may grow. Two anchors
	// in one run is mutation B, and it starts by being constructible.
	for _, call := range []string{"NewEvidence", "AddEvidence"} {
		if counts[call] != 1 {
			t.Errorf("%s is called %d times in %s; the anchor is minted exactly once",
				call, counts[call], authorizedFile)
		}
	}
}

// TestTheRunNamesNoProvenanceConcept pins that the anchor did not become Origin.
//
// ADR 0042 section 10 rests on a distinction that is easy to state and easy to
// erode: the anchor records which *execution* the operator caused, and `Origin`
// would record how an arbitrary *subject* entered the run. The first is one node
// this package writes; the second is a per-node provenance field that
// REPORT_SCHEMA.md defers and that the advertised-back counterexample refutes.
//
// A field, variable or parameter named for provenance here would be the first
// step of that erosion, and it would arrive looking helpful.
//
// The check is over the AST, so the doc comments above — which discuss
// provenance at length — do not trip it.
func TestTheRunNamesNoProvenanceConcept(t *testing.T) {
	forbidden := map[string]string{
		"Origin":     "provenance is not recorded per node; the anchor names an execution",
		"origin":     "provenance is not recorded per node; the anchor names an execution",
		"Provenance": "the graph records derivation, never provenance",
		"provenance": "the graph records derivation, never provenance",
		"SweepScope": "a scope labels an execution and must never be read for meaning",
	}

	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if why, banned := forbidden[ident.Name]; banned {
				t.Errorf("%s names %s: %s", name, ident.Name, why)
			}
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

// adapterAuthAccessors are the adapter methods that may decide the candidate
// class.
//
// One per service that has a class to decide, and each is that adapter's own
// **normalized** answer rather than a protocol detail:
//
//	AuthMethod    PostgreSQL. The endpoint names a method, so the boolean is
//	              derived from it by comparing against authMethodNone.
//	AuthRequired  Redis. The endpoint names no method — it either refuses the
//	              credential-free capability command with NOAUTH or it does not —
//	              so the adapter's normalized answer already is the boolean.
//	              RabbitMQ reuses the name in Phase 8.2 and answers it from the
//	              protocol rather than from an observation: AMQP 0-9-1 has no
//	              credential-free capability exchange, so every endpoint demands
//	              authentication. The answer is constant and still belongs to the
//	              adapter, because a composition root deciding it would be
//	              inventing the partition ADR 0041 §8.1 requires evidence for.
//
// A name earns a place here when a service's adapter genuinely answers the
// question. Adding one is the review a fourth service is forced through, and
// TestEveryAdapterAuthAccessorIsUsed fails if a name here stops being used.
var adapterAuthAccessors = map[string]bool{
	"AuthMethod":   true,
	"AuthRequired": true,
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
//
// # Phase 7.5 widened what it accepts, and narrowed how
//
// It asserted one method *name*, which described PostgreSQL rather than the
// invariant. Redis answers the same question through a differently named
// accessor because its protocol has no authentication method to compare. So the
// name is now looked up in adapterAuthAccessors, and the expression must be a
// **call** — a literal, a constant, a package-level variable and a field read all
// fail, which is what the original check was really for.
func TestTheCandidateClassComesFromTheAdapter(t *testing.T) {
	assignments := 0
	used := map[string]bool{}

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
			assignments++
			accessor, ok := adapterAuthCall(kv.Value)
			if !ok {
				t.Errorf("%s sets authRequired from %s; it must be a call to one of the "+
					"adapter accessors in adapterAuthAccessors", name, render(kv.Value))
				return true
			}
			used[accessor] = true
			return true
		})
	}

	if assignments == 0 {
		t.Error("no candidate assigns authRequired; the class partition has no source")
	}
}

// TestEveryAdapterAuthAccessorIsUsed keeps the allowlist from outliving its
// producers.
//
// An entry nobody uses is an allowance nobody reviewed, and it would silently
// pre-authorize a name for whoever wrote it next. This is the non-vacuity half of
// the guard above: widening the list only holds if every widening is spent.
func TestEveryAdapterAuthAccessorIsUsed(t *testing.T) {
	used := map[string]bool{}
	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "authRequired" {
				return true
			}
			if accessor, ok := adapterAuthCall(kv.Value); ok {
				used[accessor] = true
			}
			return true
		})
	}
	for accessor := range adapterAuthAccessors {
		if !used[accessor] {
			t.Errorf("adapterAuthAccessors allows %q but no composition uses it; "+
				"remove it rather than leaving a pre-authorized name", accessor)
		}
	}
}

// adapterAuthCall reports the allowlisted adapter accessor an expression calls.
//
// It requires a CallExpr whose function is a selector, so `session.AuthRequired`
// without parentheses, a bare `true`, and a package constant all fail. That is
// deliberate: the invariant is that the value was *answered by the adapter for
// this run*, not merely that it is spelled like one.
func adapterAuthCall(n ast.Node) (string, bool) {
	name := ""
	ast.Inspect(n, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return name == ""
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return name == ""
		}
		if adapterAuthAccessors[sel.Sel.Name] {
			name = sel.Sel.Name
			return false
		}
		return true
	})
	return name, name != ""
}

// TestTheRunChecksItsBudgetBeforeTheCredentialedStep pins the ordering ADR 0046
// depends on.
//
// A cancelled run must record no authentication node at all, so that the graph a
// cancelled run leaves stays distinguishable from one where the run held no
// credential. Since Phase 4.11b the adapter records a node whenever it is
// *entered*, which means the only thing keeping the two apart is that
// orchestration does not enter it after the budget has ended.
//
// Timing a cancellation to land in that window is not reproducible, so the
// ordering is asserted from the source instead: within measurePostgres, the
// context check precedes the call that continues the selected path.
func TestTheRunChecksItsBudgetBeforeTheCredentialedStep(t *testing.T) {
	var fn *ast.FuncDecl
	for _, name := range productionFiles(t) {
		for _, decl := range parse(t, name).Decls {
			if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "measurePostgres" {
				fn = d
			}
		}
	}
	if fn == nil {
		t.Fatal("measurePostgres not found")
	}

	var ctxCheck, continueCall token.Pos
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Err" {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "ctx" && ctxCheck == 0 {
				ctxCheck = call.Pos()
			}
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "continuePath" {
			continueCall = call.Pos()
		}
		return true
	})

	if ctxCheck == 0 {
		t.Fatal("measurePostgres no longer checks ctx.Err(); a cancelled run would enter " +
			"the authentication step and record a missing-input node")
	}
	if continueCall == 0 {
		t.Fatal("measurePostgres no longer calls continuePath")
	}
	if ctxCheck > continueCall {
		t.Error("the budget is checked after the credentialed step is entered; a cancelled " +
			"run would be recorded as having no credential configured")
	}
}
