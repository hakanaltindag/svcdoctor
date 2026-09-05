package security_test

import (
	"go/ast"
	gobuild "go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	adapterkafka "github.com/hakanaltindag/svcdoctor/internal/adapter/kafka"
)

// Kafka production closure guard.
//
// # What this file used to be, and why it is not that any more
//
// Until Phase 6.1c it asserted the opposite of what it asserts now: that
// `internal/adapter/kafka` had **zero** production importers and that no
// `DiagnoseKafka` existed. That negative was the ADR 0054 gate in executable
// form, and it did its job — it stopped the first attempt at Kafka composition,
// which would have let a rejected Kafka credential arrive as `findings: []`,
// `status: OK`, exit 0.
//
// Phase 6.1c-P2 landed the owners, so the gate's condition is satisfied and the
// negative is now false by design. **It was not deleted and it was not
// weakened.** ADR 0054 section 5 asks for a per-service closure test once the
// service becomes production-reachable, and this is it: the same file, guarding
// the same boundary, from the other side. Where it used to say *nothing may
// reach this*, it now says *exactly this reaches it, exactly these rules explain
// it, and exactly one path may spend a credential.*
//
// # What is proven here, and what is proven elsewhere
//
// These are **static** guards. They read the composition root's source and the
// adapter's type surface, and they can therefore prove structural properties on
// every build without a network: which rules are wired, how many authentication
// call sites exist, whether a credential can be minted here, whether a transport
// plan has anywhere to put a secret.
//
// They deliberately do **not** try to prove behaviour statically. That a
// malicious Metadata response produces zero credential bytes, that a run opens
// and closes a balanced number of sockets, and that an advertised endpoint
// receives no Kafka protocol byte are **runtime** properties, proven against
// real sockets in `kafka_composition_test.go` beside this file, and — for
// ADR 0051's completeness predicate — against constructed graphs in
// `internal/app/kafkacompleteness_test.go`. Each guard below names its runtime
// counterpart where one exists, so the split is legible rather than implied.

// The module path every internal import is written against.
const modulePath = "github.com/hakanaltindag/svcdoctor"

// The package whose production reachability this file governs.
const kafkaAdapter = modulePath + "/internal/adapter/kafka"

// The one composition root authorized to reach it.
const kafkaCompositionRoot = modulePath + "/internal/app"

// The file and function that hold Kafka composition.
const (
	kafkaCompositionFile  = "internal/app/kafka.go"
	kafkaCompositionEntry = "DiagnoseKafka"
)

// TestExactlyOneProductionPackageReachesTheKafkaAdapter is the transformed
// import guard.
//
// The old assertion was "no production package imports the adapter". The new one
// is strictly stronger in the direction that matters: **exactly one does, and it
// is the composition root.** A renderer, the CLI, a platform collector or a
// second adapter acquiring that import would still fail, and so would a second
// composition root appearing beside `internal/app`.
//
// The reach is what creates the exposure, so the reach is what this asserts
// about. A CLI route is not the boundary — ADR 0054 is about production
// application reachability rather than user routing, which is why "the Kafka CLI
// does not exist yet" was rejected as a defence when Phase 6.1c was first
// stopped.
func TestExactlyOneProductionPackageReachesTheKafkaAdapter(t *testing.T) {
	root := repositoryRoot(t)

	var importers []string
	for _, dir := range productionPackages(t, root) {
		path := importPath(t, root, dir)
		// The adapter and its own wire package are what this governs, not what
		// it constrains.
		if strings.HasPrefix(path, kafkaAdapter) {
			continue
		}

		pkg, err := gobuild.ImportDir(dir, gobuild.ImportComment)
		if err != nil {
			// A directory with no buildable Go files is not a package.
			continue
		}
		// pkg.Imports covers production files only; test imports live in
		// TestImports and XTestImports and are deliberately not consulted. Tests
		// exercising the adapter are how it is verified at all.
		if slices.Contains(pkg.Imports, kafkaAdapter) {
			importers = append(importers, path)
		}
	}

	if !slices.Equal(importers, []string{kafkaCompositionRoot}) {
		t.Errorf("production importers of %s = %v, want exactly [%s].\n\n"+
			"Every Kafka outcome is reachable from whatever imports the adapter. "+
			"One composition root is reviewable; a second one, or an import from "+
			"the CLI or a renderer, is a second place credentials and sockets are "+
			"sequenced. See ADR 0054.",
			kafkaAdapter, importers, kafkaCompositionRoot)
	}
}

// TestExactlyOneKafkaCompositionEntryPointExists replaces the old
// "no DiagnoseKafka exists" assertion with "exactly one does, and it is here".
//
// A second entry point is the failure this guards: two composition roots means
// two credential-authority decisions, two path selections and two chances for
// one of them to be the unreviewed one.
func TestExactlyOneKafkaCompositionEntryPointExists(t *testing.T) {
	root := repositoryRoot(t)

	var declared []string
	for _, dir := range productionPackages(t, root) {
		pkg, err := gobuild.ImportDir(dir, 0)
		if err != nil {
			continue
		}
		for _, name := range pkg.GoFiles {
			path := filepath.Join(dir, name)
			for _, fn := range functionsIn(t, path) {
				if fn.Name.Name == kafkaCompositionEntry {
					relative, err := filepath.Rel(root, path)
					if err != nil {
						t.Fatalf("relating %s: %v", path, err)
					}
					declared = append(declared, filepath.ToSlash(relative))
				}
			}
		}
	}

	if !slices.Equal(declared, []string{kafkaCompositionFile}) {
		t.Errorf("%s is declared in %v, want exactly [%s]",
			kafkaCompositionEntry, declared, kafkaCompositionFile)
	}
}

// TestTheCompositionWiresEveryOwnerOfWhatItCanProduce is the ADR 0054 closure
// assertion in its positive form, and it is the reason this file exists at all.
//
// `DiagnoseKafka` makes six families of evidence production-reachable in one
// commit: generic DNS, generic TCP, generic requested-target TLS, the four Kafka
// protocol steps, advertised-broker reachability and unusable advertisements.
// Every one of those has an owner, and this asserts that the composition
// actually **wires** all of them — because an owner that exists and is not wired
// is indistinguishable, in the report, from an owner that does not exist.
//
// The list is exact in both directions. A rule appearing here that the
// composition does not wire is a silence; a rule the composition wires that is
// not listed here is an unreviewed claim reaching a report.
func TestTheCompositionWiresEveryOwnerOfWhatItCanProduce(t *testing.T) {
	want := []string{
		// The generic failure boundary, activated in Phase 10.1b (ADR 0079).
		"diagnosis.FailureBoundary",
		// Generic requested-target transport. ADR 0043 owns DNS and TCP;
		// ADR 0053 owns the TLS handshake that Kafka bootstrap composition is
		// the first production producer of.
		"diagnosistransport.DNS",
		"diagnosistransport.TCP",
		"diagnosistransport.TLS",
		// The four Kafka protocol steps, on a closed (step, state, class) table.
		// Phase 6.1c-P2.
		"diagnosiskafka.Protocol",
		// Advertised topology. ADR 0034.
		"diagnosiskafka.AdvertisedEndpointUnreachable",
		"diagnosiskafka.UnusableAdvertisement",
		// Phase 10.2. Both read the advertised sweeps and own an outcome the
		// per-endpoint rules do not: the scope of the failure across the
		// advertised set, and the suitability hypothesis that scope admits.
		"diagnosiskafka.AdvertisedTopologyReachability",
		"diagnosiskafka.AdvertisedTopologyUnsuitable",
	}

	wantIDs := []string{
		"diag/failure-boundary",
		"transport/dns",
		"transport/tcp",
		"transport/tls",
		"kafka/protocol",
		"kafka/advertised-endpoint",
		"kafka/unusable-advertisement",
		"kafka/advertised-topology",
		"kafka/advertised-suitability",
	}

	gotIDs, got := rulesWiredIn(t, filepath.Join(repositoryRoot(t), kafkaCompositionFile))

	if !slices.Equal(got, want) {
		t.Errorf("DiagnoseKafka wires %v,\nwant %v.\n\n"+
			"An outcome whose owner is not wired reaches the report as findings=[] "+
			"and status OK, which is precisely what ADR 0054 forbids.", got, want)
	}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Errorf("DiagnoseKafka registers %v,\nwant %v.\n\n"+
			"A rule identity is stable, lower-case and hyphenated, and the generic "+
			"transport rules must carry the same identity in every composition root "+
			"(ADR 0080 section 2.5, ADR 0081 section 2.6).", gotIDs, wantIDs)
	}
}

// TestTheCompositionMintsNoCredential is ADR 0050 section 4 made mechanical.
//
// > Discovery may create evidence; discovery must not create secret authority.
//
// `security.NewCredential` is unrestricted by design: any package holding a
// `Secret` can mint a credential bound to any endpoint. The composition root is
// **the only layer that could rebind one** — it is the layer that learns
// advertised endpoints and the layer that calls `Authenticate` — so the whole of
// ADR 0050's threat model reduces to whether this package ever constructs a
// second credential.
//
// It does not, and it cannot start to without editing this test. The credential
// arrives as one parameter, bound by whoever configured the run, and
// `KafkaParams.validate` refuses one bound anywhere but the logical target.
//
// The runtime counterpart is
// `TestAMaliciousMetadataResponseGetsNoCredential`, which drives a hostile
// broker and counts bytes on the attacker's socket.
func TestTheCompositionMintsNoCredential(t *testing.T) {
	root := repositoryRoot(t)

	pkg, err := gobuild.ImportDir(filepath.Join(root, "internal/app"), 0)
	if err != nil {
		t.Fatalf("describing internal/app: %v", err)
	}
	for _, name := range pkg.GoFiles {
		path := filepath.Join(root, "internal/app", name)
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// SecretFor is checked on **any** receiver, and the two halves of
			// this switch differ for that reason. `security.NewCredential` is a
			// package function, so matching the package identifier is exact.
			// `SecretFor` is a method on a value the composition already holds,
			// written `params.Credential.SecretFor(...)` — whose receiver is
			// itself a selector, not an identifier named `security`. Requiring
			// the package prefix here would have made the guard miss the only
			// spelling the call can actually have.
			if sel.Sel.Name == "SecretFor" {
				// Reaching into a credential for its secret is the adapter's
				// job, immediately before the wire boundary and after the
				// mechanism guard, the input check, the channel policy and the
				// endpoint binding have all passed. A SecretFor here would sit
				// above all four, and the endpoint it was given would be
				// whichever one this layer happened to be holding — which, after
				// Metadata, includes endpoints a peer chose.
				t.Errorf("%s calls SecretFor.\n\n"+
					"Only internal/adapter/kafka may resolve a secret, and only "+
					"for the logical endpoint carried on the session. See ADR 0028 "+
					"section 2 and ADR 0050 section 4.", name)
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "security" {
				return true
			}
			switch sel.Sel.Name {
			case "NewCredential", "NewSecret", "Reveal":
				t.Errorf("%s calls security.%s.\n\n"+
					"The composition root receives one credential bound to the "+
					"endpoint the operator named and never constructs another. "+
					"Minting one here is how a Metadata-discovered broker would "+
					"acquire credential authority. See ADR 0050 section 4.",
					name, sel.Sel.Name)
			}
			return true
		})
	}
}

// TestAtMostOneAuthenticationCallSiteExists bounds credential cardinality
// structurally.
//
// One `kafka.Authenticate` call site, and it is not inside a loop. Those two
// facts together are what make "at most one credential-bearing attempt per run"
// a property of the source rather than of a comment: `Authenticate` takes
// exactly one session by design (ADR 0028 section 1), so a second attempt has to
// be either a second call site or a loop around this one, and both are caught
// here.
//
// **A credential-bearing retry is not an L2 or L3 transport retry.** It spends
// an attempt against whatever counts them and, in a directory-backed deployment,
// is a step towards lockout. Adding one needs its own security decision, and it
// would start by making this test fail.
//
// The runtime counterpart is `TestSeveralUsableBootstrapPathsProduceOneAttempt`.
func TestAtMostOneAuthenticationCallSiteExists(t *testing.T) {
	root := repositoryRoot(t)
	file := parseFile(t, filepath.Join(root, kafkaCompositionFile))

	sites := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selectorName(call.Fun) == "kafka.Authenticate" {
			sites++
		}
		return true
	})
	if sites != 1 {
		t.Errorf("kafka.Authenticate has %d call sites in %s, want exactly 1",
			sites, kafkaCompositionFile)
	}

	// A single call site inside a loop is still credential spraying, so the
	// enclosing statements are checked too. Every loop body in the file is
	// searched rather than only the ones that look relevant.
	ast.Inspect(file, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.ForStmt:
			body = loop.Body
		case *ast.RangeStmt:
			body = loop.Body
		default:
			return true
		}
		ast.Inspect(body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name := selectorName(call.Fun); name == "kafka.Authenticate" || name == "kafka.Metadata" {
				t.Errorf("%s calls %s inside a loop.\n\n"+
					"Authentication is per run, not per path: one credential, one "+
					"attempt, whatever the target resolved to. See ADR 0028.",
					kafkaCompositionFile, name)
			}
			return true
		})
		return true
	})
}

// TestTheAdvertisedSweepHasNowhereToPutASecret proves ADR 0050's structural half
// by inspecting the type the composition must fill in.
//
// `MeasureAdvertised` takes a context, a graph builder, a list of
// advertisements and a `TransportPlan`. The first three cannot carry credential
// material by construction; the plan is the only one with fields, so the plan is
// what this checks. **There is no parameter for a credential to occupy**, and a
// future field that changed that would have to pass here first.
//
// The check is by reflection over the real struct rather than over its source,
// so an embedded type or a field added in another file is covered too.
//
// The runtime counterpart is `TestAdvertisedEndpointsReceiveNoKafkaByte`, which
// counts what arrives on an advertised listener's socket.
func TestTheAdvertisedSweepHasNowhereToPutASecret(t *testing.T) {
	plan := reflect.TypeOf(adapterkafka.TransportPlan{})

	forbidden := []string{
		"credential", "secret", "password", "identity", "principal",
		"token", "sasl", "mechanism", "session", "auth",
	}

	for i := range plan.NumField() {
		field := plan.Field(i)
		lower := strings.ToLower(field.Name)
		for _, word := range forbidden {
			if strings.Contains(lower, word) {
				t.Errorf("kafka.TransportPlan has a field named %s.\n\n"+
					"The advertised sweep is transport-only, and its guarantee is "+
					"that nothing it is handed can carry credential material. "+
					"See ADR 0050 section 1.", field.Name)
			}
		}
		if strings.Contains(field.Type.String(), "security.") {
			t.Errorf("kafka.TransportPlan field %s has type %s.\n\n"+
				"A security type in the advertised transport plan is credential "+
				"authority travelling down a derivation edge, which ADR 0050 "+
				"section 3 refuses.", field.Name, field.Type)
		}
	}
}

// TestTheProtocolClosureTestExists is the honest half of ADR 0054 section 5.
//
// The enumeration of every production-reachable Kafka protocol outcome lives
// with the table it checks, in `internal/diagnosis/kafka`, because that is the
// only place both halves — the owners and the list derived from the producers —
// are in scope. This asserts that it is still there and still checks both
// directions, so the closure requirement cannot be satisfied by a test that
// quietly stopped enumerating.
//
// It is a pointer, not a re-implementation. Duplicating the enumeration here
// would create a second list free to drift from the first, which is the failure
// mode the single closed table exists to prevent.
func TestTheProtocolClosureTestExists(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "internal/diagnosis/kafka/protocol_test.go")
	source, err := os.ReadFile(path) //nolint:gosec // a repository path this test built.
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	for _, required := range []string{
		"func TestTheAuthorizedTableIsExactlyTheProducedOutcomes",
		"is produced and has no owner",
		"is mapped but no producer emits it",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("internal/diagnosis/kafka/protocol_test.go no longer contains %q.\n\n"+
				"ADR 0054 section 5 requires a closure test that fails in both "+
				"directions: a produced outcome with no owner, and an owner for an "+
				"outcome no producer emits.", required)
		}
	}
}

// --- source helpers ---------------------------------------------------------

// rulesWiredIn returns the identities and the rule expressions a composition
// root registers, in source order.
//
// # Why it reads an Add chain rather than NewEngine's arguments
//
// It read NewEngine's arguments until Phase 10.1a. ADR 0080 sections 2.4 and 2.5
// gave every rule a stable identity and made a rule set a frozen, identified
// collection, so the wiring moved into a `diagnosis.NewRuleSet().Add(id, rule)`
// chain and NewEngine now takes the frozen result. The property this guard
// exists for is unchanged and so is its exactness in both directions: a produced
// outcome whose owner is not wired reaches a report as silence (ADR 0054).
//
// Both halves are returned because both can drift. A misspelled identity would
// not change which rules ran today, but it would silently give one rule two
// names across the four composition roots that share the generic transport
// rules — and the merge tie-break of ADR 0081 section 2.6 is defined on that
// name.
func rulesWiredIn(t *testing.T, path string) (ids []string, rules []string) {
	t.Helper()

	sets := 0
	ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selectorName(call.Fun) == "diagnosis.NewRuleSet" {
			sets++
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Add" || len(call.Args) != 2 {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			t.Errorf("%s registers a rule under a non-literal identity; "+
				"a rule identity must never be derived from a runtime value "+
				"(ADR 0081 section 2.6)", path)
			return true
		}
		ids = append(ids, strings.Trim(literal.Value, `"`))
		rules = append(rules, selectorName(call.Args[1]))
		return true
	})

	switch {
	case sets == 0:
		t.Fatalf("%s builds no diagnosis rule set", path)
	case sets > 1:
		t.Errorf("%s builds %d rule sets; one composition wires one engine", path, sets)
	}

	// The chain is written outermost-call-first in the AST, which is the reverse
	// of how a reader sees it. Restoring source order is what makes the expected
	// list in each guard readable beside the composition it pins.
	slices.Reverse(ids)
	slices.Reverse(rules)
	return ids, rules
}

// selectorName renders `pkg.Name`, or the empty string for anything else.
func selectorName(n ast.Node) string {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name + "." + sel.Sel.Name
}

// functionsIn returns the top-level function declarations of one file.
func functionsIn(t *testing.T, path string) []*ast.FuncDecl {
	t.Helper()

	var out []*ast.FuncDecl
	for _, decl := range parseFile(t, path).Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			out = append(out, fn)
		}
	}
	return out
}

func parseFile(t *testing.T, path string) *ast.File {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return file
}

// repositoryRoot walks up from the test's directory to the module root.
func repositoryRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("locating the working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test directory")
		}
		dir = parent
	}
}

// productionPackages returns every directory in the module that may hold
// production Go sources.
func productionPackages(t *testing.T, root string) []string {
	t.Helper()

	var dirs []string
	for _, tree := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, tree),
			func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() && entry.Name() != "testdata" {
					dirs = append(dirs, path)
				}
				if entry.IsDir() && entry.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			})
		if err != nil {
			t.Fatalf("walking %s: %v", tree, err)
		}
	}
	if len(dirs) == 0 {
		t.Fatal("no package directories found; the guard would pass vacuously")
	}
	return dirs
}

// importPath maps a directory back to the import path it is reached by.
func importPath(t *testing.T, root, dir string) string {
	t.Helper()

	relative, err := filepath.Rel(root, dir)
	if err != nil {
		t.Fatalf("relating %s to %s: %v", dir, root, err)
	}
	return modulePath + "/" + filepath.ToSlash(relative)
}

// TestTheSharedSCRAMCoreIsWhereItWasAuthorized is the positive successor to the
// Phase 6.2a gate.
//
// # What this replaced, and why the swap had to be atomic
//
// Until Phase 6.2 this file carried TestNoSharedSCRAMPackageExists, which failed
// the build if `internal/sasl`, `internal/scram` or `internal/crypto/scram`
// existed at all. That negative was the security review's gate in executable
// form: extraction moves credential-derived material across a package boundary
// for the first time, and the review had to be Accepted before the package could
// be written.
//
// ADR 0055 said the guard should be deleted in the commit that recorded the
// review's acceptance. **ADR 0056 section 13 corrected that**, and the
// correction is the reason this test reads the way it does: deleting the
// negative on acceptance would have left every commit between the review and the
// implementation with no guard at all — the negative gone, the positive ones
// impossible because the package they describe did not yet exist.
//
// So the swap happened in one change-set. The package, the depguard allowlist,
// this test and the Reveal counters below all arrived together, and there was
// never a state in which neither held.
//
// This test asserts location only. The core's own guards_test.go asserts its
// imports, its exported surface, its callback cardinality and its state shape,
// from inside the package where the AST is in reach.
func TestTheSharedSCRAMCoreIsWhereItWasAuthorized(t *testing.T) {
	root := repositoryRoot(t)

	// The one authorized location, from ADR 0056 section 1.
	authorized := filepath.Join(root, "internal/sasl/scram")
	if info, err := os.Stat(authorized); err != nil || !info.IsDir() {
		t.Fatalf("internal/sasl/scram is missing.\n\n"+
			"Phase 6.2 extracted the RFC 5802 core there and every guard in this file "+
			"and in internal/sasl/scram/guards_test.go describes that package. If it was "+
			"moved, the guards describe nothing. (%v)", err)
	}

	// The locations the old negative guard named are still forbidden, because
	// each would be a second SCRAM implementation rather than a move of this
	// one.
	for _, forbidden := range []string{"internal/scram", "internal/crypto/scram"} {
		if _, err := os.Stat(filepath.Join(root, forbidden)); err == nil {
			t.Errorf("%s exists. The shared SCRAM core lives at internal/sasl/scram and "+
				"nowhere else; a second one would drift from the vectors that pin this one.",
				forbidden)
		}
	}
}

// TestRevealHasOneProductionCallSitePerService is the repository-wide credential
// surface. It is new in Phase 6.2 and was called
// TestRevealHasExactlyTwoProductionCallSites until Phase 7.5 -- the name ADR 0054
// section 4 still cites, deliberately left as written there because that record
// says what was true when it was made.
//
// # Why the name changed rather than the number
//
// The invariant was never "two". It is **one authorized reveal per service,
// inside that service's wire package, and nowhere else**, and two was a
// consequence of there being two services. Redis made that visible: the total
// moved to three and not one clause of the actual contract changed. The total is
// now derived from the authorized set below, so the set is the single place a
// service is admitted and the count cannot drift away from it.
//
// # The gap this closes
//
// Before this test, two mechanisms bounded `security.Reveal`. golangci-lint's
// forbidigo rule confines the call to `internal/adapter/*/wire/`, and
// TestPostgresCredentialSurfaceIsExactlyTwoCalls pins PostgreSQL at exactly one.
// **Nothing pinned Kafka's count, and nothing asserted the total.** A third
// reveal inside either wire package, or a whole third wire package, would have
// passed every check that existed.
//
// Phase 6.2a found that gap while arguing about whether extraction would widen
// the credential surface. It does not — but the argument only holds if the count
// is a property of the source rather than of a sentence in an ADR.
func TestRevealHasOneProductionCallSitePerService(t *testing.T) {
	root := repositoryRoot(t)

	// Where each call is allowed, and nowhere else.
	//
	// # Widening this map is the only way a service is admitted
	//
	// The invariant is **one authorized reveal per service, inside that
	// service's wire package, and nowhere else**. The total below is derived
	// from this map's length rather than written down, which is what makes a
	// blind count bump impossible: admitting a service means naming the exact
	// file that may open a secret, and a fifth service whose wire package is not
	// listed still fails on the unauthorized-path branch.
	//
	// Phase 8.2 added the RabbitMQ entry. It qualifies for the same reason the
	// other three do and for no weaker one: RabbitMQ BASIC transmits a password
	// in a SASL PLAIN response (ADR 0068), so it needs exactly one site, in its
	// own wire package, immediately before the bytes go on the socket. It does
	// not widen the contract — `internal/adapter/rabbitmq/wire` has its own
	// package-local guard asserting the same count of one, so the file is pinned
	// from both sides.
	authorized := map[string]bool{
		"internal/adapter/postgres/wire/scram.go":      true,
		"internal/adapter/kafka/wire/authenticate.go":  true,
		"internal/adapter/redis/wire/auth.go":          true,
		"internal/adapter/rabbitmq/wire/connection.go": true,
	}

	found := map[string]int{}

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "bin", "dist", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}

		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		relative = filepath.ToSlash(relative)

		// internal/security defines Reveal, and its own leak matrix proves what
		// it returns. Those calls are in-package and are not written as
		// "security.Reveal".
		if strings.HasPrefix(relative, "internal/security/") {
			return nil
		}

		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Reveal" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "security" {
				return true
			}
			found[relative]++
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}

	total := 0
	for path, count := range found {
		total += count
		if !authorized[path] {
			t.Errorf("%s calls security.Reveal %d time(s).\n\n"+
				"Only a service adapter's wire package may open a secret, immediately "+
				"before the value goes on the socket. See ADR 0027 and ADR 0056 section 12.",
				path, count)
			continue
		}
		if count != 1 {
			t.Errorf("%s calls security.Reveal %d times, want exactly 1", path, count)
		}
	}
	for path := range authorized {
		if found[path] == 0 {
			t.Errorf("%s no longer calls security.Reveal.\n\n"+
				"If authentication moved, this guard now describes nothing and must be "+
				"updated deliberately rather than left passing vacuously.", path)
		}
	}

	if total != len(authorized) {
		t.Errorf("found %d production security.Reveal call site(s), want exactly %d "+
			"(one per service, each in its wire package)", total, len(authorized))
	}
}

// TestTheSharedSCRAMCoreOpensNoSecret is the other half of the Reveal contract.
//
// The core cannot import internal/security — depguard and the package's own
// import guard both say so — which makes Reveal and SecretFor unreachable there
// by construction. This asserts it from outside the package as well, because the
// property is what the whole Model D decision rests on and a single enforcement
// point for it would be one edit away from silence.
func TestTheSharedSCRAMCoreOpensNoSecret(t *testing.T) {
	core := filepath.Join(repositoryRoot(t), "internal/sasl/scram")

	entries, err := os.ReadDir(core)
	if err != nil {
		t.Fatalf("reading internal/sasl/scram: %v", err)
	}

	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		inspected++

		ast.Inspect(parseFile(t, filepath.Join(core, name)), func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			switch ident.Name {
			case "Reveal", "SecretFor", "NewSecret", "NewCredential":
				t.Errorf("internal/sasl/scram/%s names %q.\n\n"+
					"The shared core receives a derivation callback, never a credential. "+
					"See ADR 0055 and ADR 0056 section 12.", name, ident.Name)
			}
			return true
		})
	}

	if inspected == 0 {
		t.Fatal("no production files were inspected; this guard would pass vacuously")
	}
}

// TestTheCompositionSecuritySuiteStillExists is the reciprocal of
// TestTheGuardFileStillExists in kafka_composition_test.go.
//
// The two files vouch for each other, and the reason is ADR 0054 section 6: a
// guard cannot protect itself, and the failure mode this whole boundary exists
// to prevent is a guard being deleted to make a commit pass. Static analysis
// cannot decide reachability, so the mechanism available is mutual reference —
// deleting either file fails the other, and deleting both is a diff no reviewer
// can miss.
func TestTheCompositionSecuritySuiteStillExists(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "test/security/kafka_composition_test.go")
	source, err := os.ReadFile(path) //nolint:gosec // a repository path this test built.
	if err != nil {
		t.Fatalf("the Kafka composition security suite is missing: %v", err)
	}
	for _, required := range []string{
		"func TestAMaliciousMetadataResponseGetsNoCredential",
		"func TestSeveralUsableBootstrapPathsProduceOneAttempt",
		"func TestAnUnverifiedChannelWithholdsTheCredential",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("test/security/kafka_composition_test.go no longer contains %q", required)
		}
	}
}
