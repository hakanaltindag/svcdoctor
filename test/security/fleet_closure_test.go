package security_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 9.1C sections 25 to 29: the structural closure of the multi-target
// layer.
//
// # What "closure" means here
//
// Phase 9.1A and 9.1B each added the guards their own change needed. This adds
// the ones that describe the *finished* layer: that the counts the whole
// contract is stated in have not moved, that orchestration cannot become
// diagnosis, and that credential authority has exactly the shape ADR 0072 froze.
//
// Every guard has a matching non-vacuity proof, in
// TestTheClosureGuardsCanFail, because a structural test that scans an empty
// list passes forever and looks exactly like one that passes correctly.

// ---------------------------------------------------------------------------
// Section 25: no run-level finding
// ---------------------------------------------------------------------------

// TestMTG05TheFindingCodeCountIsUnchanged pins the number the whole multi-target
// contract is stated against.
//
// # Why this did not exist before Phase 9.1C
//
// Failure classes had a count test from the start — `failureClassNames` is a
// map, so a class added without a name is a runtime hole and the count guards
// it. Finding codes are `const` declarations spread across five diagnosis
// packages with no central registry, deliberately: ADR 0009 keeps the core free
// of a global enumeration of every service's codes.
//
// The consequence is that nothing counted them, and "finding codes stay at 60"
// — which ADR 0073 section 12 makes a *decision* — was a claim in prose that no
// test could contradict. This counts them the same way the Phase 9.0 start-state
// gate did, by reading the declarations.
func TestMTG05TheFindingCodeCountIsUnchanged(t *testing.T) {
	const (
		wantTotal    = 60
		wantRabbitMQ = 11
	)

	codes := declaredFindingCodes(t)
	if len(codes) != wantTotal {
		t.Errorf("%d finding codes are declared, want %d.\n\n"+
			"ADR 0073 section 12: multi-target orchestration adds no finding code. A "+
			"configuration error is not a claim about a service, and a cancelled run "+
			"is not a claim about an endpoint. If a code was added deliberately, this "+
			"number and docs/FINDINGS.md move together.\ndeclared: %v",
			len(codes), wantTotal, sortedCodeNames(codes))
	}

	byService := map[string]int{}
	for code := range codes {
		prefix, _, found := strings.Cut(code, "_")
		if !found {
			t.Errorf("finding code %q has no service namespace", code)
			continue
		}
		byService[prefix]++
	}
	if got := byService["RABBITMQ"]; got != wantRabbitMQ {
		t.Errorf("%d RabbitMQ finding codes, want %d", got, wantRabbitMQ)
	}
	t.Logf("finding codes by namespace: %v", byService)
}

// declaredFindingCodes reads every production `domain.FindingCode = "..."`.
func declaredFindingCodes(t *testing.T) map[string]string {
	t.Helper()

	codes := map[string]string{}
	for _, pkg := range allProductionPackages(t) {
		if !strings.HasPrefix(pkg, "internal/diagnosis") {
			continue
		}
		for _, path := range productionFilesIn(t, pkg) {
			file := parseFile(t, path)
			ast.Inspect(file, func(node ast.Node) bool {
				spec, ok := node.(*ast.ValueSpec)
				if !ok || spec.Type == nil {
					return true
				}
				if !isDomainSelector(spec.Type, "FindingCode") {
					return true
				}
				for _, value := range spec.Values {
					if literal, ok := value.(*ast.BasicLit); ok {
						codes[strings.Trim(literal.Value, `"`)] = relative(t, path)
					}
				}
				return true
			})
		}
	}
	if len(codes) == 0 {
		t.Fatal("no finding code was found at all; this guard would pass vacuously")
	}
	return codes
}

func sortedCodeNames(codes map[string]string) []string {
	out := make([]string, 0, len(codes))
	for code := range codes {
		out = append(out, code)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// isDomainSelector reports whether an expression is `domain.<name>`.
func isDomainSelector(expr ast.Expr, name string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "domain"
}

// TestTheFleetLayerDeclaresNoFindingCode is section 25's structural half.
//
// ADR 0073 section 12: orchestration produces no finding. The scheduler holds
// finished reports and the aggregate wraps them; neither has evidence of
// anything, so neither may make a claim about a service.
//
// The guard reads the tree for two shapes — a `domain.FindingCode` declaration
// or conversion, and a call to `domain.NewFinding` — because those are the only
// two ways a finding can come into existence.
func TestTheFleetLayerDeclaresNoFindingCode(t *testing.T) {
	scanned := 0
	for _, pkg := range append([]string{}, fleetPackages...) {
		for _, path := range productionFilesIn(t, pkg) {
			file := parseFile(t, path)
			scanned++

			ast.Inspect(file, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.ValueSpec:
					if value.Type != nil && isDomainSelector(value.Type, "FindingCode") {
						t.Errorf("%s declares a domain.FindingCode.\n\n"+
							"A configuration error is not a claim about a service, and a "+
							"cancelled target is not a claim about an endpoint. The fleet "+
							"layer records execution states; findings belong to "+
							"internal/diagnosis, over evidence.", relative(t, path))
					}
				case *ast.CallExpr:
					if isDomainSelector(value.Fun, "NewFinding") {
						t.Errorf("%s calls domain.NewFinding; orchestration produces no "+
							"finding", relative(t, path))
					}
					if isDomainSelector(value.Fun, "FindingCode") {
						t.Errorf("%s converts a value to domain.FindingCode",
							relative(t, path))
					}
				}
				return true
			})
		}
	}
	if scanned == 0 {
		t.Fatal("no fleet source was scanned; this guard would pass vacuously")
	}
}

// ---------------------------------------------------------------------------
// Section 26: no cross-target diagnosis
// ---------------------------------------------------------------------------

// TestNoAggregateSurfaceCombinesTwoTargetsOutcomes strengthens the import ban
// beside it with a scan for the *shapes* a cross-target inference takes.
//
// # Why a shape scan as well as an import ban
//
// The import ban is the stronger guard and catches the capability: a package
// that cannot reach internal/diagnosis cannot produce a finding. But
// cross-target inference does not have to produce a *finding* to be wrong — a
// renderer that printed "both databases failed, so the network is down" would
// make a causal claim with no evidence and no finding anywhere.
//
// So this looks for the vocabulary such a claim needs. It is a weaker guard by
// nature, and it is stated as one.
func TestNoAggregateSurfaceCombinesTwoTargetsOutcomes(t *testing.T) {
	// Words that only appear if something is reasoning about a relationship
	// between two measured things.
	causal := []string{
		"root cause", "rootcause", "common cause", "shared cause", "correlat",
		"because both", "all targets failed", "every target failed",
		"the network is", "cascading", "upstream of", "depends on",
	}

	surfaces := []string{
		"internal/fleet/run",
		"internal/render/terminal",
		"internal/render/json",
		"internal/domain",
	}

	scanned := 0
	for _, pkg := range surfaces {
		for _, path := range productionFilesIn(t, pkg) {
			source, err := os.ReadFile(path) //nolint:gosec // G304: a repository path.
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			scanned++

			// Comments are excluded: this file's own prose names several of
			// these phrases in order to forbid them, and so does the aggregate's
			// documentation. What matters is the code.
			code := strippedOfComments(t, path)
			lowered := strings.ToLower(code)
			for _, phrase := range causal {
				if strings.Contains(lowered, phrase) {
					t.Errorf("%s contains the causal phrase %q in code.\n\n"+
						"svcdoctor measured each target independently and has no evidence "+
						"of any relationship between two endpoints. Multi-target v1 is "+
						"orchestration, not distributed causal inference (ADR 0073 §13).",
						relative(t, path), phrase)
				}
			}
			_ = source
		}
	}
	if scanned == 0 {
		t.Fatal("no surface was scanned; this guard would pass vacuously")
	}
}

// strippedOfComments returns a file's source with every comment blanked out.
//
// Comments have to be excluded from a phrase scan, because the code that
// *forbids* a phrase generally has to name it — this file's own documentation
// contains several of the phrases below, and so does ADR 0073's. A scan that
// read comments would fire on its own justification.
func strippedOfComments(t *testing.T, path string) string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	source, err := os.ReadFile(path) //nolint:gosec // G304: a repository path.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	out := []byte(string(source))
	for _, group := range file.Comments {
		start := fset.Position(group.Pos()).Offset
		end := fset.Position(group.End()).Offset
		if start < 0 || end > len(out) || start >= end {
			continue
		}
		for i := start; i < end; i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return string(out)
}

// callSitesOf returns every production call to pkg.Name, as repository paths.
func callSitesOf(t *testing.T, pkg, name string) []string {
	t.Helper()

	var sites []string
	for _, packagePath := range allProductionPackages(t) {
		for _, path := range productionFilesIn(t, packagePath) {
			file := parseFile(t, path)
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok && isPackageSelector(call.Fun, pkg, name) {
					sites = append(sites, relative(t, path))
				}
				return true
			})
		}
	}
	return sites
}

// methodCallSitesOf returns every production call to a method of the given name,
// on any receiver.
//
// A method rather than a package function, so the receiver is not checked: there
// is exactly one SecretFor in the module, on security.Credential, and matching
// the name is what the Phase 9.0 start-state gate counted.
func methodCallSitesOf(t *testing.T, name string) []string {
	t.Helper()

	var sites []string
	for _, packagePath := range allProductionPackages(t) {
		for _, path := range productionFilesIn(t, packagePath) {
			file := parseFile(t, path)
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok &&
					selector.Sel.Name == name {
					sites = append(sites, relative(t, path))
				}
				return true
			})
		}
	}
	return sites
}

// isPackageSelector reports whether an expression is `pkg.Name`.
func isPackageSelector(expr ast.Expr, pkg, name string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == pkg
}

// repoPath turns a repository-relative path into an absolute one.
func repoPath(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join(repoRootDir(t), filepath.FromSlash(rel))
}

// ---------------------------------------------------------------------------
// Section 28: secret authority closure
// ---------------------------------------------------------------------------

// TestMTG07TheAuthorityCallSiteCountsAreUnchanged is the mechanical count.
//
//	security.Reveal          4, one per service, each in that service's wire package
//	Credential.SecretFor     4, one per adapter
//
// Both are counted from the tree rather than asserted from memory, and both name
// where each site is, so a diff that moves one is visible.
func TestMTG07TheAuthorityCallSiteCountsAreUnchanged(t *testing.T) {
	reveal := callSitesOf(t, "security", "Reveal")
	secretFor := methodCallSitesOf(t, "SecretFor")

	if len(reveal) != 4 {
		t.Errorf("security.Reveal has %d production call sites, want 4:\n%s",
			len(reveal), strings.Join(reveal, "\n"))
	}
	if len(secretFor) != 4 {
		t.Errorf("SecretFor has %d production call sites, want 4:\n%s",
			len(secretFor), strings.Join(secretFor, "\n"))
	}

	// Each Reveal site is in a wire package, which is the only place ADR 0027
	// permits one.
	for _, site := range reveal {
		if !strings.Contains(site, "/wire/") {
			t.Errorf("security.Reveal is called outside a wire package, at %s", site)
		}
	}
}

// TestNoFleetPackageEstablishesCredentialAuthority is section 28's shape half.
//
// # The three ways authority could be got wrong, each forbidden structurally
//
//  1. A second authority type. security.Credential is the only one, and it has
//     no plain accessor: opening it requires the endpoint it is about to be used
//     against.
//  2. Authority derived from a target identifier. A target ID is a label for a
//     logical execution and is not an endpoint (ADR 0072 §7). Building an
//     endpoint from one would bind a credential to a name the operator chose.
//  3. Authority derived from reference equality. Two targets naming one variable
//     is a coincidence of the file, not a fact about either endpoint.
//
// Only `secret.CredentialFor` may call `security.NewCredential`, and it builds
// the endpoint from the target's own host and port.
func TestNoFleetPackageEstablishesCredentialAuthority(t *testing.T) {
	sites := callSitesOf(t, "security", "NewCredential")
	if len(sites) == 0 {
		t.Fatal("no security.NewCredential call site was found; this guard would " +
			"pass vacuously")
	}

	fleetSites := []string{}
	for _, site := range sites {
		if strings.HasPrefix(site, "internal/fleet/") {
			fleetSites = append(fleetSites, site)
		}
	}
	if len(fleetSites) != 1 {
		t.Errorf("the fleet layer builds a credential at %d places, want exactly 1 "+
			"(internal/fleet/secret):\n%s", len(fleetSites), strings.Join(fleetSites, "\n"))
	}
	for _, site := range fleetSites {
		if !strings.HasPrefix(site, "internal/fleet/secret/") {
			t.Errorf("%s builds a credential; only the resolver may", site)
		}
	}

	// The scheduler must not build an endpoint at all: an endpoint is the
	// authority boundary, and the scheduler passes credentials through.
	for _, site := range callSitesOf(t, "security", "NewEndpoint") {
		if strings.HasPrefix(site, "internal/fleet/run/") {
			t.Errorf("%s builds a security.Endpoint; the scheduler holds credentials "+
				"and establishes no authority", site)
		}
	}
}

// TestTheResolverBindsAuthorityToTheEndpointAndNotTheIdentifier reads the one
// function that establishes authority, and requires it to use the target's own
// host and port.
//
// A behavioural test proves that today's code does the right thing for the
// inputs it was given. This proves the *only* values in scope at the binding are
// the endpoint's, so a future edit that reached for target.ID has to delete this
// test to do it.
func TestTheResolverBindsAuthorityToTheEndpointAndNotTheIdentifier(t *testing.T) {
	const path = "internal/fleet/secret/secret.go"

	file := parseFile(t, repoPath(t, path))
	found := false

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isPackageSelector(call.Fun, "security", "NewEndpoint") {
			return true
		}
		found = true
		if len(call.Args) != 2 {
			t.Fatalf("security.NewEndpoint takes %d arguments here", len(call.Args))
		}
		for i, want := range []string{"Host", "Port"} {
			selector, ok := call.Args[i].(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != want {
				t.Errorf("the credential's endpoint is built from %s rather than from "+
					"the target's %s.\n\nADR 0072 section 7: a target identifier names a "+
					"logical execution and is not an endpoint. Binding a credential to one "+
					"would let two targets on different servers share an authority.",
					exprText(call.Args[i]), want)
			}
		}
		return true
	})

	if !found {
		t.Fatalf("%s does not build an endpoint; this guard would pass vacuously", path)
	}
}

// exprText renders an expression for a message, without a formatter.
func exprText(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return exprText(value.X) + "." + value.Sel.Name
	case *ast.CallExpr:
		return exprText(value.Fun) + "(...)"
	default:
		return "an expression"
	}
}

// ---------------------------------------------------------------------------
// Section 29: nothing is spent after the run has ended
// ---------------------------------------------------------------------------

// TestTheSchedulerChecksTheRunContextBeforeSpendingAnything is a structural
// guard, and the reason it is structural is the interesting part.
//
// # The window
//
// The dispatcher stops offering work once the run context is done, so in the
// ordinary cancellation path a queued target never reaches runOne. runOne's own
// `if e.runCtx.Err() != nil` check exists for the instant between those two
// facts: Go's select chooses uniformly at random among ready cases, so a
// dispatcher whose context is already done can still hand out one more index
// when a worker happens to be parked on the channel.
//
// Without the check, that target resolves a credential and opens a connection
// for a run that has already ended.
//
// # Why this is not a behavioural test
//
// It was tried. The window needs a worker parked on the channel at the exact
// moment the deadline fires, and neither condition can be forced from outside —
// a pre-cancelled context makes the dispatcher return before any worker is
// ready, and a tiny run budget makes the timing unrepeatable. A test that
// reaches the window sometimes is a test that reports a defect sometimes, which
// for a security property is worse than not having it.
//
// Mutations C21 and C22 delete this check, and nothing behavioural noticed. So
// the shape is asserted instead: the check is the first thing runOne does, and
// it comes before anything that costs a secret or a socket. That is a weaker
// claim than "the race is impossible", and it is stated as one.
func TestTheSchedulerChecksTheRunContextBeforeSpendingAnything(t *testing.T) {
	file := parseFile(t, repoPath(t, "internal/fleet/run/execute.go"))

	var runOne *ast.FuncDecl
	ast.Inspect(file, func(node ast.Node) bool {
		decl, ok := node.(*ast.FuncDecl)
		if ok && decl.Name.Name == "runOne" {
			runOne = decl
		}
		return true
	})
	if runOne == nil || runOne.Body == nil {
		t.Fatal("runOne is missing; this guard has nothing to read")
	}

	guardAt, resolveAt, runAt := -1, -1, -1
	for index, statement := range runOne.Body.List {
		text := statementText(statement)
		if guardAt < 0 && strings.Contains(text, "runCtx.Err()") &&
			strings.Contains(text, "mustNotStarted") {
			guardAt = index
		}
		if resolveAt < 0 && strings.Contains(text, "CredentialFor") {
			resolveAt = index
		}
		if runAt < 0 && strings.Contains(text, ".Run(") {
			runAt = index
		}
	}

	switch {
	case guardAt < 0:
		t.Fatal("runOne does not check the run context before starting a target.\n\n" +
			"A target the dispatcher offered as the run ended must not be started: " +
			"without this check it resolves a credential and opens a connection for a " +
			"run that has already finished. The check is `if e.runCtx.Err() != nil` " +
			"returning mustNotStarted.")
	case resolveAt < 0:
		t.Fatal("runOne does not resolve a credential; this guard would pass vacuously")
	case runAt < 0:
		t.Fatal("runOne does not invoke a runner; this guard would pass vacuously")
	}

	// The guard block itself must spend nothing. Mutation C21 places the
	// resolution *inside* it, which keeps the check first while still reading a
	// secret for a target that is about to be recorded as never started — an
	// ordering check alone reads that as correct, because both are statement 0.
	guardBody := statementText(runOne.Body.List[guardAt])
	for _, spend := range []string{"CredentialFor", "Run("} {
		if strings.Contains(guardBody, spend) {
			t.Errorf("the run-context guard calls %s inside its own body.\n\n"+
				"The branch exists to record a target as never started without "+
				"spending anything on it. Reading a credential there is the exact "+
				"cost it was written to avoid.", spend)
		}
	}

	if guardAt > resolveAt {
		t.Errorf("the run-context check is statement %d and the credential is resolved "+
			"at statement %d; a secret must not be read for a target that will not run",
			guardAt, resolveAt)
	}
	if guardAt > runAt {
		t.Errorf("the run-context check is statement %d and the runner is invoked at "+
			"statement %d; a connection must not be opened after the run has ended",
			guardAt, runAt)
	}
}

// statementText renders one statement's source span for substring matching.
//
// Printing the node would need go/printer and a file set threaded through; the
// positions are enough, because this only asks whether a name appears inside a
// statement rather than what the statement means.
func statementText(statement ast.Stmt) string {
	var names []string
	ast.Inspect(statement, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.Ident:
			names = append(names, value.Name)
		case *ast.SelectorExpr:
			names = append(names, exprText(value)+"(")
		case *ast.CallExpr:
			names = append(names, exprText(value.Fun)+"()")
		}
		return true
	})
	return strings.Join(names, " ")
}

// ---------------------------------------------------------------------------
// Non-vacuity
// ---------------------------------------------------------------------------

// TestTheClosureGuardsCanFail proves each scan above can see what it looks for.
//
// Every guard in this file asserts an absence. An absence test whose scan finds
// nothing to look at passes forever, and reads identically to one that passes
// because the property holds. So each scanner is pointed at something that
// genuinely contains its target.
func TestTheClosureGuardsCanFail(t *testing.T) {
	t.Run("the finding-code scanner sees real declarations", func(t *testing.T) {
		codes := declaredFindingCodes(t)
		for _, required := range []string{
			"DNS_NAME_NOT_RESOLVED", "POSTGRES_CREDENTIALS_REJECTED",
			"RABBITMQ_VHOST_NOT_FOUND", "REDIS_PING_NOT_COMPLETED",
			"KAFKA_METADATA_NOT_COMPLETED",
		} {
			if _, ok := codes[required]; !ok {
				t.Errorf("the scanner did not find %q, which is declared; the count "+
					"guard is therefore unreliable", required)
			}
		}
	})

	t.Run("the Reveal scanner sees the real call sites", func(t *testing.T) {
		sites := callSitesOf(t, "security", "Reveal")
		if len(sites) == 0 {
			t.Fatal("the scanner found no security.Reveal call at all")
		}
	})

	t.Run("the comment stripper removes comments and keeps code", func(t *testing.T) {
		stripped := strippedOfComments(t, repoPath(t, "internal/fleet/run/execute.go"))
		if strings.Contains(stripped, "ADR 0073") {
			t.Error("the comment stripper left comment text behind")
		}
		if !strings.Contains(stripped, "func execute(") {
			t.Error("the comment stripper removed code")
		}
	})

	t.Run("the causal-phrase scan can match", func(t *testing.T) {
		if !strings.Contains(strings.ToLower("The ROOT CAUSE is x"), "root cause") {
			t.Error("the phrase match is broken")
		}
	})

	t.Run("the finding-code count agrees with the domain's own vocabulary", func(t *testing.T) {
		// A code the domain would accept but that nobody declares must not be
		// counted, and one that is declared must be a valid code.
		for code := range declaredFindingCodes(t) {
			if !domain.FindingCode(code).Valid() {
				t.Errorf("%q is declared but is not a valid domain.FindingCode", code)
			}
		}
	})
}
