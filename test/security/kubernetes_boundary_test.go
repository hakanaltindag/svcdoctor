package security_test

import (
	"go/ast"
	"os"
	"strings"
	"testing"
)

// The Kubernetes dependency boundary, asserted from outside the packages that
// hold it.
//
// # Why these are security tests
//
// client-go brings about 36 modules into a process that holds plaintext
// credentials, and it brings capabilities svcdoctor has refused: a credential
// plugin runner, a full clientset, a watch machinery, a proxy-aware transport.
// ADR 0094 authorized the dependency **behind an allowlist**, and an allowlist
// that nothing checks is a comment.
//
// depguard enforces the same two properties at lint time. These are the
// independent statement of them, in the repository's own vocabulary, and they
// catch the case a lint configuration cannot: an edit to `.golangci.yml` itself.

// kubernetesLibraryImporter is the only package permitted to import k8s.io.
const kubernetesLibraryImporter = "internal/adapter/kubernetes/client"

// kubernetesClientAllowlist is the ten import paths ADR 0094 section 2.1 enumerated.
//
// **Ten paths on nine rows.** PHASE121A §4.4's table gives one row to
// `k8s.io/api/core/v1` and `k8s.io/api/discovery/v1` together — they are the two
// object groups this adapter reads — which is where the frozen records' phrase
// "nine-package allowlist" comes from. The set below is that table's contents,
// path for path, and nothing was added to make current code pass.
//
// **The refusals matter more than the permissions**, and each is a capability
// rather than a size: the full `Clientset` puts every group and verb one method
// call away; `dynamic` puts every resource there; the discovery client makes a
// round trip the budget did not account for; informers, listers and tools/cache
// are a cache and a watch inside a process that runs once and exits; and every
// `plugin/pkg/client/auth` package exists to execute or delegate the
// authentication this contract refuses.
var kubernetesClientAllowlist = map[string]bool{
	"k8s.io/client-go/rest":                          true,
	"k8s.io/client-go/tools/clientcmd":               true,
	"k8s.io/client-go/tools/clientcmd/api":           true,
	"k8s.io/client-go/kubernetes/typed/core/v1":      true,
	"k8s.io/client-go/kubernetes/typed/discovery/v1": true,
	"k8s.io/api/core/v1":                             true,
	"k8s.io/api/discovery/v1":                        true,
	"k8s.io/apimachinery/pkg/apis/meta/v1":           true,
	"k8s.io/apimachinery/pkg/api/errors":             true,
	"k8s.io/apimachinery/pkg/labels":                 true,
}

// TestOnlyTheKubernetesClientImportsClientGo is ADR 0094 section 2.10.
//
// It is the same property TestOnlyTheConfigPackageImportsTheYAMLLibrary states
// for YAML, and it is enforced for a stronger reason: a YAML decoder parses
// bytes, and a Kubernetes client speaks to a control plane with a credential.
func TestOnlyTheKubernetesClientImportsClientGo(t *testing.T) {
	importers := map[string]bool{}
	for _, pkg := range allProductionPackages(t) {
		for _, path := range importsOfPackage(t, pkg) {
			if strings.HasPrefix(path, "k8s.io/") || strings.HasPrefix(path, "sigs.k8s.io/") {
				importers[pkg] = true
			}
		}
	}

	if !importers[kubernetesLibraryImporter] {
		t.Fatalf("no package imports a Kubernetes library; this guard would pass vacuously "+
			"and %s would be unimplemented", kubernetesLibraryImporter)
	}
	for pkg := range importers {
		if pkg != kubernetesLibraryImporter {
			t.Errorf("%s imports a Kubernetes library.\n\n"+
				"ADR 0094 §2.10 confines every k8s.io package to %s. Every other layer "+
				"consumes svcdoctor's own normalized values, which is what keeps a "+
				"control-plane client out of the diagnosis, the renderer, the scheduler "+
				"and the domain model.", pkg, kubernetesLibraryImporter)
		}
	}
}

// TestTheKubernetesClientImportsAreExactlyTheAllowlist.
//
// It reads the package's own production sources, so it states the property in the
// direction the ADR wrote it: **these ten, and nothing else.** An eleventh would
// need a decision, and this is where that decision has to be written down.
func TestTheKubernetesClientImportsAreExactlyTheAllowlist(t *testing.T) {
	seen := map[string]bool{}
	scanned := 0

	for _, path := range productionFilesIn(t, kubernetesLibraryImporter) {
		scanned++
		for _, imported := range parseFile(t, path).Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if !strings.HasPrefix(importPath, "k8s.io/") &&
				!strings.HasPrefix(importPath, "sigs.k8s.io/") {
				continue
			}
			seen[importPath] = true
			if !kubernetesClientAllowlist[importPath] {
				t.Errorf("%s imports %s, which is not on ADR 0094 §2.1's allowlist.\n\n"+
					"The refused set is the point: the full Clientset, the dynamic client, "+
					"the discovery client, informers, listers, caches, watches and every "+
					"auth plugin. Adding an eleventh path is a decision with its own "+
					"record.", relative(t, path), importPath)
			}
		}
	}

	if scanned == 0 {
		t.Fatalf("no production source was found in %s; this guard would pass vacuously",
			kubernetesLibraryImporter)
	}
	if len(seen) == 0 {
		t.Fatal("no Kubernetes import was found; this guard would pass vacuously")
	}
}

// TestTheKubernetesClientReachesNoOtherSvcdoctorLayer.
//
// It holds a credential and a live control-plane client, so the layers it must
// not reach are the ones that would let either travel: diagnosis, the renderer,
// the fleet scheduler, the composition root, and every other adapter.
func TestTheKubernetesClientReachesNoOtherSvcdoctorLayer(t *testing.T) {
	forbidden := map[string]string{
		"internal/diagnosis": "an adapter produces evidence; interpreting it is diagnosis work",
		"internal/render":    "an adapter does not render",
		"internal/app":       "an adapter is composed, and does not reach back into the root",
		"internal/cli":       "an adapter is not the command boundary",
		"internal/fleet":     "an adapter knows nothing about multi-target scheduling",
		// The four transport probes, and not internal/probe itself: that package is
		// where ADR 0019 put the evidence-identifier encoding, precisely so two
		// producers cannot disagree about escaping, and every adapter borrows the
		// rule rather than copying it. What a Kubernetes adapter must not reach is
		// a probe that dials, because its transport belongs to the client library.
		"internal/probe/dns":        "the Kubernetes transport belongs to the client library",
		"internal/probe/tcp":        "the Kubernetes transport belongs to the client library",
		"internal/probe/tls":        "the Kubernetes transport belongs to the client library",
		"internal/probe/transport":  "the Kubernetes transport belongs to the client library",
		"internal/adapter/kafka":    "one service adapter never reaches another",
		"internal/adapter/postgres": "one service adapter never reaches another",
		"internal/adapter/redis":    "one service adapter never reaches another",
		"internal/adapter/rabbitmq": "one service adapter never reaches another",
	}

	scanned := 0
	for _, pkg := range []string{
		kubernetesLibraryImporter, "internal/adapter/kubernetes", "internal/service/kubernetes",
	} {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			for _, imported := range parseFile(t, path).Imports {
				importPath := strings.Trim(imported.Path.Value, `"`)
				for prefix, why := range forbidden {
					full := "github.com/hakanaltindag/svcdoctor/" + prefix
					if importPath == full || strings.HasPrefix(importPath, full+"/") {
						t.Errorf("%s imports %s: %s", relative(t, path), importPath, why)
					}
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no Kubernetes source was scanned; this guard would pass vacuously")
	}
}

// TestTheKubernetesVocabularyIsALeaf.
//
// It exists so that diagnosis and the renderer can name Kubernetes steps and
// attributes without reaching the package that produces them. A vocabulary that
// grew a dependency would become the shared service layer ADR 0034 declined to
// create.
func TestTheKubernetesVocabularyIsALeaf(t *testing.T) {
	const vocabulary = "internal/service/kubernetes"
	scanned := 0
	for _, path := range productionFilesIn(t, vocabulary) {
		scanned++
		for _, imported := range parseFile(t, path).Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if importPath == "github.com/hakanaltindag/svcdoctor/internal/domain" {
				continue
			}
			if !strings.Contains(importPath, ".") {
				t.Errorf("%s imports the standard library package %s; a vocabulary is "+
					"constants over internal/domain and nothing else",
					relative(t, path), importPath)
				continue
			}
			t.Errorf("%s imports %s; a vocabulary imports internal/domain and nothing else",
				relative(t, path), importPath)
		}
	}
	if scanned == 0 {
		t.Fatalf("no source was found in %s; this guard would pass vacuously", vocabulary)
	}
}

// TestNoKubernetesSpecialCaseExistsInAnyGenericPackage is ADR 0071 section 6.3,
// measured for a fifth service.
//
// The registry exists precisely so that adding a service needs no edit to the
// runner, the decoder, the aggregate report, the renderer or the exit mapping. A
// string literal naming Kubernetes in one of those is the first line of the
// central branching the extensibility rule forbids.
func TestNoKubernetesSpecialCaseExistsInAnyGenericPackage(t *testing.T) {
	scanned := 0
	for _, pkg := range fleetCorePackages {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			for _, literal := range stringLiterals(parseFile(t, path)) {
				if strings.EqualFold(literal, "kubernetes") || strings.EqualFold(literal, "k8s") {
					t.Errorf("%s contains the string literal %q.\n\n"+
						"A fifth service is registered, not branched on.",
						relative(t, path), literal)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no core source was scanned; this guard would pass vacuously")
	}
}

// TestTheGenericCoreImportsNoKubernetesPackage states the same boundary as an
// import rule rather than a literal one.
//
// The two catch different mistakes: a literal is how a branch begins, and an
// import is how a type leaks. `internal/domain` is the one that matters most —
// a Kubernetes type reachable from the canonical report would put a control-plane
// API into the schema every consumer parses.
func TestTheGenericCoreImportsNoKubernetesPackage(t *testing.T) {
	core := []string{
		"internal/domain", "internal/diagnosis", "internal/render/json",
		"internal/render/terminal", "internal/probe", "internal/security",
		"internal/security/redaction", "internal/cli", "internal/fleet/config",
		"internal/fleet/run", "internal/fleet/secret",
	}

	scanned := 0
	for _, pkg := range core {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, marker := range []string{"k8s.io/", "sigs.k8s.io/"} {
				if strings.Contains(string(source), marker) {
					t.Errorf("%s mentions %s; the generic core consumes svcdoctor's own "+
						"normalized values and never a Kubernetes type",
						relative(t, path), marker)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no core source was scanned; this guard would pass vacuously")
	}
}

// TestTheKubernetesAdapterNeverProducesAFinding is Phase 12.1B's own boundary.
//
// # Why it is a security test rather than an architecture one
//
// The four Kubernetes finding codes are claims about somebody's cluster, and each
// carries a claim ceiling ADR 0094 section 2.7 froze — F4 may never say a Service
// is unreachable, F2 may never say the objects are absent. A finding produced
// before the phase that argued those ceilings would carry none of them.
//
// Phase 12.1C removes this guard's premise deliberately, by wiring the rules. It
// is written to fail loudly at that point rather than to be forgotten.
func TestTheKubernetesAdapterNeverProducesAFinding(t *testing.T) {
	forbidden := []string{
		"NewFinding", "FindingCode", "SeverityError", "SeverityWarn",
		"ConfidenceHigh", "domain.Recommendation",
	}

	scanned := 0
	for _, pkg := range []string{
		kubernetesLibraryImporter, "internal/adapter/kubernetes", "internal/service/kubernetes",
	} {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, marker := range forbidden {
				if strings.Contains(string(source), marker) {
					t.Errorf("%s mentions %s.\n\n"+
						"Phase 12.1B is acquisition: it produces evidence and concludes "+
						"nothing. The four Kubernetes findings, their severities and their "+
						"claim ceilings are Phase 12.1C's, and a finding produced here "+
						"would carry none of them.", relative(t, path), marker)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no Kubernetes source was scanned; this guard would pass vacuously")
	}
}

// TestNoKubernetesFindingCodeExistsYet pins the count from the other direction.
//
// The four codes are named exactly rather than matched by prefix, because
// `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT` are the two variables
// the kubelet injects and the in-cluster path legitimately reads them. A prefix
// match found those and would have had to be weakened; naming the four says
// precisely what must not exist yet.
func TestNoKubernetesFindingCodeExistsYet(t *testing.T) {
	codes := []string{
		"KUBERNETES_SERVICE_NOT_FOUND",
		"KUBERNETES_API_ACCESS_DENIED",
		"KUBERNETES_SERVICE_SELECTS_NO_PODS",
		"KUBERNETES_SERVICE_NO_READY_ENDPOINT",
	}

	scanned := 0
	found := []string{}
	for _, pkg := range allProductionPackages(t) {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			for _, literal := range stringLiterals(parseFile(t, path)) {
				for _, code := range codes {
					if literal == code {
						found = append(found, relative(t, path)+": "+literal)
					}
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no source was scanned; this guard would pass vacuously")
	}
	if len(found) != 0 {
		t.Errorf("a KUBERNETES_ finding code exists in Phase 12.1B:\n%s\n\n"+
			"Finding codes go 65 -> 69 in Phase 12.1C, and every one of them arrives with "+
			"the rule that produces it.", strings.Join(found, "\n"))
	}
}

// TestNoKubernetesSourceReadsAStatusMessage is ADR 0094 section 2.8, structurally.
//
// # Why a behavioural test cannot state this
//
// The contract is that `Status.Message`, `Status.details.causes[].message` and
// every condition or status message are *"never read, never matched, never parsed
// and never interpolated"*. A behavioural test can only show that a hostile
// message did not reach the output of a particular run — and it cannot fail at
// all once the values are enums, because an enum has no room to carry a string.
//
// That is not a hypothetical gap. Phase 12.1B planted a classifier that branched
// on the message and it **survived** every behavioural test, because the branch
// it added was unreachable for the inputs those tests supplied. The property is
// about the source, so this reads the source.
//
// Reading the field at all is the violation. Once a message is in a local
// variable it is one interpolation away from an error, a log line or a report,
// and the reason this contract is structural rather than an escaping exercise is
// that escaping is something a later edit forgets.
func TestNoKubernetesSourceReadsAStatusMessage(t *testing.T) {
	// The field names that carry peer-supplied prose. `Reason` and `Code` are
	// deliberately absent: those are the API's own enumerations and are exactly
	// what svcdoctor classifies from.
	//
	// Matched on the **syntax tree** rather than on the file's text, because the
	// text form catches this guard's own subject: apierror.go's doc comment says
	// "Status.Message ... are never read", and a naive scan flagged the sentence
	// that states the rule. A selector expression is the thing that reads a
	// field, and a comment is not one.
	forbidden := map[string]string{
		"Message": "a Kubernetes status or condition message",
		"Details": "a Status details block, whose causes carry messages",
		"Causes":  "a Status cause list, whose entries carry messages",
	}

	scanned := 0
	for _, pkg := range []string{
		kubernetesLibraryImporter, "internal/adapter/kubernetes", "internal/service/kubernetes",
	} {
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
				selector, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				why, forbiddenField := forbidden[selector.Sel.Name]
				if !forbiddenField {
					return true
				}
				t.Errorf("%s reads .%s — %s.\n\n"+
					"A Kubernetes status message is text whoever controls the cluster — or "+
					"whoever can answer as it — chooses. It is never read, matched, parsed "+
					"or interpolated, which keeps ANSI, CRLF, token-shaped values and "+
					"filesystem paths out structurally rather than by escaping "+
					"(ADR 0094 §2.8). Classify from the HTTP status and "+
					"metav1.StatusReason instead.", relative(t, path), selector.Sel.Name, why)
				return true
			})
		}
	}
	if scanned == 0 {
		t.Fatal("no Kubernetes source was scanned; this guard would pass vacuously")
	}
}
