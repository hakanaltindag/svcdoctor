package security_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The dependency surface, pinned by count and by name.
//
// # Why this is a security test and not a housekeeping one
//
// svcdoctor transmits credentials. Every module in the build graph is code that
// runs in the same process as a plaintext password, and the repository's answer
// to that has always been to have almost none: Phase 1 through 2 had zero, Phase
// 3 added exactly one, and the reasoning is recorded each time — `kmsg` is
// protocol encoding with no transitive dependencies, and only a wire package may
// import it.
//
// # What was missing
//
// Nothing counted them. `go mod tidy` removes an *unused* requirement, so an
// accidental one cannot persist — but a requirement that is genuinely imported
// survives tidy, passes every gate, and changes the trust surface silently. That
// is the case this closes, and it is the one that matters: a dependency arrives
// because someone wanted a function from it.
//
// This is deliberately a **count and a whitelist**, not a policy engine. A new
// dependency should be a decision someone records, and the way to record it is
// to change this list and say why in the commit.
//
// # The principle changed in Phase 12.1B, and the sentence had to change with it
//
// This file used to state that a transitive dependency appearing under one of
// these "is prevented in the only durable way, by choosing dependencies that have
// none." That was true of both modules it described, and it stopped being true
// the moment ADR 0094 authorized client-go, which brings 36 of its own.
//
// The principle now reads: **prefer dependencies with none; where that is
// impossible the exception is recorded in an ADR, and every module it drags in is
// enumerated here rather than summarized.** Editing the count and leaving the old
// sentence would have made this guard lie, which is why ADR 0094 section 2.1
// required the reasoning to be amended and not merely the number.
//
// The exception is accepted with its cost written down rather than minimized:
// about 36 modules now run in the same process as a plaintext credential, and the
// reason that is the better bet is that the alternative — hand-written Kubernetes
// authentication, kubeconfig semantics, TLS assembly and API decoding — is a
// larger correctness and security burden than the modules are.

// allowedModules is every non-standard-library module svcdoctor may build
// against, with the reason it is here.
var allowedModules = map[string]string{
	// ADR 0008. Kafka protocol encoding only — never `kgo`, never a client.
	// BSD-3-Clause, and it has no transitive dependencies of its own, which is
	// most of why it was acceptable.
	"github.com/twmb/franz-go/pkg/kmsg": "Kafka protocol encoding (ADR 0008)",

	// ADR 0071 §3.3, authorized in Phase 9.0 and added in Phase 9.1A. Multi-target
	// configuration decoding only, and importable by exactly one package —
	// internal/fleet/config — which TestOnlyTheConfigPackageImportsTheYAMLLibrary
	// enforces.
	//
	// MIT and Apache-2.0, and its own go.mod requires **nothing**: it is the
	// maintained continuation of gopkg.in/yaml.v3, which is frozen at v3.0.1 and
	// whose go.mod names gopkg.in/check.v1. That difference is why this is the
	// module and that one is not.
	//
	// It was chosen on measurement rather than convention. `encoding/json` needs
	// no dependency at all and lost on two properties recorded in
	// docs/validation/MULTI_TARGET_PHASE90_CONTRACT_STUDY.md §2.1: it cannot carry
	// comments, and it accepts a duplicated key by silently taking the last — which
	// in a file whose purpose is to say which credential authorizes which endpoint
	// is the config-file form of a truncated secret.
	"go.yaml.in/yaml/v3": "multi-target configuration decoding (ADR 0071)",

	// ADR 0094 §2.1, authorized in Phase 12.1A and added in Phase 12.1B.
	// Apache-2.0, all three.
	//
	// **Importable by exactly one package** — internal/adapter/kubernetes/client —
	// which depguard and TestOnlyTheKubernetesClientImportsClientGo enforce from
	// two directions, and behind a ten-path allowlist inside that: rest,
	// clientcmd and clientcmd/api, the typed core/v1 and discovery/v1 clients,
	// k8s.io/api's core/v1 and discovery/v1, and apimachinery's meta/v1,
	// api/errors and labels.
	//
	// **Refused, and the refusals are build-enforced:** the full `Clientset`, the
	// dynamic client, the API discovery client, informers, listers, tools/cache,
	// workqueue, tools/watch, leaderelection, portforward, remotecommand,
	// transport/spdy, **every** plugin/pkg/client/auth package, controller-runtime,
	// every k8s.io/kubectl package, and every code generator.
	//
	// It was authorized on correctness rather than convenience. The exec and
	// auth-provider refusals require parsing the very structures clientcmd parses,
	// and a hand-rolled kubeconfig parser that missed a field shape would refuse
	// nothing, silently.
	//
	// It is also the reason go.mod's `go` directive reads 1.26.0 rather than 1.26:
	// all three declare `go 1.26.0`, and a main module's directive may not be lower
	// than its dependencies'. The two are the same language version.
	"k8s.io/client-go":    "Kubernetes API client, one package only (ADR 0094)",
	"k8s.io/api":          "Kubernetes API types (ADR 0094)",
	"k8s.io/apimachinery": "Kubernetes API machinery, errors and label selectors (ADR 0094)",

	// client-go's own transitive closure, written out rather than summarized.
	//
	// **None of these is imported by svcdoctor source**, and none may be: the
	// depguard rule denies every k8s.io path outside one package, and the module
	// boundary test denies the rest by name. They are here because `go mod tidy`
	// records them and because a build graph nobody enumerated is one nobody
	// audited — which is the whole reason this file exists.
	//
	// A release of client-go that adds one is a line somebody has to add here,
	// with the count moved deliberately in the same change.
	"github.com/davecgh/go-spew":           "client-go transitive: value formatting",
	"github.com/emicklei/go-restful/v3":    "client-go transitive: OpenAPI route model",
	"github.com/fxamacker/cbor/v2":         "client-go transitive: CBOR serializer",
	"github.com/go-logr/logr":              "client-go transitive: logging facade",
	"github.com/go-openapi/jsonpointer":    "client-go transitive: OpenAPI",
	"github.com/go-openapi/jsonreference":  "client-go transitive: OpenAPI",
	"github.com/go-openapi/swag":           "client-go transitive: OpenAPI",
	"github.com/google/gnostic-models":     "client-go transitive: OpenAPI models",
	"github.com/google/uuid":               "client-go transitive: UUID values",
	"github.com/josharian/intern":          "client-go transitive: string interning",
	"github.com/json-iterator/go":          "client-go transitive: JSON decoding",
	"github.com/mailru/easyjson":           "client-go transitive: JSON decoding",
	"github.com/modern-go/concurrent":      "client-go transitive: json-iterator support",
	"github.com/modern-go/reflect2":        "client-go transitive: json-iterator support",
	"github.com/munnerz/goautoneg":         "client-go transitive: content negotiation",
	"github.com/spf13/pflag":               "client-go transitive: flag types",
	"github.com/x448/float16":              "client-go transitive: CBOR support",
	"go.yaml.in/yaml/v2":                   "client-go transitive: kubeconfig YAML",
	"golang.org/x/net":                     "client-go transitive: HTTP/2 transport",
	"golang.org/x/oauth2":                  "client-go transitive: token transport types",
	"golang.org/x/sys":                     "client-go transitive: syscall support",
	"golang.org/x/term":                    "client-go transitive: terminal detection",
	"golang.org/x/text":                    "client-go transitive: text encoding",
	"golang.org/x/time":                    "client-go transitive: rate limiting types",
	"google.golang.org/protobuf":           "client-go transitive: protobuf runtime",
	"gopkg.in/evanphx/json-patch.v4":       "client-go transitive: JSON patch",
	"gopkg.in/inf.v0":                      "client-go transitive: arbitrary-precision decimals",
	"gopkg.in/yaml.v3":                     "client-go transitive: YAML",
	"k8s.io/klog/v2":                       "client-go transitive: logging",
	"k8s.io/kube-openapi":                  "client-go transitive: OpenAPI",
	"k8s.io/utils":                         "client-go transitive: shared helpers",
	"sigs.k8s.io/json":                     "client-go transitive: case-sensitive JSON decoding",
	"sigs.k8s.io/randfill":                 "client-go transitive: fuzz helpers for API types",
	"sigs.k8s.io/structured-merge-diff/v6": "client-go transitive: apply semantics",
	"sigs.k8s.io/yaml":                     "client-go transitive: YAML/JSON conversion",
}

// TestTheModuleGraphIsExactlyWhatWasDecided pins go.mod's requirements.
//
// It reads go.mod rather than `go list -m all`, so it needs no network, no
// module cache and no build, and it therefore says something narrow and exact:
// **these are the modules this repository declares.**
//
// Since Phase 12.1B that includes client-go's transitive closure, because `go mod
// tidy` writes every one of them into go.mod as an `// indirect` requirement. So
// the list below is the whole build graph and not a summary of it: a new module
// arriving underneath client-go — a release that grows a dependency — appears
// here as a line somebody has to add, with a reason.
func TestTheModuleGraphIsExactlyWhatWasDecided(t *testing.T) {
	required := requiredModules(t)

	for _, module := range required {
		if _, ok := allowedModules[module]; !ok {
			t.Errorf("go.mod requires %q, which is not in allowedModules.\n\n"+
				"svcdoctor transmits credentials, so every module in the build graph "+
				"runs in the same process as a plaintext password. Adding one is a "+
				"decision to record, not a step to take on the way to something else: "+
				"add it to allowedModules with its reason and its licence, and say why "+
				"in the commit.", module)
		}
	}
	for module, reason := range allowedModules {
		if !contains(required, module) {
			t.Errorf("allowedModules lists %q (%s) but go.mod does not require it; "+
				"the list has drifted from the build", module, reason)
		}
	}

	if len(required) != len(allowedModules) {
		t.Errorf("go.mod requires %d modules and %d are allowed",
			len(required), len(allowedModules))
	}
}

// wantDependencyCount is the headline number.
//
// It was **1** from Phase 3.1 to Phase 9.0, became **2** in Phase 9.1A when
// ADR 0071 §3.3's authorized YAML decoder landed, and became **40** in Phase
// 12.1B when ADR 0094 §2.1's authorized Kubernetes client did. Each move is
// recorded in the ADR that made it.
//
// The third move is the only one that is large, and it is stated rather than
// softened: three of the thirty-eight new modules were decided on, and the other
// thirty-five arrived underneath them. Narrowing the import surface to ten
// packages saved one module and 0.55 MB — a reachability and hygiene decision —
// and **no document may present that as a dependency-cost reduction.**
const wantDependencyCount = 40

// TestTheDependencyCountIsExact states the headline number on its own.
//
// The test above would still pass if the allowlist were edited in the same
// change as go.mod, which is exactly how a dependency arrives without anyone
// noticing the count moved. This one fails on the number, so the number has to
// be changed deliberately and appears in the diff as a number.
func TestTheDependencyCountIsExact(t *testing.T) {
	if got := len(requiredModules(t)); got != wantDependencyCount {
		t.Errorf("go.mod requires %d external modules, want %d.\n\n"+
			"If this is intentional, change wantDependencyCount and record the decision. "+
			"docs/ARCHITECTURE.md, the README and CLAUDE.md all state the count, and "+
			"they are wrong the moment this changes.", got, wantDependencyCount)
	}
}

// TestAThirdModuleStillFails proves the allowlist is an allowlist.
//
// Raising a count and widening a map are the two edits that make a dependency
// guard stop guarding, and Phase 9.1A did both. This asserts what remains true
// afterwards: a module nobody decided on is still refused, and the count is
// still a ceiling rather than a note.
func TestAThirdModuleStillFails(t *testing.T) {
	const unapproved = "example.com/some/module"
	if _, ok := allowedModules[unapproved]; ok {
		t.Fatalf("%s is unexpectedly allowed", unapproved)
	}
	// The allowlist is exactly what was decided, and nothing else is in it.
	if len(allowedModules) != wantDependencyCount {
		t.Errorf("allowedModules holds %d entries and the count is %d; the two must agree, "+
			"or one module could be swapped for another without either test noticing",
			len(allowedModules), wantDependencyCount)
	}
}

// TestTheGuardCanFail proves the parser is not returning an empty list.
func TestTheGuardCanFail(t *testing.T) {
	if len(requiredModules(t)) == 0 {
		t.Fatal("no requirements parsed from go.mod; the assertions above are vacuous")
	}
	for _, decided := range []string{
		"github.com/twmb/franz-go/pkg/kmsg",
		"go.yaml.in/yaml/v3",
		"k8s.io/client-go",
	} {
		if _, ok := allowedModules[decided]; !ok {
			t.Errorf("the decided dependency %s is absent from the allowlist", decided)
		}
	}
}

// requiredModules parses the module paths from go.mod's require directives.
//
// Hand-parsed rather than taken from `golang.org/x/mod/modfile`, because
// depending on a module-parsing module to assert that there is one module would
// be its own joke.
func requiredModules(t *testing.T) []string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(repositoryRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	var out []string
	block := false
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case line == "require (":
			block = true
		case block && line == ")":
			block = false
		case block && line != "":
			out = append(out, strings.Fields(line)[0])
		case strings.HasPrefix(line, "require "):
			if fields := strings.Fields(line); len(fields) >= 2 {
				out = append(out, fields[1])
			}
		}
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}
	return false
}
