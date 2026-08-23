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

// allowedModules is every non-standard-library module svcdoctor may build
// against, with the reason it is here.
var allowedModules = map[string]string{
	// ADR 0008. Kafka protocol encoding only — never `kgo`, never a client.
	// BSD-3-Clause, and it has no transitive dependencies of its own, which is
	// most of why it was acceptable.
	"github.com/twmb/franz-go/pkg/kmsg": "Kafka protocol encoding (ADR 0008)",
}

// TestTheModuleGraphIsExactlyWhatWasDecided pins go.mod's requirements.
//
// It reads go.mod rather than `go list -m all`, so it needs no network, no
// module cache and no build, and it therefore says something narrow and exact:
// **these are the modules this repository declares.** A transitive dependency
// appearing under one of them would be a separate finding and is prevented in
// the only durable way, by choosing dependencies that have none.
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

// TestTheDependencyCountIsOne states the headline number on its own.
//
// The test above would still pass if the allowlist were edited in the same
// change as go.mod, which is exactly how a dependency arrives without anyone
// noticing the count moved. This one fails on the number, so the number has to
// be changed deliberately and appears in the diff as a number.
func TestTheDependencyCountIsOne(t *testing.T) {
	if got := len(requiredModules(t)); got != 1 {
		t.Errorf("go.mod requires %d external modules, want 1.\n\n"+
			"If this is intentional, change the number here and record the decision. "+
			"docs/ARCHITECTURE.md, the README and CLAUDE.md all state the count, and "+
			"they are wrong the moment this changes.", got)
	}
}

// TestTheGuardCanFail proves the parser is not returning an empty list.
func TestTheGuardCanFail(t *testing.T) {
	if len(requiredModules(t)) == 0 {
		t.Fatal("no requirements parsed from go.mod; the assertions above are vacuous")
	}
	if _, ok := allowedModules["github.com/twmb/franz-go/pkg/kmsg"]; !ok {
		t.Error("the one known dependency is absent from the allowlist")
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
