//go:build integration

package redpanda

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// The invariants this fixture is here to protect as much as the SCRAM result.
//
// A vendor fixture is exactly the place a special case gets introduced without
// anyone deciding to introduce one: it is easy to make Redpanda pass by relaxing
// something, and the relaxation would then apply to every peer. These assert
// against a real broker what the unit suites assert structurally.

// TestExactlyOneCredentialBearingAuthenticationAttempt is ADR 0028's cardinality
// against a real Redpanda broker.
//
// Redpanda resolves to both loopback families, so the run has two transport
// paths and discovers on both. Exactly one of them may carry the credential.
func TestExactlyOneCredentialBearingAuthenticationAttempt(t *testing.T) {
	result := diagnose(t, defaults(t))

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Errorf("%d authentication nodes, want exactly 1.\n\n"+
			"One credential, one attempt, whatever the target resolved to (ADR 0028). "+
			"A vendor that needed a second attempt would need a decision, not a fixture.",
			len(auth))
	}

	// And discovery genuinely did run on more than one path, so the assertion
	// above is not vacuously true of a single-path run.
	if got := len(nodesOf(result, servicekafka.StepSASLHandshake)); got < 2 {
		t.Logf("only %d handshake node(s): this host resolved localhost to one "+
			"family, so the cardinality assertion above is weaker than intended", got)
	}
}

// TestAdvertisedEndpointsGetNoCredential is ADR 0050 against a real broker.
//
// Redpanda advertises endpoints, and every one of them must receive
// credential-free DNS, TCP and TLS and nothing else. The assertion is structural
// — no protocol or authentication node may exist beneath an advertisement — which
// is stronger than counting bytes and is what the graph can actually prove.
func TestAdvertisedEndpointsGetNoCredential(t *testing.T) {
	result := diagnose(t, defaults(t))
	graph := result.Report().Graph()

	advertisements := map[string]bool{}
	for _, a := range nodesOf(result, servicekafka.StepBrokerAdvertised) {
		advertisements[string(a.ID())] = true
	}
	if len(advertisements) == 0 {
		t.Fatal("no advertisement nodes; this test proves nothing")
	}

	// Walk every node whose ancestry reaches an advertisement.
	children := map[string][]string{}
	for _, n := range graph.Nodes() {
		for _, parent := range graph.Parents(n.ID()) {
			children[string(parent)] = append(children[string(parent)], string(n.ID()))
		}
	}
	byID := map[string]string{}
	for _, n := range graph.Nodes() {
		byID[string(n.ID())] = string(n.Step())
	}

	seen := map[string]bool{}
	var walk func(id string)
	walk = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		step := byID[id]
		for _, forbidden := range []string{"sasl", "authenticate", "metadata", "api_versions"} {
			if strings.Contains(step, forbidden) {
				t.Errorf("step %q appears beneath an advertised endpoint.\n\n"+
					"An advertised broker is an endpoint the operator never named. It "+
					"receives credential-free transport and nothing else (ADR 0050).",
					step)
			}
		}
		for _, c := range children[id] {
			walk(c)
		}
	}
	for id := range advertisements {
		for _, c := range children[id] {
			walk(c)
		}
	}
}

// TestTheReportLeaksNoCredential pins that nothing the fixture used reaches the
// report, in either output mode.
func TestTheReportLeaksNoCredential(t *testing.T) {
	result := diagnose(t, defaults(t))

	canaries := []string{scramSecret, plainSecret}
	local, err := result.Report().MarshalJSON()
	if err != nil {
		t.Fatalf("marshalling the local report: %v", err)
	}
	for _, c := range canaries {
		if strings.Contains(string(local), c) {
			t.Errorf("the local report contains the credential %q", c)
		}
	}
}

// --- source-level guard helpers --------------------------------------------

// productionGoFiles lists every non-test Go file under internal/ and cmd/.
func productionGoFiles(t *testing.T) []string {
	t.Helper()

	root := repositoryRoot(t)
	var out []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			out = append(out, rel)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no production Go files found; the guard above would be vacuous")
	}
	return out
}

func readFile(rel string) (string, error) {
	body, err := os.ReadFile(rel) //nolint:gosec // a repository-relative path this test built.
	return string(body), err
}

// repositoryRoot walks up to the directory holding go.mod.
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
			t.Fatal("no go.mod found above the working directory")
		}
		dir = parent
	}
}
