//go:build integration

package rabbitmq

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The credential-authority contract, proven behaviourally.
//
// ADR 0068 §6 binds a credential to the **logical endpoint the operator named**,
// never to a resolved address and never to a virtual host. There are two checks
// in the path — one in the composition root and one in the adapter's
// `SecretFor` — and this file exists because a single check is one refactor away
// from being none.

// TestACredentialBoundElsewhereIsNeverSent is the primary authority scenario.
//
// The credential is authorized for a different port on the same host, so it is
// not authorized here. The composition root refuses **before the run begins**,
// which is stronger than withholding mid-journey: no socket is opened, no
// protocol frame is exchanged, and the secret is never revealed.
//
// The refusal names both endpoints, because an operator has to be able to see
// which binding was wrong. It must never name the secret.
func TestACredentialBoundElsewhereIsNeverSent(t *testing.T) {
	const secret = "app-pw"

	err := runExpectingRefusal(t, runOptions{
		port: portAMQPS, username: userApp, password: secret,
		// Authorized for a neighbouring port, which is a different endpoint.
		credentialHost: "127.0.0.1", credentialPort: portAMQP,
		tls: trustFixtureCA(t),
	})

	if err == nil {
		t.Fatal("a credential bound to another endpoint was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("the refusal names the secret")
	}
	if !strings.Contains(err.Error(), "bound to") {
		t.Errorf("the refusal does not explain the binding: %v", err)
	}
}

// TestTheHostHalfOfTheAuthorityIsChecked complements the port half above.
//
// Both halves of the endpoint matter. A check that compared only the port would
// let a credential for one host be presented to another on the same port, which
// is the exact shape of a credential-forwarding mistake.
func TestTheHostHalfOfTheAuthorityIsChecked(t *testing.T) {
	const secret = "app-pw"

	err := runExpectingRefusal(t, runOptions{
		port: portAMQPS, username: userApp, password: secret,
		credentialHost: "192.0.2.10", credentialPort: portAMQPS,
		tls: trustFixtureCA(t),
	})

	if err == nil {
		t.Fatal("a credential bound to another host was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("the refusal names the secret")
	}
}

// TestBothAuthorityChecksExistIndependently is the mutation this file is really
// for.
//
// A behavioural test cannot distinguish "two checks" from "one check that
// happens to run", because removing either leaves the other refusing. So this
// asserts the **structure**: both call sites exist, in different packages. The
// M-series mutation that removes both at once is what proves the pair matters,
// and this guard is what makes removing them a visible edit.
func TestBothAuthorityChecksExistIndependently(t *testing.T) {
	root := repoRootOf(t)

	adapter := readFile(t, filepath.Join(root, "internal/adapter/rabbitmq/authenticate.go"))
	if !strings.Contains(adapter, "params.Credential.SecretFor(params.Endpoint)") {
		t.Error("the adapter no longer asks SecretFor for the endpoint it is diagnosing; " +
			"that call is what binds the credential to the logical endpoint (ADR 0068 §6)")
	}

	// **The refusal must be returned, never absorbed**, and the difference is
	// invisible to a behavioural test because the composition root refuses the
	// same mismatch first. A mutation that turns the error into an empty secret
	// therefore survives every scenario in this package — which is exactly why
	// this is asserted structurally.
	//
	// Absorbing it would be wrong twice over: it would make the adapter's own
	// authority check unobservable, and the node it recorded would classify
	// svcdoctor's refusal as a peer failure, accusing an endpoint that was never
	// asked for anything.
	if !strings.Contains(stripGoComments(adapter),
		"return security.Secret{}, fmt.Errorf(\"%w: %w\", ErrInvalidInput, err)") {
		t.Error("the adapter no longer returns the SecretFor refusal; an absorbed " +
			"mismatch makes the second authority check dead code (ADR 0068 §6)")
	}

	composition := readFile(t, filepath.Join(root, "internal/app/rabbitmq.go"))
	lower := strings.ToLower(stripGoComments(composition))
	if !strings.Contains(lower, "credential") {
		t.Error("the composition root no longer mentions the credential at all")
	}

	// The reveal remains confined to the wire package, and to exactly one site.
	wire := readFile(t, filepath.Join(root, "internal/adapter/rabbitmq/wire/connection.go"))
	if got := strings.Count(stripGoComments(wire), "security.Reveal("); got != 1 {
		t.Errorf("the wire package has %d security.Reveal call sites, want exactly 1", got)
	}
	for _, rel := range []string{
		"internal/adapter/rabbitmq/authenticate.go",
		"internal/adapter/rabbitmq/open.go",
		"internal/adapter/rabbitmq/connectionstart.go",
		"internal/app/rabbitmq.go",
	} {
		if strings.Contains(stripGoComments(readFile(t, filepath.Join(root, rel))),
			"security.Reveal(") {
			t.Errorf("%s reveals a secret outside the wire package", rel)
		}
	}
}

// TestConnectionSecureNeverProducesASecondCredential pins ADR 0067 §2.
//
// `Connection.Secure-Ok` is excluded from the method allowlist deliberately:
// answering it would be a second credential-bearing frame. The fake peer sends
// `Connection.Secure` after a correct Start-Ok, which is exactly the invitation
// a real broker never issues and a malicious one would.
func TestConnectionSecureNeverProducesASecondCredential(t *testing.T) {
	peer := newFakePeer(t, fakeSecureThenNothing)

	result := run(t, runOptions{
		host: "127.0.0.1", port: peer.port(),
		username: userApp, password: "app-pw",
		tls: nil, // plaintext, so the credential is withheld anyway
	})
	_ = result

	credentials, connections := peer.counts()
	if credentials > 1 {
		t.Errorf("svcdoctor sent %d credential-bearing frames; the maximum is 1 and "+
			"Connection.Secure must never elicit another", credentials)
	}
	if connections != 1 {
		t.Errorf("svcdoctor opened %d connections, want exactly 1", connections)
	}
}

// TestAPeerCloseAfterTheCredentialNeverReconnects pins the no-retry rule.
//
// One connection. No redial, no reconnect, no second attempt for any reason
// (ADR 0067 §2). A peer that drops the socket the instant the credential lands
// is the shape that tempts a retry loop, and a retry would send the operator's
// credential a second time.
func TestAPeerCloseAfterTheCredentialNeverReconnects(t *testing.T) {
	peer := newFakePeer(t, fakeCloseAfterCredential)

	result := run(t, runOptions{
		host: "127.0.0.1", port: peer.port(),
		username: userApp, password: "app-pw",
	})
	_ = result

	credentials, connections := peer.counts()
	if connections != 1 {
		t.Errorf("svcdoctor opened %d connections; a peer close is not a reason to "+
			"redial (ADR 0067 §2)", connections)
	}
	if credentials > 1 {
		t.Errorf("svcdoctor sent %d credential-bearing frames, want at most 1", credentials)
	}
}

// TestNoDiscoveredEndpointExists pins the absence of a topology stage.
//
// Kafka has advertised brokers and PostgreSQL has none; RabbitMQ BASIC has none
// either, and that is what keeps the credential's authority a single endpoint.
// The graph must contain exactly one target and one connection attempt.
func TestNoDiscoveredEndpointExists(t *testing.T) {
	result := run(t, runOptions{port: portAMQPS, username: userApp,
		password: passApp, tls: trustFixtureCA(t)})

	if got := len(nodesAt(t, result, stepTCP)); got != 1 {
		t.Errorf("got %d tcp.connect nodes, want exactly 1; a second endpoint would "+
			"be a discovered one", got)
	}
	if got := len(nodesAt(t, result, stepStart)); got != 1 {
		t.Errorf("got %d connection_start nodes, want exactly 1", got)
	}
	for _, node := range result.Report().Graph().Nodes() {
		step := string(node.Step())
		for _, forbidden := range []string{"advertised", "discovered", "topology", "cluster"} {
			if strings.Contains(strings.ToLower(step), forbidden) {
				t.Errorf("the graph contains a %q step; RabbitMQ BASIC discovers nothing", step)
			}
		}
	}
}

// --- helpers ---------------------------------------------------------------

func repoRootOf(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found")
		}
		dir = parent
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

func stripGoComments(code string) string {
	var sb strings.Builder
	i := 0
	for i < len(code) {
		switch {
		case strings.HasPrefix(code[i:], "//"):
			j := strings.IndexByte(code[i:], '\n')
			if j < 0 {
				return sb.String()
			}
			i += j
		case strings.HasPrefix(code[i:], "/*"):
			j := strings.Index(code[i:], "*/")
			if j < 0 {
				return sb.String()
			}
			i += j + 2
		default:
			sb.WriteByte(code[i])
			i++
		}
	}
	return sb.String()
}
