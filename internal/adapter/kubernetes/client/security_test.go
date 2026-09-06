package client

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// execSentinelEnv names the file the helper process writes.
//
// The helper is this test binary re-invoked, which is what makes the negative
// test work on every platform the repository builds for: a `/bin/sh` command
// would prove nothing on Windows, and mocking the exec call away would prove
// nothing anywhere — it would test the mock.
const execSentinelEnv = "SVCDOCTOR_EXEC_SENTINEL"

// TestExecCredentialPluginHelper is the process a refused kubeconfig would run.
//
// It does nothing at all in an ordinary test run. If client-go ever invokes the
// exec plugin the fixture declares, this is what runs, and the only thing it does
// is leave the evidence behind.
func TestExecCredentialPluginHelper(t *testing.T) {
	sentinel := os.Getenv(execSentinelEnv)
	if sentinel == "" {
		t.Skip("not the exec helper process")
	}
	//nolint:gosec // the path is this test's own t.TempDir; writing it is the point
	if err := os.WriteFile(sentinel, []byte("executed"), 0o600); err != nil {
		t.Fatalf("the helper could not write its sentinel: %v", err)
	}
}

// TestAnExecKubeconfigNeverExecutesAnything is the release gate.
//
// # What it proves, and why the sentinel is the only acceptable evidence
//
// ADR 0072 section 13 refuses arbitrary code execution driven by a configuration
// file, with the reopen condition *"None. This is a decision, not a deferral."*
// A kubeconfig `exec:` stanza is that shape exactly, and Phase 12.1A measured
// that client-go invokes such a plugin on the **first API request** — not at
// parse, not at client construction. So the only refusal that is worth anything
// is one issued before a request exists, and the only proof that is worth
// anything is a file that would exist if the program had run.
//
// A test asserting only that an error was returned would pass just as happily on
// a build that refused the target *after* running the plugin.
//
// Three things are asserted together, and each would be insufficient alone: the
// target is refused; **the sentinel does not exist**; and the API server counted
// zero requests, which is what makes "before the first request" a measurement
// rather than a claim about ordering.
func TestAnExecKubeconfigNeverExecutesAnything(t *testing.T) {
	server := newAPIServer(t)
	sentinel := filepath.Join(t.TempDir(), "exec-ran")

	path := kubeconfig{
		server: server.URL(),
		caPath: server.caPath,
		userBlock: "    exec:\n" +
			"      apiVersion: client.authentication.k8s.io/v1\n" +
			"      command: " + os.Args[0] + "\n" +
			"      args:\n" +
			"      - \"-test.run=TestExecCredentialPluginHelper\"\n" +
			"      env:\n" +
			"      - name: " + execSentinelEnv + "\n" +
			"        value: " + sentinel + "\n",
	}.write(t)

	// Every entry point is exercised, because a refusal that holds in one and not
	// another is a hole an operator reaches through the path nobody tested.
	for _, entry := range []struct {
		name string
		call func() error
	}{
		{"Inspect", func() error { _, err := Inspect(targetFor(path), false); return err }},
		{"Connect", func() error {
			_, err := Connect(targetFor(path), security.Credential{})
			return err
		}},
		{"Acquire", func() error {
			_, err := Acquire(context.Background(), Params{Target: targetFor(path)})
			return err
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			err := entry.call()
			if err == nil {
				t.Fatal("an exec kubeconfig was accepted")
			}
			if !errors.Is(err, ErrTarget) {
				t.Errorf("error is %v, want an ErrTarget refusal", err)
			}
			if !strings.Contains(err.Error(), "exec credential plugin") {
				t.Errorf("the refusal does not name the construct: %v", err)
			}
		})
	}

	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("the exec plugin RAN: the sentinel file exists.\n\n" +
			"A configuration file must never be able to make svcdoctor execute a local " +
			"program. ADR 0072 §13's reopen condition is \"None.\", and this is the test " +
			"that says so.")
	} else if !os.IsNotExist(err) {
		t.Fatalf("checking the sentinel: %v", err)
	}

	if got := server.requestCount(); got != 0 {
		t.Errorf("the API server received %d requests; a refused kubeconfig must reach the "+
			"network zero times, because the plugin is invoked by the first one", got)
	}
}

// TestTheRefusalNeverRepeatsTheConstructsContents is the frozen output rule.
//
// A refusal names **the construct** and never its command, arguments,
// environment names or values, or executable path. Those are strings an attacker
// influences by writing the file, and their only destinations would be an
// operator's terminal and a report they may then share.
func TestTheRefusalNeverRepeatsTheConstructsContents(t *testing.T) {
	server := newAPIServer(t)
	const (
		command  = "/opt/definitely-not-in-a-message/get-token"
		argument = "--secret-arg-canary"
		envName  = "SECRET_ENV_NAME_CANARY"
		envValue = "secret-env-value-canary"
	)
	path := kubeconfig{
		server: server.URL(),
		caPath: server.caPath,
		userBlock: "    exec:\n" +
			"      apiVersion: client.authentication.k8s.io/v1\n" +
			"      command: " + command + "\n" +
			"      args:\n" +
			"      - \"" + argument + "\"\n" +
			"      env:\n" +
			"      - name: " + envName + "\n" +
			"        value: " + envValue + "\n",
	}.write(t)

	_, err := Inspect(targetFor(path), false)
	if err == nil {
		t.Fatal("an exec kubeconfig was accepted")
	}
	for _, leaked := range []string{command, argument, envName, envValue} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("the refusal repeats %q from the refused construct:\n%v", leaked, err)
		}
	}
}

// TestEveryProhibitedConstructIsRefusedBeforeAnyRequest is the whole refusal
// list, each proven to cost zero round trips.
//
// # Zero requests is the assertion that matters
//
// Each of these was measured in Phase 12.1A to propagate into a usable
// rest.Config with **no error at all** — impersonation and proxy-url silently,
// insecure-skip-tls-verify by design. So "client-go would have failed anyway" is
// false for every row, and silence would have been indistinguishable from
// absence.
func TestEveryProhibitedConstructIsRefusedBeforeAnyRequest(t *testing.T) {
	tests := []struct {
		name      string
		userBlock string
		cluster   string
		names     string
	}{
		{
			name:      "auth-provider",
			userBlock: "    auth-provider:\n      name: gcp\n      config:\n        cmd-path: /usr/bin/gcloud\n",
			names:     "auth-provider",
		},
		// The serialized kubeconfig spells these `as`, `as-groups`, `as-uid` and
		// `as-user-extra`; the internal type clientcmd converts to calls them
		// Impersonate*. Writing the file's own spelling is the point — the
		// refusal has to fire on what an operator actually writes, and the first
		// version of this test used the internal names and passed against a build
		// that refused nothing.
		{
			name:      "impersonate user",
			userBlock: "    token: t\n    as: system:admin\n",
			names:     "impersonation",
		},
		{
			name:      "impersonate groups",
			userBlock: "    token: t\n    as-groups:\n    - system:masters\n",
			names:     "impersonation",
		},
		{
			name:      "impersonate uid",
			userBlock: "    token: t\n    as-uid: \"1000\"\n",
			names:     "impersonation",
		},
		{
			name:      "impersonate user extra",
			userBlock: "    token: t\n    as-user-extra:\n      scope:\n      - all\n",
			names:     "impersonation",
		},
		{
			name:      "basic auth",
			userBlock: "    username: admin\n    password: hunter2\n",
			names:     "basic authentication",
		},
		{
			name:      "anonymous",
			userBlock: "    {}\n",
			names:     "does not read a Kubernetes API anonymously",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newAPIServer(t)
			path := kubeconfig{
				server: server.URL(), caPath: server.caPath, userBlock: test.userBlock,
			}.write(t)

			_, err := Acquire(context.Background(), Params{Target: targetFor(path)})
			if err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
			if !errors.Is(err, ErrTarget) {
				t.Errorf("error is %v, want an ErrTarget refusal", err)
			}
			if !strings.Contains(err.Error(), test.names) {
				t.Errorf("the refusal does not name the construct %q:\n%v", test.names, err)
			}
			if got := server.requestCount(); got != 0 {
				t.Errorf("the API server received %d requests; every refusal happens before "+
					"any network operation", got)
			}
		})
	}
}

// TestProxyURLIsRefusedAndItsValueNeverAppears keeps a credential-bearing URL out
// of every message.
//
// A proxy URL may carry credentials in its userinfo, so the one thing this
// refusal must not do is repeat it — and the one thing it must not do *instead*
// is accept it, because a proxy changes the network position every claim in the
// report is scoped to.
func TestProxyURLIsRefusedAndItsValueNeverAppears(t *testing.T) {
	server := newAPIServer(t)
	// Userinfo included deliberately: a proxy URL can carry credentials, and the
	// assertion below is that none of it reaches a message.
	const proxy = "http://proxyuser:proxysecret@proxy.internal:3128" //nolint:gosec // fixture, never dialled
	path := kubeconfig{
		server: server.URL(), caPath: server.caPath,
	}.write(t)
	// Rewritten rather than templated, so the cluster block stays one shape.
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the kubeconfig: %v", err)
	}
	patched := strings.Replace(string(document), "  cluster:\n",
		"  cluster:\n    proxy-url: "+proxy+"\n", 1)
	//nolint:gosec // the path came from kubeconfig.write, which is t.TempDir
	if err := os.WriteFile(path, []byte(patched), 0o600); err != nil {
		t.Fatalf("rewriting the kubeconfig: %v", err)
	}

	_, err = Acquire(context.Background(), Params{Target: targetFor(path)})
	if err == nil {
		t.Fatal("proxy-url was accepted")
	}
	if !strings.Contains(err.Error(), "proxy-url") {
		t.Errorf("the refusal does not name the construct: %v", err)
	}
	for _, leaked := range []string{proxy, "proxysecret", "proxy.internal"} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("the refusal repeats %q from the proxy URL:\n%v", leaked, err)
		}
	}
	if got := server.requestCount(); got != 0 {
		t.Errorf("the API server received %d requests, want 0", got)
	}
}

// TestInsecureSkipTLSVerifyIsRefused keeps svcdoctor from disabling the
// verification it exists to perform.
func TestInsecureSkipTLSVerifyIsRefused(t *testing.T) {
	server := newAPIServer(t)
	path := kubeconfig{server: server.URL(), caPath: server.caPath}.write(t)
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the kubeconfig: %v", err)
	}
	patched := strings.Replace(string(document), "  cluster:\n",
		"  cluster:\n    insecure-skip-tls-verify: true\n", 1)
	//nolint:gosec // the path came from kubeconfig.write, which is t.TempDir
	if err := os.WriteFile(path, []byte(patched), 0o600); err != nil {
		t.Fatalf("rewriting the kubeconfig: %v", err)
	}

	if _, err := Acquire(context.Background(), Params{Target: targetFor(path)}); err == nil ||
		!strings.Contains(err.Error(), "insecure-skip-tls-verify") {
		t.Fatalf("insecure-skip-tls-verify was accepted or misreported: %v", err)
	}
	if got := server.requestCount(); got != 0 {
		t.Errorf("the API server received %d requests, want 0", got)
	}
}

// TestAPlaintextAPIServerIsRefused keeps a credential off an unverifiable
// channel.
//
// Every one of the four supported modes ends with a bearer token in a request
// header or a private key in a handshake. ADR 0028 and ADR 0030 fixed that a
// credential crosses only a channel svcdoctor verified, and an http:// server URL
// is not one.
func TestAPlaintextAPIServerIsRefused(t *testing.T) {
	path := kubeconfig{server: "http://api.internal:8080", caPath: "/dev/null"}.write(t)
	_, err := Inspect(targetFor(path), false)
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("a plaintext API server URL was accepted or misreported: %v", err)
	}
}

// TestAnAmbientProxyCannotChangeTheAPIRoute is the vantage guarantee.
//
// # Why the environment has to be neutralized rather than left alone
//
// Leaving rest.Config.Proxy nil makes client-go fall back to net/http's
// environment proxy support, so HTTP_PROXY or HTTPS_PROXY would silently reroute
// every request — and ADR 0092 section 2.4 froze that a claim is scoped to the
// position it was measured from. A report whose vantage depended on a variable
// the report never saw would be wrong in a way nobody could see.
//
// The proof is behavioural: with a hostile proxy set in the environment, the
// acquisition still reaches the real API server, which is only possible if
// nothing consulted the variable.
func TestAnAmbientProxyCannotChangeTheAPIRoute(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{}}
	server.slicePages = []scriptedPage{{}}

	// A proxy that would refuse every connection if it were ever consulted.
	const blackhole = "http://127.0.0.1:1"
	for _, variable := range []string{
		"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
	} {
		t.Setenv(variable, blackhole)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	result, err := Acquire(context.Background(),
		Params{Target: targetFor(tokenKubeconfig(t, server))})
	if err != nil {
		t.Fatalf("acquiring: %v", err)
	}
	if !result.Service.OK() {
		t.Fatalf("the Service read did not reach the API server: %+v", result.Service)
	}
	if got := server.requestCount(); got != 3 {
		t.Errorf("the API server received %d requests, want 3; an ambient proxy changed the "+
			"route", got)
	}
}

// TestTheDirectProxySelectsNothing states the mechanism the test above measures.
func TestTheDirectProxySelectsNothing(t *testing.T) {
	proxyURL, err := directDial(nil)
	if err != nil {
		t.Fatalf("the direct proxy returned an error: %v", err)
	}
	if proxyURL != nil {
		t.Errorf("the direct proxy selected %v; it must select nothing, ever", proxyURL)
	}
}

// TestACredentialIsBoundToTheAPIServerAndNothingElse is the credential-authority
// guarantee, proven rather than documented.
//
// # The claim
//
// A Kubernetes credential authorizes exactly one thing: the API server this
// target selected. It does not authorize a Pod IP, a Service cluster IP, an
// EndpointSlice address, a Node IP, a discovered hostname, or any Kafka,
// PostgreSQL, Redis or RabbitMQ endpoint.
//
// It is structural rather than a rule to remember: security.Credential has no
// accessor that returns the secret without naming an endpoint, and only one
// endpoint matches. This asks for the secret at four addresses a Kubernetes run
// could plausibly discover, and every one of them is refused by the type.
func TestACredentialIsBoundToTheAPIServerAndNothingElse(t *testing.T) {
	server := newAPIServer(t)
	path := tokenKubeconfig(t, server)
	host, port := mustHostPort(t, server.URL())

	view, err := loadKubeconfig(path, "prod", false)
	if err != nil {
		t.Fatalf("loading the kubeconfig: %v", err)
	}
	endpoint, err := security.NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("building the API endpoint: %v", err)
	}
	credential, err := bindCredential(view, security.Credential{}, endpoint)
	if err != nil {
		t.Fatalf("binding the credential: %v", err)
	}

	if _, err := credential.SecretFor(endpoint); err != nil {
		t.Fatalf("the credential refused its own endpoint: %v", err)
	}

	// Four addresses a Kubernetes run can reach: a Pod IP, a Service cluster IP,
	// an EndpointSlice address and another service's endpoint entirely.
	for _, elsewhere := range []struct {
		host string
		port uint16
	}{
		{"10.244.1.7", 8080},
		{"10.96.0.10", 443},
		{"fd00::1", 6443},
		{"orders-db.internal", 5432},
	} {
		other, err := security.NewEndpoint(elsewhere.host, elsewhere.port)
		if err != nil {
			t.Fatalf("building %s: %v", elsewhere.host, err)
		}
		if _, err := credential.SecretFor(other); !errors.Is(err, security.ErrEndpointMismatch) {
			t.Errorf("the Kubernetes credential was released for %s:%d (err=%v).\n\n"+
				"A Kubernetes credential authorizes the API server and nothing else. No "+
				"discovered endpoint inherits it.", elsewhere.host, elsewhere.port, err)
		}
	}
}

// TestACredentialBoundElsewhereIsRefusedRatherThanRebound is ADR 0050 section 4.
//
// A composition root may not rebind a credential. A mismatch is a refusal, and
// the refusal happens before a client exists.
func TestACredentialBoundElsewhereIsRefusedRatherThanRebound(t *testing.T) {
	server := newAPIServer(t)
	// A kubeconfig user with no credential of its own, so the only thing under
	// test is the binding. A user carrying a token as well would be refused one
	// step earlier, for ambiguity, and this test would pass without ever
	// reaching the binding check.
	path := kubeconfig{
		server: server.URL(), caPath: server.caPath, userBlock: "    {}\n",
	}.write(t)

	elsewhere, err := security.NewEndpoint("orders-db.internal", 5432)
	if err != nil {
		t.Fatalf("building an endpoint: %v", err)
	}
	credential, err := security.NewCredential(elsewhere, "", security.NewSecret("token"))
	if err != nil {
		t.Fatalf("building a credential: %v", err)
	}

	_, err = Acquire(context.Background(),
		Params{Target: targetFor(path), Credential: credential})
	if err == nil {
		t.Fatal("a credential bound elsewhere was accepted")
	}
	// **svcdoctor's own message, not security.Credential's.**
	//
	// Two independent mechanisms refuse this, and asserting the weaker one hides
	// the stronger. SecretFor refuses any endpoint but the bound one, so a build
	// with no explicit check still fails — later, from inside applyCredential,
	// with the type's message. The explicit check exists so the refusal happens
	// **before a rest.Config is built**, and this is the sentence only that check
	// produces. Planting its removal is what showed the difference: the mutation
	// survived a test that matched "bound to", which both messages contain.
	if !strings.Contains(err.Error(), "this target's API server is") {
		t.Errorf("the refusal came from the credential type rather than from the "+
			"composition check that runs before a client exists: %v", err)
	}
	if got := server.requestCount(); got != 0 {
		t.Errorf("the API server received %d requests, want 0", got)
	}
}

// TestTwoCredentialsAreRefusedRatherThanRankedByPrecedence keeps authority
// auditable.
//
// A configuration that authenticates as whichever credential a tool happens to
// prefer is one nobody can read. The refusal is the same discipline
// config.NewTargetID applies to a duplicated identifier.
func TestTwoCredentialsAreRefusedRatherThanRankedByPrecedence(t *testing.T) {
	server := newAPIServer(t)
	certPEM, keyPEM := clientCertificate(t)
	directory := t.TempDir()
	certPath := filepath.Join(directory, "client.crt")
	keyPath := filepath.Join(directory, "client.key")
	for path, content := range map[string]string{certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}

	tests := map[string]string{
		"token and client certificate": "    token: t\n" +
			"    client-certificate: " + certPath + "\n" +
			"    client-key: " + keyPath + "\n",
		"token and tokenFile": "    token: t\n    tokenFile: " + keyPath + "\n",
	}
	for name, block := range tests {
		t.Run(name, func(t *testing.T) {
			path := kubeconfig{
				server: server.URL(), caPath: server.caPath, userBlock: block,
			}.write(t)
			if _, err := Inspect(targetFor(path), false); err == nil ||
				!strings.Contains(err.Error(), "more than one credential") {
				t.Fatalf("two credentials were accepted or misreported: %v", err)
			}
		})
	}

	// A target credential beside a kubeconfig credential is the same ambiguity
	// across two files, and is refused identically.
	path := tokenKubeconfig(t, server)
	if _, err := Inspect(targetFor(path), true); err == nil ||
		!strings.Contains(err.Error(), "more than one credential") {
		t.Fatalf("a target credential beside a kubeconfig one was accepted: %v", err)
	}
}

// TestEveryAuthenticationModeReachesTheAPIServer proves the four modes work.
//
// It is the positive half of the refusal tests: a contract that refuses
// everything is easy and useless. Each mode completes a whole acquisition against
// the hermetic server, which means the credential was resolved, bound, revealed
// once and placed on the wire.
func TestEveryAuthenticationModeReachesTheAPIServer(t *testing.T) {
	certPEM, keyPEM := clientCertificate(t)

	tests := []struct {
		name string
		mode string
		user func(t *testing.T) string
	}{
		{
			name: "inline bearer token",
			mode: servicekubernetes.AuthModeToken,
			user: func(*testing.T) string { return "    token: inline-token\n" },
		},
		{
			name: "token file read by svcdoctor",
			mode: servicekubernetes.AuthModeTokenFile,
			user: func(t *testing.T) string {
				return "    tokenFile: " + writeFile(t, "token", "file-token\n") + "\n"
			},
		},
		{
			name: "client certificate and key",
			mode: servicekubernetes.AuthModeClientCert,
			user: func(t *testing.T) string {
				directory := t.TempDir()
				certPath := filepath.Join(directory, "client.crt")
				keyPath := filepath.Join(directory, "client.key")
				for path, content := range map[string]string{
					certPath: certPEM, keyPath: keyPEM,
				} {
					if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
						t.Fatalf("writing %s: %v", path, err)
					}
				}
				return "    client-certificate: " + certPath + "\n" +
					"    client-key: " + keyPath + "\n"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newAPIServer(t)
			server.service = selectorService("uid-1")
			server.podPages = []scriptedPage{{}}
			server.slicePages = []scriptedPage{{}}

			path := kubeconfig{
				server: server.URL(), caPath: server.caPath, userBlock: test.user(t),
			}.write(t)

			result, err := Acquire(context.Background(), Params{Target: targetFor(path)})
			if err != nil {
				t.Fatalf("acquiring: %v", err)
			}
			if !result.Service.OK() {
				t.Fatalf("the Service read failed: %+v", result.Service)
			}
			if got := result.Authority.Mode; got != test.mode {
				t.Errorf("auth mode is %q, want %q", got, test.mode)
			}
		})
	}
}

// TestATargetSuppliedTokenAuthenticates covers the fourth source: a credential
// the target itself names, resolved outside this package.
func TestATargetSuppliedTokenAuthenticates(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{}}
	server.slicePages = []scriptedPage{{}}

	// A kubeconfig user with no credential of its own: the target supplies it.
	path := kubeconfig{
		server: server.URL(), caPath: server.caPath, userBlock: "    {}\n",
	}.write(t)

	host, port := mustHostPort(t, server.URL())
	endpoint, err := security.NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("building the endpoint: %v", err)
	}
	credential, err := security.NewCredential(endpoint, "", security.NewSecret("target-token"))
	if err != nil {
		t.Fatalf("building the credential: %v", err)
	}

	result, err := Acquire(context.Background(),
		Params{Target: targetFor(path), Credential: credential})
	if err != nil {
		t.Fatalf("acquiring: %v", err)
	}
	if got := result.Authority.Mode; got != servicekubernetes.AuthModeToken {
		t.Errorf("auth mode is %q, want %q", got, servicekubernetes.AuthModeToken)
	}
	if !result.Service.OK() {
		t.Errorf("the Service read failed: %+v", result.Service)
	}
}

// TestConnectRevalidatesRatherThanTrustingAnEarlierInspection.
//
// # Why the check is repeated
//
// Inspect runs at configuration time, possibly minutes earlier and possibly in a
// different process. A kubeconfig that gained an `exec` stanza in between, or a
// target assembled by a caller that never inspected one at all, must not be
// reachable because an earlier pass said the configuration was clean. The refusal
// is cheap and the alternative is a time-of-check/time-of-use hole in the one
// check that matters most.
//
// A target declaring both authorities is the shape that makes the omission
// visible: without re-validation the in-cluster branch is taken and the
// kubeconfig — the thing the operator actually pointed at — is never read.
func TestConnectRevalidatesRatherThanTrustingAnEarlierInspection(t *testing.T) {
	server := newAPIServer(t)
	path := tokenKubeconfig(t, server)

	for _, test := range []struct {
		name   string
		target Target
		names  string
	}{
		{
			name: "both authorities",
			target: Target{
				Kubeconfig: path, Context: "prod", InCluster: true,
				Namespace: "payments", ServiceName: "payments-api",
			},
			names: "mutually exclusive",
		},
		{
			name: "no namespace",
			target: Target{
				Kubeconfig: path, Context: "prod", ServiceName: "payments-api",
			},
			names: "a namespace is required",
		},
		{
			name: "no context",
			target: Target{
				Kubeconfig: path, Namespace: "payments", ServiceName: "payments-api",
			},
			names: "context is required",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Connect(test.target, security.Credential{})
			if err == nil {
				t.Fatal("Connect accepted a target Validate refuses")
			}
			if !errors.Is(err, ErrTarget) {
				t.Errorf("error is %v, want an ErrTarget refusal", err)
			}
			if !strings.Contains(err.Error(), test.names) {
				t.Errorf("the refusal reads %q, want it to mention %q", err, test.names)
			}
			if got := server.requestCount(); got != 0 {
				t.Errorf("the API server received %d requests, want 0", got)
			}
		})
	}
}

// TestTheRESTConfigAlwaysSetsAnExplicitDirectProxy is the structural half of the
// vantage guarantee.
//
// # Why the behavioural test above is not sufficient on its own
//
// TestAnAmbientProxyCannotChangeTheAPIRoute runs against a loopback server, and
// Go's own `http.ProxyFromEnvironment` never proxies a loopback address whatever
// HTTP_PROXY says — so a build that dropped the explicit Proxy would still pass
// it. That is a property of the fixture, not of the product, and it was found by
// planting exactly that mutation: it survived.
//
// This asserts what the behavioural test cannot: `rest.Config.Proxy` is **set**,
// so client-go never falls back to net/http's environment support, and it selects
// no proxy for any request. Against a real API server on a routable address, that
// difference is the whole of ADR 0092 §2.4 — a report whose network vantage was
// decided by a variable the report never saw.
func TestTheRESTConfigAlwaysSetsAnExplicitDirectProxy(t *testing.T) {
	server := newAPIServer(t)
	view, err := loadKubeconfig(tokenKubeconfig(t, server), "prod", false)
	if err != nil {
		t.Fatalf("loading the kubeconfig: %v", err)
	}
	endpoint, err := view.endpoint()
	if err != nil {
		t.Fatalf("resolving the endpoint: %v", err)
	}
	credential, err := bindCredential(view, security.Credential{}, endpoint)
	if err != nil {
		t.Fatalf("binding the credential: %v", err)
	}

	config, err := buildRESTConfig(view, endpoint, credential)
	if err != nil {
		t.Fatalf("building the rest.Config: %v", err)
	}
	if config.Proxy == nil {
		t.Fatal("rest.Config.Proxy is nil.\n\n" +
			"client-go then falls back to net/http's environment proxy support, so " +
			"HTTP_PROXY silently decides the network position every claim in the report " +
			"is scoped to — a variable the report never saw deciding what the report means.")
	}

	// A routable host, deliberately: a loopback request is exempt from proxying
	// in net/http regardless, which is precisely why this test exists.
	t.Setenv("HTTPS_PROXY", "http://hostile.invalid:3128")
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, "https://api.cluster.example:6443/x", nil)
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	proxyURL, err := config.Proxy(request)
	if err != nil {
		t.Fatalf("the proxy function returned an error: %v", err)
	}
	if proxyURL != nil {
		t.Errorf("the proxy function selected %v for a routable host; it must select nothing",
			proxyURL)
	}
}
