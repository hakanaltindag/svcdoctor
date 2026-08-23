//go:build integration

// Package redpanda runs svcdoctor against a real Redpanda broker.
//
// It exists because ADR 0061 was decided on evidence from a real instance and a
// decision resting on a container someone once ran by hand is not evidence
// anybody can re-check. Phase 6.8 measured Redpanda's 130-byte SCRAM salt
// against an ad-hoc instance; this suite regenerates that measurement on demand.
//
// **The version is pinned.** Redpanda's salt size is a compile-time constant in
// its own source, so "Redpanda" is not the thing under test — v25.1.9 is. See
// env/compose.yaml.
//
// Excluded from `go test ./...` by the integration build tag. See README.md.
package redpanda

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// The broker in env/compose.yaml.
//
// Both credentials are fixture-only values on a loopback container, created by
// the Makefile's redpanda-users step. Neither authenticates anything anywhere
// else.
const (
	brokerHost = "localhost"
	tlsPort    = 19292
	plainPort  = 19291

	scramIdentity = "svcdoctor"
	scramSecret   = "svcdoctor-redpanda-canary"

	plainIdentity = "plainuser"
	plainSecret   = "plainuser-redpanda-canary"

	mechanismSCRAM = "SCRAM-SHA-256"
	mechanismPLAIN = "PLAIN"
)

func caPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile("env/certs/ca-cert.pem")
	if err != nil {
		t.Fatalf("reading the validation CA (run env/gen-certs.sh): %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the validation CA did not parse")
	}
	return pool
}

type options struct {
	host      string
	port      uint16
	identity  string
	secret    string
	mechanism string
	pool      *x509.CertPool
	plaintext bool
}

func defaults(t *testing.T) options {
	t.Helper()
	return options{
		host:      brokerHost,
		port:      tlsPort,
		identity:  scramIdentity,
		secret:    scramSecret,
		mechanism: mechanismSCRAM,
		pool:      caPool(t),
	}
}

// diagnose runs the production composition root against the real broker.
//
// `app.DiagnoseKafka` and nothing else: the whole value of this suite is that
// Redpanda travels the same code path Apache Kafka does, with no vendor branch
// anywhere. A separate harness that assembled the layers differently would prove
// something about the harness.
func diagnose(t *testing.T, o options) app.Result {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	vantage, err := domain.NewLocalVantage("validation-host.svcdoctor.test")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	var credential security.Credential
	if o.identity != "" {
		endpoint, eerr := security.NewEndpoint(o.host, o.port)
		if eerr != nil {
			t.Fatalf("security.NewEndpoint: %v", eerr)
		}
		credential, err = security.NewCredential(endpoint, o.identity, security.NewSecret(o.secret))
		if err != nil {
			t.Fatalf("security.NewCredential: %v", err)
		}
	}

	var tlsPlan *transport.TLSOptions
	if !o.plaintext {
		tlsPlan = &transport.TLSOptions{RootCAs: o.pool}
	}

	result, err := app.DiagnoseKafka(ctx, app.KafkaParams{
		Host:        o.host,
		Port:        o.port,
		Mechanism:   o.mechanism,
		Credential:  credential,
		Resolver:    dns.SystemResolver{},
		Dialer:      tcp.SystemDialer{},
		TLS:         tlsPlan,
		StepTimeout: 10 * time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-integration",
	})
	if err != nil {
		t.Fatalf("DiagnoseKafka: %v", err)
	}
	return result
}

// --- small readers over a composed result ----------------------------------

func nodesOf(r app.Result, step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, n := range r.Report().Graph().Nodes() {
		if n.Step() == step {
			out = append(out, n)
		}
	}
	return out
}

func codesOf(r app.Result) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, r.Report().FindingCount())
	for _, f := range r.Report().Findings() {
		out = append(out, f.Code())
	}
	return out
}

func hasCode(r app.Result, want domain.FindingCode) bool {
	for _, c := range codesOf(r) {
		if c == want {
			return true
		}
	}
	return false
}

// passingNode reports whether any node of the step passed.
func passingNode(r app.Result, step domain.Step) bool {
	for _, n := range nodesOf(r, step) {
		if n.State() == domain.StatePass {
			return true
		}
	}
	return false
}
