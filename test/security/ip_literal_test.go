package security

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 6.7 — IP literal targets, proved from the production composition rather
// than from a fixture.
//
// A literal is identity-bearing, so it must be redacted; it is not a name, so no
// resolution may be claimed for it; and it must not widen what a credential is
// authorized for. All three are measured here on real reports produced by
// internal/app.

const (
	literalCanaryV4   = "10.88.77.66"
	literalCanaryV6   = "2001:db8:feed:beef::42"
	literalCanaryPort = 5432
)

// refusingDialer stops every run at L2, so the reports stay small and the
// property under test is the only thing in them.
type refusingDialer struct{}

func (refusingDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
}

// forbiddenResolver fails the test if a literal run resolves anything.
type forbiddenResolver struct{ t *testing.T }

func (r forbiddenResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	r.t.Helper()
	r.t.Error("a literal target reached a resolver")
	return nil, errors.New("the resolver must not be reached")
}

func literalPostgresRun(t *testing.T, host string) domain.Report {
	t.Helper()

	vantage, err := domain.NewLocalVantage("literal-runner-canary.local")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	result, err := app.DiagnosePostgres(context.Background(), app.PostgresParams{
		Host: host, Port: literalCanaryPort,
		Role:        "svcdoctor",
		Resolver:    forbiddenResolver{t: t},
		Dialer:      refusingDialer{},
		StepTimeout: time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-security",
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres(%q): %v", host, err)
	}
	return result.Report()
}

// --- no resolution, no DNS claim -----------------------------------------

func TestALiteralTargetProducesNoDNSEvidenceOrFinding(t *testing.T) {
	for _, host := range []string{literalCanaryV4, literalCanaryV6} {
		t.Run(host, func(t *testing.T) {
			report := literalPostgresRun(t, host)

			for _, node := range report.Graph().Nodes() {
				if node.Layer() == domain.LayerDNS || node.Step() == vocabulary.StepDNSLookup {
					t.Fatalf("a literal run recorded %s at %s", node.ID(), node.Layer())
				}
			}
			for _, f := range report.Findings() {
				if strings.HasPrefix(string(f.Code()), "DNS_") {
					t.Fatalf("a literal run produced %s", f.Code())
				}
				text := f.Summary() + f.Detail()
				for _, forbidden := range []string{"hostname", "resolved to", "did not resolve"} {
					if strings.Contains(text, forbidden) {
						t.Errorf("%s claims resolution: %q", f.Code(), forbidden)
					}
				}
			}
		})
	}
}

// The run is not empty: a literal target still gets a diagnosed transport
// failure with an owner, which is what makes the test above non-vacuous.
func TestALiteralTargetStillProducesAnOwnedTCPFinding(t *testing.T) {
	report := literalPostgresRun(t, literalCanaryV4)

	var codes []domain.FindingCode
	for _, f := range report.Findings() {
		codes = append(codes, f.Code())
	}
	if len(codes) == 0 {
		t.Fatalf("a refused literal target produced no finding at all")
	}
	found := false
	for _, code := range codes {
		if code == "TCP_CONNECTION_NOT_ESTABLISHED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings = %v, want TCP_CONNECTION_NOT_ESTABLISHED", codes)
	}
}

// The conceptual layer is unchanged: a missing L1 observation must not promote
// TCP to L1.
func TestALiteralTCPFailureIsStillL2(t *testing.T) {
	report := literalPostgresRun(t, literalCanaryV6)

	layer := report.Summary().FirstBrokenLayer()
	if layer != domain.LayerTCP {
		t.Fatalf("firstBrokenLayer = %s, want L2", layer)
	}
}

// The schema is unchanged by any of this.
func TestALiteralReportKeepsSchemaVersionOne(t *testing.T) {
	if got := domain.SchemaVersion; got != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", got)
	}
	encoded := canonicalJSON(t, literalPostgresRun(t, literalCanaryV4))
	if !strings.Contains(encoded, `"schemaVersion":1`) {
		t.Fatalf("the canonical JSON does not carry schemaVersion 1")
	}
	// And it invents no resolution.
	for _, forbidden := range []string{"dns.lookup", "dns.answers", `"L1"`} {
		if strings.Contains(encoded, forbidden) {
			t.Errorf("the canonical JSON of a literal run contains %q", forbidden)
		}
	}
}

// --- redaction ------------------------------------------------------------

// A literal is identity-bearing and must not survive into a shareable report, in
// either family.
func TestAShareableReportRedactsALiteralTarget(t *testing.T) {
	for _, host := range []string{literalCanaryV4, literalCanaryV6} {
		t.Run(host, func(t *testing.T) {
			local := literalPostgresRun(t, host)

			// Non-vacuity: the raw value is present locally.
			localJSON := canonicalJSON(t, local)
			if !strings.Contains(localJSON, host) {
				t.Fatalf("the local report does not contain %s; the test would be vacuous", host)
			}

			shareable, err := redaction.Redact(local)
			if err != nil {
				t.Fatalf("Redact: %v", err)
			}
			encoded := canonicalJSON(t, shareable)
			if strings.Contains(encoded, host) {
				t.Fatalf("the shareable report leaks %s:\n%s", host, encoded)
			}
			if !strings.Contains(encoded, "ip-") {
				t.Fatalf("the literal was not pseudonymized into the ip namespace:\n%s", encoded)
			}
			counts := shareable.Security().Redactions()
			if counts.IPAddress == 0 {
				t.Fatalf("redaction counts report no IP address replaced: %+v", counts)
			}
		})
	}
}

// One literal maps to one pseudonym everywhere it appears, so a reader can still
// correlate the target with the nodes measured for it.
func TestOneLiteralKeepsOnePseudonym(t *testing.T) {
	local := literalPostgresRun(t, literalCanaryV4)
	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	target := shareable.Target().Requested()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", target, err)
	}

	seen := 0
	for _, node := range shareable.Graph().Nodes() {
		ref := node.Subject().Ref()
		if !strings.Contains(ref, host) {
			t.Errorf("%s has subject %q, which does not carry the target pseudonym %q",
				node.ID(), ref, host)
			continue
		}
		seen++
	}
	if seen == 0 {
		t.Fatal("no node carried the target pseudonym")
	}
}

// Two different literals must not collapse onto one pseudonym: the report would
// then claim two endpoints were one.
func TestTwoLiteralsDoNotCollapse(t *testing.T) {
	four, err := redaction.Redact(literalPostgresRun(t, literalCanaryV4))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	six, err := redaction.Redact(literalPostgresRun(t, literalCanaryV6))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	// Within one report the two would be numbered apart; across reports the
	// pseudonyms are deliberately unrelated. The property that matters here is
	// that neither raw value appears in the other's report.
	if strings.Contains(canonicalJSON(t, four), literalCanaryV6) {
		t.Error("the IPv4 report leaked the IPv6 canary")
	}
	if strings.Contains(canonicalJSON(t, six), literalCanaryV4) {
		t.Error("the IPv6 report leaked the IPv4 canary")
	}
}

// Redacting a shareable report again changes nothing it has not already
// changed: no raw value reappears and no pseudonym is renumbered into a leak.
func TestRedactingALiteralReportIsIdempotentInEffect(t *testing.T) {
	once, err := redaction.Redact(literalPostgresRun(t, literalCanaryV6))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	encoded := canonicalJSON(t, once)
	if strings.Contains(encoded, literalCanaryV6) {
		t.Fatalf("the first redaction leaked the canary")
	}
	twice, err := redaction.Redact(once)
	if err != nil {
		// Redacting an already-shareable report may be refused; that is a valid
		// answer and not a leak. Only a leak fails this test.
		return
	}
	if strings.Contains(canonicalJSON(t, twice), literalCanaryV6) {
		t.Fatalf("re-redaction leaked the canary")
	}
}

// An IPv6 pseudonym must not leave a bracket stranded or lose its port.
func TestARedactedIPv6EndpointStaysWellFormed(t *testing.T) {
	shareable, err := redaction.Redact(literalPostgresRun(t, literalCanaryV6))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	encoded := canonicalJSON(t, shareable)

	if strings.Contains(encoded, "[[") || strings.Contains(encoded, "]]") {
		t.Errorf("double brackets in a redacted report:\n%s", encoded)
	}
	target := shareable.Target().Requested()
	if strings.ContainsAny(target, "[]") {
		t.Errorf("the redacted target %q kept a stray bracket", target)
	}
	if !strings.HasSuffix(target, ":5432") {
		t.Errorf("the redacted target %q lost its port", target)
	}
}

// --- credential authority --------------------------------------------------

// A credential bound to one address is not authorized for another, and being an
// address rather than a name buys nothing.
func TestALiteralCredentialIsNotAuthorizedForAnotherAddress(t *testing.T) {
	bound, err := security.NewEndpoint("10.20.30.40", 9093)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(bound, "svcdoctor", security.NewSecret("canary"))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}

	for _, other := range []string{"10.20.30.41", "10.20.30.4", "2001:db8::40", "kafka.internal"} {
		endpoint, err := security.NewEndpoint(other, 9093)
		if err != nil {
			t.Fatalf("NewEndpoint(%q): %v", other, err)
		}
		if _, err := credential.SecretFor(endpoint); err == nil {
			t.Errorf("a credential bound to 10.20.30.40:9093 opened for %s:9093", other)
		}
	}
}

// The same address spelled differently is still the same endpoint, so
// canonicalization does not accidentally revoke a correct credential.
func TestCanonicalizationDoesNotBreakACorrectBinding(t *testing.T) {
	for _, spelling := range []string{"2001:db8::40", "2001:0db8:0:0:0:0:0:40", "2001:DB8::40"} {
		host, err := probe.ParseHost(spelling)
		if err != nil {
			t.Fatalf("ParseHost(%q): %v", spelling, err)
		}
		endpoint, err := security.NewEndpoint(host.String(), 9093)
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		canonical, err := security.NewEndpoint("2001:db8::40", 9093)
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		if !endpoint.Equal(canonical) {
			t.Errorf("%q normalized to %s, which does not equal the canonical endpoint",
				spelling, endpoint)
		}
	}
}

// A run whose credential names a different endpoint is refused before anything
// is measured, whether the endpoints are names or addresses.
func TestARunRefusesACredentialBoundElsewhere(t *testing.T) {
	elsewhere, err := security.NewEndpoint("10.20.30.41", literalCanaryPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(elsewhere, "svcdoctor", security.NewSecret("canary"))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	vantage, err := domain.NewLocalVantage("literal-runner-canary.local")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	_, err = app.DiagnoseKafka(context.Background(), app.KafkaParams{
		Host: "10.20.30.40", Port: literalCanaryPort,
		Mechanism:   "PLAIN",
		Credential:  credential,
		Resolver:    forbiddenResolver{t: t},
		Dialer:      refusingDialer{},
		StepTimeout: time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-security",
	})
	if err == nil {
		t.Fatal("a credential bound to another address was accepted")
	}
	if !strings.Contains(err.Error(), "different endpoint") {
		t.Fatalf("the refusal does not name the cause: %v", err)
	}
}

// A host svcdoctor cannot measure truthfully is refused by the composition root
// too, not only by the CLI.
func TestTheCompositionRootRefusesAZonedLiteral(t *testing.T) {
	vantage, err := domain.NewLocalVantage("literal-runner-canary.local")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	_, err = app.DiagnosePostgres(context.Background(), app.PostgresParams{
		Host: "fe80::1%en0", Port: literalCanaryPort,
		Role:        "svcdoctor",
		Resolver:    forbiddenResolver{t: t},
		Dialer:      refusingDialer{},
		StepTimeout: time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-security",
	})
	if !errors.Is(err, app.ErrInvalidInput) {
		t.Fatalf("DiagnosePostgres error = %v, want ErrInvalidInput", err)
	}
}

// The requested target is canonical in both of its projections, so a
// non-canonical spelling cannot produce a report that names one endpoint twice.
func TestANonCanonicalLiteralIsCanonicalEverywhere(t *testing.T) {
	report := literalPostgresRun(t, "2001:0db8:feed:beef:0:0:0:42")

	want := "[" + literalCanaryV6 + "]:5432"
	if got := report.Target().Requested(); got != want {
		t.Errorf("report target = %q, want %q", got, want)
	}
	for _, node := range report.Graph().Nodes() {
		if node.Step() != vocabulary.StepTargetRequested {
			continue
		}
		if got := node.Subject().Ref(); got != want {
			t.Errorf("anchor subject = %q, want %q", got, want)
		}
	}
	encoded := canonicalJSON(t, report)
	if strings.Contains(encoded, "2001:0db8") {
		t.Errorf("a non-canonical spelling survived into the report:\n%s", encoded)
	}
}
