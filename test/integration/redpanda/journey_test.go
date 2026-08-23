//go:build integration

package redpanda

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// TestPLAINCompletesTheWholeJourney is the control.
//
// PLAIN worked against Redpanda before ADR 0061 and must still work after it —
// it is the evidence that the bound change fixed SCRAM without disturbing the
// mechanism that was already fine.
func TestPLAINCompletesTheWholeJourney(t *testing.T) {
	o := defaults(t)
	o.mechanism = mechanismPLAIN
	o.identity, o.secret = plainIdentity, plainSecret

	result := diagnose(t, o)

	for _, step := range []domain.Step{
		servicekafka.StepAPIVersions,
		servicekafka.StepSASLHandshake,
		servicekafka.StepSASLAuthenticate,
		servicekafka.StepMetadata,
	} {
		if !passingNode(result, step) {
			t.Errorf("%s did not pass over PLAIN; findings: %v", step, codesOf(result))
		}
	}
	if got := result.Report().Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("summary = %v, want OK; findings: %v", got, codesOf(result))
	}
}

// TestWrongPLAINCredentialIsAPeerRefusal is the negative direction for PLAIN.
func TestWrongPLAINCredentialIsAPeerRefusal(t *testing.T) {
	o := defaults(t)
	o.mechanism = mechanismPLAIN
	o.identity, o.secret = plainIdentity, "definitely-not-the-plain-password"

	result := diagnose(t, o)

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Fatalf("%d authentication nodes, want exactly 1", len(auth))
	}
	if got := auth[0].FailureClass(); got != domain.FailureAuthCredentialsRejected {
		t.Errorf("failure class = %v, want AUTH_CREDENTIALS_REJECTED", got)
	}
}

// TestTheAdvertisedTopologyIsMeasured proves the journey does not stop at
// Metadata.
//
// Redpanda advertises one broker on each listener. What matters here is the
// shape: an advertisement node, then credential-free transport beneath it.
func TestTheAdvertisedTopologyIsMeasured(t *testing.T) {
	result := diagnose(t, defaults(t))

	advertisements := nodesOf(result, servicekafka.StepBrokerAdvertised)
	if len(advertisements) == 0 {
		t.Fatalf("no advertised broker was measured; findings: %v", codesOf(result))
	}
	for _, a := range advertisements {
		if a.State() != domain.StatePass {
			t.Errorf("advertisement %s is %v (%v)", a.ID(), a.State(), a.FailureClass())
		}
	}
	if got := result.Report().Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("summary = %v, want OK; findings: %v", got, codesOf(result))
	}
}

// TestTLSIsVerifiedAgainstTheFixtureCA pins that the journey above ran over a
// verified channel rather than an unverified one.
//
// It matters because svcdoctor's credential-transport policy refuses to send a
// password over an unverified channel. A suite that accidentally ran insecure
// would show authentication SKIPPED, not PASS — but stating the property
// directly means a future change to the policy cannot quietly weaken what this
// suite proves.
func TestTLSIsVerifiedAgainstTheFixtureCA(t *testing.T) {
	result := diagnose(t, defaults(t))

	if result.Report().Security().TLSVerificationDisabled() {
		t.Fatal("the run recorded disabled TLS verification; the SCRAM evidence " +
			"in this package would then say nothing about a verified channel")
	}
	if !passingNode(result, servicekafka.StepSASLAuthenticate) {
		t.Fatalf("authentication did not pass; findings: %v", codesOf(result))
	}
}

// TestNoProductionSourceNamesRedpanda is the invariant this whole fixture is
// most at risk of quietly breaking.
//
// Redpanda works because it speaks the Kafka protocol, and it must keep working
// for that reason alone. The moment a vendor name appears in a production
// branch, the compatibility claim stops being about protocol behaviour.
//
// It reads the repository rather than the binary, which is coarse but honest:
// the mention it forbids is a source-level one, and a comment naming a
// mechanism svcdoctor does not implement is not what it is looking for.
func TestNoProductionSourceNamesRedpanda(t *testing.T) {
	offenders := productionSourcesMentioning(t, "redpanda")
	if len(offenders) > 0 {
		t.Errorf("production source names Redpanda in %v.\n\n"+
			"Redpanda is diagnosed because it speaks the Kafka protocol. A "+
			"provider-specific branch would make that claim false and would make "+
			"this fixture evidence about a special case rather than about "+
			"compatibility.", offenders)
	}
}

// productionSourcesMentioning lists non-test Go files under internal/ and cmd/
// whose code — not comments — contains needle, case-insensitively.
func productionSourcesMentioning(t *testing.T, needle string) []string {
	t.Helper()

	root := repositoryRoot(t)
	var out []string
	for _, path := range productionGoFiles(t) {
		// productionGoFiles returns repository-relative paths, for readable
		// failure messages; reading one needs the root joined back on, because
		// a test's working directory is its own package.
		body, err := readFile(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue // a comment may discuss it; a branch may not
			}
			if strings.Contains(strings.ToLower(trimmed), needle) {
				out = append(out, path)
				break
			}
		}
	}
	return out
}
