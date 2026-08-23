package terminal

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The Kafka terminal goldens.
//
// # Nothing here is normalized, because nothing here is volatile
//
// Every duration is a literal, every address is a documentation address, every
// port is fixed and the run metadata is a constant. So these files are compared
// byte for byte with no placeholder substitution at all — which is a stronger
// contract than the PostgreSQL goldens in internal/cli can have, because those
// measure real loopback sockets whose ports the kernel assigns.
//
// The shapes are the ones `app.DiagnoseKafka` produces, verified against a real
// composed run rather than copied from a diagram; test/render/ holds the test
// that keeps this file and the production graph from drifting apart.

var updateKafka = flag.Bool("update-kafka", false, "rewrite the Kafka golden files")

// kafkaGraph builds one Kafka run's graph in the production shape.
type kafkaGraph struct {
	t *testing.T
	b *builder

	// bootstrap is the requested target's lookup, which every bootstrap path
	// hangs from.
	bootstrap domain.EvidenceID

	// metadata is the exchange node advertisements hang from.
	metadata domain.EvidenceID

	seq int
}

const (
	kafkaTarget = "kafka.internal:9093"
	addrOne     = "198.51.100.10:9093"
	addrTwo     = "198.51.100.11:9093"
)

func newKafkaGraph(t *testing.T) *kafkaGraph {
	t.Helper()
	g := &kafkaGraph{t: t, b: newBuilder(t)}
	g.b.service = "kafka"
	g.bootstrap = g.node("dns.lookup/kafka.internal", vocabulary.StepDNSLookup, domain.LayerDNS,
		kafkaTarget, domain.StatePass, domain.FailureNone, domain.Measured(2*time.Millisecond), "")
	return g
}

func (g *kafkaGraph) node(
	id string, step domain.Step, layer domain.Layer, subject string,
	state domain.State, class domain.FailureClass, elapsed domain.Elapsed,
	parent domain.EvidenceID,
) domain.EvidenceID {
	g.t.Helper()
	return g.b.addUnder(id, step, layer, subject, state, class, elapsed, parent)
}

// bootstrapPath records one resolved address and the stages measured over it.
//
// stages is a list of (step, state, class, elapsed) in journey order. Anything
// omitted is simply absent, which is how an unselected path and a journey that
// stopped early are both expressed.
type stage struct {
	step    domain.Step
	state   domain.State
	class   domain.FailureClass
	elapsed domain.Elapsed

	// attrs are the node's attributes. Only a TLS handshake needs any: the row
	// it produces depends on tls.verified as well as on state.
	attrs map[domain.AttributeKey]domain.AttrValue
}

func measured(us int) domain.Elapsed {
	return domain.Measured(time.Duration(us) * time.Microsecond)
}

func passed(step domain.Step, us int) stage {
	return stage{
		step: step, state: domain.StatePass, elapsed: measured(us),
		attrs: verifiedAttrs(step, true),
	}
}

// unverified is a handshake that completed without identifying the peer.
//
// It is what `--tls-insecure` produces: PASS, because the handshake really did
// complete and the channel really is encrypted, with tls.verified false because
// nobody checked who answered.
func unverified(step domain.Step, us int) stage {
	return stage{
		step: step, state: domain.StatePass, elapsed: measured(us),
		attrs: verifiedAttrs(step, false),
	}
}

// verifiedAttrs records tls.verified on handshake nodes and on nothing else.
//
// Attaching it to every node would make the renderer's "no such attribute means
// this is not a handshake" branch untested, and that branch is what keeps a TCP
// row from ever growing a TLS annotation.
func verifiedAttrs(step domain.Step, verified bool) map[domain.AttributeKey]domain.AttrValue {
	if step != vocabulary.StepTLSHandshake {
		return nil
	}
	return map[domain.AttributeKey]domain.AttrValue{
		vocabulary.AttrTLSVerified: domain.BoolAttr(verified),
	}
}

func failed(step domain.Step, class domain.FailureClass, us int) stage {
	return stage{step: step, state: domain.StateFail, class: class, elapsed: measured(us)}
}

func unknownAt(step domain.Step, class domain.FailureClass, e domain.Elapsed) stage {
	return stage{step: step, state: domain.StateUnknown, class: class, elapsed: e}
}

func skipped(step domain.Step, class domain.FailureClass) stage {
	return stage{
		step: step, state: domain.StateSkipped, class: class, elapsed: domain.Unmeasured(),
	}
}

func (g *kafkaGraph) layerOf(step domain.Step) domain.Layer {
	switch step {
	case vocabulary.StepDNSLookup:
		return domain.LayerDNS
	case vocabulary.StepTCPConnect:
		return domain.LayerTCP
	case vocabulary.StepTLSHandshake:
		return domain.LayerTLS
	case servicekafka.StepAPIVersions:
		return domain.LayerProtocol
	case servicekafka.StepSASLHandshake, servicekafka.StepSASLAuthenticate:
		return domain.LayerAuth
	default:
		return domain.LayerTopology
	}
}

// bootstrapPath records one address of the requested endpoint.
func (g *kafkaGraph) bootstrapPath(address string, stages ...stage) domain.EvidenceID {
	g.t.Helper()
	return g.chain(g.bootstrap, address, stages...)
}

func (g *kafkaGraph) chain(
	parent domain.EvidenceID, address string, stages ...stage,
) domain.EvidenceID {
	g.t.Helper()
	last := parent
	for _, s := range stages {
		g.seq++
		id := domain.EvidenceID(string(s.step) + "/" + address + "/" + itoa(g.seq))
		last = g.b.addUnderWith(string(id), s.step, g.layerOf(s.step), address,
			s.state, s.class, s.elapsed, last, s.attrs)
		if s.step == servicekafka.StepMetadata {
			g.metadata = last
		}
	}
	return last
}

// advertisement records one endpoint the cluster named, and the sweep beneath it.
func (g *kafkaGraph) advertisement(
	nodeID int64, subject string, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	g.t.Helper()
	g.seq++
	id := "kafka.broker_advertised/" + subject + "/" + itoa(g.seq)
	return g.b.addAdvertisement(id, subject, state, class, nodeID, g.metadata)
}

// sweep records the credential-free transport measured for one advertisement.
//
// The lookup's subject is the advertised **name**, and every path's subject is a
// resolved **address** — which is what the production sweep records, and the
// distinction a reader needs to see that svcdoctor resolved a peer-supplied name
// itself rather than trusting an address the cluster stated.
func (g *kafkaGraph) sweep(
	ad domain.EvidenceID, name, address string, lookup stage, paths ...[]stage,
) {
	g.t.Helper()
	g.seq++
	lookupID := g.node(
		"dns.lookup/advertised/"+name+"/"+itoa(g.seq), vocabulary.StepDNSLookup,
		domain.LayerDNS, name, lookup.state, lookup.class, lookup.elapsed, ad)
	for _, p := range paths {
		g.chain(lookupID, address, p...)
	}
}

func (g *kafkaGraph) report(findings ...domain.Finding) domain.Report {
	g.t.Helper()
	return g.b.report(findings...)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// requireKafkaGolden compares rendered output against testdata byte for byte.
func requireKafkaGolden(t *testing.T, name, actual string) {
	t.Helper()

	path := filepath.Join("testdata", name)
	if *updateKafka {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatalf("creating testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(actual), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path) //nolint:gosec // G304: a fixed testdata path.
	if err != nil {
		t.Fatalf("reading %s: %v (run with -update-kafka to create it)", path, err)
	}
	if actual != string(want) {
		t.Errorf("%s does not match.\n--- want ---\n%s\n--- got ---\n%s", path, want, actual)
	}
}

func renderKafka(t *testing.T, report domain.Report, incomplete bool) string {
	t.Helper()
	return rendered(t, render.Input{Report: report, Incomplete: incomplete})
}
