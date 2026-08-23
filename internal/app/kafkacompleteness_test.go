package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// ADR 0051's acceptance matrix, executed.
//
// # Why these run on constructed graphs and the wiring runs on a real one
//
// `incompleteKafkaRun` is a pure function of a frozen graph, and ADR 0051 states
// its acceptance matrix as ten graph *shapes* — an address that failed beside an
// address nobody measured, a handshake that timed out locally under a connection
// that passed. Driving those through a real network would mean building a
// fixture that can produce a chosen `FailureClass` at a chosen depth on a chosen
// sibling, which is a second implementation of the transport chain wearing a
// test's clothes, and it would still only reach the shapes it could arrange.
//
// So the predicate is tested against the shapes directly, and **that it is
// actually wired into a run** is tested separately, end to end, by
// TestTheCompletenessPredicateIsWiredIntoTheRun below and by the composition
// suite in test/security. Neither half is sufficient alone: the first would pass
// on a predicate nobody calls, the second on a predicate that is right only
// about the two shapes a fixture can build.
//
// The shapes are built with the exact steps the producers emit, through
// `domain.GraphBuilder`, so a rename in the vocabulary breaks these tests rather
// than silently making them vacuous.

// graphOf assembles one Kafka topology graph from a compact description.
type graphOf struct {
	t *testing.T
	b *domain.GraphBuilder

	// metadata is the exchange node, minted lazily so a test can describe a run
	// that never reached one.
	metadata domain.EvidenceID
	seq      int
}

func newGraphOf(t *testing.T) *graphOf {
	t.Helper()
	return &graphOf{t: t, b: domain.NewGraphBuilder()}
}

// at mints a unique identifier, because two nodes of one step in one graph must
// not collide and the real producers scope theirs by endpoint and address.
func (g *graphOf) at(step domain.Step) domain.EvidenceID {
	g.seq++
	return domain.EvidenceID(fmt.Sprintf("%s/n%d", step, g.seq))
}

func (g *graphOf) add(
	step domain.Step, layer domain.Layer, state domain.State,
	class domain.FailureClass, parent domain.EvidenceID,
) domain.EvidenceID {
	g.t.Helper()

	id := g.at(step)
	subject, err := domain.NewEndpointSubject("endpoint.test:9093")
	if err != nil {
		g.t.Fatalf("NewEndpointSubject: %v", err)
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: id, Subject: subject, Layer: layer, Step: step,
		State: state, FailureClass: class,
		StartedAt: time.Now(), Duration: 0,
	})
	if err != nil {
		g.t.Fatalf("NewEvidence(%s, %s, %s): %v", step, state, class, err)
	}
	if err := g.b.AddEvidence(evidence); err != nil {
		g.t.Fatalf("AddEvidence(%s): %v", id, err)
	}
	if parent != "" {
		if err := g.b.AddParent(id, parent); err != nil {
			g.t.Fatalf("AddParent(%s -> %s): %v", id, parent, err)
		}
	}
	return id
}

// metadataPassed records the exchange that permits topology measurement.
func (g *graphOf) metadataPassed() *graphOf {
	g.metadata = g.add(
		servicekafka.StepMetadata, domain.LayerTopology,
		domain.StatePass, domain.FailureNone, "")
	return g
}

// metadataAt records an exchange in some other state.
func (g *graphOf) metadataAt(state domain.State, class domain.FailureClass) *graphOf {
	g.metadata = g.add(
		servicekafka.StepMetadata, domain.LayerTopology, state, class, "")
	return g
}

// advertisement records one usable advertisement and returns its identifier.
func (g *graphOf) advertisement() domain.EvidenceID {
	return g.add(
		servicekafka.StepBrokerAdvertised, domain.LayerTopology,
		domain.StatePass, domain.FailureNone, g.metadata)
}

// lookup records the advertisement's single DNS node.
func (g *graphOf) lookup(
	advertisement domain.EvidenceID, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	return g.add(vocabulary.StepDNSLookup, domain.LayerDNS, state, class, advertisement)
}

// connect records one address beneath a lookup.
func (g *graphOf) connect(
	lookup domain.EvidenceID, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	return g.add(vocabulary.StepTCPConnect, domain.LayerTCP, state, class, lookup)
}

// handshake records the TLS node the plan required beneath one connection.
func (g *graphOf) handshake(
	connect domain.EvidenceID, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	return g.add(vocabulary.StepTLSHandshake, domain.LayerTLS, state, class, connect)
}

func (g *graphOf) freeze() domain.Graph {
	g.t.Helper()
	graph, err := g.b.Freeze()
	if err != nil {
		g.t.Fatalf("Freeze: %v", err)
	}
	return graph
}

// The two local classes that mean svcdoctor stopped rather than the target
// answering.
const (
	localTimeout = domain.FailureExecLocalTimeout
	cancelled    = domain.FailureExecCancelled
)

// plainAdvertisement builds `advertisement -> lookup PASS -> N connections`,
// which is the plaintext-plan shape.
func (g *graphOf) plainAdvertisement(paths ...[2]any) domain.EvidenceID {
	advertisement := g.advertisement()
	lookup := g.lookup(advertisement, domain.StatePass, domain.FailureNone)
	for _, path := range paths {
		state, _ := path[0].(domain.State)
		class, _ := path[1].(domain.FailureClass)
		g.connect(lookup, state, class)
	}
	return advertisement
}

// tlsAdvertisement builds the TLS-plan shape: every connection carries a
// handshake node, which is how the graph states that the plan required one.
func (g *graphOf) tlsAdvertisement(paths ...[4]any) domain.EvidenceID {
	advertisement := g.advertisement()
	lookup := g.lookup(advertisement, domain.StatePass, domain.FailureNone)
	for _, path := range paths {
		tcpState, _ := path[0].(domain.State)
		tcpClass, _ := path[1].(domain.FailureClass)
		tlsState, _ := path[2].(domain.State)
		tlsClass, _ := path[3].(domain.FailureClass)
		connect := g.connect(lookup, tcpState, tcpClass)
		g.handshake(connect, tlsState, tlsClass)
	}
	return advertisement
}

func pass() [2]any { return [2]any{domain.StatePass, domain.FailureNone} }
func refused() [2]any {
	return [2]any{domain.StateFail, domain.FailureTCPConnectionRefused}
}
func unmeasured() [2]any { return [2]any{domain.StateUnknown, localTimeout} }

// --- the acceptance matrix ---------------------------------------------------

// TestADR0051AcceptanceMatrix is the whole of ADR 0051's table, in one place.
//
// The rows are named for what they are about rather than for their letter,
// because a failure message that says "a working path beside an unmeasured one
// resolves the advertisement" is one somebody can act on and "row A" is not. The
// letters are kept in the comments so the record and the test can be read
// against each other.
func TestADR0051AcceptanceMatrix(t *testing.T) {
	tests := []struct {
		name  string
		build func(*graphOf)
		want  bool
	}{
		{
			// A. One PASS resolves the advertisement outright. Reachability is
			// existential: a client selecting the working address succeeds, and
			// nothing a further measurement could find would overturn that.
			name: "a working path beside an unmeasured one resolves the advertisement",
			build: func(g *graphOf) {
				g.metadataPassed().plainAdvertisement(pass(), unmeasured())
			},
			want: false,
		},
		{
			// B. The rejected first draft reported this complete. A refusal plus
			// an address nobody tried does not prove the endpoint unreachable —
			// a client selecting the unmeasured address might have connected.
			name: "a refusal beside an unmeasured path leaves the advertisement unresolved",
			build: func(g *graphOf) {
				g.metadataPassed().plainAdvertisement(refused(), unmeasured())
			},
			want: true,
		},
		{
			// C. The same asymmetry one layer down, and the other row the
			// revision changed.
			name: "a TLS failure beside an unmeasured path leaves the advertisement unresolved",
			build: func(g *graphOf) {
				g.metadataPassed().tlsAdvertisement(
					[4]any{domain.StatePass, domain.FailureNone,
						domain.StateFail, domain.FailureTLSHostnameMismatch},
					[4]any{domain.StateUnknown, localTimeout, domain.StateSkipped,
						domain.FailureExecSkippedPrerequisiteFailed},
				)
			},
			want: true,
		},
		{
			// D. Every path terminated in a positively observed failure, so the
			// universal negative is provable and the run is complete.
			name: "every path failing is a complete negative",
			build: func(g *graphOf) {
				g.metadataPassed().plainAdvertisement(refused(), refused())
			},
			want: false,
		},
		{
			// E. The resolution unit is the advertisement. Two resolved brokers
			// do not excuse a third nobody measured.
			name: "one unresolved broker among three makes the run incomplete",
			build: func(g *graphOf) {
				g.metadataPassed()
				g.plainAdvertisement(pass())
				g.plainAdvertisement(unmeasured(), unmeasured())
				g.plainAdvertisement(pass())
			},
			want: true,
		},
		{
			// F. Local uncertainty on siblings of resolved advertisements is
			// exactly what ADR 0047 refuses to treat as incompleteness.
			name: "unmeasured siblings under resolved advertisements do not make the run incomplete",
			build: func(g *graphOf) {
				g.metadataPassed()
				g.plainAdvertisement(pass(), unmeasured())
				g.plainAdvertisement(unmeasured(), pass())
			},
			want: false,
		},
		{
			// G. Metadata passed and the budget ended before the sweep began.
			// The advertisement exists and nothing beneath it does.
			name: "an advertisement whose sweep never began is unresolved",
			build: func(g *graphOf) {
				g.metadataPassed().advertisement()
			},
			want: true,
		},
		{
			// H. A target-side Metadata failure is an answer. The core journey
			// stopped because the target did, not because svcdoctor did.
			name: "a target-side Metadata failure is a complete run",
			build: func(g *graphOf) {
				g.metadataAt(domain.StateFail, domain.FailureProtocolPeerClosed)
			},
			want: false,
		},
		{
			// I. A handshake that never finished under a connection that passed.
			// This is the row a predicate written against `State != PASS` gets
			// wrong, because UNKNOWN is not FAIL.
			name: "a locally timed out handshake leaves the advertisement unresolved",
			build: func(g *graphOf) {
				g.metadataPassed().tlsAdvertisement(
					[4]any{domain.StatePass, domain.FailureNone,
						domain.StateUnknown, localTimeout},
				)
			},
			want: true,
		},
		{
			// J. TCP passed, TLS failed, and nothing was left unmeasured. A
			// connection that completed is not transport success when the plan
			// required a handshake.
			name: "a TLS failure with no unmeasured sibling is a complete negative",
			build: func(g *graphOf) {
				g.metadataPassed().tlsAdvertisement(
					[4]any{domain.StatePass, domain.FailureNone,
						domain.StateFail, domain.FailureTLSUnknownAuthority},
				)
			},
			want: false,
		},
		{
			// Not in the matrix, and the mirror of J: TLS passing over a passing
			// connection is the one shape that resolves a TLS-plan advertisement.
			name: "a passing handshake resolves a TLS-plan advertisement",
			build: func(g *graphOf) {
				g.metadataPassed().tlsAdvertisement(
					[4]any{domain.StatePass, domain.FailureNone,
						domain.StatePass, domain.FailureNone},
				)
			},
			want: false,
		},
		{
			// A lookup that resolved nothing is a complete negative on its own:
			// there is no address a client could have selected instead.
			name: "a failed lookup is a complete negative",
			build: func(g *graphOf) {
				advertisement := g.metadataPassed().advertisement()
				g.lookup(advertisement, domain.StateFail, domain.FailureDNSNoAddress)
			},
			want: false,
		},
		{
			// A lookup that never finished is not.
			name: "a locally timed out lookup leaves the advertisement unresolved",
			build: func(g *graphOf) {
				advertisement := g.metadataPassed().advertisement()
				g.lookup(advertisement, domain.StateUnknown, localTimeout)
			},
			want: true,
		},
		{
			// A name that resolved and against which nothing was attempted is
			// not a negative anybody proved.
			name: "a resolved lookup with no attempted path is unresolved",
			build: func(g *graphOf) {
				advertisement := g.metadataPassed().advertisement()
				g.lookup(advertisement, domain.StatePass, domain.FailureNone)
			},
			want: true,
		},
		{
			// An advertisement the cluster could not state usably is itself a
			// verdict, and no sweep was ever promised for it.
			name: "an unusable advertisement needs no sweep",
			build: func(g *graphOf) {
				g.metadataPassed()
				g.add(servicekafka.StepBrokerAdvertised, domain.LayerTopology,
					domain.StateFail, domain.FailureProtocolUnexpectedResponse, g.metadata)
			},
			want: false,
		},
		{
			// Metadata PASS with nothing advertised. There is no topology work
			// to leave unfinished.
			name: "metadata with no advertisements is a complete run",
			build: func(g *graphOf) {
				g.metadataPassed()
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGraphOf(t)
			tt.build(g)
			if got := incompleteKafkaRun(context.Background(), g.freeze()); got != tt.want {
				t.Errorf("incompleteKafkaRun = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMetadataPassDoesNotShortCircuitCompleteness is ADR 0051 section 1, stated
// as its own test because it is the one place Kafka deliberately diverges from
// PostgreSQL's shape.
//
// PostgreSQL's predicate returns false the moment a session was established. If
// Kafka copied that, this graph — a passing Metadata exchange beside a broker
// nobody measured — would report a finished run, and the report would silently
// omit that a third of the requested topology was never looked at.
func TestMetadataPassDoesNotShortCircuitCompleteness(t *testing.T) {
	g := newGraphOf(t)
	g.metadataPassed()
	g.plainAdvertisement(pass())
	g.plainAdvertisement(unmeasured(), unmeasured())
	g.plainAdvertisement(pass())
	graph := g.freeze()

	if !incompleteKafkaRun(context.Background(), graph) {
		t.Error("Kafka metadata PASS settled completeness; ADR 0051 section 1 says it must not")
	}
	// The PostgreSQL predicate on the same graph, to make the divergence
	// explicit rather than asserted. `established` is what Kafka has no analogue
	// of, and passing true is what copying it would look like.
	if incompleteRun(context.Background(), graph, true) {
		t.Error("the PostgreSQL predicate was expected to short-circuit here; " +
			"if it no longer does, this test no longer demonstrates the divergence")
	}
}

// TestCancellationOutranksEveryGraphShape pins the unconditional first clause.
//
// A fully measured, fully resolved topology on a cancelled context is still an
// incomplete run: the context is a fact about svcdoctor's execution, and nothing
// the graph contains can make a run that was cut short a finished one.
func TestCancellationOutranksEveryGraphShape(t *testing.T) {
	g := newGraphOf(t)
	g.metadataPassed()
	g.plainAdvertisement(pass())
	graph := g.freeze()

	if incompleteKafkaRun(context.Background(), graph) {
		t.Fatal("the baseline graph is already incomplete; the test proves nothing")
	}

	for name, ctx := range map[string]context.Context{
		"cancelled": cancelledContext(),
		"expired":   expiredContext(t),
	} {
		if !incompleteKafkaRun(ctx, graph) {
			t.Errorf("a %s context produced a complete run", name)
		}
	}
}

// TestTheFallbackScanCoversAnUnreachedMetadata pins the second clause.
//
// With no Metadata node there is no topology to enumerate, so the question
// reduces to ADR 0047's: did some step that was entered end undetermined because
// svcdoctor's own budget expired?
func TestTheFallbackScanCoversAnUnreachedMetadata(t *testing.T) {
	for _, tt := range []struct {
		name  string
		class domain.FailureClass
		state domain.State
		want  bool
	}{
		{"a local timeout before Metadata", localTimeout, domain.StateUnknown, true},
		{"a cancellation before Metadata", cancelled, domain.StateUnknown, true},
		{"a target-side refusal before Metadata",
			domain.FailureTCPConnectionRefused, domain.StateFail, false},
		{"a rejected credential before Metadata",
			domain.FailureAuthCredentialsRejected, domain.StateFail, false},
		{"a missing credential before Metadata",
			domain.FailureExecRequiredInputMissing, domain.StateSkipped, false},
		{"a withheld credential before Metadata",
			domain.FailureExecSkippedByPolicy, domain.StateSkipped, false},
		{"a mechanism svcdoctor cannot perform",
			domain.FailureAuthMechanismUnsupported, domain.StateUnknown, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := newGraphOf(t)
			g.add(servicekafka.StepSASLAuthenticate, domain.LayerAuth,
				tt.state, tt.class, "")
			if got := incompleteKafkaRun(context.Background(), g.freeze()); got != tt.want {
				t.Errorf("incompleteKafkaRun = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAnUnknownMechanismIsNotAnIncompleteRun is worth its own name, because it
// is the one UNKNOWN that must not make a run incomplete.
//
// `AUTH_MECHANISM_UNSUPPORTED` is UNKNOWN because svcdoctor cannot perform the
// mechanism — a gap in svcdoctor, and an answer about this run. It is not
// `EXEC_LOCAL_TIMEOUT` and it is not `EXEC_CANCELLED`, so the scan must not
// catch it. A predicate that keyed on the *state* alone rather than on the state
// and the class would report exit 4 for a run that finished and explained
// itself.
func TestAnUnknownMechanismIsNotAnIncompleteRun(t *testing.T) {
	g := newGraphOf(t)
	g.add(servicekafka.StepSASLAuthenticate, domain.LayerAuth,
		domain.StateUnknown, domain.FailureAuthMechanismUnsupported, "")

	if incompleteKafkaRun(context.Background(), g.freeze()) {
		t.Error("a mechanism svcdoctor cannot perform was reported as an unfinished run")
	}
}

// TestAnUnrecognizedSweepShapeReadsAsUnresolved pins the direction the predicate
// errs in.
//
// Two lookups under one advertisement, or two handshakes under one connection,
// are shapes `kafka.MeasureAdvertised` does not produce. The predicate does not
// pick a verdict from whichever node sorts first: it declines, and declining
// means *unresolved*, because the failure this exists to prevent is a run
// claiming to have finished when it did not.
func TestAnUnrecognizedSweepShapeReadsAsUnresolved(t *testing.T) {
	t.Run("two lookups under one advertisement", func(t *testing.T) {
		g := newGraphOf(t)
		advertisement := g.metadataPassed().advertisement()
		for range 2 {
			lookup := g.lookup(advertisement, domain.StatePass, domain.FailureNone)
			g.connect(lookup, domain.StatePass, domain.FailureNone)
		}
		if !incompleteKafkaRun(context.Background(), g.freeze()) {
			t.Error("an unrecognized sweep shape was treated as a verdict")
		}
	})

	t.Run("two handshakes under one connection", func(t *testing.T) {
		g := newGraphOf(t)
		advertisement := g.metadataPassed().advertisement()
		lookup := g.lookup(advertisement, domain.StatePass, domain.FailureNone)
		connect := g.connect(lookup, domain.StatePass, domain.FailureNone)
		for range 2 {
			g.handshake(connect, domain.StatePass, domain.FailureNone)
		}
		if !incompleteKafkaRun(context.Background(), g.freeze()) {
			t.Error("an unrecognized path shape was treated as transport success")
		}
	})
}

// TestTheCompletenessPredicateIsWiredIntoTheRun closes the gap the constructed
// graphs above leave open.
//
// Everything else in this file proves the predicate is right. This proves a run
// actually consults it: a bounded run against an endpoint that accepts a
// connection and then says nothing produces a local timeout, and the Result must
// carry it. Without this, every test above would keep passing if
// `DiagnoseKafka` stopped calling `incompleteKafkaRun` altogether.
func TestTheCompletenessPredicateIsWiredIntoTheRun(t *testing.T) {
	result, err := DiagnoseKafka(context.Background(), KafkaParams{
		Host: "kafka.example.com", Port: 9093,
		Mechanism: "PLAIN",
		Resolver:  stubResolver{addrs: addrs(t, "192.0.2.10")},
		Dialer:    hangingDialer{},
		// Short enough that the run ends on its own budget rather than on the
		// test's patience, and long enough that the timeout is svcdoctor's
		// rather than the scheduler's.
		StepTimeout: 150 * time.Millisecond,
		Vantage:     vantage(t),
		Version:     "0.0.0-test",
	})
	if err != nil {
		t.Fatalf("DiagnoseKafka: %v", err)
	}
	if !result.Incomplete() {
		t.Error("a run stopped by its own step budget reported itself complete.\n\n" +
			"Either the predicate is not wired in, or it no longer reads the " +
			"local execution classes.")
	}
	// And it is orthogonal to status: nothing about the target was proven.
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK: an unfinished measurement is not a target defect",
			result.Report().Summary().Status())
	}
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expiredContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)
	return ctx
}

// hangingDialer accepts nothing and returns nothing until the caller's budget
// ends.
//
// It is what a black-holed address looks like: no refusal, no reset, no answer.
// The transport chain records UNKNOWN with a local class rather than a target
// failure, which is the distinction ADR 0047 exists to keep.
type hangingDialer struct{}

func (hangingDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
