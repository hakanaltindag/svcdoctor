package kafka

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The producer matrix.
//
// These are every way internal/adapter/kafka can record an advertisement it
// could not turn into a network target, enumerated from the normalizer rather
// than guessed: an entry is usable exactly when it has a host and a port in
// 1..65535, so the unusable set is "no host", "port outside the range", and both
// at once. The subject refs below are the exact strings that adapter's own
// TestUnusableAdvertisementsBecomeEvidence pins.
func unusableCases() []struct {
	name string
	ref  string
} {
	return []struct {
		name string
		ref  string
	}{
		{"no host", ":9093"},
		{"port zero", "broker-2.internal:0"},
		{"negative port", "broker-2.internal:-1"},
		{"int32 minimum port", "broker-2.internal:-2147483648"},
		{"port beyond range", "broker-2.internal:70000"},
		{"no host and no usable port", ":0"},
		{"ipv6 literal with unusable port", "[2001:db8::1]:0"},
	}
}

// unusable records the FAIL advertisement node Phase 3.3 produces, with the
// attributes it carries.
func (b *builder) unusable(exchange domain.EvidenceID, nodeID int64, ref, host string, port int64) domain.EvidenceID {
	b.t.Helper()
	return b.node(
		"kafka.broker_advertised/primary.internal:9092/10.0.0.1/"+
			strconv.FormatInt(nodeID, 10)+"/"+ref,
		ref, domain.LayerTopology, "kafka.broker_advertised",
		domain.StateFail, domain.FailureProtocolUnexpectedResponse, exchange,
		map[domain.AttributeKey]domain.AttrValue{
			"kafka.broker.node_id":         domain.IntAttr(nodeID),
			"kafka.broker.advertised_host": domain.HostAttr(host),
			"kafka.broker.advertised_port": domain.IntAttr(port),
		})
}

// TestEveryUnusableShapeBuildsAValidFinding covers the whole producer matrix and
// is the test the omission branch in buildUnusable names.
func TestEveryUnusableShapeBuildsAValidFinding(t *testing.T) {
	for _, tc := range unusableCases() {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			advertisement := b.unusable(exchange, 2, tc.ref, "", 0)
			graph := b.freeze()

			f := only(t, UnusableAdvertisement(graph))

			if f.Code() != CodeAdvertisedEndpointUnusable {
				t.Errorf("code = %s, want %s", f.Code(), CodeAdvertisedEndpointUnusable)
			}
			if f.Kind() != domain.FindingKindConfirmed {
				t.Errorf("kind = %s, want CONFIRMED", f.Kind())
			}
			if f.Severity() != domain.SeverityError {
				t.Errorf("severity = %s, want ERROR", f.Severity())
			}
			if f.Confidence() != domain.ConfidenceHigh {
				t.Errorf("confidence = %s, want HIGH", f.Confidence())
			}
			if f.Layer() != domain.LayerTopology {
				t.Errorf("layer = %s, want L6", f.Layer())
			}
			if f.Discriminator() != "" {
				t.Errorf("discriminator = %q, want none on a CONFIRMED finding", f.Discriminator())
			}
			if len(f.Recommendations()) != 1 {
				t.Errorf("recommendations = %d, want 1", len(f.Recommendations()))
			}
			wantRefs(t, f, exchange, advertisement)
		})
	}
}

// TestTheFindingIsNotVantageDependent is the field that most distinguishes this
// finding from the reachability one, so it is asserted on its own.
//
// The defect is in the values the cluster reported. Every client reading the
// same Metadata response receives the same unusable pair, from anywhere, so
// network position has no bearing on the claim. Copying `true` from the
// reachability rule would have told a reader the opposite of the truth: that
// trying from somewhere else might help.
func TestTheFindingIsNotVantageDependent(t *testing.T) {
	for _, tc := range unusableCases() {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			b.unusable(exchange, 2, tc.ref, "", 0)

			f := only(t, UnusableAdvertisement(b.freeze()))
			if f.VantageDependent() {
				t.Error("vantageDependent = true; an unusable advertised value is the same " +
					"from every vantage point, and saying otherwise invites a pointless retry")
			}
		})
	}
}

// TestTheSubjectIsReusedAndNeverRepaired pins that diagnosis does not invent the
// target the cluster failed to name.
func TestTheSubjectIsReusedAndNeverRepaired(t *testing.T) {
	for _, tc := range unusableCases() {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			advertisement := b.unusable(exchange, 2, tc.ref, "", 0)
			graph := b.freeze()

			f := only(t, UnusableAdvertisement(graph))

			node, ok := graph.Node(advertisement)
			if !ok {
				t.Fatal("advertisement missing from graph")
			}
			if f.Subject() != node.Subject() {
				t.Errorf("subject = %v, want the advertisement's own subject %v",
					f.Subject(), node.Subject())
			}
			if f.Subject().Ref() != tc.ref {
				t.Errorf("subject ref = %q, want %q exactly as advertised", f.Subject().Ref(), tc.ref)
			}
		})
	}
}

// TestOnlyTheExchangeAndTheAdvertisementAreCited pins the minimal proof set.
//
// No transport evidence is cited because none exists: Phase 3.4 runs no sweep
// for an advertisement it cannot turn into a target, and a rule that invented a
// reference would fail report assembly under ADR 0014.
func TestOnlyTheExchangeAndTheAdvertisementAreCited(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.unusable(exchange, 2, ":9093", "", 9093)
	// A reachable sibling broker, whose transport evidence must not be borrowed.
	reachable(b, exchange, 3, "broker-3.internal:9092", "broker-3.internal", "10.20.0.3")
	graph := b.freeze()

	f := only(t, UnusableAdvertisement(graph))
	wantRefs(t, f, exchange, advertisement)

	for _, ref := range f.EvidenceRefs() {
		node, ok := graph.Node(ref)
		if !ok {
			t.Fatalf("reference %s is not in the graph", ref)
		}
		if node.Layer() != domain.LayerTopology {
			t.Errorf("reference %s is at %s; this claim needs no transport evidence",
				ref, node.Layer())
		}
	}
}

// TestWithholdingCases covers everything that must not produce this finding.
func TestWithholdingCases(t *testing.T) {
	tests := []struct {
		name  string
		build func(*builder)
	}{
		{
			name: "a usable advertisement",
			build: func(b *builder) {
				exchange := b.metadata(domain.StatePass)
				b.advertised(exchange, 2, "broker-2.internal:9092")
			},
		},
		{
			name: "a usable advertisement that could not be reached",
			build: func(b *builder) {
				exchange := b.metadata(domain.StatePass)
				unreachable(b, exchange, 2, "broker-2.internal:9092", "broker-2.internal", "10.20.0.2")
			},
		},
		{
			name: "a usable and reachable advertisement",
			build: func(b *builder) {
				exchange := b.metadata(domain.StatePass)
				reachable(b, exchange, 2, "broker-2.internal:9092", "broker-2.internal", "10.20.0.2")
			},
		},
		{
			name: "the Metadata exchange failed",
			build: func(b *builder) {
				exchange := b.metadata(domain.StateFail)
				b.unusable(exchange, 2, ":9093", "", 9093)
			},
		},
		{
			name: "an orphan advertisement with no exchange above it",
			build: func(b *builder) {
				b.node("kafka.broker_advertised/orphan", ":9093", domain.LayerTopology,
					"kafka.broker_advertised", domain.StateFail,
					domain.FailureProtocolUnexpectedResponse, "", nil)
			},
		},
		{
			name: "two Metadata exchanges above one advertisement",
			build: func(b *builder) {
				first := b.metadata(domain.StatePass)
				second := b.node("kafka.metadata/other:9092/10.0.0.9", "other:9092",
					domain.LayerTopology, "kafka.metadata", domain.StatePass,
					domain.FailureNone, "", nil)
				advertisement := b.unusable(first, 2, ":9093", "", 9093)
				if err := b.inner.AddParent(advertisement, second); err != nil {
					b.t.Fatalf("second exchange: %v", err)
				}
			},
		},
		{
			name: "a FAIL advertisement carrying an execution class",
			build: func(b *builder) {
				exchange := b.metadata(domain.StatePass)
				b.node("kafka.broker_advertised/odd", ":9093", domain.LayerTopology,
					"kafka.broker_advertised", domain.StateFail,
					domain.FailureExecLocalTimeout, exchange, nil)
			},
		},
		{
			name: "an advertisement in an unexpected state",
			build: func(b *builder) {
				exchange := b.metadata(domain.StatePass)
				b.node("kafka.broker_advertised/odd", ":9093", domain.LayerTopology,
					"kafka.broker_advertised", domain.StateUnknown,
					domain.FailureExecLocalTimeout, exchange, nil)
			},
		},
		{
			// This isolates the state check from the class check. Every other
			// row here is also rejected by the class, so without this one the
			// state check could be deleted and nothing would fail — which is
			// exactly what a mutation run found. UNKNOWN means svcdoctor did not
			// determine usability, and "not determined" must never become
			// "determined to be unusable".
			name: "an unknown advertisement carrying the expected class",
			build: func(b *builder) {
				exchange := b.metadata(domain.StatePass)
				b.node("kafka.broker_advertised/unknown", ":9093", domain.LayerTopology,
					"kafka.broker_advertised", domain.StateUnknown,
					domain.FailureProtocolUnexpectedResponse, exchange, nil)
			},
		},
		{
			// And this isolates the class check from the state check: a FAIL
			// advertisement whose class says the failure was something else.
			name: "a failed advertisement carrying an unrelated protocol class",
			build: func(b *builder) {
				exchange := b.metadata(domain.StatePass)
				b.node("kafka.broker_advertised/other-class", ":9093", domain.LayerTopology,
					"kafka.broker_advertised", domain.StateFail,
					domain.FailureProtocolMalformedResponse, exchange, nil)
			},
		},
		{
			name: "bootstrap transport evidence only",
			build: func(b *builder) {
				lookup := b.node("dns.lookup/primary.internal", "primary.internal",
					domain.LayerDNS, "dns.lookup", domain.StateFail,
					domain.FailureDNSNXDomain, "", nil)
				_ = lookup
			},
		},
		{
			name:  "an empty graph",
			build: func(*builder) {},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			tc.build(b)
			none(t, UnusableAdvertisement(b.freeze()))
		})
	}
}

// TestOneFindingPerUnusableAdvertisement pins multi-broker semantics: no
// aggregate, no count-derived severity.
func TestOneFindingPerUnusableAdvertisement(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	reachable(b, exchange, 1, "broker-1.internal:9092", "broker-1.internal", "10.20.0.1")
	b.unusable(exchange, 2, ":9093", "", 9093)
	b.unusable(exchange, 3, "broker-3.internal:0", "broker-3.internal", 0)

	findings := UnusableAdvertisement(b.freeze())
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (one per unusable advertisement)", len(findings))
	}
	for _, f := range findings {
		if f.Severity() != domain.SeverityError {
			t.Errorf("severity = %s; severity must not vary with how many are unusable", f.Severity())
		}
		if f.Code() != CodeAdvertisedEndpointUnusable {
			t.Errorf("code = %s, want the single authorized code", f.Code())
		}
	}
}

// TestDistinctAdvertisementFactsProduceDistinctFindings pins that nothing
// deduplicates by node identifier, endpoint, host or port.
func TestDistinctAdvertisementFactsProduceDistinctFindings(t *testing.T) {
	t.Run("one node identifier, two unusable endpoints", func(t *testing.T) {
		b := newBuilder(t)
		exchange := b.metadata(domain.StatePass)
		b.unusable(exchange, 7, "broker-a.internal:0", "broker-a.internal", 0)
		b.unusable(exchange, 7, "broker-b.internal:0", "broker-b.internal", 0)

		if got := len(UnusableAdvertisement(b.freeze())); got != 2 {
			t.Fatalf("findings = %d, want 2: node identifier is not finding identity", got)
		}
	})

	t.Run("two node identifiers, one unusable endpoint", func(t *testing.T) {
		b := newBuilder(t)
		exchange := b.metadata(domain.StatePass)
		b.unusable(exchange, 1, ":9093", "", 9093)
		b.unusable(exchange, 2, ":9093", "", 9093)

		findings := UnusableAdvertisement(b.freeze())
		if len(findings) != 2 {
			t.Fatalf("findings = %d, want 2: two advertisement facts", len(findings))
		}
		if findings[0].Subject().Ref() != findings[1].Subject().Ref() {
			t.Error("the two findings should share a subject")
		}
		if slicesEqual(findings[0].EvidenceRefs(), findings[1].EvidenceRefs()) {
			t.Error("the two findings should be distinguished by their evidence")
		}
		// After redaction both subjects collapse to the same text, so the node
		// identifier in the summary is what keeps them apart for a reader.
		if findings[0].Summary() == findings[1].Summary() {
			t.Error("summaries are identical; a reader cannot tell the two brokers apart")
		}
	})
}

// TestControllerIdentityDoesNotAffectTheFinding pins that an unusable
// advertisement is the same problem whichever broker is currently controller.
func TestControllerIdentityDoesNotAffectTheFinding(t *testing.T) {
	build := func(t *testing.T, controllerID int64) domain.Finding {
		t.Helper()
		b := newBuilder(t)
		exchange := b.node("kafka.metadata/primary.internal:9092/10.0.0.1", "primary.internal:9092",
			domain.LayerTopology, "kafka.metadata", domain.StatePass, domain.FailureNone, "",
			map[domain.AttributeKey]domain.AttrValue{
				"kafka.metadata.controller_id": domain.IntAttr(controllerID),
			})
		b.unusable(exchange, 2, ":9093", "", 9093)
		reachable(b, exchange, 7, "broker-7.internal:9092", "broker-7.internal", "10.20.0.7")
		return only(t, UnusableAdvertisement(b.freeze()))
	}

	asController, asFollower := build(t, 2), build(t, 7)
	if asController.Severity() != asFollower.Severity() {
		t.Errorf("severity changed with controller identity: %s vs %s",
			asController.Severity(), asFollower.Severity())
	}
	if asController.Summary() != asFollower.Summary() {
		t.Error("summary changed with controller identity")
	}
}

// TestUnusableProseMeetsTheQualityBar pins docs/FINDINGS.md section 3.1.
func TestUnusableProseMeetsTheQualityBar(t *testing.T) {
	forbiddenInSummary := []string{
		"PROTOCOL_UNEXPECTED_RESPONSE", "L6", "L1", "L2", "L3",
		"FAIL", "kafka.broker_advertised", "advertisement.State",
		":9093", ":0", "broker-2.internal", "9093", "70000", "-1",
	}
	rootCause := []string{
		"advertised.listeners", "misconfigur", "broker is down", "cluster is",
		"bug", "should be", "must be set",
	}

	for _, tc := range unusableCases() {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			b.unusable(exchange, 2, tc.ref, "", 0)
			f := only(t, UnusableAdvertisement(b.freeze()))

			for _, banned := range forbiddenInSummary {
				if strings.Contains(f.Summary(), banned) {
					t.Errorf("summary carries %q, which structure already provides: %q",
						banned, f.Summary())
				}
			}
			for _, s := range []string{f.Summary(), f.Detail(), f.Recommendations()[0].Action()} {
				for _, claim := range rootCause {
					if strings.Contains(strings.ToLower(s), claim) {
						t.Errorf("prose asserts a cause the evidence does not carry (%q): %q",
							claim, s)
					}
				}
			}
			if !strings.Contains(f.Detail(), "rather than of this vantage point") {
				t.Errorf("detail does not say the claim is vantage-independent: %q", f.Detail())
			}
		})
	}
}

// TestTheSummaryIsStableAcrossEverySubcase is the other half of the quality bar:
// one claim, one sentence, whatever the structural defect was.
func TestTheSummaryIsStableAcrossEverySubcase(t *testing.T) {
	var first string
	for i, tc := range unusableCases() {
		b := newBuilder(t)
		exchange := b.metadata(domain.StatePass)
		b.unusable(exchange, 2, tc.ref, "", 0)
		got := only(t, UnusableAdvertisement(b.freeze())).Summary()

		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Errorf("summary varies across subcases of one claim:\n %q (%s)\n %q",
				first, tc.name, got)
		}
	}
	if !strings.Contains(first, "broker node 2") {
		t.Errorf("summary does not name the broker: %q", first)
	}
}

// TestAnAdvertisementWithNoNodeIDStillProducesAFinding proves the identifier
// decorates prose and is never a precondition.
func TestAnUnusableAdvertisementWithNoNodeIDStillProducesAFinding(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.node("kafka.broker_advertised/no-node-id", ":9093",
		domain.LayerTopology, "kafka.broker_advertised", domain.StateFail,
		domain.FailureProtocolUnexpectedResponse, exchange, nil)

	f := only(t, UnusableAdvertisement(b.freeze()))
	wantRefs(t, f, exchange, advertisement)
	if strings.Contains(f.Summary(), "node") {
		t.Errorf("summary names a broker node it does not have: %q", f.Summary())
	}
}

// TestUnusableRecommendationTextIsValid is the test the omission branch in
// unusableRecommendations names.
func TestUnusableRecommendationTextIsValid(t *testing.T) {
	if _, err := domain.NewRecommendation(recommendUnusable); err != nil {
		t.Errorf("recommendation %q is invalid: %v", recommendUnusable, err)
	}
	if !CodeAdvertisedEndpointUnusable.Valid() {
		t.Errorf("%q is not a valid finding code", CodeAdvertisedEndpointUnusable)
	}
	if got := CodeAdvertisedEndpointUnusable.Namespace(); got != "KAFKA" {
		t.Errorf("namespace = %q, want KAFKA", got)
	}
	if got := string(CodeAdvertisedEndpointUnusable); got != "KAFKA_ADVERTISED_ENDPOINT_UNUSABLE" {
		t.Errorf("code = %q; renaming it breaks every consumer matching on it", got)
	}
}

// TestUnusableFindingsAreDeterministic pins output independent of assembly order.
func TestUnusableFindingsAreDeterministic(t *testing.T) {
	render := func(t *testing.T, reversed bool) []string {
		t.Helper()
		b := newBuilder(t)
		exchange := b.metadata(domain.StatePass)
		ids := []int64{1, 2, 3}
		if reversed {
			ids = []int64{3, 2, 1}
		}
		for _, id := range ids {
			b.unusable(exchange, id, "broker-"+strconv.FormatInt(id, 10)+".internal:0",
				"broker-"+strconv.FormatInt(id, 10)+".internal", 0)
		}
		findings := UnusableAdvertisement(b.freeze())
		domain.SortFindings(findings)

		out := make([]string, 0, len(findings))
		for _, f := range findings {
			refs := make([]string, 0, len(f.EvidenceRefs()))
			for _, r := range f.EvidenceRefs() {
				refs = append(refs, string(r))
			}
			out = append(out, f.Summary()+"|"+strings.Join(refs, ","))
		}
		return out
	}

	forward, reverse := render(t, false), render(t, true)
	if len(forward) != 3 {
		t.Fatalf("findings = %d, want 3", len(forward))
	}
	for i := range forward {
		if forward[i] != reverse[i] {
			t.Errorf("finding %d differs with assembly order:\n %s\n %s", i, forward[i], reverse[i])
		}
	}
}
