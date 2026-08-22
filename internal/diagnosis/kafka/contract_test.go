package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Contract tests: the properties the rule promises about every finding it can
// produce, rather than about one shape.

// shapes enumerates every sweep that yields a finding, so the invariant tests
// below run over the whole authorized matrix rather than over one example.
func shapes() []struct {
	name  string
	build func(*builder, domain.EvidenceID)
} {
	return []struct {
		name  string
		build func(*builder, domain.EvidenceID)
	}{
		{"dns fail", func(b *builder, ad domain.EvidenceID) {
			b.lookup(ad, "broker-2.internal", domain.StateFail, domain.FailureDNSNXDomain)
		}},
		{"plaintext, every connection refused", func(b *builder, ad domain.EvidenceID) {
			l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
			b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
			b.connect(l, "10.20.0.2", 9093, domain.StateFail, domain.FailureTCPConnectionTimeout)
		}},
		{"tls plan, every connection refused", func(b *builder, ad domain.EvidenceID) {
			l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
			c := b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
			b.skippedHandshake(c, "10.20.0.1", 9093)
		}},
		{"tls plan, every handshake rejected", func(b *builder, ad domain.EvidenceID) {
			l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
			c := b.connect(l, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
			b.handshake(c, "10.20.0.1", 9093, domain.StateFail, domain.FailureTLSHostnameMismatch)
		}},
		{"mixed causal layers", func(b *builder, ad domain.EvidenceID) {
			l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
			r := b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
			b.skippedHandshake(r, "10.20.0.1", 9093)
			c := b.connect(l, "10.20.0.2", 9093, domain.StatePass, domain.FailureNone)
			b.handshake(c, "10.20.0.2", 9093, domain.StateFail, domain.FailureTLSPeerNotTLS)
		}},
		{"hypothesis: failure beside an unknown path", func(b *builder, ad domain.EvidenceID) {
			l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
			b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
			b.connect(l, "10.20.0.2", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)
		}},
		{"hypothesis: failure beside a budget skip", func(b *builder, ad domain.EvidenceID) {
			l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
			b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
			b.connect(l, "10.20.0.2", 9093, domain.StateSkipped, domain.FailureExecCancelled)
		}},
	}
}

// eachShape runs fn against the single finding every authorized shape produces.
func eachShape(t *testing.T, fn func(*testing.T, domain.Graph, domain.Finding)) {
	t.Helper()
	for _, tc := range shapes() {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
			tc.build(b, advertisement)
			graph := b.freeze()
			fn(t, graph, only(t, AdvertisedEndpointUnreachable(graph)))
		})
	}
}

// TestEveryAuthorizedShapeBuildsAValidFinding is the test the omission branch in
// build() names.
//
// The rule has no error channel, so a finding domain.NewFinding rejected would be
// silently dropped — the failure mode the project's claim discipline exists to
// prevent. Rather than rely on that branch never being taken, this drives the
// whole authorized matrix and asserts a finding came out of each. The branch is
// proven unreachable, not trusted.
func TestEveryAuthorizedShapeBuildsAValidFinding(t *testing.T) {
	eachShape(t, func(t *testing.T, _ domain.Graph, f domain.Finding) {
		if f.Code() != CodeAdvertisedEndpointUnreachable {
			t.Errorf("code = %s", f.Code())
		}
		if len(f.EvidenceRefs()) < 3 {
			t.Errorf("refs = %v, want the exchange, the advertisement and a causal node",
				f.EvidenceRefs())
		}
	})
}

// TestEveryFindingReferencesOnlyGraphNodes pins the obligation a rule owes the
// report: a dangling reference would fail ADR 0014 validation at assembly.
func TestEveryFindingReferencesOnlyGraphNodes(t *testing.T) {
	eachShape(t, func(t *testing.T, g domain.Graph, f domain.Finding) {
		for _, ref := range f.EvidenceRefs() {
			if _, ok := g.Node(ref); !ok {
				t.Errorf("reference %s is not a node in the graph", ref)
			}
		}
	})
}

// TestNoCausalReferenceIsAPassOrAPrerequisiteSkip pins the two invariants
// ADR 0034 section 11 states about the causal set, over the whole matrix.
//
// The exchange node is excluded because it is required to be PASS: it is the
// successful half of the contrast, not a cause.
func TestNoCausalReferenceIsAPassOrAPrerequisiteSkip(t *testing.T) {
	eachShape(t, func(t *testing.T, g domain.Graph, f domain.Finding) {
		var contrast []domain.EvidenceID
		for _, node := range g.Nodes() {
			if node.Layer() == domain.LayerTopology {
				contrast = append(contrast, node.ID())
			}
		}
		assertRefsAreClean(t, g, f, contrast...)
	})
}

// TestProseCarriesNoAdvertisedIdentity is the redaction-facing property.
//
// The advertised hostname and the resolved addresses travel on the subject and
// on the referenced evidence, structurally, where redaction transforms them. Prose
// carries the broker's node identifier and nothing else identifying, so a
// shareable report needs no new heuristic. See ADR 0034 section 12.
func TestProseCarriesNoAdvertisedIdentity(t *testing.T) {
	identifying := []string{
		"broker-2.internal", "primary.internal", "10.20.0.1", "10.20.0.2", "9093",
	}
	eachShape(t, func(t *testing.T, _ domain.Graph, f domain.Finding) {
		text := []string{f.Summary(), f.Detail(), f.Discriminator()}
		for _, r := range f.Recommendations() {
			text = append(text, r.Action())
		}
		for _, s := range text {
			for _, secret := range identifying {
				if strings.Contains(s, secret) {
					t.Errorf("prose carries the identifying value %q: %q", secret, s)
				}
			}
		}
	})
}

// TestProseIsStableAndNarrow guards the claim discipline in the text itself.
func TestProseIsStableAndNarrow(t *testing.T) {
	forbidden := []string{
		"cluster is down", "cluster down", "broker down", "broker is down",
		"credentials", "controller unavailable", "network is broken",
	}
	eachShape(t, func(t *testing.T, _ domain.Graph, f domain.Finding) {
		for _, s := range []string{f.Summary(), f.Detail()} {
			lower := strings.ToLower(s)
			for _, claim := range forbidden {
				if strings.Contains(lower, claim) {
					t.Errorf("prose makes a claim the evidence does not prove (%q): %q", claim, s)
				}
			}
		}
		if !strings.Contains(strings.ToLower(f.Detail()), "vantage point") {
			t.Errorf("detail does not say the claim is relative to network position: %q", f.Detail())
		}
	})
}

// TestOnlyOneFindingCodeIsProduced pins the namespace boundary: no generic
// transport code, no aggregate cluster code, no partial-reachability variant.
func TestOnlyOneFindingCodeIsProduced(t *testing.T) {
	eachShape(t, func(t *testing.T, _ domain.Graph, f domain.Finding) {
		if f.Code() != CodeAdvertisedEndpointUnreachable {
			t.Fatalf("code = %s, want the single authorized code", f.Code())
		}
		if f.Code().Namespace() != "KAFKA" {
			t.Errorf("namespace = %q, want KAFKA", f.Code().Namespace())
		}
	})
}

// TestTheFindingCodeIsWellFormed guards the string itself, which is a
// machine-consumed contract that automation will match on.
func TestTheFindingCodeIsWellFormed(t *testing.T) {
	if !CodeAdvertisedEndpointUnreachable.Valid() {
		t.Fatalf("%q is not a valid finding code", CodeAdvertisedEndpointUnreachable)
	}
	if got := string(CodeAdvertisedEndpointUnreachable); got != "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE" {
		t.Errorf("code = %q; renaming it breaks every consumer matching on it", got)
	}
}

// TestRecommendationTextIsValid is the test the omission branch in
// recommendations() names.
func TestRecommendationTextIsValid(t *testing.T) {
	for _, action := range []string{recommendDNS, recommendTCP, recommendTLS} {
		if _, err := domain.NewRecommendation(action); err != nil {
			t.Errorf("recommendation %q is invalid: %v", action, err)
		}
	}
	if _, err := domain.NewFinding(domain.FindingInput{
		Code: CodeAdvertisedEndpointUnreachable, Kind: domain.FindingKindHypothesis,
		Severity: domain.SeverityWarn, Confidence: domain.ConfidenceLow,
		Layer: domain.LayerTopology, Summary: "probe", Discriminator: discriminator,
		EvidenceRefs: []domain.EvidenceID{"x"},
	}); err != nil {
		t.Errorf("the discriminator is not accepted by the model: %v", err)
	}
}

// TestDetailNamesATerminalLayerOnlyWhenOneWasMeasured is the Phase 3.6.5 fix,
// pinned so it cannot regress.
//
// ADR 0034 section 4 states that a sweep whose lookup produced no address has an
// **unknowable** plan: it minted no TCP node, so nothing records whether a
// handshake would have been required. The verdict does not need to know — the
// endpoint was unreachable at L1 either way — but prose that named a terminal
// layer there would assert a fact the evidence does not carry, and would assert
// the *wrong* one for every TLS-required cluster whose DNS is broken.
//
// So the detail names a layer exactly when a transport path was measured.
func TestDetailNamesATerminalLayerOnlyWhenOneWasMeasured(t *testing.T) {
	layers := []string{"L1", "L2", "L3", "L4", "L5", "L6"}

	t.Run("no path measured: no layer is named", func(t *testing.T) {
		b := newBuilder(t)
		exchange := b.metadata(domain.StatePass)
		advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
		b.lookup(advertisement, "broker-2.internal", domain.StateFail, domain.FailureDNSNXDomain)

		f := only(t, AdvertisedEndpointUnreachable(b.freeze()))
		for _, layer := range layers {
			if strings.Contains(f.Detail(), layer) {
				t.Errorf("detail names %s on a sweep that measured no transport path, "+
					"where the required layer is unknowable: %q", layer, f.Detail())
			}
		}
		if !strings.Contains(f.Detail(), "no address") {
			t.Errorf("detail does not say why nothing was measured: %q", f.Detail())
		}
	})

	t.Run("paths measured: the terminal layer is named with its label", func(t *testing.T) {
		cases := []struct {
			name string
			want string
			add  func(*builder, domain.EvidenceID)
		}{
			{"plaintext plan", "L2 (tcp)", func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
			}},
			{"tls plan, connection refused", "L3 (tls)", func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				c := b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
				b.skippedHandshake(c, "10.20.0.1", 9093)
			}},
			{"tls plan, handshake rejected", "L3 (tls)", func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				c := b.connect(l, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
				b.handshake(c, "10.20.0.1", 9093, domain.StateFail, domain.FailureTLSHostnameMismatch)
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				b := newBuilder(t)
				exchange := b.metadata(domain.StatePass)
				advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
				tc.add(b, advertisement)

				f := only(t, AdvertisedEndpointUnreachable(b.freeze()))
				if !strings.Contains(f.Detail(), tc.want) {
					t.Errorf("detail = %q, want it to name %q", f.Detail(), tc.want)
				}
			})
		}
	})
}

// TestDetailDoesNotContradictTheSummary guards the ambiguity the review found.
//
// "no path reached L2" beside a summary naming L2 as the earliest evidenced
// failing layer reads as a contradiction: the first sentence appears to deny that
// the run ever got to the layer the second sentence says it failed at. The verb
// carries the whole distinction — a path arrives at a layer and then fails to
// *complete* it — so the word is pinned rather than left to a future edit.
func TestDetailDoesNotContradictTheSummary(t *testing.T) {
	eachShape(t, func(t *testing.T, _ domain.Graph, f domain.Finding) {
		if strings.Contains(f.Detail(), "reached L") {
			t.Errorf("detail says a layer was not \"reached\" where it means not "+
				"\"completed\": %q", f.Detail())
		}
	})
}
