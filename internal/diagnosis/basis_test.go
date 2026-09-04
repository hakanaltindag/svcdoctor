package diagnosis

import (
	"errors"
	"slices"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1a, ADR 0081 section 2.4: the four evidence relations.
//
// The tests that matter here are the ones proving the relations cannot be
// collapsed. A basis that would let a blocked step count as support is the
// mechanism by which "two brokers were never tried" becomes "all three are
// unreachable".

func TestRelationNamesCoverAllRelations(t *testing.T) {
	for r := EvidenceRelation(0); int(r) < len(relationNames); r++ {
		if relationNames[r] == "" {
			t.Errorf("EvidenceRelation(%d) has no name", r)
		}
		if got := r.String(); got != relationNames[r] {
			t.Errorf("String() = %q, want %q", got, relationNames[r])
		}
	}
	if RelationUnspecified.Valid() {
		t.Error("RelationUnspecified reports valid")
	}
	for _, r := range []EvidenceRelation{
		RelationSupporting, RelationContradicting, RelationMissing, RelationBlocked,
	} {
		if !r.Valid() {
			t.Errorf("%s reports invalid", r)
		}
	}
	// Four relations, and the zero value. A fifth would need an ADR, because
	// each of the four is a distinct epistemic claim rather than a label.
	if len(relationNames) != 5 {
		t.Errorf("%d relations are defined, want 4 plus the zero value", len(relationNames)-1)
	}
	if got := EvidenceRelation(99).String(); got != "EvidenceRelation(99)" {
		t.Errorf("out-of-range String() = %q", got)
	}
}

func TestABasisSortsAndDeduplicatesEachRelation(t *testing.T) {
	g, _ := linearGraph(t)

	basis, err := NewBasis().
		Support("a-tcp", "a-dns", "a-tcp").
		Block("a-tls").
		Miss(step(t, "tls.handshake"), step(t, "dns.lookup"), step(t, "tls.handshake")).
		Freeze(g)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	if got := basis.Supporting(); !slices.Equal(got, []domain.EvidenceID{"a-dns", "a-tcp"}) {
		t.Errorf("supporting = %v, want sorted and deduplicated", got)
	}
	if got := basis.Missing(); !slices.Equal(got, []domain.Step{"dns.lookup", "tls.handshake"}) {
		t.Errorf("missing = %v, want sorted and deduplicated", got)
	}
	if got := basis.Blocked(); !slices.Equal(got, []domain.EvidenceID{"a-tls"}) {
		t.Errorf("blocked = %v", got)
	}
	if basis.IsZero() {
		t.Error("a populated basis reports zero")
	}
	if !(EvidenceBasis{}).IsZero() {
		t.Error("the zero basis does not report zero")
	}
}

// TestP06BlockedEvidenceIsNotSupportOrContradiction is property P06 and the
// sharpest case of ADR 0081 section 2.4.
//
// TLS was never attempted because TCP failed. It is neither broken nor healthy,
// and a rule that reads it in either direction is blaming a layer for a failure
// above it.
func TestP06BlockedEvidenceIsNotSupportOrContradiction(t *testing.T) {
	g, _ := linearGraph(t)

	for _, c := range []struct {
		name  string
		build func(*BasisBuilder) *BasisBuilder
	}{
		{"as support", func(b *BasisBuilder) *BasisBuilder { return b.Support("a-tls") }},
		{"as contradiction", func(b *BasisBuilder) *BasisBuilder { return b.Contradict("a-tls") }},
	} {
		_, err := c.build(NewBasis().Support("a-tcp")).Freeze(g)
		if !errors.Is(err, ErrInvalidBasis) {
			t.Errorf("citing a blocked step %s was accepted: %v", c.name, err)
		}
	}

	// The same node in the relation it does belong to is fine.
	if _, err := NewBasis().Support("a-tcp").Block("a-tls").Freeze(g); err != nil {
		t.Errorf("citing a blocked step as blocked was refused: %v", err)
	}
}

// TestARuleCannotLabelANodeBlocked pins that blocking is read, never asserted.
//
// The graph records that a step did not run and what stopped it, because the
// component that decided not to run it is the one that knows. A rule that could
// declare a node "blocked" could excuse any inconvenient evidence.
func TestARuleCannotLabelANodeBlocked(t *testing.T) {
	g, _ := linearGraph(t)

	_, err := NewBasis().Support("a-tcp").Block("a-dns").Freeze(g)
	if !errors.Is(err, ErrInvalidBasis) {
		t.Fatalf("labelling a passing node blocked was accepted: %v", err)
	}
}

// TestP05MissingIsNotContradiction is property P05, stated where the two could
// be confused: they are different fields with different types, and the missing
// one cannot hold an evidence identifier at all.
//
// A missing observation is named by step because it has no identifier — nothing
// was recorded. That also closes ADR 0081 section 2.7 by construction here: a
// step is svcdoctor's own vocabulary, so there is no way to describe a missing
// observation using a string a server chose.
func TestP05MissingIsNotContradiction(t *testing.T) {
	g, _ := linearGraph(t)

	basis, err := NewBasis().Support("a-tcp").Miss(step(t, "tls.handshake")).Freeze(g)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	if len(basis.Contradicting()) != 0 {
		t.Errorf("a missing observation landed in contradicting: %v", basis.Contradicting())
	}
	if got := basis.Missing(); len(got) != 1 || got[0] != "tls.handshake" {
		t.Errorf("missing = %v", got)
	}

	if _, err := NewBasis().Support("a-tcp").Miss("Not A Step").Freeze(g); !errors.Is(err, ErrInvalidBasis) {
		t.Errorf("a malformed missing step was accepted: %v", err)
	}
}

func TestASetsMustBeDisjoint(t *testing.T) {
	s := newSpec(t)
	dns := s.endpoint("j-dns", "x.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.endpoint("j-tcp", "x.example:5432", domain.LayerTCP, "tcp.connect", domain.StateFail)
	s.parent(tcp, dns)
	g := s.freeze()

	_, err := NewBasis().Support("j-dns").Contradict("j-dns").Freeze(g)
	if !errors.Is(err, ErrInvalidBasis) {
		t.Fatalf("one node both supporting and contradicting was accepted: %v", err)
	}
}

// TestP14EveryCitedNodeMustResolve is property P14 at the basis boundary.
func TestP14EveryCitedNodeMustResolve(t *testing.T) {
	g, _ := linearGraph(t)

	for _, build := range []func() *BasisBuilder{
		func() *BasisBuilder { return NewBasis().Support("no-such-node") },
		func() *BasisBuilder { return NewBasis().Support("a-tcp").Contradict("no-such-node") },
		func() *BasisBuilder { return NewBasis().Support("a-tcp").Block("no-such-node") },
	} {
		if _, err := build().Freeze(g); !errors.Is(err, ErrInvalidBasis) {
			t.Errorf("a dangling reference was accepted: %v", err)
		}
	}
}

// TestAnUnknownNodeMayStillBeCited pins the check deliberately not made.
//
// An UNKNOWN node is legitimate support for a claim *about not having measured
// something*, which is most of what svcdoctor says when a capability is
// unsupported. Refusing it wholesale would forbid the honest claim along with
// the dishonest one; the dishonest one is the blocked case, which is refused.
func TestAnUnknownNodeMayStillBeCited(t *testing.T) {
	s := newSpec(t)
	s.endpoint("k-dns", "y.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	s.unknown("k-tcp", "y.example:5432", domain.LayerTCP, "tcp.connect")
	g := s.freeze()

	if _, err := NewBasis().Support("k-tcp").Freeze(g); err != nil {
		t.Errorf("citing an unmeasured, unblocked node was refused: %v", err)
	}
}

// TestABasisIsIndependentOfCollectionOrder is the determinism property the
// merge and the confidence ladder both rest on.
func TestABasisIsIndependentOfCollectionOrder(t *testing.T) {
	g, _ := linearGraph(t)

	forward, err := NewBasis().Support("a-dns", "a-tcp").Freeze(g)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	reverse, err := NewBasis().Support("a-tcp", "a-dns").Freeze(g)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	if !slices.Equal(forward.Supporting(), reverse.Supporting()) {
		t.Errorf("collection order reached the basis: %v vs %v",
			forward.Supporting(), reverse.Supporting())
	}
}

// TestAFrozenBasisIsImmutable pins that the accessors hand out copies.
func TestAFrozenBasisIsImmutable(t *testing.T) {
	g, _ := linearGraph(t)

	basis, err := NewBasis().Support("a-dns").Block("a-tls").Miss(step(t, "tls.handshake")).Freeze(g)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	basis.Supporting()[0] = "mutated"
	basis.Blocked()[0] = "mutated"
	basis.Missing()[0] = "mutated"

	if basis.Supporting()[0] != "a-dns" || basis.Blocked()[0] != "a-tls" ||
		basis.Missing()[0] != "tls.handshake" {
		t.Error("editing a returned slice changed the frozen basis")
	}
}

func step(t *testing.T, s string) domain.Step {
	t.Helper()
	got, err := domain.NewStep(s)
	if err != nil {
		t.Fatalf("NewStep(%q): %v", s, err)
	}
	return got
}
