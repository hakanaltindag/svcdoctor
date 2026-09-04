package diagnosis

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1a, ADR 0080 section 2.4: registration.

func noopRule(RuleContext) []domain.Finding { return nil }

// TestDIAG021DuplicateRuleIDIsRejected is the assertion ADR 0080 section 2.4
// makes at construction rather than at review.
//
// A silent overwrite is the failure that matters: the composition would read as
// though both rules ran, one of them would not, and the report would be missing
// findings nobody knew to look for.
func TestDIAG021DuplicateRuleIDIsRejected(t *testing.T) {
	_, err := NewRuleSet().
		Add("transport/dns", noopRule).
		Add("transport/tcp", noopRule).
		Add("transport/dns", noopRule).
		Freeze()

	if !errors.Is(err, ErrInvalidRuleSet) {
		t.Fatalf("Freeze() error = %v, want ErrInvalidRuleSet", err)
	}
	if !strings.Contains(err.Error(), "transport/dns") {
		t.Errorf("the error does not name the duplicated identity: %v", err)
	}
}

// TestDuplicateIsRejectedEvenWhenTheRuleIsTheSameFunction pins that identity is
// what collides, not behaviour.
//
// Registering one function twice is still two claims on one name, and the merge
// tie-break of ADR 0081 section 2.6 would then be undefined for it.
func TestDuplicateIsRejectedEvenWhenTheRuleIsTheSameFunction(t *testing.T) {
	rule := Rule(noopRule)

	if _, err := NewRuleSet().Add("a/one", rule).Add("a/one", rule).Freeze(); err == nil {
		t.Error("registering one function under one identity twice was accepted")
	}
}

func TestAnInvalidIdentityIsRefusedAtRegistration(t *testing.T) {
	_, err := NewRuleSet().Add("NotAnIdentity", noopRule).Freeze()
	if !errors.Is(err, ErrInvalidRuleID) {
		t.Fatalf("Freeze() error = %v, want ErrInvalidRuleID", err)
	}
}

func TestTheFirstErrorIsKeptAndLaterAddsAreInert(t *testing.T) {
	set := NewRuleSet().
		Add("bad identity", noopRule).
		Add("a/valid", noopRule)

	if set.Len() != 0 {
		t.Errorf("Len() = %d after a refused registration, want 0", set.Len())
	}
	if !errors.Is(set.Err(), ErrInvalidRuleID) {
		t.Errorf("Err() = %v, want the first failure", set.Err())
	}
	if _, err := set.Freeze(); !errors.Is(err, ErrInvalidRuleID) {
		t.Errorf("Freeze() = %v, want the recorded failure", err)
	}
}

// TestDIAG016RegistrationOrderIsPreservedAndReadable pins that a registry
// describes the composition it came from.
func TestDIAG016RegistrationOrderIsPreservedAndReadable(t *testing.T) {
	want := []RuleID{"transport/dns", "transport/tcp", "kafka/protocol"}

	registry, err := NewRuleSet().
		Add("transport/dns", noopRule).
		Add("transport/tcp", noopRule).
		Add("kafka/protocol", noopRule).
		Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	if got := registry.IDs(); !slices.Equal(got, want) {
		t.Errorf("IDs() = %v, want %v (registration order, not sorted)", got, want)
	}
	if registry.Len() != 3 {
		t.Errorf("Len() = %d, want 3", registry.Len())
	}
	for _, id := range want {
		if !registry.Has(id) {
			t.Errorf("Has(%q) = false", id)
		}
	}
	if registry.Has("transport/nothing") {
		t.Error("Has() reported an unregistered identity")
	}
}

// TestP16AFrozenRegistryIsImmutable is property P16.
//
// Two ways a caller could reach into a frozen registry, and neither works:
// continuing to build the rule set it came from, and editing the slice it hands
// out. The second matters most for a fleet run, where one registry is shared by
// every target and a mutation would be a data race as well as a wrong answer.
func TestP16AFrozenRegistryIsImmutable(t *testing.T) {
	set := NewRuleSet().Add("a/one", noopRule)

	registry, err := set.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	set.Add("a/two", noopRule)
	if registry.Len() != 1 {
		t.Errorf("the frozen registry grew to %d after a later Add", registry.Len())
	}

	handedOut := registry.Rules()
	handedOut[0] = RegisteredRule{}
	if registry.Len() != 1 || registry.Rules()[0].ID() != "a/one" {
		t.Error("editing the returned slice changed the registry")
	}

	ids := registry.IDs()
	ids[0] = "z/mutated"
	if registry.IDs()[0] != "a/one" {
		t.Error("editing the returned identities changed the registry")
	}

	// A second freeze of the grown builder is independent of the first.
	second, err := set.Freeze()
	if err != nil {
		t.Fatalf("second Freeze: %v", err)
	}
	if second.Len() != 2 || registry.Len() != 1 {
		t.Errorf("freezes are not independent: first=%d second=%d",
			registry.Len(), second.Len())
	}
}

// TestAFrozenRegistryIsSafeForConcurrentReads is the property a 512-target fleet
// run depends on: one shared rule set, no synchronization, no cross-target
// leakage. Run under -race it is the whole assertion.
func TestAFrozenRegistryIsSafeForConcurrentReads(t *testing.T) {
	set := NewRuleSet()
	for i := range 8 {
		set.Add("a/rule-"+strconv.Itoa(i), noopRule)
	}
	registry, err := set.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	engine := NewEngine(registry)
	graph, _ := linearGraph(t)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := len(engine.Registry().Rules()); got != 8 {
				t.Errorf("Rules() = %d entries, want 8", got)
			}
			if out := engine.Evaluate(RuleContext{Graph: graph}); out.Failed() {
				t.Errorf("evaluation reported failures: %v", out.Failures())
			}
		}()
	}
	wg.Wait()
}

// TestTheZeroRegistryIsAnEmptyRuleSet pins that an unwired engine is inert
// rather than broken. A composition root that forgot to freeze produces no
// findings, which a test catches; it must not produce a panic in production.
func TestTheZeroRegistryIsAnEmptyRuleSet(t *testing.T) {
	graph, _ := linearGraph(t)

	engine := NewEngine(Registry{})
	if engine.RuleCount() != 0 {
		t.Errorf("RuleCount() = %d, want 0", engine.RuleCount())
	}
	out := engine.Evaluate(RuleContext{Graph: graph})
	if len(out.Findings()) != 0 || out.Failed() {
		t.Errorf("the zero registry produced %d findings and failed=%v",
			len(out.Findings()), out.Failed())
	}
}

func TestARegisteredRuleCarriesBothHalves(t *testing.T) {
	registry, err := NewRuleSet().Add("a/one", noopRule).Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	rule := registry.Rules()[0]
	if rule.IsZero() {
		t.Fatal("a registered rule reports zero")
	}
	if rule.ID() != "a/one" {
		t.Errorf("ID() = %q", rule.ID())
	}
	if rule.Eval() == nil {
		t.Error("Eval() = nil")
	}
	if (RegisteredRule{}).IsZero() != true {
		t.Error("the zero RegisteredRule does not report zero")
	}
}
