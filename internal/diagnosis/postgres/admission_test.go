package postgres

import (
	"go/ast"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Unit tests for the admission-scope rule (ADR 0085 section 2).
//
// The rule is the first PostgreSQL rule that is about a *set*, so most of what
// is asserted here is about the boundaries of the set rather than about prose:
// when it declines to speak, what it counts as an answer, and what it refuses to
// count as one.

// TestTheAdmissionScopeCountsThreeCategoriesAndNeverTwo is the rule's central
// property.
//
// An address that reached no decision is not an address that was refused, and
// the incomplete sentence must never be the complete one with a smaller number.
func TestTheAdmissionScopeCountsThreeCategoriesAndNeverTwo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		shapes     []admissionShape
		incomplete bool
		wantSubstr string
		wantAbsent []string
	}{
		{
			name:   "one refused and one admitted",
			shapes: []admissionShape{shapeRefused, shapeAdmitted},
			wantSubstr: "at 1 of the 2 addresses this target resolved to; the startup " +
				"exchange completed at the other 1",
			wantAbsent: []string{"no admission decision was observed"},
		},
		{
			name:       "every address refused",
			shapes:     []admissionShape{shapeRefused, shapeRefused},
			wantSubstr: "at all 2 addresses this target resolved to",
			wantAbsent: []string{" of the "},
		},
		{
			name:   "one refused and one never decided",
			shapes: []admissionShape{shapeRefused, shapeTimedOut},
			wantSubstr: "at 1 of the 2 addresses this target resolved to; the startup " +
				"exchange completed at 0 and no admission decision was observed at 1",
			// The uniform sentence must be unreachable here: it would assert a
			// total nobody established.
			wantAbsent: []string{"at all "},
		},
		{
			name:       "one refused, one other failure",
			shapes:     []admissionShape{shapeRefused, shapeOtherFailure},
			wantSubstr: "no admission decision was observed at 1",
			wantAbsent: []string{"at all "},
		},
		{
			name:       "one refused, one blocked",
			shapes:     []admissionShape{shapeRefused, shapeBlocked},
			wantSubstr: "no admission decision was observed at 1",
			wantAbsent: []string{"at all "},
		},
		{
			name:       "complete counts, but svcdoctor's own budget ended the run",
			shapes:     []admissionShape{shapeRefused, shapeRefused},
			incomplete: true,
			wantSubstr: "no admission decision was observed at 0",
			wantAbsent: []string{"at all ", "account for the whole set"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := only(t, admissionFindings(admissionGraph(t, tc.shapes...), tc.incomplete))
			if !strings.Contains(f.Summary(), tc.wantSubstr) {
				t.Errorf("summary does not contain %q.\n\nsummary: %s", tc.wantSubstr, f.Summary())
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(f.Summary(), absent) {
					t.Errorf("summary contains %q, which this shape does not support.\n\n"+
						"summary: %s", absent, f.Summary())
				}
			}
		})
	}
}

// TestTheAdmissionScopeIsSilentWhereItWouldOnlyDuplicate pins the three gates.
//
// Each is a case where the aggregate would restate what a per-address finding
// already says, or would state something no evidence supports.
func TestTheAdmissionScopeIsSilentWhereItWouldOnlyDuplicate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shapes []admissionShape
	}{
		{"a single address, refused", []admissionShape{shapeRefused}},
		{"a single address, admitted", []admissionShape{shapeAdmitted}},
		{"two addresses, nothing refused", []admissionShape{shapeAdmitted, shapeAdmitted}},
		{"two addresses, no decision anywhere", []admissionShape{shapeTimedOut, shapeTimedOut}},
		{"two addresses, only other failures", []admissionShape{shapeOtherFailure, shapeOtherFailure}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := admissionFindings(admissionGraph(t, tc.shapes...), false); len(got) != 0 {
				t.Errorf("got %d finding(s), want none: %v", len(got), codesOf(got))
			}
		})
	}
}

// TestTheAdmissionScopeWithholdsWithoutExactlyOneAnchor is the withhold-rather-
// than-guess direction.
//
// The subject is the anchor's own. A graph with none has no target to speak
// about, and a graph with two has no defensible answer to which one this is —
// picking either would make the output depend on traversal order.
func TestTheAdmissionScopeWithholdsWithoutExactlyOneAnchor(t *testing.T) {
	// No anchor: the single-address builder produces one, which is the shape
	// every other rule in this package works on.
	b := newBuilder(t)
	b.startupNode(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", boolPtr(true), "")
	if got := admissionFindings(b.freeze(), false); len(got) != 0 {
		t.Errorf("a graph with no requested-target anchor produced %v", codesOf(got))
	}

	// Two anchors: a shape no producer emits, and one this must refuse.
	b2 := newBuilder(t)
	twoAddressAdmission(b2, admissionContrast)
	second, err := domain.NewTargetSubject("other.internal:5432")
	if err != nil {
		t.Fatalf("NewTargetSubject: %v", err)
	}
	if err := b2.b.AddEvidence(mustEvidence(t, domain.EvidenceInput{
		ID:           "target.requested/other.internal:5432",
		Subject:      second,
		Layer:        domain.LayerInput,
		Step:         "target.requested",
		State:        domain.StatePass,
		FailureClass: domain.FailureNone,
		StartedAt:    b2.at,
		Elapsed:      domain.Unmeasured(),
	})); err != nil {
		t.Fatalf("adding a second anchor: %v", err)
	}
	if got := admissionFindings(b2.freeze(), false); len(got) != 0 {
		t.Errorf("a graph with two requested-target anchors produced %v", codesOf(got))
	}
}

// TestTheAdmissionScopeSubjectIsTheTargetAndNeverAnAddress is the identity half
// of ADR 0081.
//
// A set-level count under an address-level identity would collide with the
// per-address finding that is already there, and would say the set's number
// about one member of it.
func TestTheAdmissionScopeSubjectIsTheTargetAndNeverAnAddress(t *testing.T) {
	f := only(t, admissionFindings(admissionGraph(t, admissionContrast...), false))

	if got := f.Subject().Kind(); got != domain.SubjectKindTarget {
		t.Errorf("subject kind = %s, want %s", got, domain.SubjectKindTarget)
	}
	if got := f.Subject().Ref(); got != targetRef {
		t.Errorf("subject ref = %q, want %q", got, targetRef)
	}

	// And it does not share an identity with any per-address finding, which is
	// what keeps the two from being merge candidates at all.
	for _, other := range allFindings(admissionGraph(t, admissionContrast...)) {
		if other.Code() == CodeAdmissionScope {
			continue
		}
		if other.Subject() == f.Subject() {
			t.Errorf("%s shares the aggregate's subject %q", other.Code(), f.Subject().Ref())
		}
	}
}

// TestTheAdmissionScopeIsInfoAndMovesNoExitCode is ADR 0034 section 13 applied
// to a second service.
//
// Severity is the impact of this finding's own claim, and never a count-derived
// verdict about the target. The impact of a refusal is carried at ERROR, once
// per address, by POSTGRES_CONNECTION_NOT_PERMITTED — which this must not
// duplicate and must not escalate.
func TestTheAdmissionScopeIsInfoAndMovesNoExitCode(t *testing.T) {
	for _, shapes := range [][]admissionShape{
		admissionContrast,
		admissionUniform,
		{shapeRefused, shapeRefused, shapeRefused, shapeRefused},
		{shapeRefused, shapeTimedOut},
	} {
		f := only(t, admissionFindings(admissionGraph(t, shapes...), false))
		if f.Severity() != domain.SeverityInfo {
			t.Errorf("severity = %s for %d addresses, want INFO; escalating on a count "+
				"is this finding grading the target", f.Severity(), len(shapes))
		}
		if f.Kind() != domain.FindingKindConfirmed {
			t.Errorf("kind = %s, want CONFIRMED; every number in it is a count of nodes "+
				"the graph already holds", f.Kind())
		}
		if f.Discriminator() != "" {
			t.Errorf("a CONFIRMED observation carries the discriminator %q; there is no "+
				"open question for one to settle", f.Discriminator())
		}
	}
}

// TestTheAdmissionScopeCitesEveryNodeItCounted is ADR 0078 section 2.3 rule 1
// stated as a test: delete any cited node and a count changes.
func TestTheAdmissionScopeCitesEveryNodeItCounted(t *testing.T) {
	g := admissionGraph(t, shapeRefused, shapeAdmitted, shapeTimedOut)
	f := only(t, admissionFindings(g, false))

	refs := map[domain.EvidenceID]bool{}
	for _, ref := range f.EvidenceRefs() {
		if _, ok := g.Node(ref); !ok {
			t.Errorf("reference %q does not resolve", ref)
		}
		refs[ref] = true
	}

	// One anchor plus one startup node per address, and nothing else: the TCP
	// nodes are how the addresses were reached and are not what was counted.
	want := 1 + 3
	if len(refs) != want {
		t.Errorf("cites %d nodes, want %d: %v", len(refs), want, f.EvidenceRefs())
	}
	for _, node := range g.Nodes() {
		if node.Step() != "postgres.startup" {
			continue
		}
		if !refs[node.ID()] {
			t.Errorf("startup node %q was counted and is not cited", node.ID())
		}
	}
}

// TestTheAdmissionScopeRecommendsOnlyObservations is ADR 0082 section 2.3.
//
// There is no remediation here at any confidence: the only change this evidence
// could point at is an edit to an admission policy svcdoctor has not read and
// has no expectation for, and widening one is security-relevant.
func TestTheAdmissionScopeRecommendsOnlyObservations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		shapes     []admissionShape
		incomplete bool
		want       int
	}{
		{"contrast carries the comparison", admissionContrast, false, 1},
		{"a uniform complete refusal carries none", admissionUniform, false, 0},
		{"a partial set carries the budget observation", []admissionShape{shapeRefused, shapeTimedOut}, false, 1},
		{"contrast and partial carry both", []admissionShape{shapeRefused, shapeAdmitted, shapeTimedOut}, false, 2},
		{"an interrupted run carries the budget observation", admissionUniform, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := only(t, admissionFindings(admissionGraph(t, tc.shapes...), tc.incomplete))
			if got := len(f.Recommendations()); got != tc.want {
				t.Fatalf("%d recommendations, want %d: %v", got, tc.want, actionsOf(f))
			}
			for _, action := range actionsOf(f) {
				if err := diagnosis.ValidateActionText(action); err != nil {
					t.Errorf("recommendation %q is not safe advice: %v", action, err)
				}
				lower := strings.ToLower(action)
				for _, banned := range []string{
					"add ", "edit", "widen", "allow ", "grant", "restart", "reload",
					"pg_hba", "trust",
				} {
					if strings.Contains(lower, banned) {
						t.Errorf("recommendation %q contains %q; an admission policy that "+
							"refuses an address may be exactly what it was written to do",
							action, banned)
					}
				}
			}
		})
	}
}

// TestTheAdmissionScopeNamesNoConfigurationAndNoCause is the forbidden-claim
// gate for this code, over every surface a reader sees.
func TestTheAdmissionScopeNamesNoConfigurationAndNoCause(t *testing.T) {
	for _, shapes := range [][]admissionShape{
		admissionContrast, admissionUniform, {shapeRefused, shapeTimedOut},
	} {
		f := only(t, admissionFindings(admissionGraph(t, shapes...), false))
		surfaces := append([]string{f.Summary(), f.Detail()}, actionsOf(f)...)
		for _, surface := range surfaces {
			lower := strings.ToLower(surface)
			for _, banned := range []string{
				"pg_hba.conf", "misconfigur", "wrong", "should", "must be",
				"firewall", "bad password", "invalid credential", "server is",
				"split", "failover", "replica", "primary", "standby",
			} {
				if strings.Contains(lower, banned) {
					t.Errorf("the admission scope contains %q, which is a cause, a "+
						"judgement or an identity it did not observe.\n\ntext: %s",
						banned, surface)
				}
			}
		}
	}
}

// TestEveryAdmissionShapeBuildsAValidFinding proves the rule's error branch is
// unreachable rather than merely believed to be.
func TestEveryAdmissionShapeBuildsAValidFinding(t *testing.T) {
	for _, shapes := range [][]admissionShape{
		{shapeRefused, shapeAdmitted},
		{shapeRefused, shapeRefused},
		{shapeRefused, shapeTimedOut},
		{shapeRefused, shapeBlocked},
		{shapeRefused, shapeOtherFailure},
		{shapeRefused, shapeAdmitted, shapeTimedOut, shapeBlocked, shapeOtherFailure},
	} {
		for _, incomplete := range []bool{false, true} {
			findings := admissionFindings(admissionGraph(t, shapes...), incomplete)
			if len(findings) != 1 || findings[0].IsZero() {
				t.Errorf("shapes %v incomplete=%v produced %d findings",
					shapes, incomplete, len(findings))
			}
		}
	}
}

// TestTheAdmissionRuleReadsNoAttribute keeps Phase 10.3's central restraint
// mechanical.
//
// The whole phase adds no attribute read to diagnosis. That is what keeps
// ADR 0040 section 22's authorized surface closed and, with it, the path by
// which a replica claim would arrive without a decision — the session
// parameters are one selector expression away at all times, and this is the test
// that fails on the attempt rather than on a shape a test happened to cover.
func TestTheAdmissionRuleReadsNoAttribute(t *testing.T) {
	var found []string
	ast.Inspect(parse(t, "admission.go"), func(n ast.Node) bool {
		selector, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "servicepostgres" &&
			strings.HasPrefix(selector.Sel.Name, "Attr") {
			found = append(found, selector.Sel.Name)
		}
		if selector.Sel.Name == "Attribute" {
			found = append(found, "Attribute()")
		}
		return true
	})
	if len(found) != 0 {
		t.Errorf("admission.go reads %v; the admission scope is derived from states, "+
			"failure classes and steps alone", found)
	}
}

// mustEvidence builds evidence or fails the test.
func mustEvidence(t *testing.T, in domain.EvidenceInput) domain.Evidence {
	t.Helper()
	evidence, err := domain.NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence(%q): %v", in.ID, err)
	}
	return evidence
}

// actionsOf returns a finding's recommendation texts.
func actionsOf(f domain.Finding) []string {
	out := make([]string, 0, len(f.Recommendations()))
	for _, r := range f.Recommendations() {
		out = append(out, r.Action())
	}
	return out
}
