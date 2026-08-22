package kafka

import (
	"slices"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// only asserts that exactly one finding was produced and returns it.
func only(t *testing.T, findings []domain.Finding) domain.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %v", len(findings), summaries(findings))
	}
	return findings[0]
}

// none asserts that the rule withheld every claim.
func none(t *testing.T, findings []domain.Finding) {
	t.Helper()
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want none: %v", len(findings), summaries(findings))
	}
}

func summaries(findings []domain.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Summary())
	}
	return out
}

// confirmed asserts the exact field set ADR 0034 fixes for a proven-unreachable
// advertisement.
func confirmed(t *testing.T, f domain.Finding) {
	t.Helper()
	assertFields(t, f, domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh)
	if f.Discriminator() != "" {
		t.Errorf("discriminator = %q, want none on a CONFIRMED finding", f.Discriminator())
	}
}

// hypothesis asserts the exact field set for the mixed FAIL/unmeasured sweep.
func hypothesis(t *testing.T, f domain.Finding) {
	t.Helper()
	assertFields(t, f, domain.FindingKindHypothesis, domain.SeverityWarn, domain.ConfidenceLow)
	if f.Discriminator() != discriminator {
		t.Errorf("discriminator = %q, want %q", f.Discriminator(), discriminator)
	}
}

func assertFields(
	t *testing.T, f domain.Finding, kind domain.FindingKind, sev domain.Severity, conf domain.Confidence,
) {
	t.Helper()
	if f.Code() != CodeAdvertisedEndpointUnreachable {
		t.Errorf("code = %s, want %s", f.Code(), CodeAdvertisedEndpointUnreachable)
	}
	if f.Kind() != kind {
		t.Errorf("kind = %s, want %s", f.Kind(), kind)
	}
	if f.Severity() != sev {
		t.Errorf("severity = %s, want %s", f.Severity(), sev)
	}
	if f.Confidence() != conf {
		t.Errorf("confidence = %s, want %s", f.Confidence(), conf)
	}
	if !f.VantageDependent() {
		t.Error("vantageDependent = false; reachability is always relative to where svcdoctor ran")
	}
	if f.Layer() != domain.LayerTopology {
		t.Errorf("layer = %s, want %s", f.Layer(), domain.LayerTopology)
	}
}

// wantRefs asserts the finding's evidence references exactly, as a sorted set.
//
// The references are pinned rather than counted, because "which nodes prove
// this?" is the part of the policy most easily broken by a plausible refactor.
func wantRefs(t *testing.T, f domain.Finding, want ...domain.EvidenceID) {
	t.Helper()

	got := f.EvidenceRefs()
	expected := slices.Clone(want)
	slices.Sort(expected)

	if !slices.Equal(got, expected) {
		t.Errorf("evidence refs:\n got %v\nwant %v", got, expected)
	}
	if !slices.IsSorted(got) {
		t.Errorf("evidence refs are not sorted: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i] == got[i-1] {
			t.Errorf("evidence refs contain a duplicate: %s", got[i])
		}
	}
}

// assertRefsAreClean checks the two invariants ADR 0034 section 11 states about
// the causal set, over the whole reference list minus the two contrast nodes.
func assertRefsAreClean(t *testing.T, g domain.Graph, f domain.Finding, contrast ...domain.EvidenceID) {
	t.Helper()

	for _, ref := range f.EvidenceRefs() {
		node, ok := g.Node(ref)
		if !ok {
			t.Fatalf("reference %s is not in the graph", ref)
		}
		if slices.Contains(contrast, ref) {
			continue
		}
		if node.State() == domain.StatePass {
			t.Errorf("causal reference %s is a PASS node", ref)
		}
		if node.State() == domain.StateSkipped &&
			node.FailureClass() == domain.FailureExecSkippedPrerequisiteFailed {
			t.Errorf("causal reference %s is a prerequisite skip; its blocker owns the failure", ref)
		}
	}
}
