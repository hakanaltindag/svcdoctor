package diagnosis

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1a, ADR 0083 section 2.4 level L4: fuzzing.
//
// Four targets, and each answers a question a unit test cannot: what happens
// when the input is not one anybody thought of. The last is a security control
// rather than a robustness exercise — it is the automated form of ADR 0081
// section 2.7.

// FuzzRuleID drives the identity constructor.
//
// The invariants are that it never panics, that acceptance is exactly
// round-tripping, and that anything it accepts also passes Valid — so a value
// cannot be admitted by one path and refused by the other.
func FuzzRuleID(f *testing.F) {
	for _, seed := range []string{
		"", "/", "a/b", "transport/dns", "kafka/advertised-endpoint",
		"A/b", "a//b", "a/b/c", "-a/b", "a/-b", "a/b-", "1/2",
		"a/" + strings.Repeat("b", 64), "ä/b", "a/b\x00", "a/b\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		id, err := NewRuleID(in)
		if err != nil {
			if id != "" {
				t.Fatalf("a refused identity returned %q, want the zero value", id)
			}
			if RuleID(in).Valid() {
				t.Fatalf("%q was refused by NewRuleID and accepted by Valid", in)
			}
			return
		}

		if string(id) != in {
			t.Fatalf("NewRuleID(%q) = %q; an accepted identity is stored as written", in, id)
		}
		if !id.Valid() {
			t.Fatalf("%q was accepted and reports invalid", in)
		}
		if id.Owner() == "" || id.Name() == "" {
			t.Fatalf("%q was accepted with an empty part %q/%q", in, id.Owner(), id.Name())
		}
		if id.Owner()+"/"+id.Name() != in {
			t.Fatalf("%q does not reassemble from its parts", in)
		}
		// The spelling restriction is what makes byte order and meaning order
		// agree, which the merge tie-break rests on.
		if strings.ToLower(in) != in || !utf8.ValidString(in) {
			t.Fatalf("%q was accepted despite not being lower-case ASCII", in)
		}
	})
}

// FuzzActionText drives the recommendation-safety validator.
//
// It must never panic on arbitrary text, and anything it accepts must be free of
// the shell metacharacters that turn a sentence into something a reader could
// paste.
func FuzzActionText(f *testing.F) {
	for _, seed := range []string{
		"", " ", "read the configured listeners", "kubectl get pods",
		"a | b", "a && b", "$(x)", "`x`", "a\nb", "SELECT 1", "sudo x",
		"compare the advertised address with a routable one",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, action string) {
		if err := ValidateActionText(action); err != nil {
			return
		}

		if strings.TrimSpace(action) != action || action == "" {
			t.Fatalf("%q was accepted with surrounding whitespace", action)
		}
		if strings.ContainsAny(action, shellMetacharacters) {
			t.Fatalf("%q was accepted and contains a shell metacharacter", action)
		}
		for _, token := range strings.Fields(action) {
			if strings.HasPrefix(token, "-") && !strings.HasPrefix(token, "--") {
				t.Fatalf("%q was accepted and contains the short flag %q", action, token)
			}
		}
		first := action
		if space := strings.IndexAny(action, " \t\n"); space >= 0 {
			first = action[:space]
		}
		trimmed := strings.Trim(first, ".,:;\"'()")
		lowered := strings.ToLower(trimmed)
		if _, banned := commandWords[lowered]; banned {
			t.Fatalf("%q was accepted and begins with the command word %q", action, lowered)
		}
		if looksLikeSQL(trimmed, lowered, action) {
			t.Fatalf("%q was accepted and opens a SQL statement", action)
		}
	})
}

// FuzzBoundaryTraversal drives the graph walks against structures assembled from
// arbitrary bytes.
//
// A domain.Graph is a DAG by construction, so this cannot manufacture a cycle
// through GraphBuilder. What it does exercise is every other malformed shape a
// caller can build — self-referential intent, dense blocking, subjects with no
// nodes, states in any combination — against traversals whose termination must
// not depend on a caller's invariant. The assertions are that nothing panics,
// nothing recurses without bound, and the four claim-discipline properties hold
// whatever the input.
func FuzzBoundaryTraversal(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{4, 4, 4, 4, 2, 2, 2, 2, 1, 1})

	f.Fuzz(func(t *testing.T, shape []byte) {
		g := graphFromBytes(t, shape)

		for _, b := range Boundaries(g) {
			failing, ok := g.Node(b.FirstEvidencedFailure())
			if !ok {
				t.Fatalf("a boundary cites %q, which is not in the graph",
					b.FirstEvidencedFailure())
			}
			// UNKNOWN and SKIPPED are neither half. This is the property the
			// whole boundary exists to preserve.
			if failing.State() != domain.StateFail && failing.State() != domain.StateDegraded {
				t.Fatalf("a %s node was reported as the first evidenced failure",
					failing.State())
			}
			if last, ok := b.LastConfirmedGood(); ok {
				good, present := g.Node(last)
				if !present {
					t.Fatalf("a boundary cites %q, which is not in the graph", last)
				}
				if good.State() != domain.StatePass {
					t.Fatalf("a %s node was reported as confirmed good", good.State())
				}
				if good.Layer() >= failing.Layer() {
					t.Fatalf("the confirmed-good node is at %s, not above the failure at %s",
						good.Layer(), failing.Layer())
				}
				if good.Subject() != b.Subject() || failing.Subject() != b.Subject() {
					t.Fatal("a boundary cites evidence about another subject")
				}
			}
			// A blocked step is never the failure, and never confirmed good.
			for _, blocked := range b.Blocked() {
				if blocked == b.FirstEvidencedFailure() {
					t.Fatal("the failure appears in its own blocked set")
				}
			}
		}

		// Sibling counting classifies every child subject exactly once.
		for _, node := range g.Nodes() {
			counts := SiblingOutcome(g, node.ID())
			seen := map[domain.Subject]int{}
			for _, s := range counts.Passed() {
				seen[s]++
			}
			for _, s := range counts.Failed() {
				seen[s]++
			}
			for _, s := range counts.NotMeasured() {
				seen[s]++
			}
			for subject, times := range seen {
				if times != 1 {
					t.Fatalf("subject %s was classified %d times", subject, times)
				}
			}
			if len(seen) != counts.Total() {
				t.Fatalf("Total() = %d over %d distinct subjects", counts.Total(), len(seen))
			}
		}

		// Every traversal terminates and stays inside the graph.
		for _, node := range g.Nodes() {
			chain := BlockedChain(g, node.ID())
			if len(chain) > g.Len() {
				t.Fatalf("BlockedChain returned %d entries over %d nodes",
					len(chain), g.Len())
			}
			for _, id := range chain {
				if _, ok := g.Node(id); !ok {
					t.Fatalf("BlockedChain returned %q, which is not in the graph", id)
				}
			}
		}
	})
}

// FuzzHostileServerText is ADR 0081 section 2.7 as a control rather than a
// convention, and adversarial review attack 20.
//
// A server chooses its error strings. A rule may read a peer-supplied value to
// decide what to claim and may never copy it into prose, because a report is
// designed to be shared and the reader may not be the operator who ran it.
//
// The fuzzer puts an arbitrary string into an evidence attribute — the one place
// a peer value may legitimately reach, where it is typed, bounded and redactable
// — and drives a rule of the most dangerous shape there is: one that reads the
// attribute and then writes prose.
//
// # Why the assertion is byte-identity and not substring absence
//
// Substring absence was the first formulation and the fuzzer refuted it in
// seconds: a peer value of "a" is a substring of almost any English sentence,
// so the check failed on a rule that was behaving correctly. Lengthening the
// minimum would have hidden the false positive rather than fixed it.
//
// The property that is actually wanted is stronger and has no such edge: the
// peer's value must not be able to change a single byte of the prose. Two runs
// differing only in the attribute's contents produce identical findings, so
// there is no channel from a server-chosen string into a shared document at all
// — not an interpolation, not a length, not a branch on its contents.
//
// This is the same technique Phase 9.1C used for secret leakage, and for the
// same reason: "changing the value changes no byte of the output" is checkable
// where "the value does not appear" is not.
//
// The empty value is excluded because a rule may legitimately branch on
// *whether* a peer said anything, which is a fact about the exchange rather than
// a peer-chosen string. TestPeerTextCannotChangeProse covers that boundary.
//
// The committed seed testdata/fuzz/FuzzHostileServerText/single-character-value
// is the input that refuted the first formulation. It is kept as a regression
// seed rather than deleted with the assertion it broke.
func FuzzHostileServerText(f *testing.F) {
	for _, seed := range []string{
		"", "ok",
		"ERROR: password authentication failed for user \"admin\"",
		"<script>alert(1)</script>",
		"../../etc/passwd",
		"\x00\x01\x02",
		strings.Repeat("A", 300),
		"connection from 10.1.2.3 rejected",
		"%s %v %d",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, hostile string) {
		if hostile == "" {
			return // see the note above: absence is not a peer-chosen string
		}

		hostileGraph, ok := graphWithPeerAttribute(t, hostile)
		if !ok {
			return // the value is not one an attribute may carry; nothing to test
		}
		referenceGraph, ok := graphWithPeerAttribute(t, peerReferenceValue)
		if !ok {
			t.Fatal("the reference value is not carryable; the target proves nothing")
		}

		engine := engineOf(t, peerReadingRule(t))
		got := proseOf(engine.Diagnose(RuleContext{Graph: hostileGraph}))
		want := proseOf(engine.Diagnose(RuleContext{Graph: referenceGraph}))

		if got != want {
			t.Fatalf("the peer's value changed a finding's prose:\n"+
				"value:     %q\nprose:     %q\nreference: %q", hostile, got, want)
		}
	})
}

// peerReferenceValue is the benign attribute value every hostile one is compared
// against. Its only requirements are that it is non-empty and that no rule has
// any reason to treat it specially.
const peerReferenceValue = "reference"

// proseOf flattens every free-text field a finding carries.
//
// Four fields, and the list is exhaustive on purpose: summary, detail,
// discriminator and each recommendation's action are the whole prose surface of
// the report, and a field added to domain.Finding without being added here would
// be an unchecked channel.
func proseOf(findings []domain.Finding) string {
	var out strings.Builder
	for _, f := range findings {
		out.WriteString(f.Summary())
		out.WriteString("\x00")
		out.WriteString(f.Detail())
		out.WriteString("\x00")
		out.WriteString(f.Discriminator())
		out.WriteString("\x00")
		for _, r := range f.Recommendations() {
			out.WriteString(r.Action())
			out.WriteString("\x00")
		}
		out.WriteString("\n")
	}
	return out.String()
}

// TestPeerTextCannotChangeProse is the seeded, always-run half of
// FuzzHostileServerText.
//
// A fuzz target only runs its corpus during an ordinary `go test`, so the
// property is stated here too against the values a reviewer would want to see
// checked by name.
func TestPeerTextCannotChangeProse(t *testing.T) {
	engine := engineOf(t, peerReadingRule(t))

	reference, ok := graphWithPeerAttribute(t, peerReferenceValue)
	if !ok {
		t.Fatal("the reference value is not carryable")
	}
	want := proseOf(engine.Diagnose(RuleContext{Graph: reference}))
	if want == "" {
		t.Fatal("the fixture rule produced no prose; the property would be vacuous")
	}

	for _, hostile := range []string{
		"ERROR: password authentication failed for user \"admin\"",
		"a",
		"the peer reported a condition and named it",
		"<script>alert(1)</script>",
		strings.Repeat("A", 200),
		"10.1.2.3",
		"%s %v %d",
	} {
		g, ok := graphWithPeerAttribute(t, hostile)
		if !ok {
			continue
		}
		if got := proseOf(engine.Diagnose(RuleContext{Graph: g})); got != want {
			t.Errorf("the peer value %q changed the prose:\ngot  %q\nwant %q",
				hostile, got, want)
		}
	}
}

// peerReadingRule reads a peer-supplied attribute and writes prose about it.
//
// It is the shape ADR 0081 section 2.7 exists to forbid, written correctly: the
// value decides *what* to claim, and the claim is composed entirely of text the
// rule owns. Nothing peer-supplied is interpolated.
func peerReadingRule(t *testing.T) Rule {
	t.Helper()

	key, err := domain.NewAttributeKey("peer.message")
	if err != nil {
		t.Fatalf("NewAttributeKey: %v", err)
	}

	return func(ctx RuleContext) []domain.Finding {
		var out []domain.Finding
		for _, node := range ctx.Graph.Nodes() {
			value, ok := node.Attribute(key)
			if !ok {
				continue
			}
			// The value is read to decide the claim, and the claim is static
			// text this rule owns.
			summary := "the peer reported a condition and named it"
			if value.String() == "" {
				summary = "the peer reported a condition and named nothing"
			}
			out = append(out, findingAbout(t, "TCP_CONNECTION_REFUSED", node.Subject(),
				domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
				summary, node.ID()))
		}
		return out
	}
}

// graphWithPeerAttribute builds a one-node graph carrying value as a normalized
// attribute, and reports whether the value could be carried at all.
func graphWithPeerAttribute(t *testing.T, value string) (domain.Graph, bool) {
	t.Helper()

	key, err := domain.NewAttributeKey("peer.message")
	if err != nil {
		t.Fatalf("NewAttributeKey: %v", err)
	}
	subject, err := domain.NewEndpointSubject("peer.example:5432")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	step, err := domain.NewStep("tcp.connect")
	if err != nil {
		t.Fatalf("NewStep: %v", err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           "peer-node",
		Subject:      subject,
		Layer:        domain.LayerTCP,
		Step:         step,
		State:        domain.StateFail,
		FailureClass: domain.FailureTCPConnectionRefused,
		Attributes:   map[domain.AttributeKey]domain.AttrValue{key: domain.StringAttr(value)},
		StartedAt:    fuzzStart,
		Elapsed:      domain.Measured(0),
	})
	if err != nil {
		// The evidence model refused the value, which is the outer boundary
		// doing its job. There is nothing left for this target to check.
		return domain.Graph{}, false
	}

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	g, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return g, true
}

// graphFromBytes builds a graph whose shape is derived from arbitrary bytes.
//
// It never fails: a byte sequence that would describe an invalid structure
// produces a smaller valid one instead. The target is the traversals, not
// GraphBuilder, which has its own fuzzing.
func graphFromBytes(t *testing.T, shape []byte) domain.Graph {
	t.Helper()

	const maxNodes = 24
	states := []domain.State{
		domain.StatePass, domain.StateFail, domain.StateDegraded,
		domain.StateUnknown, domain.StateSkipped,
	}
	layers := []domain.Layer{
		domain.LayerInput, domain.LayerDNS, domain.LayerTCP, domain.LayerTLS,
		domain.LayerProtocol, domain.LayerAuth, domain.LayerTopology,
	}

	s := newSpec(t)
	var ids []domain.EvidenceID
	skipped := map[domain.EvidenceID]bool{}

	for i, b := range shape {
		if i >= maxNodes {
			break
		}
		state := states[int(b)%len(states)]
		layer := layers[int(b>>2)%len(layers)]
		ref := "f" + string(rune('a'+int(b>>4)%4)) + ".example:5432"
		id := domain.EvidenceID("f-" + string(rune('a'+i%26)) + "-" + string(rune('0'+i/26)))

		// One node per identifier: the builder rejects a repeat, and a repeat
		// here would be this helper's bug rather than the traversal's.
		if slicesContainsID(ids, id) {
			continue
		}
		s.endpoint(string(id), ref, layer, "step.number"+string(rune('0'+i%10)), state)
		ids = append(ids, id)
		skipped[id] = state == domain.StateSkipped
	}

	// Blocking edges, from a non-skipped node to a skipped one, respecting the
	// builder's rule that only a skipped node may be blocked.
	for i, id := range ids {
		if !skipped[id] || i == 0 {
			continue
		}
		blocker := ids[int(shape[i%len(shape)])%i]
		if blocker == id || skipped[blocker] && blocker == id {
			continue
		}
		_ = s.b.AddBlockedBy(id, blocker)
	}

	g, err := s.b.Freeze()
	if err != nil {
		// A structure the builder refuses is not an input this target is about.
		return domain.Graph{}
	}
	return g
}

func slicesContainsID(ids []domain.EvidenceID, want domain.EvidenceID) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// FuzzActivatedPipeline drives the Phase 10.1B production path against graphs
// assembled from arbitrary bytes.
//
// Phase 10.1A's FuzzBoundaryTraversal covered the queries. This covers what
// activation added: a boundary that becomes a *finding*, and convergence that
// decides whether two findings are one. The invariants are the ones a report
// consumer depends on — every citation resolves, no state was promoted, and two
// findings never share an identity.
func FuzzActivatedPipeline(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{4, 4, 2, 2, 1, 1, 3, 3, 0, 0, 2, 4})

	f.Fuzz(func(t *testing.T, shape []byte) {
		g := graphFromBytes(t, shape)

		registry, err := NewRuleSet().Add("diag/failure-boundary", FailureBoundary).Freeze()
		if err != nil {
			t.Fatalf("Freeze: %v", err)
		}
		out := NewEngine(registry).Evaluate(RuleContext{Graph: g})

		if out.Failed() {
			t.Fatalf("the boundary rule failed on a well-formed graph: %v", out.Failures())
		}

		seen := map[SemanticIdentity]int{}
		for _, finding := range out.Findings() {
			// Two findings may never share an identity: that is what convergence
			// exists to prevent, and a consumer keying on (code, subject) would
			// silently lose one.
			id := IdentityOf(finding)
			seen[id]++
			if seen[id] > 1 {
				t.Fatalf("identity %s appears %d times after convergence", id, seen[id])
			}

			if finding.Code() != CodeFailureBoundary {
				t.Fatalf("an unexpected code %s reached the output", finding.Code())
			}
			if finding.Subject().IsZero() {
				t.Fatal("a boundary was emitted with no subject")
			}
			if finding.Severity() != domain.SeverityInfo {
				t.Fatalf("a boundary is %s, want INFO", finding.Severity())
			}
			if finding.Discriminator() != "" {
				t.Fatalf("a CONFIRMED boundary carries the discriminator %q",
					finding.Discriminator())
			}

			refs := finding.EvidenceRefs()
			if len(refs) == 0 || len(refs) > 2 {
				t.Fatalf("a boundary cites %d nodes, want one or two", len(refs))
			}
			var failing, good int
			for _, ref := range refs {
				node, ok := g.Node(ref)
				if !ok {
					t.Fatalf("a boundary cites %q, which is not in the graph", ref)
				}
				if node.Subject() != finding.Subject() {
					t.Fatalf("a boundary cites evidence about another subject")
				}
				switch node.State() {
				case domain.StateFail, domain.StateDegraded:
					failing++
					if node.Layer() != finding.Layer() {
						t.Fatalf("the boundary is filed at %s and its failure is at %s",
							finding.Layer(), node.Layer())
					}
				case domain.StatePass:
					good++
				default:
					t.Fatalf("a boundary cites a %s node; not measured is neither half",
						node.State())
				}
			}
			if failing != 1 {
				t.Fatalf("a boundary cites %d failing nodes, want exactly 1", failing)
			}
			if good > 1 {
				t.Fatalf("a boundary cites %d confirmed-good nodes, want at most 1", good)
			}
		}

		// Repeating the evaluation cannot change it.
		again := NewEngine(registry).Evaluate(RuleContext{Graph: g})
		if a, b := len(out.Findings()), len(again.Findings()); a != b {
			t.Fatalf("repeated evaluation produced %d then %d findings", a, b)
		}
	})
}
