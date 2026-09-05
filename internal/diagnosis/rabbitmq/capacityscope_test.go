package rabbitmq

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// Phase 10.8B — the capacity-scope canonical explanation.
//
// What these tests exist to hold is narrow and easy to lose: the finding gains
// one sentence naming which ceiling the peer named, and **nothing else moves**.
// Not the code, not the severity, not the confidence, not the recommendations,
// not the evidence references, and not the explanation of any other outcome.
//
// ADR 0091 is the authorizing record. RCCE-001 … RCCE-023 in
// docs/validation/PHASE108B_RABBITMQ_CAPACITY_CANONICAL_EXPLANATION.md.

// openNode builds one connection-open evidence node with a close outcome.
//
// The outcome is written as a plain string rather than through the constant, so
// a test can supply a value no constant spells — which is most of the point.
func openNode(t *testing.T, class domain.FailureClass, outcome string, present bool) domain.Graph {
	t.Helper()
	attrs := map[domain.AttributeKey]domain.AttrValue{}
	if present {
		attrs[servicerabbitmq.AttrCloseOutcome] = domain.StringAttr(outcome)
	}
	return graphWith(t, servicerabbitmq.StepConnectionOpen, domain.StateFail, class, attrs)
}

// oneOpenFinding drives the real rule and returns its single finding.
func oneOpenFinding(t *testing.T, g domain.Graph) domain.Finding {
	t.Helper()
	findings := ConnectionOpen(rctx(g))
	if len(findings) != 1 {
		t.Fatalf("produced %d findings, want exactly 1", len(findings))
	}
	return findings[0]
}

// --- RCCE-007/008/009: the three scopes ------------------------------------

// TestCapacityOutcomesNameTheirScope is the positive matrix.
//
// It asserts the whole sentence rather than a keyword, because the risk this
// phase carries is a *wrong* scope rather than a missing one, and "contains
// node" would pass for a detail that named the node while citing a user ceiling.
func TestCapacityOutcomesNameTheirScope(t *testing.T) {
	tests := []struct {
		name    string
		outcome servicerabbitmq.CloseOutcome
		want    string
	}{
		{"node", servicerabbitmq.CloseNodeConnectionLimit,
			"The endpoint named a connection limit scoped to the node."},
		{"vhost", servicerabbitmq.CloseVHostConnectionLimit,
			"The endpoint named a connection limit scoped to the virtual host."},
		{"user", servicerabbitmq.CloseUserConnectionLimit,
			"The endpoint named a connection limit scoped to the user."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := openNode(t, domain.FailureResourceLimitReached, string(tt.outcome), true)
			f := oneOpenFinding(t, g)

			if !strings.Contains(f.Detail(), tt.want) {
				t.Errorf("detail does not name its scope.\ngot:  %q\nwant to contain: %q",
					f.Detail(), tt.want)
			}

			// The other two scopes must be absent. A detail naming two scopes
			// would be worse than one naming none.
			for _, other := range tests {
				if other.name == tt.name {
					continue
				}
				if strings.Contains(f.Detail(), other.want) {
					t.Errorf("a %s ceiling also named the %s scope", tt.name, other.name)
				}
			}

			// The generic hedge is what this replaces; it must be gone.
			if strings.Contains(f.Detail(), "Where the endpoint named a capacity ceiling") {
				t.Error("the generic hedge survived beside the specific sentence")
			}
			// And the impermanence sentence is what it must not replace.
			if !strings.Contains(f.Detail(), "a second run a moment later may succeed") {
				t.Error("the impermanence sentence was dropped")
			}
		})
	}
}

// --- RCCE-010/011: everything else keeps today's explanation ----------------

// TestNonCapacityOutcomesKeepTheGenericExplanation is the byte-stability half.
//
// Every one of these must produce detailConnectionNotPermitted **exactly**, and
// the assertion is equality rather than absence-of-keywords: a detail that
// gained a sentence nobody noticed would pass a "does not say node" check.
func TestNonCapacityOutcomesKeepTheGenericExplanation(t *testing.T) {
	tests := []struct {
		name    string
		class   domain.FailureClass
		outcome string
		present bool
	}{
		{"unspecified", domain.FailureAuthzNotPermitted,
			string(servicerabbitmq.CloseUnspecified), true},
		{"unspecified truncated", domain.FailureAuthzNotPermitted,
			string(servicerabbitmq.CloseUnspecifiedTruncated), true},
		{"attribute absent", domain.FailureAuthzNotPermitted, "", false},
		{"attribute empty", domain.FailureAuthzNotPermitted, "", true},
		{"unknown value", domain.FailureAuthzNotPermitted, "SOMETHING_ELSE", true},

		// The same, on the class that *does* admit enrichment. A capacity class
		// with no recognizable outcome is the truncation case in production, and
		// it must degrade rather than guess.
		{"limit class, unspecified", domain.FailureResourceLimitReached,
			string(servicerabbitmq.CloseUnspecified), true},
		{"limit class, truncated", domain.FailureResourceLimitReached,
			string(servicerabbitmq.CloseUnspecifiedTruncated), true},
		{"limit class, absent", domain.FailureResourceLimitReached, "", false},
		{"limit class, empty", domain.FailureResourceLimitReached, "", true},

		// A capacity outcome on a class that is not the capacity class cannot
		// happen in production — classify() pairs them — and if it ever did, the
		// specific sentence would describe a refusal that was not a ceiling.
		{"wrong class, node outcome", domain.FailureAuthzNotPermitted,
			string(servicerabbitmq.CloseNodeConnectionLimit), true},
		{"wrong class, vhost outcome", domain.FailureAuthzNotPermitted,
			string(servicerabbitmq.CloseVHostConnectionLimit), true},
		{"wrong class, user outcome", domain.FailureAuthzNotPermitted,
			string(servicerabbitmq.CloseUserConnectionLimit), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := openNode(t, tt.class, tt.outcome, tt.present)
			f := oneOpenFinding(t, g)
			if f.Detail() != detailConnectionNotPermitted {
				t.Errorf("explanation changed for a case that must be untouched.\ngot:  %q\nwant: %q",
					f.Detail(), detailConnectionNotPermitted)
			}
		})
	}
}

// --- RCCE-005: a hostile peer cannot reach the explanation ------------------

// TestHostileOutcomeValuesCannotProduceCapacityProse is the security property,
// asserted at the consumer rather than trusted from the producer.
//
// The producer cannot emit any of these — normalizeClose returns one of seven
// constants and is fuzz-proven to. These are planted directly into evidence
// anyway, because the mapping's safety must not depend on that invariant
// holding: it is a lookup on exact keys, so a near-miss is a miss.
func TestHostileOutcomeValuesCannotProduceCapacityProse(t *testing.T) {
	hostile := []string{
		// Near misses on a real key. Every one of these would match under a
		// prefix, suffix, trimming or case-folding comparison.
		"NODE_CONNECTION_LIMIT ",
		" NODE_CONNECTION_LIMIT",
		"node_connection_limit",
		"Node_Connection_Limit",
		"NODE_CONNECTION_LIMITS",
		"XNODE_CONNECTION_LIMIT",
		"NODE_CONNECTION_LIMIT\x00",
		"USER_CONNECTION_LIMIT_",
		"VHOST_CONNECTION_LIMIT\n",

		// Peer prose, including the shapes a terminal would misrender.
		"NOT_ALLOWED - connection refused: node connection limit (0) is reached",
		"connection limit (0) is reached",
		"\r\nFAKE LINE",
		"\x1b[31mred\x1b[0m",
		"\x1b]0;title\x07",
		strings.Repeat("A", 100000),
		"password=hunter2",
		"' OR 1=1 --",
		"",
	}

	for _, value := range hostile {
		g := openNode(t, domain.FailureResourceLimitReached, value, true)
		f := oneOpenFinding(t, g)
		if f.Detail() != detailConnectionNotPermitted {
			t.Errorf("value %q produced a non-generic explanation:\n%q", value, f.Detail())
		}
		// Belt and braces: whatever happened, the peer's bytes are not in it.
		if value != "" && strings.Contains(f.Detail(), value) {
			t.Errorf("the value %q reached the explanation", value)
		}
	}
}

// --- RCCE-004: everything except Detail is untouched ------------------------

// TestOnlyDetailChangesForCapacityOutcomes compares a capacity finding against
// the generic one field by field.
//
// **Recommendations are the field this phase most had to resist.** ADR 0091 §7
// separates explanation specificity from remediation specificity: the outcome
// proves which ceiling the peer named, and proves nothing about what to change.
func TestOnlyDetailChangesForCapacityOutcomes(t *testing.T) {
	base := oneOpenFinding(t, openNode(t, domain.FailureResourceLimitReached,
		string(servicerabbitmq.CloseUnspecified), true))

	for _, outcome := range []servicerabbitmq.CloseOutcome{
		servicerabbitmq.CloseNodeConnectionLimit,
		servicerabbitmq.CloseVHostConnectionLimit,
		servicerabbitmq.CloseUserConnectionLimit,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			got := oneOpenFinding(t, openNode(t, domain.FailureResourceLimitReached,
				string(outcome), true))

			// **Absolute, not relative.** Comparing only against `base` would
			// pass for a mutation that moved the whole arm — both findings come
			// from the same switch case, so a severity changed there changes
			// both sides and the difference stays zero. The Phase 10.8B mutation
			// harness planted exactly that and it survived, which is how these
			// four literals got here.
			if got.Code() != CodeConnectionNotPermitted {
				t.Errorf("code = %s, want RABBITMQ_CONNECTION_NOT_PERMITTED", got.Code())
			}
			if got.Kind() != domain.FindingKindConfirmed {
				t.Errorf("kind = %s, want CONFIRMED", got.Kind())
			}
			if got.Severity() != domain.SeverityError {
				t.Errorf("severity = %s, want ERROR", got.Severity())
			}
			if got.Confidence() != domain.ConfidenceHigh {
				t.Errorf("confidence = %s, want HIGH", got.Confidence())
			}
			if got.Layer() != domain.LayerAuth {
				t.Errorf("layer = %s, want L5", got.Layer())
			}
			// The recommendation is the field ADR 0091 §7 froze byte-identical,
			// so it is asserted against its own constant rather than against a
			// sibling finding.
			recs := got.Recommendations()
			if len(recs) != 1 || recs[0].Action() != recommendConnectionNotPermitted {
				t.Errorf("recommendation changed: %v, want the single action %q",
					recs, recommendConnectionNotPermitted)
			}
			if got.Code() != base.Code() {
				t.Errorf("code drifted from the generic finding: %s vs %s",
					got.Code(), base.Code())
			}
			if got.Subject() != base.Subject() {
				t.Errorf("subject = %v, want %v", got.Subject(), base.Subject())
			}
			if got.Summary() != base.Summary() {
				t.Errorf("summary = %q, want %q", got.Summary(), base.Summary())
			}
			if got.VantageDependent() != base.VantageDependent() {
				t.Error("vantageDependent changed")
			}
			if got.Discriminator() != base.Discriminator() {
				t.Error("discriminator changed")
			}
			if got.EvidenceRefCount() != base.EvidenceRefCount() {
				t.Errorf("evidence refs = %d, want %d",
					got.EvidenceRefCount(), base.EvidenceRefCount())
			}

			// Recommendations, compared as encoded bytes so that a field added
			// to Recommendation later is compared too.
			if gotJSON, baseJSON := mustJSON(t, got.Recommendations()),
				mustJSON(t, base.Recommendations()); gotJSON != baseJSON {
				t.Errorf("recommendations changed.\ngot:  %s\nwant: %s", gotJSON, baseJSON)
			}

			// And the one field that must change, did.
			if got.Detail() == base.Detail() {
				t.Error("detail did not change for a mapped capacity outcome")
			}
		})
	}
}

// --- RCCE-013: canonical JSON, both halves ----------------------------------

// TestCanonicalJSONChangesOnlyInDetail proves the §9 compatibility contract on
// the encoded bytes rather than on the accessors.
//
// The mapped half is not "JSON unchanged" and this phase does not claim it is:
// the bytes move, and they must move in `detail` and nowhere else.
func TestCanonicalJSONChangesOnlyInDetail(t *testing.T) {
	baseline := mustJSON(t, oneOpenFinding(t, openNode(t,
		domain.FailureResourceLimitReached, string(servicerabbitmq.CloseUnspecified), true)))

	var baseObj map[string]any
	if err := json.Unmarshal([]byte(baseline), &baseObj); err != nil {
		t.Fatalf("unmarshal baseline: %v", err)
	}

	for _, outcome := range []servicerabbitmq.CloseOutcome{
		servicerabbitmq.CloseNodeConnectionLimit,
		servicerabbitmq.CloseVHostConnectionLimit,
		servicerabbitmq.CloseUserConnectionLimit,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			encoded := mustJSON(t, oneOpenFinding(t, openNode(t,
				domain.FailureResourceLimitReached, string(outcome), true)))

			var gotObj map[string]any
			if err := json.Unmarshal([]byte(encoded), &gotObj); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if len(gotObj) != len(baseObj) {
				t.Fatalf("field count = %d, want %d — the JSON structure moved",
					len(gotObj), len(baseObj))
			}
			for key, want := range baseObj {
				got, present := gotObj[key]
				if !present {
					t.Fatalf("field %q disappeared", key)
				}
				if key == "detail" {
					if got == want {
						t.Error("detail did not change")
					}
					continue
				}
				if mustJSON(t, got) != mustJSON(t, want) {
					t.Errorf("field %q changed: got %v, want %v", key, got, want)
				}
			}
		})
	}
}

// --- RCCE-006: the mapping is keyed by outcome, not by product --------------

// TestTheMappingIsKeyedByOutcomeAlone is the product-independence proof.
//
// LavinMQ reaches VHOST_CONNECTION_LIMIT through its own reply template and
// earns the same explanation (ADR 0091 §6). Nothing in this package can even see
// which implementation answered — there is no product attribute on this node and
// no import that could supply one — so the structural proof is stronger than a
// behavioural one, and this asserts the structure.
func TestTheMappingIsKeyedByOutcomeAlone(t *testing.T) {
	// Every key is a CloseOutcome constant and the map has exactly the three
	// capacity values. A fourth entry, or an entry keyed on anything else, is a
	// different feature.
	if len(capacityScopeDetail) != 3 {
		t.Fatalf("the capacity map has %d entries, want exactly 3", len(capacityScopeDetail))
	}
	for _, want := range []servicerabbitmq.CloseOutcome{
		servicerabbitmq.CloseNodeConnectionLimit,
		servicerabbitmq.CloseVHostConnectionLimit,
		servicerabbitmq.CloseUserConnectionLimit,
	} {
		if _, ok := capacityScopeDetail[want]; !ok {
			t.Errorf("the capacity map is missing %s", want)
		}
	}
	// The non-capacity outcomes are absent, which is what keeps a vhost-absent
	// or unclassified refusal from acquiring a scope.
	for _, absent := range []servicerabbitmq.CloseOutcome{
		servicerabbitmq.CloseUnspecified,
		servicerabbitmq.CloseUnspecifiedTruncated,
		servicerabbitmq.CloseVHostNotFound,
		servicerabbitmq.CloseVHostAccessRefused,
	} {
		if _, ok := capacityScopeDetail[absent]; ok {
			t.Errorf("%s is mapped and must not be", absent)
		}
	}
}

// --- RCCE-022: the wording ceiling ------------------------------------------

// TestCapacityExplanationsRefuseTheOverclaims scopes its assertions to the three
// new strings, deliberately.
//
// A repository-wide keyword scan would be brittle and would fail on unrelated
// prose that legitimately uses one of these words. These are the sentences the
// phase authored, and these are the claims ADR 0091 §8 forbids permanently.
func TestCapacityExplanationsRefuseTheOverclaims(t *testing.T) {
	forbidden := []string{
		"exhaust", "globally", "global", "overload", "unhealthy", "misconfigur",
		"too low", "increase", "root cause", "leak", "all slots", "capacity exhausted",
		"cluster", "permanently", "always", "definitely",
	}

	for name, detail := range map[string]string{
		"node":  detailCapacityNode,
		"vhost": detailCapacityVHost,
		"user":  detailCapacityUser,
	} {
		lower := strings.ToLower(detail)
		for _, word := range forbidden {
			if strings.Contains(lower, word) {
				t.Errorf("the %s explanation contains the forbidden claim %q", name, word)
			}
		}
		// The raw enum identifier must not surface either: the design is fixed
		// human prose, and leaking the constant would be the interpolation this
		// phase exists to avoid.
		for _, raw := range []string{"NODE_CONNECTION_LIMIT", "VHOST_CONNECTION_LIMIT",
			"USER_CONNECTION_LIMIT", "close_outcome"} {
			if strings.Contains(detail, raw) {
				t.Errorf("the %s explanation leaks the raw identifier %q", name, raw)
			}
		}
		// It must still refuse cause, duration and remedy.
		if !strings.Contains(detail, "it proves nothing about why, for how long, or what to change") {
			t.Errorf("the %s explanation dropped the no-cause sentence", name)
		}
	}
}

// --- RCCE-012: repeated construction is deterministic -----------------------

func TestCapacityExplanationIsDeterministic(t *testing.T) {
	for i := 0; i < 32; i++ {
		f := oneOpenFinding(t, openNode(t, domain.FailureResourceLimitReached,
			string(servicerabbitmq.CloseUserConnectionLimit), true))
		if f.Detail() != detailCapacityUser {
			t.Fatalf("iteration %d produced a different explanation", i)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(encoded)
}

// --- RCCE-021: the closed-value property, over arbitrary strings ------------

// FuzzOnlyClosedOutcomesEnrich is the invariant stated as a property.
//
// The unit table above enumerates the values a reviewer thought of. This states
// the rule itself: **for any string at all, capacity prose appears only when the
// string is byte-equal to one of the three admitted outcomes.** No prefix, no
// suffix, no trimming, no case folding, no normalization of any kind.
//
// It matters because the producer's closure and this consumer's closure are
// independent defences. `normalizeClose` is already fuzz-proven to emit one of
// seven constants, so in production nothing else can arrive — but the mapping
// must not *depend* on that, because a future producer change would then turn a
// safe lookup into an exploitable one silently.
func FuzzOnlyClosedOutcomesEnrich(f *testing.F) {
	f.Add("NODE_CONNECTION_LIMIT")
	f.Add("node_connection_limit")
	f.Add(" VHOST_CONNECTION_LIMIT ")
	f.Add("USER_CONNECTION_LIMITX")
	f.Add("UNSPECIFIED")
	f.Add("")
	f.Add("NOT_ALLOWED - connection refused: node connection limit (0) is reached")
	f.Add("\x1b[31m")

	admitted := map[string]bool{
		string(servicerabbitmq.CloseNodeConnectionLimit):  true,
		string(servicerabbitmq.CloseVHostConnectionLimit): true,
		string(servicerabbitmq.CloseUserConnectionLimit):  true,
	}

	f.Fuzz(func(t *testing.T, outcome string) {
		detail := oneOpenFinding(t,
			openNode(t, domain.FailureResourceLimitReached, outcome, true)).Detail()

		enriched := detail != detailConnectionNotPermitted

		if enriched != admitted[outcome] {
			t.Fatalf("outcome %q: enriched=%v, admitted=%v", outcome, enriched, admitted[outcome])
		}
		if !enriched {
			return
		}
		// An enriched explanation is one of exactly three constants. It is never
		// assembled, so no input can appear in it.
		switch detail {
		case detailCapacityNode, detailCapacityVHost, detailCapacityUser:
		default:
			t.Fatalf("outcome %q produced prose that is not one of the three constants:\n%q",
				outcome, detail)
		}
	})
}
