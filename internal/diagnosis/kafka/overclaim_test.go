package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The truthfulness guard for everything this package says out loud.
//
// # Why prose needs a test at all
//
// Every other property of a claim — its code, severity, confidence, layer,
// subject, references — is a typed value some test compares. The prose is a
// string constant, and until Phase 6.5 nothing read it. Mutation found the gap:
// rewriting summaryCredentialsRejected to *"The password configured for this
// Kafka endpoint is wrong"* passed the entire suite, including the golden
// terminal output, which simply re-rendered the new sentence.
//
// That sentence is the exact overclaim CodeCredentialsRejected's own
// documentation forbids. Kafka returns one error code for a wrong secret, an
// unknown principal, a disabled or locked account and a failing authentication
// backend alike, and its message is deliberately generic — so *"rejected"* is
// the whole of what was observed and *"the password is wrong"* is a cause
// nobody evidenced. An operator sent to rotate a correct credential is worse
// off than one told nothing.
//
// TestPeerVerificationIsNeverRenderedAsARejectedCredential already holds the
// neighbouring direction at the output boundary. This holds the source of the
// words, for every claim rather than for one.
//
// # A disclaimer is not a claim, and the guard has to know the difference
//
// The first version of this test failed on truthful prose. `KAFKA_METADATA_NOT_
// COMPLETED` ends *"so this says nothing about topics, partitions, the
// controller, or whether the cluster is healthy"* — a sentence whose entire
// purpose is to refuse the claims it names. Banning the vocabulary outright
// would forbid the disclaimers this package is careful to write, which is the
// opposite of the discipline being protected.
//
// So the rule is applied per sentence, and a sentence that disclaims may name
// what it refuses. Summaries and recommendations are checked without that
// exemption: neither is ever a disclaimer, and every one in the table is a plain
// observation.
var overclaims = []string{
	// A refusal is not a diagnosis of the credential.
	"is wrong",
	"are wrong",
	"wrong password",
	"incorrect password",
	"bad password",
	"invalid password",
	"invalid credential",

	// Liveness svcdoctor never measured.
	"is down",
	"are down",
	"is offline",
	"is unavailable",
	"not running",

	// Fitness claims. One endpoint answering proves nothing about a cluster, and
	// ADR 0052 forbids the success vocabulary as firmly as the failure one.
	"is healthy",
	"is unhealthy",
	"cluster healthy",
	"cluster is broken",
	"cluster is reachable",
	"cluster is unreachable",
	"all brokers",
	"every broker",

	// Work no BASIC run performs, so no claim may rest on it.
	"consumer lag",
	"partition",
	"replication",
	"in-sync",
	"throughput",
	"quorum",
}

// disclaimers are the phrasings this package uses to refuse a claim.
//
// A sentence containing one is naming what it will *not* assert, so the
// vocabulary above is allowed inside it. The list is explicit phrases rather
// than bare words like "not", because "not" appears in ordinary assertions too
// and exempting every sentence containing it would empty the guard.
//
// TestEveryDisclaimerIsEarned keeps the list from growing unused escape hatches.
var disclaimers = []string{
	"says nothing about",
	"does not state",
	"does not say",
	"not that",
	"and not why",
	"is unknown",
	"not an observation",
	"not a defect",
	"indistinguishable",
}

// TestNoKafkaClaimOverclaims sweeps the prose of every finding this package can
// build.
//
// It drives the authorized protocol table and both advertised-broker rules, so
// a new claim is covered the moment it exists rather than when somebody
// remembers to add it here.
func TestNoKafkaClaimOverclaims(t *testing.T) {
	for _, f := range everyFindingThisPackageCanBuild(t) {
		assertNoOverclaim(t, f)
	}
}

// TestTheOverclaimGuardCanFail proves the sweep is not vacuous.
//
// A prose test that examined no text, or matched case-sensitively against text
// that is capitalized differently, would pass forever. This runs the same
// predicate over the sentence the mutation actually planted, and over the
// production wording it must leave alone.
func TestTheOverclaimGuardCanFail(t *testing.T) {
	planted := "The password configured for this Kafka endpoint is wrong"
	if phrase, ok := firstOverclaim(planted); !ok {
		t.Error("the guard does not flag the sentence mutation M11 planted")
	} else if phrase != "is wrong" {
		t.Errorf("flagged %q, want the phrase that is actually present", phrase)
	}

	if _, ok := firstOverclaim(summaryCredentialsRejected); ok {
		t.Errorf("the production wording is flagged; the guard is too broad: %q",
			summaryCredentialsRejected)
	}

	// A disclaimer sentence keeps its exemption; the same words asserted do not.
	if overclaimInProse("This says nothing about whether the cluster is healthy.") {
		t.Error("a disclaimer was treated as a claim")
	}
	if !overclaimInProse("The cluster is healthy.") {
		t.Error("an assertion escaped by borrowing a disclaimer's vocabulary")
	}
}

// TestEveryDisclaimerIsEarned keeps the exemption list honest.
//
// Each entry must be a phrase some production sentence actually uses. An unused
// disclaimer is a hole nobody is watching: it exempts sentences this package
// does not write today and would silently permit one written tomorrow.
func TestEveryDisclaimerIsEarned(t *testing.T) {
	var prose []string
	for _, f := range everyFindingThisPackageCanBuild(t) {
		prose = append(prose, strings.ToLower(f.Detail()))
	}

	for _, d := range disclaimers {
		used := false
		for _, p := range prose {
			if strings.Contains(p, d) {
				used = true
				break
			}
		}
		if !used {
			t.Errorf("no claim's detail uses the disclaimer %q.\n\n"+
				"An unused exemption widens what the guard permits without any "+
				"prose needing it.", d)
		}
	}
}

// TestEveryClaimIsSweptByTheOverclaimGuard pins the sweep's coverage.
//
// The guard is only as good as the set it runs over, and the set is built
// rather than listed. This asserts that building it really did reach every
// authorized protocol outcome plus both advertised claims — so a table entry
// that stopped producing a finding would fail here instead of silently
// shrinking the sweep.
func TestEveryClaimIsSweptByTheOverclaimGuard(t *testing.T) {
	codes := map[domain.FindingCode]bool{}
	for _, f := range everyFindingThisPackageCanBuild(t) {
		codes[f.Code()] = true
	}

	// The eleven protocol codes, plus the two advertised-broker ones.
	if len(codes) != 13 {
		t.Errorf("the sweep covers %d codes, want 13: %v", len(codes), codes)
	}
	for _, want := range []domain.FindingCode{
		CodeAdvertisedEndpointUnreachable, CodeAdvertisedEndpointUnusable,
		CodeCredentialsRejected, CodePeerVerificationFailed,
	} {
		if !codes[want] {
			t.Errorf("%s is never swept", want)
		}
	}
}

// everyFindingThisPackageCanBuild returns one finding per producible claim.
func everyFindingThisPackageCanBuild(t *testing.T) []domain.Finding {
	t.Helper()

	var out []domain.Finding
	for key := range protocolClaims {
		out = append(out, findingsFor(t, key.step, key.state, key.failure)...)
	}

	// Every advertised sweep shape, which between them produce the CONFIRMED and
	// HYPOTHESIS forms of the unreachability claim.
	for _, tc := range shapes() {
		b := newBuilder(t)
		exchange := b.metadata(domain.StatePass)
		advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
		tc.build(b, advertisement)
		out = append(out, AdvertisedEndpointUnreachable(rctx(b.freeze()))...)
	}

	// The advertisement the cluster could not state usably.
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	b.unusableAdvertised(exchange, 3)
	out = append(out, UnusableAdvertisement(rctx(b.freeze()))...)

	return out
}

// assertNoOverclaim reads everything one finding says.
//
// The summary and the recommendations are checked whole, because neither is
// ever a disclaimer. The detail is checked a sentence at a time.
func assertNoOverclaim(t *testing.T, f domain.Finding) {
	t.Helper()

	if phrase, ok := firstOverclaim(f.Summary()); ok {
		report(t, f, "summary", phrase, f.Summary())
	}
	for _, r := range f.Recommendations() {
		if phrase, ok := firstOverclaim(r.Action()); ok {
			report(t, f, "recommendation", phrase, r.Action())
		}
	}
	for _, sentence := range sentences(f.Detail()) {
		if disclaims(sentence) {
			continue
		}
		if phrase, ok := firstOverclaim(sentence); ok {
			report(t, f, "detail", phrase, sentence)
		}
	}
}

func report(t *testing.T, f domain.Finding, where, phrase, text string) {
	t.Helper()
	t.Errorf("%s %s asserts %q:\n  %s\n\n"+
		"A claim may state what was observed. It may not state a cause nobody "+
		"evidenced, and it may not widen from this endpoint to the cluster. "+
		"A sentence that disclaims one of these may name it; this one does not. "+
		"See docs/FINDINGS.md section 3.1 and ADR 0052.",
		f.Code(), where, phrase, strings.TrimSpace(text))
}

// overclaimInProse is the whole predicate over one block of prose, used by the
// self-test above.
func overclaimInProse(text string) bool {
	for _, sentence := range sentences(text) {
		if disclaims(sentence) {
			continue
		}
		if _, ok := firstOverclaim(sentence); ok {
			return true
		}
	}
	return false
}

// sentences splits prose the way a reader would.
//
// Findings separate paragraphs with a newline and sentences with a full stop, so
// both are boundaries. Empty fragments are dropped rather than checked.
func sentences(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		for _, s := range strings.Split(line, ". ") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// disclaims reports whether a sentence is refusing a claim rather than making
// one.
func disclaims(sentence string) bool {
	lower := strings.ToLower(sentence)
	for _, d := range disclaimers {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// firstOverclaim returns the first forbidden phrase in text, if any.
//
// Comparison is case-insensitive, because a summary starts its sentence with a
// capital and a detail's later sentences may not.
func firstOverclaim(text string) (string, bool) {
	lower := strings.ToLower(text)
	for _, phrase := range overclaims {
		if strings.Contains(lower, phrase) {
			return phrase, true
		}
	}
	return "", false
}
