package cli

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// The capability-claim audit for the two documents an operator reads before
// running anything: the README and `--help`.
//
// # Why this exists
//
// Phase 6.5's mutation matrix planted two sentences and nothing failed:
// a README that says literal IPv4/IPv6 targets are supported, and an opening
// claim that names Confluent Cloud, AWS MSK and Redpanda as supported. Both are
// false, both are the kind of sentence that gets written in a hurry before a
// release, and neither is reachable from any test that reads Go code.
//
// The cost of each is asymmetric with its size. An operator who believes
// `--host` accepts an address gets a run whose transport diagnosis is right and
// whose `dns.lookup` PASS and hostname-resolution wording are not — the defect
// is reproduced and recorded in docs/BACKLOG.md, and the honest position until
// it is decided is that the capability is not advertised. An operator who
// believes a managed provider is supported has been told svcdoctor validated
// something against an implementation it has never run against; the Kafka
// fixture is Apache Kafka, and protocol similarity is not evidence.
//
// # What these do not do
//
// They do not read prose for meaning. Each pins one checkable structural fact,
// so ordinary editing is free and the two specific reversals are not.

// managedProviders are the names that would imply provider compatibility.
//
// Both services, because the claim is equally unproven on either side and a
// README does not separate them.
var managedProviders = []string{
	"Redpanda", "Confluent", "MSK", "Event Hubs",
	"RDS", "Aurora", "Cloud SQL", "Azure Database",
}

// denials are the words that mark a line as recording an absence rather than
// making a claim.
//
// Matched as whole words against a line stripped of Markdown emphasis, because
// the README writes "are **not** implemented" and a substring search for "not "
// misses it — which is how the first version of this guard failed on truthful
// prose.
var denials = map[string]bool{
	"not": true, "no": true, "never": true,
	"deferred": true, "unproven": true, "without": true,
}

// TestTheREADMENeverClaimsManagedCompatibility keeps provider names where they
// belong.
//
// A provider may be named only while the README is denying support for it or
// listing it as future work. Anywhere else — an opening summary, a feature
// table, an example — naming one asserts a compatibility nothing has measured.
//
// The Roadmap section is exempt as a whole, because its entire content is work
// not yet done and requiring a denial word on each of its bullets would be
// noise.
func TestTheREADMENeverClaimsManagedCompatibility(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	inRoadmap := false
	for _, line := range strings.Split(readme, "\n") {
		if strings.HasPrefix(line, "## ") {
			inRoadmap = strings.Contains(line, "Roadmap")
		}
		if inRoadmap {
			continue
		}
		// Sentence by sentence, not line by line. One README line carries both
		// the opening capability claim and an unrelated "No APM ... is required"
		// beside it, and a line-level denial check let a planted "including
		// Confluent Cloud, AWS MSK and Redpanda" ride on that neighbouring "No".
		for _, sentence := range claimSentences(line) {
			for _, provider := range managedProviders {
				if !strings.Contains(sentence, provider) || denies(sentence) {
					continue
				}
				t.Errorf("the README names %s outside the Roadmap without denying "+
					"support:\n  %s\n\n"+
					"Kafka BASIC is validated against Apache Kafka and PostgreSQL "+
					"BASIC against PostgreSQL and pgBouncer. Protocol similarity is "+
					"not evidence, and managed-service compatibility is an open "+
					"backlog item.", provider, sentence)
			}
		}
	}

	// And the backlog item stays visible, so the absence is recorded rather than
	// merely true.
	if !strings.Contains(readme, "managed-service protocol compatibility") {
		t.Error("the README no longer lists managed-service compatibility as future work")
	}
}

// TestTheREADMENeverClaimsIPLiteralSupport pins the boundary Phase 6.4C
// measured.
//
// `net.Resolver` returns a literal unchanged, so a literal target produces a
// `dns.lookup` PASS with a measured duration for work that did not happen, and
// the generic TCP finding's prose names a hostname that does not exist. The
// transport diagnosis below L1 is right and the L1 claim is not.
//
// The fix is the graph-shape decision in docs/BACKLOG.md, not a special case in
// a command — so until it is taken, the contract is that `--host` expects a name
// that resolves, and this is where that sentence is held.
func TestTheREADMENeverClaimsIPLiteralSupport(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	if !strings.Contains(readme, "no literal IPv4/IPv6 target support") {
		t.Error("the README's `Not in v0.1` list no longer records that literal " +
			"IPv4/IPv6 targets are unsupported")
	}
	if !strings.Contains(readme, "`--host` expects a name that resolves") {
		t.Error("the README no longer states what `--host` accepts")
	}
	assertNoIPLiteralClaim(t, "README.md", readme)
}

// TestTheKafkaHelpNeverClaimsIPLiteralSupport holds the same line in the text
// an operator reads without opening a browser.
//
// The help describes `--host` as *the bootstrap endpoint to diagnose*, which
// claims nothing about the form it takes. That is the honest wording while the
// graph semantics are undecided, and this fails if it grows into a promise.
func TestTheKafkaHelpNeverClaimsIPLiteralSupport(t *testing.T) {
	for _, service := range []string{"kafka", "postgres"} {
		h := newHarness(app.Result{}, nil)
		if code := h.run("diagnose", service, "--help"); code != ExitOK {
			t.Fatalf("`diagnose %s --help` exit = %d", service, code)
		}
		assertNoIPLiteralClaim(t, service+" help", h.stdout.String())
	}
}

// assertNoIPLiteralClaim fails on any sentence offering an address as valid
// input.
//
// It matches the phrasings that would be written, not the concept: a document
// may explain that literals are unsupported, and every phrase here is one that
// only appears when offering the capability.
func assertNoIPLiteralClaim(t *testing.T, where, text string) {
	t.Helper()

	claims := []string{
		"hostname or ip",
		"host or ip",
		"name or address",
		"name or an address",
		"ip address or",
		"accepts an ip",
		"accepts either",
		"ipv4 or ipv6 address",
		"literal ipv4/ipv6 targets are supported",
	}
	lower := strings.ToLower(text)
	for _, claim := range claims {
		if strings.Contains(lower, claim) {
			t.Errorf("%s offers %q as valid input for a target.\n\n"+
				"A literal reaches transport and produces a false `dns.lookup` PASS "+
				"and hostname-resolution wording. The capability is an open design "+
				"item in docs/BACKLOG.md and must not be advertised.", where, claim)
		}
	}
}

// TestTheDocsClaimGuardsCanFail proves neither guard is vacuous.
func TestTheDocsClaimGuardsCanFail(t *testing.T) {
	// The exact line mutation M29 planted: a capability claim followed by an
	// unrelated denial. Split correctly, the first sentence is not a denial.
	planted := "**PostgreSQL BASIC and Kafka BASIC are supported today, including " +
		"Confluent Cloud, AWS MSK and Redpanda.** No APM, OpenTelemetry collector,"
	sentences := claimSentences(planted)
	if len(sentences) < 2 {
		t.Fatalf("the claim and the denial beside it were not separated: %q", sentences)
	}
	if denies(sentences[0]) {
		t.Errorf("a sentence claiming managed support reads as a denial: %q", sentences[0])
	}
	if !strings.Contains(sentences[0], "Confluent") {
		t.Errorf("the claim sentence lost its provider name: %q", sentences[0])
	}
	if !denies("`AWS_MSK_IAM` and mTLS client-certificate authentication are **not** implemented.") {
		t.Error("the production denial is not recognized as one")
	}

	fake := &testing.T{}
	assertNoIPLiteralClaim(fake, "planted", "`--host` accepts either a hostname or an IP address.")
	if !fake.Failed() {
		t.Error("the guard does not flag a planted IP-literal claim")
	}
}

// claimSentences splits one Markdown line into the sentences a reader parses.
//
// Emphasis and code spans are removed first, so "supported today.** No APM"
// becomes two sentences rather than one — which is the whole point, since the
// second one's "No" must not exempt the first one's claim.
func claimSentences(line string) []string {
	stripped := strings.Map(func(r rune) rune {
		if r == '*' || r == '`' {
			return -1
		}
		return r
	}, line)

	var out []string
	for _, s := range strings.Split(stripped, ". ") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// denies reports whether a sentence is recording an absence.
//
// Markdown emphasis and code spans are stripped first, and the remainder is
// matched word by word: "**not**" and "`no`" are denials, and a provider name
// that happens to contain one of these letter sequences is not.
func denies(line string) bool {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '*', '`', '_':
			return -1
		case ',', '.', ';', ':', '(', ')', '"':
			return ' '
		}
		return r
	}, strings.ToLower(line))

	for _, word := range strings.Fields(cleaned) {
		if denials[word] {
			return true
		}
	}
	return false
}
