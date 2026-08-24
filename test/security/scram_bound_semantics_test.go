package security_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The prose half of ADR 0061 §19, guarded where a wording change is most likely
// to slip through review.
//
// # The defect this exists for
//
// svcdoctor bounds the size of the SCRAM values it will process. Those bounds
// are its own policy — RFC 5802 and RFC 7677 set no maximum on a salt, a nonce,
// an attribute list or a message — so a value above one of them is **legal
// protocol svcdoctor declined to read**.
//
// Kafka's capability finding covers two causes that share one code, because to
// an operator they are one fact: *svcdoctor could not do this*. But they are not
// one sentence. One is a mechanism svcdoctor does not implement; the other is an
// exchange svcdoctor declined **inside a mechanism it does**. Redpanda's legal
// 130-byte salt is the measured case, and telling that operator their broker
// negotiated an unsupported mechanism would send them to fix SCRAM-SHA-256 —
// which svcdoctor implements and which was never the problem.
//
// The classification itself is pinned inside each package, where the functions
// are reachable. This guards the strings, which no type checker protects.

// TestTheExchangeCapabilityProseDoesNotClaimAMechanismGap keeps the two wordings
// apart.
func TestTheExchangeCapabilityProseDoesNotClaimAMechanismGap(t *testing.T) {
	source := repoSource(t, "internal/diagnosis/kafka/protocol.go")

	if !strings.Contains(source, "summaryUnsupportedExchange") {
		t.Fatal("the exchange-side capability prose is gone.\n\n" +
			"Without it the mechanism wording is reused for a defensive-bound " +
			"refusal, which says the endpoint negotiated something svcdoctor does " +
			"not implement — false for every cause routed there (ADR 0061 §19).")
	}

	block := between(source, "summaryUnsupportedExchange = ", "recommendUnsupportedExchange = ")
	if block == "" {
		t.Fatal("could not read the exchange-side prose block")
	}

	for _, forbidden := range []string{
		"does not implement",
		"cannot perform the SASL mechanism",
		"mechanism svcdoctor does not",
	} {
		if strings.Contains(block, forbidden) {
			t.Errorf("the exchange-side prose contains %q.\n\n"+
				"Every cause routed to it arrives inside a mechanism svcdoctor does "+
				"implement — it ran the handshake and began the exchange before "+
				"declining a parameter in it.", forbidden)
		}
	}

	lower := strings.ToLower(joinLiterals(block))
	for _, required := range []struct{ phrase, why string }{
		{"svcdoctor", "the claim must name whose limit it was"},
		{"defensive", "the limit must be recorded as policy rather than as a protocol rule"},
		{"neither accepted nor rejected", "an UNKNOWN node must not read as a refusal"},
	} {
		if !strings.Contains(lower, required.phrase) {
			t.Errorf("the exchange-side prose does not contain %q: %s",
				required.phrase, required.why)
		}
	}
}

// TestThePostgreSQLCapabilityProseCoversSizeRefusals is the same audit for the
// other service, whose wording was already mechanism-agnostic and only needed
// its enumeration widened.
func TestThePostgreSQLCapabilityProseCoversSizeRefusals(t *testing.T) {
	source := repoSource(t, "internal/diagnosis/postgres/authentication.go")
	block := between(source, "detailUnsupportedBySvcdoctor = ", "recommendUnsupportedBySvcdoctor = ")
	if block == "" {
		t.Fatal("could not read the PostgreSQL capability prose block")
	}

	lower := strings.ToLower(joinLiterals(block))
	if !strings.Contains(lower, "message size") && !strings.Contains(lower, "message sizes") {
		t.Error("the PostgreSQL capability detail does not mention bounded SCRAM " +
			"message sizes, so a size refusal reaches an operator described only as " +
			"a password-range or iteration-count limitation (ADR 0061 §19)")
	}
	if !strings.Contains(lower, "neither accepted nor rejected") {
		t.Error("the PostgreSQL capability detail no longer says the credential was " +
			"neither accepted nor rejected; an UNKNOWN node must not read as a refusal")
	}
}

// TestTheProseGuardsCanFail proves the parsing above is not vacuous.
func TestTheProseGuardsCanFail(t *testing.T) {
	const planted = "summaryUnsupportedExchange = \"svcdoctor cannot perform the SASL " +
		"mechanism\"\nrecommendUnsupportedExchange = "
	block := between(planted, "summaryUnsupportedExchange = ", "recommendUnsupportedExchange = ")
	if block == "" {
		t.Fatal("between() returned nothing for a well-formed block")
	}
	if !strings.Contains(block, "cannot perform the SASL mechanism") {
		t.Error("the guard would not see a planted mechanism claim")
	}
	if between("no markers here", "summaryUnsupportedExchange = ", "x") != "" {
		t.Error("between() invented a block that is not there")
	}

	// joinLiterals is what makes the required-phrase half work at all, and it is
	// also the half most able to hide a failure: if it mangled the text, every
	// forbidden phrase would stop matching and the guard would pass silently.
	wrapped := "\"the credential was neither accepted nor \" +\n\t\t\"rejected\""
	if got := joinLiterals(wrapped); !strings.Contains(got, "neither accepted nor rejected") {
		t.Errorf("joinLiterals did not splice a wrapped phrase: %q", got)
	}
	if got := joinLiterals("\"does not \" +\n\t\t\"implement\""); !strings.Contains(got, "does not implement") {
		t.Errorf("joinLiterals did not splice a wrapped forbidden phrase: %q", got)
	}
}

// joinLiterals splices Go string concatenation back together.
//
// The prose is wrapped to a column, so a phrase routinely lands as
// `"...neither accepted nor " + "rejected..."` and a naive substring search over
// the source misses it. Without this the guard would fail whenever someone
// re-wrapped a line, which teaches the next reader to weaken it.
func joinLiterals(block string) string {
	for _, seam := range []string{"\" +\n\t\t\"", "\" +\n\t\t\t\"", "\" + \""} {
		block = strings.ReplaceAll(block, seam, "")
	}
	// Whatever wrapping remains collapses to single spaces.
	return strings.Join(strings.Fields(block), " ")
}

// between returns the text from the first occurrence of start up to the first
// occurrence of end after it.
func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return rest
	}
	return rest[:j]
}

// repoSource reads one repository-relative file.
func repoSource(t *testing.T, rel string) string {
	t.Helper()

	path := filepath.Join(repositoryRoot(t), rel)
	body, err := os.ReadFile(path) //nolint:gosec // a repository path this test built.
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	return string(body)
}
