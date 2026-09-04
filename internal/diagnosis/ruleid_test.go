package diagnosis

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Phase 10.1a, ADR 0080 section 2.5 and ADR 0081 section 2.6: rule identity.
//
// The identity is load-bearing twice over — it is what duplicate detection
// compares and what the merge tie-break sorts on — and it is not in the report,
// so nothing downstream would notice it going wrong.

func TestDIAG022RuleIDAcceptsTheFrozenSpelling(t *testing.T) {
	for _, id := range []string{
		"transport/dns",
		"transport/tcp",
		"kafka/advertised-endpoint",
		"postgres/ssl-request",
		"rabbitmq/connection-start",
		"a/b",
		"owner2/name3",
		"diag/failure-boundary",
	} {
		got, err := NewRuleID(id)
		if err != nil {
			t.Errorf("NewRuleID(%q) = %v, want it accepted", id, err)
			continue
		}
		if string(got) != id {
			t.Errorf("NewRuleID(%q) = %q; an identity is stored as written", id, got)
		}
		if !got.Valid() {
			t.Errorf("%q was accepted but reports invalid", id)
		}
	}
}

func TestDIAG022RuleIDRejectsEverythingElse(t *testing.T) {
	cases := []struct {
		id  string
		why string
	}{
		{"", "empty"},
		{"transport", "no owner/name separator"},
		{"transport/", "empty name"},
		{"/dns", "empty owner"},
		{"transport/dns/extra", "two separators"},
		{"Transport/dns", "upper case would let two spellings mean one rule"},
		{"transport/DNS", "upper case in the name"},
		{"transport/dns_lookup", "underscore is not the word separator"},
		{"transport/dns lookup", "space"},
		{"transport/-dns", "leading hyphen"},
		{"transport/dns-", "trailing hyphen"},
		{"transport/dns--lookup", "double hyphen is a second spelling of one name"},
		{"2transport/dns", "a part must start with a letter"},
		{"transport/2dns", "a part must start with a letter"},
		{"transport/dns.lookup", "a dot is a step separator, not an identity one"},
		{"tränsport/dns", "non-ASCII invites confusables"},
		{"transport/" + strings.Repeat("a", maxRuleIDPart+1), "over the length bound"},
	}

	for _, c := range cases {
		if _, err := NewRuleID(c.id); err == nil {
			t.Errorf("NewRuleID(%q) was accepted; %s", c.id, c.why)
		} else if !errors.Is(err, ErrInvalidRuleID) {
			t.Errorf("NewRuleID(%q) = %v, want ErrInvalidRuleID", c.id, err)
		}
	}
}

func TestRuleIDPartsAreReadable(t *testing.T) {
	id, err := NewRuleID("kafka/advertised-endpoint")
	if err != nil {
		t.Fatalf("NewRuleID: %v", err)
	}
	if got := id.Owner(); got != "kafka" {
		t.Errorf("Owner() = %q, want %q", got, "kafka")
	}
	if got := id.Name(); got != "advertised-endpoint" {
		t.Errorf("Name() = %q, want %q", got, "advertised-endpoint")
	}
	if got := id.String(); got != "kafka/advertised-endpoint" {
		t.Errorf("String() = %q", got)
	}

	// A malformed value yields empty parts rather than a panic or a partial
	// guess. Nothing should be reading parts off an unvalidated identity, and if
	// something does, the answer must be harmless.
	var zero RuleID
	if zero.Owner() != "" || zero.Name() != "" {
		t.Errorf("the zero RuleID yielded parts %q/%q", zero.Owner(), zero.Name())
	}
	if zero.Valid() {
		t.Error("the zero RuleID reports valid")
	}
}

// TestDIAG031RuleIDOrderIsByteOrder is the property the merge tie-break rests on.
//
// ADR 0081 section 2.6 breaks a merge tie by RuleID ascending, and calls the
// choice arbitrary and stable. Stable is the requirement, and it holds only
// because the spelling is restricted: with mixed case or Unicode, "sorted by
// bytes" and "sorted the way a reader would" could disagree, and two
// implementations would then break a tie two ways.
func TestDIAG031RuleIDOrderIsByteOrder(t *testing.T) {
	ids := []RuleID{
		"transport/tls", "kafka/protocol", "transport/dns",
		"kafka/advertised-endpoint", "postgres/session",
	}
	want := []RuleID{
		"kafka/advertised-endpoint", "kafka/protocol", "postgres/session",
		"transport/dns", "transport/tls",
	}

	got := slices.Clone(ids)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("sorted = %v, want %v", got, want)
	}

	// Sorting is idempotent and independent of the starting order, which is what
	// makes a tie-break reproducible rather than merely defined.
	for _, start := range [][]RuleID{
		{"transport/dns", "kafka/protocol"},
		{"kafka/protocol", "transport/dns"},
	} {
		shuffled := slices.Clone(start)
		slices.Sort(shuffled)
		if !slices.Equal(shuffled, []RuleID{"kafka/protocol", "transport/dns"}) {
			t.Errorf("sorting %v gave %v", start, shuffled)
		}
	}
}

// TestRuleIDDerivesFromNothingAtRuntime is the negative half of ADR 0081
// section 2.6's "no identifier derives from a runtime value".
//
// It is asserted behaviourally because the structural half — that this package
// imports no clock and no random source — is a build failure elsewhere. What is
// left to prove is that the constructor is a pure function of its argument.
func TestRuleIDDerivesFromNothingAtRuntime(t *testing.T) {
	const input = "transport/dns"

	first, err := NewRuleID(input)
	if err != nil {
		t.Fatalf("NewRuleID: %v", err)
	}
	for i := range 128 {
		again, err := NewRuleID(input)
		if err != nil {
			t.Fatalf("NewRuleID (iteration %d): %v", i, err)
		}
		if again != first {
			t.Fatalf("iteration %d produced %q, want %q", i, again, first)
		}
	}
}
