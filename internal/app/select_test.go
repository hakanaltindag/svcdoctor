package app

import (
	"net/netip"
	"slices"
	"testing"
)

// The selector is pure, so it is tested without a network, a server or a graph.
// That is the point of extracting it: the one place a path-selection policy
// could hide is reviewable on its own.

func addr(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return a
}

func set(t *testing.T, addresses ...string) []candidate[int] {
	t.Helper()
	out := make([]candidate[int], 0, len(addresses))
	for i, s := range addresses {
		out = append(out, candidate[int]{address: addr(t, s), result: i, authRequired: true})
	}
	return out
}

// TestSelectionIsIndependentOfInputOrder is the property the whole design rests
// on: the order paths were discovered in must not reach the output.
//
// Discovery order is a function of DNS answers and connection timing. If it
// could change which path receives the one credential a run is allowed, two
// identical runs against an unchanged target could authenticate over different
// addresses — and a diagnostic tool that is not reproducible is not much of one.
func TestSelectionIsIndependentOfInputOrder(t *testing.T) {
	addresses := []string{"10.0.0.7:5432", "[2001:db8::1]:5432", "10.0.0.5:5432", "10.0.0.6:5432"}

	forward := set(t, addresses...)
	want := forward[selectPath(forward, true)].address

	reversed := slices.Clone(addresses)
	slices.Reverse(reversed)
	if got := set(t, reversed...); got[selectPath(got, true)].address != want {
		t.Errorf("reversed input selected %s, want %s", got[selectPath(got, true)].address, want)
	}

	// Every rotation, so the result cannot depend on which entry happens to be
	// first or last.
	for i := range addresses {
		rotated := slices.Clone(addresses)
		rotated = append(rotated[i:], rotated[:i]...)
		c := set(t, rotated...)
		if got := c[selectPath(c, true)].address; got != want {
			t.Errorf("rotation %d selected %s, want %s", i, got, want)
		}
	}
}

// TestSelectionIsStableAcrossRepeatedCalls pins that nothing in the selector
// consults a clock, a map or a random source.
func TestSelectionIsStableAcrossRepeatedCalls(t *testing.T) {
	c := set(t, "10.0.0.9:5432", "[2001:db8::2]:5432", "10.0.0.3:5432")
	want := selectPath(c, true)

	for i := range 512 {
		if got := selectPath(c, true); got != want {
			t.Fatalf("call %d selected index %d, want %d", i, got, want)
		}
	}
}

// TestSelectionIsTheCanonicalMinimumAndNotAPosition distinguishes the policy
// from the two things it is most likely to be mistaken for.
//
// A selector that returned the first entry, or the last, would pass a test that
// only checked "something was selected". These cases are constructed so that the
// canonical minimum is neither.
func TestSelectionIsTheCanonicalMinimumAndNotAPosition(t *testing.T) {
	tests := []struct {
		name      string
		addresses []string
		want      string
	}{
		{"minimum is in the middle", []string{"10.0.0.9:5432", "10.0.0.1:5432", "10.0.0.5:5432"}, "10.0.0.1:5432"},
		{"minimum is last", []string{"10.0.0.9:5432", "10.0.0.5:5432", "10.0.0.1:5432"}, "10.0.0.1:5432"},
		{"minimum is first", []string{"10.0.0.1:5432", "10.0.0.5:5432", "10.0.0.9:5432"}, "10.0.0.1:5432"},
		{"a single candidate", []string{"[2001:db8::5]:5432"}, "[2001:db8::5]:5432"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := set(t, tt.addresses...)
			if got := c[selectPath(c, true)].address.String(); got != tt.want {
				t.Errorf("selected %s, want %s", got, tt.want)
			}
		})
	}
}

// TestAnEmptyCandidateSetSelectsNothing pins the total case.
func TestAnEmptyCandidateSetSelectsNothing(t *testing.T) {
	if got := selectPath[int](nil, true); got != -1 {
		t.Errorf("selectPath(nil) = %d, want -1", got)
	}
	if got := selectPath([]candidate[int]{}, true); got != -1 {
		t.Errorf("selectPath(empty) = %d, want -1", got)
	}
}

// TestCanonicalOrderIsATieBreakAndNotAFamilyPreference is the test that names
// what this policy is, so a future reader cannot mistake the mechanism for the
// meaning.
//
// Canonical order does place every IPv4 address before every IPv6 one — that is
// netip.Addr.Compare, and it is exactly why ADR 0024 removed this ordering from
// the transport chain, where it decided *which single path was measured at all*.
//
// Here it decides something much smaller. By the time the selector runs, every
// candidate has already been measured through SSLRequest, TLS and Startup, and
// any difference between them is already recorded as evidence. What is left is
// which of several equally-measured paths receives the one credential a run may
// present, and that needs an answer that is deterministic rather than one that
// is meaningful.
//
// The assertions below therefore pin the mechanism *and* its scope: an
// IPv6-only set selects IPv6, which is what proves the rule is an ordering and
// not a preference for a family.
func TestCanonicalOrderIsATieBreakAndNotAFamilyPreference(t *testing.T) {
	mixed := set(t, "[2001:db8::1]:5432", "10.0.0.1:5432")
	if got := mixed[selectPath(mixed, true)].address.String(); got != "10.0.0.1:5432" {
		t.Errorf("mixed set selected %s, want the canonical minimum 10.0.0.1:5432", got)
	}

	// The rule is an ordering, not a family: with no IPv4 candidate the
	// canonical minimum is IPv6, and it is selected without hesitation.
	sixOnly := set(t, "[2001:db8::9]:5432", "[2001:db8::1]:5432")
	if got := sixOnly[selectPath(sixOnly, true)].address.String(); got != "[2001:db8::1]:5432" {
		t.Errorf("IPv6-only set selected %s, want [2001:db8::1]:5432", got)
	}

	// And the ordering the selector uses is the one sortedAddresses renders, so
	// the two cannot drift apart.
	if want := sortedAddresses(mixed)[0]; mixed[selectPath(mixed, true)].address != want {
		t.Errorf("the selector and the canonical ordering disagree")
	}
}

// --- class preference -------------------------------------------------------

// mixedSet builds candidates with an explicit class per address.
func mixedSet(t *testing.T, spec map[string]bool) []candidate[int] {
	t.Helper()

	// Deterministic construction order, so a failure is reproducible.
	addresses := make([]string, 0, len(spec))
	for a := range spec {
		addresses = append(addresses, a)
	}
	slices.Sort(addresses)

	out := make([]candidate[int], 0, len(addresses))
	for i, a := range addresses {
		out = append(out, candidate[int]{address: addr(t, a), result: i, authRequired: spec[a]})
	}
	return out
}

// TestClassPreferenceBeatsCanonicalOrder is the correction this review forced.
//
// The scenario is real and is not exotic: `pg_hba.conf` selects behaviour by
// source address, so one family can be admitted on `trust` while the other is
// asked for SCRAM. Canonical order alone would continue the trust path, and a
// run that had been given a credential would return OK **without ever
// exercising it** — answering a different question than the one asked.
//
// Neither class is healthier. The preference is about what the run can find out.
func TestClassPreferenceBeatsCanonicalOrder(t *testing.T) {
	// The canonically smaller address is the trust path, so a selector that
	// only ordered addresses would pick it.
	spec := map[string]bool{
		"10.0.0.1:5432":      false, // trust
		"[2001:db8::1]:5432": true,  // SCRAM
	}

	t.Run("a credential is configured", func(t *testing.T) {
		c := mixedSet(t, spec)
		got := c[selectPath(c, true)]
		if !got.authRequired {
			t.Fatalf("selected the trust path %s while carrying a credential", got.address)
		}
		if want := "[2001:db8::1]:5432"; got.address.String() != want {
			t.Errorf("selected %s, want %s", got.address, want)
		}
	})

	t.Run("no credential is configured", func(t *testing.T) {
		c := mixedSet(t, spec)
		got := c[selectPath(c, false)]
		if got.authRequired {
			t.Fatalf("selected the auth-required path %s with no credential", got.address)
		}
		if want := "10.0.0.1:5432"; got.address.String() != want {
			t.Errorf("selected %s, want %s", got.address, want)
		}
	})
}

// TestClassPreferenceSurvivesInputOrder proves the correction did not
// reintroduce an order dependence.
func TestClassPreferenceSurvivesInputOrder(t *testing.T) {
	forward := []candidate[int]{
		{address: addr(t, "10.0.0.1:5432"), result: 0, authRequired: false},
		{address: addr(t, "10.0.0.2:5432"), result: 1, authRequired: true},
		{address: addr(t, "10.0.0.3:5432"), result: 2, authRequired: true},
	}
	reversed := slices.Clone(forward)
	slices.Reverse(reversed)

	for _, want := range []bool{true, false} {
		a := forward[selectPath(forward, want)].address
		b := reversed[selectPath(reversed, want)].address
		if a != b {
			t.Errorf("wantAuthRequired=%v: forward selected %s, reversed selected %s", want, a, b)
		}
	}

	// And the winner within the preferred class is still the canonical minimum.
	if got := forward[selectPath(forward, true)].address.String(); got != "10.0.0.2:5432" {
		t.Errorf("selected %s, want the canonical minimum of the auth-required class", got)
	}
}

// TestTheOtherClassIsUsedOnlyWhenThePreferredOneIsEmpty pins the fallback edge.
//
// It is a class fallback at selection time, not a retry: still exactly one path
// is continued, and still at most one credential is ever presented.
func TestTheOtherClassIsUsedOnlyWhenThePreferredOneIsEmpty(t *testing.T) {
	onlyTrust := mixedSet(t, map[string]bool{"10.0.0.1:5432": false, "10.0.0.2:5432": false})
	if got := selectPath(onlyTrust, true); got == -1 {
		t.Fatal("a credentialed run found no path at all when only trust paths exist")
	} else if onlyTrust[got].address.String() != "10.0.0.1:5432" {
		t.Errorf("selected %s, want the canonical minimum", onlyTrust[got].address)
	}

	onlyAuth := mixedSet(t, map[string]bool{"10.0.0.1:5432": true, "10.0.0.2:5432": true})
	if got := selectPath(onlyAuth, false); got == -1 {
		t.Fatal("a credential-free run found no path at all when only auth paths exist")
	} else if onlyAuth[got].address.String() != "10.0.0.1:5432" {
		t.Errorf("selected %s, want the canonical minimum", onlyAuth[got].address)
	}
}
