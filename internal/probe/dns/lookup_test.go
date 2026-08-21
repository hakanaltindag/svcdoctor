package dns

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"

	"github.com/hakanaltindag/svcdoctor/internal/probe"
)

// fakeResolver is the whole reason Resolver exists. Every test here is hermetic:
// nothing resolves a real name, so no test depends on the network, on this
// machine's resolver configuration, or on a zone somebody else controls.
type fakeResolver struct {
	addrs    []netip.Addr
	err      error
	gotHost  string
	callHost bool
}

func (f *fakeResolver) LookupAddresses(_ context.Context, host string) ([]netip.Addr, error) {
	f.gotHost = host
	f.callHost = true
	return f.addrs, f.err
}

func addrs(t *testing.T, values ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			t.Fatalf("netip.ParseAddr(%q): %v", v, err)
		}
		out = append(out, addr)
	}
	return out
}

func lookup(t *testing.T, r Resolver, host string) domain.Evidence {
	t.Helper()
	e, err := Lookup(context.Background(), r, host, probe.SweepScope{})
	if err != nil {
		t.Fatalf("Lookup(%q): unexpected error: %v", host, err)
	}
	return e
}

func answersOf(t *testing.T, e domain.Evidence) []string {
	t.Helper()
	v, ok := e.Attribute(AttrAnswers)
	if !ok {
		return nil
	}
	list, ok := v.HostList()
	if !ok {
		t.Fatalf("attribute %s has kind %s, want hostList", AttrAnswers, v.Kind())
	}
	return list
}

// --- success and canonical answers ---------------------------------------

func TestLookupCanonicalizesAnswers(t *testing.T) {
	tests := []struct {
		name     string
		resolved []string
		want     []string
	}{
		{"single ipv4", []string{"10.0.0.1"}, []string{"10.0.0.1"}},
		{"single ipv6", []string{"2001:db8::1"}, []string{"2001:db8::1"}},
		{
			"mixed families are both kept",
			[]string{"2001:db8::1", "10.0.0.1"},
			[]string{"10.0.0.1", "2001:db8::1"},
		},
		{
			"multiple addresses are sorted",
			[]string{"10.0.0.3", "10.0.0.1", "10.0.0.2"},
			[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			"duplicates are removed",
			[]string{"10.0.0.1", "10.0.0.1", "2001:db8::1", "2001:db8::1"},
			[]string{"10.0.0.1", "2001:db8::1"},
		},
		{
			"ipv4-mapped ipv6 is unmapped and deduplicated against its ipv4 form",
			[]string{"::ffff:10.0.0.1", "10.0.0.1"},
			[]string{"10.0.0.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := lookup(t, &fakeResolver{addrs: addrs(t, tt.resolved...)}, "host.internal")

			got := answersOf(t, e)
			if len(got) != len(tt.want) {
				t.Fatalf("answers = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("answers = %v, want %v", got, tt.want)
				}
			}
			if e.State() != domain.StatePass {
				t.Errorf("state = %s, want PASS", e.State())
			}
		})
	}
}

// TestAnswersAreBareAddresses guards the security contract of the attribute
// shape. Structural redaction recognizes an identifying attribute value only
// when it parses as an address or a host:port reference, so an entry that is
// anything else would survive into a shareable report.
func TestAnswersAreBareAddresses(t *testing.T) {
	e := lookup(t, &fakeResolver{addrs: addrs(t, "10.0.0.1", "2001:db8::1")}, "host.internal")

	for _, answer := range answersOf(t, e) {
		if _, err := netip.ParseAddr(answer); err != nil {
			t.Errorf("answer %q does not parse as an address: %v", answer, err)
		}
	}
}

func TestLookupEvidenceContract(t *testing.T) {
	before := time.Now()
	e := lookup(t, &fakeResolver{addrs: addrs(t, "10.0.0.1")}, "primary.internal")

	if got, want := e.ID(), domain.EvidenceID("dns.lookup/primary.internal"); got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
	if got, want := e.Layer(), domain.LayerDNS; got != want {
		t.Errorf("layer = %s, want %s", got, want)
	}
	if got, want := e.Step(), StepLookup; got != want {
		t.Errorf("step = %s, want %s", got, want)
	}
	if got, want := e.Subject().Kind(), domain.SubjectKindEndpoint; got != want {
		t.Errorf("subject kind = %s, want %s", got, want)
	}
	if got, want := e.Subject().Ref(), "primary.internal"; got != want {
		t.Errorf("subject ref = %q, want %q", got, want)
	}
	if got, want := e.FailureClass(), domain.FailureNone; got != want {
		t.Errorf("failure class = %s, want %s", got, want)
	}
	if got, want := e.AttributeCount(), 1; got != want {
		t.Errorf("attribute count = %d, want %d", got, want)
	}
	if e.StartedAt().IsZero() {
		t.Error("startedAt is zero")
	}
	if e.StartedAt().Before(before.UTC().Add(-time.Second)) {
		t.Errorf("startedAt = %s, want at or after %s", e.StartedAt(), before)
	}
	if e.StartedAt().Location() != time.UTC {
		t.Errorf("startedAt location = %s, want UTC", e.StartedAt().Location())
	}
	if e.Duration() < 0 {
		t.Errorf("duration = %s, want non-negative", e.Duration())
	}
}

// TestLookupQueriesTheNameVerbatim proves the probe performs no normalization of
// its own. Lowercasing or trailing-dot handling would change the question that
// was asked, and evidence must record the question actually asked.
func TestLookupQueriesTheNameVerbatim(t *testing.T) {
	const host = "Primary.Internal."

	r := &fakeResolver{addrs: addrs(t, "10.0.0.1")}
	e := lookup(t, r, host)

	if r.gotHost != host {
		t.Errorf("resolver received %q, want %q", r.gotHost, host)
	}
	if got := e.Subject().Ref(); got != host {
		t.Errorf("subject ref = %q, want %q", got, host)
	}
}

func TestEvidenceIDIsDerivedAndStable(t *testing.T) {
	first := lookup(t, &fakeResolver{addrs: addrs(t, "10.0.0.1")}, "primary.internal")
	second := lookup(t, &fakeResolver{addrs: addrs(t, "10.0.0.9")}, "primary.internal")
	other := lookup(t, &fakeResolver{addrs: addrs(t, "10.0.0.1")}, "other.internal")

	if first.ID() != second.ID() {
		t.Errorf("same step and host produced %q then %q", first.ID(), second.ID())
	}
	if first.ID() == other.ID() {
		t.Errorf("different hosts share the identifier %q", first.ID())
	}
	if !strings.HasPrefix(first.ID().String(), StepLookup.String()) {
		t.Errorf("id %q does not start with the step %q", first.ID(), StepLookup)
	}
}

// --- classification -------------------------------------------------------

func TestLookupClassification(t *testing.T) {
	tests := []struct {
		name         string
		resolved     []string
		err          error
		wantState    domain.State
		wantFailure  domain.FailureClass
		wantAnswerNo bool
	}{
		{
			name:      "addresses returned",
			resolved:  []string{"10.0.0.1"},
			wantState: domain.StatePass, wantFailure: domain.FailureNone,
		},
		{
			// A resolver that distinguishes NODATA reports it this way: the
			// lookup succeeded and the answer set is empty.
			name:      "empty answer without error",
			wantState: domain.StateFail, wantFailure: domain.FailureDNSNoAddress,
			wantAnswerNo: true,
		},
		{
			// The standard library sets IsNotFound for both NXDOMAIN and
			// NODATA, so this is deliberately not classified as DNS_NXDOMAIN.
			// DNS_NO_ADDRESS claims only that the lookup yielded no usable
			// address, which is true either way.
			name:      "resolver reports not found",
			err:       &net.DNSError{Err: "no such host", Name: "absent.internal", IsNotFound: true},
			wantState: domain.StateFail, wantFailure: domain.FailureDNSNoAddress,
			wantAnswerNo: true,
		},
		{
			name:      "resolver reports a timeout",
			err:       &net.DNSError{Err: "i/o timeout", Name: "slow.internal", IsTimeout: true},
			wantState: domain.StateFail, wantFailure: domain.FailureDNSTimeout,
			wantAnswerNo: true,
		},
		{
			name:      "resolver reports a temporary failure",
			err:       &net.DNSError{Err: "server misbehaving", Name: "sick.internal", IsTemporary: true},
			wantState: domain.StateFail, wantFailure: domain.FailureDNSResolverFailure,
			wantAnswerNo: true,
		},
		{
			name:      "resolver returns an error svcdoctor cannot classify",
			err:       errors.New("resolver exploded"),
			wantState: domain.StateFail, wantFailure: domain.FailureDNSResolverFailure,
			wantAnswerNo: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := lookup(t, &fakeResolver{addrs: addrs(t, tt.resolved...), err: tt.err}, "host.internal")

			if e.State() != tt.wantState {
				t.Errorf("state = %s, want %s", e.State(), tt.wantState)
			}
			if e.FailureClass() != tt.wantFailure {
				t.Errorf("failure class = %s, want %s", e.FailureClass(), tt.wantFailure)
			}
			if tt.wantAnswerNo && e.AttributeCount() != 0 {
				t.Errorf("attribute count = %d, want 0 when nothing resolved", e.AttributeCount())
			}
		})
	}
}

// TestNXDomainStaysReserved enforces the boundary between the two not-found
// classes. DNS_NXDOMAIN is the stronger claim and requires a resolver that
// evidences non-existence distinctly; nothing the standard library reports
// qualifies, so this probe must never produce it.
func TestNXDomainStaysReserved(t *testing.T) {
	results := []struct {
		addrs []netip.Addr
		err   error
	}{
		{err: &net.DNSError{Err: "no such host", Name: "absent.internal", IsNotFound: true}},
		{err: &net.DNSError{Err: "no such host", Name: "nodata.internal", IsNotFound: true, IsTemporary: true}},
		{err: &net.DNSError{Err: "server misbehaving", Name: "sick.internal", IsTemporary: true}},
		{err: &net.DNSError{Err: "i/o timeout", Name: "slow.internal", IsTimeout: true}},
		{err: errors.New("resolver exploded")},
		{},
		{addrs: []netip.Addr{{}}},
	}

	for _, result := range results {
		e := lookup(t, &fakeResolver{addrs: result.addrs, err: result.err}, "host.internal")
		if e.FailureClass() == domain.FailureDNSNXDomain {
			t.Errorf("resolver result %+v produced DNS_NXDOMAIN, which needs evidence of non-existence", result)
		}
	}
}

// TestOnlyInvalidAddressesCountAsNoAddress covers a resolver that answers with
// values the probe cannot use. Dropping them silently and reporting PASS would
// claim a resolution that produced nothing connectable.
func TestOnlyInvalidAddressesCountAsNoAddress(t *testing.T) {
	e := lookup(t, &fakeResolver{addrs: []netip.Addr{{}}}, "host.internal")

	if e.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", e.State())
	}
	if e.FailureClass() != domain.FailureDNSNoAddress {
		t.Errorf("failure class = %s, want DNS_NO_ADDRESS", e.FailureClass())
	}
}

// --- local budget versus remote failure -----------------------------------

// TestCallerDeadlineIsNotARemoteFailure is the single most important test in
// this package. The standard library reports a caller deadline as a
// *net.DNSError with IsTimeout set, which does not wrap context.DeadlineExceeded
// and is indistinguishable from a resolver that timed out. Trusting it would
// turn svcdoctor's own budget expiring into a claim about the target.
func TestCallerDeadlineIsNotARemoteFailure(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	r := &fakeResolver{err: &net.DNSError{Err: "i/o timeout", Name: "slow.internal", IsTimeout: true}}
	e, err := Lookup(ctx, r, "slow.internal", probe.SweepScope{})
	if err != nil {
		t.Fatalf("Lookup: unexpected error: %v", err)
	}

	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN: a local deadline proves nothing about the target", e.State())
	}
	if e.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("failure class = %s, want EXEC_LOCAL_TIMEOUT", e.FailureClass())
	}
}

func TestResolverReportedDeadlineIsAlsoLocal(t *testing.T) {
	r := &fakeResolver{err: context.DeadlineExceeded}
	e := lookup(t, r, "slow.internal")

	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", e.State())
	}
	if e.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("failure class = %s, want EXEC_LOCAL_TIMEOUT", e.FailureClass())
	}
}

func TestCancellationIsNotARemoteFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := &fakeResolver{err: &net.DNSError{Err: "operation was canceled", Name: "host.internal"}}
	e, err := Lookup(ctx, r, "host.internal", probe.SweepScope{})
	if err != nil {
		t.Fatalf("Lookup: unexpected error: %v", err)
	}

	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", e.State())
	}
	if e.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("failure class = %s, want EXEC_CANCELLED", e.FailureClass())
	}
}

func TestResolverReportedCancellationIsRecordedAsCancelled(t *testing.T) {
	e := lookup(t, &fakeResolver{err: context.Canceled}, "host.internal")

	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", e.State())
	}
	if e.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("failure class = %s, want EXEC_CANCELLED", e.FailureClass())
	}
}

// TestCompletedLookupSurvivesLaterContextExpiry pins the other half of the
// ordering rule. A lookup that answered is a measurement that happened; a
// deadline expiring immediately afterwards must not retract it, or a run near
// its budget would randomly report UNKNOWN for facts it actually collected.
func TestCompletedLookupSurvivesLaterContextExpiry(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	e, err := Lookup(ctx, &fakeResolver{addrs: addrs(t, "10.0.0.1")}, "host.internal", probe.SweepScope{})
	if err != nil {
		t.Fatalf("Lookup: unexpected error: %v", err)
	}

	if e.State() != domain.StatePass {
		t.Errorf("state = %s, want PASS", e.State())
	}
	if e.FailureClass() != domain.FailureNone {
		t.Errorf("failure class = %s, want NONE", e.FailureClass())
	}
}

// --- input validation -----------------------------------------------------

func TestLookupRejectsUnusableInput(t *testing.T) {
	hosts := map[string]string{
		"empty":               "",
		"leading whitespace":  " host.internal",
		"trailing whitespace": "host.internal ",
		"inner whitespace":    "host internal",
		"control character":   "host.internal\n",
	}

	for name, host := range hosts {
		t.Run(name, func(t *testing.T) {
			e, err := Lookup(context.Background(), &fakeResolver{}, host, probe.SweepScope{})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if !e.IsZero() {
				t.Error("evidence was produced for unusable input")
			}
		})
	}
}

// TestIdentifierSeparatorDoesNotRestrictInput pins the rule that a bookkeeping
// choice may not narrow what svcdoctor will look at. Phase 2.1 refused a host
// containing the identifier separator; the encoding escapes it instead, so the
// query still happens and the identifier stays unambiguous.
//
// A name with a slash is not resolvable, but this probe deliberately enforces no
// hostname grammar: it asks the resolver what the caller asked about and records
// the answer.
func TestIdentifierSeparatorDoesNotRestrictInput(t *testing.T) {
	const host = "weird/name.internal"

	r := &fakeResolver{addrs: addrs(t, "10.0.0.1")}
	e := lookup(t, r, host)

	if r.gotHost != host {
		t.Errorf("resolver received %q, want %q", r.gotHost, host)
	}
	if got, want := e.Subject().Ref(), host; got != want {
		t.Errorf("subject ref = %q, want %q", got, want)
	}
	if got, want := e.ID(), domain.EvidenceID("dns.lookup/weird%2Fname.internal"); got != want {
		t.Errorf("id = %q, want %q", got, want)
	}

	// The escape is what keeps the encoding injective: a host literally named
	// with the escape sequence must not collide with the one containing a slash.
	escaped := lookup(t, &fakeResolver{addrs: addrs(t, "10.0.0.1")}, "weird%2Fname.internal")
	if escaped.ID() == e.ID() {
		t.Errorf("hosts %q and %q share the identifier %q", host, "weird%2Fname.internal", e.ID())
	}
}

func TestLookupRejectsNilResolver(t *testing.T) {
	e, err := Lookup(context.Background(), nil, "host.internal", probe.SweepScope{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if !e.IsZero() {
		t.Error("evidence was produced without a resolver")
	}
}

//nolint:staticcheck // passing a nil context is exactly what this guard is for.
func TestLookupRejectsNilContext(t *testing.T) {
	e, err := Lookup(nil, &fakeResolver{}, "host.internal", probe.SweepScope{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if !e.IsZero() {
		t.Error("evidence was produced without a context")
	}
}

func TestInvalidInputDoesNotReachTheResolver(t *testing.T) {
	r := &fakeResolver{}
	if _, err := Lookup(context.Background(), r, "", probe.SweepScope{}); err == nil {
		t.Fatal("expected an error for an empty host")
	}
	if r.callHost {
		t.Error("the resolver was called with input the probe should have rejected")
	}
}

// --- determinism ----------------------------------------------------------

// canonicalWithoutTiming returns the evidence's canonical JSON with the two
// per-run fields removed. Everything that remains must be identical for the same
// facts, whatever order a resolver happened to answer in.
func canonicalWithoutTiming(t *testing.T, e domain.Evidence) string {
	t.Helper()

	encoded, err := e.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	delete(fields, "startedAt")
	delete(fields, "duration")

	stable, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(stable)
}

func TestCanonicalEvidenceIsIndependentOfResolverOrder(t *testing.T) {
	forward := lookup(t,
		&fakeResolver{addrs: addrs(t, "10.0.0.1", "10.0.0.2", "2001:db8::1")}, "host.internal")
	shuffled := lookup(t,
		&fakeResolver{addrs: addrs(t, "2001:db8::1", "10.0.0.2", "10.0.0.1")}, "host.internal")

	if got, want := canonicalWithoutTiming(t, shuffled), canonicalWithoutTiming(t, forward); got != want {
		t.Errorf("resolver order changed the canonical evidence:\n got %s\nwant %s", got, want)
	}
}

// --- no raw runtime values ------------------------------------------------

// TestResolverErrorTextNeverReachesEvidence guards ADR 0010 at the place it is
// easiest to breach. A resolver error can name the resolver's own address, a
// search domain or the queried host, in prose structural redaction cannot
// recognize, so none of it may be recorded.
func TestResolverErrorTextNeverReachesEvidence(t *testing.T) {
	const canary = "resolver-canary-10.53.0.1"

	e := lookup(t, &fakeResolver{
		err: &net.DNSError{Err: canary, Name: canary, Server: canary, IsTemporary: true},
	}, "host.internal")

	encoded, err := e.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if strings.Contains(string(encoded), canary) {
		t.Errorf("canonical evidence contains resolver error text: %s", encoded)
	}
	if strings.Contains(e.String(), canary) {
		t.Errorf("evidence rendering contains resolver error text: %s", e.String())
	}
}

// TestEvidenceHoldsOnlyClosedAttributeKinds is the structural half of the same
// guarantee: a raw runtime object cannot be recorded, because every attribute
// value belongs to the closed union.
func TestEvidenceHoldsOnlyClosedAttributeKinds(t *testing.T) {
	e := lookup(t, &fakeResolver{addrs: addrs(t, "10.0.0.1")}, "host.internal")

	for key, value := range e.Attributes() {
		if !value.Valid() {
			t.Errorf("attribute %s holds an invalid value", key)
		}
		if value.Kind() != domain.AttrKindHostList {
			t.Errorf("attribute %s has kind %s, want hostList", key, value.Kind())
		}
	}
}
