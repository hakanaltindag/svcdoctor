package redaction

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 3.7.5: endpoint references whose port is not a usable port number.
//
// A cluster can report any host and any int32 port, so a subject reference is
// not always a well-formed endpoint. The redactor used to read "this port is out
// of range" as "this reference has no port", and then treated the entire display
// string as one hostname identity. Three things followed, and all three are
// pinned below: an invented pseudonym where no host existed, an IP address
// counted as a hostname, and a token with no identity meaning being searched for
// in every report.

// refReport builds a minimal report whose single node carries ref as its
// subject, plus a declared host attribute when one is supplied.
func refReport(t *testing.T, ref string, declaredHost string) domain.Report {
	t.Helper()

	attrs := map[domain.AttributeKey]domain.AttrValue{
		"probe.note": domain.StringAttr("TLSv1.3"),
	}
	if declaredHost != "" {
		attrs["probe.host"] = domain.HostAttr(declaredHost)
	}

	b := domain.NewGraphBuilder()
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           mustID(t, "probe.step/"+ref),
		Subject:      mustEndpointSubject(t, ref),
		Layer:        domain.LayerTCP,
		Step:         mustStep(t, "probe.step"),
		State:        domain.StateFail,
		FailureClass: domain.FailureTCPConnectionRefused,
		Attributes:   attrs,
		StartedAt:    testStart,
		Elapsed:      domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if err := b.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := b.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	run, err := domain.NewRunMetadata("0.0.0-dev", testStart, time.Second, "kafka")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("bootstrap.example.internal:9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage("runner.example.internal")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage, Graph: graph, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

func redactedRef(t *testing.T, report domain.Report) (string, domain.RedactionCounts) {
	t.Helper()
	out, err := Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	return out.Graph().Nodes()[0].Subject().Ref(), out.Security().Redactions()
}

// TestEndpointRefsWithUnusablePorts is the matrix.
//
// The port text is preserved in every row: a port is diagnostic information
// rather than an identifier, which is the rule the redactor already applied to
// well-formed references and now applies to these as well.
func TestEndpointRefsWithUnusablePorts(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		want      string
		wantHosts int
		wantIPs   int
	}{
		{
			// The reported bug. There is no host, so there is no identity, and
			// nothing may be invented in its place.
			name: "no host and an unusable port", ref: ":0", want: ":0",
			wantHosts: 2, wantIPs: 0,
		},
		{
			// Already correct before the fix, and pinned so it stays that way.
			name: "no host and a usable port", ref: ":9093", want: ":9093",
			wantHosts: 2, wantIPs: 0,
		},
		{
			// The host is real identity and is pseudonymized; the port survives
			// rather than being swallowed into the hostname.
			// host-002 because pseudonyms are numbered in sorted order and
			// the target's "bootstrap.example.internal" sorts first.
			name: "host with an unusable port", ref: "broker.example.internal:0",
			want: "host-002:0", wantHosts: 3, wantIPs: 0,
		},
		{
			name: "host with a negative port", ref: "broker.example.internal:-1",
			want: "host-002:-1", wantHosts: 3, wantIPs: 0,
		},
		{
			name: "host with an out-of-range port", ref: "broker.example.internal:70000",
			want: "host-002:70000", wantHosts: 3, wantIPs: 0,
		},
		{
			// An IPv6 literal is an address whatever its port says, so it is
			// pseudonymized and counted as one.
			name: "ipv6 literal with an unusable port", ref: "[2001:db8::1]:0",
			want: "ip-001:0", wantHosts: 2, wantIPs: 1,
		},
		{
			name: "ipv6 literal with a usable port", ref: "[2001:db8::1]:9093",
			want: "ip-001:9093", wantHosts: 2, wantIPs: 1,
		},
		{
			name: "ipv4 with an unusable port", ref: "10.20.30.40:0",
			want: "ip-001:0", wantHosts: 2, wantIPs: 1,
		},
		{
			name: "ordinary hostname endpoint", ref: "broker.example.internal:9092",
			want: "host-002:9092", wantHosts: 3, wantIPs: 0,
		},
		{
			name: "ordinary ipv4 endpoint", ref: "10.20.30.40:9092",
			want: "ip-001:9092", wantHosts: 2, wantIPs: 1,
		},
		{
			name: "bare ipv6 with no port at all", ref: "2001:db8::1",
			want: "ip-001", wantHosts: 2, wantIPs: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, counts := redactedRef(t, refReport(t, tc.ref, ""))
			if got != tc.want {
				t.Errorf("subject ref = %q, want %q", got, tc.want)
			}
			if counts.Hostname != tc.wantHosts {
				t.Errorf("hostname redactions = %d, want %d", counts.Hostname, tc.wantHosts)
			}
			if counts.IPAddress != tc.wantIPs {
				t.Errorf("ip redactions = %d, want %d", counts.IPAddress, tc.wantIPs)
			}
		})
	}
}

// TestNoHostIsInventedForAHostlessReference states the property on its own,
// because it is the one a reader of a shareable report depends on.
//
// If ":0" became "host-001:0" the report would claim the cluster named a host
// it never named, which is worse than leaking nothing: it is a fabricated fact
// in a document whose whole purpose is to be trustworthy after identity is gone.
func TestNoHostIsInventedForAHostlessReference(t *testing.T) {
	for _, ref := range []string{":0", ":9093", ":-1", ":70000"} {
		t.Run(ref, func(t *testing.T) {
			got, _ := redactedRef(t, refReport(t, ref, ""))
			if got != ref {
				t.Errorf("subject ref = %q, want %q: there is no host to replace", got, ref)
			}
			if strings.Contains(got, "host-") || strings.Contains(got, "ip-") {
				t.Errorf("subject ref = %q invents a pseudonym for a host that was never named", got)
			}
		})
	}
}

// TestOneHostGetsOnePseudonymAcrossRepresentations is the defect that made the
// counts wrong.
//
// The same host appears twice — once declared on an attribute and once inside a
// subject whose port is unusable. Before the fix the subject registered
// "broker.example.internal:0" as a separate hostname, so one host held two
// pseudonyms and the hostname count was inflated by one.
func TestOneHostGetsOnePseudonymAcrossRepresentations(t *testing.T) {
	const host = "broker.example.internal"

	out, err := Redact(refReport(t, host+":0", host))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	node := out.Graph().Nodes()[0]

	attr, ok := node.Attribute("probe.host")
	if !ok {
		t.Fatal("the declared host attribute is missing")
	}
	declared, _ := attr.Host()
	subject := node.Subject().Ref()

	if want := declared + ":0"; subject != want {
		t.Errorf("subject = %q and attribute = %q; one host must hold one pseudonym (want %q)",
			subject, declared, want)
	}
	if got := out.Security().Redactions().Hostname; got != 3 {
		t.Errorf("hostname redactions = %d, want 3 (target, vantage, broker)", got)
	}
}

// TestUnusablePortTextIsNotAnIdentity proves the residual scan no longer hunts
// for punctuation.
//
// ":0" occurs in the encoding of every report that has severity counts. Before
// the fix it was registered as a hostname, so the scan found it in `"info":0`
// and refused a report that had been transformed correctly.
func TestUnusablePortTextIsNotAnIdentity(t *testing.T) {
	out, err := Redact(refReport(t, ":0", ""))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !strings.Contains(string(encoded), `"info":0`) {
		t.Fatal("the fixture no longer contains the colliding text; this test would be vacuous")
	}
	if !strings.Contains(string(encoded), `":0"`) {
		t.Fatal("the subject no longer contains \":0\"; this test would be vacuous")
	}
}

// TestUndeclaredStringsStillNeedAUsablePort keeps the opportunistic safety net
// narrow.
//
// A plain string attribute was never declared to be identity, so it is only
// treated as an endpoint when it reads like one. Widening the syntactic split
// must not widen this: "cipher:aes" and "TLSv1.3" have to survive intact, or
// redaction starts corrupting diagnostic facts.
func TestUndeclaredStringsStillNeedAUsablePort(t *testing.T) {
	untouched := []string{"TLSv1.3", "cipher:aes", "NOERROR", "state:closed", "a:b"}

	b := domain.NewGraphBuilder()
	attrs := map[domain.AttributeKey]domain.AttrValue{}
	for i, s := range untouched {
		attrs[domain.AttributeKey("probe.note_"+string(rune('a'+i)))] = domain.StringAttr(s)
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: mustID(t, "probe.step/plain"), Subject: mustEndpointSubject(t, "host.example.internal:9092"),
		Layer: domain.LayerTCP, Step: mustStep(t, "probe.step"), State: domain.StatePass,
		Attributes: attrs, StartedAt: testStart, Elapsed: domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if err := b.AddEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	graph, err := b.Freeze()
	if err != nil {
		t.Fatal(err)
	}

	base := refReport(t, "host.example.internal:9092", "")
	local, err := domain.NewReport(domain.ReportInput{
		Run: base.Run(), Target: base.Target(), Vantage: base.Vantage(),
		Graph: graph, Security: base.Security(),
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	out, err := Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	node := out.Graph().Nodes()[0]
	for i, want := range untouched {
		key := domain.AttributeKey("probe.note_" + string(rune('a'+i)))
		value, ok := node.Attribute(key)
		if !ok {
			t.Fatalf("attribute %s is missing", key)
		}
		got, _ := value.Str()
		if got != want {
			t.Errorf("attribute %s = %q, want %q untouched", key, got, want)
		}
	}
}

// TestKnownLimitationIdentityTextOccurringInOtherReportText pins what Phase
// 3.7.5 did **not** fix, so that the boundary is visible and so that a future
// fix is noticed here.
//
// The residual scan asks "does this identity's text appear in any string the
// report contains?". After this phase it no longer searches numbers or
// punctuation, so `"info":0` and `-1` in an integer attribute are gone as
// collision sources. What remains is collision with other *strings*: the
// svcdoctor version, the service identifier, an attribute key, a pseudonym.
//
// So a host whose name is a substring of ordinary report text is still reported
// as having survived when it has not, and the run cannot produce a shareable
// report. It fails **closed**, which is the safe direction, and it is much
// narrower than the defect this phase fixed — that one broke every endpoint
// whose port was out of range, which a misconfigured cluster produces readily.
//
// No shape-based rule can settle it: "is this occurrence of `host` the hostname
// or part of the key `probe.host`?" is a question about provenance, not about
// text, and guessing would either miss leaks or keep failing valid reports.
// Settling it needs verification that checks identity-bearing surfaces
// structurally rather than searching the serialized document — recorded in
// docs/SECURITY.md and docs/BACKLOG.md.
//
// **Delete this test when that lands, and replace it with the positive cases.**
func TestKnownLimitationIdentityTextOccurringInOtherReportText(t *testing.T) {
	// Each of these collides with a string the report legitimately contains:
	// "kafka" with the service identifier, "dev" with the version, "host" with
	// an attribute key and with the host pseudonym, "0" with a timestamp.
	stillFails := []string{"kafka", "dev", "host", "ip", "evidence", "0"}

	for _, host := range stillFails {
		t.Run(host, func(t *testing.T) {
			if _, err := Redact(refReport(t, host+":9092", "")); err == nil {
				t.Errorf("redaction now succeeds for the host %q — the known limitation is "+
					"fixed, so delete this row and add a positive case", host)
			}
		})
	}

	// The control: an ordinary hostname, and one that merely shares a *suffix*
	// with report text, both redact cleanly. Without this the test above could
	// pass because redaction was broken for everything.
	for _, host := range []string{"broker.example.internal", "internal", "prod-1.corp"} {
		t.Run("clean/"+host, func(t *testing.T) {
			if _, err := Redact(refReport(t, host+":9092", "")); err != nil {
				t.Errorf("redaction failed for an ordinary hostname %q: %v", host, err)
			}
		})
	}
}
