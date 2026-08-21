package tcp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// fakeDialer is why Dialer exists. Every test here is hermetic: nothing dials a
// real service, so no test depends on the network or on a host somebody else
// controls.
type fakeDialer struct {
	conn    net.Conn
	err     error
	gotAddr netip.AddrPort
	calls   int
}

func (d *fakeDialer) DialTCP(_ context.Context, addr netip.AddrPort) (net.Conn, error) {
	d.calls++
	d.gotAddr = addr
	return d.conn, d.err
}

// fakeConn is one end of an in-memory pipe that counts its own closes. Counting
// is what makes the ownership tests assertions rather than hopes.
type fakeConn struct {
	net.Conn
	closes int
}

func (c *fakeConn) Close() error {
	c.closes++
	return c.Conn.Close()
}

// newFakeConn returns a live connection whose peer end is cleaned up with the
// test. It is a real net.Conn, so a caller that takes ownership can actually use
// it, which is what proves the transfer is worth something.
func newFakeConn(t *testing.T) *fakeConn {
	t.Helper()

	client, _ := pipePair(t)
	return client
}

// pipePair returns both ends, for the tests that need to send bytes over a
// transferred connection rather than only count closes.
func pipePair(t *testing.T) (client *fakeConn, server net.Conn) {
	t.Helper()

	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	return &fakeConn{Conn: local}, remote
}

func addrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()

	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("netip.ParseAddrPort(%q): %v", s, err)
	}
	return addr
}

const testEndpoint = "primary.internal:9092"

func connect(t *testing.T, d Dialer, addr netip.AddrPort) *Result {
	t.Helper()

	r, err := Connect(context.Background(), d, testEndpoint, addr)
	if err != nil {
		t.Fatalf("Connect: unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// dialError builds the error shape the standard library actually returns, so
// classification is tested against reality rather than against a convenient
// stand-in.
func dialError(addr string, err error) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP(addr), Port: 9092},
		Err:  os.NewSyscallError("connect", err),
	}
}

// --- success --------------------------------------------------------------

func TestConnectSuccess(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		wantSubject string
	}{
		{"ipv4", "10.0.0.1:9092", "10.0.0.1:9092"},
		{"ipv6", "[2001:db8::1]:9092", "[2001:db8::1]:9092"},
		{"ipv4-mapped ipv6 is unmapped", "[::ffff:10.0.0.1]:9092", "10.0.0.1:9092"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn(t)
			r := connect(t, &fakeDialer{conn: conn}, addrPort(t, tt.addr))

			e := r.Evidence()
			if e.State() != domain.StatePass {
				t.Errorf("state = %s, want PASS", e.State())
			}
			if e.FailureClass() != domain.FailureNone {
				t.Errorf("failure class = %s, want NONE", e.FailureClass())
			}
			if got := e.Subject().Ref(); got != tt.wantSubject {
				t.Errorf("subject ref = %q, want %q", got, tt.wantSubject)
			}
			if got := e.Subject().Kind(); got != domain.SubjectKindEndpoint {
				t.Errorf("subject kind = %s, want ENDPOINT", got)
			}
			if !r.Connected() {
				t.Error("a successful attempt has no connection to transfer")
			}
		})
	}
}

func TestConnectEvidenceContract(t *testing.T) {
	before := time.Now()
	conn := newFakeConn(t)
	r := connect(t, &fakeDialer{conn: conn}, addrPort(t, "10.0.0.1:9092"))
	e := r.Evidence()

	if got, want := e.ID(), domain.EvidenceID("tcp.connect/primary.internal:9092/10.0.0.1"); got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
	if got, want := e.Layer(), domain.LayerTCP; got != want {
		t.Errorf("layer = %s, want %s", got, want)
	}
	if got, want := e.Step(), StepConnect; got != want {
		t.Errorf("step = %s, want %s", got, want)
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

// TestConnectRecordsNoAttributes pins the decision that this probe adds none.
// A peer-address attribute would restate the subject, and a family attribute
// would restate the address. Duration is already a field.
func TestConnectRecordsNoAttributes(t *testing.T) {
	conn := newFakeConn(t)
	r := connect(t, &fakeDialer{conn: conn}, addrPort(t, "10.0.0.1:9092"))

	if got := r.Evidence().AttributeCount(); got != 0 {
		t.Errorf("attribute count = %d, want 0: %v", got, r.Evidence().Attributes())
	}
}

// TestConnectDialsTheGivenAddressOnly proves the probe cannot resolve. The
// dialer receives the exact address it was given, and the seam's type makes a
// hostname unrepresentable.
func TestConnectDialsTheGivenAddressOnly(t *testing.T) {
	d := &fakeDialer{conn: newFakeConn(t)}
	addr := addrPort(t, "10.0.0.7:9092")

	connect(t, d, addr)

	if d.calls != 1 {
		t.Errorf("dial calls = %d, want 1", d.calls)
	}
	if d.gotAddr != addr {
		t.Errorf("dialed %s, want %s", d.gotAddr, addr)
	}
}

// --- failure classification -----------------------------------------------

func TestConnectClassification(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantState   domain.State
		wantFailure domain.FailureClass
	}{
		{
			name: "connection refused", err: dialError("10.0.0.1", syscall.ECONNREFUSED),
			wantState: domain.StateFail, wantFailure: domain.FailureTCPConnectionRefused,
		},
		{
			name: "connection reset", err: dialError("10.0.0.1", syscall.ECONNRESET),
			wantState: domain.StateFail, wantFailure: domain.FailureTCPConnectionReset,
		},
		{
			name: "network unreachable", err: dialError("10.0.0.1", syscall.ENETUNREACH),
			wantState: domain.StateFail, wantFailure: domain.FailureTCPNetworkUnreachable,
		},
		{
			name: "host unreachable", err: dialError("10.0.0.1", syscall.EHOSTUNREACH),
			wantState: domain.StateFail, wantFailure: domain.FailureTCPHostUnreachable,
		},
		{
			// The kernel reporting an unanswered SYN is evidence about the
			// network, unlike a deadline svcdoctor imposed.
			name: "network stack timeout", err: dialError("10.0.0.1", syscall.ETIMEDOUT),
			wantState: domain.StateFail, wantFailure: domain.FailureTCPConnectionTimeout,
		},
		{
			name: "unclassifiable dial failure", err: errors.New("dial failed somehow"),
			wantState: domain.StateFail, wantFailure: domain.FailureTCPConnectionFailed,
		},
		{
			name: "error number svcdoctor does not map", err: dialError("10.0.0.1", syscall.EACCES),
			wantState: domain.StateFail, wantFailure: domain.FailureTCPConnectionFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := connect(t, &fakeDialer{err: tt.err}, addrPort(t, "10.0.0.1:9092"))
			e := r.Evidence()

			if e.State() != tt.wantState {
				t.Errorf("state = %s, want %s", e.State(), tt.wantState)
			}
			if e.FailureClass() != tt.wantFailure {
				t.Errorf("failure class = %s, want %s", e.FailureClass(), tt.wantFailure)
			}
			if r.Connected() {
				t.Error("a failed attempt reports a connection to transfer")
			}
		})
	}
}

// TestNetworkStackTimeoutOutranksTheGenericTimeoutTest guards the ordering that
// makes the previous table honest. A *net.OpError wrapping ETIMEDOUT also
// reports Timeout() == true, so a probe that tested for a timeout before
// checking the error number would file every kernel timeout as a local budget
// expiry and lose a real network fact.
func TestNetworkStackTimeoutOutranksTheGenericTimeoutTest(t *testing.T) {
	err := dialError("10.0.0.1", syscall.ETIMEDOUT)

	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatal("precondition failed: an ETIMEDOUT dial error should also report Timeout()")
	}

	r := connect(t, &fakeDialer{err: err}, addrPort(t, "10.0.0.1:9092"))

	if got := r.Evidence().FailureClass(); got != domain.FailureTCPConnectionTimeout {
		t.Errorf("failure class = %s, want TCP_CONNECTION_TIMEOUT", got)
	}
	if got := r.Evidence().State(); got != domain.StateFail {
		t.Errorf("state = %s, want FAIL", got)
	}
}

// TestUnattributableTimeoutIsLocal covers a dialer that imposed a deadline of
// its own. Nothing identifies it as the network's, so svcdoctor takes the blame
// rather than making a claim about the peer.
func TestUnattributableTimeoutIsLocal(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}

	r := connect(t, &fakeDialer{err: err}, addrPort(t, "10.0.0.1:9092"))
	e := r.Evidence()

	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", e.State())
	}
	if e.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("failure class = %s, want EXEC_LOCAL_TIMEOUT", e.FailureClass())
	}
}

// TestDialerReportingNeitherOutcomeClaimsNothing covers a defective dialer. An
// attempt that returned no connection and no error taught svcdoctor nothing, and
// inventing an outcome would be a claim about the target.
func TestDialerReportingNeitherOutcomeClaimsNothing(t *testing.T) {
	r := connect(t, &fakeDialer{}, addrPort(t, "10.0.0.1:9092"))
	e := r.Evidence()

	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", e.State())
	}
	if r.Connected() {
		t.Error("a dialer that returned nothing produced a connection")
	}
}

// --- local budget versus remote failure -----------------------------------

// TestCallerDeadlineIsNotARemoteFailure is the most important classification
// test in this package, and mirrors the DNS one. A dial cut short by the
// caller's deadline comes back as a *net.OpError that reports Timeout() and does
// not wrap context.DeadlineExceeded, so trusting the error alone would turn
// svcdoctor's own budget into a claim that the peer did not answer.
func TestCallerDeadlineIsNotARemoteFailure(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	d := &fakeDialer{err: &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}}
	r, err := Connect(ctx, d, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if err != nil {
		t.Fatalf("Connect: unexpected error: %v", err)
	}
	defer func() { _ = r.Close() }()

	e := r.Evidence()
	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN: a local deadline proves nothing about the target", e.State())
	}
	if e.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("failure class = %s, want EXEC_LOCAL_TIMEOUT", e.FailureClass())
	}
}

func TestCancellationIsNotARemoteFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := &fakeDialer{err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("operation was canceled")}}
	r, err := Connect(ctx, d, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if err != nil {
		t.Fatalf("Connect: unexpected error: %v", err)
	}
	defer func() { _ = r.Close() }()

	e := r.Evidence()
	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", e.State())
	}
	if e.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("failure class = %s, want EXEC_CANCELLED", e.FailureClass())
	}
}

func TestDialerReportedCancellationIsRecordedAsCancelled(t *testing.T) {
	r := connect(t, &fakeDialer{err: context.Canceled}, addrPort(t, "10.0.0.1:9092"))

	if got := r.Evidence().FailureClass(); got != domain.FailureExecCancelled {
		t.Errorf("failure class = %s, want EXEC_CANCELLED", got)
	}
}

// TestCompletedConnectionSurvivesLaterContextExpiry pins the other half of the
// ordering rule. A dial that returned a connection is a measurement that
// happened, and the connection is usable, so an expired context must not retract
// either.
func TestCompletedConnectionSurvivesLaterContextExpiry(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	conn := newFakeConn(t)
	r, err := Connect(ctx, &fakeDialer{conn: conn}, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if err != nil {
		t.Fatalf("Connect: unexpected error: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got := r.Evidence().State(); got != domain.StatePass {
		t.Errorf("state = %s, want PASS", got)
	}
	if !r.Connected() {
		t.Error("the established connection was discarded because the context had expired")
	}
}

// --- identifiers ----------------------------------------------------------

func TestEvidenceIDsDistinguishAddressesUnderOneEndpoint(t *testing.T) {
	addresses := []string{"10.0.0.1:9092", "10.0.0.2:9092", "[2001:db8::1]:9092"}

	seen := make(map[domain.EvidenceID]string, len(addresses))
	for _, address := range addresses {
		r := connect(t, &fakeDialer{conn: newFakeConn(t)}, addrPort(t, address))
		id := r.Evidence().ID()

		if previous, clash := seen[id]; clash {
			t.Errorf("addresses %s and %s share the identifier %q", previous, address, id)
		}
		seen[id] = address
	}
}

// TestEvidenceIDsDistinguishEndpointsSharingAnAddress is why the endpoint is in
// the identifier at all. Two names can resolve to one address, and those are two
// attempts: without the endpoint component the second would collide with the
// first and the graph would reject a legitimate node.
func TestEvidenceIDsDistinguishEndpointsSharingAnAddress(t *testing.T) {
	addr := addrPort(t, "10.0.0.1:9092")

	first, err := Connect(context.Background(), &fakeDialer{conn: newFakeConn(t)}, "one.internal:9092", addr)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = first.Close() }()

	second, err := Connect(context.Background(), &fakeDialer{conn: newFakeConn(t)}, "two.internal:9092", addr)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = second.Close() }()

	if first.Evidence().ID() == second.Evidence().ID() {
		t.Errorf("two endpoints sharing an address share the identifier %q", first.Evidence().ID())
	}
	if first.Evidence().Subject().Ref() != second.Evidence().Subject().Ref() {
		t.Error("the subject should be the address, which is the same for both")
	}
}

func TestEvidenceIDIsDeterministic(t *testing.T) {
	addr := addrPort(t, "10.0.0.1:9092")

	first := connect(t, &fakeDialer{conn: newFakeConn(t)}, addr)
	second := connect(t, &fakeDialer{err: errors.New("failed this time")}, addr)

	if first.Evidence().ID() != second.Evidence().ID() {
		t.Errorf("identifier changed with the outcome: %q then %q",
			first.Evidence().ID(), second.Evidence().ID())
	}
}

// TestIPv6IdentifiersAreUnambiguous checks the encoding against the address form
// most likely to break it. A colon-rich address needs no escaping, and the
// bracketed endpoint form stays readable.
func TestIPv6IdentifiersAreUnambiguous(t *testing.T) {
	r, err := Connect(context.Background(), &fakeDialer{conn: newFakeConn(t)},
		"[2001:db8::1]:9092", addrPort(t, "[2001:db8::1]:9092"))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = r.Close() }()

	want := domain.EvidenceID("tcp.connect/[2001:db8::1]:9092/2001:db8::1")
	if got := r.Evidence().ID(); got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
	if !r.Evidence().ID().Valid() {
		t.Error("identifier is not valid for the domain")
	}
}

// TestIdentifierSeparatorDoesNotRestrictInput pins the rule that bookkeeping may
// not narrow what svcdoctor will look at: an endpoint label containing the
// separator is encoded, not refused.
func TestIdentifierSeparatorDoesNotRestrictInput(t *testing.T) {
	r, err := Connect(context.Background(), &fakeDialer{conn: newFakeConn(t)},
		"weird/endpoint:9092", addrPort(t, "10.0.0.1:9092"))
	if err != nil {
		t.Fatalf("Connect: an endpoint containing the separator was refused: %v", err)
	}
	defer func() { _ = r.Close() }()

	want := domain.EvidenceID("tcp.connect/weird%2Fendpoint:9092/10.0.0.1")
	if got := r.Evidence().ID(); got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
}

// --- input validation -----------------------------------------------------

func TestConnectRejectsUnusableInput(t *testing.T) {
	tests := map[string]struct {
		endpoint string
		addr     netip.AddrPort
	}{
		"empty endpoint":      {"", addrPort(t, "10.0.0.1:9092")},
		"padded endpoint":     {" primary.internal:9092", addrPort(t, "10.0.0.1:9092")},
		"control character":   {"primary.internal:9092\n", addrPort(t, "10.0.0.1:9092")},
		"unspecified address": {testEndpoint, netip.AddrPort{}},
		"zero port":           {testEndpoint, netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 0)},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := &fakeDialer{conn: newFakeConn(t)}
			r, err := Connect(context.Background(), d, tt.endpoint, tt.addr)

			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if r != nil {
				t.Error("a result was produced for unusable input")
			}
			if d.calls != 0 {
				t.Error("the dialer was called with input the probe should have rejected")
			}
		})
	}
}

// TestEndpointLabelsAreNotOverRestricted is the counterpart to the test above.
// The endpoint is an opaque scope label this probe never connects to, so it must
// not impose a host:port grammar on callers.
func TestEndpointLabelsAreNotOverRestricted(t *testing.T) {
	endpoints := []string{
		"primary.internal:9092", "10.0.0.1:9092", "[2001:db8::1]:9092",
		"a label with spaces", "üñïçø∂é.internal:9092", "no-port-at-all",
	}

	for _, endpoint := range endpoints {
		r, err := Connect(context.Background(), &fakeDialer{conn: newFakeConn(t)},
			endpoint, addrPort(t, "10.0.0.1:9092"))
		if err != nil {
			t.Errorf("endpoint %q was refused: %v", endpoint, err)
			continue
		}
		_ = r.Close()
	}
}

func TestConnectRejectsNilDialer(t *testing.T) {
	r, err := Connect(context.Background(), nil, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if r != nil {
		t.Error("a result was produced without a dialer")
	}
}

//nolint:staticcheck // passing a nil context is exactly what this guard is for.
func TestConnectRejectsNilContext(t *testing.T) {
	r, err := Connect(nil, &fakeDialer{}, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if r != nil {
		t.Error("a result was produced without a context")
	}
}

// --- no raw runtime values ------------------------------------------------

// TestDialErrorTextNeverReachesEvidence guards ADR 0010 where it is easiest to
// breach. A dial error names the address, the syscall and sometimes the local
// interface, in prose structural redaction cannot recognize.
func TestDialErrorTextNeverReachesEvidence(t *testing.T) {
	const canary = "dial-canary-192.0.2.77"

	r := connect(t, &fakeDialer{err: &net.OpError{
		Op:  canary,
		Net: canary,
		Err: errors.New(canary),
	}}, addrPort(t, "10.0.0.1:9092"))

	encoded, err := r.Evidence().MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if strings.Contains(string(encoded), canary) {
		t.Errorf("canonical evidence contains dial error text: %s", encoded)
	}
	if strings.Contains(r.Evidence().String(), canary) {
		t.Errorf("evidence rendering contains dial error text: %s", r.Evidence().String())
	}
}

// TestEvidenceCannotCarryTheConnection is the structural half of the ownership
// rule. The connection stays live and usable while its evidence is serialized,
// which is only possible because the two are separate things.
func TestEvidenceCannotCarryTheConnection(t *testing.T) {
	conn := newFakeConn(t)
	r := connect(t, &fakeDialer{conn: conn}, addrPort(t, "10.0.0.1:9092"))

	encoded, err := r.Evidence().MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	// The field set is the proof: there is no field a connection could occupy.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	allowed := map[string]bool{
		"id": true, "subject": true, "layer": true, "step": true, "state": true,
		"failureClass": true, "attributes": true, "startedAt": true, "duration": true,
	}
	for field := range fields {
		if !allowed[field] {
			t.Errorf("canonical evidence carries an unexpected field %q: %s", field, encoded)
		}
	}
	if conn.closes != 0 {
		t.Error("serializing evidence disturbed the connection")
	}
	if !r.Connected() {
		t.Error("serializing evidence lost the connection")
	}
}
