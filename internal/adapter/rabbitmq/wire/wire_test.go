package wire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// --- fixtures ---------------------------------------------------------------

// scriptedConn is a deterministic in-memory peer.
//
// Reads come from a fixed script and writes land in a buffer, with no goroutine
// and no synchronization, so a test can assert on exactly what reached the peer
// without racing a drain loop. An exhausted script returns io.EOF, which is what
// a broker closing the socket looks like.
type scriptedConn struct {
	script *bytes.Reader
	sent   bytes.Buffer
}

func (c *scriptedConn) Read(b []byte) (int, error)  { return c.script.Read(b) }
func (c *scriptedConn) Write(b []byte) (int, error) { return c.sent.Write(b) }
func (c *scriptedConn) Close() error                { return nil }
func (c *scriptedConn) LocalAddr() net.Addr         { return dummyAddr{} }
func (c *scriptedConn) RemoteAddr() net.Addr        { return dummyAddr{} }
func (c *scriptedConn) SetDeadline(time.Time) error { return nil }

func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "scripted" }
func (dummyAddr) String() string  { return "scripted" }

// pipeConn gives a Conn a peer that replies from a script.
func pipeConn(t *testing.T, script []byte) (*Conn, *bytes.Buffer) {
	t.Helper()
	peer := &scriptedConn{script: bytes.NewReader(script)}
	return NewConn(peer, "/", "alice"), &peer.sent
}

// methodFrame builds an inbound frame the way a broker would.
func methodFrame(class, method uint16, fields []byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, class)
	body = binary.BigEndian.AppendUint16(body, method)
	body = append(body, fields...)

	out := []byte{frameTypeMethod}
	out = binary.BigEndian.AppendUint16(out, 0)
	//nolint:gosec // G115: test fixtures built from literals this file controls.
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	return append(out, frameEnd)
}

func tableEntryStr(key, value string) []byte {
	//nolint:gosec // G115: test fixtures built from literals this file controls.
	out := []byte{byte(len(key))}
	out = append(out, key...)
	out = append(out, 'S')
	//nolint:gosec // G115: test fixtures built from literals this file controls.
	out = binary.BigEndian.AppendUint32(out, uint32(len(value)))
	return append(out, value...)
}

// startFrame builds a Connection.Start with the given top-level properties.
func startFrame(props []byte, mechanisms string) []byte {
	fields := []byte{0, 9}
	//nolint:gosec // G115: test fixtures built from literals this file controls.
	fields = binary.BigEndian.AppendUint32(fields, uint32(len(props)))
	fields = append(fields, props...)
	//nolint:gosec // G115: test fixtures built from literals this file controls.
	fields = binary.BigEndian.AppendUint32(fields, uint32(len(mechanisms)))
	fields = append(fields, mechanisms...)
	fields = binary.BigEndian.AppendUint32(fields, uint32(len("en_US")))
	fields = append(fields, "en_US"...)
	return methodFrame(classConnection, inStart, fields)
}

func closeFrame(code uint16, text string, class, method uint16) []byte {
	fields := binary.BigEndian.AppendUint16(nil, code)
	//nolint:gosec // G115: test fixtures built from literals this file controls.
	fields = append(fields, byte(len(text)))
	fields = append(fields, text...)
	fields = binary.BigEndian.AppendUint16(fields, class)
	fields = binary.BigEndian.AppendUint16(fields, method)
	return methodFrame(classConnection, inClose, fields)
}

// --- the credential frame ---------------------------------------------------

// TestPlainResponseIsByteExact is ADR 0068 section 8's requirement.
//
// An off-by-one here writes the operator's password into the broker's log:
// rabbit_auth_mechanism_plain formats the *entire* response into an error when
// it cannot parse it, and that error reaches the broker log and the
// user_authentication_failure event. So the encoding is pinned literally rather
// than described.
func TestPlainResponseIsByteExact(t *testing.T) {
	c, sent := pipeConn(t, methodFrame(classConnection, inTune,
		[]byte{0x07, 0xFF, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3C}))

	secret := security.NewSecret("s3cr3t")
	if _, err := c.SendStartOk(context.Background(), 2*time.Second, "alice", secret); err != nil {
		t.Fatalf("SendStartOk: %v", err)
	}

	frame := sent.Bytes()
	want := append([]byte{0x00}, "alice"...)
	want = append(want, 0x00)
	want = append(want, "s3cr3t"...)

	idx := bytes.Index(frame, want)
	if idx < 0 {
		t.Fatalf("the PLAIN response is not on the wire in the frozen form %q", want)
	}

	// Exactly two NUL separators in the response region, and nothing after the
	// password: the longstr length must equal len(response) exactly.
	lenAt := idx - 4
	if lenAt < 0 {
		t.Fatal("the response has no length prefix")
	}
	declared := binary.BigEndian.Uint32(frame[lenAt : lenAt+4])
	if int(declared) != len(want) {
		t.Errorf("response longstr declares %d bytes, want %d — a trailing byte would "+
			"change which bytes the broker reads as the password", declared, len(want))
	}
	if got := bytes.Count(want, []byte{0x00}); got != 2 {
		t.Errorf("the PLAIN response carries %d NUL separators, want exactly 2", got)
	}
	if want[len(want)-1] == 0x00 {
		t.Error("the PLAIN response ends with a NUL")
	}
}

// TestNoCredentialAppearsInClientProperties proves the secret is confined to the
// SASL response and does not leak into the table beside it.
func TestNoCredentialAppearsInClientProperties(t *testing.T) {
	props := clientProperties()
	for _, canary := range []string{"s3cr3t", "alice", "password", "pass"} {
		if bytes.Contains(props, []byte(canary)) {
			t.Errorf("client-properties contains %q", canary)
		}
	}
}

// TestClientPropertiesAreAFixedLiteral pins the whole table.
//
// It is a literal so that the only variable bytes in a Start-Ok frame are the
// credential, which is what makes the byte-exact test above meaningful. A new
// capability added here fails this test before a reviewer sees it.
func TestClientPropertiesAreAFixedLiteral(t *testing.T) {
	props := clientProperties()

	for _, want := range []string{"product", "svcdoctor", "platform", "Go", "version",
		"capabilities", "authentication_failure_close"} {
		if !bytes.Contains(props, []byte(want)) {
			t.Errorf("client-properties is missing %q", want)
		}
	}

	// Exactly one capability. ADR 0068 section 3: connection.blocked changes
	// broker behaviour on a running connection, and BASIC has none.
	for _, forbidden := range []string{
		"connection.blocked", "consumer_cancel_notify", "publisher_confirms",
		"exchange_exchange_bindings", "basic.nack", "per_consumer_qos",
		"direct_reply_to", "consumer_priorities",
	} {
		if bytes.Contains(props, []byte(forbidden)) {
			t.Errorf("client-properties advertises %q, which BASIC does not need", forbidden)
		}
	}

	// Far below LavinMQ's measured 4096-byte Start-Ok ceiling.
	if len(props) > 512 {
		t.Errorf("client-properties is %d bytes; it is meant to be small enough that "+
			"a Start-Ok stays far below LavinMQ's measured 4096-byte ceiling", len(props))
	}
}

// TestStartOkRefusesAnEmptyCredential proves svcdoctor never sends an empty
// password, which an endpoint would count as an attempt.
func TestStartOkRefusesAnEmptyCredential(t *testing.T) {
	c, sent := pipeConn(t, nil)
	if _, err := c.SendStartOk(context.Background(), time.Second, "alice", security.Secret{}); err == nil {
		t.Fatal("an empty credential was accepted")
	}
	if sent.Len() != 0 {
		t.Errorf("%d bytes reached the peer for a refused credential", sent.Len())
	}
}

// TestStartOkRefusesNULInCredentialParts proves a NUL cannot silently change
// which bytes the broker reads as the password.
func TestStartOkRefusesNULInCredentialParts(t *testing.T) {
	secret := security.NewSecret("pw\x00extra")
	c, sent := pipeConn(t, nil)
	if _, err := c.SendStartOk(context.Background(), time.Second, "alice", secret); err == nil {
		t.Fatal("a password containing a NUL was accepted")
	}
	if sent.Len() != 0 {
		t.Errorf("%d bytes reached the peer for a refused credential", sent.Len())
	}
}

// --- close normalization ----------------------------------------------------

// TestNormalizeCloseMatchesEveryMeasuredText replays the exact strings Phase
// 8.0C captured from real brokers.
//
// The vhost and username are the ones those scenarios used, because
// construct-and-compare renders its candidates from svcdoctor's own inputs.
// TestTheRecognizedMechanismSetIsExactlyFrozen pins ADR 0067 §4.2.
//
// `knownMechanisms` is the closed set svcdoctor intersects the peer's advertised
// list against, and it is what makes the recorded observation svcdoctor's own
// constants rather than the peer's bytes. Widening it widens what a peer can put
// in a report — so the set is pinned by value, not merely by behaviour.
//
// Phase 8.2-R3 added this after a mutation that appended one token to the slice
// survived every other guard in the tree.
func TestTheRecognizedMechanismSetIsExactlyFrozen(t *testing.T) {
	want := []string{"PLAIN", "AMQPLAIN", "ANONYMOUS", "EXTERNAL", "RABBIT-CR-DEMO"}

	if len(knownMechanisms) != len(want) {
		t.Fatalf("knownMechanisms = %v, want exactly %v", knownMechanisms, want)
	}
	for i, name := range want {
		if knownMechanisms[i] != name {
			t.Errorf("knownMechanisms[%d] = %q, want %q", i, knownMechanisms[i], name)
		}
	}

	// Only PLAIN is ever selected; the rest exist so the observation can name
	// what was offered without echoing a peer's bytes (ADR 0068 §2).
	selectable := 0
	for _, name := range knownMechanisms {
		if name == "PLAIN" {
			selectable++
		}
	}
	if selectable != 1 {
		t.Errorf("PLAIN appears %d times in the recognized set, want 1", selectable)
	}
}

func TestNormalizeCloseMatchesEveryMeasuredText(t *testing.T) {
	const user = "labuser7814"

	tests := []struct {
		name  string
		code  uint16
		text  string
		vhost string
		want  CloseOutcome
	}{
		{"RabbitMQ vhost not found", 530,
			"NOT_ALLOWED - vhost vh-nope-80c not found", "vh-nope-80c", CloseVHostNotFound},
		{"RabbitMQ vhost denied", 530,
			"NOT_ALLOWED - access to vhost 'vh-denied' refused for user 'labuser7814'",
			"vh-denied", CloseVHostAccessRefused},
		{"RabbitMQ vhost connection limit", 530,
			"NOT_ALLOWED - access to vhost 'vh-ok' refused for user 'labuser7814': " +
				"connection limit (0) is reached", "vh-ok", CloseVHostConnectionLimit},
		{"RabbitMQ user connection limit", 530,
			"NOT_ALLOWED - connection refused for user 'labuser7814': " +
				"user connection limit (0) is reached", "vh-ok", CloseUserConnectionLimit},
		{"RabbitMQ node connection limit", 530,
			"NOT_ALLOWED - connection refused: node connection limit (0) is reached",
			"/", CloseNodeConnectionLimit},
		{"LavinMQ vhost not found", 530,
			"NOT_ALLOWED - vhost not found", "lmq-nope-80c", CloseVHostNotFound},
		{"LavinMQ vhost denied", 530,
			"NOT_ALLOWED - 'labuser7814' doesn't have access to 'lmq-denied'",
			"lmq-denied", CloseVHostAccessRefused},
		// Live-measured in Phase 8.2 against LavinMQ 2.3.0 under a vhost
		// max-connections of 0. Phase 8.0C could only derive this template from
		// LavinMQ's source; the fixture now exercises it, and the bytes matched.
		{"LavinMQ vhost connection limit", 530,
			"NOT_ALLOWED - access to vhost 'lmq-ok' refused: connection limit (0) is reached",
			"lmq-ok", CloseVHostConnectionLimit},
		{"authentication refusal carries no distinction", 403,
			"ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. " +
				"For details see the broker logfile.", "/", CloseUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeClose(tt.code, tt.text, tt.vhost, user); got != tt.want {
				t.Errorf("outcome = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestTruncationShortCircuitsClassification is the highest-value case Phase 8.0C
// measured.
//
// A 119-byte vhost and an 80-byte username under a real capacity ceiling
// produced exactly 255 bytes ending in three dots, with ": connection limit (0)
// is reached" entirely gone. A prefix matcher still matched the bare-denial
// template and reported an authorization denial for a capacity ceiling.
func TestTruncationShortCircuitsClassification(t *testing.T) {
	vhost := "vh-" + strings.Repeat("v", 116)
	user := "user-" + strings.Repeat("u", 75)

	full := "NOT_ALLOWED - access to vhost '" + vhost + "' refused for user '" + user +
		"': connection limit (0) is reached"
	if len(full) <= 255 {
		t.Fatalf("the fixture is not long enough to truncate: %d bytes", len(full))
	}
	truncated := full[:252] + "..."

	if got := normalizeClose(530, truncated, vhost, user); got != CloseUnspecifiedTruncated {
		t.Errorf("outcome = %s, want %s", got, CloseUnspecifiedTruncated)
	}

	// The hazard itself: a prefix matcher would still have matched.
	bare := "NOT_ALLOWED - access to vhost '" + vhost + "' refused for user '" + user + "'"
	if !strings.HasPrefix(truncated, bare[:200]) {
		t.Fatal("the fixture no longer reproduces the prefix-matcher hazard")
	}
}

// TestCraftedVhostCannotConfuseClassification is the second measured hazard.
//
// A vhost legally named `a': connection limit (5) is reached`, refused for lack
// of permission, made an infix matcher report a capacity ceiling. Rendering the
// candidate from svcdoctor's own input classifies it correctly, because the
// crafted bytes appear in the candidate too.
func TestCraftedVhostCannotConfuseClassification(t *testing.T) {
	const vhost = "a': connection limit (5) is reached"
	const user = "labuser7814"
	text := "NOT_ALLOWED - access to vhost '" + vhost + "' refused for user '" + user + "'"

	if got := normalizeClose(530, text, vhost, user); got != CloseVHostAccessRefused {
		t.Errorf("outcome = %s, want %s", got, CloseVHostAccessRefused)
	}

	// Non-vacuity: a naive infix matcher really would get this wrong.
	if !strings.Contains(text, "': connection limit (") {
		t.Fatal("the fixture no longer reproduces the infix-matcher hazard")
	}
}

// TestCraftedUsernameCannotConfuseClassification is the crafted-vhost hazard,
// mirrored onto the operand Phase 8.0C did not craft.
//
// A username is operator-supplied and RabbitMQ interpolates it into two
// different templates, so a name carrying a sentinel is the same attack from the
// other side. Construct-and-compare is immune for the same reason: the crafted
// bytes appear in svcdoctor's own candidate too.
func TestCraftedUsernameCannotConfuseClassification(t *testing.T) {
	// A username that ends the denial sentence early and appends a ceiling.
	const user = "bob': connection limit (5) is reached"
	const vhost = "vh-denied"
	text := "NOT_ALLOWED - access to vhost '" + vhost + "' refused for user '" + user + "'"

	if got := normalizeClose(530, text, vhost, user); got != CloseVHostAccessRefused {
		t.Errorf("outcome = %s, want %s; a capacity ceiling was reported for an "+
			"authorization denial", got, CloseVHostAccessRefused)
	}

	// Non-vacuity: a naive infix matcher really would get this wrong.
	if !strings.Contains(text, ": connection limit (") {
		t.Fatal("the fixture no longer reproduces the infix-matcher hazard")
	}

	// And the mirror case: a username carrying the user-limit sentinel must not
	// be classified as a user connection limit when the sentence is a denial.
	const sneaky = "carol': user connection limit (9) is reached"
	denial := "NOT_ALLOWED - access to vhost '" + vhost + "' refused for user '" + sneaky + "'"
	if got := normalizeClose(530, denial, vhost, sneaky); got != CloseVHostAccessRefused {
		t.Errorf("outcome = %s, want %s", got, CloseVHostAccessRefused)
	}
}

// TestBackendSuffixStillClassifiesAsDenial covers T3, the one prefix rule.
//
// An authorization backend may append arbitrary bytes. The extension only ever
// reaches a conclusion the bare template already supports, so allowing it adds
// no authority — and the appended bytes are still never extracted.
func TestBackendSuffixStillClassifiesAsDenial(t *testing.T) {
	const vhost, user = "vh-denied", "alice"
	text := "NOT_ALLOWED - access to vhost '" + vhost + "' refused for user '" + user +
		"' by backend rabbit_auth_backend_ldap: anything at all"

	if got := normalizeClose(530, text, vhost, user); got != CloseVHostAccessRefused {
		t.Errorf("outcome = %s, want %s", got, CloseVHostAccessRefused)
	}
}

// TestUnmatchedTextDegrades proves the default is the weakest true conclusion
// rather than a guess.
func TestUnmatchedTextDegrades(t *testing.T) {
	for _, text := range []string{
		"", "NOT_ALLOWED - something nobody has seen",
		"NOT_ALLOWED - vhost / not found extra",                          // near-miss: trailing bytes
		strings.Repeat("x", 300),                                         // above the shortstr maximum
		"NOT_ALLOWED - access to vhost 'other' refused for user 'alice'", // wrong vhost
	} {
		if got := normalizeClose(530, text, "/", "alice"); got != CloseUnspecified {
			t.Errorf("normalizeClose(%q) = %s, want %s", text, got, CloseUnspecified)
		}
	}
}

// TestDigitHoleIsFixedPositionAndBounded proves the limit templates cannot be
// satisfied by anything but digits at the exact position.
func TestDigitHoleIsFixedPositionAndBounded(t *testing.T) {
	base := "NOT_ALLOWED - connection refused: node connection limit ("
	for _, middle := range []string{
		"", "abc", "1a", " 1", "1 ", "-1", "+1", strings.Repeat("9", 21),
	} {
		text := base + middle + ") is reached"
		if got := normalizeClose(530, text, "/", "alice"); got == CloseNodeConnectionLimit {
			t.Errorf("middle %q was accepted as a digit hole", middle)
		}
	}
	if got := normalizeClose(530, base+"0) is reached", "/", "alice"); got != CloseNodeConnectionLimit {
		t.Errorf("a single digit was rejected: %s", got)
	}
	if got := normalizeClose(530, base+strings.Repeat("9", 20)+") is reached", "/", "alice"); got != CloseNodeConnectionLimit {
		t.Errorf("twenty digits were rejected: %s", got)
	}
}

// TestNoVHostDownNormalizationExists pins ADR 0069 section 6.2.
//
// 541 was source-proven and never live-measured, so no normalized outcome is
// authorized for it. It reaches the weakest true conclusion, and a VHOST_DOWN
// constant does not exist to be reached by accident.
func TestNoVHostDownNormalizationExists(t *testing.T) {
	text := "INTERNAL_ERROR - access to vhost '/' refused for user 'alice': vhost '/' is down"
	if got := normalizeClose(541, text, "/", "alice"); got != CloseUnspecified {
		t.Errorf("541 produced %s; ADR 0069 section 6.2 authorizes no measured "+
			"normalization for a condition that was never measured", got)
	}

	source := readSource(t, "close.go")
	if strings.Contains(source, "VHOST_DOWN") {
		t.Error("close.go declares a VHOST_DOWN outcome, which ADR 0069 section 6.2 forbids " +
			"until the condition is live-measured")
	}
}

// --- frame bounds -----------------------------------------------------------

func TestFrameSizeIsRefusedBeforeAllocation(t *testing.T) {
	// A four-gibibyte declaration, with no payload behind it at all.
	hdr := []byte{frameTypeMethod, 0, 0}
	hdr = binary.BigEndian.AppendUint32(hdr, 0xFFFFFFFF)

	r := newReader(bytes.NewReader(hdr))
	_, err := r.readFrame()
	if !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("err = %v, want ErrMalformedFrame", err)
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Errorf("the refusal does not name the ceiling: %v", err)
	}
}

func TestFrameRejectsMalformedShapes(t *testing.T) {
	good := methodFrame(classConnection, inOpenOk, nil)

	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"bad frame-end", append(append([]byte{}, good[:len(good)-1]...), 0x00), ErrMalformedFrame},
		{"truncated header", good[:3], ErrPeerClosed},
		{"truncated payload", good[:len(good)-2], ErrPeerClosed},
		{"non-method frame type", func() []byte {
			f := append([]byte{}, good...)
			f[0] = 8 // heartbeat
			return f
		}(), ErrUnexpectedFrame},
		{"non-zero channel", func() []byte {
			f := append([]byte{}, good...)
			binary.BigEndian.PutUint16(f[1:3], 7)
			return f
		}(), ErrUnexpectedFrame},
		{"payload shorter than a method id", func() []byte {
			f := []byte{frameTypeMethod, 0, 0}
			f = binary.BigEndian.AppendUint32(f, 2)
			return append(f, 0x00, 0x0A, frameEnd)
		}(), ErrMalformedFrame},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newReader(bytes.NewReader(tt.frame))
			if _, err := r.readFrame(); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNegotiatedCeilingNeverExceedsWhatWeAdvertise(t *testing.T) {
	r := newReader(bytes.NewReader(nil))
	if r.ceiling != preTunePayloadMax {
		t.Fatalf("initial ceiling = %d, want %d", r.ceiling, preTunePayloadMax)
	}
	r.negotiated(1 << 30)
	if r.ceiling > postTunePayloadMax {
		t.Errorf("ceiling = %d after a peer-sized request, want at most %d",
			r.ceiling, postTunePayloadMax)
	}
	r.negotiated(16)
	if r.ceiling < preTunePayloadMax {
		t.Error("the ceiling was lowered")
	}
}

// --- the field-table walker -------------------------------------------------

func TestWalkExtractsOnlyTheFourWantedKeys(t *testing.T) {
	var props []byte
	props = append(props, tableEntryStr("product", "RabbitMQ")...)
	props = append(props, tableEntryStr("version", "4.2.0")...)
	props = append(props, tableEntryStr("platform", "Erlang/OTP 27")...)
	props = append(props, tableEntryStr("cluster_name", "rabbit@node")...)
	props = append(props, tableEntryStr("copyright", "Copyright (c) somebody")...)
	props = append(props, tableEntryStr("information", "Licensed under something")...)

	// A nested table, which must be skipped whole.
	var caps []byte
	caps = append(caps, byte(len("publisher_confirms")))
	caps = append(caps, "publisher_confirms"...)
	caps = append(caps, 't', 0x01)
	props = append(props, byte(len("capabilities")))
	props = append(props, "capabilities"...)
	props = append(props, 'F')
	//nolint:gosec // G115: test fixtures built from literals this file controls.
	props = binary.BigEndian.AppendUint32(props, uint32(len(caps)))
	props = append(props, caps...)

	cur := &cursor{b: props}
	got, err := walkTopLevelTable(cur, len(props))
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("extracted %d keys, want exactly 4: %v", len(got), got)
	}
	for key, want := range map[string]string{
		"product": "RabbitMQ", "version": "4.2.0",
		"platform": "Erlang/OTP 27", "cluster_name": "rabbit@node",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
	for _, unwanted := range []string{"copyright", "information", "capabilities",
		"publisher_confirms"} {
		if _, present := got[unwanted]; present {
			t.Errorf("%s was extracted; only four keys are wanted", unwanted)
		}
	}
}

// TestWalkNeverRecurses is the structural half of ADR 0070 section 5.1.
//
// A depth bound would have been the "N times the observed value" reasoning
// ADR 0061 forbids, so the descent is deleted instead. This asserts the deletion
// by reading the source: walkTopLevelTable must not call itself.
func TestWalkNeverRecurses(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(sourceDir(t), "table.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "walkTopLevelTable" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "walkTopLevelTable" {
				t.Error("walkTopLevelTable calls itself; nesting depth is meant to be " +
					"1 by construction, not bounded by a number")
			}
			return true
		})
		return
	}
	t.Fatal("walkTopLevelTable not found; this guard would pass vacuously")
}

// TestNestedDepthBombIsSkippedNotEntered proves the deletion works in practice.
func TestNestedDepthBombIsSkippedNotEntered(t *testing.T) {
	// Build 200 levels of nested table around one leaf.
	inner := tableEntryStr("leaf", "x")
	for i := 0; i < 200; i++ {
		wrapped := []byte{byte(len("n"))}
		wrapped = append(wrapped, "n"...)
		wrapped = append(wrapped, 'F')
		//nolint:gosec // G115: test fixtures built from literals this file controls.
		wrapped = binary.BigEndian.AppendUint32(wrapped, uint32(len(inner)))
		wrapped = append(wrapped, inner...)
		inner = wrapped
	}
	props := append(tableEntryStr("product", "RabbitMQ"), inner...)

	cur := &cursor{b: props}
	got, err := walkTopLevelTable(cur, len(props))
	if err != nil {
		t.Fatalf("a nested bomb should be skipped, not refused: %v", err)
	}
	if got["product"] != "RabbitMQ" {
		t.Errorf("product = %q after a nested bomb", got["product"])
	}
	if len(got) != 1 {
		t.Errorf("extracted %d keys from a bomb, want 1", len(got))
	}
}

func TestWalkRefusesMalformedTables(t *testing.T) {
	tests := map[string][]byte{
		"unknown field type": {1, 'k', '?'},
		"length past the end": func() []byte {
			out := []byte{1, 'k', 'S'}
			return binary.BigEndian.AppendUint32(out, 0xFFFF)
		}(),
		"name past the end": {200, 'k'},
	}
	for name, props := range tests {
		t.Run(name, func(t *testing.T) {
			cur := &cursor{b: props}
			if _, err := walkTopLevelTable(cur, len(props)); !errors.Is(err, ErrMalformedFrame) {
				t.Errorf("err = %v, want ErrMalformedFrame", err)
			}
		})
	}
}

// --- Connection.Start -------------------------------------------------------

func TestStartRecordsOnlyRecognizedMechanisms(t *testing.T) {
	props := append(tableEntryStr("product", "RabbitMQ"), tableEntryStr("version", "4.2.0")...)
	c, _ := pipeConn(t, startFrame(props, "PLAIN AMQPLAIN ANONYMOUS SOMETHING-CUSTOM"))

	got, err := c.Start(context.Background(), 2*time.Second)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got.Mechanisms != "AMQPLAIN ANONYMOUS PLAIN" {
		t.Errorf("mechanisms = %q, want the sorted recognized subset", got.Mechanisms)
	}
	if strings.Contains(got.Mechanisms, "SOMETHING-CUSTOM") {
		t.Error("an unrecognized peer token reached the recorded observation")
	}
	if !got.PlainOffered || !got.AnonymousOffered {
		t.Errorf("PlainOffered=%v AnonymousOffered=%v", got.PlainOffered, got.AnonymousOffered)
	}
}

// TestPlainIsMatchedAsATokenNotASubstring proves `PLAINTEXT` does not offer
// `PLAIN`.
func TestPlainIsMatchedAsATokenNotASubstring(t *testing.T) {
	c, _ := pipeConn(t, startFrame(nil, "PLAINTEXT-ONLY EXTERNALISH"))
	got, err := c.Start(context.Background(), 2*time.Second)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got.PlainOffered {
		t.Error("a mechanism list of PLAINTEXT-ONLY was read as offering PLAIN")
	}
	if got.Mechanisms != "" {
		t.Errorf("mechanisms = %q, want empty", got.Mechanisms)
	}
}

// TestAProtocolHeaderAnswerIsARefusal covers the wrong-port and wrong-version
// cases. RabbitMQ answers unrecognized input with eight bytes and closes.
func TestAProtocolHeaderAnswerIsARefusal(t *testing.T) {
	c, _ := pipeConn(t, []byte{'A', 'M', 'Q', 'P', 0x03, 0x01, 0x00, 0x00})
	if _, err := c.Start(context.Background(), 2*time.Second); !errors.Is(err, ErrNotAMQP091) {
		t.Errorf("err = %v, want ErrNotAMQP091", err)
	}
}

// --- Tune -------------------------------------------------------------------

// TestSelectTuneIsTheFrozenContract covers the cross-version window Phase 8.0C
// measured: 4096 is accepted by RabbitMQ 3.13 and 4.0 and refused by 4.2, and
// 8192 is accepted everywhere.
func TestSelectTuneIsTheFrozenContract(t *testing.T) {
	tests := []struct {
		name     string
		offer    Tune
		want     Selected
		wantErr  bool
		scenario string
	}{
		{"RabbitMQ default offer", Tune{ChannelMax: 2047, FrameMax: 131072, Heartbeat: 60},
			Selected{ChannelMax: 1, FrameMax: 8192, Heartbeat: 0}, false, "3.13, 4.0 and 4.2"},
		{"LavinMQ default offer", Tune{ChannelMax: 2048, FrameMax: 131072, Heartbeat: 300},
			Selected{ChannelMax: 1, FrameMax: 8192, Heartbeat: 0}, false, "LavinMQ 2.3"},
		{"server offers no limit", Tune{FrameMax: 0},
			Selected{ChannelMax: 1, FrameMax: 8192, Heartbeat: 0}, false, "frame_max 0 means unlimited"},
		{"server offers exactly the spec floor", Tune{FrameMax: 4096},
			Selected{ChannelMax: 1, FrameMax: 4096, Heartbeat: 0}, false, "clamped down, still legal"},
		{"server offers below the spec floor", Tune{FrameMax: 2048},
			Selected{}, true, "no client can satisfy this broker"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SelectTune(tt.offer)
			if tt.wantErr {
				if !errors.Is(err, ErrTuneUnsupported) {
					t.Fatalf("err = %v, want ErrTuneUnsupported (%s)", err, tt.scenario)
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectTune: %v", err)
			}
			if got != tt.want {
				t.Errorf("selected = %+v, want %+v (%s)", got, tt.want, tt.scenario)
			}
		})
	}
}

// TestSelectTuneNeverSendsZero pins the measured trap: zero is not "no limit"
// at RabbitMQ, and sending it causes a silent close after about three seconds.
func TestSelectTuneNeverSendsZero(t *testing.T) {
	for _, offer := range []Tune{
		{ChannelMax: 2047, FrameMax: 131072}, {ChannelMax: 0, FrameMax: 0},
		{ChannelMax: 1, FrameMax: 8192},
	} {
		got, err := SelectTune(offer)
		if err != nil {
			continue
		}
		if got.ChannelMax == 0 {
			t.Errorf("channel_max 0 selected for offer %+v", offer)
		}
		if got.FrameMax == 0 {
			t.Errorf("frame_max 0 selected for offer %+v", offer)
		}
		if got.Heartbeat != 0 {
			t.Errorf("heartbeat %d selected; the contract is 0 and no heartbeat loop",
				got.Heartbeat)
		}
	}
}

// --- Connection.Secure ------------------------------------------------------

// TestSecureChallengeIsNotAnswered proves the second credential-bearing frame
// cannot happen. Unreachable against RabbitMQ's PLAIN, which is why it is
// written down rather than assumed.
func TestSecureChallengeIsNotAnswered(t *testing.T) {
	c, sent := pipeConn(t, methodFrame(classConnection, inSecure, []byte{0, 0, 0, 0}))
	secret := security.NewSecret("s3cr3t")
	if _, err := c.SendStartOk(context.Background(), 2*time.Second, "alice", secret); !errors.Is(err, ErrSecureChallenge) {
		t.Fatalf("err = %v, want ErrSecureChallenge", err)
	}

	// Exactly one credential-bearing frame reached the peer.
	if got := bytes.Count(sent.Bytes(), []byte("s3cr3t")); got != 1 {
		t.Errorf("the credential appears %d times on the wire, want exactly 1", got)
	}
}

// --- structural guards ------------------------------------------------------

// TestOnlyConnectionClassMethodsAreEncodable is the guard the phase requires.
//
// encodeMethod takes a connectionMethod and hardcodes the class, so a Channel,
// Queue, Exchange or Basic method is not expressible. This asserts both halves:
// the type has exactly the five frozen values, and no other class constant
// exists in the package.
func TestOnlyConnectionClassMethodsAreEncodable(t *testing.T) {
	dir := sourceDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var methodValues []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		src := readSource(t, entry.Name())

		// No AMQP class other than connection may be named at all.
		for _, forbidden := range []string{
			"classChannel", "classExchange", "classQueue", "classBasic",
			"channel.open", "queue.declare", "exchange.declare",
			"basic.publish", "basic.consume", "basic.get", "queue.bind",
		} {
			if strings.Contains(src, forbidden) {
				t.Errorf("%s names %q; BASIC encodes connection-class methods only",
					entry.Name(), forbidden)
			}
		}

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", entry.Name(), perr)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || vs.Type == nil {
					continue
				}
				if id, ok := vs.Type.(*ast.Ident); ok && id.Name == "connectionMethod" {
					for _, n := range vs.Names {
						methodValues = append(methodValues, n.Name)
					}
				}
			}
		}
	}

	want := map[string]bool{"mStartOk": true, "mTuneOk": true, "mOpen": true,
		"mClose": true, "mCloseOk": true}
	if len(methodValues) != len(want) {
		t.Errorf("connectionMethod has %d values (%v), want exactly the five frozen "+
			"outbound methods", len(methodValues), methodValues)
	}
	for _, name := range methodValues {
		if !want[name] {
			t.Errorf("connectionMethod declares %s, which ADR 0067 section 2 does not authorize", name)
		}
	}
}

// TestExactlyOneRevealInThisPackage pins the credential boundary.
func TestExactlyOneRevealInThisPackage(t *testing.T) {
	dir := sourceDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	sites := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", entry.Name(), perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Reveal" {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "security" {
				sites++
			}
			return true
		})
	}
	if sites != 1 {
		t.Errorf("security.Reveal has %d call sites in this package, want exactly 1", sites)
	}
}

// TestRefusalCarriesNoPeerText pins ADR 0069 section 2 at the type level.
//
// A field able to hold reply text is the escape hatch. There is none, and the
// error value a refusal produces names only a constant and a numeric code.
func TestRefusalCarriesNoPeerText(t *testing.T) {
	c, _ := pipeConn(t, closeFrame(530, "NOT_ALLOWED - vhost secret-name not found", 10, 40))
	err := c.Open(context.Background(), 2*time.Second)

	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("err = %v, want a RefusedError", err)
	}
	if strings.Contains(err.Error(), "secret-name") {
		t.Errorf("the error message carries peer text: %v", err)
	}
	if refused.Refusal.ReplyCode != 530 {
		t.Errorf("reply code = %d, want 530", refused.Refusal.ReplyCode)
	}
	if refused.Refusal.PeerClassID != 10 || refused.Refusal.PeerMethodID != 40 {
		t.Errorf("peer class/method = %d/%d, want 10/40 recorded as corroboration",
			refused.Refusal.PeerClassID, refused.Refusal.PeerMethodID)
	}

	source := readSource(t, "errors.go")
	for _, forbidden := range []string{"ReplyText", "Text string", "Reason string"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("Refusal declares %q; reply text has no field by design", forbidden)
		}
	}
}

// --- helpers ----------------------------------------------------------------

func sourceDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(sourceDir(t), name)) //nolint:gosec // a package-local path.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
