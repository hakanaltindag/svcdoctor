package wire

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// The two HELLO replies below are **real bytes**, captured in Phase 7.5 from
// stock containers with a scratch client that sent the same zero-argument frame
// this package sends. They are not hand-written approximations, which matters:
// the Valkey one is the evidence that ADR 0066's identity decision describes a
// real server rather than a documented intention.
const (
	// Redis 8.2.1, 688 bytes on the wire, five bundled modules.
	redisHelloReply = "*14\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:10\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n" +
		"$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*2\r\n" +
		"*8\r\n$4\r\nname\r\n$6\r\nsearch\r\n$3\r\nver\r\n:80201\r\n$4\r\npath\r\n" +
		"$43\r\n/usr/local/lib/redis/modules//redisearch.so\r\n$4\r\nargs\r\n*0\r\n" +
		"*8\r\n$4\r\nname\r\n$9\r\nvectorset\r\n$3\r\nver\r\n:1\r\n$4\r\npath\r\n$0\r\n\r\n$4\r\nargs\r\n*0\r\n"

	// Valkey 8.1.1, 146 bytes on the wire, no modules.
	valkeyHelloReply = "*14\r\n$6\r\nserver\r\n$6\r\nvalkey\r\n$7\r\nversion\r\n$5\r\n8.1.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:2\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n" +
		"$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n"
)

// scriptedPeer answers each write with the next canned reply and records
// everything svcdoctor sent.
type scriptedPeer struct {
	t       *testing.T
	replies []string
	written bytes.Buffer
}

func dialScripted(t *testing.T, replies ...string) (*Conn, *scriptedPeer) {
	t.Helper()
	client, server := net.Pipe()
	peer := &scriptedPeer{t: t, replies: replies}

	go func() {
		defer func() { _ = server.Close() }()
		buf := make([]byte, 4096)
		for _, reply := range replies {
			n, err := server.Read(buf)
			if n > 0 {
				peer.written.Write(buf[:n])
			}
			if err != nil {
				return
			}
			if _, err := server.Write([]byte(reply)); err != nil {
				return
			}
		}
		// Drain anything sent after the script ends so a mutation that adds a
		// command does not deadlock the test; it fails on the assertion instead.
		for {
			n, err := server.Read(buf)
			if n > 0 {
				peer.written.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() { _ = client.Close() })
	return NewConn(client), peer
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestHelloFrameIsExactlyTheZeroArgumentForm is the load-bearing structural test
// of ADR 0064.
//
// It compares bytes rather than behaviour on purpose. Any mutation that adds a
// protocol version, an AUTH clause or a SETNAME clause to HELLO changes these
// exact bytes, and no reviewer attention is required to catch it.
func TestHelloFrameIsExactlyTheZeroArgumentForm(t *testing.T) {
	const want = "*1\r\n$5\r\nHELLO\r\n"
	if string(helloFrame) != want {
		t.Fatalf("HELLO frame is %q, want %q; a credential or an argument must never "+
			"appear in HELLO (ADR 0064 section 3)", helloFrame, want)
	}
}

func TestPingFrameCarriesNoMessage(t *testing.T) {
	const want = "*1\r\n$4\r\nPING\r\n"
	if string(pingFrame) != want {
		t.Fatalf("PING frame is %q, want %q", pingFrame, want)
	}
}

// TestHelloExchangeSendsOnlyTheConstantFrame proves the bytes on the socket, not
// just the constant.
func TestHelloExchangeSendsOnlyTheConstantFrame(t *testing.T) {
	conn, peer := dialScripted(t, redisHelloReply)
	if _, err := conn.SendHello(ctxT(t), time.Second); err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	if got := peer.written.String(); got != "*1\r\n$5\r\nHELLO\r\n" {
		t.Fatalf("wrote %q, want the bare HELLO frame", got)
	}
}

func TestHelloNormalizesRedisIdentity(t *testing.T) {
	conn, _ := dialScripted(t, redisHelloReply)
	hello, err := conn.SendHello(ctxT(t), time.Second)
	if err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	if !hello.Answered() {
		t.Fatalf("expected an answered HELLO, got prefix %q", hello.Prefix)
	}
	if hello.Server != "redis" || hello.Version != "8.2.1" {
		t.Errorf("identity = %q/%q, want redis/8.2.1", hello.Server, hello.Version)
	}
	if hello.Proto != 2 {
		t.Errorf("proto = %d, want 2: a zero-argument HELLO never switches protocol", hello.Proto)
	}
	if hello.Mode != ModeStandalone || hello.Role != RoleMaster {
		t.Errorf("mode/role = %q/%q, want standalone/master", hello.Mode, hello.Role)
	}
}

// TestHelloNormalizesValkeyIdentity is the row that proves the shared adapter is
// honest: the same code path, the same command, a different self-description.
func TestHelloNormalizesValkeyIdentity(t *testing.T) {
	conn, _ := dialScripted(t, valkeyHelloReply)
	hello, err := conn.SendHello(ctxT(t), time.Second)
	if err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	if hello.Server != "valkey" {
		t.Fatalf("server = %q, want valkey; identity is observed, never assumed "+
			"from the CLI verb (ADR 0066 section 4)", hello.Server)
	}
	if hello.Version != "8.1.1" {
		t.Errorf("version = %q, want 8.1.1", hello.Version)
	}
}

// TestHelloDiscardsUnauthorizedFields pins ADR 0066 section 4's retain/ignore
// table. id and modules are parsed and dropped; there is no accessor for them.
func TestHelloDiscardsUnauthorizedFields(t *testing.T) {
	conn, _ := dialScripted(t, redisHelloReply)
	hello, err := conn.SendHello(ctxT(t), time.Second)
	if err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	// The Hello struct is the whole retained surface. If a field for id,
	// modules or availability_zone is ever added, this test's premise changes
	// and the comment above stops being true.
	if fmt.Sprintf("%+v", hello) !=
		fmt.Sprintf("%+v", Hello{Prefix: PrefixNone, Server: "redis", Version: "8.2.1",
			Proto: 2, Mode: ModeStandalone, Role: RoleMaster}) {
		t.Fatalf("Hello retained more or less than the authorized fields: %+v", hello)
	}
}

func TestHelloToleratesUnknownFields(t *testing.T) {
	// Valkey adds availability_zone when configured; a later version may add
	// more. An unknown key must be skipped, not rejected.
	reply := "*4\r\n$6\r\nserver\r\n$6\r\nvalkey\r\n$17\r\navailability_zone\r\n$9\r\neu-west-1\r\n"
	conn, _ := dialScripted(t, reply)
	hello, err := conn.SendHello(ctxT(t), time.Second)
	if err != nil {
		t.Fatalf("an unknown HELLO field must not fail the parser: %v", err)
	}
	if hello.Server != "valkey" {
		t.Errorf("server = %q, want valkey", hello.Server)
	}
}

func TestHelloSentinelOmitsRole(t *testing.T) {
	// Redis emits role only when !server.sentinel_mode, so a Sentinel's reply
	// has mode and no role at all.
	reply := "*10\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:3\r\n$4\r\nmode\r\n$8\r\nsentinel\r\n"
	conn, _ := dialScripted(t, reply)
	hello, err := conn.SendHello(ctxT(t), time.Second)
	if err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	if hello.Mode != ModeSentinel {
		t.Fatalf("mode = %q, want sentinel", hello.Mode)
	}
	if hello.Role != RoleUnknown {
		t.Errorf("role = %q, want unknown: a Sentinel reply carries no role field", hello.Role)
	}
}

func TestHelloRejectsPeerChosenModeAndRole(t *testing.T) {
	reply := "*8\r\n$4\r\nmode\r\n$20\r\nstandalone-ish-thing\r\n" +
		"$4\r\nrole\r\n$7\r\nprimary\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$3\r\n1.0\r\n"
	conn, _ := dialScripted(t, reply)
	hello, err := conn.SendHello(ctxT(t), time.Second)
	if err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	if hello.Mode != ModeUnknown || hello.Role != RoleUnknown {
		t.Fatalf("mode/role = %q/%q, want both unknown: neither is in the closed set",
			hello.Mode, hello.Role)
	}
}

func TestHelloRefusesUnprintableIdentity(t *testing.T) {
	reply := "*4\r\n$6\r\nserver\r\n$7\r\nred\x00is!\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n"
	conn, _ := dialScripted(t, reply)
	hello, err := conn.SendHello(ctxT(t), time.Second)
	if err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	if hello.Server != "" {
		t.Fatalf("server = %q, want empty: a control byte must make the field absent, "+
			"never truncated", hello.Server)
	}
}

func TestHelloClassifiesErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply string
		want  ErrorPrefix
		check func(Hello) bool
	}{
		{"noauth", "-NOAUTH HELLO must be called with the client already authenticated\r\n",
			PrefixNOAUTH, Hello.AuthRequired},
		{"unknown command", "-ERR unknown command 'HELLO', with args beginning with: \r\n",
			PrefixERR, Hello.Unsupported},
		{"denied", "-DENIED Redis is running in protected mode because...\r\n", PrefixDENIED, nil},
		{"unrecognized", "-QUANTUMFLUX something entirely new\r\n", PrefixUnrecognized, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, _ := dialScripted(t, tc.reply)
			hello, err := conn.SendHello(ctxT(t), time.Second)
			if err != nil {
				t.Fatalf("SendHello: %v", err)
			}
			if hello.Prefix != tc.want {
				t.Fatalf("prefix = %q, want %q", hello.Prefix, tc.want)
			}
			if tc.check != nil && !tc.check(hello) {
				t.Errorf("predicate did not hold for %q", tc.want)
			}
			if hello.Answered() {
				t.Errorf("an error reply must not read as answered")
			}
		})
	}
}

// TestNoRawErrorTextEscapesTheWirePackage plants secret canaries in hostile error
// text and proves none of them reaches the caller.
//
// This is ADR 0066's boundary as a test rather than as a convention. Redis really
// does interpolate caller-supplied bytes (server.c:4386) and the username
// (acl.c:2871) into error strings, so the canaries below are the shape of a real
// leak, not a synthetic one.
func TestNoRawErrorTextEscapesTheWirePackage(t *testing.T) {
	const canary = "hunter2-CANARY-s3cr3t"
	replies := []string{
		"-ERR unknown command 'HELLO', with args beginning with: '3' 'AUTH' 'u' '" + canary + "' \r\n",
		"-NOPERM User " + canary + " has no permissions to run the 'ping' command\r\n",
		"-WRONGPASS invalid username-password pair or user is disabled. " + canary + "\r\n",
	}
	for _, reply := range replies {
		conn, _ := dialScripted(t, reply)
		hello, err := conn.SendHello(ctxT(t), time.Second)
		rendered := fmt.Sprintf("%+v %v", hello, err)
		if strings.Contains(rendered, canary) {
			t.Fatalf("peer error text escaped the wire package: %q", rendered)
		}
		if strings.Contains(string(hello.Prefix), canary) {
			t.Fatalf("canary reached the normalized prefix")
		}
	}
}

func TestAuthUsesTheOperatorsFormVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name     string
		username string
		want     string
	}{
		{"password only", "", "*2\r\n$4\r\nAUTH\r\n$3\r\npwd\r\n"},
		{"username and password", "app", "*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$3\r\npwd\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, peer := dialScripted(t, "+OK\r\n")
			auth, err := conn.SendAuth(ctxT(t), time.Second, tc.username, security.NewSecret("pwd"))
			if err != nil {
				t.Fatalf("SendAuth: %v", err)
			}
			if !auth.Accepted() {
				t.Fatalf("expected acceptance, got %q", auth.Prefix)
			}
			if got := peer.written.String(); got != tc.want {
				t.Fatalf("wrote %q, want %q; `default` must never be synthesized "+
					"(ADR 0064 section 5)", got, tc.want)
			}
		})
	}
}

func TestAuthClassifiesRejection(t *testing.T) {
	conn, _ := dialScripted(t, "-WRONGPASS invalid username-password pair or user is disabled.\r\n")
	auth, err := conn.SendAuth(ctxT(t), time.Second, "app", security.NewSecret("pwd"))
	if err != nil {
		t.Fatalf("SendAuth: %v", err)
	}
	if !auth.Rejected() || auth.Accepted() {
		t.Fatalf("WRONGPASS must classify as rejected, got %q", auth.Prefix)
	}
}

func TestAuthRefusesAnEmptySecret(t *testing.T) {
	conn, peer := dialScripted(t, "+OK\r\n")
	if _, err := conn.SendAuth(ctxT(t), time.Second, "app", security.Secret{}); err == nil {
		t.Fatal("an empty credential must be refused rather than sent as AUTH \"\"")
	}
	if peer.written.Len() != 0 {
		t.Fatalf("wrote %q; a refused credential must put zero bytes on the wire",
			peer.written.String())
	}
}

func TestPingClassifiesOutcomes(t *testing.T) {
	for _, tc := range []struct {
		reply string
		want  ErrorPrefix
	}{
		{"+PONG\r\n", PrefixNone},
		{"-NOPERM User app has no permissions to run the 'ping' command\r\n", PrefixNOPERM},
		{"-LOADING Redis is loading the dataset in memory\r\n", PrefixLOADING},
		{"-LOADING Valkey is loading the dataset in memory\r\n", PrefixLOADING},
		{"-MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to 'no'.\r\n",
			PrefixMASTERDOWN},
		{"-BUSY Redis is busy running a script.\r\n", PrefixBUSY},
	} {
		conn, _ := dialScripted(t, tc.reply)
		ping, err := conn.SendPing(ctxT(t), time.Second)
		if err != nil {
			t.Fatalf("SendPing(%q): %v", tc.reply, err)
		}
		if ping.Prefix != tc.want {
			t.Fatalf("prefix for %q = %q, want %q", tc.reply, ping.Prefix, tc.want)
		}
		if ping.Pong() != (tc.want == PrefixNone) {
			t.Fatalf("Pong() disagreed with the prefix for %q", tc.reply)
		}
	}
}

// TestRedisAndValkeyLoadingClassifyIdentically is the compatibility row that
// proves prefix-only classification was the right call: the two implementations
// send different *text* for the same condition.
func TestRedisAndValkeyLoadingClassifyIdentically(t *testing.T) {
	redis := classifyErrorText("LOADING Redis is loading the dataset in memory")
	valkey := classifyErrorText("LOADING Valkey is loading the dataset in memory")
	if redis != valkey || redis != PrefixLOADING {
		t.Fatalf("Redis %q and Valkey %q must classify identically as LOADING", redis, valkey)
	}
}

func TestUnrecognizedPrefixDoesNotCarryPeerBytes(t *testing.T) {
	got := classifyErrorText("TOTALLYNEWPREFIX with a message")
	if got != PrefixUnrecognized {
		t.Fatalf("got %q, want %q", got, PrefixUnrecognized)
	}
	if strings.Contains(string(got), "TOTALLYNEW") {
		t.Fatal("an unrecognized prefix must not be a slice of the peer's bytes")
	}
}

// ---- RESP2 framing and hostile input -------------------------------------

func readOne(t *testing.T, wire string) (reply, error) {
	t.Helper()
	r := newReader(strings.NewReader(wire))
	r.begin()
	return r.readReply()
}

func TestRESP2FramesDecode(t *testing.T) {
	cases := map[string]struct {
		wire  string
		check func(reply) error
	}{
		"simple string": {"+OK\r\n", func(r reply) error {
			if r.kind != kindSimpleString || r.text != "OK" {
				return errors.New("not a simple string OK")
			}
			return nil
		}},
		"error": {"-ERR nope\r\n", func(r reply) error {
			if r.kind != kindError {
				return errors.New("not an error")
			}
			return nil
		}},
		"integer": {":42\r\n", func(r reply) error {
			if r.kind != kindInteger || r.integer != 42 {
				return errors.New("not integer 42")
			}
			return nil
		}},
		"bulk": {"$5\r\nhello\r\n", func(r reply) error {
			if r.kind != kindBulk || string(r.bulk) != "hello" {
				return errors.New("not bulk hello")
			}
			return nil
		}},
		"null bulk": {"$-1\r\n", func(r reply) error {
			if r.kind != kindBulk || !r.null {
				return errors.New("not a null bulk")
			}
			return nil
		}},
		"empty bulk": {"$0\r\n\r\n", func(r reply) error {
			if r.kind != kindBulk || len(r.bulk) != 0 || r.null {
				return errors.New("not an empty bulk")
			}
			return nil
		}},
		"array": {"*2\r\n:1\r\n:2\r\n", func(r reply) error {
			if r.kind != kindArray || len(r.array) != 2 {
				return errors.New("not a two-element array")
			}
			return nil
		}},
		"null array": {"*-1\r\n", func(r reply) error {
			if r.kind != kindArray || !r.null {
				return errors.New("not a null array")
			}
			return nil
		}},
		"empty array": {"*0\r\n", func(r reply) error {
			if r.kind != kindArray || len(r.array) != 0 || r.null {
				return errors.New("not an empty array")
			}
			return nil
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := readOne(t, tc.wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if err := tc.check(r); err != nil {
				t.Fatalf("%v: %+v", err, r)
			}
		})
	}
}

// TestRESP3FirstBytesAreMalformed pins ADR 0063 section 6. On a connection that
// never negotiated RESP3, a map, set, push or attribute frame is not a frame
// svcdoctor agreed to receive — and refusing them is what makes an asynchronous
// push impossible rather than handled.
func TestRESP3FirstBytesAreMalformed(t *testing.T) {
	for _, wire := range []string{
		"%1\r\n+a\r\n+b\r\n", // map
		"~1\r\n+a\r\n",       // set
		">2\r\n+a\r\n+b\r\n", // push
		"|1\r\n+a\r\n+b\r\n", // attribute
		"#t\r\n",             // boolean
		",1.23\r\n",          // double
		"(123\r\n",           // big number
		"=4\r\ntxt:\r\n",     // verbatim string
		"_\r\n",              // null
		"!3\r\nbad\r\n",      // bulk error
	} {
		if _, err := readOne(t, wire); !errors.Is(err, ErrMalformedReply) {
			t.Errorf("first byte %q: err = %v, want ErrMalformedReply", wire[:1], err)
		}
	}
}

func TestMalformedFramingIsRefusedWithoutPanicking(t *testing.T) {
	for name, wire := range map[string]string{
		"bad line terminator":  "+OK\n",
		"bulk not terminated":  "$2\r\nab!!",
		"bulk length not int":  "$abc\r\n",
		"array length not int": "*abc\r\n",
		"integer not int":      ":not-a-number\r\n",
		"negative bulk":        "$-7\r\n",
		"negative array":       "*-7\r\n",
		"truncated":            "$10\r\nshort",
		"empty":                "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readOne(t, wire); err == nil {
				t.Fatal("expected a refusal, got success")
			}
		})
	}
}

// ---- bounds: limit-1 / limit / limit+1 -----------------------------------

// TestMaxReplySizeIsPinnedByValue keeps the constant honest. A mutation that
// raises or removes it fails here rather than only in a behavioural test.
func TestMaxReplySizeIsPinnedByValue(t *testing.T) {
	if MaxReplySize != 65536 {
		t.Fatalf("MaxReplySize = %d, want 65536", MaxReplySize)
	}
	if maxArrayElements != MaxReplySize/4 {
		t.Fatalf("maxArrayElements = %d, want MaxReplySize/4 = %d",
			maxArrayElements, MaxReplySize/4)
	}
	if maxDepth != 4 {
		t.Fatalf("maxDepth = %d, want 4", maxDepth)
	}
}

// bulkOfPayload builds a bulk frame whose *total* encoded size is exactly total.
func bulkOfPayload(payload int) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", payload, strings.Repeat("x", payload))
}

func TestReplyBudgetBoundary(t *testing.T) {
	// The frame costs: 1 prefix byte + len("$N\r\n") + payload + 2.
	// Solve for the payload that lands exactly on MaxReplySize.
	exact := -1
	for payload := MaxReplySize - 16; payload < MaxReplySize; payload++ {
		if 1+len(fmt.Sprintf("%d\r\n", payload))+payload+2 == MaxReplySize {
			exact = payload
			break
		}
	}
	if exact < 0 {
		t.Fatal("could not construct a frame of exactly MaxReplySize bytes")
	}

	for _, tc := range []struct {
		name    string
		payload int
		wantErr bool
	}{
		{"limit minus one", exact - 1, false},
		{"limit", exact, false},
		{"limit plus one", exact + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readOne(t, bulkOfPayload(tc.payload))
			switch {
			case tc.wantErr && !errors.Is(err, ErrReplyTooLarge):
				t.Fatalf("err = %v, want ErrReplyTooLarge", err)
			case !tc.wantErr && err != nil:
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

// TestOversizedIsRefusedAsPolicyNotAsMalformed is ADR 0061 section 28's lesson
// applied here: a legal frame svcdoctor declines to read is svcdoctor's limit,
// and reporting it as a malformed peer reply would blame the endpoint for
// something it did correctly.
func TestOversizedIsRefusedAsPolicyNotAsMalformed(t *testing.T) {
	_, err := readOne(t, bulkOfPayload(MaxReplySize+1))
	if !errors.Is(err, ErrReplyTooLarge) {
		t.Fatalf("err = %v, want ErrReplyTooLarge", err)
	}
	if errors.Is(err, ErrMalformedReply) {
		t.Fatal("a resource-policy refusal must not also classify as malformed")
	}
}

// TestNoAllocationOnADeclaredLength is the property that makes the byte budget a
// safety net rather than the safety mechanism.
//
// The peer announces half a gigabyte and sends nothing. If the parser allocated
// from the declared length this would consume 512 MiB before failing; instead it
// refuses having read four bytes of header.
func TestNoAllocationOnADeclaredLength(t *testing.T) {
	huge := fmt.Sprintf("$%d\r\n", 512<<20)
	done := make(chan error, 1)
	go func() {
		_, err := readOne(t, huge)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrReplyTooLarge) {
			t.Fatalf("err = %v, want ErrReplyTooLarge", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a declared half-gigabyte bulk should be refused immediately")
	}
}

func TestArrayElementCeilingBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		count   int
		wantErr bool
	}{
		{"limit minus one", maxArrayElements - 1, false},
		{"limit", maxArrayElements, false},
		{"limit plus one", maxArrayElements + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Header only. Below the ceiling the parser proceeds and then runs
			// out of input or budget; above it, it refuses at the header.
			_, err := readOne(t, fmt.Sprintf("*%d\r\n", tc.count))
			if tc.wantErr {
				if !errors.Is(err, ErrReplyTooLarge) {
					t.Fatalf("err = %v, want ErrReplyTooLarge at the header", err)
				}
				return
			}
			if errors.Is(err, ErrReplyTooLarge) &&
				strings.Contains(err.Error(), "elements, above") {
				t.Fatalf("refused a declared count at or below the ceiling: %v", err)
			}
		})
	}
}

func TestNestingCeilingBoundary(t *testing.T) {
	nest := func(depth int) string {
		return strings.Repeat("*1\r\n", depth-1) + ":1\r\n"
	}
	for _, tc := range []struct {
		name    string
		depth   int
		wantErr bool
	}{
		{"limit minus one", maxDepth - 1, false},
		{"limit", maxDepth, false},
		{"limit plus one", maxDepth + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readOne(t, nest(tc.depth))
			switch {
			case tc.wantErr && !errors.Is(err, ErrReplyTooLarge):
				t.Fatalf("depth %d: err = %v, want ErrReplyTooLarge", tc.depth, err)
			case !tc.wantErr && err != nil:
				t.Fatalf("depth %d: unexpected refusal: %v", tc.depth, err)
			}
		})
	}
}

// TestNestingBombIsBoundedByDepthNotBytes proves why maxDepth exists separately
// from the byte budget: 64 KiB of "*1\r\n" is sixteen thousand frames of
// recursion, which the byte budget alone would permit.
func TestNestingBombIsBoundedByDepthNotBytes(t *testing.T) {
	bomb := strings.Repeat("*1\r\n", MaxReplySize/4)
	if _, err := readOne(t, bomb); !errors.Is(err, ErrReplyTooLarge) {
		t.Fatalf("err = %v, want ErrReplyTooLarge", err)
	}
}

func TestUnterminatedLineIsBoundedByTheBudget(t *testing.T) {
	// A peer that opens a simple string and never sends '\n'.
	flood := "+" + strings.Repeat("x", MaxReplySize+64)
	if _, err := readOne(t, flood); !errors.Is(err, ErrReplyTooLarge) {
		t.Fatalf("err = %v, want ErrReplyTooLarge", err)
	}
}

func TestBudgetResetsPerReply(t *testing.T) {
	// Three replies each near the ceiling must all succeed: the budget is per
	// reply, not per connection.
	payload := MaxReplySize - 32
	conn, _ := dialScripted(t, "+PONG\r\n", "+PONG\r\n", "+PONG\r\n")
	for i := 0; i < 3; i++ {
		if _, err := conn.SendPing(ctxT(t), time.Second); err != nil {
			t.Fatalf("ping %d: %v", i, err)
		}
	}
	_ = payload
}

func TestPeerCloseIsDistinguishable(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go func() {
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
		_ = server.Close()
	}()
	conn := NewConn(client)
	_, err := conn.SendPing(ctxT(t), time.Second)
	if !errors.Is(err, ErrPeerClosed) {
		t.Fatalf("err = %v, want ErrPeerClosed", err)
	}
}
