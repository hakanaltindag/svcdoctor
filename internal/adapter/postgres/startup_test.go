package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// plaintextSession negotiates a plaintext session against a peer scripted to
// answer a startup packet with reply.
func plaintextSession(t *testing.T, reply []byte) (*Session, *domain.GraphBuilder, *pgPeer) {
	t.Helper()

	peer := newPGPeer(t, script{expectNoSSLRequest: true, afterStartup: reply})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{TLS: TLSDisabled})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, builder, peer
}

// TestStartupRecordsWhatTheServerDemanded covers every authentication a server
// can ask for. Phase 4.3 identifies each and performs none.
func TestStartupRecordsWhatTheServerDemanded(t *testing.T) {
	cases := []struct {
		name  string
		reply []byte
		want  string
	}{
		{"trust", authOK(), "ok"},
		{"cleartext password", authCode(3), "cleartext"},
		{"md5", append(authCode(5), 1, 2, 3, 4), "md5"},
		{"gss", authCode(7), "gss"},
		{"sspi", authCode(9), "sspi"},
		{"sasl", saslReply("SCRAM-SHA-256"), "sasl"},
		{"future method", authCode(99), "unknown"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session, builder, _ := plaintextSession(t, tc.reply)

			result, err := Startup(context.Background(), builder, session, StartupParams{
				User: "payments_writer", Database: "payments_prod",
			})
			if err != nil {
				t.Fatalf("Startup: %v", err)
			}
			if result == nil {
				t.Fatal("Startup produced no result")
			}
			t.Cleanup(func() { _ = result.Close() })

			if got := result.AuthMethod(); got != tc.want {
				t.Errorf("AuthMethod() = %q, want %q", got, tc.want)
			}

			g := freeze(t, builder)
			startup := nodeFor(t, g, StepStartup)
			if startup.State() != domain.StatePass {
				t.Errorf("state = %s, want PASS: the server accepted the startup packet", startup.State())
			}
			if got := stringOf(t, startup, AttrAuthMethod); got != tc.want {
				t.Errorf("auth_method attribute = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestStartupStopsBeforeAuthenticating is the phase boundary, asserted on the
// wire rather than in the source.
//
// Whatever the server demands, svcdoctor writes the startup packet and nothing
// more. A password message, an MD5 digest or a SASL initial response would all
// be additional bytes, and there are none.
func TestStartupStopsBeforeAuthenticating(t *testing.T) {
	session, builder, peer := plaintextSession(t, authCode(3))

	result, err := Startup(context.Background(), builder, session, StartupParams{User: "app"})
	if err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if result == nil {
		t.Fatal("Startup produced no result")
	}
	t.Cleanup(func() { _ = result.Close() })

	packet := peer.waitForStartup(t)
	if len(peer.startupPackets()) != 1 {
		t.Errorf("peer read %d packets, want exactly 1", len(peer.startupPackets()))
	}
	// The packet's own length field must account for every byte the peer read,
	// which is only true if nothing followed it.
	if declared := binary.BigEndian.Uint32(packet[:4]); int(declared) != len(packet) {
		t.Errorf("packet declares %d bytes but %d were read: something followed the "+
			"startup message", declared, len(packet))
	}
	if bytes.Contains(bytes.ToLower(packet), []byte("password")) {
		t.Error("the startup packet mentions a password")
	}
}

// TestStartupRejection covers a server that refuses the startup outright.
func TestStartupRejection(t *testing.T) {
	cases := []struct {
		name     string
		sqlState string
		want     domain.FailureClass
	}{
		{
			// The server refuses the protocol version it was sent.
			name: "unsupported protocol version", sqlState: "0A000",
			want: domain.FailureProtocolUnsupportedVersion,
		},
		{
			// pg_hba refused on identity and origin, before any authentication
			// was requested and before any credential existed to evaluate.
			name: "refused before any credential", sqlState: "28000",
			want: domain.FailureAuthzNotPermitted,
		},
		{
			// A code svcdoctor declines to normalize. The code is still
			// recorded, so nothing is lost by not naming a cause.
			name: "unmapped code", sqlState: "53300",
			want: domain.FailureProtocolUnexpectedResponse,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session, builder, _ := plaintextSession(t, errorReply(tc.sqlState))

			result, err := Startup(context.Background(), builder, session, StartupParams{User: "app"})
			if err != nil {
				t.Fatalf("Startup: %v", err)
			}
			if result != nil {
				t.Fatal("a rejected startup produced a usable result")
			}

			g := freeze(t, builder)
			startup := nodeFor(t, g, StepStartup)
			if startup.State() != domain.StateFail {
				t.Errorf("state = %s, want FAIL", startup.State())
			}
			if startup.FailureClass() != tc.want {
				t.Errorf("failure = %s, want %s", startup.FailureClass(), tc.want)
			}
			if got := stringOf(t, startup, AttrSQLState); got != tc.sqlState {
				t.Errorf("sqlstate = %q, want %q", got, tc.sqlState)
			}
			if got := stringOf(t, startup, AttrErrorSeverity); got != "FATAL" {
				t.Errorf("severity = %q, want FATAL", got)
			}
			if native, ok := startup.Attribute(AttrErrorIsNative); !ok || !boolOf(native) {
				t.Error("error_is_native was not recorded for a reply carrying V")
			}
		})
	}
}

// TestPoolerRejectionDegradesToAWeakerTrueClaim is the pgBouncer lesson from
// Phase 4.0, enforced.
//
// A pooler collapses every SQLSTATE to 08P01 and omits the non-localized
// severity. svcdoctor must record what it can prove and no more: an unmapped
// code, and error_is_native false.
func TestPoolerRejectionDegradesToAWeakerTrueClaim(t *testing.T) {
	// A pooler-shaped reply: localized severity only, no V, protocol_violation.
	reply := errorReplyWithout("08P01", "V")
	session, builder, _ := plaintextSession(t, reply)

	if _, err := Startup(context.Background(), builder, session, StartupParams{User: "app"}); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	g := freeze(t, builder)
	startup := nodeFor(t, g, StepStartup)
	if startup.FailureClass() != domain.FailureProtocolUnexpectedResponse {
		t.Errorf("failure = %s, want the unmapped class", startup.FailureClass())
	}
	if got := stringOf(t, startup, AttrSQLState); got != "08P01" {
		t.Errorf("sqlstate = %q, want 08P01", got)
	}
	if native, ok := startup.Attribute(AttrErrorIsNative); !ok || boolOf(native) {
		t.Error("error_is_native should be false when the reply carried no V field")
	}
	if _, present := startup.Attribute(AttrErrorSeverity); present {
		t.Error("a localized severity was recorded; only V may be")
	}
}

// TestStartupErrorProseNeverReachesEvidence is the whitelist proof end to end.
func TestStartupErrorProseNeverReachesEvidence(t *testing.T) {
	reply := errorReply("28000",
		"M", `no pg_hba.conf entry for host "203.0.113.77", user "MSG-CANARY", database "DB-CANARY"`,
		"D", "DETAIL-CANARY", "H", "HINT-CANARY",
		"F", "auth.c", "R", "ClientAuthentication", "L", "530",
	)
	session, builder, _ := plaintextSession(t, reply)

	if _, err := Startup(context.Background(), builder, session, StartupParams{User: "app"}); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	assertNoCanary(t, freeze(t, builder),
		"MSG-CANARY", "DB-CANARY", "DETAIL-CANARY", "HINT-CANARY",
		"pg_hba.conf", "203.0.113.77", "auth.c", "ClientAuthentication",
	)
}

// TestStartupRecordsIdentitiesAsIdentity is the Phase 4.1 producer obligation,
// now real.
//
// A role and a database recorded as ordinary strings would survive into a
// shareable report. The kind is what makes redaction able to replace them.
func TestStartupRecordsIdentitiesAsIdentity(t *testing.T) {
	session, builder, _ := plaintextSession(t, authOK())

	if _, err := Startup(context.Background(), builder, session, StartupParams{
		User: "payments_writer", Database: "payments_prod",
	}); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	startup := nodeFor(t, freeze(t, builder), StepStartup)
	for key, want := range map[domain.AttributeKey]string{
		AttrRole:     "payments_writer",
		AttrDatabase: "payments_prod",
	} {
		v, ok := startup.Attribute(key)
		if !ok {
			t.Fatalf("attribute %s is missing", key)
		}
		if v.Kind() != domain.AttrKindIdentity {
			t.Errorf("%s has kind %s, want identity: an ordinary string would survive "+
				"into a shareable report (ADR 0037)", key, v.Kind())
		}
		got, _ := v.Identity()
		if got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// TestSubjectIsTheAddressNotTheIdentity pins what a node is about.
//
// The socket touched an address. The role and database are parameters of the
// session, and putting them in the subject would break correlation with the TCP
// and TLS nodes on the same connection — and would push identity into the one
// field redaction pseudonymizes as a host.
func TestSubjectIsTheAddressNotTheIdentity(t *testing.T) {
	session, builder, _ := plaintextSession(t, authOK())

	if _, err := Startup(context.Background(), builder, session, StartupParams{
		User: "payments_writer", Database: "payments_prod",
	}); err != nil {
		t.Fatalf("Startup: %v", err)
	}

	g := freeze(t, builder)
	want := canaryAddr + ":5432"

	for _, step := range []domain.Step{StepSSLRequest, StepStartup, "tcp.connect"} {
		node := nodeFor(t, g, step)
		if got := node.Subject().Ref(); got != want {
			t.Errorf("%s subject = %q, want the concrete address %q", step, got, want)
		}
		if id := node.ID().String(); strings.Contains(id, "payments_writer") ||
			strings.Contains(id, "payments_prod") {
			t.Errorf("%s evidence id contains a logical identity: %s", step, id)
		}
	}
}

// TestStartupPeerFailures covers replies that are not an answer.
func TestStartupPeerFailures(t *testing.T) {
	cases := []struct {
		name  string
		reply []byte
		want  domain.FailureClass
	}{
		{
			name:  "malformed length",
			reply: []byte{'R', 0, 0, 0, 1},
			want:  domain.FailureProtocolMalformedResponse,
		},
		{
			name:  "message the protocol does not allow here",
			reply: []byte{'Z', 0, 0, 0, 5, 'I'},
			want:  domain.FailureProtocolUnexpectedResponse,
		},
		{
			name:  "truncated authentication body",
			reply: []byte{'R', 0, 0, 0, 6, 0, 0},
			want:  domain.FailureProtocolMalformedResponse,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session, builder, _ := plaintextSession(t, tc.reply)

			result, err := Startup(context.Background(), builder, session, StartupParams{User: "app"})
			if err != nil {
				t.Fatalf("Startup: %v", err)
			}
			if result != nil {
				t.Error("a failed exchange produced a usable result")
			}

			startup := nodeFor(t, freeze(t, builder), StepStartup)
			if startup.State() != domain.StateFail {
				t.Errorf("state = %s, want FAIL", startup.State())
			}
			if startup.FailureClass() != tc.want {
				t.Errorf("failure = %s, want %s", startup.FailureClass(), tc.want)
			}
		})
	}
}

// TestStartupSkipsNotices proves a warning before the answer does not end the
// exchange.
func TestStartupSkipsNotices(t *testing.T) {
	notice := frameOf('N', errorBody("S", "WARNING", "C", "01000"))
	session, builder, _ := plaintextSession(t, append(notice, authOK()...))

	result, err := Startup(context.Background(), builder, session, StartupParams{User: "app"})
	if err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if result == nil {
		t.Fatal("a notice before the answer ended the exchange")
	}
	t.Cleanup(func() { _ = result.Close() })

	if got := result.AuthMethod(); got != "ok" {
		t.Errorf("AuthMethod() = %q, want ok", got)
	}
}

// TestStartupOwnershipIsSingleAndTerminal pins the ADR 0021 rules for the type
// this phase hands to Phase 4.4.
func TestStartupOwnershipIsSingleAndTerminal(t *testing.T) {
	session, builder, _ := plaintextSession(t, authOK())

	// The session's connection moves to the result.
	result, err := Startup(context.Background(), builder, session, StartupParams{User: "app"})
	if err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if result == nil {
		t.Fatal("no result")
	}
	if session.Available() {
		t.Error("the session still reports a connection after handing it on")
	}
	if _, ok := session.TakeConn(); ok {
		t.Error("the session handed out a connection it no longer owns")
	}

	conn, ok := result.TakeConn()
	if !ok {
		t.Fatal("the result had no connection to continue on")
	}
	if _, again := result.TakeConn(); again {
		t.Error("a connection was transferred twice")
	}
	// Close after a transfer must not touch somebody else's connection.
	if err := result.Close(); err != nil {
		t.Errorf("Close after a transfer: %v", err)
	}
	if err := result.Close(); err != nil {
		t.Errorf("Close is not idempotent: %v", err)
	}
	_ = conn.Close()
}

// --- architecture guards -----------------------------------------------------

// TestNoEnglishMessageClassification is the ban ADR 0036 section 6 rests on.
//
// SQLSTATE is stable across locales, versions and poolers; a message is not. The
// Phase 4.0 study measured two different causes emitting the same English text,
// and one cause emitting different text behind a pooler, so a classifier that
// read prose would be making confident claims about a string the peer chose.
//
// The guard is scoped to the files that **interpret what a peer sent**. The
// files it exempts use strings only on svcdoctor's own input — rejecting a NUL
// in a role name, splitting a port off an endpoint label the caller supplied —
// which is validation rather than classification. Exempting them by name keeps
// the rule reviewable instead of approximating a data-flow analysis.
func TestNoEnglishMessageClassification(t *testing.T) {
	// Files whose string work is on svcdoctor's own input, not on peer bytes.
	exempt := map[string]string{
		"params.go":       "rejects control characters in caller-supplied identities",
		"negotiate.go":    "splits a port off the caller's endpoint label",
		"wire/startup.go": "rejects a NUL in caller-supplied startup parameters",
	}

	forbidden := map[string]bool{
		"Contains": true, "ContainsAny": true, "HasPrefix": true, "HasSuffix": true,
		"Index": true, "LastIndex": true, "EqualFold": true, "Split": true, "Fields": true,
	}

	for _, dir := range []string{".", "wire"} {
		for _, path := range productionFiles(t, dir) {
			key := filepath.ToSlash(path)
			key = strings.TrimPrefix(key, "./")
			if _, ok := exempt[key]; ok {
				continue
			}

			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			for _, imp := range file.Imports {
				if imp.Path.Value == `"regexp"` {
					t.Errorf("%s imports regexp: peer text is never pattern-matched", path)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "strings" || !forbidden[sel.Sel.Name] {
					return true
				}
				t.Errorf("%s:%d calls strings.%s: a file that interprets a peer's reply "+
					"must classify on SQLSTATE and protocol position, never on text "+
					"(ADR 0036 section 6)", path, fset.Position(sel.Pos()).Line, sel.Sel.Name)
				return true
			})
		}
	}
}

// TestEnglishMessageGuardCoversTheClassifier is the control for the exemptions
// above: it fails if the file that maps SQLSTATE onto a failure class is ever
// added to the exempt list, which would make the guard vacuous where it matters.
func TestEnglishMessageGuardCoversTheClassifier(t *testing.T) {
	src, err := os.ReadFile("startup.go")
	if err != nil {
		t.Fatalf("reading startup.go: %v", err)
	}
	if !strings.Contains(string(src), "func sqlStateFailure(") {
		t.Fatal("sqlStateFailure moved; the guard above may no longer cover the classifier")
	}

	// The authentication classifier is covered too, and may not join the
	// exemption list: it maps SQLSTATE onto a failure class.
	//
	// The SCRAM attribute walker used to be named here as well. Phase 6.2 moved
	// it to internal/sasl/scram, so the path follows it rather than the entry
	// being dropped — a guard that stops naming what it guards is how this kind
	// of coverage disappears. The walker still performs no strings operation,
	// and the shared core cannot import strings at all: it is absent from the
	// depguard allowlist, which is a stronger statement than this guard makes.
	for _, want := range []struct{ path, symbol string }{
		{"authenticate.go", "func authSQLStateFailure("},
		{"../../sasl/scram/parse.go", "func attributes("},
	} {
		body, readErr := os.ReadFile(want.path)
		if readErr != nil {
			t.Fatalf("reading %s: %v", want.path, readErr)
		}
		if !strings.Contains(string(body), want.symbol) {
			t.Fatalf("%s moved out of %s; the guard may no longer cover it",
				want.symbol, want.path)
		}
	}
}

// TestPostgresCredentialSurfaceIsExactlyTwoCalls is the scope guard for Phase
// 4.4b, and it replaces the Phase 4.3 guard that asserted no credential was sent
// at all.
//
// That earlier guard did its job: it made "this phase transmits nothing" a
// property of the source rather than a claim in a comment, and it had to be
// deliberately edited for authentication to be written. This is the stronger
// successor. Phase 4.4b transmits exactly one credential, so the guard now pins
// **where** rather than **whether**:
//
//   - security.Reveal appears exactly once, in wire/scram.go
//   - Credential.SecretFor appears exactly once, in authenticate.go
//   - neither appears anywhere else, in either package
//   - nothing dials, at all
//
// A second Reveal, a Reveal that migrated out of the wire package, or a
// SecretFor in the wire package all fail here — and the first two also fail
// golangci-lint's forbidigo rule, so the boundary has two independent guards.
func TestPostgresCredentialSurfaceIsExactlyTwoCalls(t *testing.T) {
	// Where each call is allowed, and nowhere else.
	allowed := map[string]string{
		"Reveal":    "wire/scram.go",
		"SecretFor": "authenticate.go",
	}
	forbiddenEverywhere := map[string]string{
		"Dial":    "an adapter must not open a connection",
		"DialTCP": "an adapter must not open a connection",
		"Dialer":  "an adapter must not own a dialer",
	}

	counts := map[string]int{}

	for _, dir := range []string{".", "wire"} {
		for _, path := range productionFiles(t, dir) {
			key := strings.TrimPrefix(filepath.ToSlash(path), "./")

			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				name := sel.Sel.Name
				line := fset.Position(sel.Pos()).Line

				if reason, banned := forbiddenEverywhere[name]; banned {
					t.Errorf("%s:%d calls %s: %s", key, line, name, reason)
					return true
				}
				if home, tracked := allowed[name]; tracked {
					counts[name]++
					if key != home {
						t.Errorf("%s:%d calls %s, which may only appear in %s",
							key, line, name, home)
					}
				}
				return true
			})
		}
	}

	for name, want := range map[string]int{"Reveal": 1, "SecretFor": 1} {
		if counts[name] != want {
			t.Errorf("found %d call(s) to %s in postgres production code, want %d",
				counts[name], name, want)
		}
	}
}

// TestPostgresImplementsExactlyOneMechanism pins the phase's scope in the
// source.
//
// MD5, cleartext and channel binding are observed and declined, and the way that
// stays true is that the code to perform them does not exist. Each import below
// would be the first sign that one had been started.
func TestPostgresImplementsExactlyOneMechanism(t *testing.T) {
	banned := map[string]string{
		`"crypto/md5"`:  "MD5 authentication is declined, not implemented",
		`"crypto/sha1"`: "no SCRAM-SHA-1 variant is implemented",
	}

	for _, dir := range []string{".", "wire"} {
		for _, path := range productionFiles(t, dir) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			for _, imp := range file.Imports {
				if reason, bad := banned[imp.Path.Value]; bad {
					t.Errorf("%s imports %s: %s", path, imp.Path.Value, reason)
				}
			}
		}
	}

	// The one mechanism name svcdoctor sends, stated once.
	if wire.MechanismSCRAMSHA256 != "SCRAM-SHA-256" {
		t.Errorf("mechanism = %q, want SCRAM-SHA-256", wire.MechanismSCRAMSHA256)
	}
}

// TestPostgresImportsNothingItShouldNot pins the dependency direction.
func TestPostgresImportsNothingItShouldNot(t *testing.T) {
	banned := map[string]string{
		`"crypto/tls"`:   "an adapter must not inspect a connection to re-derive a channel",
		`"net/http"`:     "an adapter speaks one protocol",
		`"database/sql"`: "svcdoctor executes no SQL",
		`"os/exec"`:      "an adapter runs no commands",
		"kmsg":           "the Kafka protocol library has no business here",
		"pgx":            "no PostgreSQL client library; the wire is implemented directly",
		"pgconn":         "no PostgreSQL client library",
		"pgproto3":       "no PostgreSQL client library",
		"lib/pq":         "no PostgreSQL client library",
	}

	for _, dir := range []string{".", "wire"} {
		for _, path := range productionFiles(t, dir) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, src, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			for _, imp := range file.Imports {
				for needle, reason := range banned {
					if strings.Contains(imp.Path.Value, strings.Trim(needle, `"`)) {
						t.Errorf("%s imports %s: %s", path, imp.Path.Value, reason)
					}
				}
			}
		}
	}
}

// productionFiles lists the non-test Go files in a directory relative to this
// package, and fails if there are none, so a moved package cannot make a guard
// pass vacuously.
func productionFiles(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	if len(out) == 0 {
		t.Fatalf("no production Go files in %s", dir)
	}
	return out
}

// --- reply builders ----------------------------------------------------------

func frameOf(kind byte, body []byte) []byte {
	out := []byte{kind}
	if len(body) > 1<<20 {
		panic("fixture body too large to frame")
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4)) //nolint:gosec // bounded above.
	return append(out, body...)
}

func authCode(code uint32) []byte {
	return frameOf('R', binary.BigEndian.AppendUint32(nil, code))
}

func authOK() []byte { return authCode(0) }

func errorBody(pairs ...string) []byte {
	var body []byte
	for i := 0; i+1 < len(pairs); i += 2 {
		body = append(body, pairs[i][0])
		body = append(body, pairs[i+1]...)
		body = append(body, 0)
	}
	return append(body, 0)
}

// errorReplyWithout builds an ErrorResponse omitting one field code, which is
// how a pooler-shaped reply is produced.
func errorReplyWithout(sqlState, omit string) []byte {
	pairs := []string{"S", "FATAL", "V", "FATAL", "C", sqlState}
	var kept []string
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i] == omit {
			continue
		}
		kept = append(kept, pairs[i], pairs[i+1])
	}
	return frameOf('E', errorBody(kept...))
}

// TestSessionEstablishmentExecutesNoSQL is the scope guard for Phase 4.5b.
//
// ADR 0039 section 17 re-verified the no-SQL decision rather than inheriting it:
// every fact the session step needs arrives as a ParameterStatus, and the one
// that would need a statement — the session-local transaction_read_only — is
// deferred as a *fact*, not obtained by weakening the rule. This makes that a
// property of the source.
//
// The scan is over identifiers and string literals in the two files that own the
// window, so a comment explaining why there is no SQL does not trip it.
func TestSessionEstablishmentExecutesNoSQL(t *testing.T) {
	forbiddenCalls := map[string]string{
		"Query":       "the session step issues no statement",
		"QueryRow":    "the session step issues no statement",
		"Exec":        "the session step issues no statement",
		"ExecContext": "the session step issues no statement",
		"Prepare":     "the session step issues no statement",
	}
	// The needles are statement-shaped rather than word-shaped. A bare
	// "transaction_read_only" was tried and removed: it is a substring of
	// `default_transaction_read_only`, which is a ParameterStatus key this phase
	// legitimately retains, so the guard flagged the allowlist itself. "SHOW "
	// already covers the statement that would fetch the session-local value,
	// which is the thing actually being prevented.
	forbiddenText := []string{
		"SELECT ", "select 1", "SHOW ", "pg_is_in_recovery",
		"pg_catalog", "pg_stat_",
	}

	for _, path := range []string{"establish.go", "wire/session.go"} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}

		for _, imp := range file.Imports {
			if imp.Path.Value == `"database/sql"` {
				t.Errorf("%s imports database/sql", path)
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if reason, banned := forbiddenCalls[node.Sel.Name]; banned {
					t.Errorf("%s:%d calls %s: %s",
						path, fset.Position(node.Pos()).Line, node.Sel.Name, reason)
				}
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				for _, needle := range forbiddenText {
					if strings.Contains(node.Value, needle) {
						t.Errorf("%s:%d has the string literal %s, which looks like SQL",
							path, fset.Position(node.Pos()).Line, node.Value)
					}
				}
			}
			return true
		})
	}
}

// TestSessionResultCarriesNoConnection pins the terminal-ownership decision in
// the type rather than in a comment.
//
// ADR 0039 section 15: the step consumes its connection and closes it on every
// outcome, because nothing in v0.1 runs after ReadyForQuery. A field or accessor
// that handed the socket back would make `Terminate` unsendable by its owner and
// would add a third carrier for one connection.
func TestSessionResultCarriesNoConnection(t *testing.T) {
	result := reflect.TypeOf(SessionResult{})
	for i := range result.NumField() {
		field := result.Field(i)
		if strings.Contains(field.Type.String(), "net.Conn") {
			t.Errorf("SessionResult.%s carries a connection", field.Name)
		}
	}

	pointer := reflect.TypeOf(&SessionResult{})
	for i := range pointer.NumMethod() {
		method := pointer.Method(i)
		for out := range method.Type.NumOut() {
			if strings.Contains(method.Type.Out(out).String(), "net.Conn") {
				t.Errorf("SessionResult.%s returns a connection", method.Name)
			}
		}
		switch method.Name {
		case "Endpoint", "Evidence":
		default:
			t.Errorf("SessionResult gained the method %s; the type is deliberately "+
				"two accessors wide (ADR 0039 section 15)", method.Name)
		}
	}
}
