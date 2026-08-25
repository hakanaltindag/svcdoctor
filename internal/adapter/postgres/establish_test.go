package postgres

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// --- fixtures ---------------------------------------------------------------

// authenticated runs the real chain to an AuthenticatedSession over a verified
// TLS channel, with the peer scripted to send trailing after AuthenticationOk.
func authenticated(t *testing.T, s scramScript) (*AuthenticatedSession, *domain.GraphBuilder, *pgPeer) {
	t.Helper()

	result, builder, peer := verifiedTLS(t, s)
	session, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session == nil {
		t.Fatal("authentication did not produce a session")
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, builder, peer
}

// establishOver runs the whole chain and then the session step.
func establishOver(t *testing.T, s scramScript) (*SessionResult, *domain.GraphBuilder, *pgPeer) {
	t.Helper()

	session, builder, peer := authenticated(t, s)
	result, err := EstablishSession(context.Background(), builder, session, SessionParams{})
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	return result, builder, peer
}

func sessionNode(t *testing.T, builder *domain.GraphBuilder) domain.Evidence {
	t.Helper()
	return nodeFor(t, freeze(t, builder), StepSession)
}

func requireSession(
	t *testing.T, builder *domain.GraphBuilder, state domain.State, class domain.FailureClass,
) domain.Evidence {
	t.Helper()
	node := sessionNode(t, builder)
	if node.State() != state {
		t.Errorf("state = %s, want %s", node.State(), state)
	}
	if node.FailureClass() != class {
		t.Errorf("failure class = %s, want %s", node.FailureClass(), class)
	}
	return node
}

func attrOr(node domain.Evidence, key domain.AttributeKey) string {
	if v, ok := node.Attributes()[key]; ok {
		return v.String()
	}
	return "<absent>"
}

// --- success --------------------------------------------------------------

func TestSessionReachesReadyForQuery(t *testing.T) {
	result, builder, peer := establishOver(t, scramScript{trailing: healthySession()})

	if result == nil {
		t.Fatal("a healthy session produced no result")
	}
	node := requireSession(t, builder, domain.StatePass, domain.FailureNone)

	if node.Layer() != domain.LayerAuth {
		t.Errorf("layer = %s, want L5", node.Layer())
	}
	if got := attrOr(node, AttrTransactionStatus); got != "idle" {
		t.Errorf("transaction status = %q, want idle", got)
	}
	if got := attrOr(node, AttrServerVersion); got != canaryServerVersion {
		t.Errorf("server_version = %q", got)
	}
	if got := attrOr(node, AttrInHotStandby); got != "off" {
		t.Errorf("in_hot_standby = %q, want off", got)
	}
	if got := attrOr(node, AttrDefaultTransactionReadOnly); got != "off" {
		t.Errorf("default_transaction_read_only = %q, want off", got)
	}
	if got := attrOr(node, AttrIsSuperuser); got != "on" {
		t.Errorf("is_superuser = %q, want on", got)
	}

	// Parented to the authentication node, and authentication stays PASS.
	g := freeze(t, builder)
	auth := nodeFor(t, g, StepAuthentication)
	if !hasParent(g, node.ID(), auth.ID()) {
		t.Error("the session node is not parented to the authentication node")
	}
	if auth.State() != domain.StatePass {
		t.Errorf("authentication state = %s, want PASS", auth.State())
	}
	if got := peer.connections(); got != 1 {
		t.Errorf("peer accepted %d connections, want 1", got)
	}
}

func TestSessionWithNoParametersAtAll(t *testing.T) {
	result, builder, _ := establishOver(t, scramScript{trailing: readyForQueryFrame('I')})

	if result == nil {
		t.Fatal("a bare ReadyForQuery produced no result")
	}
	node := requireSession(t, builder, domain.StatePass, domain.FailureNone)
	for _, key := range []domain.AttributeKey{
		AttrServerVersion, AttrInHotStandby, AttrDefaultTransactionReadOnly, AttrIsSuperuser,
	} {
		if _, present := node.Attributes()[key]; present {
			t.Errorf("%s was recorded although no ParameterStatus arrived", key)
		}
	}
	if got := attrOr(node, AttrTransactionStatus); got != "idle" {
		t.Errorf("transaction status = %q, want idle", got)
	}
}

// TestNonIdleTransactionStatusIsAFactNotAFailure pins that reaching the boundary
// is what passes, and the byte is an observation about the session.
func TestNonIdleTransactionStatusIsAFactNotAFailure(t *testing.T) {
	for status, want := range map[byte]string{
		'I': "idle", 'T': "in-transaction", 'E': "failed-transaction",
	} {
		t.Run(want, func(t *testing.T) {
			result, builder, _ := establishOver(t, scramScript{
				trailing: readyForQueryFrame(status),
			})
			if result == nil {
				t.Fatalf("status %q did not produce a session", status)
			}
			node := requireSession(t, builder, domain.StatePass, domain.FailureNone)
			if got := attrOr(node, AttrTransactionStatus); got != want {
				t.Errorf("transaction status = %q, want %q", got, want)
			}
		})
	}
}

// --- the ParameterStatus allowlist -----------------------------------------

// TestParameterAllowlistIsExactlyFourKeys is the cardinality guard. A fifth key
// added during implementation fails here before any reviewer sees it.
func TestParameterAllowlistIsExactlyFourKeys(t *testing.T) {
	var everything []byte
	for _, kv := range [][2]string{
		// The four.
		{"server_version", canaryServerVersion},
		{"in_hot_standby", "on"},
		{"default_transaction_read_only", "on"},
		{"is_superuser", "off"},
		// Identity, and must never appear.
		{"session_authorization", canaryRole},
		{"search_path", canarySearchPath},
		// No consumer, and must never appear.
		{"application_name", "svcdoctor-canary"},
		{"client_encoding", "UTF8"},
		{"server_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"},
		{"IntervalStyle", "postgres"},
		{"TimeZone", "Etc/UTC"},
		{"integer_datetimes", "on"},
		{"standard_conforming_strings", "on"},
		{"scram_iterations", "4096"},
		{"lc_monetary", "en_US.UTF-8"},
		{"custom.qk7z_setting", "leak-me-if-you-can"},
	} {
		everything = append(everything, paramStatusFrame(kv[0], kv[1])...)
	}
	everything = append(everything, readyForQueryFrame('I')...)

	_, builder, _ := establishOver(t, scramScript{trailing: everything})
	node := requireSession(t, builder, domain.StatePass, domain.FailureNone)

	want := map[domain.AttributeKey]string{
		AttrServerVersion:              canaryServerVersion,
		AttrInHotStandby:               "on",
		AttrDefaultTransactionReadOnly: "on",
		AttrIsSuperuser:                "off",
		AttrTransactionStatus:          "idle",
	}
	got := node.Attributes()
	if len(got) != len(want) {
		t.Fatalf("session node has %d attributes, want exactly %d: %+v", len(got), len(want), got)
	}
	for key, value := range want {
		if attrOr(node, key) != value {
			t.Errorf("%s = %q, want %q", key, attrOr(node, key), value)
		}
	}
}

// TestDroppedParametersReachNothing plants canaries in every parameter the
// allowlist excludes and proves none survives anywhere a reader could see.
func TestDroppedParametersReachNothing(t *testing.T) {
	var burst []byte
	burst = append(burst, paramStatusFrame("session_authorization", canaryRole)...)
	burst = append(burst, paramStatusFrame("search_path", canarySearchPath)...)
	burst = append(burst, paramStatusFrame("application_name", "APPNAME-CANARY-QK7z")...)
	burst = append(burst, paramStatusFrame("custom.secret_guc", "GUC-CANARY-QK7z")...)
	burst = append(burst, readyForQueryFrame('I')...)

	_, builder, _ := establishOver(t, scramScript{trailing: burst})
	node := sessionNode(t, builder)

	surfaces := map[string]string{
		"report JSON":     encodeJSON(t, pgReportFrom(t, builder)),
		"node JSON":       encodeJSON(t, node),
		"node attributes": fmt.Sprintf("%+v", node.Attributes()),
		"graph":           fmt.Sprintf("%+v", freeze(t, builder).Nodes()),
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s"} {
		surfaces["node "+verb] = fmt.Sprintf(verb, node)
	}

	for surface, text := range surfaces {
		for _, canary := range []string{
			canaryRole, canarySearchPath, "APPNAME-CANARY-QK7z",
			"GUC-CANARY-QK7z", "schema_QK7z_internal", "$user",
		} {
			if strings.Contains(text, canary) {
				t.Errorf("%s contains the dropped value %q", surface, canary)
			}
		}
	}
}

// TestRepeatedParameterTakesTheLastValue pins the duplicate rule.
//
// A ParameterStatus reports what a parameter *is*, and a later frame supersedes
// an earlier one. This is deliberately the opposite of DecodeErrorFields, where
// duplicates are fields inside one message and the first wins.
func TestRepeatedParameterTakesTheLastValue(t *testing.T) {
	var burst []byte
	burst = append(burst, paramStatusFrame("in_hot_standby", "off")...)
	burst = append(burst, paramStatusFrame("server_version", "OLD-VALUE")...)
	burst = append(burst, paramStatusFrame("in_hot_standby", "on")...)
	burst = append(burst, paramStatusFrame("server_version", "NEW-VALUE")...)
	burst = append(burst, readyForQueryFrame('I')...)

	_, builder, _ := establishOver(t, scramScript{trailing: burst})
	node := requireSession(t, builder, domain.StatePass, domain.FailureNone)

	if got := attrOr(node, AttrInHotStandby); got != "on" {
		t.Errorf("in_hot_standby = %q, want the later value on", got)
	}
	if got := attrOr(node, AttrServerVersion); got != "NEW-VALUE" {
		t.Errorf("server_version = %q, want the later value", got)
	}
}

// --- partial observations ---------------------------------------------------

// TestObservedParametersSurviveAFailure is the TLS precedent applied here: an
// attribute appears when the observation produced it, whatever the outcome.
func TestObservedParametersSurviveAFailure(t *testing.T) {
	t.Run("failure", func(t *testing.T) {
		var burst []byte
		burst = append(burst, paramStatusFrame("server_version", canaryServerVersion)...)
		burst = append(burst, paramStatusFrame("in_hot_standby", "on")...)
		burst = append(burst, errorFrame("S", "FATAL", "V", "FATAL", "C", "3D000")...)

		_, builder, _ := establishOver(t, scramScript{trailing: burst})
		node := requireSession(t, builder, domain.StateFail, domain.FailureResourceNotFound)

		if got := attrOr(node, AttrServerVersion); got != canaryServerVersion {
			t.Errorf("server_version = %q; an observed fact was discarded", got)
		}
		if got := attrOr(node, AttrInHotStandby); got != "on" {
			t.Errorf("in_hot_standby = %q; an observed fact was discarded", got)
		}
		// Nothing is fabricated for what was never seen.
		if _, present := node.Attributes()[AttrIsSuperuser]; present {
			t.Error("is_superuser was recorded although no such frame arrived")
		}
		if _, present := node.Attributes()[AttrTransactionStatus]; present {
			t.Error("a transaction status was recorded although ReadyForQuery never arrived")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		var burst []byte
		burst = append(burst, paramStatusFrame("server_version", canaryServerVersion)...)
		burst = append(burst, paramStatusFrame("in_hot_standby", "on")...)

		session, builder, _ := authenticated(t, scramScript{
			trailing: burst,
			postAuth: func(net.Conn) { time.Sleep(3 * time.Second) },
		})

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()

		result, err := EstablishSession(ctx, builder, session, SessionParams{})
		if err != nil {
			t.Fatalf("EstablishSession: %v", err)
		}
		if result != nil {
			t.Fatal("a timed-out window produced a session result")
		}

		node := sessionNode(t, builder)
		if node.State() != domain.StateUnknown {
			t.Fatalf("state = %s, want UNKNOWN", node.State())
		}
		if got := attrOr(node, AttrServerVersion); got != canaryServerVersion {
			t.Errorf("server_version = %q; an observed fact was discarded on UNKNOWN", got)
		}
		if got := attrOr(node, AttrInHotStandby); got != "on" {
			t.Errorf("in_hot_standby = %q; an observed fact was discarded on UNKNOWN", got)
		}
	})
}

// --- BackendKeyData ---------------------------------------------------------

func TestBackendKeyDataIsDiscardedWhole(t *testing.T) {
	// A key frame whose bytes are unmistakable, so absence is a real assertion.
	key := pgFrame('K', []byte{0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF})

	var burst []byte
	burst = append(burst, key...)
	burst = append(burst, readyForQueryFrame('I')...)

	result, builder, _ := establishOver(t, scramScript{trailing: burst})
	if result == nil {
		t.Fatal("a session with BackendKeyData did not pass")
	}
	node := requireSession(t, builder, domain.StatePass, domain.FailureNone)

	encoded := encodeJSON(t, pgReportFrom(t, builder))
	shareable := encodeJSON(t, redactReport(t, builder))
	rendered := fmt.Sprintf("%+v %+v", node, node.Attributes())

	for _, surface := range []string{encoded, shareable, rendered} {
		for _, canary := range []string{
			"3405691582", "3735928559", // the two 32-bit halves, decimal
			"cafebabe", "deadbeef", "CAFEBABE", "DEADBEEF",
		} {
			if strings.Contains(surface, canary) {
				t.Errorf("a BackendKeyData value (%s) reached output", canary)
			}
		}
	}
}

func TestMalformedFramesAreMalformed(t *testing.T) {
	tests := []struct {
		name    string
		trailer []byte
	}{
		{"BackendKeyData too short", pgFrame('K', []byte{1, 2, 3})},
		{"ParameterStatus with no terminator", pgFrame('S', []byte("in_hot_standby\x00on"))},
		{"ParameterStatus with no separator", pgFrame('S', []byte("in_hot_standby"))},
		{"ParameterStatus with surplus bytes", pgFrame('S', []byte("in_hot_standby\x00on\x00extra"))},
		{"ReadyForQuery with no status", pgFrame('Z', nil)},
		{"ReadyForQuery with two bytes", pgFrame('Z', []byte("II"))},
		{"ReadyForQuery with an invalid status", pgFrame('Z', []byte{'X'})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, builder, _ := establishOver(t, scramScript{trailing: tt.trailer})
			if result != nil {
				t.Fatal("a malformed frame produced a session result")
			}
			requireSession(t, builder,
				domain.StateFail, domain.FailureProtocolMalformedResponse)
		})
	}
}

// --- SQLSTATE, scoped to this step ------------------------------------------

func TestSessionSQLStateClassification(t *testing.T) {
	tests := []struct {
		name     string
		sqlState string
		class    domain.FailureClass
	}{
		{"unknown database", "3D000", domain.FailureResourceNotFound},
		{"CONNECT denied", "42501", domain.FailureAuthzDenied},
		// Phase 8.1 (ADR 0069): the peer names this ceiling itself, so it is no
		// longer the weak class. Nothing else about 53300 moved — the finding,
		// the severity and the Phase 7.3A detail sentence are unchanged.
		{"connection slots exhausted", "53300", domain.FailureResourceLimitReached},
		{"a pooler's default code", "08P01", domain.FailureProtocolUnexpectedResponse},
		{"cannot connect now", "57P03", domain.FailureProtocolUnexpectedResponse},
		{"an authentication code arriving here", "28P01", domain.FailureProtocolUnexpectedResponse},
		{"anything unmapped", "XX000", domain.FailureProtocolUnexpectedResponse},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, builder, _ := establishOver(t, scramScript{
				trailing: errorFrame("S", "FATAL", "V", "FATAL", "C", tt.sqlState),
			})
			if result != nil {
				t.Fatal("an ErrorResponse produced a session result")
			}
			node := requireSession(t, builder, domain.StateFail, tt.class)

			if got := attrOr(node, AttrSQLState); got != tt.sqlState {
				t.Errorf("sqlstate = %q, want %q", got, tt.sqlState)
			}
			if got := attrOr(node, AttrErrorSeverity); got != "FATAL" {
				t.Errorf("severity = %q, want FATAL", got)
			}
		})
	}
}

// TestSQLStateMeaningIsScopedToItsStep is the architectural guard, and it is the
// reason the three classifiers are not one.
//
// A test asserting only `3D000 -> RESOURCE_NOT_FOUND` would pass against a
// global lookup table. These rows are the ones that would not: the same code
// arriving where its meaning is not established stays at the honest weak class.
func TestSQLStateMeaningIsScopedToItsStep(t *testing.T) {
	tests := []struct {
		sqlState string
		session  domain.FailureClass
		startup  domain.FailureClass
		auth     domain.FailureClass
	}{
		{
			sqlState: "3D000",
			session:  domain.FailureResourceNotFound,
			startup:  domain.FailureProtocolUnexpectedResponse,
			auth:     domain.FailureProtocolUnexpectedResponse,
		},
		{
			sqlState: "42501",
			session:  domain.FailureAuthzDenied,
			startup:  domain.FailureProtocolUnexpectedResponse,
			auth:     domain.FailureProtocolUnexpectedResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.sqlState, func(t *testing.T) {
			if got := sessionSQLStateFailure(tt.sqlState); got != tt.session {
				t.Errorf("session step: %s = %s, want %s", tt.sqlState, got, tt.session)
			}
			if got := sqlStateFailure(tt.sqlState); got != tt.startup {
				t.Errorf("startup step: %s = %s, want %s — a stronger class leaked "+
					"into a step that does not prove it", tt.sqlState, got, tt.startup)
			}
			if got := authSQLStateFailure(tt.sqlState); got != tt.auth {
				t.Errorf("authentication step: %s = %s, want %s — a stronger class "+
					"leaked into a step that does not prove it", tt.sqlState, got, tt.auth)
			}
		})
	}
}

// TestEachStepHasItsOwnClassifier makes the "refactor them into one dictionary"
// change expensive rather than invisible.
func TestEachStepHasItsOwnClassifier(t *testing.T) {
	for _, want := range []struct{ path, symbol string }{
		{"startup.go", "func sqlStateFailure("},
		{"authenticate.go", "func authSQLStateFailure("},
		{"establish.go", "func sessionSQLStateFailure("},
	} {
		body := readSource(t, want.path)
		if !strings.Contains(body, want.symbol) {
			t.Fatalf("%s is not in %s: SQLSTATE classification must stay per step, "+
				"and a shared table is a rejected alternative (ADR 0039 section 7.1)",
				want.symbol, want.path)
		}
	}
}

// --- frames a real server does not send -------------------------------------

func TestNoticeResponseIsSkippedAndItsProseNeverLands(t *testing.T) {
	const (
		noticeMessage = "NOTICE-CANARY-QK7z role payments_writer from 192.168.65.1"
		noticeDetail  = "DETAIL-CANARY-QK7z /var/lib/postgresql/pg_hba.conf"
		noticeHint    = "HINT-CANARY-QK7z contact dba@corp.internal"
	)

	var burst []byte
	// Both notices carry a full field set on purpose. An earlier version gave
	// the second one only S and M, and that silently defused the test: an
	// implementation that *did* decode notices would have had its first
	// (canary-bearing) decode overwritten by the second (empty) one, and the
	// assertions below would have passed against broken code. The mutation
	// matrix caught it.
	notice := func() []byte {
		return noticeFrame(
			"S", "NOTICE", "V", "NOTICE", "C", "01000",
			"M", noticeMessage, "D", noticeDetail, "H", noticeHint)
	}
	burst = append(burst, notice()...)
	burst = append(burst, paramStatusFrame("in_hot_standby", "off")...)
	burst = append(burst, notice()...)
	burst = append(burst, readyForQueryFrame('I')...)

	result, builder, _ := establishOver(t, scramScript{trailing: burst})
	if result == nil {
		t.Fatal("a notice made the session fail")
	}
	node := requireSession(t, builder, domain.StatePass, domain.FailureNone)

	// A notice is not an error: nothing from its field list may land.
	for _, key := range []domain.AttributeKey{
		AttrSQLState, AttrErrorSeverity, AttrErrorIsNative,
	} {
		if _, present := node.Attributes()[key]; present {
			t.Errorf("a NoticeResponse produced the %s attribute", key)
		}
	}

	encoded := encodeJSON(t, pgReportFrom(t, builder))
	for _, canary := range []string{
		noticeMessage, noticeDetail, noticeHint,
		"NOTICE-CANARY-QK7z", "dba@corp.internal", "192.168.65.1", "01000",
	} {
		if strings.Contains(encoded, canary) {
			t.Errorf("notice content %q reached the report", canary)
		}
	}
}

func TestUnknownFrameTypesAreRefused(t *testing.T) {
	for _, kind := range []byte{'T', 'D', 'C', 'A', 'n', 'q', 0x00, 0xFF} {
		t.Run(fmt.Sprintf("%q", kind), func(t *testing.T) {
			result, builder, _ := establishOver(t, scramScript{
				trailing: rawFrame(kind, []byte("payload")),
			})
			if result != nil {
				t.Fatalf("frame type %q produced a session result", kind)
			}
			requireSession(t, builder,
				domain.StateFail, domain.FailureProtocolUnexpectedResponse)
		})
	}
}

// --- lifecycle --------------------------------------------------------------

func TestPeerCloseBeforeReadyForQuery(t *testing.T) {
	result, builder, _ := establishOver(t, scramScript{
		trailing: paramStatusFrame("in_hot_standby", "off"),
		postAuth: func(conn net.Conn) { _ = conn.Close() },
	})
	if result != nil {
		t.Fatal("a closed peer produced a session result")
	}
	requireSession(t, builder, domain.StateFail, domain.FailureProtocolPeerClosed)
}

func TestSessionCancellationIsNotAPeerFailure(t *testing.T) {
	session, builder, _ := authenticated(t, scramScript{
		postAuth: func(net.Conn) { time.Sleep(3 * time.Second) },
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	result, err := EstablishSession(ctx, builder, session, SessionParams{})
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	if result != nil {
		t.Fatal("a cancelled window produced a session result")
	}
	if got := sessionNode(t, builder).State(); got != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", got)
	}
}

// TestSessionIsTerminal proves the connection never escapes and closes exactly
// once, on every outcome.
func TestSessionIsTerminal(t *testing.T) {
	for _, tt := range []struct {
		name    string
		trailer []byte
	}{
		{"success", healthySession()},
		{"error", errorFrame("S", "FATAL", "C", "3D000")},
		{"malformed", pgFrame('Z', []byte("XX"))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			session, builder, peer := authenticated(t, scramScript{trailing: tt.trailer})

			result, err := EstablishSession(
				context.Background(), builder, session, SessionParams{})
			if err != nil {
				t.Fatalf("EstablishSession: %v", err)
			}

			// The session was consumed, whatever happened.
			if session.Available() {
				t.Error("the authenticated session still offers a connection")
			}
			if _, ok := session.TakeConn(); ok {
				t.Error("the connection could be taken after the step consumed it")
			}
			// Close after the step is a no-op, not a double close.
			for range 3 {
				if err := session.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
			}
			if got := peer.connections(); got != 1 {
				t.Errorf("peer accepted %d connections, want 1 — something redialled", got)
			}

			// SessionResult exposes an endpoint and an evidence identifier, and
			// nothing that could carry a socket.
			if result != nil && result.Endpoint() == "" {
				t.Error("a passing result carries no endpoint")
			}
		})
	}
}

// --- Terminate --------------------------------------------------------------

func TestHealthySessionSendsTerminate(t *testing.T) {
	_, _, peer := establishOver(t, scramScript{trailing: healthySession()})

	// Give the peer's reader a moment to see it.
	time.Sleep(250 * time.Millisecond)
	sent := peer.afterStartup()

	want := []byte{'X', 0, 0, 0, 4}
	if !strings.HasSuffix(string(sent), string(want)) {
		t.Fatalf("the peer's last bytes were %q, want a Terminate %q",
			tail(sent, 8), want)
	}
}

func TestFailedSessionSendsNoTerminate(t *testing.T) {
	_, _, peer := establishOver(t, scramScript{
		trailing: errorFrame("S", "FATAL", "C", "3D000"),
	})

	time.Sleep(250 * time.Millisecond)
	if strings.HasSuffix(string(peer.afterStartup()), string([]byte{'X', 0, 0, 0, 4})) {
		t.Error("Terminate was sent for a session that never reached ReadyForQuery")
	}
}

// TestTerminateFailureDoesNotUnmakeTheSession pins that a courtesy message that
// could not be delivered does not rewrite an outcome the peer already gave.
func TestTerminateFailureDoesNotUnmakeTheSession(t *testing.T) {
	result, builder, _ := establishOver(t, scramScript{
		trailing: healthySession(),
		// The peer hangs up the instant it has sent ReadyForQuery, so the
		// Terminate write lands on a closed socket.
		postAuth: func(conn net.Conn) { _ = conn.Close() },
	})

	if result == nil {
		t.Fatal("the session was reported as failed because Terminate could not be written")
	}
	requireSession(t, builder, domain.StatePass, domain.FailureNone)
}

// --- input validation -------------------------------------------------------

func TestEstablishSessionRejectsUnusableInput(t *testing.T) {
	session, builder, _ := authenticated(t, scramScript{trailing: healthySession()})

	//nolint:staticcheck // deliberately nil, to prove the guard exists.
	if _, err := EstablishSession(nil, builder, session, SessionParams{}); err == nil {
		t.Error("a nil context was accepted")
	}
	if _, err := EstablishSession(context.Background(), nil, session, SessionParams{}); err == nil {
		t.Error("a nil builder was accepted")
	}
	if _, err := EstablishSession(context.Background(), builder, nil, SessionParams{}); err == nil {
		t.Error("a nil session was accepted")
	}
	if _, err := EstablishSession(context.Background(), builder, session, SessionParams{
		ReadTimeout: -time.Second,
	}); err == nil {
		t.Error("a negative timeout was accepted")
	}
}

// --- determinism ------------------------------------------------------------

// TestSessionOutputIsStableAcrossParameterOrder proves the canonical report does
// not depend on the order the server happened to send parameters in.
func TestSessionOutputIsStableAcrossParameterOrder(t *testing.T) {
	forward := [][2]string{
		{"server_version", canaryServerVersion},
		{"in_hot_standby", "on"},
		{"default_transaction_read_only", "off"},
		{"is_superuser", "on"},
	}
	reversed := [][2]string{forward[3], forward[2], forward[1], forward[0]}

	render := func(order [][2]string) string {
		var burst []byte
		for _, kv := range order {
			burst = append(burst, paramStatusFrame(kv[0], kv[1])...)
		}
		burst = append(burst, readyForQueryFrame('I')...)

		_, builder, _ := establishOver(t, scramScript{trailing: burst})
		return fmt.Sprintf("%+v", sessionNode(t, builder).Attributes())
	}

	if a, b := render(forward), render(reversed); a != b {
		t.Errorf("attribute set depends on frame order:\n %s\n %s", a, b)
	}
}

func tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}
