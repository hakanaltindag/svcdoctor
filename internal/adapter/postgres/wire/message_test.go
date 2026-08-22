package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// --- framing -----------------------------------------------------------------

// TestReadMessageFraming covers the envelope: a length that includes itself, a
// body that does not, and the boundaries either side.
func TestReadMessageFraming(t *testing.T) {
	cases := []struct {
		name     string
		raw      []byte
		wantType byte
		wantBody []byte
		wantErr  error
	}{
		{
			name:     "empty body is legal",
			raw:      []byte{'R', 0, 0, 0, 4},
			wantType: 'R',
			wantBody: nil,
		},
		{
			name:     "ordinary body",
			raw:      frame('R', []byte{0, 0, 0, 0}),
			wantType: 'R',
			wantBody: []byte{0, 0, 0, 0},
		},
		{
			name:     "unknown type is returned, not rejected",
			raw:      frame('Z', []byte{'I'}),
			wantType: 'Z',
			wantBody: []byte{'I'},
		},
		{
			// The length counts itself, so 3 cannot describe a frame and the
			// subtraction that follows would wrap.
			name:    "length below the header size",
			raw:     []byte{'R', 0, 0, 0, 3},
			wantErr: ErrMalformedMessage,
		},
		{
			name:    "length zero",
			raw:     []byte{'R', 0, 0, 0, 0},
			wantErr: ErrMalformedMessage,
		},
		{
			name:    "length one",
			raw:     []byte{'R', 0, 0, 0, 1},
			wantErr: ErrMalformedMessage,
		},
		{
			// Announced four gibibytes. Refused before anything is allocated.
			name:    "length beyond what svcdoctor will read",
			raw:     []byte{'R', 0xFF, 0xFF, 0xFF, 0xFF},
			wantErr: ErrFrameTooLarge,
		},
		{
			name:    "truncated header",
			raw:     []byte{'R', 0, 0},
			wantErr: ErrPeerClosed,
		},
		{
			name:    "body shorter than announced",
			raw:     []byte{'R', 0, 0, 0, 20, 1, 2, 3},
			wantErr: ErrPeerClosed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := scriptedPeer(t, func(conn net.Conn, _ *peer) {
				defer conn.Close()
				_, _ = conn.Write(tc.raw)
				time.Sleep(200 * time.Millisecond)
			})

			msg, err := ReadMessage(testContext(t), p.dial(t))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadMessage: %v", err)
			}
			if msg.Type != tc.wantType {
				t.Errorf("type = %q, want %q", msg.Type, tc.wantType)
			}
			if !bytes.Equal(msg.Body, tc.wantBody) {
				t.Errorf("body = % x, want % x", msg.Body, tc.wantBody)
			}
		})
	}
}

// TestOversizedFrameAllocatesNothing proves the size check happens before the
// allocation rather than after it.
//
// A peer announcing a huge body must cost svcdoctor the five header bytes and
// nothing else. The peer here sends only the header, so a reader that allocated
// first and read second would block waiting for gigabytes that never arrive.
func TestOversizedFrameAllocatesNothing(t *testing.T) {
	header := []byte{'R', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[1:5], MaxMessageSize+5)

	p := scriptedPeer(t, func(conn net.Conn, _ *peer) {
		defer conn.Close()
		_, _ = conn.Write(header)
		time.Sleep(300 * time.Millisecond)
	})

	done := make(chan error, 1)
	go func() {
		_, err := ReadMessage(testContext(t), p.dial(t))
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Errorf("err = %v, want ErrFrameTooLarge", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadMessage blocked waiting for a body it should have refused")
	}
}

// TestSequentialMessages proves one message does not consume the next, which is
// what lets the startup loop skip notices.
func TestSequentialMessages(t *testing.T) {
	p := scriptedPeer(t, func(conn net.Conn, _ *peer) {
		defer conn.Close()
		_, _ = conn.Write(frame(MsgNoticeResponse, errorFields("C", "00000")))
		_, _ = conn.Write(authFrame(0, nil))
		time.Sleep(300 * time.Millisecond)
	})

	conn := p.dial(t)
	ctx := testContext(t)

	first, err := ReadMessage(ctx, conn)
	if err != nil {
		t.Fatalf("first ReadMessage: %v", err)
	}
	if first.Type != MsgNoticeResponse {
		t.Fatalf("first type = %q, want %q", first.Type, MsgNoticeResponse)
	}

	second, err := ReadMessage(ctx, conn)
	if err != nil {
		t.Fatalf("second ReadMessage: %v", err)
	}
	if second.Type != MsgAuthentication {
		t.Errorf("second type = %q, want %q", second.Type, MsgAuthentication)
	}
}

// --- ErrorResponse -----------------------------------------------------------

// hostileFields is an ErrorResponse shaped like one a real server sends, with
// every discarded field carrying a canary.
//
// The message field is modelled on a real capture from the Phase 4.0 study,
// which contained the role, the database and svcdoctor's own NAT source address
// as the server observed it — an address appearing nowhere else in a report, so
// no structural redaction could pseudonymize it.
var hostileFields = []string{
	"S", "FATAL",
	"V", "FATAL",
	"C", "28000",
	"M", `no pg_hba.conf entry for host "203.0.113.77", user "payments_writer", database "payments_prod"`,
	"D", "DETAIL-CANARY: /var/lib/postgresql/data/pg_hba.conf line 42",
	"H", "HINT-CANARY: contact dba@corp.internal",
	"P", "1",
	"q", "SELECT secret FROM vault",
	"W", "WHERE-CANARY",
	"s", "SCHEMA-CANARY",
	"t", "TABLE-CANARY",
	"c", "COLUMN-CANARY",
	"d", "DATATYPE-CANARY",
	"n", "CONSTRAINT-CANARY",
	"F", "auth.c",
	"L", "530",
	"R", "ClientAuthentication",
}

// canaries lists every value that must not survive decoding.
var canaries = []string{
	"pg_hba.conf", "203.0.113.77", "payments_writer", "payments_prod",
	"DETAIL-CANARY", "HINT-CANARY", "WHERE-CANARY", "SCHEMA-CANARY",
	"TABLE-CANARY", "COLUMN-CANARY", "DATATYPE-CANARY", "CONSTRAINT-CANARY",
	"auth.c", "ClientAuthentication", "vault", "dba@corp.internal",
}

// TestErrorResponseRetainsOnlyTheApprovedFields is the whitelist proof.
//
// It decodes a message carrying every field a real server can send and checks
// that the two retained values are right and that nothing else survived — not
// into a field, because there is no field to survive into.
func TestErrorResponseRetainsOnlyTheApprovedFields(t *testing.T) {
	got, err := DecodeErrorFields(errorFields(hostileFields...))
	if err != nil {
		t.Fatalf("DecodeErrorFields: %v", err)
	}

	if got.SQLState != "28000" {
		t.Errorf("SQLState = %q, want %q", got.SQLState, "28000")
	}
	if got.Severity != "FATAL" {
		t.Errorf("Severity = %q, want %q", got.Severity, "FATAL")
	}
	if !got.Native {
		t.Error("Native = false, but the message carried a V field")
	}

	// Every string field the struct holds, found by reflection rather than named
	// one by one. Naming them would make this test blind to a field somebody
	// adds later, which is exactly the change it exists to catch.
	all := flattenStrings(t, got)
	for _, canary := range canaries {
		if strings.Contains(all, canary) {
			t.Errorf("canary %q survived decoding into %q", canary, all)
		}
	}
}

// flattenStrings joins every string-typed field of v, including ones added after
// this test was written.
func flattenStrings(t *testing.T, v ErrorFields) string {
	t.Helper()

	rv := reflect.ValueOf(v)
	var b strings.Builder
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).Kind() == reflect.String {
			b.WriteString(rv.Field(i).String())
			b.WriteByte(0)
		}
	}
	return b.String()
}

// TestErrorFieldsHoldsOnlyTheApprovedShape is the structural half of the
// whitelist.
//
// The absence of a Message field is the mechanism, not a promise, so the shape
// of the struct is contract. Adding a field here is a visible change that must
// come with a reason.
func TestErrorFieldsHoldsOnlyTheApprovedShape(t *testing.T) {
	want := map[string]reflect.Kind{
		"SQLState": reflect.String,
		"Severity": reflect.String,
		"Native":   reflect.Bool,
	}

	rt := reflect.TypeOf(ErrorFields{})
	if rt.NumField() != len(want) {
		t.Fatalf("ErrorFields has %d fields, want %d: a field was added without a "+
			"decision. ADR 0036 section 6 retains only C and V", rt.NumField(), len(want))
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		kind, approved := want[f.Name]
		if !approved {
			t.Errorf("ErrorFields has an unapproved field %q", f.Name)
			continue
		}
		if f.Type.Kind() != kind {
			t.Errorf("field %s is %s, want %s", f.Name, f.Type.Kind(), kind)
		}
	}
}

// TestErrorResponseFieldCombinations covers what arrives when a peer sends less
// than a full backend does.
func TestErrorResponseFieldCombinations(t *testing.T) {
	cases := []struct {
		name         string
		pairs        []string
		wantSQLState string
		wantSeverity string
		wantNative   bool
	}{
		{"code and severity", []string{"C", "0A000", "V", "FATAL"}, "0A000", "FATAL", true},
		{"code only", []string{"C", "3D000"}, "3D000", "", false},
		{"severity only", []string{"V", "ERROR"}, "", "ERROR", true},
		{
			// A pooler sends a localized severity and no V. Native records that.
			name:         "localized severity without V",
			pairs:        []string{"S", "FATAL", "C", "08P01", "M", "SASL authentication failed"},
			wantSQLState: "08P01",
			wantNative:   false,
		},
		{
			// S must never be promoted into Severity: it may be translated.
			name:         "localized severity is not a substitute",
			pairs:        []string{"S", "SCHWERWIEGEND", "C", "28P01"},
			wantSQLState: "28P01",
			wantNative:   false,
		},
		{"first code wins", []string{"C", "28000", "C", "00000"}, "28000", "", false},
		{"first severity wins", []string{"V", "FATAL", "V", "LOG"}, "", "FATAL", true},
		{"malformed sqlstate is dropped", []string{"C", "TOO-LONG-FOR-A-CODE"}, "", "", false},
		{"unknown severity keeps native", []string{"V", "CATACLYSM"}, "", "", true},
		{"empty body", nil, "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeErrorFields(errorFields(tc.pairs...))
			if err != nil {
				t.Fatalf("DecodeErrorFields: %v", err)
			}
			if got.SQLState != tc.wantSQLState {
				t.Errorf("SQLState = %q, want %q", got.SQLState, tc.wantSQLState)
			}
			if got.Severity != tc.wantSeverity {
				t.Errorf("Severity = %q, want %q", got.Severity, tc.wantSeverity)
			}
			if got.Native != tc.wantNative {
				t.Errorf("Native = %v, want %v", got.Native, tc.wantNative)
			}
		})
	}
}

// TestErrorResponseMalformed rejects a field list the sender did not finish.
func TestErrorResponseMalformed(t *testing.T) {
	cases := map[string][]byte{
		"value without a terminator":    {'C', '2', '8', '0', '0', '0'},
		"field list without terminator": append([]byte{'C'}, append([]byte("28000"), 0)...),
		"type byte with nothing after":  {'C'},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeErrorFields(body); !errors.Is(err, ErrMalformedMessage) {
				t.Errorf("err = %v, want ErrMalformedMessage", err)
			}
		})
	}
}

// --- Authentication ----------------------------------------------------------

// TestDecodeAuthRequest identifies what a server demanded without performing any
// of it.
func TestDecodeAuthRequest(t *testing.T) {
	cases := []struct {
		name       string
		body       []byte
		wantMethod AuthMethod
		wantName   string
		wantMechs  []string
	}{
		{"ok", binary.BigEndian.AppendUint32(nil, 0), AuthMethodOK, "ok", nil},
		{"cleartext", binary.BigEndian.AppendUint32(nil, 3), AuthMethodCleartextPassword, "cleartext", nil},
		{
			name:       "md5 with salt",
			body:       append(binary.BigEndian.AppendUint32(nil, 5), 1, 2, 3, 4),
			wantMethod: AuthMethodMD5Password,
			wantName:   "md5",
		},
		{"gss", binary.BigEndian.AppendUint32(nil, 7), AuthMethodGSS, "gss", nil},
		{"sspi", binary.BigEndian.AppendUint32(nil, 9), AuthMethodSSPI, "sspi", nil},
		{"kerberos", binary.BigEndian.AppendUint32(nil, 2), AuthMethodKerberosV5, "kerberos", nil},
		{
			// The channel-dependent list: a real server offers PLUS only over TLS.
			name:       "sasl over tls",
			body:       saslBody("SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"),
			wantMethod: AuthMethodSASL,
			wantName:   "sasl",
			wantMechs:  []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"},
		},
		{
			name:       "sasl plaintext",
			body:       saslBody("SCRAM-SHA-256"),
			wantMethod: AuthMethodSASL,
			wantName:   "sasl",
			wantMechs:  []string{"SCRAM-SHA-256"},
		},
		{
			// A future method must be reported, not rejected.
			name:       "unrecognized code",
			body:       binary.BigEndian.AppendUint32(nil, 99),
			wantMethod: AuthMethodUnknown,
			wantName:   "unknown",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeAuthRequest(tc.body)
			if err != nil {
				t.Fatalf("DecodeAuthRequest: %v", err)
			}
			if got.Method != tc.wantMethod {
				t.Errorf("method = %v, want %v", got.Method, tc.wantMethod)
			}
			if got.Method.String() != tc.wantName {
				t.Errorf("name = %q, want %q", got.Method.String(), tc.wantName)
			}
			if len(got.Mechanisms) != len(tc.wantMechs) {
				t.Fatalf("mechanisms = %v, want %v", got.Mechanisms, tc.wantMechs)
			}
			for i := range tc.wantMechs {
				if got.Mechanisms[i] != tc.wantMechs[i] {
					t.Errorf("mechanism %d = %q, want %q", i, got.Mechanisms[i], tc.wantMechs[i])
				}
			}
		})
	}
}

// TestDecodeAuthRequestMalformed rejects bodies that cannot be read.
func TestDecodeAuthRequestMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":                  {},
		"short code":             {0, 0, 0},
		"sasl list unterminated": append(binary.BigEndian.AppendUint32(nil, 10), []byte("SCRAM")...),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAuthRequest(body); !errors.Is(err, ErrMalformedMessage) {
				t.Errorf("err = %v, want ErrMalformedMessage", err)
			}
		})
	}
}

// TestAuthRequestCarriesNoChallengeData is a scope guard.
//
// The MD5 salt and any SASL payload are on the wire and are deliberately not
// retained: nothing in this phase answers a challenge, and a field holding
// challenge material would be a half-built authentication engine.
func TestAuthRequestCarriesNoChallengeData(t *testing.T) {
	const saltCanary = "\xDE\xAD\xBE\xEF"

	got, err := DecodeAuthRequest(append(binary.BigEndian.AppendUint32(nil, 5), saltCanary...))
	if err != nil {
		t.Fatalf("DecodeAuthRequest: %v", err)
	}
	if got.Method != AuthMethodMD5Password {
		t.Fatalf("method = %v, want md5", got.Method)
	}

	// The struct has three fields; none may hold the salt.
	if strings.Contains(strings.Join(got.Mechanisms, ""), saltCanary) {
		t.Error("the MD5 salt was retained in the mechanism list")
	}
}

func saslBody(mechanisms ...string) []byte {
	body := binary.BigEndian.AppendUint32(nil, 10)
	for _, m := range mechanisms {
		body = append(body, m...)
		body = append(body, 0)
	}
	return append(body, 0)
}
