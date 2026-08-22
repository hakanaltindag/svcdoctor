package wire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// decodeStartup reads a StartupMessage back without using the encoder, so the
// tests below check the bytes against the protocol rather than against
// themselves.
func decodeStartup(t *testing.T, raw []byte) (uint32, map[string]string) {
	t.Helper()

	if len(raw) < 9 {
		t.Fatalf("startup message is %d bytes, too short to be one", len(raw))
	}
	length := binary.BigEndian.Uint32(raw[0:4])
	if int(length) != len(raw) {
		t.Fatalf("length field = %d, but the message is %d bytes", length, len(raw))
	}
	version := binary.BigEndian.Uint32(raw[4:8])

	params := map[string]string{}
	rest := raw[8:]
	if rest[len(rest)-1] != 0 {
		t.Fatal("startup message does not end with a NUL terminator")
	}
	rest = rest[:len(rest)-1]

	for len(rest) > 0 {
		key, ok := nextString(&rest)
		if !ok {
			t.Fatal("startup parameter key is not NUL-terminated")
		}
		value, ok := nextString(&rest)
		if !ok {
			t.Fatal("startup parameter value is not NUL-terminated")
		}
		params[key] = value
	}
	return version, params
}

func nextString(rest *[]byte) (string, bool) {
	i := bytes.IndexByte(*rest, 0)
	if i < 0 {
		return "", false
	}
	s := string((*rest)[:i])
	*rest = (*rest)[i+1:]
	return s, true
}

// TestStartupEncoding pins the layout and the protocol version.
func TestStartupEncoding(t *testing.T) {
	cases := []struct {
		name   string
		params StartupParams
		want   map[string]string
	}{
		{
			name:   "user only",
			params: StartupParams{User: "payments_writer"},
			want:   map[string]string{"user": "payments_writer"},
		},
		{
			name:   "user and database",
			params: StartupParams{User: "payments_writer", Database: "payments_prod"},
			want:   map[string]string{"user": "payments_writer", "database": "payments_prod"},
		},
		{
			// An empty database is not sent at all: the protocol's own default
			// is "the database named after the user", and sending an empty
			// string would ask for a database with no name.
			name:   "empty database is omitted",
			params: StartupParams{User: "app", Database: ""},
			want:   map[string]string{"user": "app"},
		},
		{
			name:   "unicode identities round-trip",
			params: StartupParams{User: "müşteri", Database: "用户库"},
			want:   map[string]string{"user": "müşteri", "database": "用户库"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := EncodeStartup(tc.params)
			if err != nil {
				t.Fatalf("EncodeStartup: %v", err)
			}

			version, params := decodeStartup(t, raw)
			if version != 196608 {
				t.Errorf("protocol version = %d, want 196608 (3.0)", version)
			}
			if len(params) != len(tc.want) {
				t.Fatalf("parameters = %v, want %v", params, tc.want)
			}
			for k, v := range tc.want {
				if params[k] != v {
					t.Errorf("parameter %q = %q, want %q", k, params[k], v)
				}
			}
		})
	}
}

// TestStartupSendsNothingItWasNotAskedFor is a scope guard.
//
// A diagnostic tool should minimize both what it asks a server to do and what it
// writes into that server's logs. Every parameter below is available and
// deliberately omitted; adding one needs a reason.
func TestStartupSendsNothingItWasNotAskedFor(t *testing.T) {
	raw, err := EncodeStartup(StartupParams{User: "app", Database: "appdb"})
	if err != nil {
		t.Fatalf("EncodeStartup: %v", err)
	}
	_, params := decodeStartup(t, raw)

	for _, unwanted := range []string{
		"application_name", "client_encoding", "options", "replication",
		"password", "search_path", "DateStyle", "TimeZone",
	} {
		if _, present := params[unwanted]; present {
			t.Errorf("startup sent %q, which nothing asked for", unwanted)
		}
	}
}

// TestStartupCarriesNoCredential is the phase's central scope assertion, made
// against the bytes rather than against the source.
//
// There is no password field on StartupParams, so this cannot fail without
// somebody adding one — which is the point: the absence is structural.
func TestStartupCarriesNoCredential(t *testing.T) {
	const passwordCanary = "svcdoctor-canary-password-8a71fe"

	raw, err := EncodeStartup(StartupParams{User: "app", Database: "appdb"})
	if err != nil {
		t.Fatalf("EncodeStartup: %v", err)
	}
	if bytes.Contains(raw, []byte(passwordCanary)) {
		t.Fatal("a credential reached the startup packet")
	}
	if bytes.Contains(bytes.ToLower(raw), []byte("password")) {
		t.Error("the startup packet mentions a password parameter")
	}
}

// TestStartupRejectsUnencodableInput covers what cannot become a well-formed
// packet.
//
// A NUL is refused rather than escaped, because the protocol has no escape: a
// value containing one would terminate early and silently change which role or
// database the server sees, which is an injection rather than a formatting
// problem.
func TestStartupRejectsUnencodableInput(t *testing.T) {
	cases := map[string]StartupParams{
		"no user":         {User: ""},
		"NUL in user":     {User: "app\x00admin"},
		"NUL in database": {User: "app", Database: "db\x00other"},
		"NUL only":        {User: "\x00"},
	}

	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeStartup(params); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("err = %v, want ErrInvalidInput", err)
			}
		})
	}
}

// TestSendStartupWritesExactlyTheEncodedPacket proves nothing joins it on the
// wire.
func TestSendStartupWritesExactlyTheEncodedPacket(t *testing.T) {
	params := StartupParams{User: "app", Database: "appdb"}
	want, err := EncodeStartup(params)
	if err != nil {
		t.Fatalf("EncodeStartup: %v", err)
	}

	p := scriptedPeer(t, func(conn net.Conn, p *peer) {
		defer conn.Close()
		readN(conn, p, len(want))
		time.Sleep(200 * time.Millisecond)
	})

	if err := SendStartup(testContext(t), p.dial(t), params); err != nil {
		t.Fatalf("SendStartup: %v", err)
	}
	p.waitForBytes(t, len(want))
	if got := p.bytesReceived(); !bytes.Equal(got, want) {
		t.Errorf("peer received % x, want % x", got, want)
	}
}

// TestSendStartupDoesNotLeaveADeadlineBehind is the ownership guard for the
// second exchange, matching the one the SSL negotiation has.
//
// The read below is a raw conn.Read rather than ReadMessage, and that is the
// whole point: ReadMessage binds a fresh deadline from its own context, which
// would overwrite the stale one this test exists to detect and make it pass
// either way.
func TestSendStartupDoesNotLeaveADeadlineBehind(t *testing.T) {
	p := scriptedPeer(t, func(conn net.Conn, p *peer) {
		defer conn.Close()
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		// Answer well after the write's short deadline would have expired.
		time.Sleep(400 * time.Millisecond)
		_, _ = conn.Write(authFrame(0, nil))
		time.Sleep(300 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	conn := p.dial(t)
	if err := SendStartup(ctx, conn, StartupParams{User: "app"}); err != nil {
		t.Fatalf("SendStartup: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("reading after SendStartup: %v; the deadline was not cleared", err)
	}
	if header[0] != MsgAuthentication {
		t.Errorf("type = %q, want %q", header[0], MsgAuthentication)
	}
}

// TestStartupParameterNamesAreLowercase pins the exact keys, since a server
// matches them literally.
func TestStartupParameterNamesAreLowercase(t *testing.T) {
	raw, err := EncodeStartup(StartupParams{User: "app", Database: "appdb"})
	if err != nil {
		t.Fatalf("EncodeStartup: %v", err)
	}
	if !strings.Contains(string(raw), "user\x00app\x00") {
		t.Error("the user parameter is not encoded as user\\0<value>\\0")
	}
	if !strings.Contains(string(raw), "database\x00appdb\x00") {
		t.Error("the database parameter is not encoded as database\\0<value>\\0")
	}
}
