package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A scripted SCRAM peer, not a PostgreSQL server.
//
// It performs enough of the server half of SCRAM-SHA-256 to answer svcdoctor
// truthfully, and enough of the wrong halves to prove svcdoctor refuses them.
// Everything is deterministic — fixed salt, fixed server nonce, fixed iteration
// count — so a test can pin exact bytes.
//
// It deliberately builds its own frames rather than calling the production
// encoder. A fixture that framed with the encoder under test would agree with it
// about a framing bug.

// Deterministic SCRAM parameters. The salt is arbitrary and constant.
const (
	fixtureIterations = 4096
	fixtureServerTail = "SERVERNONCEsuffix123456="
)

// canaryPassword is the credential every SCRAM fixture authenticates with.
//
// High entropy and unmistakable, so a leak matrix can assert its exact absence
// rather than assert that output "looks masked".
//
//nolint:gosec // G101: a leak-test canary, not a credential.
const canaryPassword = "Zx9-QUARK-pw-7Kv2wLpN4tRb"

func fixtureSalt() []byte { return []byte("0123456789abcdef") }

// scramScript describes one server-side SCRAM conversation.
type scramScript struct {
	// mechanisms is the AuthenticationSASL advertisement. Empty means the
	// default single SCRAM-SHA-256 entry.
	mechanisms []string

	// password is what the server's verifier is built from. Empty means
	// canaryPassword.
	password string

	iterations int

	// serverFirstOverride replaces the whole server-first payload, for parser
	// tests. Empty means build a well-formed one.
	serverFirstOverride string

	// beforeContinue replaces AuthenticationSASLContinue entirely.
	beforeContinue []byte

	// respondFinal writes the answer to the client-final message. It receives
	// the signature a correct server would send. Nil means the honest response
	// followed by AuthenticationOk.
	respondFinal func(w io.Writer, correctSignature []byte)

	// trailing is written immediately after whatever respondFinal wrote, in the
	// same burst, so a test can prove svcdoctor left it unread.
	trailing []byte
}

func (s scramScript) mechanismList() []string {
	if len(s.mechanisms) == 0 {
		return []string{"SCRAM-SHA-256"}
	}
	return s.mechanisms
}

func (s scramScript) pw() string {
	if s.password == "" {
		return canaryPassword
	}
	return s.password
}

func (s scramScript) iters() int {
	if s.iterations == 0 {
		return fixtureIterations
	}
	return s.iterations
}

// serveSCRAM runs the server half over conn, recording every byte the client
// sent after startup.
func (p *pgPeer) serveSCRAM(conn net.Conn, s scramScript) {
	if _, err := conn.Write(authSASLFrame(s.mechanismList())); err != nil {
		return
	}

	// Everything from here is credential-derived on the client side. A refusal
	// path must leave this at zero bytes.
	msg, ok := p.readClientMessage(conn)
	if !ok {
		return
	}

	clientFirst, ok := decodeSASLInitial(msg)
	if !ok {
		return
	}
	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")
	p.mu.Lock()
	p.clientFirstBare = clientFirstBare
	p.mu.Unlock()

	if s.beforeContinue != nil {
		_, _ = conn.Write(s.beforeContinue)
		p.drain(conn)
		return
	}

	serverFirst := s.serverFirstOverride
	if serverFirst == "" {
		clientNonce := attrValue(clientFirstBare, 'r')
		serverFirst = "r=" + clientNonce + fixtureServerTail +
			",s=" + base64.StdEncoding.EncodeToString(fixtureSalt()) +
			",i=" + strconv.Itoa(s.iters())
	}
	p.mu.Lock()
	p.serverFirst = serverFirst
	p.mu.Unlock()
	if _, err := conn.Write(authFrame(11, []byte(serverFirst))); err != nil {
		return
	}

	final, ok := p.readClientMessage(conn)
	if !ok {
		return
	}
	clientFinal := string(final.body)
	p.mu.Lock()
	p.clientFinal = clientFinal
	p.mu.Unlock()

	signature := fixtureServerSignature(s.pw(), s.iters(), clientFirstBare, serverFirst, clientFinal)

	var out bytes.Buffer
	if s.respondFinal != nil {
		s.respondFinal(&out, signature)
	} else {
		out.Write(authFrame(12, []byte("v="+base64.StdEncoding.EncodeToString(signature))))
		out.Write(authFrame(0, nil))
	}
	out.Write(s.trailing)
	_, _ = conn.Write(out.Bytes())

	p.drain(conn)
}

// fixtureServerSignature computes what an honest server would return.
//
// It re-derives from the password independently of the production code path, so
// a test that passes proves the two agree rather than proving one is
// self-consistent.
func fixtureServerSignature(password string, iterations int, clientFirstBare, serverFirst, clientFinal string) []byte {
	salted, err := pbkdf2.Key(sha256.New, password, fixtureSalt(), iterations, sha256.Size)
	if err != nil {
		return nil
	}
	withoutProof := clientFinal
	if i := strings.Index(clientFinal, ",p="); i >= 0 {
		withoutProof = clientFinal[:i]
	}
	authMessage := clientFirstBare + "," + serverFirst + "," + withoutProof

	serverKey := hmacSum(salted, []byte("Server Key"))
	return hmacSum(serverKey, []byte(authMessage))
}

// fixtureClientProof computes the proof an honest client would send, so a leak
// test can assert the peer really received it.
func fixtureClientProof(password string, iterations int, clientFirstBare, serverFirst, withoutProof string) string {
	salted, err := pbkdf2.Key(sha256.New, password, fixtureSalt(), iterations, sha256.Size)
	if err != nil {
		return ""
	}
	clientKey := hmacSum(salted, []byte("Client Key"))
	stored := sha256.Sum256(clientKey)
	authMessage := clientFirstBare + "," + serverFirst + "," + withoutProof
	sig := hmacSum(stored[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ sig[i]
	}
	return base64.StdEncoding.EncodeToString(proof)
}

func hmacSum(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// clientMessage is one framed message the client sent.
type clientMessage struct {
	kind byte
	body []byte
}

// readClientMessage reads one framed client message and records its raw bytes.
func (p *pgPeer) readClientMessage(conn net.Conn) (clientMessage, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var header [5]byte
	if !readExactly(conn, header[:]) {
		return clientMessage{}, false
	}
	length := binary.BigEndian.Uint32(header[1:5])
	if length < 4 || length > 1<<20 {
		return clientMessage{}, false
	}
	body := make([]byte, length-4)
	if !readExactly(conn, body) {
		return clientMessage{}, false
	}

	p.mu.Lock()
	p.afterStartupBytes = append(p.afterStartupBytes, header[:]...)
	p.afterStartupBytes = append(p.afterStartupBytes, body...)
	p.mu.Unlock()

	return clientMessage{kind: header[0], body: body}, true
}

// drain reads whatever else the client sends, so a test can prove it sent
// nothing more.
func (p *pgPeer) drain(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			p.mu.Lock()
			p.afterStartupBytes = append(p.afterStartupBytes, buf[:n]...)
			p.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// decodeSASLInitial reads a SASLInitialResponse body: mechanism NUL, Int32
// length, payload.
func decodeSASLInitial(m clientMessage) (string, bool) {
	if m.kind != 'p' {
		return "", false
	}
	i := bytes.IndexByte(m.body, 0)
	if i < 0 || len(m.body) < i+5 {
		return "", false
	}
	n := binary.BigEndian.Uint32(m.body[i+1 : i+5])
	rest := m.body[i+5:]
	if int(n) != len(rest) {
		return "", false
	}
	return string(rest), true
}

// attrValue returns the value of a single-letter SCRAM attribute.
func attrValue(s string, key byte) string {
	for _, attr := range strings.Split(s, ",") {
		if len(attr) >= 2 && attr[0] == key && attr[1] == '=' {
			return attr[2:]
		}
	}
	return ""
}

// --- frame builders, independent of production encoding -------------------

func pgFrame(kind byte, body []byte) []byte {
	if len(body) > 1<<20 {
		panic("fixture body too large to frame")
	}
	out := make([]byte, 5+len(body))
	out[0] = kind
	//nolint:gosec // G115: bounded above.
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}

// authFrame builds an Authentication message with a code and optional payload.
func authFrame(code uint32, payload []byte) []byte {
	body := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(body, code)
	body = append(body, payload...)
	return pgFrame('R', body)
}

// authSASLFrame builds AuthenticationSASL with a NUL-terminated mechanism list.
func authSASLFrame(mechanisms []string) []byte {
	var payload []byte
	for _, m := range mechanisms {
		payload = append(payload, m...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0)
	return authFrame(10, payload)
}

// errorFrame builds an ErrorResponse from field pairs.
func errorFrame(pairs ...string) []byte {
	var body []byte
	for i := 0; i+1 < len(pairs); i += 2 {
		body = append(body, pairs[i][0])
		body = append(body, pairs[i+1]...)
		body = append(body, 0)
	}
	body = append(body, 0)
	return pgFrame('E', body)
}

// paramStatusFrame builds a ParameterStatus message.
func paramStatusFrame(key, value string) []byte {
	body := make([]byte, 0, len(key)+len(value)+2)
	body = append(body, key...)
	body = append(body, 0)
	body = append(body, value...)
	body = append(body, 0)
	return pgFrame('S', body)
}

// backendKeyFrame builds a BackendKeyData message.
func backendKeyFrame() []byte {
	body := make([]byte, 8)
	binary.BigEndian.PutUint32(body[0:4], 4242)
	binary.BigEndian.PutUint32(body[4:8], 8484)
	return pgFrame('K', body)
}

// readyForQueryFrame builds a ReadyForQuery message.
func readyForQueryFrame() []byte { return pgFrame('Z', []byte{'I'}) }

// --- assertions ------------------------------------------------------------

// exchange returns the decoded SCRAM messages the fixture observed, so a leak
// test can recompute the real intermediates without doing string surgery on a
// framed byte stream.
func (p *pgPeer) exchange() (clientFirstBare, serverFirst, clientFinal string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clientFirstBare, p.serverFirst, p.clientFinal
}

// afterStartup returns every byte the client sent after its StartupMessage.
func (p *pgPeer) afterStartup() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]byte, len(p.afterStartupBytes))
	copy(out, p.afterStartupBytes)
	return out
}

// requireNoCredentialBytes proves the peer's protocol layer received nothing
// after the StartupMessage.
//
// This is what makes a refusal test meaningful. Asserting only that the evidence
// says SKIPPED would pass even if a credential had gone out first.
func (p *pgPeer) requireNoCredentialBytes(t *testing.T) {
	t.Helper()
	// Give a wrong implementation time to actually write something.
	time.Sleep(200 * time.Millisecond)
	if got := p.afterStartup(); len(got) != 0 {
		t.Fatalf("peer received %d bytes after startup, want 0: %q", len(got), got)
	}
}
