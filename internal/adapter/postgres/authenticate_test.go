package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// --- fixtures ---------------------------------------------------------------

func canaryCredential(t *testing.T) security.Credential {
	t.Helper()
	return credentialFor(t, canaryHost, 5432, canaryPassword)
}

func credentialFor(t *testing.T, host string, port uint16, password string) security.Credential {
	t.Helper()
	endpoint, err := security.NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(endpoint, "payments_writer", security.NewSecret(password))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return credential
}

// verifiedTLS runs the chain to StartupResult over a verified TLS channel, which
// is the only channel the default policy permits a credential on.
func verifiedTLS(t *testing.T, s scramScript) (*StartupResult, *domain.GraphBuilder, *pgPeer) {
	t.Helper()
	peer := newPGPeer(t, script{sslReply: []byte("S"), upgradeTLS: true, scram: &s})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{
		TLS:        TLSRequired,
		TLSOptions: TLSOptions{ServerName: "localhost", RootCAs: peer.ca},
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	if session.Channel() != security.ChannelTLSVerified {
		t.Fatalf("channel = %s, want tls-verified", session.Channel())
	}

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
	return result, builder, peer
}

// authNode returns the authentication node, failing if absent.
func authNode(t *testing.T, builder *domain.GraphBuilder) domain.Evidence {
	t.Helper()
	return nodeFor(t, freeze(t, builder), StepAuthentication)
}

// requireNode asserts the state and class of the authentication node.
func requireNode(t *testing.T, builder *domain.GraphBuilder, state domain.State, class domain.FailureClass) domain.Evidence {
	t.Helper()
	node := authNode(t, builder)
	if node.State() != state {
		t.Errorf("state = %s, want %s", node.State(), state)
	}
	if node.FailureClass() != class {
		t.Errorf("failure class = %s, want %s", node.FailureClass(), class)
	}
	return node
}

// --- the happy path ---------------------------------------------------------

func TestAuthenticateSucceedsOverVerifiedTLS(t *testing.T) {
	result, builder, peer := verifiedTLS(t, scramScript{})

	session, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session == nil {
		t.Fatal("Authenticate produced no session")
	}
	t.Cleanup(func() { _ = session.Close() })

	node := requireNode(t, builder, domain.StatePass, domain.FailureNone)

	if got := node.Layer(); got != domain.LayerAuth {
		t.Errorf("layer = %s, want L5", got)
	}
	if got := attrString(t, node, AttrSASLMechanism); got != "SCRAM-SHA-256" {
		t.Errorf("mechanism = %q, want SCRAM-SHA-256", got)
	}
	if got := attrInt(t, node, AttrSCRAMIterations); got != fixtureIterations {
		t.Errorf("iterations = %d, want %d", got, fixtureIterations)
	}

	// The authentication node derives from the startup node.
	g := freeze(t, builder)
	startup := nodeFor(t, g, StepStartup)
	if !hasParent(g, node.ID(), startup.ID()) {
		t.Error("authentication node is not parented to the startup node")
	}

	// One socket for the whole run.
	if got := peer.connections(); got != 1 {
		t.Errorf("peer accepted %d connections, want 1", got)
	}
}

// TestSuccessfulAuthenticationReallySentTheProof is the control that stops every
// leak and refusal test in this file from being vacuous.
//
// If svcdoctor never actually transmitted a client proof, an assertion that the
// proof is absent from a report would pass for the wrong reason.
func TestSuccessfulAuthenticationReallySentTheProof(t *testing.T) {
	result, builder, peer := verifiedTLS(t, scramScript{})

	session, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{})
	if err != nil || session == nil {
		t.Fatalf("Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	sent := string(peer.afterStartup())
	if !strings.Contains(sent, "SCRAM-SHA-256") {
		t.Fatal("the peer never received a SASLInitialResponse")
	}
	if !strings.Contains(sent, ",p=") {
		t.Fatal("the peer never received a client proof")
	}
	if !strings.Contains(sent, "c=biws") {
		t.Fatal("the peer never received the channel-binding value")
	}
}

// --- mechanism selection ----------------------------------------------------

func TestMechanismSelection(t *testing.T) {
	tests := []struct {
		name       string
		mechanisms []string
		state      domain.State
		class      domain.FailureClass
	}{
		{
			name:       "SCRAM-SHA-256 offered",
			mechanisms: []string{"SCRAM-SHA-256"},
			state:      domain.StatePass,
		},
		{
			name:       "both offered, plain SCRAM is chosen",
			mechanisms: []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"},
			state:      domain.StatePass,
		},
		{
			name:       "only PLUS offered is a gap in svcdoctor",
			mechanisms: []string{"SCRAM-SHA-256-PLUS"},
			state:      domain.StateUnknown,
			class:      domain.FailureAuthMechanismUnsupported,
		},
		{
			name:       "no SCRAM at all is a fact about the peer",
			mechanisms: []string{"GSSAPI", "EXTERNAL"},
			state:      domain.StateFail,
			class:      domain.FailureAuthMechanismNotOffered,
		},
		{
			name:       "empty advertisement is a fact about the peer",
			mechanisms: []string{"NOTHING-WE-SPEAK"},
			state:      domain.StateFail,
			class:      domain.FailureAuthMechanismNotOffered,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, builder, peer := verifiedTLS(t, scramScript{mechanisms: tt.mechanisms})

			session, err := Authenticate(
				context.Background(), builder, result, canaryCredential(t), AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}

			if tt.state == domain.StatePass {
				if session == nil {
					t.Fatal("expected an authenticated session")
				}
				t.Cleanup(func() { _ = session.Close() })
				requireNode(t, builder, domain.StatePass, domain.FailureNone)
				return
			}

			if session != nil {
				t.Fatal("a refused mechanism returned a session")
			}
			requireNode(t, builder, tt.state, tt.class)
			peer.requireNoCredentialBytes(t)
		})
	}
}

// TestUnsupportedAuthMethodsOverVerifiedTLS is the real matrix, over a channel
// the policy permits — so a refusal here can only be about the mechanism.
func TestUnsupportedAuthMethodsOverVerifiedTLS(t *testing.T) {
	tests := []struct {
		name  string
		reply []byte
	}{
		{"cleartext password", authCode(3)},
		{"md5", append(authCode(5), 1, 2, 3, 4)},
		{"kerberos v5", authCode(2)},
		{"scm credential", authCode(6)},
		{"gss", authCode(7)},
		{"sspi", authCode(9)},
		{"a method this repository does not recognize", authCode(99)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := newPGPeer(t, script{
				sslReply: []byte("S"), upgradeTLS: true, afterStartup: tt.reply,
			})
			path, builder := pathTo(t, peer)

			session, err := Negotiate(context.Background(), builder, path, Params{
				TLS:        TLSRequired,
				TLSOptions: TLSOptions{ServerName: "localhost", RootCAs: peer.ca},
			})
			if err != nil {
				t.Fatalf("Negotiate: %v", err)
			}
			t.Cleanup(func() { _ = session.Close() })

			result, err := Startup(context.Background(), builder, session,
				StartupParams{User: "payments_writer"})
			if err != nil || result == nil {
				t.Fatalf("Startup: %v", err)
			}
			t.Cleanup(func() { _ = result.Close() })

			authenticated, err := Authenticate(
				context.Background(), builder, result, canaryCredential(t), AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if authenticated != nil {
				t.Fatal("an unsupported mechanism returned a session")
			}

			requireNode(t, builder,
				domain.StateUnknown, domain.FailureAuthMechanismUnsupported)
			peer.requireNoCredentialBytes(t)
		})
	}
}

// TestUnsupportedMechanismRecordsNoMechanismAttribute proves the node does not
// claim a choice svcdoctor never made. The startup node already carries
// postgres.auth_method.
func TestUnsupportedMechanismRecordsNoMechanismAttribute(t *testing.T) {
	result, builder, _ := verifiedTLS(t, scramScript{mechanisms: []string{"SCRAM-SHA-256-PLUS"}})

	if _, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	node := authNode(t, builder)
	if _, ok := node.Attributes()[AttrSASLMechanism]; ok {
		t.Error("a refused mechanism recorded postgres.sasl_mechanism anyway")
	}
}

// TestTrustAuthenticationRecordsNoNode covers a server that demands nothing.
//
// svcdoctor presented no credential, so a PASS authentication node would be an
// overclaim. The connection continues, which is what keeps `trust` over
// plaintext diagnosable.
func TestTrustAuthenticationRecordsNoNode(t *testing.T) {
	peer := newPGPeer(t, script{expectNoSSLRequest: true, afterStartup: authOK()})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{TLS: TLSDisabled})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	result, err := Startup(context.Background(), builder, session, StartupParams{User: "app"})
	if err != nil || result == nil {
		t.Fatalf("Startup: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	authenticated, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if authenticated == nil {
		t.Fatal("a trust server produced no session")
	}
	t.Cleanup(func() { _ = authenticated.Close() })

	if hasNode(freeze(t, builder), StepAuthentication) {
		t.Error("a trust server produced an authentication node")
	}
	// The session's parent for the next phase is the startup node.
	if authenticated.Evidence() != result.Evidence() {
		t.Error("a trust session does not point at the startup node")
	}
	peer.requireNoCredentialBytes(t)
}

// --- channel policy ---------------------------------------------------------

func TestChannelPolicy(t *testing.T) {
	t.Run("plaintext is refused and blocked by the ssl_request node", func(t *testing.T) {
		s := scramScript{}
		peer := newPGPeer(t, script{expectNoSSLRequest: true, scram: &s})
		path, builder := pathTo(t, peer)

		session, err := Negotiate(context.Background(), builder, path, Params{TLS: TLSDisabled})
		if err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		if session.Channel() != security.ChannelPlaintext {
			t.Fatalf("channel = %s, want plaintext", session.Channel())
		}

		result, err := Startup(context.Background(), builder, session,
			StartupParams{User: "payments_writer"})
		if err != nil || result == nil {
			t.Fatalf("Startup: %v", err)
		}
		t.Cleanup(func() { _ = result.Close() })

		authenticated, err := Authenticate(
			context.Background(), builder, result, canaryCredential(t), AuthParams{})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if authenticated != nil {
			t.Fatal("a refused channel returned a session")
		}

		node := requireNode(t, builder,
			domain.StateSkipped, domain.FailureExecSkippedByPolicy)
		peer.requireNoCredentialBytes(t)

		g := freeze(t, builder)
		ssl := nodeFor(t, g, StepSSLRequest)
		if !hasBlocker(g, node.ID(), ssl.ID()) {
			t.Error("the refusal does not point at the postgres.ssl_request node")
		}
	})

	t.Run("unverified TLS is refused and blocked by the handshake node", func(t *testing.T) {
		s := scramScript{}
		peer := newPGPeer(t, script{sslReply: []byte("S"), upgradeTLS: true, scram: &s})
		path, builder := pathTo(t, peer)

		session, err := Negotiate(context.Background(), builder, path, Params{
			TLS:        TLSRequired,
			TLSOptions: TLSOptions{ServerName: "localhost", InsecureSkipVerify: true},
		})
		if err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		if session.Channel() != security.ChannelTLSUnverified {
			t.Fatalf("channel = %s, want tls-unverified", session.Channel())
		}

		result, err := Startup(context.Background(), builder, session,
			StartupParams{User: "payments_writer"})
		if err != nil || result == nil {
			t.Fatalf("Startup: %v", err)
		}
		t.Cleanup(func() { _ = result.Close() })

		authenticated, err := Authenticate(
			context.Background(), builder, result, canaryCredential(t), AuthParams{})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if authenticated != nil {
			t.Fatal("a refused channel returned a session")
		}

		node := requireNode(t, builder,
			domain.StateSkipped, domain.FailureExecSkippedByPolicy)
		peer.requireNoCredentialBytes(t)

		g := freeze(t, builder)
		tlsNode := nodeFor(t, g, "tls.handshake")
		if !hasBlocker(g, node.ID(), tlsNode.ID()) {
			t.Error("the refusal does not point at the tls.handshake node")
		}
	})
}

// TestUnknownChannelRefuses proves the fail-closed direction: a StartupResult
// whose channel was never classified permits nothing.
func TestUnknownChannelRefuses(t *testing.T) {
	var policy security.CredentialTransportPolicy
	for _, channel := range []security.Channel{
		security.ChannelUnknown,
		security.Channel(42),
	} {
		if policy.PermitsCredentials(channel) {
			t.Errorf("policy permitted a credential on channel %v", channel)
		}
	}
}

// --- endpoint authority -----------------------------------------------------

func TestCredentialEndpointAuthority(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		port    uint16
		allowed bool
	}{
		{"exact endpoint", canaryHost, 5432, true},
		{"uppercase host normalizes", strings.ToUpper(canaryHost), 5432, true},
		{"trailing dot normalizes", canaryHost + ".", 5432, true},
		{"different host", "other.payments.internal", 5432, false},
		{"different port", canaryHost, 5433, false},
		{"the resolved address cannot widen authority", canaryAddr, 5432, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, builder, peer := verifiedTLS(t, scramScript{})

			session, err := Authenticate(context.Background(), builder, result,
				credentialFor(t, tt.host, tt.port, canaryPassword), AuthParams{})

			if tt.allowed {
				if err != nil {
					t.Fatalf("Authenticate: %v", err)
				}
				if session == nil {
					t.Fatal("expected an authenticated session")
				}
				t.Cleanup(func() { _ = session.Close() })
				requireNode(t, builder, domain.StatePass, domain.FailureNone)
				return
			}

			if !errors.Is(err, security.ErrEndpointMismatch) {
				t.Fatalf("err = %v, want ErrEndpointMismatch", err)
			}
			if session != nil {
				t.Fatal("a mismatched credential returned a session")
			}
			// A local invocation error is not a fact about the target.
			if hasNode(freeze(t, builder), StepAuthentication) {
				t.Error("an endpoint mismatch recorded an authentication node")
			}
			peer.requireNoCredentialBytes(t)
		})
	}
}

// TestEndpointMismatchErrorCarriesNoSecret proves the Go error a mismatch
// produces names the endpoints and nothing else.
func TestEndpointMismatchErrorCarriesNoSecret(t *testing.T) {
	result, builder, _ := verifiedTLS(t, scramScript{})

	_, err := Authenticate(context.Background(), builder, result,
		credentialFor(t, "elsewhere.internal", 5432, canaryPassword), AuthParams{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), canaryPassword) {
		t.Fatalf("the password reached the error: %q", err)
	}
}

// TestResolvedAddressesDoNotAlterAuthority proves that one logical endpoint
// resolving to several addresses stays one authorized endpoint.
func TestResolvedAddressesDoNotAlterAuthority(t *testing.T) {
	credential := canaryCredential(t)

	for _, addr := range []string{"10.88.0.17", "10.88.0.18", "2001:db8::1"} {
		endpoint, err := security.NewEndpoint(canaryHost, 5432)
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		if _, err := credential.SecretFor(endpoint); err != nil {
			t.Fatalf("credential refused for a path that resolved to %s: %v", addr, err)
		}

		resolved := netip.MustParseAddr(addr)
		addressEndpoint, err := security.NewEndpoint(resolved.String(), 5432)
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		if _, err := credential.SecretFor(addressEndpoint); !errors.Is(err, security.ErrEndpointMismatch) {
			t.Fatalf("a resolved address authorized the credential: %v", err)
		}
	}
}

// --- the printable-ASCII limitation -----------------------------------------

func TestNonASCIIPasswordIsAGapInSvcdoctor(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"U+001F", "pa\x1fss"},
		{"U+007F", "pa\x7fss"},
		{"U+00A0 no-break space", "pa\u00a0ss"},
		{"U+00AD soft hyphen", "pa\u00adss"},
		{"U+200B zero-width space", "pa\u200bss"},
		{"Turkish dotless i", "parola\u0131"},
		{"European sharp s", "pa\u00dfword"},
		{"emoji", "pass\U0001F510"},
		{"invalid UTF-8", "pa\xffss"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, builder, peer := verifiedTLS(t, scramScript{})

			session, err := Authenticate(context.Background(), builder, result,
				credentialFor(t, canaryHost, 5432, tt.password), AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if session != nil {
				t.Fatal("an unsupported password returned a session")
			}

			node := requireNode(t, builder,
				domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor)

			// Never a claim about the peer.
			if node.FailureClass() == domain.FailureAuthCredentialsRejected {
				t.Fatal("a svcdoctor limitation was reported as a credential rejection")
			}
			peer.requireNoCredentialBytes(t)
		})
	}
}

func TestPrintableASCIIPasswordsAreAccepted(t *testing.T) {
	for _, password := range []string{
		" leading-space",
		"trailing-tilde~",
		canaryPassword,
		"!\"#$%&'()*+,-./0123456789:;<=>?@AZ[\\]^_`az{|}~",
	} {
		t.Run(password, func(t *testing.T) {
			result, builder, _ := verifiedTLS(t, scramScript{password: password})

			session, err := Authenticate(context.Background(), builder, result,
				credentialFor(t, canaryHost, 5432, password), AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if session == nil {
				t.Fatal("a printable-ASCII password was refused")
			}
			t.Cleanup(func() { _ = session.Close() })
			requireNode(t, builder, domain.StatePass, domain.FailureNone)
		})
	}
}

// --- the success boundary ---------------------------------------------------

// TestAuthenticationPassesOnlyOnTheConjunction is the release-blocking guard.
//
// PASS requires a verified server signature **and** AuthenticationOk. Every row
// below removes exactly one of those and must not pass. A mutation that skips
// signature verification turns rows two and three green, which is what makes
// this test worth its length.
func TestAuthenticationPassesOnlyOnTheConjunction(t *testing.T) {
	tests := []struct {
		name    string
		respond func(w io.Writer, correct []byte)
		state   domain.State
		class   domain.FailureClass
	}{
		{
			name:  "signature verifies and AuthenticationOk arrives",
			state: domain.StatePass,
		},
		{
			// The peer accepted the proof — it would not have sent a server-final
			// otherwise — and then failed to prove itself. That is svcdoctor
			// refusing the peer, the opposite direction from a rejected
			// credential, and it has its own class as of Phase 4.6a.5.
			name: "signature is forged, AuthenticationOk still arrives",
			respond: func(w io.Writer, _ []byte) {
				forged := bytes.Repeat([]byte{0xAA}, 32)
				_, _ = w.Write(authFrame(12, []byte("v="+base64.StdEncoding.EncodeToString(forged))))
				_, _ = w.Write(authFrame(0, nil))
			},
			state: domain.StateFail,
			class: domain.FailureAuthPeerVerificationFailed,
		},
		{
			name: "no server-final at all, AuthenticationOk arrives",
			respond: func(w io.Writer, _ []byte) {
				_, _ = w.Write(authFrame(0, nil))
			},
			state: domain.StateFail,
			class: domain.FailureProtocolUnexpectedResponse,
		},
		{
			name: "signature verifies, then an ErrorResponse instead of AuthenticationOk",
			respond: func(w io.Writer, correct []byte) {
				_, _ = w.Write(authFrame(12, []byte("v="+base64.StdEncoding.EncodeToString(correct))))
				_, _ = w.Write(errorFrame("S", "FATAL", "V", "FATAL", "C", "08P01"))
			},
			state: domain.StateFail,
			// The peer proved itself and then refused the session, which is not
			// a credential rejection.
			class: domain.FailureProtocolUnexpectedResponse,
		},
		{
			name: "signature verifies, then the peer closes",
			respond: func(w io.Writer, correct []byte) {
				_, _ = w.Write(authFrame(12, []byte("v="+base64.StdEncoding.EncodeToString(correct))))
			},
			state: domain.StateFail,
			class: domain.FailureProtocolPeerClosed,
		},
		{
			name: "server-final carries an error token",
			respond: func(w io.Writer, _ []byte) {
				_, _ = w.Write(authFrame(12, []byte("e=invalid-proof")))
				_, _ = w.Write(authFrame(0, nil))
			},
			state: domain.StateFail,
			class: domain.FailureAuthCredentialsRejected,
		},
		{
			// unknown-user is the same direction: the peer declining what it was
			// presented, because there is no principal to verify it against.
			name: "server-final carries the unknown-user token",
			respond: func(w io.Writer, _ []byte) {
				_, _ = w.Write(authFrame(12, []byte("e=unknown-user")))
				_, _ = w.Write(authFrame(0, nil))
			},
			state: domain.StateFail,
			class: domain.FailureAuthCredentialsRejected,
		},
		{
			// An encoding fault in the username field, which is not a decision
			// about the material and must not read as one. Unreachable in
			// practice: this client sends an empty username.
			name: "server-final carries the invalid-username-encoding token",
			respond: func(w io.Writer, _ []byte) {
				_, _ = w.Write(authFrame(12, []byte("e=invalid-username-encoding")))
				_, _ = w.Write(authFrame(0, nil))
			},
			state: domain.StateFail,
			class: domain.FailureProtocolUnexpectedResponse,
		},
		{
			name: "server-final is neither a verifier nor an error",
			respond: func(w io.Writer, _ []byte) {
				_, _ = w.Write(authFrame(12, []byte("x=confused")))
			},
			state: domain.StateFail,
			class: domain.FailureProtocolMalformedResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, builder, _ := verifiedTLS(t, scramScript{respondFinal: tt.respond})

			session, err := Authenticate(
				context.Background(), builder, result, canaryCredential(t), AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}

			if tt.state == domain.StatePass {
				if session == nil {
					t.Fatal("the honest exchange did not produce a session")
				}
				t.Cleanup(func() { _ = session.Close() })
			} else if session != nil {
				t.Fatal("a failed authentication returned a live session")
			}

			requireNode(t, builder, tt.state, tt.class)
		})
	}
}

// --- ErrorResponse classification -------------------------------------------

func TestErrorResponseClassification(t *testing.T) {
	tests := []struct {
		name  string
		when  string // "continue" = before the proof, "final" = after it
		state domain.State
		pairs []string
		class domain.FailureClass
	}{
		{
			name: "28P01 after the proof", when: "final",
			pairs: []string{"S", "FATAL", "V", "FATAL", "C", "28P01"},
			state: domain.StateFail, class: domain.FailureAuthCredentialsRejected,
		},
		{
			name: "28000 before any material", when: "continue",
			pairs: []string{"S", "FATAL", "V", "FATAL", "C", "28000"},
			state: domain.StateFail, class: domain.FailureAuthzNotPermitted,
		},
		{
			name: "08P01 after the proof", when: "final",
			pairs: []string{"S", "FATAL", "C", "08P01"},
			state: domain.StateFail, class: domain.FailureProtocolUnexpectedResponse,
		},
		{
			name: "08P01 before any material", when: "continue",
			pairs: []string{"S", "FATAL", "C", "08P01"},
			state: domain.StateFail, class: domain.FailureProtocolUnexpectedResponse,
		},
		{
			name: "an unmapped SQLSTATE", when: "final",
			pairs: []string{"S", "FATAL", "V", "FATAL", "C", "53300"},
			state: domain.StateFail, class: domain.FailureProtocolUnexpectedResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s scramScript
			if tt.when == "continue" {
				s.beforeContinue = errorFrame(tt.pairs...)
			} else {
				s.respondFinal = func(w io.Writer, _ []byte) {
					_, _ = w.Write(errorFrame(tt.pairs...))
				}
			}

			result, builder, _ := verifiedTLS(t, s)

			session, err := Authenticate(
				context.Background(), builder, result, canaryCredential(t), AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if session != nil {
				t.Fatal("a rejected authentication returned a session")
			}

			node := requireNode(t, builder, tt.state, tt.class)

			// The SQLSTATE is recorded whatever the class.
			wantState := tt.pairs[len(tt.pairs)-1]
			if got := attrString(t, node, AttrSQLState); got != wantState {
				t.Errorf("sqlstate = %q, want %q", got, wantState)
			}
		})
	}
}

// TestPoolerCollapseNeverBecomesACredentialClaim pins the semantic contract, not
// a fixture's behaviour.
//
// `08P01` is pgBouncer's **default** SQLSTATE — the value it substitutes when
// `disconnect_client()` supplies none, which is every client-facing failure it
// has. Its own source says so: *"PgBouncer used to report SQLSTATE 08P01
// (protocol_violation) for all cases."* Measured against pgBouncer 1.25.2, the
// same code arrives for a wrong password, an unknown role, an unknown database,
// an unpooled database and an unreachable backend — in three different protocol
// positions, and with the *same* logical cause landing in different positions
// depending on whether the pooler had the role's verifier cached.
//
// So no arrangement of svcdoctor's own protocol state isolates the credential
// case, and `AUTH_CREDENTIALS_REJECTED` — *"the peer refused the authentication
// material it was presented"* — is never provable from `08P01`. The table below
// walks every position svcdoctor can observe it in and requires the **same**
// honest weak class from all of them.
func TestPoolerCollapseNeverBecomesACredentialClaim(t *testing.T) {
	positions := []struct {
		name    string
		script  scramScript
		hasNode bool
	}{
		{
			name: "before any SASL material, as for an unknown role",
			script: scramScript{
				beforeContinue: errorFrame("S", "FATAL", "C", "08P01"),
			},
			hasNode: true,
		},
		{
			name: "after the client proof, with no verifying signature",
			script: scramScript{
				respondFinal: func(w io.Writer, _ []byte) {
					_, _ = w.Write(errorFrame("S", "FATAL", "C", "08P01"))
				},
			},
			hasNode: true,
		},
		{
			name: "after a signature that verified, as for an unknown database",
			script: scramScript{
				respondFinal: func(w io.Writer, correct []byte) {
					_, _ = w.Write(authFrame(12, []byte("v="+base64.StdEncoding.EncodeToString(correct))))
					_, _ = w.Write(errorFrame("S", "FATAL", "C", "08P01"))
				},
			},
			hasNode: true,
		},
	}

	for _, p := range positions {
		t.Run(p.name, func(t *testing.T) {
			result, builder, _ := verifiedTLS(t, p.script)

			if _, err := Authenticate(
				context.Background(), builder, result, canaryCredential(t), AuthParams{}); err != nil {
				t.Fatalf("Authenticate: %v", err)
			}

			node := authNode(t, builder)
			if node.FailureClass() == domain.FailureAuthCredentialsRejected {
				t.Fatalf("08P01 in this position was classified as a credential "+
					"rejection, which the code does not prove (state = %s)", node.State())
			}
			if node.FailureClass() != domain.FailureProtocolUnexpectedResponse {
				t.Errorf("class = %s, want PROTOCOL_UNEXPECTED_RESPONSE",
					node.FailureClass())
			}

			// Nothing a later rule needs is lost: the code and the pooler signal
			// are both on the node.
			if got := attrString(t, node, AttrSQLState); got != "08P01" {
				t.Errorf("sqlstate = %q, want 08P01", got)
			}
			if native, ok := node.Attributes()[AttrErrorIsNative]; !ok {
				t.Error("error_is_native was not recorded")
			} else if native.String() != "false" {
				t.Errorf("error_is_native = %s, want false", native)
			}
		})
	}
}

// TestOnlyThePeersOwnCodeProducesACredentialClaim states the rule the table
// above is an instance of.
//
// AUTH_CREDENTIALS_REJECTED is produced from `28P01` — PostgreSQL's own
// `invalid_password`, where the peer asserted the refusal — and from a SCRAM
// server-final carrying the peer's own refusal token. It is never produced by
// inferring a cause from a generic code plus a protocol position.
func TestOnlyThePeersOwnCodeProducesACredentialClaim(t *testing.T) {
	for _, sqlState := range []string{
		"08P01", "08006", "53300", "57P03", "3D000", "42501", "XX000", "",
	} {
		if got := authSQLStateFailure(sqlState); got == domain.FailureAuthCredentialsRejected {
			t.Errorf("sqlstate %q produced AUTH_CREDENTIALS_REJECTED", sqlState)
		}
	}
	if got := authSQLStateFailure("28P01"); got != domain.FailureAuthCredentialsRejected {
		t.Errorf("28P01 = %s, want AUTH_CREDENTIALS_REJECTED", got)
	}
	if got := authSQLStateFailure("28000"); got != domain.FailureAuthzNotPermitted {
		t.Errorf("28000 = %s, want AUTHZ_NOT_PERMITTED", got)
	}
}

// TestPoolerUnknownDatabaseKeepsTheNativeSignal is the control that the two
// facts a later rule would need really are recorded.
func TestPoolerUnknownDatabaseKeepsTheNativeSignal(t *testing.T) {
	result, builder, _ := verifiedTLS(t, scramScript{
		respondFinal: func(w io.Writer, correct []byte) {
			_, _ = w.Write(authFrame(12, []byte("v="+base64.StdEncoding.EncodeToString(correct))))
			_, _ = w.Write(errorFrame("S", "FATAL", "C", "08P01", "M", "no such database: payments_prod"))
		},
	})

	if _, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	node := requireNode(t, builder,
		domain.StateFail, domain.FailureProtocolUnexpectedResponse)

	// pgBouncer omits the non-localized severity, which is the one structural
	// signal that the responder is not a genuine backend.
	if native, ok := node.Attributes()[AttrErrorIsNative]; !ok {
		t.Error("error_is_native was not recorded")
	} else if native.String() != "false" {
		t.Errorf("error_is_native = %s, want false", native)
	}
	// And the peer's prose is still nowhere.
	if strings.Contains(fmt.Sprintf("%+v", node.Attributes()), "no such database") {
		t.Error("the peer's message reached the node")
	}
}

// --- the read-ahead boundary ------------------------------------------------

// TestPhase45BytesSurviveAuthentication is the byte-preservation guard.
//
// The peer sends the server-final, AuthenticationOk, ParameterStatus,
// BackendKeyData and ReadyForQuery in one write. Authentication must return
// having consumed exactly the first two, and the very next frame on the returned
// connection must be the ParameterStatus.
//
// A bufio.Reader anywhere on this path takes all of it into a buffer the session
// step has no handle on. Measured against a real server: 455 bytes.
func TestPhase45BytesSurviveAuthentication(t *testing.T) {
	var trailing []byte
	trailing = append(trailing, paramStatusFrame("in_hot_standby", "off")...)
	trailing = append(trailing, paramStatusFrame("server_version", "18.6")...)
	trailing = append(trailing, backendKeyFrame()...)
	trailing = append(trailing, readyForQueryFrame('I')...)

	result, builder, _ := verifiedTLS(t, scramScript{trailing: trailing})

	session, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{})
	if err != nil || session == nil {
		t.Fatalf("Authenticate: %v", err)
	}

	conn, ok := session.TakeConn()
	if !ok {
		t.Fatal("the authenticated session held no connection")
	}
	t.Cleanup(func() { _ = conn.Close() })

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Frame one: ParameterStatus, byte for byte.
	kind, body := readFrame(t, conn)
	if kind != 'S' {
		t.Fatalf("first frame after authentication is %q, want 'S' (ParameterStatus)", kind)
	}
	if want := "in_hot_standby"; !bytes.HasPrefix(body, []byte(want)) {
		t.Fatalf("first ParameterStatus is %q, want one for %q", body, want)
	}

	// Frames two to four, proving nothing in the burst was consumed or reordered.
	if kind, _ := readFrame(t, conn); kind != 'S' {
		t.Fatalf("second frame is %q, want 'S'", kind)
	}
	if kind, _ := readFrame(t, conn); kind != 'K' {
		t.Fatalf("third frame is %q, want 'K' (BackendKeyData)", kind)
	}
	if kind, body := readFrame(t, conn); kind != 'Z' || string(body) != "I" {
		t.Fatalf("fourth frame is %q/%q, want 'Z'/\"I\" (ReadyForQuery)", kind, body)
	}
}

// readFrame reads one typed message straight off the connection.
func readFrame(t *testing.T, conn io.Reader) (byte, []byte) {
	t.Helper()
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("reading frame header: %v", err)
	}
	length := binary.BigEndian.Uint32(header[1:5])
	if length < 4 {
		t.Fatalf("frame announced an impossible length %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("reading frame body: %v", err)
	}
	return header[0], body
}

// --- ownership --------------------------------------------------------------

func TestOwnership(t *testing.T) {
	t.Run("success keeps the socket and consumes the startup result", func(t *testing.T) {
		result, builder, peer := verifiedTLS(t, scramScript{})

		session, err := Authenticate(
			context.Background(), builder, result, canaryCredential(t), AuthParams{})
		if err != nil || session == nil {
			t.Fatalf("Authenticate: %v", err)
		}
		t.Cleanup(func() { _ = session.Close() })

		if result.Available() {
			t.Error("the startup result still offers a connection after Authenticate")
		}
		if !session.Available() {
			t.Error("a successful authentication produced no usable connection")
		}
		if got := peer.connections(); got != 1 {
			t.Errorf("peer accepted %d connections, want 1", got)
		}
	})

	t.Run("TakeConn succeeds once", func(t *testing.T) {
		result, builder, _ := verifiedTLS(t, scramScript{})
		session, err := Authenticate(
			context.Background(), builder, result, canaryCredential(t), AuthParams{})
		if err != nil || session == nil {
			t.Fatalf("Authenticate: %v", err)
		}

		conn, ok := session.TakeConn()
		if !ok {
			t.Fatal("first TakeConn failed")
		}
		t.Cleanup(func() { _ = conn.Close() })
		if _, ok := session.TakeConn(); ok {
			t.Fatal("second TakeConn succeeded")
		}
		// Close after a transfer must not touch the transferred connection.
		if err := session.Close(); err != nil {
			t.Fatalf("Close after transfer: %v", err)
		}
		if _, err := conn.Write([]byte{'X'}); err != nil {
			t.Fatalf("the transferred connection was closed by its former owner: %v", err)
		}
	})

	t.Run("Close is idempotent", func(t *testing.T) {
		result, builder, _ := verifiedTLS(t, scramScript{})
		session, err := Authenticate(
			context.Background(), builder, result, canaryCredential(t), AuthParams{})
		if err != nil || session == nil {
			t.Fatalf("Authenticate: %v", err)
		}
		for range 3 {
			if err := session.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		}
	})

	t.Run("no failure path redials", func(t *testing.T) {
		result, builder, peer := verifiedTLS(t, scramScript{
			respondFinal: func(w io.Writer, _ []byte) {
				_, _ = w.Write(errorFrame("S", "FATAL", "V", "FATAL", "C", "28P01"))
			},
		})

		if _, err := Authenticate(
			context.Background(), builder, result, canaryCredential(t), AuthParams{}); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if got := peer.connections(); got != 1 {
			t.Errorf("peer accepted %d connections, want 1 — something redialled", got)
		}
	})
}

// TestOneCredentialAttemptPerCall proves no path retries the password.
//
// The peer counts SASLInitialResponse messages. A retry loop anywhere would send
// a second.
func TestOneCredentialAttemptPerCall(t *testing.T) {
	result, builder, peer := verifiedTLS(t, scramScript{
		respondFinal: func(w io.Writer, _ []byte) {
			_, _ = w.Write(errorFrame("S", "FATAL", "V", "FATAL", "C", "28P01"))
		},
	})

	if _, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if got := strings.Count(string(peer.afterStartup()), "SCRAM-SHA-256"); got != 1 {
		t.Errorf("peer received %d SASLInitialResponse messages, want 1", got)
	}
}

// --- budget -----------------------------------------------------------------

func TestCallerDeadlineIsNotAPeerFailure(t *testing.T) {
	result, builder, _ := verifiedTLS(t, scramScript{
		beforeContinue: nil,
		respondFinal: func(_ io.Writer, _ []byte) {
			time.Sleep(3 * time.Second)
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	session, err := Authenticate(ctx, builder, result, canaryCredential(t), AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session != nil {
		t.Fatal("an expired budget returned a session")
	}

	node := authNode(t, builder)
	if node.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", node.State())
	}
	if node.FailureClass() != domain.FailureExecLocalTimeout &&
		node.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("failure class = %s, want a local execution class", node.FailureClass())
	}
}

func TestCancellationIsNotAPeerFailure(t *testing.T) {
	result, builder, _ := verifiedTLS(t, scramScript{
		respondFinal: func(_ io.Writer, _ []byte) {
			time.Sleep(3 * time.Second)
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	session, err := Authenticate(ctx, builder, result, canaryCredential(t), AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session != nil {
		t.Fatal("a cancelled run returned a session")
	}
	if got := authNode(t, builder).State(); got != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", got)
	}
}

// TestPeerCloseIsAPeerFailure keeps the local-versus-remote distinction sharp.
func TestPeerCloseIsAPeerFailure(t *testing.T) {
	result, builder, _ := verifiedTLS(t, scramScript{
		beforeContinue: []byte{}, // write nothing, then drain and close
	})

	session, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session != nil {
		t.Fatal("a broken exchange returned a session")
	}
	requireNode(t, builder, domain.StateFail, domain.FailureProtocolPeerClosed)
}

// --- excessive iterations ---------------------------------------------------

// TestExcessiveIterationsAreAGapInSvcdoctor proves the ceiling produces UNKNOWN
// rather than FAIL, and that it costs nothing.
//
// PostgreSQL's own maximum would be minutes of PBKDF2. If this test becomes
// slow, the check moved after the derivation.
func TestExcessiveIterationsAreAGapInSvcdoctor(t *testing.T) {
	result, builder, _ := verifiedTLS(t, scramScript{iterations: 2147483647})

	started := time.Now()
	session, err := Authenticate(
		context.Background(), builder, result, canaryCredential(t), AuthParams{})
	elapsed := time.Since(started)

	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session != nil {
		t.Fatal("an excessive iteration count returned a session")
	}
	requireNode(t, builder, domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor)

	if elapsed > 5*time.Second {
		t.Fatalf("the exchange took %s — the iteration ceiling ran after the derivation", elapsed)
	}
}

// TestMalformedServerFirstIsAPeerFault covers the parser rejections at the
// adapter boundary, where the class is what a reader sees.
func TestMalformedServerFirstIsAPeerFault(t *testing.T) {
	for _, override := range []string{
		"s=MDEyMzQ1Njc4OWFiY2RlZg==,i=4096",
		"r=SHORT,s=MDEyMzQ1Njc4OWFiY2RlZg==,i=4096",
		"r=CLIENTNONCEsuffix,s=!!!,i=4096",
		"r=CLIENTNONCEsuffix,s=MDEyMzQ1Njc4OWFiY2RlZg==,i=abc",
		"garbage",
	} {
		t.Run(override, func(t *testing.T) {
			result, builder, _ := verifiedTLS(t, scramScript{serverFirstOverride: override})

			session, err := Authenticate(
				context.Background(), builder, result, canaryCredential(t), AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if session != nil {
				t.Fatal("a malformed server-first returned a session")
			}
			node := authNode(t, builder)
			if node.State() != domain.StateFail {
				t.Errorf("state = %s, want FAIL", node.State())
			}
			if node.FailureClass() != domain.FailureProtocolMalformedResponse &&
				node.FailureClass() != domain.FailureProtocolUnexpectedResponse {
				t.Errorf("failure class = %s, want a protocol class", node.FailureClass())
			}
		})
	}
}

// --- input validation -------------------------------------------------------

func TestAuthenticateRejectsUnusableInput(t *testing.T) {
	result, builder, _ := verifiedTLS(t, scramScript{})

	//nolint:staticcheck // deliberately nil, to prove the guard exists.
	if _, err := Authenticate(nil, builder, result, canaryCredential(t), AuthParams{}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil context: err = %v", err)
	}
	if _, err := Authenticate(context.Background(), nil, result, canaryCredential(t), AuthParams{}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil builder: err = %v", err)
	}
	if _, err := Authenticate(context.Background(), builder, nil, canaryCredential(t), AuthParams{}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil result: err = %v", err)
	}
	// A zero credential was in this list until Phase 4.11b. It is no longer a
	// caller defect: an endpoint that demands authentication and a run that holds
	// nothing is a diagnostic outcome, and it is recorded rather than refused.
	// See TestAZeroCredentialIsRecordedRatherThanRefused.
	if _, err := Authenticate(context.Background(), builder, result, canaryCredential(t), AuthParams{
		ExchangeTimeout: -time.Second,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("negative timeout: err = %v", err)
	}
}

// TestAZeroCredentialIsRecordedRatherThanRefused pins ADR 0046's producer.
//
// The run reaches authentication, has nothing to present, and says so. Every
// assertion here is one half of the reason the class exists: the node must be
// distinguishable from a cancelled run at the same point, and from every other
// way this step declines to continue.
func TestAZeroCredentialIsRecordedRatherThanRefused(t *testing.T) {
	result, builder, _ := verifiedTLS(t, scramScript{})

	session, err := Authenticate(
		context.Background(), builder, result, security.Credential{}, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session != nil {
		t.Fatal("a session was returned; nothing was authenticated")
	}

	node := requireNode(t, builder, domain.StateSkipped, domain.FailureExecRequiredInputMissing)

	// No mechanism was selected, so none is claimed.
	if _, ok := node.Attributes()[AttrSASLMechanism]; ok {
		t.Error("a mechanism attribute was written; svcdoctor selected none")
	}
	// Nothing describes the absent credential. There is no value to describe.
	if got := node.AttributeCount(); got != 0 {
		t.Errorf("node carries %d attributes, want 0", got)
	}
	if got := node.Duration(); got != 0 {
		t.Errorf("duration = %s, want 0: no exchange ran", got)
	}
}

// TestAnUnsupportedMechanismOutranksAMissingCredential pins the ordering.
//
// Both conditions hold: the endpoint demands something svcdoctor cannot perform,
// and the run has nothing to perform it with. The capability gap is the truthful
// report, because it would be true whatever the run held — and telling an
// operator to configure a credential for a mechanism svcdoctor cannot do would
// send them to fix the wrong thing.
func TestAnUnsupportedMechanismOutranksAMissingCredential(t *testing.T) {
	peer := newPGPeer(t, script{
		sslReply: []byte("S"), upgradeTLS: true,
		afterStartup: append(authCode(5), 1, 2, 3, 4), // md5
	})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{
		TLS:        TLSRequired,
		TLSOptions: TLSOptions{ServerName: "localhost", RootCAs: peer.ca},
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	result, err := Startup(context.Background(), builder, session,
		StartupParams{User: "payments_writer"})
	if err != nil || result == nil {
		t.Fatalf("Startup: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	if _, err := Authenticate(
		context.Background(), builder, result, security.Credential{}, AuthParams{}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	node := authNode(t, builder)
	if got := node.FailureClass(); got == domain.FailureExecRequiredInputMissing {
		t.Error("the missing credential was reported; the capability gap outranks it, " +
			"because it would be true whatever the run held")
	}
	if got := node.FailureClass(); got != domain.FailureAuthMechanismUnsupported {
		t.Errorf("class = %s, want the mechanism gap", got)
	}
}

// --- helpers ----------------------------------------------------------------

func attrString(t *testing.T, node domain.Evidence, key domain.AttributeKey) string {
	t.Helper()
	v, ok := node.Attributes()[key]
	if !ok {
		t.Fatalf("attribute %s is absent", key)
	}
	return v.String()
}

func attrInt(t *testing.T, node domain.Evidence, key domain.AttributeKey) int64 {
	t.Helper()
	v, ok := node.Attributes()[key]
	if !ok {
		t.Fatalf("attribute %s is absent", key)
	}
	n, err := strconv.ParseInt(v.String(), 10, 64)
	if err != nil {
		t.Fatalf("attribute %s = %q is not an integer", key, v.String())
	}
	return n
}

func hasParent(g domain.Graph, child, parent domain.EvidenceID) bool {
	for _, p := range g.Parents(child) {
		if p == parent {
			return true
		}
	}
	return false
}

func hasBlocker(g domain.Graph, node, blocker domain.EvidenceID) bool {
	for _, b := range g.BlockedBy(node) {
		if b == blocker {
			return true
		}
	}
	return false
}

// --- The direction contract -------------------------------------------------

// TestCredentialRejectionIsDirectionalAndSoIsItsClass is the guard the whole of
// Phase 4.6a.5 exists for.
//
// SCRAM authenticates both parties, so a failure has a direction, and the two
// directions are different observations that lead to opposite actions:
//
//	peer -> svcdoctor   the peer refused the material it was presented
//	svcdoctor -> peer   the peer failed to prove it knows the credential
//
// Until Phase 4.6a.5 both produced AUTH_CREDENTIALS_REJECTED, which was not
// merely imprecise: a server sends a server-final **only after accepting the
// client proof**, so on the second path the peer had accepted the material and
// the class stated the opposite of what happened. See ADR 0038 amendment D.
//
// This test does not go through the wire at all. It drives classify() directly,
// so it fails on the mapping itself rather than on any scripted peer, and it
// stays green only while the two directions keep separate classes.
func TestCredentialRejectionIsDirectionalAndSoIsItsClass(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		want      domain.FailureClass
		direction string
	}{
		{
			name:      "the peer refused the proof",
			err:       wire.ErrSCRAMRejected,
			want:      domain.FailureAuthCredentialsRejected,
			direction: "peer refused svcdoctor",
		},
		{
			name:      "svcdoctor refused the peer's signature",
			err:       wire.ErrServerSignatureMismatch,
			want:      domain.FailureAuthPeerVerificationFailed,
			direction: "svcdoctor refused the peer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observed := authObservation{err: tt.err, scram: wire.SCRAM{Iterations: 4096}}

			state, class := observed.classify()
			if state != domain.StateFail {
				t.Errorf("state = %s, want FAIL", state)
			}
			if class != tt.want {
				t.Fatalf("class = %s, want %s (%s)", class, tt.want, tt.direction)
			}
		})
	}

	// Stated separately and negatively, because this is the assertion a future
	// simplification is most likely to undo by "tidying" the two branches back
	// into one.
	mismatch := authObservation{err: wire.ErrServerSignatureMismatch}
	if _, class := mismatch.classify(); class == domain.FailureAuthCredentialsRejected {
		t.Error("a server-signature mismatch must never be AUTH_CREDENTIALS_REJECTED: " +
			"the peer accepted the material and then failed to prove itself")
	}

	// And the converse, so the split cannot be satisfied by moving both.
	rejected := authObservation{err: wire.ErrSCRAMRejected}
	if _, class := rejected.classify(); class == domain.FailureAuthPeerVerificationFailed {
		t.Error("a peer-side SCRAM refusal must never be AUTH_PEER_VERIFICATION_FAILED: " +
			"svcdoctor verified nothing on that path")
	}
}

// TestPeerVerificationFailureRecordsNoSCRAMValue pins that the new class carries
// no new evidence with it.
//
// The distinction is the FailureClass and nothing else. No attribute was added
// for it, so there is no field into which a signature, an expected signature or
// any other derived value could be placed — which is why this correction needed
// no redaction change. The attribute set is asserted exactly, so adding one
// later is a deliberate act rather than a drift.
func TestPeerVerificationFailureRecordsNoSCRAMValue(t *testing.T) {
	observed := authObservation{
		err:   wire.ErrServerSignatureMismatch,
		scram: wire.SCRAM{Iterations: 4096},
	}

	attributes := observed.attributes()

	want := map[domain.AttributeKey]bool{
		AttrSASLMechanism:   true,
		AttrSCRAMIterations: true,
	}
	for key := range attributes {
		if !want[key] {
			t.Errorf("unexpected attribute %q on a peer-verification failure", key)
		}
	}
	for key := range want {
		if _, ok := attributes[key]; !ok {
			t.Errorf("attribute %q is missing", key)
		}
	}

	// Nothing derived from the exchange can be here, because wire.SCRAM holds
	// none of it: there is no signature, proof, nonce, salt or auth message on
	// the struct to copy. Asserted through the rendered values rather than by
	// reading fields that do not exist.
	for key, value := range attributes {
		if strings.Contains(strings.ToLower(value.String()), "signature") {
			t.Errorf("attribute %q renders a signature-shaped value: %q", key, value.String())
		}
	}
}
