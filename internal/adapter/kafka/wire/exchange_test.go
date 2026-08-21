package wire

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// The framing itself is exercised end to end through the adapter's tests, over
// real sockets and a fake broker. What is tested here is the one guard those
// tests cannot reach, because no current request kind can trip it.

// TestFlexibleMessagesAreRefused protects the next phase from a silent bug.
//
// A flexible response carries tagged fields in its header, which readResponse
// does not consume, so decoding one as though it were header v0 would misparse
// the body rather than fail. SaslAuthenticate v2 is flexible; v0 and v1 are not.
// Whoever adds authentication has to make that choice deliberately, and this is
// what makes the wrong one loud.
func TestFlexibleMessagesAreRefused(t *testing.T) {
	request := kmsg.NewPtrSASLAuthenticateRequest()
	request.SetVersion(2)
	response := kmsg.NewPtrSASLAuthenticateResponse()
	response.SetVersion(2)

	if !request.IsFlexible() || !response.IsFlexible() {
		t.Fatal("precondition: SaslAuthenticate v2 is expected to be flexible")
	}

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	err := exchange(context.Background(), client, correlationSASLHandshake, request, response)
	if err == nil {
		t.Fatal("a flexible message was accepted by a reader that cannot parse its header")
	}
	if !strings.Contains(err.Error(), "flexible") {
		t.Errorf("error = %v, want one naming the reason", err)
	}
}

// TestNonFlexibleMessagesPassTheGuard is the other half: the versions this
// package actually sends must not be refused by it.
func TestNonFlexibleMessagesPassTheGuard(t *testing.T) {
	cases := []struct {
		name     string
		version  int16
		request  kmsg.Request
		response kmsg.Response
	}{
		{
			"api versions", apiVersionsRequestVersion,
			kmsg.NewPtrApiVersionsRequest(), kmsg.NewPtrApiVersionsResponse(),
		},
		{
			"sasl handshake", saslHandshakeRequestVersion,
			kmsg.NewPtrSASLHandshakeRequest(), kmsg.NewPtrSASLHandshakeResponse(),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tt.request.SetVersion(tt.version)
			tt.response.SetVersion(tt.version)

			if tt.request.IsFlexible() || tt.response.IsFlexible() {
				t.Errorf("%s v%d is flexible; this package's framing does not support it",
					tt.name, tt.version)
			}
		})
	}
}

// TestVersionsMatchTheProtocolFlow pins the two version choices, because both
// are decisions rather than defaults: ApiVersions v0 is the one every broker
// answers, and SaslHandshake v1 is the flow whose authentication failures arrive
// as error codes rather than as a closed socket. See ADR 0025 and ADR 0026.
func TestVersionsMatchTheProtocolFlow(t *testing.T) {
	if got := RequestAPIVersion(); got != 0 {
		t.Errorf("ApiVersions version = %d, want 0", got)
	}
	if got := SASLHandshakeVersion(); got != 1 {
		t.Errorf("SaslHandshake version = %d, want 1", got)
	}
}

// TestExchangeRefusesNoConnection covers the caller error that would otherwise
// surface as a nil dereference inside the framing.
func TestExchangeRefusesNoConnection(t *testing.T) {
	_, err := ExchangeSASLHandshake(context.Background(), nil, "PLAIN")
	if err == nil {
		t.Fatal("a nil connection was accepted")
	}
	// It is a caller defect, not a diagnostic fact, so it must not look like one.
	for _, sentinel := range []error{ErrPeerClosed, ErrNotKafka, ErrMalformedResponse} {
		if errors.Is(err, sentinel) {
			t.Errorf("a caller defect was classified as %v", sentinel)
		}
	}
}
