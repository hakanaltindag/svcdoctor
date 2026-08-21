package security

import (
	"fmt"
	"strings"
	"testing"
)

// TestChannelNamesCoverAllChannels fails if a channel is added without a name,
// which would otherwise surface as an empty string in a report.
func TestChannelNamesCoverAllChannels(t *testing.T) {
	// Four states. Updating this number is meant to be a deliberate act: a new
	// channel is a new thing a connection can prove, and every policy that reads
	// one has to be revisited.
	const want = 4
	if got := len(channelNames); got != want {
		t.Fatalf("channelNames has %d entries, want %d", got, want)
	}
	for i, name := range channelNames {
		if name == "" {
			t.Errorf("channel %d has no name", i)
		}
	}
}

func TestChannelStrings(t *testing.T) {
	cases := map[Channel]string{
		ChannelUnknown:       "unknown",
		ChannelPlaintext:     "plaintext",
		ChannelTLSUnverified: "tls-unverified",
		ChannelTLSVerified:   "tls-verified",
	}
	for channel, want := range cases {
		if got := channel.String(); got != want {
			t.Errorf("Channel(%d).String() = %q, want %q", channel, got, want)
		}
	}
}

// TestZeroChannelIsUnknown pins the zero value. A Continuation, Session or
// policy field that nobody set must not claim anything about a connection.
func TestZeroChannelIsUnknown(t *testing.T) {
	var c Channel
	if c != ChannelUnknown {
		t.Errorf("zero Channel = %d, want ChannelUnknown", c)
	}
	if c.IdentityVerified() {
		t.Error("the zero Channel claims a verified identity")
	}
}

// TestUnknownIsNotPlaintext is the distinction section 3 of the phase brief
// insisted on: absence of a classification is not a positive security fact.
func TestUnknownIsNotPlaintext(t *testing.T) {
	if ChannelUnknown == ChannelPlaintext {
		t.Fatal("unknown and plaintext are the same value")
	}
	if ChannelUnknown.String() == ChannelPlaintext.String() {
		t.Error("unknown and plaintext render identically, so a report cannot tell them apart")
	}
}

// TestOnlyVerifiedTLSVerifiesIdentity is the single property every credential
// decision rests on.
func TestOnlyVerifiedTLSVerifiesIdentity(t *testing.T) {
	verified := map[Channel]bool{
		ChannelUnknown:       false,
		ChannelPlaintext:     false,
		ChannelTLSUnverified: false,
		ChannelTLSVerified:   true,
	}
	for channel, want := range verified {
		if got := channel.IdentityVerified(); got != want {
			t.Errorf("%s.IdentityVerified() = %v, want %v", channel, got, want)
		}
	}
}

// TestUndefinedChannelIsTreatedAsUnknown covers a value that arrives from a
// future parser, a corrupted read, or an integer somebody cast.
func TestUndefinedChannelIsTreatedAsUnknown(t *testing.T) {
	for _, c := range []Channel{Channel(-1), Channel(99)} {
		if c.Valid() {
			t.Errorf("Channel(%d) reports itself valid", c)
		}
		if c.IdentityVerified() {
			t.Errorf("Channel(%d) claims a verified identity", c)
		}
		if got := c.String(); got != "unknown" {
			t.Errorf("Channel(%d).String() = %q, want unknown", c, got)
		}
	}
}

// --- policy ----------------------------------------------------------------

// TestZeroPolicyRequiresVerifiedTLS is the fail-closed guarantee. A policy that
// was never set, never parsed or never threaded through a call chain must be the
// strictest one, not the most permissive.
func TestZeroPolicyRequiresVerifiedTLS(t *testing.T) {
	var policy CredentialTransportPolicy

	if policy != RequireVerifiedTLS {
		t.Errorf("zero policy = %d, want RequireVerifiedTLS", policy)
	}
	if got := policy.String(); got != "require-verified-tls" {
		t.Errorf("zero policy String() = %q", got)
	}
	if policy.PermitsCredentials(ChannelPlaintext) {
		t.Error("the zero policy permits credentials over plaintext")
	}
	if !policy.PermitsCredentials(ChannelTLSVerified) {
		t.Error("the zero policy refuses credentials over verified TLS, so nothing could ever authenticate")
	}
}

func TestPolicyPermitsOnlyVerifiedTLS(t *testing.T) {
	var policy CredentialTransportPolicy

	cases := map[Channel]bool{
		ChannelUnknown:       false,
		ChannelPlaintext:     false,
		ChannelTLSUnverified: false,
		ChannelTLSVerified:   true,
	}
	for channel, want := range cases {
		if got := policy.PermitsCredentials(channel); got != want {
			t.Errorf("PermitsCredentials(%s) = %v, want %v", channel, got, want)
		}
	}
}

// TestEncryptedIsNotVerified is the mistake this whole phase exists to make
// impossible: a completed handshake with verification off proves the channel is
// encrypted and proves nothing about who is on the other end.
func TestEncryptedIsNotVerified(t *testing.T) {
	var policy CredentialTransportPolicy

	if policy.PermitsCredentials(ChannelTLSUnverified) {
		t.Fatal("credentials are permitted over TLS with verification disabled")
	}
	if ChannelTLSUnverified == ChannelTLSVerified {
		t.Fatal("verified and unverified TLS are the same value")
	}
}

// TestUndefinedPolicyDenies covers the other direction of "I do not know": a
// policy value nobody defined must refuse rather than fall through to a default
// that happens to permit.
func TestUndefinedPolicyDenies(t *testing.T) {
	for _, p := range []CredentialTransportPolicy{CredentialTransportPolicy(-1), CredentialTransportPolicy(7)} {
		for _, channel := range []Channel{
			ChannelUnknown, ChannelPlaintext, ChannelTLSUnverified, ChannelTLSVerified,
		} {
			if p.PermitsCredentials(channel) {
				t.Errorf("undefined policy %d permitted credentials over %s", p, channel)
			}
		}
		if got := p.String(); got != "require-verified-tls" {
			t.Errorf("undefined policy %d String() = %q, want the strictest name", p, got)
		}
	}
}

// TestPolicyHasExactlyOneValue pins the section 6 decision: no unsafe override
// exists, because no layer can own one yet. Adding a weaker member is meant to
// be a visible change to this file with an ADR attached, and this test is what
// makes it visible.
func TestPolicyHasExactlyOneValue(t *testing.T) {
	if RequireVerifiedTLS != 0 {
		t.Error("RequireVerifiedTLS is not the zero value")
	}
	// Every value other than the single defined one denies everything, so no
	// integer a caller could invent becomes a bypass.
	for i := 1; i < 16; i++ {
		p := CredentialTransportPolicy(i)
		if p.PermitsCredentials(ChannelTLSVerified) {
			t.Errorf("policy value %d permits credentials; an undeclared bypass exists", i)
		}
	}
}

// TestPolicyCarriesNoJudgement pins the boundary against diagnosis. The policy
// answers one question with a bool. It has no severity, no finding, and no
// explanation of what a refusal means for the user.
func TestPolicyCarriesNoJudgement(t *testing.T) {
	var policy any = RequireVerifiedTLS

	if _, ok := policy.(interface{ Severity() int }); ok {
		t.Error("the policy carries a severity")
	}
	if _, ok := policy.(interface{ Finding() string }); ok {
		t.Error("the policy produces a finding")
	}
	if _, ok := policy.(interface{ Explain() string }); ok {
		t.Error("the policy explains itself, which is a renderer's job")
	}

	var channel any = ChannelTLSVerified
	if _, ok := channel.(interface{ Severity() int }); ok {
		t.Error("the channel carries a severity")
	}
}

// TestChannelAndPolicyCarryNoIdentity checks that neither type can leak a
// hostname, an address or a secret into whatever prints it.
func TestChannelAndPolicyCarryNoIdentity(t *testing.T) {
	rendered := []string{
		ChannelUnknown.String(), ChannelPlaintext.String(),
		ChannelTLSUnverified.String(), ChannelTLSVerified.String(),
		RequireVerifiedTLS.String(),
		fmt.Sprintf("%v %+v %#v", ChannelTLSVerified, ChannelTLSVerified, ChannelTLSVerified),
		fmt.Sprintf("%v %+v %#v", RequireVerifiedTLS, RequireVerifiedTLS, RequireVerifiedTLS),
	}
	for _, s := range rendered {
		for _, forbidden := range []string{".", ":", "/", "@"} {
			if strings.Contains(s, forbidden) {
				t.Errorf("rendered value %q contains %q, which an identity could hide in", s, forbidden)
			}
		}
	}
}
