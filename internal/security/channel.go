package security

// Channel classifies what a live connection proved about the peer at the other
// end of it.
//
// It answers one question and refuses the others: **was the identity of this
// peer verified on this connection?** It is not a description of the transport,
// not a summary of the handshake, and not a judgement. Negotiated version,
// cipher suite, certificate names and expiry are diagnostic facts and live in
// the TLS evidence, where a rule can reason about them; this value exists so
// that a layer holding a connection can decide whether a secret may be written
// to it without reconstructing anything.
//
// # Why an ordered set rather than a set of booleans
//
// The obvious alternative was three facts — TLS used, verification requested,
// verification succeeded — which is more expressive and worse. Three booleans
// admit eight combinations of which five are nonsense, including "no TLS but
// verification succeeded". A value that can represent an impossible state
// eventually will, and a security decision is the wrong place to discover it.
// These four states are exactly the states that can occur.
//
// # Why it is not a "credentials permitted" flag
//
// A channel is a mechanism fact: it says what happened. Whether that is good
// enough to carry a password is policy, and it belongs to
// CredentialTransportPolicy. Merging them would put policy inside the probe that
// established the connection, which is the layer least entitled to hold it.
//
// The zero value is ChannelUnknown, which no policy accepts. A Channel that was
// never set therefore denies rather than permits.
type Channel int

const (
	// ChannelUnknown means nothing established what this connection proved.
	//
	// It is the zero value and it is deliberately not "plaintext". A connection
	// nobody classified and a connection known to be in the clear are different
	// facts, and recording the second when only the first is true would be a
	// synthetic fact of exactly the kind this project refuses elsewhere. Both
	// are refused by policy; only one of them is a claim.
	ChannelUnknown Channel = iota

	// ChannelPlaintext means no TLS was performed on this connection, so
	// everything written to it is readable by anything on the path.
	//
	// It is a positive fact, recorded because the caller did not ask for TLS —
	// never inferred from a missing TLS observation.
	ChannelPlaintext

	// ChannelTLSUnverified means a TLS handshake completed but the peer's
	// identity was not verified.
	//
	// The channel is encrypted and the peer is unknown. That is a strictly
	// weaker statement than ChannelTLSVerified and must never be treated as
	// equivalent to it: encryption to an unidentified peer is encryption to
	// whoever answered.
	ChannelTLSUnverified

	// ChannelTLSVerified means a TLS handshake completed and the peer's identity
	// was verified against the trust source in force.
	ChannelTLSVerified
)

// channelNames is indexed by Channel. TestChannelNamesCoverAllChannels fails if
// the two drift apart.
var channelNames = [...]string{
	ChannelUnknown:       "unknown",
	ChannelPlaintext:     "plaintext",
	ChannelTLSUnverified: "tls-unverified",
	ChannelTLSVerified:   "tls-verified",
}

// String implements fmt.Stringer.
//
// An undefined value renders as "unknown" rather than as a number, so a
// mis-set value reads as the safe state it is treated as.
func (c Channel) String() string {
	if !c.Valid() {
		return channelNames[ChannelUnknown]
	}
	return channelNames[c]
}

// Valid reports whether c is a defined channel. ChannelUnknown is valid: it is a
// real state, and it is the one that denies.
func (c Channel) Valid() bool {
	return c >= ChannelUnknown && int(c) < len(channelNames)
}

// IdentityVerified reports whether this channel established who the peer is.
//
// It is the single property every credential decision rests on, expressed once
// here so that no caller has to write the comparison and get it subtly wrong.
// Unknown and undefined values report false, so the failure direction is fixed
// by the implementation rather than by each caller remembering it.
func (c Channel) IdentityVerified() bool {
	return c == ChannelTLSVerified
}
