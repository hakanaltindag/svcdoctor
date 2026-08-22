package wire

import (
	"bytes"
	"encoding/binary"
)

// AuthMethod is the authentication a server demanded, normalized.
//
// This is **discovery only**. Phase 4.3 identifies what was asked for and
// performs none of it: there is no code in this repository that answers a
// password request, computes an MD5 digest or runs a SCRAM exchange. The type
// exists so a later phase can decide whether it is able to continue, and so the
// current phase can record what the server wanted.
//
// The zero value is AuthMethodUnknown, which is what an unrecognized code
// becomes. A future PostgreSQL method must not turn a diagnostic run into a
// decode failure: "the server asked for something svcdoctor does not recognize"
// is a better report than an error.
type AuthMethod uint8

const (
	// AuthMethodUnknown means the code was not one this package recognizes.
	AuthMethodUnknown AuthMethod = iota
	// AuthMethodOK is code 0: no authentication is required, and the startup
	// exchange has already succeeded.
	AuthMethodOK
	// AuthMethodKerberosV5 is code 2. PostgreSQL no longer supports it.
	AuthMethodKerberosV5
	// AuthMethodCleartextPassword is code 3.
	AuthMethodCleartextPassword
	// AuthMethodMD5Password is code 5, followed by a four-byte salt.
	AuthMethodMD5Password
	// AuthMethodSCMCredential is code 6, a local-socket mechanism.
	AuthMethodSCMCredential
	// AuthMethodGSS is code 7.
	AuthMethodGSS
	// AuthMethodGSSContinue is code 8.
	AuthMethodGSSContinue
	// AuthMethodSSPI is code 9.
	AuthMethodSSPI
	// AuthMethodSASL is code 10, followed by the mechanism list.
	AuthMethodSASL
	// AuthMethodSASLContinue is code 11.
	AuthMethodSASLContinue
	// AuthMethodSASLFinal is code 12.
	AuthMethodSASLFinal
)

// authMethodNames is indexed by AuthMethod. The strings reach a report as the
// postgres.auth_method attribute, so they are contract.
var authMethodNames = [...]string{
	AuthMethodUnknown:           "unknown",
	AuthMethodOK:                "ok",
	AuthMethodKerberosV5:        "kerberos",
	AuthMethodCleartextPassword: "cleartext",
	AuthMethodMD5Password:       "md5",
	AuthMethodSCMCredential:     "scm",
	AuthMethodGSS:               "gss",
	AuthMethodGSSContinue:       "gss-continue",
	AuthMethodSSPI:              "sspi",
	AuthMethodSASL:              "sasl",
	AuthMethodSASLContinue:      "sasl-continue",
	AuthMethodSASLFinal:         "sasl-final",
}

// String returns the stable name recorded as evidence.
func (m AuthMethod) String() string {
	if int(m) >= len(authMethodNames) {
		return authMethodNames[AuthMethodUnknown]
	}
	return authMethodNames[m]
}

// authMethodByCode maps the protocol's integers onto the normalized set. Codes
// 1 and 4 are unused by PostgreSQL and are absent rather than reserved.
var authMethodByCode = map[uint32]AuthMethod{
	0:  AuthMethodOK,
	2:  AuthMethodKerberosV5,
	3:  AuthMethodCleartextPassword,
	5:  AuthMethodMD5Password,
	6:  AuthMethodSCMCredential,
	7:  AuthMethodGSS,
	8:  AuthMethodGSSContinue,
	9:  AuthMethodSSPI,
	10: AuthMethodSASL,
	11: AuthMethodSASLContinue,
	12: AuthMethodSASLFinal,
}

// AuthRequest is what an Authentication message asked for.
//
// It carries the normalized method, the raw code so an unrecognized one is still
// reportable, and — for SASL only — the mechanism names the server advertised.
//
// **It carries no challenge data.** The MD5 salt, the SCRAM server-first message
// and the GSS token are all deliberately absent: nothing in this phase answers a
// challenge, and a field holding challenge material would be a half-built
// authentication engine sitting in a package that must not have one. A later
// phase adds what it actually needs, at the point where it can use it.
type AuthRequest struct {
	Method AuthMethod
	Code   uint32

	// Mechanisms are the SASL mechanism names, in the order the server listed
	// them, which is its preference order.
	//
	// They are parsed here because the list is the one thing a later phase must
	// read before it can decide whether it is able to authenticate at all, and
	// because it is a fact worth recording now: the list is channel-dependent —
	// a real server offers SCRAM-SHA-256-PLUS only over TLS — so it says
	// something about the connection as well as the server.
	Mechanisms []string
}

// DecodeAuthRequest decodes the body of an Authentication message.
//
// The body is a 32-bit code, optionally followed by method-specific data. Only
// the SASL mechanism list is read; every other trailing payload is left
// unexamined, because nothing here answers a challenge.
func DecodeAuthRequest(body []byte) (AuthRequest, error) {
	if len(body) < 4 {
		return AuthRequest{}, ErrMalformedMessage
	}

	code := binary.BigEndian.Uint32(body[0:4])
	out := AuthRequest{Code: code, Method: authMethodByCode[code]}

	if out.Method != AuthMethodSASL {
		return out, nil
	}

	mechanisms, err := decodeMechanisms(body[4:])
	if err != nil {
		return AuthRequest{}, err
	}
	out.Mechanisms = mechanisms
	return out, nil
}

// decodeMechanisms reads a NUL-terminated list of names ended by an empty name.
//
// A list without its terminator is malformed for the same reason a field list is:
// the sender said there was more and there was not.
func decodeMechanisms(body []byte) ([]string, error) {
	var out []string
	for i := 0; i < len(body); {
		if body[i] == 0 {
			// The empty name that ends the list.
			return out, nil
		}
		end := bytes.IndexByte(body[i:], 0)
		if end < 0 {
			return nil, ErrMalformedMessage
		}
		out = append(out, string(body[i:i+end]))
		i += end + 1
	}
	return nil, ErrMalformedMessage
}
