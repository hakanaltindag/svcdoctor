package wire

import "strings"

// ErrorPrefix is a normalized Redis error condition.
//
// It is the **only** thing a peer's error reply contributes beyond this package.
// ADR 0066 fixes that boundary and gives two upstream reasons for it, both
// verified rather than assumed:
//
//   - Redis interpolates the caller's own command arguments into an unknown-
//     command error (redis/src/server.c:4386), and the username into every
//     NOPERM (redis/src/acl.c:2871). Error text is peer-controlled and
//     caller-controlled at once.
//   - Valkey parameterizes the shared error strings by server name
//     (valkey/src/server.c:2138), so the *text* differs between implementations
//     while the prefix is byte-identical. Classifying on text would make the
//     Redis fixture and the Valkey fixture disagree about the same condition.
//
// # Why it is a closed set rather than a pass-through of the first token
//
// The RESP specification calls the prefix "a convention used by Redis rather
// than part of the RESP error type", so the first token of an error is not a
// protocol field and cannot be trusted to be one. A peer is free to send
// "-<four kilobytes of anything>". Matching against a closed set and collapsing
// everything else into PrefixUnrecognized means no peer-chosen byte ever becomes
// a value in the report, not even a short one.
//
// A prefix a future Redis adds arrives as PrefixUnrecognized, which is truthful:
// svcdoctor did not classify it. Nothing breaks, and nothing is invented.
type ErrorPrefix string

// The prefixes svcdoctor classifies.
//
// The first block is reachable from the frozen journey. The second is recognized
// defensively: ADR 0065 proves those cannot arrive on a keyless command, and
// recognizing them costs one map entry each while guaranteeing that if one ever
// did arrive it would be named rather than silently becoming "unrecognized".
const (
	// PrefixNone means the reply was not an error.
	PrefixNone ErrorPrefix = ""

	// PrefixUnrecognized means the peer sent an error whose prefix svcdoctor
	// does not classify. It is a statement about svcdoctor's vocabulary and
	// never about the peer being wrong.
	PrefixUnrecognized ErrorPrefix = "UNRECOGNIZED"

	// Reachable from HELLO, AUTH or PING.

	PrefixNOAUTH     ErrorPrefix = "NOAUTH"
	PrefixWRONGPASS  ErrorPrefix = "WRONGPASS"
	PrefixNOPERM     ErrorPrefix = "NOPERM"
	PrefixDENIED     ErrorPrefix = "DENIED"
	PrefixLOADING    ErrorPrefix = "LOADING"
	PrefixMASTERDOWN ErrorPrefix = "MASTERDOWN"
	PrefixBUSY       ErrorPrefix = "BUSY"
	PrefixERR        ErrorPrefix = "ERR"

	// Recognized defensively. ADR 0065 gives none of these an owner, because a
	// keyless command is never cluster-redirected and svcdoctor never writes.

	PrefixNOPROTO     ErrorPrefix = "NOPROTO"
	PrefixMOVED       ErrorPrefix = "MOVED"
	PrefixASK         ErrorPrefix = "ASK"
	PrefixCLUSTERDOWN ErrorPrefix = "CLUSTERDOWN"
	PrefixTRYAGAIN    ErrorPrefix = "TRYAGAIN"
	PrefixCROSSSLOT   ErrorPrefix = "CROSSSLOT"
	PrefixOOM         ErrorPrefix = "OOM"
	PrefixMISCONF     ErrorPrefix = "MISCONF"
	PrefixREADONLY    ErrorPrefix = "READONLY"
	PrefixNOREPLICAS  ErrorPrefix = "NOREPLICAS"
	PrefixWRONGTYPE   ErrorPrefix = "WRONGTYPE"
	PrefixEXECABORT   ErrorPrefix = "EXECABORT"
	PrefixNOSCRIPT    ErrorPrefix = "NOSCRIPT"
	PrefixUNBLOCKED   ErrorPrefix = "UNBLOCKED"
	PrefixNOTBUSY     ErrorPrefix = "NOTBUSY"
)

// classified is the closed set. Membership is the whole of the classification
// rule: there is no pattern, no prefix match and no case folding beyond the
// exact upper-case token Redis and Valkey both emit.
var classified = map[string]ErrorPrefix{
	"NOAUTH":      PrefixNOAUTH,
	"WRONGPASS":   PrefixWRONGPASS,
	"NOPERM":      PrefixNOPERM,
	"DENIED":      PrefixDENIED,
	"LOADING":     PrefixLOADING,
	"MASTERDOWN":  PrefixMASTERDOWN,
	"BUSY":        PrefixBUSY,
	"ERR":         PrefixERR,
	"NOPROTO":     PrefixNOPROTO,
	"MOVED":       PrefixMOVED,
	"ASK":         PrefixASK,
	"CLUSTERDOWN": PrefixCLUSTERDOWN,
	"TRYAGAIN":    PrefixTRYAGAIN,
	"CROSSSLOT":   PrefixCROSSSLOT,
	"OOM":         PrefixOOM,
	"MISCONF":     PrefixMISCONF,
	"READONLY":    PrefixREADONLY,
	"NOREPLICAS":  PrefixNOREPLICAS,
	"WRONGTYPE":   PrefixWRONGTYPE,
	"EXECABORT":   PrefixEXECABORT,
	"NOSCRIPT":    PrefixNOSCRIPT,
	"UNBLOCKED":   PrefixUNBLOCKED,
	"NOTBUSY":     PrefixNOTBUSY,
}

// String implements fmt.Stringer.
func (p ErrorPrefix) String() string { return string(p) }

// classifyErrorText normalizes one error reply to a prefix.
//
// # It reads exactly one token and discards the rest
//
// The remainder of the line is the part that carries the username, the echoed
// command arguments and the implementation's name. It is not returned, not
// logged, not wrapped into an error and not retained on the reply value that
// leaves this function's caller.
//
// The token itself is only ever *compared*. A match returns the constant from
// this package — never a slice of the peer's bytes — so a report can contain a
// prefix svcdoctor knows and nothing a peer chose.
func classifyErrorText(text string) ErrorPrefix {
	token := text
	if i := strings.IndexAny(token, " \t"); i >= 0 {
		token = token[:i]
	}
	if prefix, ok := classified[token]; ok {
		return prefix
	}
	return PrefixUnrecognized
}
