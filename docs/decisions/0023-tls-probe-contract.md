# ADR 0023: The TLS probe consumes a connection, verifies an identity, and hands the connection on

## Status

Accepted.

## Decision

The TLS probe performs a handshake **over a connection it is given** and returns
the wrapped connection plus one evidence node. It never dials and never resolves.

```go
conn, _ := tcpResult.TakeConn()
r, err := tls.Handshake(ctx, conn, tls.Params{
    Endpoint: "primary.internal:9092",   // scope for the identifier
    Address:  addr,                      // the concrete peer: becomes the subject
    ServerName: "primary.internal",      // the identity to verify
})
```

### It takes ownership unconditionally

After `Handshake` returns, the connection is never the caller's again — in every
outcome, including a returned error. A failed handshake closes it; a successful
one leaves it owned by the returned `Result` under the ADR 0021 rules.

The alternative, transferring ownership only on success, was rejected: a caller
would have to know which outcomes left it responsible, and would eventually
forget. "Once you pass it, it is ours" is the only version that cannot leak.

Because a `crypto/tls.Conn` wraps and closes what it was given, there is never a
moment where a raw and a wrapped value both need closing. The wrapper is the
resource.

### The subject is the peer; the server name is an attribute

A handshake happens over a concrete address and verifies a logical name. Those
are two facts:

```text
subject          10.0.0.7:9092        the socket the handshake ran over
tls.server_name  primary.internal     the identity the certificate was checked against
```

Overwriting the subject with the server name would claim the socket went
somewhere it did not, and would break correlation with the L2 node, which carries
the same address. Recording only the subject would lose what was verified — the
whole point of a hostname-mismatch diagnosis.

The server name is never inferred from the address. A caller that wants an IP
verified passes it deliberately.

### Verification is on, and disabling it is recorded on the node

The zero `Params` verifies against the system trust store. `InsecureSkipVerify`
is per-attempt, explicit, and **never an automatic fallback**: a failed verified
handshake is evidence, and silently retrying without verification would convert a
safety failure into a successful-looking result.

`tls.verified` is recorded on every node, true only when the handshake completed
*and* verification was enabled. It is not a duplicate of the report's
`tlsVerificationDisabled`: that field is run configuration, while this is what
this handshake actually did. The distinction is load-bearing because **diagnosis
receives only the evidence graph** (ADR 0017), so a rule can never see report
security metadata. A fact recorded only there would be invisible to the layer
that has to reason about it.

`tls.trust_source` records `system` or `custom`, and is absent when verification
was disabled because no trust source was consulted. It never records a filesystem
path: a path is identity a shareable report has no way to redact.

### Facts, never judgements

The probe records that a certificate is valid until an instant, that the version
is TLS1.2, that a named cipher was chosen. It never records that an expiry is
*soon*, a version *old*, or a cipher *weak*. Those need policy, and policy is
diagnosis work on frozen evidence.

### Classification uses typed errors, and stops where the standard library does

| Observation | State | Class |
|---|---|---|
| handshake completed | PASS | — |
| peer's first record was not TLS | FAIL | `TLS_PEER_NOT_TLS` |
| certificate name did not match | FAIL | `TLS_HOSTNAME_MISMATCH` |
| certificate outside its validity window | FAIL | `TLS_CERTIFICATE_EXPIRED` / `_NOT_YET_VALID` |
| chain did not verify | FAIL | `TLS_UNKNOWN_AUTHORITY` |
| any other handshake failure | FAIL | `TLS_HANDSHAKE_FAILURE` |
| unattributable timeout, caller deadline | UNKNOWN | `EXEC_LOCAL_TIMEOUT` |
| caller cancelled | UNKNOWN | `EXEC_CANCELLED` |

Two distinctions were investigated against the real standard library and
deliberately **not** made:

- **Version mismatch.** A received `protocol_version` alert arrives as an
  unexported error type; `tls.AlertError` matches only locally generated alerts.
  So a version mismatch is `TLS_HANDSHAKE_FAILURE`. `TLS_VERSION_MISMATCH` stays
  reserved.
- **Unknown authority versus other verification failures.** On platforms using
  the system verifier the error is opaque rather than
  `x509.UnknownAuthorityError`. Rather than classify differently per platform,
  any unrecognized `CertificateVerificationError` is `TLS_UNKNOWN_AUTHORITY`,
  whose contract — "the chain did not verify against the trust source" — is
  exactly what that error proves everywhere.

Expired versus not-yet-valid *is* distinguished, because `x509` reports one
reason for both but carries the certificate, so the comparison is against its own
dates rather than against the error's prose.

`TLS_CLIENT_CERTIFICATE_REQUIRED` and `_REJECTED` stay reserved: mTLS is not
implemented. `TestReservedClassesAreNeverProduced` keeps all three reserved
classes honest.

### Deferred, explicitly

- **mTLS.** No caller can supply a client certificate yet. Doing it properly means
  private key material in a parameter struct, and secret source resolution is
  Phase 5. `Params` can gain a field without breaking anything.
- **ALPN.** Neither v0.1 service uses it, so a requested-protocol list would have
  no consumer and a negotiated-protocol attribute would always be empty. Note the
  distinction for whoever adds it: the requested list is caller configuration, the
  negotiated protocol is evidence.
- **Custom trust material loading.** `Params` accepts an assembled
  `*x509.CertPool`; reading one from disk belongs to the layer that owns files.

## Context

`docs/ARCHITECTURE.md` section 4 has required since Phase 0 that generic
transport own DNS, TCP and TLS and hand a live connection onward. Phase 2.2 made
that concrete for TCP. TLS is the first layer that is both a consumer and a
producer of that contract, which is what makes it the real test of ADR 0021.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| A `Handshaker` test seam | Every case — verified, unknown authority, hostname mismatch, expiry, version mismatch, plaintext peer, hang-up, cancellation — is reproducible against a real `crypto/tls` server on a loopback listener the test controls. An interface with no test consumer is exactly the speculative abstraction the architecture forbids | A case appears that a controlled peer cannot produce |
| The TLS probe accepting a `tcp.Result` | Couples one probe to another's ownership type and makes TLS the sequencer. Sequencing is the transport chain's job, and TLS should work over any connection, including one no TCP probe produced | Never |
| Transferring ownership only on success | The caller would have to know which outcomes left it responsible; the version that cannot leak is the one where passing the connection always transfers it | Never |
| Overwriting the subject with the server name | Claims the socket went somewhere it did not, and breaks correlation with the L2 node | Never |
| Recording the certificate's subject or issuer DN | An unstructured string carrying arbitrary identity, which structural redaction cannot safely handle and which no planned rule needs | A rule needs a fact only the DN carries |
| Recording a certificate fingerprint or serial | No consumer, and a fingerprint is a stable identifier of a deployment | A pinning check exists |
| Disabling verification to collect more certificate facts | Would convert a safety failure into a successful-looking result. The rejected chain is available through the verification error anyway | Never |
| Reimplementing chain verification to classify errors precisely | Custom crypto for cosmetic classification. The conservative class is honest and free | Never |
| A shared `Result` abstraction across tcp and tls | Two structs that look alike are not yet a pattern; they hold different things and are used at different layers | A third appears and all three genuinely need one contract |

## Consequences

- The protocol layer will speak over the connection whose DNS, TCP and TLS facts
  were all measured — the end-to-end goal of the transport engine.
- A shareable TLS report keeps the negotiated version, the cipher, the validity
  window and whether identity was verified, while every name and address in it is
  pseudonymized (ADR 0022).
- The probe is testable end to end with real `crypto/tls` on both sides and no
  network, which is why it needs no seam of its own.
- Certificate facts are recorded on verification failure as well as success,
  because the rejected chain is what makes a failure actionable.
