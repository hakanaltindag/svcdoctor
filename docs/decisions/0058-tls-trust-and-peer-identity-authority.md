# ADR 0058: Trust answers "whose certificate is this"; identity answers "is it the peer I meant"

## Status

**Accepted in Phase 6.6, as policy. Not implemented, because almost nothing needs
implementing.**

Phase 6.6 was a decision phase and changed no production Go. The policy below is
overwhelmingly a *ratification* of what `internal/probe/tls`,
`internal/probe/transport`, `internal/adapter/postgres` and `internal/app`
already do — which is the outcome a review should hope for and is not the
outcome it should assume. Every clause was checked against source, and the
externally-observable ones against the Go standard library rather than against
its documentation.

Three product gaps were found. None is a trust or identity defect; all three
are recorded in §14 with their reproduction and deferred to Phase 6.7:

1. the terminal renderer never says that peer verification was disabled,
2. PostgreSQL accepts TLS flags that its own `--tls disable` makes inert, where
   Kafka refuses them,
3. a plaintext PostgreSQL run can report `tlsVerificationDisabled: true`.

Two clauses of the policy turned out to be **unguarded rather than unimplemented**
— trust replacement and the chain's server-name rule — and the mutation matrix in
§15 is how that was found. Three test files close them and a third pins Go's
IP-SAN behaviour for Phase 6.7. No production Go changed.

This ADR closes the standing *TLS Trust & Identity Policy Review* backlog item.
It does not close IP-literal target semantics (Phase 6.7), managed-service
compatibility, or Redpanda compatibility.

## Context

svcdoctor decides what to trust and whose identity to check on every TLS
handshake it performs, and until now that decision was implicit — spread across a
probe, a chain, two adapters and two CLI commands, with no single record saying
what it *is*. Three bodies of work were queued behind it: IP-literal targets,
managed-service compatibility, and release validation. Each would have made a
trust or identity assumption, and without this record each would have made its
own.

The product constraint is the one that governs everything else:

> svcdoctor diagnoses what it can prove from the exact execution path it
> performed, and never silently weakens TLS verification to make a diagnosis
> succeed.

## Threat model

What this policy is defending against, in the order it matters:

- **An operator believing a channel was authenticated when it was not.** The
  primary risk, and the only one svcdoctor can create by itself. A tool that
  reports `✓ PASS TLS` for an unverified handshake has manufactured a false
  belief that no attacker had to work for.
- **Trust widening by accident.** An unusable `--tls-ca-file` that quietly falls
  back to the system store hands an operator public-CA trust when they asked for
  one private issuer. The operator sees success and concludes their private PKI
  is correct.
- **A peer choosing its own identity.** Kafka's Metadata response is
  peer-supplied. If a broker could nominate the name its own certificate is
  checked against, certificate verification would be a formality.
- **Discovery escalating into credential authority.** A hostile advertised
  endpoint presenting a perfectly valid certificate for *itself* must not thereby
  become somewhere a password may go.
- **Resolution silently relocating identity.** If connecting to `10.0.0.14` made
  `10.0.0.14` the identity to verify, then anything that can influence DNS can
  choose the certificate svcdoctor will accept.

Explicitly **not** in the model: defending the operator's own machine from the
operator, protecting against a compromised system trust store, and certificate
transparency, revocation or pinning. None is refused on principle; none is in
BASIC, and §17 records the reopen condition for revocation.

## 1. Trust and identity are two questions, and collapsing them is the defect

    TRUST     does this chain verify against the roots this run was given?
    IDENTITY  does the certificate at the end of that chain name the peer I meant?

Both must hold. Neither implies the other, and the failure modes lead operators
to opposite actions: a trust failure is usually *the trust context is wrong*, and
an identity failure is usually *you are talking to the wrong thing, or a
certificate needs a name added*.

svcdoctor already keeps them apart in its finding vocabulary — `TLS_CHAIN_NOT_TRUSTED`
and `TLS_IDENTITY_MISMATCH` are separate codes with separate recommendations
(ADR 0053) — and this ADR fixes that as policy rather than as an accident of the
five-code split.

**A trusted chain with the wrong identity is never reported as successful peer
verification.** Go enforces this for us: certificate verification is one
operation and it fails if either half fails.

## 2. Trust-source policy: the supplied CA REPLACES the system store

**Model A. Accepted.** When `--tls-ca-file` is supplied, it is the *complete*
trust source for the run. System roots are not consulted.

This is what the code does today — `tls.Config.RootCAs`, when non-nil, is used
instead of the host's root set — and it was verified rather than assumed: an
empty non-nil `CertPool` rejects a certificate that the same pool populated would
accept, which is only possible if a non-nil pool is authoritative.

Rejected alternatives:

- **Model B, system + custom.** Rejected as the default. It cannot express *"only
  this issuer is acceptable here"*, which is the request an operator is making
  when they name a CA file. Worse, it is silently forgiving: an operator who
  supplies the *wrong* CA still gets a passing handshake against a
  publicly-issued certificate, and concludes their private PKI is configured
  correctly. A diagnostic tool that reports success for a configuration that is
  wrong is worse than one that reports failure.
- **Model C, custom-only-when-supplied-but-system-otherwise.** This is Model A
  described differently, and the wording invites the reader to think a third
  behaviour exists.
- **Model D, explicit modes.** A `--tls-trust replace|append` flag is a real
  option and is deliberately not taken now. It adds a flag to serve a case
  nobody has reported, and it can be added later without invalidating anything
  here: today's behaviour becomes `replace`, which stays the default. §17 records
  the reopen condition.

The evaluation that decided it:

| | Model A (replace) | Model B (append) |
|---|---|---|
| least surprise | matches `curl --cacert`, `openssl -CAfile`, Go, and `libpq` `sslrootcert` | matches almost nothing |
| private PKI | exact | works, and also works when misconfigured |
| managed services | operator supplies the provider bundle; exact | provider bundle unnecessary — hides a real misconfiguration |
| accidental widening | impossible | the normal case |
| reproducibility | run depends only on the named file | run depends on the host's trust store |
| diagnostic truthfulness | a pass means *this issuer signed it* | a pass means *someone acceptable signed it* |

An operator who genuinely wants both concatenates the PEMs. That is explicit,
reproducible and needs no flag.

## 3. Requested-target identity: the name the operator typed

For `--host H`, the TLS identity is exactly **`H`**, unless `--tls-server-name`
overrides it.

**DNS resolution never alters TLS identity.** `transport.Params.tlsParams` derives
`ServerName` from `TLS.ServerName || p.Host` and the resolved `netip.AddrPort` is
passed only as the address to connect to and the evidence subject. PostgreSQL's
`Params.tlsParams` applies the identical rule to its logical endpoint label. One
hostname resolving to five addresses produces five handshakes that all verify the
same name — which is what a real client does, and what makes per-address
divergence a fact about the target rather than about svcdoctor.

This is the identity analogue of ADR 0028's credential rule, and for the same
reason: resolution is a runtime fact that changes, differs per vantage and can be
attacker-influenced.

## 4. `--tls-server-name` controls BOTH verification and SNI

It sets `tls.Config.ServerName`, which in Go is one field with two consequences,
and this was measured rather than inferred:

| `ServerName` | verified against | SNI actually sent |
|---|---|---|
| `kafka.internal` (in DNS SAN) | DNS SANs — passes | `kafka.internal` |
| `other.internal` (not in SANs) | DNS SANs — fails | `other.internal` |
| `cn-only.example` (CN only, not a SAN) | **fails** | `cn-only.example` |
| `127.0.0.1` (in IP SAN) | IP SANs — passes | **nothing** |

Splitting the two — verifying one name while announcing another — is refused. It
has no operator use case, it is not expressible through `tls.Config` without
hand-written verification, and a report would have to explain which name each
half used.

**What svcdoctor claims when they differ.** With `--host kafka.internal
--tls-server-name broker.example.com`, a successful handshake means: *a TLS
handshake to an address `kafka.internal` resolved to presented a certificate that
verified as `broker.example.com`.* The logical diagnostic target stays
`kafka.internal` — it is what the report's `target` says and what every evidence
node is scoped by — and `tls.server_name` records `broker.example.com` on the
handshake node. **The override changes what was verified, never what was
diagnosed.**

## 5. SNI

Behaviour follows from §4 and needs no separate rule, but the IP case is worth
stating because it surprises people:

| target | override | SNI sent |
|---|---|---|
| hostname | — | the hostname |
| hostname | DNS name | the override |
| IP literal | — | **none** |
| IP literal | DNS name | the override |

Go suppresses SNI for IP literals because RFC 6066 §3 forbids them there. This is
correct, it is not a gap, and svcdoctor must not work around it. A server that
requires SNI to select a certificate cannot be reached by IP without
`--tls-server-name`, and that is a true fact about the server which svcdoctor
should report rather than paper over.

**Certificate verification and SNI emission stay separately described**, because
for an IP target one happens and the other does not.

## 6. IP SANs verify without an override

`--host 10.20.30.40` against a certificate carrying `IP SAN 10.20.30.40`
**verifies, today, with no flag**. Go's `VerifyHostname` parses an IP-literal
`ServerName` and matches it against `IPAddresses`. No change is required, and
`TLS_IDENTITY_MISMATCH` is already named for identity rather than for hostnames,
so an IP SAN mismatch is already owned by a truthful code.

`--host 10.20.30.40 --tls-server-name kafka.internal` connects to the address and
verifies the DNS identity, sending `kafka.internal` in SNI. This is the correct
shape for a host reachable only by address whose certificate names it by DNS.

**No CN fallback, ever.** Go ignores `CN` for hostname verification, and svcdoctor
will not add custom verification to resurrect it. A CN-only certificate fails with
`TLS_IDENTITY_MISMATCH`, which is truthful: no *name* in that certificate matched.
Writing a `VerifyPeerCertificate` to accept it would mean svcdoctor accepting
peers that every modern client rejects, and reporting success no real client
could reproduce.

**The TLS layer is therefore already sufficient for Phase 6.7.** What Phase 6.7
must fix is the DNS and graph layer, where a literal produces a `dns.lookup` PASS
for work that did not happen. Nothing in this section is blocked on it.

## 7. Advertised-broker identity: the advertised name, and never the bootstrap's

For a Kafka endpoint learned from Metadata, the identity verified is **that
endpoint's own advertised hostname**.

`app.advertisedTLSPlan` copies the run's TLS options and clears `ServerName`;
the sweep then falls back to the advertised host. `RootCAs`, the version bounds
and `InsecureSkipVerify` are inherited, because those are *run-wide trust
configuration* and identity is *per-endpoint*.

Alternatives rejected:

- **The bootstrap hostname.** Verifying `broker-2`'s certificate against
  `kafka.company.com` reports an identity mismatch no real client would ever see.
  Managed Kafka routinely serves a distinct certificate per broker endpoint, so
  this would make svcdoctor report a fabricated failure against precisely the
  deployments it most needs to be right about.
- **`--tls-server-name`, propagated.** Same failure, now switchable on.

### The override does not propagate, and one flag could not do the job

`--tls-server-name` applies to **the requested target only**. This is not a
limitation being tolerated; it is the only truthful arrangement available:

- The bootstrap endpoint and the advertised endpoints are *different endpoints*.
  A single name cannot be the correct expected identity for all of them unless
  every broker shares one certificate, which is the uncommon case.
- A bootstrap address is frequently a load balancer or a CNAME with its own
  certificate, while brokers carry their own. That is the *normal* managed
  topology — Confluent Cloud, MSK, Redpanda Cloud, and Kubernetes with a
  headless service all look like this.
- Propagating it would take the one situation the override exists for (a
  bootstrap whose certificate names something else) and use it to produce
  guaranteed-wrong verification for every broker.

So the answer to *"can one global `--tls-server-name` truthfully represent both?"*
is **no**, and the accepted resolution is that it does not try. If a deployment
ever needs per-advertised-endpoint identity control, that is a new decision with
its own record; §17 states the condition. **No new flag is added here.**

## 8. Discovery creates identity context, never credential authority

The distinction this ADR is most concerned to state plainly, because the two look
similar and are not:

> **Discovery creates endpoint identity context. Discovery never creates
> credential authority.**

An advertised hostname *necessarily* becomes the expected peer identity for a
connection to that advertised endpoint — there is no other name a client could
sensibly check, and refusing to check any name would be worse. That is identity
context, and a peer supplying it is not a vulnerability: it constrains what
svcdoctor will accept at an endpoint it was already going to contact, and it
constrains it *upward*.

Credential authority is the opposite direction. ADR 0050 binds it to the logical
endpoint the operator named, and nothing a peer says can extend it.

The consequence is stated as a rule with no exception:

> A verified TLS handshake to an advertised endpoint authorizes **nothing**.
> Zero credential bytes, zero SASL handshake bytes, zero SASL authenticate bytes,
> zero Kafka protocol bytes of any kind.

svcdoctor **may** truthfully report an advertised endpoint's handshake as
verified. `attacker.internal` presenting a certificate that legitimately verifies
as `attacker.internal` is a true observation, and reporting it is correct. It
remains an endpoint that receives DNS, TCP and TLS and nothing else, because TLS
proves endpoint identity and never cluster membership.

This is structural rather than promised: `kafka.TransportPlan` has no field a
credential, secret, identity, mechanism or session could occupy, and a reflection
guard fails the build if one appears.

## 9. `--tls-insecure` disables identity verification, and nothing else

It sets `InsecureSkipVerify`, which in Go disables **both** chain verification and
name verification — they are one operation, so it cannot disable only one.

Everything it must not touch, and does not:

- credential-transport policy — `security.CredentialTransportPolicy` still
  requires a verified channel, so an insecure run **withholds** the credential
  and records `KAFKA_CREDENTIAL_WITHHELD` / its PostgreSQL sibling. Turning off
  verification is therefore not a way to make authentication happen; it is a way
  to make it not happen.
- credential authority, endpoint selection, mechanism selection, protocol
  behaviour, retry behaviour.

It is **explicit and per-run**. It is never an automatic fallback after a
verification failure — a failed verified handshake is itself the evidence, and
retrying without verification would convert a safety failure into a
successful-looking result.

### Transport success and peer verification must remain distinguishable

They already are, in the domain:

- the handshake node carries `tls.verified`, defined as *the handshake completed
  **and** verification was enabled*;
- the run carries `security.tlsVerificationDisabled`;
- an unverified path yields an unverified `security.Channel`, which the
  credential policy refuses.

**Policy: a report must never let `TLS PASS` be read as `peer verified`.** The
canonical JSON satisfies this today. The terminal renderer does not — see §14.1.

**The mechanism is a renderer annotation, not a finding.** A finding claims
something about the target; `--tls-insecure` is a fact about how the operator
configured the run, and manufacturing a target-side finding out of it would
misattribute the operator's own choice, and would take the exit code with it.
The existing `Shareable report · identities redacted` banner is the right
precedent.

## 10. Failure ownership

The five generic codes (ADR 0053) are the requested-target owners and are
unchanged:

| Observation | FailureClass | Code | Sev | Vantage |
|---|---|---|---|---|
| peer did not answer with TLS | `TLS_PEER_NOT_TLS` | `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` | ERROR | yes |
| no name matched (DNS **or** IP SAN) | `TLS_HOSTNAME_MISMATCH` | `TLS_IDENTITY_MISMATCH` | ERROR | yes |
| chain did not verify | `TLS_UNKNOWN_AUTHORITY` | `TLS_CHAIN_NOT_TRUSTED` | ERROR | yes |
| outside the validity window | `TLS_CERTIFICATE_EXPIRED` / `_NOT_YET_VALID` | `TLS_CERTIFICATE_NOT_VALID_NOW` | ERROR | yes |
| attempted, unattributable | `TLS_HANDSHAKE_FAILURE` | `TLS_HANDSHAKE_NOT_COMPLETED` | ERROR | yes |

**No new code, class or severity.** The one distinction §13 of the review brief
worried about — unknown CA versus name mismatch, which need different operator
actions — is already two codes.

Deliberately absent, and each for a stated reason:

- **verification intentionally disabled.** Not a finding; §9.
- **a local CA-file error.** Not a finding either: it is unusable input, refused
  before any network work, exit code 2. An evidence node would report svcdoctor
  on its own caller.
- **a received `protocol_version` alert.** Go returns an unexported type, so it
  lands on the floor rather than being reconstructed from error text.
- **advertised-endpoint TLS failures.** Owned by
  `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`, which aggregates transport at the
  advertisement. Its recommendation already names both certificate naming and
  issuer trust. **Accepted for BASIC**: an advertisement's question is *could a
  client have reached this endpoint*, and every transport reason answers it the
  same way. §17 records when to revisit.

## 11. TLS version policy: the standard library's defaults, deliberately

`MinVersion` and `MaxVersion` are zero everywhere in production, so Go's client
defaults apply: **TLS 1.2 minimum**, TLS 1.3 negotiated when offered. Measured, not
assumed — a default-configured client negotiated 1.3 with a 1.3-capable server
and 1.2 with a 1.2-only server.

Both services behave identically, and both expose the bounds as parameters that
nothing sets.

**Not raised to 1.3.** svcdoctor reports what a client would experience, and a
client on this vantage uses these defaults. Pinning stricter bounds would make
the evidence describe svcdoctor rather than the target: a broker that a real
client reaches over TLS 1.2 would be reported as a handshake failure. Enterprise
PostgreSQL and self-managed Kafka on older JVMs are exactly where this would
bite, and they are exactly the deployments the tool exists for.

The same reasoning forbids pinning cipher suites or curves, which the probe
already documents and does not do.

## 12. PostgreSQL and Kafka: one policy, two implementations

The trust and identity rules are **identical**, which was checked rather than
assumed. Both build `probetls.Params` with `ServerName = override || logical
host`, both pass `RootCAs` straight through, both share one `trustSource` loader,
and both expose the same four flags. The only real difference is *when* the
handshake happens — PostgreSQL negotiates it in band after `SSLRequest`
(ADR 0044), Kafka runs it as ordinary transport (ADR 0053) — and that changes
nothing above.

Per-clause regression status:

| Policy | PostgreSQL today | Kafka today |
|---|---|---|
| custom CA replaces system roots | YES | YES |
| identity = `--host` unless overridden | YES | YES |
| DNS never alters identity | YES | YES |
| override drives verification and SNI | YES | YES |
| IP SAN verifies without override | YES | YES |
| insecure disables both halves only | YES | YES |
| insecure does not weaken credential policy | YES | YES |
| malformed CA fails closed | YES | YES |
| stdlib version defaults | YES | YES |
| advertised identity per endpoint | n/a | YES |
| override does not propagate to advertised | n/a | YES |
| terminal states verification was disabled | **NO** (§14.1) → YES (ADR 0060) | **NO** (§14.1) → YES (ADR 0060) |
| TLS flags refused when TLS is disabled | **NO** (§14.2) → YES (ADR 0060) | YES |
| plaintext run reports `tlsVerificationDisabled: false` | **NO** (§14.3) → YES (ADR 0060) | YES |

**No released PostgreSQL semantics change in Phase 6.6.**

## 13. Managed services: three different statements, kept apart

| | protocol/auth supported | TLS policy compatible | actually validated |
|---|---|---|---|
| Apache Kafka self-hosted | yes | yes | **yes** — 3-broker fixture |
| Redpanda self-hosted / Cloud | yes, expected | yes | **no** |
| Confluent Cloud | yes, expected (SASL over TLS, public CA) | yes | **no** |
| AWS MSK, TLS + SCRAM | yes, expected | yes — provider CA via `--tls-ca-file`, or public roots | **no** |
| AWS MSK, IAM | **no** — `AWS_MSK_IAM` is not implemented | yes, irrelevant | **no** |
| Azure Event Hubs (Kafka API) | partial — `PLAIN` yes, `OAUTHBEARER` no | yes | **no** |
| RDS / Aurora / Cloud SQL / Azure PostgreSQL | yes, expected | yes — provider CA bundle | **no** |

The middle column is the only one this ADR speaks to, and it says something
narrow: *nothing in this policy structurally prevents these from working.* Per-broker
certificates are handled by §7, provider CA bundles by §2, SNI-selected
certificates by §4.

**TLS policy compatibility is not compatibility.** MSK IAM does not become
supported because its TLS works; it is unsupported because no exchange in
`internal/adapter/kafka/wire` performs `AWS_MSK_IAM`. Validation is Phase 6.8.

## 14. Recorded gaps — deferred to Phase 6.7, closed by ADR 0060 in Phase 6.8A

> **All three are closed.** Phase 6.7 measured them and found them to be one coupled defect
> with one fix order; Phase 6.8A reproduced each against a release-shaped binary and then
> closed them together. See [ADR 0060](0060-tls-option-validity-and-verification-state-projection.md).
> The reproductions below stand as the record of what was wrong.

### 14.1 The terminal never says verification was disabled

`internal/render/terminal` contains **no** reference to `TLSVerificationDisabled`,
`tls.verified` or insecure mode. Reproduced by rendering a report whose
`security.tlsVerificationDisabled` is true:

```text
svcdoctor · kafka · kafka.internal:9093

  ✓ PASS  DNS  2.0ms

  Path 198.51.100.10:9093 · continued
    ✓ PASS  TCP                         190µs
    ✓ PASS  TLS                         1.7ms          ← identity never verified
    ...
Result
  status     OK    no target-side error was proven
  outcome    Kafka metadata obtained
```

Nothing in that document is false, and the impression it leaves is. It is the
same failure ADR 0048 §9 fixed for `OK`, which is why `OK` never appears without
its gloss. The canonical JSON is correct throughout
(`security.tlsVerificationDisabled: true`, `tls.verified: false`), so this is a
projection gap and not a semantic one — which is why it is a recorded gap rather
than a STOP.

**Required in 6.7:** a header annotation next to the shareable banner, and the
handshake row distinguishing a verified handshake from an unverified one. No
finding, no new code, no schema change.

### 14.2 PostgreSQL accepts TLS flags that `--tls disable` makes inert

Measured against the built binary:

```text
$ svcdoctor diagnose postgres --host h --user u --tls disable --tls-server-name other.example
(accepted; runs plaintext)
$ svcdoctor diagnose postgres --host h --user u --tls disable --tls-insecure
(accepted; runs plaintext)

$ svcdoctor diagnose kafka --host h --sasl-mechanism PLAIN --tls disable --tls-server-name other.example
svcdoctor: invalid invocation: --tls-server-name has no effect with --tls disable
```

Kafka's `kafkaTLSPlan` refuses all three combinations, for the reason it
documents: accepting them lets an operator believe they configured trust for a
run that has no handshake. PostgreSQL predates that reasoning.

**Not fixed here**, because a previously-accepted invocation becoming exit 2 is a
released-CLI change and §18 of the review brief requires explicit regression
review for one.

### 14.3 A plaintext PostgreSQL run can report `tlsVerificationDisabled: true`

`app.DiagnosePostgres` passes `params.TLSOptions.InsecureSkipVerify` through
unconditionally; `DiagnoseKafka` gates the same boolean on a TLS plan existing.
So `--tls disable --tls-insecure` yields a PostgreSQL report claiming
verification was disabled on a run that attempted no handshake.

It errs safe — it over-reports risk rather than concealing it — and it is
reachable only via the combination §14.2 should refuse. Fixing both together in
6.7 is one change.

## 15. Mutation matrix

Sixteen mutations were applied to production source and restored exactly. Each
targets one clause above. **Three survived the first pass; one of those three was
an inert mutation and the other two were real guard gaps**, both now closed by
tests that change no production behaviour.

| # | Mutation | Result |
|---|---|---|
| 1 | supplied CA **appends** to system roots | was SURVIVING → now caught |
| 3 | trust kept, identity dropped (chain-only verification) | caught — see below |
| 4 | `InsecureSkipVerify` becomes the default | caught |
| 5 | `--tls-server-name` ignored by the chain | was SURVIVING → now caught |
| 5b | the override wins even when unset | caught |
| 6 | override reaches SNI but not verification | caught (does not compile) |
| 8 | the resolved IP becomes `ServerName` | caught |
| 9 | the bootstrap name verifies advertised brokers | caught |
| 12 | malformed CA falls back to system roots | caught |
| 13 | unreadable CA falls back to system roots | caught |
| 14 | IP SAN verification defeated | was uncovered → now caught |
| 16 | `tls.verified` true when verification was off | caught |
| 20 | PostgreSQL ignores its server-name override | caught |

Mutations 2, 7, 10, 11, 15, 17, 18 and 19 of the review brief's list are not in
the table because each is unwritable against this architecture rather than
untested: there is one `tls.Config` construction site and `ServerName` is one
field, so *"append when policy says replace"* and *"replace when policy says
append"* are the same mutation (1), and *"SNI without verification"* and
*"verification without SNI"* cannot be expressed without hand-written
verification (6 fails to compile). *"A trusted advertised endpoint gains
credential authority"* (11) has no field to occupy — `kafka.TransportPlan`'s
reflection guard is Phase 6.5's, re-run here and still passing. 17, 18 and 19 are
prose and SNI-emission claims already covered by the Phase 6.5 overclaim guard
and by §5's measurements.

### The inert mutation is worth recording

Mutation 3's first form added a permissive `VerifyConnection` to disable name
checking while keeping chain verification. It survived, and the survival was
meaningless: Go calls `VerifyConnection` **after** normal verification rather
than instead of it, so the mutation changed nothing. Measured against the
standard library rather than assumed, then rewritten as `InsecureSkipVerify`
plus a hand-written chain-only `VerifyPeerCertificate` — the only reachable way
to split trust from identity, and precisely what §6 forbids svcdoctor from
writing. In that form it is caught by five tests.

**A surviving mutation is a hypothesis, not a finding.** This one would have been
reported as a guard gap that did not exist.

### The two real gaps

**Trust replacement was unguarded.** Replacing `x509.NewCertPool()` with
`x509.SystemCertPool()` in `trustSource` — the single most consequential clause
of §2 — passed the entire repository suite. Every existing test covered what the
loader *refuses*; none covered what the pool it returns *contains*.
`internal/cli/trustsource_test.go` now asserts pool equality against the supplied
PEM alone, which is total in a way that counting certificates would not be.

**The chain's identity rule was unguarded.** Replacing `TLS.ServerName || Host`
with `Host` — ignoring `--tls-server-name` outright — also passed. The
PostgreSQL adapter's copy of the same rule *was* covered (mutation 20), so the
two halves of one policy were guarded unequally, and the uncovered half is the
one every Kafka handshake and every advertised sweep goes through.
`internal/probe/transport/identity_test.go` now pins the override, the fallback,
that resolution never becomes the identity, and that several addresses of one
name all verify that name.

**IP SAN behaviour was measured but not pinned.** §6's claims were established
against the standard library in a scratch module during this review. A
measurement taken once, outside the repository, is not a contract —
`internal/probe/tls/ipsan_test.go` re-takes it on every build, including the
refusals (a DNS SAN spelled like an address, an IP SAN for a different address,
and a `CN`-only certificate).

## 16. Implementation requirements for Phase 6.7

- [x] terminal surfaces disabled verification (§14.1) — annotation, not a finding *(ADR 0060, Phase 6.8A)*
- [x] PostgreSQL refuses inert TLS flags under `--tls disable` (§14.2), with a
      regression test pinning the exit code and the message *(ADR 0060, Phase 6.8A)*
- [x] PostgreSQL's `tlsVerificationDisabled` gated on a TLS plan (§14.3) *(ADR 0060, Phase 6.8A)*
- [ ] IP-literal graph semantics — the `dns.lookup` question; **no TLS change**
- [ ] a guard that `advertisedTLSPlan` clears `ServerName` and only `ServerName`
- [ ] a guard that production sets no `MinVersion`/`MaxVersion`

None requires a new `FindingCode`, `FailureClass`, `schemaVersion`, flag or
dependency.

## 17. Reopen conditions

- an operator reports a real deployment needing system-**plus**-custom trust →
  reconsider Model D, with `replace` remaining the default
- an operator reports a deployment needing per-advertised-endpoint identity
  overrides → a new decision, and only then a new flag
- revocation, pinning or certificate transparency enters scope
- an advertised endpoint's TLS failure needs its own code rather than folding
  into `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` (§10)
- Go changes its client-default version floor, its IP-SAN handling, or its SNI
  suppression for IP literals — each is measured by test rather than assumed
- mTLS client certificates enter scope: that credential's authority is **not**
  decided here and must not be assumed to follow §2
