# PostgreSQL end-to-end validation — Phase 4.8a

The PostgreSQL vertical slice, driven from a real socket to a redacted report,
against real servers. This is the first phase in which diagnosis meets a graph it
did not receive hand-built.

**No production composition root was created, and that is the phase's boundary
rather than an omission.** `internal/app`, `cmd/svcdoctor` and `internal/render`
remain empty, asserted by a test. The decisions an orchestrator needs — which
transport path may be authenticated and why, whether more than one ever is, where
the whole-run budget lives, whether a run emits a shareable report — are deferred
to **ADR 0041**. ADR 0028 §1 already said so: *"Today the only caller is a test;
when application orchestration exists it selects and records why."* This harness
is that test caller.

## 1. Environment

| | |
|---|---|
| PostgreSQL | **18.6** (`postgres:18`, Debian 18.6-1.pgdg13+2), two listeners |
| TLS listener | port 55432, `ssl=on`, throwaway RSA-2048 self-signed certificate, SAN `DNS:pg.svcdoctor.test, DNS:localhost, IP:127.0.0.1` |
| Plaintext listener | port 55433, `ssl=off` — exists to answer `SSLRequest` with `N` |
| Docker | 28.3.2, darwin/arm64 host |
| Auth | `password_encryption=scram-sha-256`, `hba_file` per role |
| pgBouncer | **not present** — see §5 |
| Suite runtime | **0.8 s** for 31 tests; the whole gate including container lifecycle ~25 s |

Roles and databases: `scramuser` (SCRAM, printable-ASCII password spanning space
to tilde), `trustuser` (trust), `md5user` (md5), `clearuser` (cleartext),
`norights` (SCRAM, no `CONNECT` on `closeddb`), **`rejectuser`** (pg_hba
`reject`, added this phase), **`svcdcanaryrole`** + **`svcdcanarydb`** (redaction
canaries, added this phase). Databases `appdb`, `closeddb`, `svcdcanarydb`.

### 1.1 The host is `127.0.0.1`, and the reason is a real finding

The suite previously used `localhost` and took `Continuations()[0]`.
**`localhost` resolves to both `127.0.0.1` and `::1`**, so the chain returns two
completed paths and `[0]` silently selected IPv4 — *exactly* the invisible
address-family preference ADR 0024 §3 removed from the transport chain, sitting
unnoticed in the validation suite that was supposed to be exercising the real
thing.

It surfaced the moment `requireSingleContinuation` replaced the index, on the
first run. The fix is not to choose: the suite now names a host that resolves to
one address, so there is nothing to choose between, and the count is asserted
rather than assumed. The generated certificate already carried `IP:127.0.0.1`, so
verification is unaffected.

## 2. The execution chain

Every stage is production code. The harness adds sequencing and nothing else.

```text
transport.Run            real SystemResolver, real SystemDialer   -> dns.lookup, tcp.connect
  requireSingleContinuation                                       fixture precondition
  postgres.Negotiate     real SSLRequest, real probe/tls handshake -> postgres.ssl_request, tls.handshake
  postgres.Startup       real StartupMessage                       -> postgres.startup
  postgres.Authenticate  real SCRAM-SHA-256                        -> postgres.authentication
  postgres.EstablishSession                                        -> postgres.session
  builder.Freeze()       the real graph
  diagnosis.NewEngine(4 rules).Diagnose(graph)
  domain.NewReport(graph, findings)
  redaction.Redact(report)
```

TLS is deliberately **not** requested from the transport chain: PostgreSQL
negotiates encryption in band, so the handshake belongs after `SSLRequest` and
`internal/adapter/postgres` performs it on the same socket.

## 3. Scenario results — MEASURED against a real server

Every row below ran. "Graph" lists the non-passing node; unlisted upstream nodes
passed.

| # | Scenario | Graph (step / state / class / SQLSTATE) | Finding | Report |
|---|---|---|---|---|
| A | Healthy TLS + SCRAM → `ReadyForQuery` | full chain PASS, `transaction_status=idle` | **none** | `OK` |
| B | Wrong password | `authentication` FAIL `AUTH_CREDENTIALS_REJECTED` `28P01`; **no session node** | `POSTGRES_CREDENTIALS_REJECTED` | `PROBLEMS_FOUND` |
| C | Unknown role | identical to B — `28P01`, indistinguishable | `POSTGRES_CREDENTIALS_REJECTED` | `PROBLEMS_FOUND` |
| D | Missing database | `authentication` PASS; `session` FAIL `RESOURCE_NOT_FOUND` `3D000` | `POSTGRES_DATABASE_NOT_FOUND` | `PROBLEMS_FOUND` |
| E | `CONNECT` revoked | `authentication` PASS; `session` FAIL `AUTHZ_DENIED` `42501` | `POSTGRES_DATABASE_CONNECT_DENIED` | `PROBLEMS_FOUND` |
| F | TLS required, server without TLS | `ssl_request` FAIL `PROTOCOL_UNSUPPORTED_CAPABILITY`, `ssl.offered=false`; no startup/auth/session | `POSTGRES_TLS_DECLINED` | `PROBLEMS_FOUND` |
| G | `pg_hba` reject | `startup` FAIL `AUTHZ_NOT_PERMITTED` `28000`; **no authentication node** | `POSTGRES_CONNECTION_NOT_PERMITTED`, `vantageDependent=true` | `PROBLEMS_FOUND` |
| H | md5 demanded | `authentication` UNKNOWN `AUTH_MECHANISM_UNSUPPORTED` | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE`, **INFO** | — |
| I | cleartext demanded | as H | as H | — |
| J | trust | `startup` PASS `auth_method=ok`; **no authentication node**; `session` PASS | **none** | `OK` |
| K | Plaintext channel, credential configured | `ssl_request` SKIPPED `EXEC_SKIPPED_BY_POLICY`; `authentication` SKIPPED `EXEC_SKIPPED_BY_POLICY`; no session | `POSTGRES_CREDENTIAL_WITHHELD`, WARN | — |

Three results are worth stating separately.

**The healthy run produces zero findings and claims nothing about a backend.**
That is not a gap. Phase 4.5a measured pgBouncer serving a complete passing
session with its PostgreSQL backend *stopped*, so `ReadyForQuery` cannot support
a backend-health claim, and the graph a pooler produces is byte-identical to this
one. Mutation L confirms a healthy-backend finding fails the suite.

**G was previously unmeasured.** `AUTHZ_NOT_PERMITTED` had no real producer in the
fixture; a `pg_hba` `reject` line for a dedicated role gives one, and `28000`
arrives before any authentication request — so the "before evaluating any
credential" half of the claim is now observed rather than argued.

**F required a second listener.** The single TLS server could never answer `N`.
Adding a plaintext-only listener measures the negotiation; simulating the byte
would have proved nothing about it.

## 4. Redaction — MEASURED

Two real runs (healthy and failing) through `LOCAL_FULL` → `SHAREABLE_REDACTED`.

The canaries reach the graph the ordinary way, as identity attributes the startup
step records — not through a constructor a test called.

| Canary | In `LOCAL_FULL` | In `SHAREABLE_REDACTED` |
|---|---|---|
| Role `svcdcanaryrole` | present (asserted, else the test proves nothing) | **absent** |
| Database `svcdcanarydb` / `nosuchdb-svcd` | present | **absent** |
| Host/IP `127.0.0.1` | present | **absent** |
| Password `svcd-canary-pw-9Q7x` | **absent** | **absent** |

Preserved across redaction: report status, graph size, finding code, kind,
severity, confidence, layer, `vantageDependent`, and every sentence byte for
byte. Every evidence reference still resolves in the redacted graph. Redaction is
idempotent over a real report.

The credential is additionally swept from the local report, the shareable report
and all finding prose in scenarios B, G, H, I and K. The SCRAM intermediates —
nonce, salt, proof, signature — are covered by the lower-level leak tests, which
remain authoritative; no field of the wire result holds one.

## 5. NOT MEASURED — and why

| Scenario | Status | Why |
|---|---|---|
| **pgBouncer** — `08P01` collapse, cached `ReadyForQuery` with the backend down | **not exercised here** | No pgBouncer in this environment. The behaviour is measured in `POSTGRES_PHASE4_SCRAM_STUDY.md` §10 and `POSTGRES_PHASE45_SESSION_STUDY.md` §9, and the diagnosis policy over it is covered by the Phase 4.6b hand-built acceptance rows. **No claim in this phase is based on a pgBouncer run.** |
| **Session floor** (`53300`, connection-limit refusal) | **not exercised here** | Reproducing it needs `max_connections` exhaustion, which is slow and flaky in a gate. Covered by the Phase 4.6b acceptance matrix and measured on the wire in Phase 4.5a §3. |
| **`bindDeadline` regression** | **not covered** | See §6. |
| Untrusted CA / hostname mismatch / expired certificate | not exercised | Generic TLS evidence, and no PostgreSQL finding is authorized over it (ADR 0040 §2). |
| Replica / `in_hot_standby` | not exercised | No rule reads those attributes (ADR 0040 §20). |

## 6. The deadline regression is NOT covered, and this is the honest result

Phase 4.5b fixed a released-watcher race in `bindDeadline`, where `release`
cleared the deadline without waiting for its watcher goroutine.

The composed path now exercises `Startup → Authentication → Session` including
the `Terminate` write that follows a bounded read — the sequence that surfaced
the bug. So the obvious question is whether reverting the fix breaks this suite.

**It does not.** The fix was reverted, the tree compiled, and the healthy
end-to-end path ran **40 times**: all passed. The race needs the caller's context
to end at a specific moment relative to `release()`, and against a local server
with a 30-second budget the context never fires.

Widening the window with sleeps would produce a test that fails for a reason the
production path does not have. So no coverage is claimed. **Phase 4.5b's evidence
— an `i/o timeout` against a peer that was plainly still listening — remains the
authority**, and this remains a known gap rather than a solved one.

## 7. Mutation results

Eleven applied, compiled, caught and restored.

| # | Mutation | Caught by |
|---|---|---|
| A | Skip diagnosis in the harness | every finding assertion |
| B | Drop findings before `NewReport` | report status assertions |
| D | Hand-build evidence in the harness | `TestTheHarnessUsesRealEvidenceOnly` |
| E | Index `Continuations()` outside the precondition helper | `TestOnlyThePreconditionHelperIndexesAPath` |
| F | Wrong-password expectation → `DATABASE_NOT_FOUND` | scenario B |
| G | `3D000` expectation → `AUTHENTICATION_FAILED` | scenario D |
| H | `42501` expectation → session floor | scenario E |
| I | Reveal the credential inside the adapter | **forbidigo** — `security.Reveal` is confined to a wire package |
| J | `redaction.Redact` becomes a no-op | the canary sweep |
| K | Manufacture a PostgreSQL finding for `tcp.connect` | scenarios A and F |
| L | A healthy `ReadyForQuery` claims the backend is healthy | scenario A and J |

**C — "redact before diagnosis" — is structurally impossible and is not
counted.** `redaction.Redact` takes a `domain.Report`, and `domain.NewReport`
requires the findings, so redaction cannot precede diagnosis without inventing a
different API. That is a stronger property than a guard would give, and it is why
diagnosis is guaranteed to run on truthful internal evidence.

## 8. What this phase does not change

No production Go file was modified. The additions are the harness, the guards,
and the environment: a second listener, a `reject` role, and two canary
identities.

`security.Reveal` production sites: **2**. Dependencies: **1**. `schemaVersion`:
**1**. `FailureClass` count: unchanged. No diagnosis semantics changed, no
redaction change, no Kafka change, no SQL, no CLI, no `internal/app`.
