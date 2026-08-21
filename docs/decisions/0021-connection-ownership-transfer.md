# ADR 0021: A successful connection is owned, transferred and closed explicitly

## Status

Accepted.

## Decision

A generic transport probe that establishes a connection **produces a resource**,
not just a fact. The resource is returned to the caller alongside the evidence,
in a concrete type that owns it until somebody takes it:

```go
r, err := tcp.Connect(ctx, dialer, endpoint, addr)
if err != nil { return err }
defer r.Close()                  // safe in every path, including after a transfer

if conn, ok := r.TakeConn(); ok {
    defer conn.Close()           // the caller owns it now
    // hand conn to the next stage
}
```

`tcp.Result` holds the evidence and, on success, the live `net.Conn`. Three rules
make ownership unambiguous:

- **The probe never closes a successful connection.** It hands it over.
- **`TakeConn` transfers ownership once.** The second call reports that there is
  nothing to take rather than handing the same connection to a second owner.
- **`Close` releases the connection only while the Result still owns it.** After a
  transfer it does nothing; a second call does nothing; on a failed attempt it
  does nothing. So `defer r.Close()` is correct in every path.

The last rule is what makes the contract survive real code. A resource protocol
that requires the caller to know which branch they are in is a leak, or a double
close, waiting to be written.

## Context

`docs/ARCHITECTURE.md` section 4 has required since Phase 0 that generic transport
be able to hand a live connection to a protocol adapter. Until Phase 2.2 nothing
established a connection, so the requirement had no API to live in.

The failure mode it exists to prevent:

```text
probe:   dial -> measure -> close
adapter: dial again
```

This is not primarily a resource-efficiency problem. It is a **correctness**
problem: every fact measured about the first connection then describes something
the protocol exchange never used. The DNS answer that was selected, the address
that worked, the handshake latency, the peer that accepted — all of it belongs to
a socket that was thrown away. The report still looks right, and no test fails.
That is precisely why the invariant needed to become an API rather than a
sentence: sentences do not fail builds.

It also matters for what svcdoctor is *for*. A diagnostic that connects twice can
be right about the first connection and wrong about the second, in exactly the
intermittent conditions users run it to investigate.

## Evidence and resources are separate

`domain.Evidence` cannot hold a `net.Conn`: its attributes are a closed union of
normalized values, so there is no field a connection could occupy (ADR 0010). The
graph holds evidence, the report holds the graph, and neither can hold a live
resource. `Result` is the only thing that does, and it never enters the domain
model.

The two also have different lifetimes on purpose. Evidence describes a moment that
has passed and stays true afterwards: closing the connection does not make the
attempt stop having succeeded. `Result.Connected` reports on the resource,
`Evidence.State` reports on the fact, and they are allowed to disagree.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Dial, measure, close, let the adapter redial | The failure this ADR exists to prevent: measured facts would describe a connection the protocol exchange never used, and nothing would fail | Never |
| A registry or map keyed by `EvidenceID` | Global mutable state holding live sockets, with no owner, no lifetime and a leak whenever a key is not collected. It also makes the graph look like it owns connections | Never |
| Storing the connection in the `context` | Same ambiguity with worse discoverability, and a context is for cancellation and deadlines, not for carrying resources | Never |
| A generic resource-handle framework | One resource type exists. A framework would be invented rather than discovered, and the architecture already forbids speculative machinery | A second, structurally different resource appears — TLS returns the *same* connection, so it is not one |
| Returning `(domain.Evidence, net.Conn, error)` | A bare connection alongside evidence has no owner and no way to say "there is nothing to take". Every caller would reinvent the nil check and the close discipline | — |
| `Result` implementing `io.Closer` only, with no `TakeConn` | Ownership could only be surrendered by not closing, which is indistinguishable from forgetting | — |
| Building the adapter package now, to have somewhere to put the connection | Would drag Phase 3 forward to justify a Phase 2 API, and the transfer must work for any next stage, not one service | Never |

## Consequences

- The transport chain can hand the TLS layer, and later an adapter, the exact
  connection whose establishment was measured.
- A failed attempt owns nothing, so error paths cannot leak.
- Concurrency is not addressed: a `Result` has one owner and is not safe for
  concurrent use. If the chain ever probes addresses in parallel, each attempt
  still has its own `Result` and its own owner.
- `Result` is the shape later probes should follow when they produce a resource.
  TLS is expected to *take* a connection and return the wrapped one, which is the
  same contract seen from the other side.
- The invariant is now enforced by tests: a probe that closed a successful
  connection, handed it out twice, or closed one it had already transferred would
  fail `internal/probe/tcp/result_test.go`.
