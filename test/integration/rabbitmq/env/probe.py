#!/usr/bin/env python3
"""One-shot ground truth for a single scenario.

A thin argument-driven front end over groundtruth.py, so a Go scenario can
establish what the broker does before asking svcdoctor. It prints one line:

    RESULT[ code=N][ cm=C/M][ text=...]

Usage:
    probe.py --port 56672 [--user U] [--pass P] [--vhost V] [--tls] [--ca FILE]
             [--server-name NAME] [--no-credential]
"""
import argparse
import os
import sys

# Importing groundtruth writes env/__pycache__/groundtruth.cpython-NNN.pyc, and
# this fixture is a release gate: Phase 14.0A measured `make integration-rabbitmq`
# rewriting a *committed* copy of that file — same length, different bytes,
# because the cache header carries source metadata. A gate whose own execution
# dirties the repository cannot support the cleanliness or reproducibility
# assertion a release gate exists to make.
#
# Set before the import, which is where CPython consults it. The generated cache
# is not test evidence and nothing reads it, so the fix is to stop producing it
# rather than to tolerate and ignore it — the ignore rule in .gitignore is the
# second line of defence, for an interpreter or invocation path that writes one
# anyway. Bytecode caching saves single-digit milliseconds on a fixture that then
# opens a TCP connection.
sys.dont_write_bytecode = True

# Anchor to this file's directory so a caller may invoke it from anywhere and
# still have `--ca certs/server.crt` mean the fixture's own material. The Go
# suite runs from test/integration/rabbitmq, one level up.
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.getcwd())

import groundtruth as g  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--user", default="")
    ap.add_argument("--password", default="")
    ap.add_argument("--vhost", default="/")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--ca", default=None)
    ap.add_argument("--server-name", default=None)
    ap.add_argument("--no-credential", action="store_true")
    a = ap.parse_args()

    r = g.journey(a.host, a.port, a.user, a.password, a.vhost,
                  use_tls=a.tls, cafile=a.ca, server_name=a.server_name,
                  send_credential=not a.no_credential)

    parts = [r["result"]]
    if r.get("reply_code"):
        parts.append(f"code={r['reply_code']}")
    if r.get("class_method"):
        parts.append(f"cm={r['class_method']}")
    if r.get("mechanisms"):
        parts.append(f"mechs={r['mechanisms']}")
    if r.get("tune"):
        t = r["tune"]
        parts.append(f"tune={t['channel_max']}/{t['frame_max']}/{t['heartbeat']}")
    if r.get("graceful_close") is not None:
        parts.append(f"graceful={r['graceful_close']}")
    if r.get("reply_text") and r["result"] in ("AUTH_REFUSED", "OPEN_REFUSED"):
        parts.append(f"text={r['reply_text']}")
    print(" ".join(parts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
