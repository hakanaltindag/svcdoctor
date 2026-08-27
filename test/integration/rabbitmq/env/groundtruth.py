#!/usr/bin/env python3
"""Independent ground truth for the RabbitMQ and LavinMQ validation brokers.

This is a scratch AMQP 0-9-1 client written for the validation phase. It exists
so the brokers' behaviour is established **before** svcdoctor is asked anything,
and by something that shares no code with it: a fixture that only agreed with the
implementation under test would prove nothing.

It speaks exactly the frozen journey and nothing else — protocol header,
Connection.Start-Ok, Tune-Ok, Open — and it never opens a channel, declares a
queue or touches an exchange, because the contract it is measuring forbids all
three.

Run: python3 groundtruth.py
"""
import socket, ssl, struct, sys

FRAME_END = 0xCE
HEADER = b"AMQP\x00\x00\x09\x01"


def _short(b, i):
    return struct.unpack_from(">H", b, i)[0], i + 2


def _long(b, i):
    return struct.unpack_from(">I", b, i)[0], i + 4


def _shortstr(b, i):
    n = b[i]
    return b[i + 1:i + 1 + n].decode("utf-8", "replace"), i + 1 + n


def _longstr(b, i):
    n, i = _long(b, i)
    return b[i:i + n], i + n


def recv_frame(sock):
    """Reads one frame, returning (type, channel, payload)."""
    head = b""
    while len(head) < 7:
        chunk = sock.recv(7 - len(head))
        if not chunk:
            return None
        head += chunk
    ftype, chan, size = struct.unpack(">BHI", head)
    body = b""
    while len(body) < size:
        chunk = sock.recv(size - len(body))
        if not chunk:
            return None
        body += chunk
    if sock.recv(1) != bytes([FRAME_END]):
        raise RuntimeError("bad frame end")
    return ftype, chan, body


def send_method(sock, cls, meth, payload):
    body = struct.pack(">HH", cls, meth) + payload
    sock.sendall(struct.pack(">BHI", 1, 0, len(body)) + body + bytes([FRAME_END]))


def parse_table_keys(b, i):
    """Returns the top-level server-properties keys, without descending."""
    size, i = _long(b, i)
    end = i + size
    keys = []
    while i < end:
        k, i = _shortstr(b, i)
        keys.append(k)
        t = chr(b[i]); i += 1
        if t == "S":
            n, i = _long(b, i); i += n
        elif t == "F":
            n, i = _long(b, i); i += n
        elif t == "t":
            i += 1
        elif t in ("b", "B"):
            i += 1
        elif t in ("U", "u"):
            i += 2
        elif t in ("I", "i", "f"):
            i += 4
        elif t in ("L", "l", "d", "T"):
            i += 8
        else:
            return keys, end
    return keys, end


def connect(host, port, use_tls, server_name=None, cafile=None, timeout=10):
    sock = socket.create_connection((host, port), timeout=timeout)
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if cafile:
            ctx.load_verify_locations(cafile)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=server_name or host)
    return sock


def journey(host, port, user, password, vhost, use_tls=False, cafile=None,
            server_name=None, send_credential=True):
    """Walks the frozen journey and reports where it stopped."""
    out = {"start": None, "mechanisms": None, "tune": None, "result": None,
           "reply_code": None, "reply_text": None, "class_method": None,
           "product": None, "version": None}
    try:
        sock = connect(host, port, use_tls, server_name, cafile)
    except Exception as e:
        out["result"] = "TRANSPORT_FAILED"
        out["reply_text"] = f"{type(e).__name__}: {e}"
        return out
    try:
        sock.sendall(HEADER)
        f = recv_frame(sock)
        if f is None:
            out["result"] = "CLOSED_BEFORE_START"
            return out
        _, _, body = f
        cls, meth = struct.unpack_from(">HH", body, 0)
        if (cls, meth) != (10, 10):
            out["result"] = f"UNEXPECTED_{cls}_{meth}"
            return out
        i = 4 + 2  # version-major, version-minor
        keys, i = parse_table_keys(body, i)
        out["start"] = len(body)
        mechs, i = _longstr(body, i)
        out["mechanisms"] = mechs.decode()
        out["props_keys"] = keys

        if not send_credential:
            out["result"] = "STOPPED_BEFORE_CREDENTIAL"
            return out

        resp = b"\x00" + user.encode() + b"\x00" + password.encode()
        # client-properties advertising `authentication_failure_close`.
        #
        # Without it the broker sends **no frame at all** and simply closes the
        # socket, which is why ADR 0068 §3 makes the capability mandatory rather
        # than optional. Measured here: an empty client-properties table turned
        # every credential refusal into a bare socket close on all four brokers.
        inner = (bytes([28]) + b"authentication_failure_close" + b"t" + b"\x01")
        caps = (bytes([12]) + b"capabilities" + b"F" + struct.pack(">I", len(inner)) + inner)
        payload = (struct.pack(">I", len(caps)) + caps +
                   bytes([5]) + b"PLAIN" +
                   struct.pack(">I", len(resp)) + resp +
                   bytes([0]))                      # locale
        send_method(sock, 10, 11, payload)

        f = recv_frame(sock)
        if f is None:
            out["result"] = "CLOSED_AFTER_CREDENTIAL_NO_FRAME"
            return out
        _, _, body = f
        cls, meth = struct.unpack_from(">HH", body, 0)
        if (cls, meth) == (10, 50):
            code, i = _short(body, 4)
            text, i = _shortstr(body, i)
            ccls, i = _short(body, i)
            cmeth, i = _short(body, i)
            out.update(result="AUTH_REFUSED", reply_code=code, reply_text=text,
                       class_method=f"{ccls}/{cmeth}")
            return out
        if (cls, meth) != (10, 30):
            out["result"] = f"UNEXPECTED_{cls}_{meth}"
            return out
        chmax, i = _short(body, 4)
        frmax, i = _long(body, i)
        hb, i = _short(body, i)
        out["tune"] = {"channel_max": chmax, "frame_max": frmax, "heartbeat": hb}

        # Tune-Ok with the frozen values: channel_max 1, frame_max 8192, heartbeat 0.
        send_method(sock, 10, 31, struct.pack(">HIH", 1, 8192, 0))
        send_method(sock, 10, 40,
                    bytes([len(vhost.encode())]) + vhost.encode() + bytes([0]) + bytes([0]))

        f = recv_frame(sock)
        if f is None:
            out["result"] = "CLOSED_AFTER_OPEN_NO_FRAME"
            return out
        _, _, body = f
        cls, meth = struct.unpack_from(">HH", body, 0)
        if (cls, meth) == (10, 41):
            out["result"] = "OPEN_OK"
            send_method(sock, 10, 50, struct.pack(">H", 200) + bytes([0]) + struct.pack(">HH", 0, 0))
            f = recv_frame(sock)
            out["graceful_close"] = bool(f and struct.unpack_from(">HH", f[2], 0) == (10, 51))
            return out
        if (cls, meth) == (10, 50):
            code, i = _short(body, 4)
            text, i = _shortstr(body, i)
            ccls, i = _short(body, i)
            cmeth, i = _short(body, i)
            out.update(result="OPEN_REFUSED", reply_code=code, reply_text=text,
                       class_method=f"{ccls}/{cmeth}")
            return out
        out["result"] = f"UNEXPECTED_{cls}_{meth}"
        return out
    except Exception as e:
        out["result"] = "ERROR"
        out["reply_text"] = f"{type(e).__name__}: {e}"
        return out
    finally:
        try:
            sock.close()
        except Exception:
            pass


CERT = "certs/server.crt"

BROKERS = {
    "rabbit-4.2.0":  ("127.0.0.1", 56672, 56671),
    "rabbit-3.13.7": ("127.0.0.1", 56674, 56675),
    "rabbit-4.0.9":  ("127.0.0.1", 56676, 56677),
    "lavinmq-2.3.0": ("127.0.0.1", 56680, 56681),
}


def show(label, r):
    bits = [f"result={r['result']}"]
    if r.get("reply_code"):
        bits.append(f"code={r['reply_code']}")
    if r.get("class_method"):
        bits.append(f"cm={r['class_method']}")
    if r.get("tune"):
        bits.append(f"tune={r['tune']}")
    if r.get("mechanisms"):
        bits.append(f"mechs='{r['mechanisms']}'")
    print(f"  {label:<34} " + "  ".join(bits))
    if r.get("reply_text") and r["result"] in ("AUTH_REFUSED", "OPEN_REFUSED"):
        print(f"      reply_text ({len(r['reply_text'])}B): {r['reply_text']!r}")


def main():
    for name, (host, plain, tls) in BROKERS.items():
        print(f"\n=== {name} ===")
        lav = name.startswith("lavinmq")
        user, pw = ("guest", "guest") if lav else ("app", "app-pw")

        show("A start only (no credential)",
             journey(host, plain, "", "", "/", send_credential=False))
        show("B correct auth, vhost /",
             journey(host, plain, user, pw, "/"))
        show("C wrong password",
             journey(host, plain, user, "wrong-pw", "/"))
        show("D unknown user",
             journey(host, plain, "nosuchuser", "x", "/"))
        show("E vhost not found",
             journey(host, plain, user, pw, "no-such-vhost"))
        if not lav:
            show("F vhost access refused",
                 journey(host, plain, "noperm", "noperm-pw", "/"))
            show("G vhost connection limit",
                 journey(host, plain, user, pw, "limited"))
            show("H guest from remote",
                 journey(host, plain, "guest", "guest", "/"))
        show("I TLS verified",
             journey(host, tls, user, pw, "/", use_tls=True, cafile=CERT,
                     server_name="rabbit.svcdoctor.test"))


if __name__ == "__main__":
    main()
