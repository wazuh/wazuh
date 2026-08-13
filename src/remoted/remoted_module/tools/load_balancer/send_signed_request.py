#!/usr/bin/env python3
"""
Sends AES-CMAC-signed requests to remoted's HTTPS events API, with the precise control the
load-balancer tests need.

The sibling tools in ../ (send_stateless.py, send_agent_json.py) hardcode target="/stateless"
per scenario and sign and send in one step. That is right for their job but cannot express
these tests. This tool adds:

  * the request target is signed AND SENT VERBATIM  -> detects proxy normalisation
  * --repeat        resends the SAME signed bytes N times            -> replay
  * --timestamp     pins an absolute timestamp, so two invocations produce byte-identical
                    requests                                        -> replay across nodes
  * --keepalive     reuses ONE connection for every request          -> per-connection vs
                                                                        per-request balancing
  * --strip-content-encoding / --add-content-encoding
                    changes that header AFTER signing                -> unsigned-field tests
  * --client-cert   presents a client certificate                    -> verification_mode tests
  * --no-auth       sends NO Authorization header                    -> health-check tests, and
                                                                        proof that unsigned
                                                                        requests are rejected
  * --print-auth    prints the Authorization header and exits        -> lets OTHER clients (e.g.
                                                                        curl --http2) send a
                                                                        validly signed request

It speaks raw http.client rather than `requests`, because requests/urllib3 normalise the URL
and would destroy exactly what we are trying to measure.

Canonical string signed (see ../../src/auth/authMiddleware.cpp, beginSession):

    "WAZUH-REQUEST\\n" + protocol_version + "\\n" + METHOD + "\\n" + request_target + "\\n"
    + agent_id + "\\n" + timestamp + "\\n" + body

Response codes and what they prove:

    202  signature valid AND event ingested by the engine
    401  signature rejected                      -> authentication FAILED
    400  signature valid, body not understood    -> authentication PASSED
    503  signature valid, engine unavailable     -> authentication PASSED
    502  the proxy could not reach the node      -> never reached authentication

A manipulation that returns 400 or 503 instead of 401 got past authentication.
"""

import argparse
import http.client
import json
import socket
import ssl
import sys
import time
from collections import Counter
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

DEFAULT_BODY = 'H {"wazuh":{"agent":{"id":"1001"}}}\nE 1:/var/log/syslog:load balancer test event'


def read_agent_key(path: str, agent_id: str) -> bytes:
    """client.keys layout: 'id name ip key'. The key is lowercase hex -> 16/24/32 bytes."""
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip() or line.startswith("#") or line.startswith(" "):
                continue
            fields = line.split()
            if len(fields) >= 4 and fields[0] == agent_id:
                key = bytes.fromhex(fields[3])
                if len(key) not in (16, 24, 32):
                    sys.exit(f"the key for agent {agent_id} decodes to {len(key)} bytes "
                             "(remoted requires 16, 24 or 32)")
                return key
    sys.exit(f"agent {agent_id} not found in {path}")


def sign(key: bytes, protocol_version: str, method: str, target: str,
         agent_id: str, timestamp: int, body: bytes) -> str:
    """AES-CMAC over the canonical request. Returns lowercase hex."""
    mac = CMAC(algorithms.AES(key))
    mac.update(b"WAZUH-REQUEST\n")
    mac.update(protocol_version.encode() + b"\n")
    mac.update(method.upper().encode() + b"\n")
    mac.update(target.encode() + b"\n")
    mac.update(agent_id.encode() + b"\n")
    mac.update(str(timestamp).encode() + b"\n")
    mac.update(body)
    return mac.finalize().hex()


def build_tls_context(client_cert: str = None, client_key: str = None) -> ssl.SSLContext:
    """Server verification is off on purpose: the lab uses self-signed certificates and the
    point of these tests is what the SERVER does, not what the client trusts."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if client_cert:
        # mTLS: present a client certificate (verification_mode tests).
        context.load_cert_chain(certfile=client_cert, keyfile=client_key or client_cert)
    return context


def send_once(host: str, port: int, method: str, target: str, headers: dict, body: bytes,
              timeout: float, client_cert: str = None, client_key: str = None):
    """One request on a fresh connection. The target goes on the wire VERBATIM.
    Returns (status, reason, body) or (None, error_text, '')."""
    connection = http.client.HTTPSConnection(
        host, port, context=build_tls_context(client_cert, client_key), timeout=timeout)
    try:
        connection.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", f"{host}:{port}")
        connection.putheader("Content-Length", str(len(body)))
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders()
        connection.send(body)
        response = connection.getresponse()
        return response.status, response.reason, response.read(400).decode("utf-8", "replace")
    except (http.client.HTTPException, ssl.SSLError, socket.error, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}", ""
    finally:
        connection.close()


def send_on_one_connection(host: str, port: int, method: str, target: str, headers: dict,
                           body: bytes, timeout: float, count: int, interval: float = 0.0,
                           client_cert: str = None, client_key: str = None):
    """N requests over a SINGLE TCP/TLS connection. This is what distinguishes balancing per
    connection (L4 passthrough: everything lands on one node) from balancing per request
    (L7 termination: the nodes alternate). With an interval it also measures idle timeouts:
    a proxy that closes idle keep-alive connections kills the requests sent after the pause."""
    connection = http.client.HTTPSConnection(
        host, port, context=build_tls_context(client_cert, client_key), timeout=timeout)
    results = []
    try:
        for attempt in range(count):
            if attempt and interval:
                time.sleep(interval)
            connection.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", f"{host}:{port}")
            connection.putheader("Content-Length", str(len(body)))
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders()
            connection.send(body)
            response = connection.getresponse()
            results.append((response.status, response.reason,
                            response.read().decode("utf-8", "replace")[:200]))
    except (http.client.HTTPException, ssl.SSLError, socket.error, OSError) as exc:
        results.append((None, f"{type(exc).__name__}: {exc}", ""))
    finally:
        connection.close()
    return results


def send_resuming_session(host: str, port: int, method: str, target: str, headers: dict,
                          body: bytes, timeout: float, count: int,
                          client_cert: str = None, client_key: str = None):
    """N requests on N SEPARATE connections, where each one RESUMES the TLS session of the
    previous. That is what a proxy does by default -- nginx has proxy_ssl_session_reuse on, and
    HAProxy reuses sessions unless told otherwise -- so it is the ordinary case, not an exotic
    one. Sending it from a single-shot client is the only way to observe it deliberately, since
    every other path here builds a fresh context and therefore never resumes anything.

    Returns (status, reason, body) per request; a failed handshake shows up as status None, the
    same as any other TLS-level failure."""
    context = build_tls_context(client_cert, client_key)
    results = []
    session = None
    for _ in range(count):
        try:
            tls = context.wrap_socket(socket.create_connection((host, port), timeout=timeout),
                                      server_hostname=host, session=session)
        except (ssl.SSLError, socket.error, OSError) as exc:
            results.append((None, f"{type(exc).__name__}: {exc}", ""))
            break
        # http.client writes the request for us, over the socket we already handshook, so the
        # target still goes on the wire verbatim.
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.sock = tls
        try:
            connection.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", f"{host}:{port}")
            connection.putheader("Content-Length", str(len(body)))
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders()
            connection.send(body)
            response = connection.getresponse()
            results.append((response.status, response.reason,
                            response.read(400).decode("utf-8", "replace")))
            session = tls.session
        except (http.client.HTTPException, ssl.SSLError, socket.error, OSError) as exc:
            results.append((None, f"{type(exc).__name__}: {exc}", ""))
            break
        finally:
            connection.close()
    return results


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="https://127.0.0.1:1517",
                        help="target base URL (default: %(default)s). Use :8443 for the "
                             "terminating proxy, :8444 for passthrough")
    parser.add_argument("--client-keys", default="/var/wazuh-manager/etc/client.keys")
    parser.add_argument("--agent-id", default="1001")
    parser.add_argument("--target", default="/stateless",
                        help="request target, signed AND sent verbatim (default: %(default)s)")
    parser.add_argument("--method", default="POST")
    parser.add_argument("--protocol-version", default="1")
    parser.add_argument("--body", default=DEFAULT_BODY)
    parser.add_argument("--body-file")
    parser.add_argument("--repeat", type=int, default=1,
                        help="resend the SAME signed request N times (replay)")
    parser.add_argument("--interval", type=float, default=0.0,
                        help="seconds to wait between resends")
    parser.add_argument("--keepalive", action="store_true",
                        help="reuse ONE connection for all resends")
    parser.add_argument("--resume-session", action="store_true",
                        help="one connection per resend, each RESUMING the previous TLS "
                             "session (what a proxy does by default)")
    parser.add_argument("--timestamp", type=int,
                        help="absolute timestamp to sign. Pinning it makes two invocations "
                             "produce byte-identical requests, for replay across nodes")
    parser.add_argument("--timestamp-offset", type=int, default=0,
                        help="shift the signed timestamp (negative = older)")
    parser.add_argument("--zstd", action="store_true",
                        help="compress the body and add Content-Encoding: zstd")
    parser.add_argument("--strip-content-encoding", action="store_true",
                        help="remove Content-Encoding AFTER signing (unsigned-field test)")
    parser.add_argument("--add-content-encoding",
                        help="add this Content-Encoding AFTER signing (unsigned-field test)")
    parser.add_argument("--tamper", action="store_true",
                        help="modify the body after signing; must return 401")
    parser.add_argument("--header", action="append", default=[], metavar="NAME:VALUE",
                        help="extra header (repeatable)")
    parser.add_argument("--no-auth", action="store_true",
                        help="send NO Authorization header (health-check tests). Does not need "
                             "client.keys")
    parser.add_argument("--print-auth", action="store_true",
                        help="print the Authorization header value and exit without sending, so "
                             "another client (e.g. curl --http2) can send a validly signed "
                             "request. Sign the exact same --method/--target/--body there")
    parser.add_argument("--client-cert", help="client certificate to present (mTLS)")
    parser.add_argument("--client-key", help="private key for the client certificate")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--label", default="", help="label for the output")
    parser.add_argument("--json", action="store_true", help="machine-readable JSONL output")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    url = urlparse(args.url)
    host = url.hostname or "127.0.0.1"
    port = url.port or (443 if url.scheme == "https" else 80)

    if args.body_file:
        with open(args.body_file, "rb") as handle:
            body = handle.read()
    else:
        body = args.body.encode()

    timestamp = (args.timestamp if args.timestamp is not None
                 else int(time.time()) + args.timestamp_offset)

    headers = {"protocol-version": args.protocol_version}
    if args.zstd:
        import zstandard
        body = zstandard.ZstdCompressor().compress(body)
        headers["Content-Encoding"] = "zstd"

    if args.no_auth:
        # Unauthenticated on purpose (health probe / rejection test): nothing is signed, so
        # this path works even on a box whose client.keys is empty.
        mac = "(unauthenticated)"
    else:
        key = read_agent_key(args.client_keys, args.agent_id)
        # Signed HERE. Anything after this point simulates what an intermediary could alter.
        mac = sign(key, args.protocol_version, args.method, args.target,
                   args.agent_id, timestamp, body)
        if args.print_auth:
            print(f"Wazuh {args.agent_id}:{timestamp}:{mac}")
            return 0
        headers["Authorization"] = f"Wazuh {args.agent_id}:{timestamp}:{mac}"

    if args.strip_content_encoding:
        headers.pop("Content-Encoding", None)
    if args.add_content_encoding:
        headers["Content-Encoding"] = args.add_content_encoding
    if args.tamper:
        body += b" TAMPERED"
    for raw in args.header:
        name, _, value = raw.partition(":")
        headers[name.strip()] = value.strip()

    label = args.label or f"{args.method} {args.target}"
    if not args.json:
        print(f"--> {label}  ({args.url}, agent {args.agent_id}, ts {timestamp}, "
              f"{len(body)} byte body)")
        if args.repeat > 1:
            connection_note = ("one shared connection" if args.keepalive
                               else "a new connection each, resuming the TLS session"
                               if args.resume_session else "a new connection each")
            print(f"    signed ONCE, resent {args.repeat} times over {connection_note} "
                  f"-- MAC {mac[:16]}...")

    if args.resume_session:
        results = send_resuming_session(host, port, args.method, args.target, headers, body,
                                        args.timeout, args.repeat,
                                        args.client_cert, args.client_key)
    elif args.keepalive:
        results = send_on_one_connection(host, port, args.method, args.target, headers, body,
                                        args.timeout, args.repeat, args.interval,
                                        args.client_cert, args.client_key)
    else:
        results = []
        for attempt in range(args.repeat):
            if attempt and args.interval:
                time.sleep(args.interval)
            results.append(send_once(host, port, args.method, args.target, headers, body,
                                     args.timeout, args.client_cert, args.client_key))

    statuses = []
    for index, (status, reason, payload) in enumerate(results):
        statuses.append(status)
        if args.json:
            print(json.dumps({"label": label, "attempt": index + 1, "status": status,
                              "reason": reason, "body": payload[:200]}))
        else:
            shown = payload.replace("\n", " ")[:110]
            counter = f"[{index + 1}/{args.repeat}] " if args.repeat > 1 else ""
            print(f"<-- {counter}{status if status else 'NO RESPONSE'} {reason}"
                  f"{'  ' + shown if shown else ''}")

    if args.repeat > 1 and not args.json:
        summary = ", ".join(f"{count}x {status}" for status, count in Counter(statuses).items())
        print(f"    SUMMARY: {summary}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
