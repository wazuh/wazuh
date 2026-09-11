#!/usr/bin/env python3
"""
Sends bearer-authenticated (wazuh-agent+jwt) requests to remoted's HTTPS events API, with the precise
control the load-balancer tests need.

The sibling tools in ../ (send_stateless.py, send_agent_json.py) hardcode target="/stateless" per
scenario. That is right for their job but cannot express these tests. This tool adds:

  * the request target is SENT VERBATIM                            -> detects proxy normalisation
                    (it is not part of authentication: a rewritten path is a 404, never a 401)
  * --repeat        resends the SAME bytes -- same token -- N times  -> replay
  * --timestamp     pins the token's iat (with --jti), so two invocations produce byte-identical
                    requests                                        -> replay across nodes
  * --keepalive     reuses ONE connection for every request          -> per-connection vs
                                                                        per-request balancing
  * --strip-content-encoding / --add-content-encoding / --tamper-body
                    changes the header or the body after minting    -> proves they are NOT
                    the token                                          authenticated
  * --tamper        corrupts the token's signature                   -> must be 401
  * --client-cert   presents a client certificate                    -> verification_mode tests
  * --no-auth       sends NO Authorization header                    -> health-check tests, and
                                                                        proof that unauthenticated
                                                                        requests are rejected
  * --print-auth    prints the Authorization header and exits        -> lets OTHER clients (e.g.
                                                                        curl --http2) send an
                                                                        authenticated request

It speaks raw http.client rather than `requests`, because requests/urllib3 normalise the URL
and would destroy exactly what we are trying to measure.

The token (see ../wire_jwt.py, which must sit next to ../): HS256 over exactly
{alg,kid,typ} / {exp,iat,iss,jti,nbf,sub}, keyed with the 32 bytes of the agent's client.keys
secret. It binds the agent's identity only -- not the method, target, headers or body.

Response codes and what they prove:

    202  token valid AND event ingested by the engine
    401  token rejected                            -> authentication FAILED
    400  token valid, body not understood          -> authentication PASSED
    503  token valid, engine unavailable           -> authentication PASSED
    404  the route does not exist (prefix/path)    -> never reached authentication
    502  the proxy could not reach the node        -> never reached authentication

A manipulation that returns 400 or 503 instead of 401 got past authentication.
"""

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import time
from collections import Counter
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from wire_jwt import make_jwt, read_agent_key, tamper_token  # noqa: E402  (../wire_jwt.py)

DEFAULT_BODY = 'H {"wazuh":{"agent":{"id":"1001"}}}\nE 1:/var/log/syslog:load balancer test event'


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
                        help="request target, sent verbatim (default: %(default)s). Not part of "
                             "authentication: the bearer token binds the agent's identity only")
    parser.add_argument("--method", default="POST")
    parser.add_argument("--protocol-version", default="1")
    parser.add_argument("--body", default=DEFAULT_BODY)
    parser.add_argument("--body-file")
    parser.add_argument("--repeat", type=int, default=1,
                        help="resend the SAME request -- same token -- N times (replay)")
    parser.add_argument("--interval", type=float, default=0.0,
                        help="seconds to wait between resends")
    parser.add_argument("--keepalive", action="store_true",
                        help="reuse ONE connection for all resends")
    parser.add_argument("--resume-session", action="store_true",
                        help="one connection per resend, each RESUMING the previous TLS "
                             "session (what a proxy does by default)")
    parser.add_argument("--timestamp", type=int,
                        help="absolute iat for the token. Pinning it (with --jti) makes two "
                             "invocations produce byte-identical requests, for replay across nodes")
    parser.add_argument("--timestamp-offset", type=int, default=0,
                        help="shift the token's iat (negative = older)")
    parser.add_argument("--jti", help="fixed token id (22 base64url chars); default: fresh per run")
    parser.add_argument("--zstd", action="store_true",
                        help="compress the body and add Content-Encoding: zstd")
    parser.add_argument("--strip-content-encoding", action="store_true",
                        help="remove Content-Encoding after minting the token (the header is not authenticated)")
    parser.add_argument("--add-content-encoding",
                        help="add this Content-Encoding after minting the token (the header is not authenticated)")
    parser.add_argument("--tamper", action="store_true",
                        help="corrupt the token's signature; must return 401")
    parser.add_argument("--tamper-body", action="store_true",
                        help="modify the body after minting the token; the body is NOT authenticated, so "
                             "this passes auth (400/503, never 401)")
    parser.add_argument("--header", action="append", default=[], metavar="NAME:VALUE",
                        help="extra header (repeatable)")
    parser.add_argument("--no-auth", action="store_true",
                        help="send NO Authorization header (health-check tests). Does not need "
                             "client.keys")
    parser.add_argument("--print-auth", action="store_true",
                        help="print the Authorization header value and exit without sending, so "
                             "another client (e.g. curl --http2) can send an authenticated "
                             "request with it (any method/target/body: the token binds identity only)")
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
        # Unauthenticated on purpose (health probe / rejection test): no token is minted, so
        # this path works even on a box whose client.keys is empty.
        token = "(unauthenticated)"
    else:
        key_hex = read_agent_key(args.agent_id, args.client_keys)
        # Minted HERE. Anything after this point simulates what an intermediary could alter.
        token = make_jwt(args.agent_id, key_hex, now=timestamp, jti=args.jti)
        if args.tamper:
            token = tamper_token(token)
        if args.print_auth:
            print(f"Bearer {token}")
            return 0
        headers["Authorization"] = f"Bearer {token}"

    if args.strip_content_encoding:
        headers.pop("Content-Encoding", None)
    if args.add_content_encoding:
        headers["Content-Encoding"] = args.add_content_encoding
    if args.tamper_body:
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
            print(f"    token minted ONCE, resent {args.repeat} times over {connection_note} "
                  f"-- token {token[-16:]}")

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
