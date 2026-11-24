"""
Copyright (C) Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

A container registry served locally, for the integration tests of remote references.

## Why it has to impersonate ghcr.io

The module accepts a `<ref>` only when its registry is `ghcr.io`, and it builds the request URL
with no port, so a registry on `localhost:5000` is rejected before a single request is made.
Rather than weaken that check for the benefit of a test, the server here *is* `ghcr.io` for the
duration of a test: it listens on 127.0.0.1:443, serves a certificate issued for `ghcr.io` by a
throwaway certificate authority, and the test adds a hosts entry so the name resolves locally.
The agent is pointed at that authority through `<ca_bundle>`, which also exercises the
certificate resolution the module does at run time.

Nothing here needs a container engine, a network, or a real registry.

## Amazon ECR

The same server also answers as the three Amazon ECR hosts the module recognises, selected with
``flavor``:

- ``ecr-public`` answers as ``public.ecr.aws``: a Bearer token from ``/token/``, always anonymous.
- ``ecr-private`` answers as ``123456789012.dkr.ecr.us-east-1.amazonaws.com``: a ``Basic`` token
  that only the AWS API endpoint, ``api.ecr.us-east-1.amazonaws.com``, can issue. The registry
  never accepts anything else, and answers ``400`` and a ``DENIED`` body to a token it did not
  issue, which is what the real registry was measured to do.

The API endpoint verifies the AWS Signature Version 4 of the ``GetAuthorizationToken`` request
itself. The verification is written here with Python's ``hmac`` and ``hashlib`` alone, so it
shares nothing with the C++ signer it checks. A wrong secret key is answered with the AWS
``InvalidSignatureException`` shape and a message that quotes the request, to prove that the
module does not copy that text into its log.

## What it implements

The subset of the OCI distribution API the module actually uses:

- `GET /token` - the token endpoint the challenge advertises. Validates HTTP Basic for a private
  repository and refuses an anonymous or wrong credential.
- `GET /v2/<repository>/manifests/<reference>` - answers `401` with a `WWW-Authenticate`
  challenge until a bearer token is presented, then the image index or the image manifest.
- `GET /v2/<repository>/blobs/<digest>` - the configuration blob and the layer blobs. A layer is
  answered with a `307` to a second local host, so the tests exercise the redirect the real
  registry performs and can prove the token is not carried across it.

Every request is recorded, so a test can assert on what was *not* requested. That is what makes
the unchanged-image case checkable: the assertion is "no blob was fetched", not "it was quick".
"""
import base64
import calendar
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The name the module insists on, and the port it uses implicitly.
REGISTRY_HOST = 'ghcr.io'
REGISTRY_PORT = 443

# Where a layer request is redirected, mirroring the real registry's content host.
CONTENT_HOST = 'pkg-containers.githubusercontent.com'

TOKEN_VALUE = 'a-scripted-bearer-token'

# Amazon ECR, as the module recognises it.
ECR_PUBLIC_HOST = 'public.ecr.aws'
ECR_REGION = 'us-east-1'
ECR_PRIVATE_HOST = '123456789012.dkr.ecr.%s.amazonaws.com' % ECR_REGION
ECR_API_HOST = 'api.ecr.%s.amazonaws.com' % ECR_REGION
ECR_TARGET = 'AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken'

# The AWS key pair the local API endpoint accepts, and the keystore keys the tests store it under.
# Not real credentials.
ECR_ACCESS_KEY_ID = 'AKIDEXAMPLETESTKEY'
ECR_SECRET_ACCESS_KEY = 'SecretAccessKeyOfTheIntegrationTest/0123456789'
ECR_KEYS = ('ecr_key_id', 'ecr_secret')

# Every name the server answers for, and so every name the certificate and the hosts entry need.
ALL_HOSTS = [REGISTRY_HOST, CONTENT_HOST, ECR_PUBLIC_HOST, ECR_PRIVATE_HOST, ECR_API_HOST]

FLAVOR_HOSTS = {'ghcr': REGISTRY_HOST, 'ecr-public': ECR_PUBLIC_HOST, 'ecr-private': ECR_PRIVATE_HOST}


def verify_sigv4(method: str, path: str, query: str, headers, body: bytes, access_key_id: str,
                 secret_access_key: str, region: str, service: str = 'ecr', now: float = None) -> str:
    """Verify an AWS Signature Version 4 header, written independently of the module's signer.

    Returns ``'ok'`` or the reason it is not: ``'malformed'``, ``'unknown_key'``, ``'scope'``,
    ``'clock'`` or ``'signature'``.
    """
    match = re.match(r'AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request, '
                     r'SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$', headers.get('Authorization', ''))

    if not match:
        return 'malformed'

    key_id, date, signed_region, signed_service, signed_headers, signature = match.groups()

    if key_id != access_key_id:
        return 'unknown_key'

    if (signed_region, signed_service) != (region, service):
        return 'scope'

    amz_date = headers.get('X-Amz-Date', '')

    try:
        issued = calendar.timegm(time.strptime(amz_date, '%Y%m%dT%H%M%SZ'))
    except ValueError:
        return 'malformed'

    if abs((time.time() if now is None else now) - issued) > 300 or not amz_date.startswith(date):
        return 'clock'

    canonical_headers = ''.join('%s:%s\n' % (name, ' '.join(headers.get(name, '').split()))
                                for name in signed_headers.split(';'))
    canonical_request = '\n'.join([method, path, query, canonical_headers, signed_headers,
                                   hashlib.sha256(body).hexdigest()])
    scope = '%s/%s/%s/aws4_request' % (date, region, service)
    string_to_sign = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope,
                                hashlib.sha256(canonical_request.encode()).hexdigest()])

    key = ('AWS4' + secret_access_key).encode()

    for part in (date, region, service, 'aws4_request'):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()

    expected = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    return 'ok' if hmac.compare_digest(expected, signature) else 'signature'


def issue_certificate(directory: str, hosts: list = None) -> tuple:
    """Create a throwaway CA and a certificate for the registry host.

    Returns ``(ca_certificate_path, server_certificate_path, server_key_path)``. The CA is what
    the agent is pointed at through ``<ca_bundle>``; it is generated per run and never reused.
    """
    ca_key = os.path.join(directory, 'ca.key')
    ca_certificate = os.path.join(directory, 'ca.crt')
    server_key = os.path.join(directory, 'server.key')
    server_request = os.path.join(directory, 'server.csr')
    server_certificate = os.path.join(directory, 'server.crt')
    extensions = os.path.join(directory, 'server.ext')

    names = ', '.join('DNS:%s' % host for host in (hosts or ALL_HOSTS))

    with open(extensions, 'w') as handle:
        handle.write(
            'subjectAltName = %s, DNS:localhost, IP:127.0.0.1\n'
            'basicConstraints = CA:FALSE\n'
            'keyUsage = digitalSignature, keyEncipherment\n'
            'extendedKeyUsage = serverAuth\n' % names
        )

    def run(*arguments):
        subprocess.run(list(arguments), check=True, capture_output=True)

    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', ca_key, '-out', ca_certificate, '-days', '1',
        '-subj', '/CN=wazuh-container-images-test-ca')

    run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', server_key, '-out', server_request,
        '-subj', '/CN=%s' % REGISTRY_HOST)

    run('openssl', 'x509', '-req', '-in', server_request,
        '-CA', ca_certificate, '-CAkey', ca_key, '-CAcreateserial',
        '-out', server_certificate, '-days', '1', '-extfile', extensions)

    return ca_certificate, server_certificate, server_key


class Repository:
    """One repository the local registry serves."""

    def __init__(self, name: str, private: bool = False):
        self.name = name
        self.private = private
        self.blobs = {}       # digest -> bytes
        self.layer_digests = set()  # the subset of blobs that are layers, which redirect
        self.manifests = {}   # digest -> bytes
        self.tags = {}        # tag -> digest

    def add_blob(self, body: bytes, layer: bool = False) -> str:
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        self.blobs[digest] = body

        if layer:
            self.layer_digests.add(digest)

        return digest

    def add_manifest(self, body: bytes, tag: str = None) -> str:
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        self.manifests[digest] = body

        if tag:
            self.tags[tag] = digest

        return digest

    def resolve(self, reference: str) -> bytes:
        """The manifest a tag or a digest names, or None."""
        digest = self.tags.get(reference, reference)

        return self.manifests.get(digest)


class LocalRegistry:
    """A TLS registry on 127.0.0.1:443, answering as ``ghcr.io`` or as an Amazon ECR host."""

    def __init__(self, port: int = REGISTRY_PORT, content_authority: str = None, flavor: str = 'ghcr'):
        self.port = port
        self.flavor = flavor
        self.host = FLAVOR_HOSTS[flavor]

        # ecr-private: the AWS key pair the API endpoint accepts, what it was asked, and the
        # token it issued (the only one the registry then accepts).
        self.aws_credential = None      # (access key id, secret access key)
        self.api_requests = []          # one dict per POST: verification result and headers
        self.issued_token = None

        # Where a layer request is redirected. The real registry sends layers to a
        # different host, and that difference is load-bearing: libcurl only withholds the
        # Authorization header across a change of host, which is the property that keeps
        # the token away from the content host. A caller that cannot resolve the real name
        # passes a different local name here, which preserves the cross-host behaviour
        # while still resolving to this socket.
        self.content_authority = content_authority or (
            CONTENT_HOST if port == REGISTRY_PORT else '%s:%d' % (CONTENT_HOST, port))
        self._directory = tempfile.mkdtemp(prefix='wazuh-local-registry-')
        self.ca_certificate, certificate, key = issue_certificate(self._directory)

        self.repositories = {}
        self.requests = []          # every path requested, in order
        self.credential = None      # (user, passkey) a private repository requires
        self.throttle_paths = {}    # path fragment -> remaining number of 429 answers

        registry = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_args):
                """Silent: the test's own assertions are the record that matters."""

            def _send(self, status, body=b'', headers=None):
                self.send_response(status)

                for name, value in (headers or {}).items():
                    self.send_header(name, value)

                self.send_header('Content-Length', str(len(body)))
                self.end_headers()

                if body:
                    self.wfile.write(body)

            def _authorized(self):
                if registry.flavor == 'ecr-private':
                    return (registry.issued_token is not None and
                            registry.issued_token != registry.expired_token and
                            self.headers.get('Authorization') == 'Basic %s' % registry.issued_token)

                return self.headers.get('Authorization') == 'Bearer %s' % TOKEN_VALUE

            def _refuse(self, repository_name=None):
                """The answer to a request that carries no accepted token."""
                if registry.flavor == 'ecr-private':
                    if self.headers.get('Authorization'):
                        # Measured against the real registry: a token it did not issue is a 400.
                        registry.refused_tokens += 1
                        self._send(400, b'{"errors":[{"code":"DENIED","message":"Your Authorization Token is invalid."}]}',
                                   {'Content-Type': 'application/json'})
                    else:
                        self._send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                                   {'WWW-Authenticate': 'Basic realm="https://%s/",service="ecr.amazonaws.com"'
                                                        % registry.host})
                    return

                if registry.flavor == 'ecr-public':
                    challenge = 'Bearer realm="https://%s/token/",service="%s",scope="aws"' % (registry.host, registry.host)
                elif registry.port != 443:
                    challenge = ('Bearer realm="https://%s:%d/token",service="%s",scope="repository:%s:pull"'
                                 % (registry.host, registry.port, registry.host, repository_name))
                else:
                    challenge = ('Bearer realm="https://%s/token",service="%s",scope="repository:%s:pull"'
                                 % (registry.host, registry.host, repository_name))

                self._send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                           {'WWW-Authenticate': challenge, 'Content-Type': 'application/json'})

            def do_POST(self):  # noqa: N802 - the name the base class requires
                """The AWS API endpoint: ``GetAuthorizationToken``, signature verified."""
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                path, _, query = self.path.partition('?')
                outcome = 'no_credential'

                if registry.aws_credential and self.headers.get('X-Amz-Target') == ECR_TARGET:
                    outcome = verify_sigv4('POST', path, query, self.headers, body, registry.aws_credential[0],
                                           registry.aws_credential[1], ECR_REGION)

                registry.api_requests.append({'outcome': outcome, 'host': self.headers.get('Host'),
                                              'target': self.headers.get('X-Amz-Target'),
                                              'authorization': self.headers.get('Authorization', '')})

                if outcome == 'ok':
                    password = 'registry-password-' + secrets.token_hex(8)
                    registry.issued_password = password
                    registry.issued_token = base64.b64encode(('AWS:' + password).encode()).decode()
                    answer = json.dumps({'authorizationData': [{
                        'authorizationToken': registry.issued_token,
                        'expiresAt': time.time() + 43200,
                        'proxyEndpoint': 'https://%s' % ECR_PRIVATE_HOST}]}).encode()
                    self._send(200, answer, {'Content-Type': 'application/x-amz-json-1.1'})
                    return

                if outcome in ('unknown_key', 'no_credential'):
                    answer = {'__type': 'UnrecognizedClientException',
                              'message': 'The security token included in the request is invalid.'}
                elif outcome == 'clock':
                    answer = {'__type': 'InvalidSignatureException',
                              'message': 'Signature expired: the request is too far from the server time'}
                else:
                    # The shape AWS answers a bad signature with, and its habit of quoting the
                    # request: the module must not copy any of this into its log.
                    answer = {'__type': 'InvalidSignatureException',
                              'message': 'The request signature we calculated does not match the signature you '
                                         'provided. Authorization: %s' % self.headers.get('Authorization', '')}

                self._send(400, json.dumps(answer).encode(), {'Content-Type': 'application/x-amz-json-1.1'})

            def do_GET(self):  # noqa: N802 - the name the base class requires
                registry.requests.append(self.path)

                for fragment, remaining in list(registry.throttle_paths.items()):
                    if fragment in self.path and remaining > 0:
                        registry.throttle_paths[fragment] = remaining - 1
                        self._send(429, b'{"errors":[{"code":"TOOMANYREQUESTS"}]}',
                                   {'Retry-After': '1', 'Content-Type': 'application/json'})
                        return

                # Both host names resolve to this one socket, so the path is what tells the
                # registry endpoints apart from the content host that layers redirect to.
                if self.path.startswith('/content/'):
                    self._content()
                elif self.path.startswith('/token'):
                    self._token()
                elif '/manifests/' in self.path:
                    self._manifest()
                elif '/blobs/' in self.path:
                    self._blob()
                else:
                    self._send(404, b'{"errors":[{"code":"NOT_FOUND"}]}')

            def _repository_and_reference(self, separator):
                path = self.path.split('?')[0]
                name, _, reference = path[len('/v2/'):].partition('/%s/' % separator)

                return registry.repositories.get(name), reference

            def _token(self):
                scope = ''

                for parameter in self.path.split('?', 1)[-1].split('&'):
                    if parameter.startswith('scope='):
                        scope = parameter[len('scope='):]

                # The module percent-encodes the scope, so "repository:owner/app:pull" arrives
                # as "repository%3Aowner%2Fapp%3Apull".
                decoded = scope.replace('%3A', ':').replace('%2F', '/')
                parts = decoded.split(':')
                name = parts[1] if len(parts) >= 3 else ''
                repository = registry.repositories.get(name)

                if repository is not None and repository.private:
                    header = self.headers.get('Authorization', '')

                    if not header.startswith('Basic '):
                        registry.anonymous_token_attempts += 1
                        self._send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}')
                        return

                    supplied = base64.b64decode(header[len('Basic '):]).decode()
                    expected = '%s:%s' % registry.credential if registry.credential else None

                    if supplied != expected:
                        registry.rejected_credentials.append(supplied.split(':')[0])
                        self._send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}')
                        return

                self._send(200, json.dumps({'token': TOKEN_VALUE}).encode(),
                           {'Content-Type': 'application/json'})

            def _manifest(self):
                repository, reference = self._repository_and_reference('manifests')

                if repository is None:
                    self._send(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}')
                    return

                if not self._authorized():
                    self._refuse(repository.name)
                    return

                body = repository.resolve(reference)

                if body is None:
                    self._send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}')
                    return

                media_type = json.loads(body).get('mediaType', 'application/vnd.oci.image.manifest.v1+json')
                self._send(200, body, {
                    'Content-Type': media_type,
                    'Docker-Content-Digest': 'sha256:' + hashlib.sha256(body).hexdigest(),
                })

            def _blob(self):
                repository, digest = self._repository_and_reference('blobs')

                if repository is None or digest not in repository.blobs:
                    self._send(404, b'{"errors":[{"code":"BLOB_UNKNOWN"}]}')
                    return

                if not self._authorized():
                    self._refuse(repository.name)
                    return

                # A token that dies while the image is being read: the first layer request is
                # answered 400 DENIED, as a token the registry no longer accepts was measured to
                # be, and so is every request that still carries that token afterwards.
                if (registry.expire_token_on_first_layer and registry.expired_token is None
                        and digest in repository.layer_digests):
                    registry.expired_token = registry.issued_token
                    self._refuse(repository.name)
                    return

                body = repository.blobs[digest]

                # A layer is redirected to the content host, as the real registry does. The
                # configuration blob is answered directly, which it also does.
                if digest in repository.layer_digests:
                    self._send(307, b'', {'Location': 'https://%s/content/%s/%s'
                                                      % (registry.content_authority,
                                                         repository.name, digest)})
                    return

                self._send(200, body, {'Content-Type': 'application/octet-stream'})

            def _content(self):
                # What the test needs from here is whether the credential followed the redirect.
                registry.redirect_authorization = self.headers.get('Authorization')

                # The repository name contains a slash ("owner/app"), so the digest is
                # what follows the LAST one, not the first.
                remainder = self.path[len('/content/'):]
                name, _, digest = remainder.rpartition('/')
                repository = registry.repositories.get(name)

                if repository is None or digest not in repository.blobs:
                    self._send(404, b'')
                    return

                self._send(200, repository.blobs[digest], {'Content-Type': 'application/octet-stream'})

        self.redirect_authorization = None
        self.anonymous_token_attempts = 0
        self.rejected_credentials = []
        self.refused_tokens = 0
        self.issued_password = None
        self.expire_token_on_first_layer = False
        self.expired_token = None

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)

        self._server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        # shutdown() waits for serve_forever() to exit, so it would block forever if the
        # server was never started.
        if self._thread.is_alive():
            self._server.shutdown()

        self._server.server_close()

    def add_repository(self, name: str, private: bool = False) -> Repository:
        repository = Repository(name, private)
        self.repositories[name] = repository

        return repository

    def blob_requests(self) -> list:
        """Every request for a blob, whether direct or redirected.

        This includes the *configuration* blob, which the module reads to learn an image's
        platform. Use :meth:`layer_requests` when the question is whether image contents were
        retrieved, because a reference can legitimately read a configuration blob and then
        decline the image: a manifest that is not part of an index carries no platform of its
        own, so the configuration blob is the only thing that can confirm it.
        """
        return [path for path in self.requests if '/blobs/' in path or path.startswith('/content/')]

    def layer_requests(self) -> list:
        """Every request for a layer. This is what "image contents were retrieved" means."""
        layers = set()

        for repository in self.repositories.values():
            layers.update(repository.layer_digests)

        return [path for path in self.requests
                if any(digest in path for digest in layers)]
