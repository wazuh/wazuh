# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Fixtures for the credential resolver's tests.

The suite runs as root and refuses to run otherwise: the resolver's job is ownership and mode checks, which a
non-root run could only skip, and a suite that skips most of its cases looks exactly like one that passes them
(src/shared_modules/manager_certs/tests/ci/assert_no_skipped_tests.sh tells that story).

Every test works in a private root:root 0700 tree under /root, never in pytest's tmp_path: /tmp is world-writable,
and the resolver's rules refuse what such a tree holds. The service account is played by `daemon`, which exists on
Debian, Ubuntu and RHEL alike, so CI runners need no wazuh-manager account.
"""

import hashlib
import json
import importlib.machinery
import importlib.util
import os
import pwd
import shutil
import stat
import sys
import tempfile

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

# Test fixtures need many RSA keys and generating them dominated the suite's time. They come from a pool built once
# per session; draws are consecutive, so the keys of one fixture are always distinct. The program's own minting and
# issuing, in the code under test, still generate fresh keys.
_KEY_POOL = []
_KEY_DRAWS = [0]


def pool_key():
    if not _KEY_POOL:
        _KEY_POOL.extend(rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(8))
    key = _KEY_POOL[_KEY_DRAWS[0] % len(_KEY_POOL)]
    _KEY_DRAWS[0] += 1
    return key


def intermediate(issuer_cert, issuer_key, cn="intermediate-ca", *, days=(-1, 3650), is_ca=True, key_cert_sign=True,
                 path_length=None, eku=None):
    """A CA certificate signed by `issuer_cert`/`issuer_key`, or self-signed when both are None. The keyword arguments
    break one property at a time; `eku` restricts the CA to those extended key usages. Returns (certificate, key)."""
    key = pool_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder().subject_name(name)
               .issuer_name(issuer_cert.subject if issuer_cert is not None else name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now + datetime.timedelta(days=days[0]))
               .not_valid_after(now + datetime.timedelta(days=days[1]))
               .add_extension(x509.BasicConstraints(ca=is_ca, path_length=path_length if is_ca else None),
                              critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False, key_cert_sign=key_cert_sign,
                                            crl_sign=key_cert_sign, encipher_only=False, decipher_only=False),
                              critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(issuer_key if issuer_key is not None else key, hashes.SHA256()), key


def unparsable_certificate(issuer_cert=None, issuer_key=None, cn="unparsable", *, duplicate=False):
    """A certificate whose extensions cannot be parsed: a basicConstraints holding garbage, or (`duplicate`) the same
    extension twice, made by patching keyUsage's OID into subjectKeyIdentifier's in the DER (the signature no longer
    matches, which does not matter: parsing fails first). Signed by `issuer_cert`/`issuer_key`, or self-signed.
    Returns (PEM bytes, key)."""
    key = pool_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder().subject_name(name)
               .issuer_name(issuer_cert.subject if issuer_cert is not None else name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30)))
    if duplicate:
        builder = (builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                                crl_sign=False, encipher_only=False, decipher_only=False), critical=True))
    else:
        builder = builder.add_extension(x509.UnrecognizedExtension(ExtensionOID.BASIC_CONSTRAINTS, b"\x01\x02\x03"),
                                        critical=True)
    der = builder.sign(issuer_key if issuer_key is not None else key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER)
    if duplicate:
        der = der.replace(b"\x06\x03\x55\x1d\x0f", b"\x06\x03\x55\x1d\x0e", 1)
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM), key


PROGRAM = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "wazuh-manager-resolve-credentials.py")
ACCOUNT = "daemon"


def pytest_configure(config):
    if os.geteuid() != 0:
        pytest.exit("the credential resolver suite must run as root (it never skips root-only cases)", returncode=2)


def load_program():
    """Load the program by path: it is a script with dashes in its name, not an importable module."""
    loader = importlib.machinery.SourceFileLoader("wazuh_manager_resolve_credentials", PROGRAM)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def resolver():
    return load_program()


# Stand-ins for the three Wazuh programs the resolver drives. They read their behaviour from <home>/stub-control.json
# and record what they were given, so tests can assert on it. Values on stdin are recorded too: the stubs are the
# only place a test may look at a password.
KEYSTORE_STUB = """
import json, os, sys
home = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
control = json.load(open(os.path.join(home, "stub-control.json")))
store_path = os.path.join(home, "queue", "keystore", "keystore.json")
store = json.load(open(store_path)) if os.path.exists(store_path) else {}
args = sys.argv[1:]
family, key, get = args[args.index("-f") + 1], args[args.index("-k") + 1], "-g" in args
entry = f"{family}/{key}"
if get:
    if store.get(entry):
        print(store[entry])
        sys.exit(0)
    sys.exit(1)
if control.get("keystore_fail"):
    print("Error storing the value.", file=sys.stderr)
    sys.exit(1)
value = sys.stdin.readline().rstrip("\\n")
if not value:
    print("Error reading from stdin.", file=sys.stderr)
    sys.exit(1)
store[entry] = value
json.dump(store, open(store_path, "w"))
"""

CONF_STUB = """
import json, os, sys
home = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
control = json.load(open(os.path.join(home, "stub-control.json")))
args = sys.argv[1:]
if args[-1] == "dump":
    # The effective configuration with the schema's defaults, rooted at the sandbox's <CONF>; `conf_dump` overrides
    # dotted keys, `dump_exit` fails the call, `dump_raw` replaces the output, `dump_sleep` delays it (seconds). Not
    # logged: --check must leave the sandbox's tree as it found it.
    if control.get("dump_sleep"):
        import time
        time.sleep(control["dump_sleep"])
    certs = os.path.join(os.path.dirname(args[args.index("-f") + 1]), "certs")
    document = {
        "cluster": {"node_type": control.get("role") or "master"},
        "remote": {"https": {"certificate": os.path.join(certs, "remoted.pem"),
                             "key": os.path.join(certs, "remoted-key.pem"),
                             "ca_certificate": os.path.join(certs, "root-ca.pem"), "ca": ""}},
        "auth": {"disabled": False, "ssl_manager_cert": os.path.join(certs, "remoted.pem"),
                 "ssl_manager_key": os.path.join(certs, "remoted-key.pem"), "ssl_agent_ca": ""},
        "indexer": {"ssl": {"certificate_authorities": [os.path.join(certs, "indexer-ca.pem")],
                            "certificate": os.path.join(certs, "indexer-connector.pem"),
                            "key": os.path.join(certs, "indexer-connector-key.pem")}},
    }
    for dotted, value in control.get("conf_dump", {}).items():
        *parents, last = dotted.split(".")
        node = document
        for part in parents:
            node = node.setdefault(part, {})
        node[last] = value
    code = control.get("dump_exit", 0)
    if code == 0:
        print(control["dump_raw"] if "dump_raw" in control else json.dumps(document))
    sys.exit(code)
with open(os.path.join(home, "conf-calls.log"), "a") as log:
    log.write(json.dumps(args) + "\\n")
code = control.get("conf_exit", 0)
if code == 0:
    print(control.get("role", "master"))
sys.exit(code)
"""

RBAC_STUB = """
import json, os, sys
home = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))))
control_path = os.path.join(home, "stub-control.json")
control = json.load(open(control_path))
assert sys.argv[1:] == ["seed", "--passwords-file", "-"], sys.argv
received = json.loads(sys.stdin.read())
with open(os.path.join(home, "seed-calls.json"), "a") as log:
    log.write(json.dumps(received) + "\\n")
if control.get("rbac_fail_times", 0) > 0:
    control["rbac_fail_times"] -= 1
    json.dump(control, open(control_path, "w"))
    print("\\tInternal error: database is locked")
    sys.exit(1)
db = os.path.join(home, "api", "configuration", "security", "rbac.db")
os.makedirs(os.path.dirname(db), exist_ok=True)
with open(db, "w") as handle:
    handle.write("seeded")
print(f"\\t{db} created")
"""


def install_stubs(sandbox):
    """Put the three stand-ins where Paths expects the real programs."""
    home = sandbox.home
    for directory in ("bin", "framework/python/bin", "framework/scripts"):
        os.makedirs(os.path.join(home, directory), exist_ok=True)
    shebang = f"#!{sys.executable} -I\n"
    sandbox.write(os.path.join(home, "bin", "wazuh-manager-keystore"), shebang + KEYSTORE_STUB, mode=0o750)
    sandbox.write(os.path.join(home, "bin", "wazuh-manager-conf"), shebang + CONF_STUB, mode=0o750)
    os.symlink(sys.executable, os.path.join(home, "framework", "python", "bin", "python3"))
    sandbox.write(os.path.join(home, "framework", "scripts", "rbac_control.py"), RBAC_STUB, mode=0o640)
    sandbox.control()


class Sandbox:
    """A private tree: <base>/conf (<CONF>, 0770 root:daemon), <base>/home, <base>/indexer-export (absent until a
    test creates it)."""

    def __init__(self, resolver, base):
        self.base = base
        self.conf = os.path.join(base, "conf")
        self.home = os.path.join(base, "home")
        self.indexer_export = os.path.join(base, "indexer-export")
        account = pwd.getpwnam(ACCOUNT)
        self.account_uid = account.pw_uid
        self.account_gid = account.pw_gid
        os.mkdir(self.conf)
        os.chown(self.conf, 0, self.account_gid)
        os.chmod(self.conf, 0o770)
        os.mkdir(self.home, 0o750)
        # The home-side directories --clear walks, owned as the installer leaves them.
        for parts, uid, gid, mode in ((("queue",), "account", "account", 0o770),
                                      (("queue", "keystore"), "account", "account", 0o750),
                                      (("var",), 0, "account", 0o750),
                                      (("var", "run"), 0, "account", 0o770)):
            path = os.path.join(self.home, *parts)
            os.mkdir(path)
            os.chown(path, self.account_uid if uid == "account" else uid, self.account_gid)
            os.chmod(path, mode)
        # certs/ as the installer leaves it (src/init/inst-functions.sh SetCertsOwnership): the resolver never creates it.
        self.certs = os.path.join(self.conf, "certs")
        os.mkdir(self.certs)
        os.chown(self.certs, 0, self.account_gid)
        os.chmod(self.certs, 0o750)
        self.resolver = resolver
        self.proc = os.path.join(base, "proc")
        self.write_proc()
        self.paths = resolver.Paths(home=self.home, conf=self.conf, indexer_export=self.indexer_export,
                                    service_user=ACCOUNT, service_group=ACCOUNT, proc=self.proc)
        install_stubs(self)
        self.make_indexer_trust()

    def write_proc(self, route=None, ipv6_route=None, if_inet6=None):
        """/proc/net fixtures. Default: eth0 carries both default routes and has one global IPv6 address; docker0
        has addresses but no default route."""
        net = os.path.join(self.proc, "net")
        os.makedirs(net, exist_ok=True)
        default_route = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
                         "eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\n"
                         "docker0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n")
        default_v6 = ("00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
                      "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n")
        default_inet6 = ("20010db8000000000000000000000010 02 40 00 00 eth0\n"
                         "fe800000000000000000000000000002 02 40 20 80 eth0\n"
                         "20010db8000000000000000000000099 03 40 00 00 docker0\n")
        for name, text in (("route", default_route if route is None else route),
                           ("ipv6_route", default_v6 if ipv6_route is None else ipv6_route),
                           ("if_inet6", default_inet6 if if_inet6 is None else if_inet6)):
            with open(os.path.join(net, name), "w") as handle:
                handle.write(text)

    def make_indexer_trust(self, eku="client", ca_is_ca=True, foreign=False, expired=False, key_mismatch=False,
                           mode=0o750, via_intermediate=False, intermediate_eku=None):
        """What wazuh-indexer publishes on this host for the manager: its CA (export/ca.pem) and a client pair it
        issued (export/manager-client.pem, leaf then CA, and its key). The keyword arguments break one property;
        `via_intermediate` has an intermediate CA issue the leaf, carried in the client file between leaf and CA, and
        `intermediate_eku` restricts that intermediate's extended key usages.
        Returns {"ca": ca_pem, "client": client_pem, "key": key_pem}, plus "leaf" and "intermediate" (PEM) with
        `via_intermediate`."""
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key = pool_key()
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wazuh-indexer-ca")])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number())
              .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=ca_is_ca, path_length=None), critical=True)
              .sign(ca_key, hashes.SHA256()))
        signer, issuer = ca_key, ca_name
        middle = None
        if via_intermediate:
            middle, signer = intermediate(ca, ca_key, "wazuh-indexer-intermediate-ca", eku=intermediate_eku)
            issuer = middle.subject
        if foreign:
            signer = pool_key()
        key = pool_key()
        window = (now - datetime.timedelta(days=60), now - datetime.timedelta(days=1)) if expired else \
                 (now - datetime.timedelta(days=1), now + datetime.timedelta(days=3650))
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wazuh-manager")]))
                   .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(window[0]).not_valid_after(window[1])
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
        if eku == "client":
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        elif eku == "server":
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        leaf = builder.sign(signer, hashes.SHA256())
        pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
        key_pem = (pool_key() if key_mismatch else key) \
            .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        os.makedirs(self.indexer_export, exist_ok=True)
        os.chown(self.indexer_export, 0, 0)
        os.chmod(self.indexer_export, mode)
        files = {"ca": pem(ca), "client": pem(leaf) + (pem(middle) if middle else b"") + pem(ca), "key": key_pem}
        if middle:
            files.update(leaf=pem(leaf), intermediate=pem(middle))
        self.write(os.path.join(self.indexer_export, "ca.pem"), files["ca"], mode=0o644)
        self.write(os.path.join(self.indexer_export, "manager-client.pem"), files["client"], mode=0o600)
        self.write(os.path.join(self.indexer_export, "manager-client-key.pem"), files["key"], mode=0o600)
        return files

    def stage_ca(self, node="node1", key=True, bundle=True, pairs=True):
        """What a finished --install leaves, made with the program itself: the CA (without the mint marker, so it
        counts as staged), certs/root-ca.pem and both server pairs. Returns the CA certificate's PEM bytes."""
        r = self.resolver
        generate = r.rsa.generate_private_key
        r.rsa.generate_private_key = lambda **_: pool_key()         # only while staging; restored below
        try:
            return self._stage_ca(node, key, bundle, pairs)
        finally:
            r.rsa.generate_private_key = generate

    def _stage_ca(self, node, key, bundle, pairs):
        r = self.resolver
        with r.open_top(self.conf, r.conf_spec(self.paths)) as conf:
            with r.ensure_dir(conf, "ca", r.CA_SPEC) as ca:
                state = r.mint_ca(ca, node)
        os.unlink(os.path.join(self.conf, "ca", r.CA_MARKER))
        if bundle:
            self.write(os.path.join(self.certs, "root-ca.pem"), state.cert_bytes, mode=0o640, gid=self.account_gid)
        if pairs:
            sans = r.finish_sans([r.San("DNS", node)])
            for name in ("remoted", "apid"):
                cert, key_bytes = r.issue_server_pair(state, node, sans)
                self.write(os.path.join(self.certs, f"{name}-key.pem"), key_bytes, mode=0o640, gid=self.account_gid)
                self.write(os.path.join(self.certs, f"{name}.pem"), cert, mode=0o640, gid=self.account_gid)
        if not key:
            os.unlink(os.path.join(self.conf, "ca", r.CA_KEY))
        return state.cert_bytes

    def control(self, **settings):
        """Set the stubs' behaviour: role, conf_exit, conf_dump, dump_exit, dump_raw, dump_sleep, keystore_fail,
        rbac_fail_times."""
        with open(os.path.join(self.home, "stub-control.json"), "w") as handle:
            json.dump(settings, handle)

    def api_yaml(self, text, mode=0o660):
        """<home>/api/configuration/api.yaml as the installer leaves it: the account's group may write it."""
        directory = os.path.join(self.home, "api", "configuration")
        os.makedirs(directory, exist_ok=True)
        return self.write(os.path.join(directory, "api.yaml"), text, mode=mode, gid=self.account_gid)

    @property
    def keystore_dir(self):
        return os.path.join(self.home, "queue", "keystore")

    def keystore(self):
        path = os.path.join(self.keystore_dir, "keystore.json")
        return json.load(open(path)) if os.path.exists(path) else {}

    def seed_calls(self):
        path = os.path.join(self.home, "seed-calls.json")
        return [json.loads(line) for line in open(path)] if os.path.exists(path) else []

    def conf_calls(self):
        path = os.path.join(self.home, "conf-calls.log")
        return [json.loads(line) for line in open(path)] if os.path.exists(path) else []

    @property
    def rbac_db(self):
        return os.path.join(self.home, "api", "configuration", "security", "rbac.db")

    def path(self, *parts):
        return os.path.join(self.base, *parts)

    def write(self, path, data, mode=0o600, uid=0, gid=0):
        """Create a file as root (or as the account with uid/gid) with exact owner and mode."""
        with open(path, "wb") as handle:
            handle.write(data if isinstance(data, bytes) else data.encode())
        os.chown(path, uid, gid)
        os.chmod(path, mode)
        return path

    def plant(self, path, data=b"planted\n", mode=0o640):
        """A file the service account wrote."""
        return self.write(path, data, mode=mode, uid=self.account_uid, gid=self.account_gid)

    def make_indexer_export(self, credentials=None, mode=0o750):
        os.makedirs(self.indexer_export, exist_ok=True)
        os.chown(self.indexer_export, 0, 0)
        os.chmod(self.indexer_export, mode)
        if credentials is not None:
            self.write(os.path.join(self.indexer_export, "credentials.env"), credentials)
        return self.indexer_export

    def tree_state(self):
        """Names, types, owners, modes and content digests of everything in the sandbox (no link is followed)."""
        state = {}
        for root, dirs, files in os.walk(self.base):
            for name in dirs + files:
                full = os.path.join(root, name)
                st = os.lstat(full)
                digest = None
                if stat.S_ISREG(st.st_mode):
                    with open(full, "rb") as handle:
                        digest = hashlib.sha256(handle.read()).hexdigest()
                elif stat.S_ISLNK(st.st_mode):
                    digest = os.readlink(full)
                state[os.path.relpath(full, self.base)] = (stat.S_IFMT(st.st_mode), st.st_uid, st.st_gid,
                                                           stat.S_IMODE(st.st_mode), digest)
        return state


# Host facts the resolver reads, made deterministic for every test: the host name, its canonical name, and the
# primary IPv4 address of each interface (the /proc/net fixtures name the interfaces).
HOST_NAME = "node1.example.com"
INTERFACE_IPV4 = {"eth0": "192.0.2.10", "docker0": "172.18.0.1", "lo": "127.0.0.1"}


@pytest.fixture(autouse=True)
def deterministic_host(resolver, monkeypatch):
    monkeypatch.setattr(resolver.socket, "gethostname", lambda: HOST_NAME)
    monkeypatch.setattr(resolver, "canonical_name", lambda host: HOST_NAME)
    monkeypatch.setattr(resolver, "interface_ipv4", lambda name: INTERFACE_IPV4.get(name))


@pytest.fixture
def sandbox(resolver):
    base = tempfile.mkdtemp(prefix="wazuh-resolver-tests.", dir="/root")
    os.chmod(base, 0o700)
    try:
        yield Sandbox(resolver, base)
    finally:
        shutil.rmtree(base, ignore_errors=True)
