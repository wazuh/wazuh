# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The two server pairs, remoted and apid: issued with one profile (the shell resolver's _wmc_generate_server_pair,
wazuh/wazuh#40085), kept when usable, never repaired, and refused when half or broken."""

import datetime
import hashlib
import io
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from conftest import intermediate, pool_key, unparsable_certificate

IDX = {"WAZUH_INDEXER_MANAGER_PASSWORD": "Idx.Passw0rd-789"}
PAIRS = ("remoted", "apid")


def run(resolver, sandbox, *argv, environ=None):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=dict(IDX, **(environ or {})), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def cert_of(sandbox, name):
    return x509.load_pem_x509_certificates(open(os.path.join(sandbox.certs, f"{name}.pem"), "rb").read())


def digest(sandbox, name):
    return hashlib.sha256(open(os.path.join(sandbox.certs, name), "rb").read()).hexdigest()


def ca_cert(sandbox):
    return x509.load_pem_x509_certificate(open(os.path.join(sandbox.conf, "ca", "root-ca.pem"), "rb").read())


def ca_key(sandbox):
    return serialization.load_pem_private_key(open(os.path.join(sandbox.conf, "ca", "root-ca.key"), "rb").read(), None)


# ---------------------------------------------------------------- issuing

@pytest.mark.parametrize("name", PAIRS)
def test_profile_parity(resolver, sandbox, name):
    """Every attribute of the shell's server profile, item by item."""
    run(resolver, sandbox, "--install")
    raw = open(os.path.join(sandbox.certs, f"{name}.pem"), "rb").read()
    leaf, ca = x509.load_pem_x509_certificates(raw)
    ca_file = open(os.path.join(sandbox.conf, "ca", "root-ca.pem"), "rb").read()
    assert raw == leaf.public_bytes(serialization.Encoding.PEM) + b"\n" + ca_file      # leaf, blank line, CA file
    assert ca == ca_cert(sandbox)
    key = serialization.load_pem_private_key(open(os.path.join(sandbox.certs, f"{name}-key.pem"), "rb").read(), None)
    assert b"BEGIN PRIVATE KEY" in open(os.path.join(sandbox.certs, f"{name}-key.pem"), "rb").read()   # PKCS#8
    assert key.key_size == 2048 and key.public_key().public_numbers() == leaf.public_key().public_numbers()
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA256) and leaf.version == x509.Version.v3
    assert [(a.oid, a.value) for a in leaf.subject] == [
        (NameOID.COUNTRY_NAME, "US"), (NameOID.LOCALITY_NAME, "California"), (NameOID.ORGANIZATION_NAME, "Wazuh"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "Wazuh"), (NameOID.COMMON_NAME, "node1")]
    assert leaf.issuer == ca.subject
    leaf.verify_directly_issued_by(ca)
    now = datetime.datetime.now(datetime.timezone.utc)
    assert abs((now - leaf.not_valid_before_utc) - datetime.timedelta(days=1)) < datetime.timedelta(minutes=5)
    assert abs((leaf.not_valid_after_utc - now) - datetime.timedelta(days=3650)) < datetime.timedelta(minutes=5)
    ext = leaf.extensions
    assert [e.oid for e in ext] == [ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                                    ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
                                    ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME]
    aki = ext.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
    assert aki.authority_cert_issuer is None
    assert aki.key_identifier == ca.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
    bc = ext.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.critical and bc.value.ca is False
    ku = ext.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    assert ku.critical and ku.value.digital_signature and ku.value.key_encipherment and not ku.value.key_cert_sign
    eku = ext.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    assert not eku.critical and list(eku.value) == [ExtendedKeyUsageOID.SERVER_AUTH]
    san = ext.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    assert not san.critical


def test_issue_both(resolver, sandbox):
    code, out, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == "", err
    for name in PAIRS:
        for filename in (f"{name}.pem", f"{name}-key.pem"):
            st = os.lstat(os.path.join(sandbox.certs, filename))
            assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (0o640, 0, sandbox.account_gid)
        assert f"{sandbox.certs}/{name}.pem: issued; DN CN=node1,OU=Wazuh,O=Wazuh,L=California,C=US; SANs " in out
    assert b"PRIVATE KEY" not in (out + err).encode()


def test_keep_usable(resolver, sandbox):
    run(resolver, sandbox, "--install")
    before = {n: digest(sandbox, n) for n in os.listdir(sandbox.certs)}
    code, out, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == ""
    assert {n: digest(sandbox, n) for n in os.listdir(sandbox.certs)} == before
    assert f"{sandbox.certs}/remoted.pem: kept; DN " in out and f"{sandbox.certs}/apid.pem: kept; DN " in out


@pytest.mark.parametrize("name", PAIRS)
@pytest.mark.parametrize("missing", ["cert", "key"])
def test_half_pair(resolver, sandbox, name, missing):
    sandbox.stage_ca()
    gone = f"{name}.pem" if missing == "cert" else f"{name}-key.pem"
    present = f"{name}-key.pem" if missing == "cert" else f"{name}.pem"
    os.unlink(os.path.join(sandbox.certs, gone))
    keep = digest(sandbox, present)
    code, _, err = run(resolver, sandbox, "--install")
    assert f"INVALID {sandbox.certs}/{present}: half a pair ({gone} is missing)" in err
    assert not os.path.exists(os.path.join(sandbox.certs, gone)) and digest(sandbox, present) == keep
    assert run(resolver, sandbox, "--prestart")[0] == 1


def _replace_remoted(sandbox, days=(-1, 30), issuer_name=None, sign_with=None, ca_bytes=None, drop=(), **ext):
    """Stage a remoted pair built here: the issuer, the validity window and the extensions can be changed one by
    one (`drop` removes an extension, a keyword replaces one: bc, eku, san)."""
    ca, signer = ca_cert(sandbox), ca_key(sandbox)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node1")]))
               .issuer_name(issuer_name or ca.subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now + datetime.timedelta(days=days[0]))
               .not_valid_after(now + datetime.timedelta(days=days[1])))
    extensions = {"bc": x509.BasicConstraints(ca=False, path_length=None),
                  "eku": x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                  "san": x509.SubjectAlternativeName([x509.DNSName("node1")])}
    extensions.update(ext)
    for name, value in extensions.items():
        if name not in drop:
            builder = builder.add_extension(value, critical=name == "bc")
    leaf = builder.sign(sign_with or signer, hashes.SHA256())
    pem = leaf.public_bytes(serialization.Encoding.PEM) + b"\n" + (ca_bytes or ca.public_bytes(serialization.Encoding.PEM))
    sandbox.write(os.path.join(sandbox.certs, "remoted.pem"), pem, mode=0o640, gid=sandbox.account_gid)
    sandbox.write(os.path.join(sandbox.certs, "remoted-key.pem"),
                  key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()), mode=0o640, gid=sandbox.account_gid)


@pytest.mark.parametrize("case,reason", [
    ("expired", "expired"),
    ("foreign chain", "not issued by the manager's CA"),
    ("key mismatch", "its key remoted-key.pem does not match it"),
    ("ca leaf", "a CA certificate, not a server certificate"),
    ("client only", "its extendedKeyUsage does not include serverAuth"),
    ("no san", "has no subjectAltName"),
    ("no basic constraints", "needs an explicit basicConstraints CA:FALSE"),
])
def test_invalid_kept(resolver, sandbox, case, reason):
    sandbox.stage_ca()
    if case == "expired":
        _replace_remoted(sandbox, days=(-60, -1))
    elif case == "foreign chain":
        _replace_remoted(sandbox, sign_with=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    elif case == "key mismatch":
        _replace_remoted(sandbox)
        apid_key = open(os.path.join(sandbox.certs, "apid-key.pem"), "rb").read()
        sandbox.write(os.path.join(sandbox.certs, "remoted-key.pem"), apid_key, mode=0o640, gid=sandbox.account_gid)
    elif case == "ca leaf":
        _replace_remoted(sandbox, bc=x509.BasicConstraints(ca=True, path_length=None))
    elif case == "client only":
        _replace_remoted(sandbox, eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]))
    elif case == "no san":
        _replace_remoted(sandbox, drop=("san",))
    else:
        _replace_remoted(sandbox, drop=("bc",))
    keep = digest(sandbox, "remoted.pem")
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and f"INVALID {sandbox.certs}/remoted.pem: {reason}" in err
    assert digest(sandbox, "remoted.pem") == keep


@pytest.mark.parametrize("case,expected", [("mode 0644", "UNSAFE"), ("account-owned", "UNSAFE")])
def test_unsafe_kept(resolver, sandbox, case, expected):
    sandbox.stage_ca()
    path = os.path.join(sandbox.certs, "apid-key.pem")
    if case == "mode 0644":
        os.chmod(path, 0o644)
    else:
        os.chown(path, sandbox.account_uid, sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and f"{expected} {path}: " in err


def test_eku_absent_is_accepted(resolver, sandbox):
    """A server certificate without extendedKeyUsage is unrestricted (RFC 5280); the shell accepted it too."""
    sandbox.stage_ca()
    _replace_remoted(sandbox, drop=("eku",))
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 0, err


def test_remoted_chain_to_bundle(resolver, sandbox):
    """remoted may be issued by a rotation CA the agents' bundle carries; apid must chain to the manager's CA."""
    own = sandbox.stage_ca()
    rotation_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    rotation_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rotation-ca")])
    rotation = (x509.CertificateBuilder().subject_name(rotation_name).issuer_name(rotation_name)
                .public_key(rotation_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=90))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(rotation_key, hashes.SHA256()))
    rotation_pem = rotation.public_bytes(serialization.Encoding.PEM)
    sandbox.write(os.path.join(sandbox.certs, "root-ca.pem"), own + rotation_pem, mode=0o640, gid=sandbox.account_gid)

    _replace_remoted(sandbox, issuer_name=rotation_name, sign_with=rotation_key, ca_bytes=rotation_pem)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 0, err


def rotation_ca(key, *, days=(-1, 90), is_ca=True, key_cert_sign=True):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rotation-ca")])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + datetime.timedelta(days=days[0]))
            .not_valid_after(now + datetime.timedelta(days=days[1]))
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                        data_encipherment=False, key_agreement=False, key_cert_sign=key_cert_sign,
                                        crl_sign=key_cert_sign, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
@pytest.mark.parametrize("used", [True, False])
@pytest.mark.parametrize("options,reason", [
    ({"days": (-90, -1)}, "expired"),
    ({"days": (1, 90)}, "not valid yet"),
    ({"is_ca": False}, "not a CA certificate"),
    ({"key_cert_sign": False}, "keyUsage does not include keyCertSign"),
])
def test_rotation_issuer_must_be_usable(resolver, sandbox, mode, used, options, reason):
    """Historical entries can remain in the bundle, but cannot authorize the active server certificate."""
    assert run(resolver, sandbox, "--install")[0] == 0
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotation = rotation_ca(key, **options)
    pem = rotation.public_bytes(serialization.Encoding.PEM)
    own = ca_cert(sandbox).public_bytes(serialization.Encoding.PEM)
    sandbox.write(os.path.join(sandbox.certs, "root-ca.pem"), own + pem, mode=0o640, gid=sandbox.account_gid)
    if used:
        _replace_remoted(sandbox, issuer_name=rotation.subject, sign_with=key, ca_bytes=pem)
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, mode)
    if used:
        assert code == 1 and f"INVALID {sandbox.certs}/remoted.pem: issuer CA: {reason}" in err, err
    else:
        assert code == 0 and err == "", err
    assert sandbox.tree_state() == before


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
def test_rotation_issuer_uses_valid_candidate(resolver, sandbox, mode):
    """A renewed CA certificate can share the subject and key of a historical expired certificate."""
    assert run(resolver, sandbox, "--install")[0] == 0
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired = rotation_ca(key, days=(-90, -1)).public_bytes(serialization.Encoding.PEM)
    valid = rotation_ca(key)
    pem = valid.public_bytes(serialization.Encoding.PEM)
    own = ca_cert(sandbox).public_bytes(serialization.Encoding.PEM)
    sandbox.write(os.path.join(sandbox.certs, "root-ca.pem"), own + expired + pem,
                  mode=0o640, gid=sandbox.account_gid)
    _replace_remoted(sandbox, issuer_name=valid.subject, sign_with=key, ca_bytes=pem)
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, mode)
    assert code == 0 and err == "", err
    assert sandbox.tree_state() == before


# ---------------------------------------------------------------- intermediate CAs

PEM = serialization.Encoding.PEM


def _stage_pair(sandbox, name, issuer, issuer_key, chain=(), key=None):
    """Stage `name` as a server leaf that `issuer` signed, followed in its file by the certificates of `chain`; on
    `key` when given (otherwise an RSA key from the pool)."""
    key = key or pool_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node1")]))
            .issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("node1")]), critical=False)
            .sign(issuer_key, None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()))
    pem = b"".join(cert.public_bytes(PEM) for cert in (leaf, *chain))
    sandbox.write(os.path.join(sandbox.certs, f"{name}.pem"), pem, mode=0o640, gid=sandbox.account_gid)
    sandbox.write(os.path.join(sandbox.certs, f"{name}-key.pem"),
                  key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
                  mode=0o640, gid=sandbox.account_gid)


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
@pytest.mark.parametrize("name", PAIRS)
@pytest.mark.parametrize("with_root", [False, True])
def test_pair_through_intermediate_kept(resolver, sandbox, mode, name, with_root):
    """A pair issued by an intermediate CA is usable when its file carries the intermediate after the leaf, and
    for remoted when the agents' bundle holds it too; the file may also end with the root, as the files --install
    writes do."""
    sandbox.stage_ca()
    root, root_key = ca_cert(sandbox), ca_key(sandbox)
    middle, middle_key = intermediate(root, root_key)
    if name == "remoted":
        sandbox.write(os.path.join(sandbox.certs, "root-ca.pem"), root.public_bytes(PEM) + middle.public_bytes(PEM),
                      mode=0o640, gid=sandbox.account_gid)
    _stage_pair(sandbox, name, middle, middle_key, chain=(middle, root) if with_root else (middle,))
    before = sandbox.tree_state() if mode == "--check" else {n: digest(sandbox, n) for n in os.listdir(sandbox.certs)}
    code, out, err = run(resolver, sandbox, mode)
    assert code == 0 and err == "", err
    if mode == "--check":
        assert sandbox.tree_state() == before
    else:
        assert all(digest(sandbox, n) == before[n] for n in before)          # completed around, never rewritten
        assert f"{sandbox.certs}/{name}.pem: kept; DN CN=node1; SANs DNS:node1" in out


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
@pytest.mark.parametrize("case,reason", [
    ("intermediate not in the file", "not issued by the manager's CA ("),
    ("expired intermediate", "not issued by the manager's CA ("),
    ("intermediate not a CA", "not issued by the manager's CA ("),
    ("path length exceeded", "not issued by the manager's CA ("),
    ("intermediate cannot sign", "issuer CA: keyUsage does not include keyCertSign"),
    ("foreign root in the file", "not issued by the manager's CA ("),
])
def test_pair_through_intermediate_refused(resolver, sandbox, mode, case, reason):
    """The path from the leaf must reach the manager's CA through usable CAs; certificates in the pair's own file
    are only intermediates, never trusted on their own. (apid: remoted takes no intermediate from its file.)"""
    sandbox.stage_ca()
    root, root_key = ca_cert(sandbox), ca_key(sandbox)
    if case == "intermediate not in the file":
        middle, middle_key = intermediate(root, root_key)
        _stage_pair(sandbox, "apid", middle, middle_key)
    elif case == "path length exceeded":
        middle, middle_key = intermediate(root, root_key, path_length=0)
        lower, lower_key = intermediate(middle, middle_key, "lower-ca")
        _stage_pair(sandbox, "apid", lower, lower_key, chain=(lower, middle))
    elif case == "foreign root in the file":
        foreign, foreign_key = intermediate(None, None, "foreign-root-ca")
        _stage_pair(sandbox, "apid", foreign, foreign_key, chain=(foreign,))
    else:
        breaks = {"expired intermediate": {"days": (-90, -1)}, "intermediate not a CA": {"is_ca": False},
                  "intermediate cannot sign": {"key_cert_sign": False}}[case]
        middle, middle_key = intermediate(root, root_key, **breaks)
        _stage_pair(sandbox, "apid", middle, middle_key, chain=(middle,))
    before = {n: digest(sandbox, n) for n in ("apid.pem", "apid-key.pem")}
    code, _, err = run(resolver, sandbox, mode)
    assert code == 1 and f"INVALID {sandbox.certs}/apid.pem: {reason}" in err, err
    assert {n: digest(sandbox, n) for n in before} == before                    # refused, never repaired


def _ed25519_intermediate(root, root_key, cn="ed25519-intermediate-ca"):
    key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(root.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256()))
    return cert, key


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
@pytest.mark.parametrize("case,reason", [
    ("leaf key", "an Ed25519 key; use RSA of 2048 bits or more, or ECDSA on P-256, P-384 or P-521"),
    ("intermediate key", "issuer CA (CN=ed25519-intermediate-ca): an Ed25519 key; use RSA of 2048 bits or more, or "
                         "ECDSA on P-256, P-384 or P-521"),
])
def test_pair_on_an_unusable_key_type(resolver, sandbox, mode, case, reason):
    """A staged pair whose leaf, or a CA on whose path, has a key the certificate checks do not accept is refused in
    plain words, naming the certificate, not with the path builder's debug text."""
    sandbox.stage_ca()
    root, root_key = ca_cert(sandbox), ca_key(sandbox)
    if case == "leaf key":
        _stage_pair(sandbox, "apid", root, root_key, key=ed25519.Ed25519PrivateKey.generate())
    else:
        middle, middle_key = _ed25519_intermediate(root, root_key)
        _stage_pair(sandbox, "apid", middle, middle_key, chain=(middle,))
    code, _, err = run(resolver, sandbox, mode)
    assert code == 1 and f"INVALID {sandbox.certs}/apid.pem: {reason}\n" in err, err
    assert "AlgorithmIdentifier" not in err and "internal error" not in err, err


def test_bundle_ca_anchors_remoted_only(resolver, sandbox):
    """remoted may chain to any certificate of the agents' bundle, an intermediate kept there included; apid only to
    ca/root-ca.pem, the CA the dashboard is handed."""
    sandbox.stage_ca()
    root, root_key = ca_cert(sandbox), ca_key(sandbox)
    middle, middle_key = intermediate(root, root_key)
    sandbox.write(os.path.join(sandbox.certs, "root-ca.pem"), root.public_bytes(PEM) + middle.public_bytes(PEM),
                  mode=0o640, gid=sandbox.account_gid)
    for name in PAIRS:
        _stage_pair(sandbox, name, middle, middle_key)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and f"INVALID {sandbox.certs}/apid.pem: not issued by the manager's CA (" in err, err
    assert "remoted.pem" not in err


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
def test_remoted_intermediate_only_in_its_file_refused(resolver, sandbox, mode):
    """Agents are handed certs/root-ca.pem alone (GET /cacerts): a remoted leaf that chains to it only through an
    intermediate carried in remoted.pem would serve TLS while no agent could bootstrap its trust from the bundle."""
    sandbox.stage_ca()
    root, root_key = ca_cert(sandbox), ca_key(sandbox)
    middle, middle_key = intermediate(root, root_key)
    _stage_pair(sandbox, "remoted", middle, middle_key, chain=(middle, root))
    code, _, err = run(resolver, sandbox, mode)
    assert code == 1, err
    assert (f"INVALID {sandbox.certs}/remoted.pem: not issued by the manager's CA (agents are handed "
            f"{sandbox.certs}/root-ca.pem alone: an intermediate CA that issued it belongs in that file)") in err


ANY_EKU = x509.ObjectIdentifier("2.5.29.37.0")


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
@pytest.mark.parametrize("eku,accepted", [
    ([ExtendedKeyUsageOID.SERVER_AUTH], True),
    ([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH], True),
    ([ExtendedKeyUsageOID.CLIENT_AUTH], False),
    ([ANY_EKU], False),                              # OpenSSL does not take anyExtendedKeyUsage as serverAuth
])
def test_intermediate_purpose(resolver, sandbox, mode, eku, accepted):
    """A CA on the path that restricts its extended key usages must allow serverAuth."""
    sandbox.stage_ca()
    root, root_key = ca_cert(sandbox), ca_key(sandbox)
    middle, middle_key = intermediate(root, root_key, eku=eku)
    _stage_pair(sandbox, "apid", middle, middle_key, chain=(middle,))
    code, _, err = run(resolver, sandbox, mode)
    if accepted:
        assert code == 0 and err == "", err
    else:
        assert code == 1 and (f"INVALID {sandbox.certs}/apid.pem: issuer CA: its extendedKeyUsage does not include "
                              f"serverAuth") in err, err


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
def test_anchor_purpose(resolver, sandbox, mode):
    """The rule holds for the anchor too: a CA of the agents' bundle restricted to clientAuth cannot vouch for
    remoted."""
    sandbox.stage_ca()
    restricted, restricted_key = intermediate(None, None, "client-only-root-ca", eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    bundle = ca_cert(sandbox).public_bytes(PEM) + restricted.public_bytes(PEM)
    sandbox.write(os.path.join(sandbox.certs, "root-ca.pem"), bundle, mode=0o640, gid=sandbox.account_gid)
    _stage_pair(sandbox, "remoted", restricted, restricted_key)
    code, _, err = run(resolver, sandbox, mode)
    assert code == 1 and (f"INVALID {sandbox.certs}/remoted.pem: issuer CA: its extendedKeyUsage does not include "
                          f"serverAuth") in err, err


# ---------------------------------------------------------------- inputs that are verdicts, never internal errors

PARSE_ERROR = "a certificate it holds cannot be parsed"


def test_long_node_name_is_refused_before_issuance(resolver, sandbox):
    """With a CA staged by the operator, a node name over 64 characters (a valid DNS name with dots) cannot be a
    certificate's common name: nothing is issued, the variable is named, and the rest of the run still happens."""
    sandbox.make_indexer_trust()
    sandbox.stage_ca(pairs=False)
    name = "a" * 40 + "." + "b" * 40
    code, _, err = run(resolver, sandbox, "--install", environ={"WAZUH_MANAGER_NODE_NAME": name})
    assert code == 0 and "internal error" not in err, err
    assert ("INVALID WAZUH_MANAGER_NODE_NAME: too long for a certificate's common name (64 characters at most; "
            "set in the environment)") in err, err
    assert not any(os.path.exists(os.path.join(sandbox.certs, f)) for f in ("remoted.pem", "apid.pem"))
    assert os.path.exists(os.path.join(sandbox.certs, "indexer-connector.pem"))


def test_64_character_node_name_is_accepted(resolver, sandbox):
    sandbox.make_indexer_trust()
    sandbox.stage_ca(pairs=False)
    name = "a" * 31 + "." + "b" * 32
    assert len(name) == 64
    code, _, err = run(resolver, sandbox, "--install", environ={"WAZUH_MANAGER_NODE_NAME": name})
    assert code == 0 and err == "", err
    for pair in PAIRS:
        leaf = cert_of(sandbox, pair)[0]
        assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == name


@pytest.mark.parametrize("case", ["remoted leaf", "apid leaf", "apid intermediate", "remoted duplicated extension",
                                  "bundle certificate"])
def test_unparsable_certificate_is_invalid(resolver, sandbox, case):
    """A certificate whose extensions cannot be parsed is INVALID with its path, under --check and --install alike,
    and the install goes on with its other steps."""
    sandbox.make_indexer_trust()
    sandbox.stage_ca()
    root, root_key = ca_cert(sandbox), ca_key(sandbox)
    target = os.path.join(sandbox.certs, "remoted.pem")
    if case in ("remoted leaf", "remoted duplicated extension", "apid leaf"):
        name = "apid" if case == "apid leaf" else "remoted"
        target = os.path.join(sandbox.certs, f"{name}.pem")
        pem, key = unparsable_certificate(root, root_key, "node1", duplicate=case.endswith("extension"))
        sandbox.write(target, pem, mode=0o640, gid=sandbox.account_gid)
        sandbox.write(os.path.join(sandbox.certs, f"{name}-key.pem"),
                      key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
                      mode=0o640, gid=sandbox.account_gid)
    elif case == "apid intermediate":
        target = os.path.join(sandbox.certs, "apid.pem")
        bad, _ = unparsable_certificate(root, root_key, "broken-intermediate")
        sandbox.write(target, open(target, "rb").read() + bad, mode=0o640, gid=sandbox.account_gid)
    else:
        target = os.path.join(sandbox.certs, "root-ca.pem")
        bad, _ = unparsable_certificate(None, None, "broken-rotation-ca")
        sandbox.write(target, open(target, "rb").read() + bad, mode=0o640, gid=sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and f"INVALID {target}: {PARSE_ERROR} (" in err and "internal error" not in err, err
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and f"INVALID {target}: {PARSE_ERROR} (" in err and "internal error" not in err, err
    assert os.path.exists(os.path.join(sandbox.certs, "indexer-connector.pem"))      # the later step still ran


def test_anchor_only_missing(resolver, sandbox):
    sandbox.stage_ca(key=False, pairs=False)
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0
    assert f"MISSING {sandbox.certs}/remoted.pem: no CA key to issue it; stage the pair or the CA in {sandbox.conf}/ca" in err
    assert not os.path.exists(os.path.join(sandbox.certs, "remoted.pem"))


def test_anchor_only_with_staged_pairs(resolver, sandbox):
    sandbox.stage_ca(key=False)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 0, err


@pytest.mark.parametrize("mode,code_expected", [("--upgrade", 0), ("--prestart", 1)])
def test_upgrade_prestart_never_issue(resolver, sandbox, mode, code_expected):
    sandbox.stage_ca(pairs=False)
    code, _, err = run(resolver, sandbox, mode)
    assert code == code_expected
    assert f"MISSING {sandbox.certs}/apid.pem: run --install to issue it, or stage the pair" in err
    assert not os.path.exists(os.path.join(sandbox.certs, "apid.pem"))


def test_check_pairs(resolver, sandbox):
    """--check validates present pairs and explicit lists, never reports MISSING and writes nothing."""
    sandbox.stage_ca(pairs=False)
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 0 and "MISSING" not in err and sandbox.tree_state() == before
    run(resolver, sandbox, "--install")
    _replace_remoted(sandbox, days=(-60, -1))
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and f"INVALID {sandbox.certs}/remoted.pem: expired" in err and sandbox.tree_state() == before
    code, _, err = run(resolver, sandbox, "--check", environ={"WAZUH_MANAGER_APID_CERT_SANS": "DNS:bad_name"})
    assert "INVALID WAZUH_MANAGER_APID_CERT_SANS: DNS:bad_name: not a valid DNS name" in err
