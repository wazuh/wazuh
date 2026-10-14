# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The manager's own CA: its states (minted, staged with its key, staged without it), minting only when nothing
else is there, the profile, export/ca.pem, and certs/root-ca.pem created when absent and kept byte for byte
otherwise."""

import datetime
import hashlib
import io
import os
import shutil
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

IDX = {"WAZUH_INDEXER_MANAGER_PASSWORD": "Idx.Passw0rd-789"}
PUBLICATION_BLOCK = (b"##\n## Wazuh CA bundle\n##\n## Publication: 1789840456\n## Content-SHA256: " + b"0" * 64 +
                     b"\n## Updated: 2026-09-19T17:54:16Z\n## Written by: wazuh-manager-certs 5.0.0\n##\n")


def run(resolver, sandbox, *argv, environ=None):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=dict(IDX, **(environ or {})), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def ca_path(sandbox, name):
    return os.path.join(sandbox.conf, "ca", name)


def load(path):
    return x509.load_pem_x509_certificate(open(path, "rb").read())


def mode_owner(path):
    st = os.lstat(path)
    return stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid


def make_cert(subject_cn, issuer_key=None, issuer_cn=None, ca=True, days=(-1, 3650), key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or subject_cn)]))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now + datetime.timedelta(days=days[0]))
               .not_valid_after(now + datetime.timedelta(days=days[1]))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return key, cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key, password=None):
    encryption = (serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


def stage(sandbox, cert=None, key=None, key_mode=0o400, cert_mode=0o644):
    os.makedirs(os.path.join(sandbox.conf, "ca"), mode=0o700, exist_ok=True)
    if cert is not None:
        sandbox.write(ca_path(sandbox, "root-ca.pem"), cert, mode=cert_mode)
    if key is not None:
        sandbox.write(ca_path(sandbox, "root-ca.key"), key, mode=key_mode)


# ---------------------------------------------------------------- minting

def test_mint_fresh(resolver, sandbox):
    code, out, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == "", err
    assert mode_owner(ca_path(sandbox, "root-ca.key")) == (0o400, 0, 0)
    assert mode_owner(ca_path(sandbox, "root-ca.pem")) == (0o644, 0, 0)
    assert mode_owner(ca_path(sandbox, ".wazuh-manager-bootstrap-ca")) == (0o600, 0, 0)
    cert = open(ca_path(sandbox, "root-ca.pem"), "rb").read()
    export = os.path.join(sandbox.conf, "export", "ca.pem")
    assert open(export, "rb").read() == cert and mode_owner(export) == (0o644, 0, 0)
    bundle = os.path.join(sandbox.certs, "root-ca.pem")
    assert open(bundle, "rb").read() == cert and mode_owner(bundle) == (0o640, 0, sandbox.account_gid)
    assert "minted" in out and b"PRIVATE KEY" not in (out + err).encode()


def test_mint_profile(resolver, sandbox, monkeypatch):
    monkeypatch.setattr(resolver.socket, "gethostname", lambda: "mgr01.example.com")
    run(resolver, sandbox, "--install")
    cert = load(ca_path(sandbox, "root-ca.pem"))
    assert [(a.oid, a.value) for a in cert.subject] == [
        (NameOID.COUNTRY_NAME, "US"), (NameOID.LOCALITY_NAME, "California"), (NameOID.ORGANIZATION_NAME, "Wazuh"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "Wazuh"), (NameOID.COMMON_NAME, "wazuh-manager-mgr01")]
    assert cert.issuer == cert.subject
    assert cert.public_key().key_size == 2048 and cert.public_key().public_numbers().e == 65537
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)
    now = datetime.datetime.now(datetime.timezone.utc)
    assert abs((now - cert.not_valid_before_utc) - datetime.timedelta(days=1)) < datetime.timedelta(minutes=5)
    assert abs((cert.not_valid_after_utc - now) - datetime.timedelta(days=3650)) < datetime.timedelta(minutes=5)
    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.critical and bc.value.ca
    ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    assert ku.critical and ku.value.key_cert_sign and ku.value.crl_sign and not ku.value.digital_signature
    ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
    aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
    assert aki.key_identifier == ski.digest and aki.authority_cert_issuer is None
    key = serialization.load_pem_private_key(open(ca_path(sandbox, "root-ca.key"), "rb").read(), password=None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()


@pytest.mark.parametrize("name", ["remoted.pem", "remoted-key.pem", "apid.pem", "apid-key.pem", "root-ca.pem"])
def test_mint_refused_beside_material(resolver, sandbox, name):
    """No CA is minted beside existing manager material: nothing would chain to it."""
    sandbox.write(os.path.join(sandbox.certs, name), b"staged\n", mode=0o640, gid=sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0
    assert f"MISSING {ca_path(sandbox, 'root-ca.pem')}: stage the CA that issued the pairs" in err
    assert os.listdir(os.path.join(sandbox.conf, "ca")) == []


def test_save_files_ignored(resolver, sandbox):
    """apt remove / rpm -e rename the old key to *.save: it is not a CA, a reinstall mints a new one."""
    stage(sandbox)
    sandbox.write(ca_path(sandbox, "root-ca.key.save"), b"old key\n", mode=0o400)
    assert run(resolver, sandbox, "--install")[0] == 0
    assert os.path.exists(ca_path(sandbox, ".wazuh-manager-bootstrap-ca"))


def test_install_idempotent(resolver, sandbox):
    run(resolver, sandbox, "--install")
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == ""
    assert sandbox.tree_state() == before



def test_minted_label(resolver, sandbox):
    """After the run that minted it, the CA is reported as this host's, which --clear removes, never as staged."""
    code, out, _ = run(resolver, sandbox, "--install")
    assert code == 0 and ": minted" in out
    for mode in ("--prestart", "--upgrade", "--install"):
        code, out, err = run(resolver, sandbox, mode)
        assert code == 0 and ": minted earlier" in out and ": staged" not in out, (mode, out, err)


# ---------------------------------------------------------------- staged CAs

def test_staged_signing(resolver, sandbox):
    key, cert = make_cert("operator-ca")
    stage(sandbox, cert, key_pem(key))
    code, out, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == "" and "CN=operator-ca: staged" in out
    assert not os.path.exists(ca_path(sandbox, ".wazuh-manager-bootstrap-ca"))
    assert open(os.path.join(sandbox.conf, "export", "ca.pem"), "rb").read() == cert
    assert open(os.path.join(sandbox.certs, "root-ca.pem"), "rb").read() == cert


def test_staged_anchor_only(resolver, sandbox):
    """A certificate without its key is a valid CA (an external PKI); it just cannot issue."""
    _, cert = make_cert("external-ca")
    stage(sandbox, cert)
    code, out, err = run(resolver, sandbox, "--install")
    assert code == 0 and "staged without its key" in out
    assert open(os.path.join(sandbox.certs, "root-ca.pem"), "rb").read() == cert
    # It cannot issue: the pairs have to be staged (the issue's own MISSING example).
    for name in ("remoted", "apid"):
        assert (f"MISSING {sandbox.certs}/{name}.pem: no CA key to issue it; stage the pair or the CA in "
                f"{sandbox.conf}/ca\n") in err


def test_key_only(resolver, sandbox):
    key, _ = make_cert("x")
    stage(sandbox, key=key_pem(key))
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and f"INVALID {ca_path(sandbox, 'root-ca.key')}: no certificate beside it" in err
    assert not os.path.exists(os.path.join(sandbox.certs, "root-ca.pem"))
    assert run(resolver, sandbox, "--prestart")[0] == 1


def _foreign_issuer():
    issuer_key, _ = make_cert("issuer")
    return make_cert("leaf-as-ca", issuer_key=issuer_key, issuer_cn="issuer")


@pytest.mark.parametrize("case,reason", [
    ("not self-signed", "not self-signed"), ("ca false", "not a CA certificate"), ("expired", "expired"),
    ("two certs", "holds 2 certificates"), ("key mismatch", "does not match"), ("encrypted key", "encrypted"),
    ("garbage cert", "not a PEM certificate"), ("garbage key", "not a PEM private key"),
])
def test_invalid_ca(resolver, sandbox, case, reason):
    key, cert = make_cert("ca")
    key_bytes = key_pem(key)
    if case == "not self-signed":
        key, cert = _foreign_issuer()
        key_bytes = key_pem(key)
    elif case == "ca false":
        key, cert = make_cert("ca", ca=False)
        key_bytes = key_pem(key)
    elif case == "expired":
        key, cert = make_cert("ca", days=(-3000, -1))
        key_bytes = key_pem(key)
    elif case == "two certs":
        cert = cert + make_cert("other")[1]
    elif case == "key mismatch":
        key_bytes = key_pem(make_cert("other")[0])
    elif case == "encrypted key":
        key_bytes = key_pem(key, password=b"Pa55word")
    elif case == "garbage cert":
        cert = b"not a certificate\n"
    else:
        key_bytes = b"not a key\n"
    stage(sandbox, cert, key_bytes)
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and err.startswith("INVALID ") and reason in err
    assert not os.path.exists(os.path.join(sandbox.certs, "root-ca.pem"))
    assert not os.path.exists(os.path.join(sandbox.conf, "export", "ca.pem"))


@pytest.mark.parametrize("case,reason", [("key 0440", "readable by others"), ("cert 0664", "group-writable"),
                                         ("ca dir 0750", "mode is 0750")])
def test_unsafe_ca(resolver, sandbox, case, reason):
    key, cert = make_cert("ca")
    stage(sandbox, cert, key_pem(key), key_mode=0o440 if case == "key 0440" else 0o400,
          cert_mode=0o664 if case == "cert 0664" else 0o644)
    if case == "ca dir 0750":
        os.chmod(os.path.join(sandbox.conf, "ca"), 0o750)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and "UNSAFE " in err and reason in err


# ---------------------------------------------------------------- certs/root-ca.pem: created when absent, never rewritten

def test_bundle_kept(resolver, sandbox):
    """A bundle wazuh-manager-certs stamped, with a rotation CA, survives every mode byte for byte."""
    own = sandbox.stage_ca(bundle=False)
    bundle = os.path.join(sandbox.certs, "root-ca.pem")
    sandbox.write(bundle, PUBLICATION_BLOCK + own + make_cert("rotation-ca")[1], mode=0o640, gid=sandbox.account_gid)
    digest = hashlib.sha256(open(bundle, "rb").read()).hexdigest()
    for mode in ("--install", "--upgrade", "--prestart", "--check"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 0 and err == "", (mode, err)
        assert hashlib.sha256(open(bundle, "rb").read()).hexdigest() == digest


def test_bundle_foreign(resolver, sandbox):
    sandbox.stage_ca(bundle=False)
    bundle = os.path.join(sandbox.certs, "root-ca.pem")
    foreign = make_cert("someone-else")[1]
    sandbox.write(bundle, foreign, mode=0o640, gid=sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1
    assert f"INVALID {bundle}: does not contain {ca_path(sandbox, 'root-ca.pem')}" in err
    assert open(bundle, "rb").read() == foreign


@pytest.mark.parametrize("mode,expected", [("--upgrade", 0), ("--prestart", 1)])
def test_upgrade_prestart_never_mint(resolver, sandbox, mode, expected):
    code, _, err = run(resolver, sandbox, mode)
    assert code == expected and f"MISSING {ca_path(sandbox, 'root-ca.pem')}: " in err
    assert os.listdir(os.path.join(sandbox.conf, "ca")) == []


def test_prestart_missing_bundle(resolver, sandbox):
    sandbox.stage_ca(bundle=False)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and f"MISSING {sandbox.certs}/root-ca.pem: " in err
    assert not os.path.exists(os.path.join(sandbox.certs, "root-ca.pem"))


# ---------------------------------------------------------------- --check (read-only, never MISSING), certs/, node name

def test_check_ca(resolver, sandbox):
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 0 and "MISSING" not in err and sandbox.tree_state() == before
    assert not os.path.exists(os.path.join(sandbox.conf, "ca"))
    _, cert = make_cert("ca", ca=False)
    stage(sandbox, cert)
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and "not a CA certificate" in err and sandbox.tree_state() == before


def test_check_foreign_bundle(resolver, sandbox):
    sandbox.stage_ca(bundle=False)
    sandbox.write(os.path.join(sandbox.certs, "root-ca.pem"), make_cert("x")[1], mode=0o640, gid=sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and "does not contain" in err


@pytest.mark.parametrize("case,expected", [("absent", "INVALID"), ("account-owned", "UNSAFE"),
                                           ("group-writable", "UNSAFE")])
def test_certs_dir(resolver, sandbox, case, expected):
    if case == "absent":
        os.rmdir(sandbox.certs)
    elif case == "account-owned":
        os.chown(sandbox.certs, sandbox.account_uid, sandbox.account_gid)
    else:
        os.chmod(sandbox.certs, 0o770)
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and f"{expected} {sandbox.certs}: " in err
    assert not os.path.exists(ca_path(sandbox, "root-ca.pem"))


@pytest.mark.parametrize("source,expected_cn", [("env", "envnode"), ("local.env", "localnode"),
                                                ("host", "hostnode")])
def test_node_name(resolver, sandbox, monkeypatch, source, expected_cn):
    monkeypatch.setattr(resolver.socket, "gethostname", lambda: "hostnode.example.com")
    environ = {"WAZUH_MANAGER_NODE_NAME": "envnode"} if source == "env" else {}
    if source == "local.env":
        sandbox.write(os.path.join(sandbox.conf, "local.env"), "WAZUH_MANAGER_NODE_NAME=localnode\n")
    run(resolver, sandbox, "--install", environ=environ)
    cn = load(ca_path(sandbox, "root-ca.pem")).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "wazuh-manager-" + expected_cn


@pytest.mark.parametrize("name", ["bad_name", "-lead", "a" * 64, "x..y"])
def test_node_name_invalid(resolver, sandbox, name):
    code, _, err = run(resolver, sandbox, "--install", environ={"WAZUH_MANAGER_NODE_NAME": name})
    assert code == 0 and "INVALID WAZUH_MANAGER_NODE_NAME: " in err
    assert os.listdir(os.path.join(sandbox.conf, "ca")) == []


def test_node_name_too_long_for_cn(resolver, sandbox):
    name = "a" * 63                       # a valid label, but wazuh-manager-<name> exceeds 64 characters
    code, _, err = run(resolver, sandbox, "--install", environ={"WAZUH_MANAGER_NODE_NAME": name})
    assert "too long for the CA's common name" in err


# ---------------------------------------------------------------- the service account hides ca/

def test_ca_hidden_nothing_else(resolver, sandbox):
    """Hiding ca/ before a fresh install gets a new CA minted: nothing else is there to protect, nothing leaks."""
    run(resolver, sandbox, "--install")
    first = open(ca_path(sandbox, "root-ca.pem"), "rb").read()
    shutil.rmtree(os.path.join(sandbox.conf, "ca"))
    for name in ("root-ca.pem", "remoted.pem", "remoted-key.pem", "apid.pem", "apid-key.pem"):
        os.unlink(os.path.join(sandbox.certs, name))
    run(resolver, sandbox, "--install")
    assert open(ca_path(sandbox, "root-ca.pem"), "rb").read() != first


def test_ca_hidden_with_material(resolver, sandbox):
    """With the bundle (or pairs) present, a hidden ca/ is never replaced by a new CA."""
    run(resolver, sandbox, "--install")
    os.rename(os.path.join(sandbox.conf, "ca"), os.path.join(sandbox.conf, "ca.hidden"))
    code, _, err = run(resolver, sandbox, "--install")
    assert "stage the CA that issued the pairs" in err
    assert os.listdir(os.path.join(sandbox.conf, "ca")) == []
