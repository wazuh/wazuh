# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The dashboard's client pair in export/: issued by the manager's CA on a master, for the dashboard to import later.
The resolver keeps, reissues and removes only the pair its marker accounts for; an operator's is validated and never
written. Nothing about it refuses a start: client certificates are not required anywhere yet."""

import datetime
import hashlib
import io
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from conftest import pool_key

IDX = {"WAZUH_INDEXER_MANAGER_PASSWORD": "Idx.Passw0rd-789"}
CERT, KEY, MARKER = "dashboard-client.pem", "dashboard-client-key.pem", ".dashboard-client.issued"


def run(resolver, sandbox, *argv):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=dict(IDX), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def export(sandbox, name):
    return os.path.join(sandbox.conf, "export", name)


def read(path):
    with open(path, "rb") as handle:
        return handle.read()


def files(sandbox):
    return {name: read(export(sandbox, name)) for name in (CERT, KEY, MARKER) if os.path.exists(export(sandbox, name))}


def manager_ca(sandbox):
    ca = os.path.join(sandbox.conf, "ca")
    cert = x509.load_pem_x509_certificate(read(os.path.join(ca, "root-ca.pem")))
    key = serialization.load_pem_private_key(read(os.path.join(ca, "root-ca.key")), None)
    return cert, key


def client_pair(issuer_cert, issuer_key, *, days=(-1, 365), eku=(ExtendedKeyUsageOID.CLIENT_AUTH,), key=None,
                cn="wazuh-dashboard"):
    """A client pair as an operator's PKI would issue it. Returns {CERT: pem (leaf then issuer), KEY: pem}."""
    key = key or pool_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .issuer_name(issuer_cert.subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now + datetime.timedelta(days=days[0]))
               .not_valid_after(now + datetime.timedelta(days=days[1]))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
    leaf = builder.sign(issuer_key, hashes.SHA256())
    pem = serialization.Encoding.PEM
    return {CERT: leaf.public_bytes(pem) + issuer_cert.public_bytes(pem),
            KEY: key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())}


def place(sandbox, pair, marker=None):
    """Put a pair in export/ (created root:root 0700 when absent) with the modes the resolver uses, and optionally a
    marker."""
    directory = os.path.join(sandbox.conf, "export")
    if not os.path.isdir(directory):
        os.mkdir(directory)
        os.chown(directory, 0, 0)
        os.chmod(directory, 0o700)
    for name, mode in ((CERT, 0o644), (KEY, 0o600)):
        if name in pair:
            sandbox.write(export(sandbox, name), pair[name], mode=mode)
    if marker is not None:
        sandbox.write(export(sandbox, MARKER), marker, mode=0o600)


def leaf_of(data):
    return x509.load_pem_x509_certificates(data)[0]


def installed(resolver, sandbox):
    code, out, err = run(resolver, sandbox, "--install")
    assert (code, err) == (0, ""), err
    return out


# ---------------------------------------------------------------- issuing and keeping

def test_install_issues_the_pair(resolver, sandbox):
    out = installed(resolver, sandbox)
    assert f"{export(sandbox, CERT)}: issued; DN " in out and "CN=wazuh-dashboard" in out
    for name, mode in ((CERT, 0o644), (KEY, 0o600), (MARKER, 0o600)):
        st = os.lstat(export(sandbox, name))
        assert (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (0, 0, mode), name
    ca_cert, ca_key = manager_ca(sandbox)
    leaf = leaf_of(read(export(sandbox, CERT)))
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "wazuh-dashboard"
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == \
        [ExtendedKeyUsageOID.CLIENT_AUTH]
    with pytest.raises(x509.ExtensionNotFound):
        leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    leaf.verify_directly_issued_by(ca_cert)
    spki = lambda public: public.public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    apid = leaf_of(read(os.path.join(sandbox.certs, "apid.pem")))
    assert spki(leaf.public_key()) not in (spki(ca_key.public_key()), spki(apid.public_key()))
    marker = read(export(sandbox, MARKER)).decode()
    for name in (KEY, CERT):
        assert f"{name} {hashlib.sha256(read(export(sandbox, name))).hexdigest()} -" in marker


@pytest.mark.parametrize("mode", ["--prestart", "--upgrade"])
def test_issued_when_absent_then_kept(resolver, sandbox, mode):
    """An upgraded manager gets one too; a valid own pair is kept byte for byte."""
    sandbox.stage_ca()
    code, out, err = run(resolver, sandbox, mode)
    assert (code, err) == (0, "") and f"{export(sandbox, CERT)}: issued" in out
    first = files(sandbox)
    code, out, err = run(resolver, sandbox, mode)
    assert (code, err) == (0, "") and f"{export(sandbox, CERT)}: kept" in out
    assert files(sandbox) == first


def test_worker_issues_nothing(resolver, sandbox):
    sandbox.control(role="worker")
    code, out, err = run(resolver, sandbox, "--install")
    assert code == 0 and not os.path.exists(export(sandbox, CERT))
    assert "dashboard" not in out + err


def test_unreadable_configuration_issues_nothing(resolver, sandbox):
    sandbox.stage_ca()
    sandbox.control(dump_exit=1)
    run(resolver, sandbox, "--prestart")
    assert not os.path.exists(export(sandbox, CERT))


@pytest.mark.parametrize("mode", ["--check", "--prestart"])
def test_no_ca_key_says_it_was_not_generated(resolver, sandbox, mode):
    """The same diagnosis in both: --check says it as --prestart does."""
    sandbox.stage_ca(key=False)
    place(sandbox, {})                                     # export/ exists, as after any earlier run
    code, _, err = run(resolver, sandbox, mode)
    assert code == 0, err
    assert (f"WARNING: dashboard client pair not generated: {sandbox.conf}/ca has no key; provision it externally "
            f"in {sandbox.conf}/export") in err
    assert not os.path.exists(export(sandbox, CERT))


def test_prestart_validates_what_it_wrote(resolver, sandbox, monkeypatch):
    """After its steps, --prestart judges the result as --check would: a key the step left readable by the group is
    refused, and the start with it."""
    sandbox.stage_ca()
    real = resolver.write_file

    def lax(parent, name, data, mode, uid, gid):
        return real(parent, name, data, 0o640 if name == KEY else mode, uid, gid)

    monkeypatch.setattr(resolver, "write_file", lax)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and f"UNSAFE {export(sandbox, KEY)}: readable by others than root" in err, err


# ---------------------------------------------------------------- rotation and expiry

def test_reissued_when_the_ca_changes(resolver, sandbox):
    installed(resolver, sandbox)
    old = files(sandbox)
    ca = os.path.join(sandbox.conf, "ca")
    for name in os.listdir(ca):
        os.unlink(os.path.join(ca, name))
    for name in ("root-ca.pem", "remoted.pem", "remoted-key.pem", "apid.pem", "apid-key.pem"):
        os.unlink(os.path.join(sandbox.certs, name))
    sandbox.stage_ca()                                    # another CA, staged by hand
    code, out, err = run(resolver, sandbox, "--prestart")
    assert (code, err) == (0, ""), err
    assert f"{export(sandbox, CERT)}: reissued (not issued by the manager's CA" in out
    assert "the dashboard must import it again" in out
    leaf_of(read(export(sandbox, CERT))).verify_directly_issued_by(manager_ca(sandbox)[0])
    assert files(sandbox)[CERT] != old[CERT]


def test_expired_own_pair_is_reissued(resolver, sandbox, ):
    installed(resolver, sandbox)
    expired = client_pair(*manager_ca(sandbox), days=(-60, -1))
    place(sandbox, expired, resolver._marker_bytes(expired, {}))
    code, out, err = run(resolver, sandbox, "--prestart")
    assert (code, err) == (0, "") and f"{export(sandbox, CERT)}: reissued (expired on " in out
    assert leaf_of(read(export(sandbox, CERT))).not_valid_after_utc > datetime.datetime.now(datetime.timezone.utc)


@pytest.mark.parametrize("stop_before", [KEY, CERT])
@pytest.mark.parametrize("when", ["first issue", "reissue"])
def test_interrupted_write_is_finished(resolver, sandbox, monkeypatch, stop_before, when):
    """Every file is replaced atomically and the marker comes first, so a write that stops halfway is finished by
    the next run, never mistaken for an operator's pair."""
    if when == "reissue":
        installed(resolver, sandbox)
        expired = client_pair(*manager_ca(sandbox), days=(-60, -1))
        place(sandbox, expired, resolver._marker_bytes(expired, {}))
        mode = "--prestart"
    else:
        sandbox.stage_ca()
        mode = "--prestart"
    real = resolver.write_file

    def stop(parent, name, *args, **kwargs):
        if name == stop_before:
            raise RuntimeError("interrupted")
        return real(parent, name, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(resolver, "write_file", stop)
        assert run(resolver, sandbox, mode)[0] == 2
    code, out, err = run(resolver, sandbox, "--prestart")
    assert (code, err) == (0, ""), err
    assert "provided by the operator" not in out
    marker = read(export(sandbox, MARKER)).decode()
    for name in (KEY, CERT):
        assert f"{name} {hashlib.sha256(read(export(sandbox, name))).hexdigest()} " in marker
    assert run(resolver, sandbox, "--prestart")[1].count(f"{export(sandbox, CERT)}: kept") == 1


# ---------------------------------------------------------------- the operator's pair

def test_operator_pair_is_kept(resolver, sandbox):
    sandbox.stage_ca()
    pair = client_pair(*manager_ca(sandbox))
    place(sandbox, pair)
    for mode in ("--check", "--prestart", "--upgrade"):
        code, out, err = run(resolver, sandbox, mode)
        assert (code, err) == (0, ""), (mode, err)
    assert f"{export(sandbox, CERT)}: provided by the operator; kept as it is" in out
    assert files(sandbox) == {CERT: pair[CERT], KEY: pair[KEY]}


def test_changed_own_pair_becomes_the_operators(resolver, sandbox):
    """A pair whose content no longer matches the marker was replaced by hand: never reissued, kept by --clear."""
    installed(resolver, sandbox)
    mine = client_pair(*manager_ca(sandbox))
    place(sandbox, mine)                                   # the resolver's marker stays
    code, out, err = run(resolver, sandbox, "--prestart")
    assert (code, err) == (0, "") and "provided by the operator; kept as it is" in out
    assert {CERT: read(export(sandbox, CERT)), KEY: read(export(sandbox, KEY))} == mine
    code, out, _ = run(resolver, sandbox, "--clear")
    assert code == 0 and f"kept {export(sandbox, CERT)} (provided by the operator)" in out
    assert files(sandbox) == mine                          # the stale marker is gone, the pair stays


@pytest.mark.parametrize("case,reason", [
    ("expired", "expired on "),
    ("wrong issuer", "not issued by the manager's CA"),
    ("no clientAuth", "has no extendedKeyUsage with clientAuth"),
    ("ca key", "its key is the manager CA's key"),
    ("apid key", "its key is the Server API's key (apid-key.pem)"),
    ("key mismatch", "its key does not match it"),
    ("half pair", f"half a pair ({CERT} is missing)"),
])
def test_operator_pair_defects_only_warn(resolver, sandbox, case, reason):
    sandbox.stage_ca()
    ca_cert, ca_key = manager_ca(sandbox)
    if case == "expired":
        pair = client_pair(ca_cert, ca_key, days=(-60, -1))
    elif case == "wrong issuer":
        from conftest import intermediate
        pair = client_pair(*intermediate(None, None, "someone-else"))
    elif case == "no clientAuth":
        pair = client_pair(ca_cert, ca_key, eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
    elif case == "ca key":
        pair = client_pair(ca_cert, ca_key, key=ca_key)
    elif case == "apid key":
        apid_key = serialization.load_pem_private_key(read(os.path.join(sandbox.certs, "apid-key.pem")), None)
        pair = client_pair(ca_cert, ca_key, key=apid_key)
    elif case == "key mismatch":
        pair = client_pair(ca_cert, ca_key)
        pair[KEY] = client_pair(ca_cert, ca_key)[KEY]
    else:
        pair = {KEY: client_pair(ca_cert, ca_key)[KEY]}
    place(sandbox, pair)
    before = files(sandbox)
    for mode in ("--check", "--prestart"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 0 and f"WARNING: {export(sandbox, CERT)}: {reason}" in err, (mode, err)
        assert "provided by the operator, kept as it is" in err
    assert files(sandbox) == before


# ---------------------------------------------------------------- unsafe entries

@pytest.mark.parametrize("case", ["key readable by the group", "certificate owned by the account", "key a symlink",
                                  "marker readable by others"])
def test_unsafe_entries_stop_writes(resolver, sandbox, case):
    installed(resolver, sandbox)
    target = {"key readable by the group": KEY, "certificate owned by the account": CERT, "key a symlink": KEY,
              "marker readable by others": MARKER}[case]
    path = export(sandbox, target)
    if case == "key readable by the group":
        os.chmod(path, 0o640)
    elif case == "certificate owned by the account":
        os.chown(path, sandbox.account_uid, sandbox.account_gid)
    elif case == "key a symlink":
        os.unlink(path)
        os.symlink(os.path.join(sandbox.conf, "ca", "root-ca.key"), path)
    else:
        os.chmod(path, 0o644)
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and f"UNSAFE {path}: " in err, err
    run(resolver, sandbox, "--prestart")
    assert {k: v for k, v in sandbox.tree_state().items() if k.startswith("conf/export")} == \
        {k: v for k, v in before.items() if k.startswith("conf/export")}


def test_ca_dir_holding_the_pair_is_a_swap(resolver, sandbox):
    installed(resolver, sandbox)
    sandbox.write(os.path.join(sandbox.conf, "ca", CERT), read(export(sandbox, CERT)), mode=0o644)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and f"UNSAFE {sandbox.conf}/ca: holds {CERT}, which belongs in export/" in err, err
