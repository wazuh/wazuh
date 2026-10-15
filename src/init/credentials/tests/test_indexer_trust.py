# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Trust in the indexer: certs/indexer-ca.pem and the client pair the indexer issues for this manager.

Files staged by the operator (no import marker) are validated and never touched. Absent ones are imported from the
indexer's export/ on this host, the marker written first; imported ones are imported again when the indexer's files
change. The client pair must be issued by the indexer's CA and carry clientAuth.
"""

import hashlib
import io
import os
import shutil
import stat

import pytest
from cryptography.x509.oid import ExtendedKeyUsageOID

IDX = {"WAZUH_INDEXER_MANAGER_PASSWORD": "Idx.Passw0rd-789"}
TRUST = ("indexer-ca.pem", "indexer-connector.pem", "indexer-connector-key.pem")
MARKERS = (".indexer-ca.imported", ".indexer-connector.imported")


def run(resolver, sandbox, *argv):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=dict(IDX), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def certs(sandbox, name):
    return os.path.join(sandbox.certs, name)


def read(path):
    return open(path, "rb").read()


def digests(sandbox):
    return {n: hashlib.sha256(read(certs(sandbox, n))).hexdigest() for n in TRUST if os.path.exists(certs(sandbox, n))}


def stage_trust(sandbox, files):
    """Files an operator placed in certs/ by hand (no marker)."""
    sandbox.write(certs(sandbox, "indexer-ca.pem"), files["ca"], mode=0o640, gid=sandbox.account_gid)
    sandbox.write(certs(sandbox, "indexer-connector.pem"), files["client"], mode=0o640, gid=sandbox.account_gid)
    sandbox.write(certs(sandbox, "indexer-connector-key.pem"), files["key"], mode=0o640, gid=sandbox.account_gid)


def test_import_fresh(resolver, sandbox):
    published = sandbox.make_indexer_trust()
    code, out, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == "", err
    assert read(certs(sandbox, "indexer-ca.pem")) == published["ca"]
    assert read(certs(sandbox, "indexer-connector.pem")) == published["client"]
    assert read(certs(sandbox, "indexer-connector-key.pem")) == published["key"]
    for name in TRUST + MARKERS:
        st = os.lstat(certs(sandbox, name))
        assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (0o640, 0, sandbox.account_gid), name
    assert f"{certs(sandbox, 'indexer-connector.pem')}: imported from {sandbox.indexer_export}" in out
    assert b"PRIVATE KEY" not in (out + err).encode()


def test_marker_written_first(resolver, sandbox, monkeypatch):
    """A run that dies after the marker leaves a unit the next run imports again, never one that looks staged."""
    real = resolver.write_file

    def die_on_connector(parent, name, *args, **kwargs):
        if name == "indexer-connector.pem":
            raise RuntimeError("interrupted")
        return real(parent, name, *args, **kwargs)
    monkeypatch.setattr(resolver, "write_file", die_on_connector)
    assert run(resolver, sandbox, "--install")[0] == 2
    assert os.path.exists(certs(sandbox, ".indexer-connector.imported"))
    assert not os.path.exists(certs(sandbox, "indexer-connector.pem"))
    monkeypatch.setattr(resolver, "write_file", real)
    assert check_without_writes(resolver, sandbox, monkeypatch)[0] == 0
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 0, err
    assert os.path.exists(certs(sandbox, "indexer-connector.pem"))


def interrupt_rotation(resolver, sandbox, monkeypatch, before="indexer-connector.pem"):
    """Leave a mix of two generations, with the original import markers still present."""
    assert run(resolver, sandbox, "--install")[0] == 0
    original = {name: read(certs(sandbox, name)) for name in TRUST}
    published = sandbox.make_indexer_trust()
    real = resolver.write_file

    def interrupt(parent, name, *args, **kwargs):
        if name == before:
            raise RuntimeError("interrupted rotation")
        return real(parent, name, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(resolver, "write_file", interrupt)
        assert run(resolver, sandbox, "--prestart")[0] == 2
    assert read(certs(sandbox, "indexer-connector.pem")) == original["indexer-connector.pem"]
    return published


def check_without_writes(resolver, sandbox, monkeypatch):
    before = sandbox.tree_state()

    def forbidden(*args, **kwargs):
        raise AssertionError("--check must not write, lock or execute subprocesses but the configuration reader")

    real_run = resolver.subprocess.run

    def configuration_reader_only(argv, *args, **kwargs):
        if argv[0] != sandbox.paths.conf_bin or argv[-1] != "dump":
            forbidden()
        return real_run(argv, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(resolver, "write_file", forbidden)
        patch.setattr(resolver, "acquire_lock", forbidden)
        patch.setattr(resolver.subprocess, "run", configuration_reader_only)
        result = run(resolver, sandbox, "--check")
    assert sandbox.tree_state() == before
    return result


@pytest.mark.parametrize("before", ["indexer-connector-key.pem", "indexer-connector.pem"])
@pytest.mark.parametrize("check_first", [True, False])
def test_interrupted_rotation_recovers(resolver, sandbox, monkeypatch, before, check_first):
    published = interrupt_rotation(resolver, sandbox, monkeypatch, before)
    assert read(certs(sandbox, "indexer-ca.pem")) == published["ca"]
    if before == "indexer-connector.pem":
        assert read(certs(sandbox, "indexer-connector-key.pem")) == published["key"]
    if check_first:
        code, _, err = check_without_writes(resolver, sandbox, monkeypatch)
        assert code == 0 and err == "", err
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 0 and err == "", err
    for name, key in zip(TRUST, ("ca", "client", "key")):
        assert read(certs(sandbox, name)) == published[key]
    assert check_without_writes(resolver, sandbox, monkeypatch)[0] == 0
    inodes = {name: os.stat(certs(sandbox, name)).st_ino for name in TRUST}
    assert run(resolver, sandbox, "--prestart")[0] == 0
    assert {name: os.stat(certs(sandbox, name)).st_ino for name in TRUST} == inodes


@pytest.mark.parametrize("case", ["missing export", "missing key", "invalid pair", "invalid ca", "unsafe export",
                                  "staged pair", "staged half pair", "staged ca", "unsafe marker",
                                  "symlink marker"])
def test_interrupted_rotation_requires_valid_recovery(resolver, sandbox, monkeypatch, case):
    interrupt_rotation(resolver, sandbox, monkeypatch)
    if case == "missing export":
        shutil.rmtree(sandbox.indexer_export)
    elif case == "missing key":
        os.unlink(os.path.join(sandbox.indexer_export, "manager-client-key.pem"))
    elif case == "invalid pair":
        sandbox.make_indexer_trust(key_mismatch=True)
    elif case == "invalid ca":
        sandbox.write(os.path.join(sandbox.indexer_export, "ca.pem"), b"invalid PEM", mode=0o644)
    elif case == "unsafe export":
        os.chmod(sandbox.indexer_export, 0o770)
    elif case == "unsafe marker":
        os.chmod(certs(sandbox, ".indexer-connector.imported"), 0o660)
    elif case == "symlink marker":
        os.unlink(certs(sandbox, ".indexer-connector.imported"))
        os.symlink(".indexer-ca.imported", certs(sandbox, ".indexer-connector.imported"))
    elif case in ("staged pair", "staged half pair"):
        os.unlink(certs(sandbox, ".indexer-connector.imported"))
        if case == "staged half pair":
            os.unlink(certs(sandbox, "indexer-connector-key.pem"))
    else:
        os.unlink(certs(sandbox, ".indexer-ca.imported"))
        sandbox.make_indexer_trust()  # a new pair cannot replace this operator's CA
    expected = "UNSAFE " if case in ("unsafe export", "unsafe marker", "symlink marker") else "INVALID "
    code, _, err = check_without_writes(resolver, sandbox, monkeypatch)
    assert code == 1 and expected in err, err
    operator_files = {name: read(certs(sandbox, name)) for name in TRUST if os.path.exists(certs(sandbox, name))}
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and expected in err, err
    if case.startswith("staged"):
        assert {name: read(certs(sandbox, name)) for name in operator_files} == operator_files


def test_rotation_source_disappears_after_preflight(resolver, sandbox, monkeypatch):
    interrupt_rotation(resolver, sandbox, monkeypatch)
    assert check_without_writes(resolver, sandbox, monkeypatch)[0] == 0
    real = resolver.acquire_lock

    def acquire(*args, **kwargs):
        shutil.rmtree(sandbox.indexer_export)
        return real(*args, **kwargs)

    monkeypatch.setattr(resolver, "acquire_lock", acquire)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and "its key does not match it" in err, err


def test_rotation_source_restored_after_preflight(resolver, sandbox, monkeypatch):
    """A transient INVALID seen before the lock must not survive a successful repair."""
    published = interrupt_rotation(resolver, sandbox, monkeypatch)
    shutil.rmtree(sandbox.indexer_export)
    real = resolver.acquire_lock

    def acquire(*args, **kwargs):
        os.mkdir(sandbox.indexer_export, 0o750)
        for name, key in (("ca.pem", "ca"), ("manager-client.pem", "client"), ("manager-client-key.pem", "key")):
            sandbox.write(os.path.join(sandbox.indexer_export, name), published[key], mode=0o600)
        return real(*args, **kwargs)

    monkeypatch.setattr(resolver, "acquire_lock", acquire)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 0 and err == "", err
    assert check_without_writes(resolver, sandbox, monkeypatch)[0] == 0


@pytest.mark.parametrize("unit", ["ca", "pair"])
def test_staged_never_touched(resolver, sandbox, unit):
    staged = sandbox.make_indexer_trust()
    stage_trust(sandbox, staged)
    if unit == "ca":
        os.unlink(certs(sandbox, "indexer-connector.pem"))
        os.unlink(certs(sandbox, "indexer-connector-key.pem"))
    else:
        os.unlink(certs(sandbox, "indexer-ca.pem"))
        sandbox.write(certs(sandbox, "indexer-ca.pem"), staged["ca"], mode=0o640, gid=sandbox.account_gid)
    sandbox.make_indexer_trust()                      # the indexer republishes different material
    before = {n: d for n, d in digests(sandbox).items()}
    run(resolver, sandbox, "--install")
    after = digests(sandbox)
    if unit == "ca":
        assert after["indexer-ca.pem"] == before["indexer-ca.pem"]
        assert not os.path.exists(certs(sandbox, ".indexer-ca.imported"))
    else:
        assert after == before
        assert not any(os.path.exists(certs(sandbox, m)) for m in MARKERS)


def test_reimport_on_change(resolver, sandbox):
    sandbox.make_indexer_trust()
    run(resolver, sandbox, "--install")
    republished = sandbox.make_indexer_trust()        # the indexer was reinstalled
    code, out, err = run(resolver, sandbox, "--prestart")
    assert code == 0, err
    assert read(certs(sandbox, "indexer-ca.pem")) == republished["ca"]
    assert read(certs(sandbox, "indexer-connector.pem")) == republished["client"]
    assert "re-imported" in out
    assert all(os.path.exists(certs(sandbox, m)) for m in MARKERS)


def test_unchanged_is_not_rewritten(resolver, sandbox):
    run(resolver, sandbox, "--install")
    before = {n: os.lstat(certs(sandbox, n)).st_ino for n in TRUST}
    run(resolver, sandbox, "--install")
    assert {n: os.lstat(certs(sandbox, n)).st_ino for n in TRUST} == before


def test_kept_when_source_gone(resolver, sandbox):
    run(resolver, sandbox, "--install")
    before = digests(sandbox)
    shutil.rmtree(sandbox.indexer_export)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 0, err
    assert digests(sandbox) == before


@pytest.mark.parametrize("export_present", [True, False])
def test_marker_without_files(resolver, sandbox, export_present):
    run(resolver, sandbox, "--install")
    for name in TRUST:
        os.unlink(certs(sandbox, name))
    if not export_present:
        shutil.rmtree(sandbox.indexer_export)
    code, _, err = run(resolver, sandbox, "--install")
    if export_present:
        assert err == "" and all(os.path.exists(certs(sandbox, n)) for n in TRUST)
    else:
        assert f"MISSING {certs(sandbox, 'indexer-ca.pem')}: " in err


@pytest.mark.parametrize("mode,expected", [("--install", 0), ("--prestart", 1)])
def test_missing(resolver, sandbox, mode, expected):
    shutil.rmtree(sandbox.indexer_export)
    if mode == "--prestart":
        sandbox.stage_ca()
    code, _, err = run(resolver, sandbox, mode)
    assert code == expected
    assert (f"MISSING {certs(sandbox, 'indexer-ca.pem')}: install wazuh-indexer on this host first, or stage the "
            "indexer's export/ca.pem there\n") in err
    assert (f"MISSING {certs(sandbox, 'indexer-connector.pem')}: install wazuh-indexer on this host first, or stage "
            "a pair issued by the indexer's CA for this node\n") in err


@pytest.mark.parametrize("eku,imported", [("none", False), ("server", False), ("client", True)])
def test_strict_client_auth(resolver, sandbox, eku, imported):
    sandbox.make_indexer_trust(eku=eku)
    code, _, err = run(resolver, sandbox, "--install")
    assert os.path.exists(certs(sandbox, "indexer-connector.pem")) is imported
    if not imported:
        assert (f"INVALID {sandbox.indexer_export}/manager-client.pem: has no extendedKeyUsage with clientAuth"
                in err)


def test_foreign_chain(resolver, sandbox):
    sandbox.make_indexer_trust(foreign=True)
    code, _, err = run(resolver, sandbox, "--install")
    assert (f"INVALID {sandbox.indexer_export}/manager-client.pem: not issued by "
            f"{certs(sandbox, 'indexer-ca.pem')}") in err
    assert not os.path.exists(certs(sandbox, "indexer-connector.pem"))


def test_staged_pair_from_another_ca(resolver, sandbox):
    """A staged pair is validated against the CA in place: one issued by another CA is refused, never replaced."""
    good = sandbox.make_indexer_trust()
    other = sandbox.make_indexer_trust()
    stage_trust(sandbox, {"ca": good["ca"], "client": other["client"], "key": other["key"]})
    code, _, err = run(resolver, sandbox, "--prestart")
    assert f"INVALID {certs(sandbox, 'indexer-connector.pem')}: not issued by" in err
    assert read(certs(sandbox, "indexer-connector.pem")) == other["client"]


@pytest.mark.parametrize("case,source,reason", [
    ("ca not ca", "ca.pem", "not a CA certificate"),
    ("key mismatch", "manager-client.pem", "its key does not match it"),
    ("garbage ca", "ca.pem", "not a PEM certificate"),
])
def test_invalid_sources(resolver, sandbox, case, source, reason):
    if case == "ca not ca":
        sandbox.make_indexer_trust(ca_is_ca=False)
    elif case == "key mismatch":
        sandbox.make_indexer_trust(key_mismatch=True)
    else:
        sandbox.write(os.path.join(sandbox.indexer_export, "ca.pem"), b"garbage\n", mode=0o644)
    code, _, err = run(resolver, sandbox, "--install")
    assert f"INVALID {sandbox.indexer_export}/{source}: {reason}" in err
    assert not os.path.exists(certs(sandbox, "indexer-connector.pem"))


def test_half_pair_staged(resolver, sandbox):
    files = sandbox.make_indexer_trust()
    sandbox.write(certs(sandbox, "indexer-connector.pem"), files["client"], mode=0o640, gid=sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--install")
    assert (f"INVALID {certs(sandbox, 'indexer-connector.pem')}: half a pair (indexer-connector-key.pem is missing)"
            in err)
    assert not os.path.exists(certs(sandbox, "indexer-connector-key.pem"))


@pytest.mark.parametrize("case", ["export group-writable", "source account-owned"])
def test_unsafe_source(resolver, sandbox, case):
    run(resolver, sandbox, "--install")
    before = digests(sandbox)
    sandbox.make_indexer_trust(mode=0o770 if case == "export group-writable" else 0o750)
    if case == "source account-owned":
        os.chown(os.path.join(sandbox.indexer_export, "manager-client.pem"), sandbox.account_uid, sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 1 and "UNSAFE " in err
    assert digests(sandbox) == before                  # kept, never replaced from an unsafe source


def test_staged_ca_imported_pair(resolver, sandbox):
    published = sandbox.make_indexer_trust()
    sandbox.write(certs(sandbox, "indexer-ca.pem"), published["ca"], mode=0o640, gid=sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == "", err
    assert not os.path.exists(certs(sandbox, ".indexer-ca.imported"))
    assert os.path.exists(certs(sandbox, ".indexer-connector.imported"))


@pytest.mark.parametrize("staged", [False, True])
def test_connector_through_intermediate(resolver, sandbox, staged):
    """A client pair issued by an intermediate CA is accepted when the client file carries it after the leaf."""
    published = sandbox.make_indexer_trust(via_intermediate=True)
    if staged:
        stage_trust(sandbox, published)
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == "", err
    assert read(certs(sandbox, "indexer-connector.pem")) == published["client"]
    assert os.path.exists(certs(sandbox, ".indexer-connector.imported")) is not staged
    assert run(resolver, sandbox, "--check")[0] == 0


def test_connector_under_intermediate_kept_as_indexer_ca(resolver, sandbox):
    """An intermediate CA staged as indexer-ca.pem is trusted as it is: a leaf it issued needs nothing more."""
    published = sandbox.make_indexer_trust(via_intermediate=True)
    stage_trust(sandbox, {"ca": published["intermediate"], "client": published["leaf"], "key": published["key"]})
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 0 and err == "", err


def test_connector_intermediate_missing(resolver, sandbox):
    published = sandbox.make_indexer_trust(via_intermediate=True)
    stage_trust(sandbox, {"ca": published["ca"], "client": published["leaf"], "key": published["key"]})
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1, err
    assert f"INVALID {certs(sandbox, 'indexer-connector.pem')}: not issued by {certs(sandbox, 'indexer-ca.pem')} (" in err
    assert sandbox.tree_state() == before


def test_check_indexer_trust(resolver, sandbox):
    """--check validates what exists, never reports MISSING and writes nothing."""
    shutil.rmtree(sandbox.indexer_export)
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 0 and "MISSING" not in err and sandbox.tree_state() == before
    good, other = sandbox.make_indexer_trust(), sandbox.make_indexer_trust()
    stage_trust(sandbox, {"ca": good["ca"], "client": other["client"], "key": other["key"]})
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and f"INVALID {certs(sandbox, 'indexer-connector.pem')}: not issued by" in err
    assert sandbox.tree_state() == before
    os.chmod(sandbox.indexer_export, 0o770)
    code, _, err = run(resolver, sandbox, "--check")
    assert f"UNSAFE {sandbox.indexer_export}: group-writable" in err


def test_only_certs_written(resolver, sandbox):
    before = set(os.listdir(sandbox.conf))
    run(resolver, sandbox, "--install")
    assert set(os.listdir(sandbox.conf)) - before <= {"ca", "export"}
    assert set(TRUST + MARKERS) <= set(os.listdir(sandbox.certs))


# ---------------------------------------------------------------- the CA and the pair, imported together

def _markers(sandbox):
    return {name: os.path.exists(certs(sandbox, name)) for name in MARKERS}


def _refused_import(resolver, sandbox, line):
    """Both --check and --prestart refuse the export with `line`, and nothing in certs/ changes: the working CA and
    pair stay, so a restart is refused before the stop instead of leaving the manager down."""
    before, markers = digests(sandbox), _markers(sandbox)
    check = run(resolver, sandbox, "--check")
    prestart = run(resolver, sandbox, "--prestart")
    assert check[0] == 1 and line in check[2], check[2]
    assert prestart[0] == 1 and line in prestart[2], prestart[2]
    assert {l for l in check[2].splitlines() if l.startswith("INVALID")} == \
        {l for l in prestart[2].splitlines() if l.startswith("INVALID")}
    assert digests(sandbox) == before and _markers(sandbox) == markers
    shutil.rmtree(sandbox.indexer_export)            # without the export, what is in place is still valid
    assert run(resolver, sandbox, "--check") == (0, run(resolver, sandbox, "--check")[1], "")
    return prestart


def test_new_ca_with_refused_pair_imports_nothing(resolver, sandbox):
    sandbox.make_indexer_trust()
    assert run(resolver, sandbox, "--install")[0] == 0
    sandbox.make_indexer_trust(key_mismatch=True)          # a new CA, and a pair whose key does not match it
    _, out, _ = _refused_import(resolver, sandbox,
                                f"INVALID {sandbox.indexer_export}/manager-client.pem: its key does not match it")
    assert (f"{certs(sandbox, 'indexer-ca.pem')}: kept; the indexer's CA is imported only with a client pair it "
            f"issued") in out


def test_new_ca_that_does_not_issue_the_staged_pair_is_refused(resolver, sandbox):
    sandbox.make_indexer_trust()
    assert run(resolver, sandbox, "--install")[0] == 0
    os.unlink(certs(sandbox, ".indexer-connector.imported"))       # the pair is now the operator's
    sandbox.make_indexer_trust()
    _refused_import(resolver, sandbox, f"INVALID {sandbox.indexer_export}/ca.pem: does not issue the staged "
                                       f"{certs(sandbox, 'indexer-connector.pem')}; nothing was imported")


def test_new_ca_that_does_not_issue_the_kept_pair_is_refused(resolver, sandbox):
    sandbox.make_indexer_trust()
    assert run(resolver, sandbox, "--install")[0] == 0
    sandbox.make_indexer_trust()
    for name in ("manager-client.pem", "manager-client-key.pem"):  # the export carries a new CA only
        os.unlink(os.path.join(sandbox.indexer_export, name))
    _refused_import(resolver, sandbox, f"INVALID {sandbox.indexer_export}/ca.pem: does not issue the kept "
                                       f"{certs(sandbox, 'indexer-connector.pem')}; nothing was imported")


def test_ca_alone_is_imported_when_no_pair_is_in_place(resolver, sandbox):
    """Nothing to break: the CA is imported and the pair stays missing."""
    published = sandbox.make_indexer_trust()
    for name in ("manager-client.pem", "manager-client-key.pem"):
        os.unlink(os.path.join(sandbox.indexer_export, name))
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and read(certs(sandbox, "indexer-ca.pem")) == published["ca"]
    assert os.path.exists(certs(sandbox, ".indexer-ca.imported"))
    assert f"MISSING {certs(sandbox, 'indexer-connector.pem')}" in err


def test_self_signed_ca_in_the_connector_file_is_not_an_intermediate(resolver, sandbox):
    """The imported client file ends with its CA. Against another CA of the same name, the refusal names the real
    reason, instead of the path builder going round that self-signed certificate until it gives up."""
    sandbox.make_indexer_trust()
    assert run(resolver, sandbox, "--install")[0] == 0
    for name in MARKERS:
        os.unlink(certs(sandbox, name))                             # both staged now
    other = sandbox.make_indexer_trust()
    sandbox.write(certs(sandbox, "indexer-ca.pem"), other["ca"], mode=0o640, gid=sandbox.account_gid)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and (f"INVALID {certs(sandbox, 'indexer-connector.pem')}: not issued by "
                          f"{certs(sandbox, 'indexer-ca.pem')} (signature does not match)") in err, err
    assert "max depth" not in err


@pytest.mark.parametrize("eku,accepted", [([ExtendedKeyUsageOID.CLIENT_AUTH], True),
                                          ([ExtendedKeyUsageOID.SERVER_AUTH], False)])
def test_connector_intermediate_purpose(resolver, sandbox, eku, accepted):
    """An intermediate CA that restricts its extended key usages must allow clientAuth, as OpenSSL requires."""
    sandbox.make_indexer_trust(via_intermediate=True, intermediate_eku=eku)
    code, _, err = run(resolver, sandbox, "--install")
    if accepted:
        assert code == 0 and err == "", err
    else:
        assert (f"INVALID {sandbox.indexer_export}/manager-client.pem: issuer CA: its extendedKeyUsage does not "
                f"include clientAuth") in err
        assert not os.path.exists(certs(sandbox, "indexer-connector.pem"))


@pytest.mark.parametrize("which", ["indexer-ca.pem", "indexer-connector.pem"])
def test_unparsable_indexer_file_is_invalid(resolver, sandbox, which):
    """A staged indexer CA or connector certificate that cannot be parsed is INVALID with its path."""
    from conftest import unparsable_certificate
    published = sandbox.make_indexer_trust()
    bad, _ = unparsable_certificate(None, None, "broken-indexer-file")
    files = dict(published)
    files["ca" if which == "indexer-ca.pem" else "client"] = bad
    stage_trust(sandbox, files)
    for mode in ("--check", "--install"):
        code, _, err = run(resolver, sandbox, mode)
        assert f"INVALID {certs(sandbox, which)}: a certificate it holds cannot be parsed (" in err, err
        assert "internal error" not in err and code == (1 if mode == "--check" else 0), (mode, code, err)



# ---------------------------------------------------------------- validity windows
#
# Material that only the clock refuses (expired, not valid yet) is reported as a WARNING and does not stop the start:
# the indexer connection fails until it is renewed or the clock is right. Anything structural still refuses it.

import datetime  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from conftest import intermediate, pool_key  # noqa: E402

EXPIRED, FUTURE, VALID = (-60, -1), (1, 365), (-30, 365)
WARNED = "the indexer connection fails until it is renewed or the clock is right"


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


class Pki:
    """An indexer CA (with its key) that issues client pairs with chosen validity windows, in days from now."""

    def __init__(self, ca_days=(-90, 3650)):
        self.ca, self.ca_key = intermediate(None, None, "wazuh-indexer-ca", days=ca_days)

    def files(self, leaf_days=VALID, *, key_mismatch=False, foreign=False, middle_days=None):
        signer, signer_key, chain = self.ca, self.ca_key, b""
        if middle_days is not None:
            middle, signer_key = intermediate(self.ca, self.ca_key, "wazuh-indexer-intermediate", days=middle_days)
            signer, chain = middle, _pem(middle)
        key = pool_key()
        now = datetime.datetime.now(datetime.timezone.utc)
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wazuh-manager")]))
                .issuer_name(signer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now + datetime.timedelta(days=leaf_days[0]))
                .not_valid_after(now + datetime.timedelta(days=leaf_days[1]))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(pool_key() if foreign else signer_key, hashes.SHA256()))
        key_pem = (pool_key() if key_mismatch else key).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return {"ca": _pem(self.ca), "client": _pem(leaf) + chain + _pem(self.ca), "key": key_pem}


def export(sandbox, files):
    """What the indexer publishes on this host."""
    for role, name, mode in (("ca", "ca.pem", 0o644), ("client", "manager-client.pem", 0o600),
                             ("key", "manager-client-key.pem", 0o600)):
        sandbox.write(os.path.join(sandbox.indexer_export, name), files[role], mode=mode)


@pytest.mark.parametrize("window,said", [(EXPIRED, "expired on "), (FUTURE, "not valid until ")])
def test_imported_pair_outside_its_window_warns(resolver, sandbox, window, said):
    """An imported pair the clock refuses, with the export unchanged: kept, warned about, the start goes on."""
    files = Pki().files(window)
    export(sandbox, files)
    run(resolver, sandbox, "--install")
    assert read(certs(sandbox, "indexer-connector.pem")) == files["client"]
    before = digests(sandbox)
    for mode in ("--check", "--prestart"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 0, (mode, err)
        assert f"WARNING: {certs(sandbox, 'indexer-connector.pem')}: {said}" in err and WARNED in err, (mode, err)
        assert "INVALID" not in err
    assert digests(sandbox) == before


@pytest.mark.parametrize("case,blamed,said", [
    ("expired pair", "indexer-connector.pem", "expired on "),
    ("expired ca", "indexer-ca.pem", "a CA it holds (CN=wazuh-indexer-ca) expired on "),
    ("expired intermediate", "indexer-connector.pem", "a CA on its path (CN=wazuh-indexer-intermediate) expired on "),
])
def test_staged_material_outside_its_window_warns(resolver, sandbox, case, blamed, said):
    sandbox.stage_ca()
    if case == "expired pair":
        files = Pki().files(EXPIRED)
    elif case == "expired ca":
        files = Pki(ca_days=(-90, -1)).files((-60, 365))
    else:
        files = Pki().files((-30, 365), middle_days=(-60, -1))
    stage_trust(sandbox, files)
    before = digests(sandbox)
    for mode in ("--check", "--prestart"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 0 and f"WARNING: {certs(sandbox, blamed)}: {said}" in err, (mode, err)
    assert digests(sandbox) == before


def test_extra_listed_ca_outside_its_window_warns(resolver, sandbox):
    sandbox.stage_ca()
    pki = Pki()
    stage_trust(sandbox, pki.files())
    sandbox.write(certs(sandbox, "old-indexer-ca.pem"), _pem(intermediate(None, None, "old-indexer-ca",
                                                                          days=(-900, -1))[0]),
                  mode=0o640, gid=sandbox.account_gid)
    sandbox.control(conf_dump={"indexer.ssl.certificate_authorities": [certs(sandbox, "indexer-ca.pem"),
                                                                       certs(sandbox, "old-indexer-ca.pem")]})
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 0 and f"WARNING: {certs(sandbox, 'old-indexer-ca.pem')}: a CA it holds (CN=old-indexer-ca) " \
                         f"expired on " in err, err


@pytest.mark.parametrize("window", [EXPIRED, FUTURE])
def test_first_import_outside_its_window(resolver, sandbox, window):
    """Nothing in place: the export the clock refuses fills the gap, with a warning, and the start goes on."""
    files = Pki().files(window)
    export(sandbox, files)
    code, out, err = run(resolver, sandbox, "--install")
    assert code == 0 and f"WARNING: {sandbox.indexer_export}/manager-client.pem: " in err, err
    assert read(certs(sandbox, "indexer-connector.pem")) == files["client"]
    assert f"{certs(sandbox, 'indexer-connector.pem')}: imported from" in out
    assert run(resolver, sandbox, "--prestart")[0] == 0


def test_valid_pair_not_replaced_by_one_outside_its_window(resolver, sandbox):
    pki = Pki()
    valid = pki.files()
    export(sandbox, valid)
    assert run(resolver, sandbox, "--install")[0::2] == (0, "")
    export(sandbox, pki.files(FUTURE))
    for mode in ("--check", "--prestart"):
        code, out, err = run(resolver, sandbox, mode)
        assert code == 0 and f"WARNING: {sandbox.indexer_export}/manager-client.pem: not valid until " in err, err
    assert f"{certs(sandbox, 'indexer-connector.pem')}: kept; the export is not imported over a pair valid now" in out
    assert read(certs(sandbox, "indexer-connector.pem")) == valid["client"]


@pytest.mark.parametrize("case,reason", [("key mismatch", "its key does not match it"),
                                         ("wrong issuer", "not issued by ")])
def test_structural_defect_wins_over_the_window(resolver, sandbox, case, reason):
    files = Pki().files(EXPIRED, key_mismatch=case == "key mismatch", foreign=case == "wrong issuer")
    stage_trust(sandbox, files)
    for mode in ("--check", "--prestart"):
        code, _, err = run(resolver, sandbox, mode)
        assert code == 1 and f"INVALID {certs(sandbox, 'indexer-connector.pem')}: {reason}" in err, (mode, err)
        assert "WARNING" not in err


def test_check_counts_warnings(resolver, sandbox):
    stage_trust(sandbox, Pki().files(EXPIRED))
    before = sandbox.tree_state()
    code, out, err = run(resolver, sandbox, "--check")
    assert code == 0 and "check: no problem found (1 warnings)" in out and err.count("WARNING") == 1, (out, err)
    assert sandbox.tree_state() == before


# ---------------------------------------------------------------- the identity the connector presents

def test_selected_client_pair_is_described(resolver, sandbox):
    """The pair finally in place is described as the server pairs are: its DN and its SANs, `none` when it has
    none (a client certificate need not have any). A progress line: -q drops it."""
    line = f"{certs(sandbox, 'indexer-connector.pem')}: DN CN=wazuh-manager; SANs none"
    code, out, err = run(resolver, sandbox, "--install")
    assert (code, err) == (0, "") and line in out, out
    code, out, err = run(resolver, sandbox, "--prestart")         # kept, imported earlier
    assert (code, err) == (0, "") and line in out, out
    code, out, err = run(resolver, sandbox, "--prestart", "-q")
    assert (code, out, err) == (0, "", "")


def test_describe_leaf_names_each_san_type(resolver):
    import ipaddress
    key = pool_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("node1"), x509.IPAddress(ipaddress.ip_address("192.0.2.1")),
                x509.RFC822Name("ops@example.com"), x509.UniformResourceIdentifier("spiffe://example/manager")]),
                critical=False)
            .sign(key, hashes.SHA256()))
    assert resolver.describe_leaf(cert) == ("DN CN=client; SANs DNS:node1, IP:192.0.2.1, email:ops@example.com, "
                                            "URI:spiffe://example/manager")

