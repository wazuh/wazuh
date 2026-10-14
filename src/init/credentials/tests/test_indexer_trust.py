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
    code, _, err = run(resolver, sandbox, "--prestart")
    assert code == 0, err
    assert os.path.exists(certs(sandbox, "indexer-connector.pem"))


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
    sandbox.stage_ca()
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
    ("expired pair", "manager-client.pem", "expired"),
    ("key mismatch", "manager-client.pem", "its key does not match it"),
    ("garbage ca", "ca.pem", "not a PEM certificate"),
])
def test_invalid_sources(resolver, sandbox, case, source, reason):
    if case == "ca not ca":
        sandbox.make_indexer_trust(ca_is_ca=False)
    elif case == "expired pair":
        sandbox.make_indexer_trust(expired=True)
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
