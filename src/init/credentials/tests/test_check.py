# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""--check: read-only, it reports UNSAFE and INVALID, and MISSING only for what --prestart could not complete either
(it runs before a restart stops anything); what --prestart completes is left to it."""

import io
import os
import shutil
import stat

import pytest


def run(resolver, sandbox, *argv):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ={}, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_check_resolved_tree(resolver, sandbox):
    sandbox.stage_ca()
    assert run(resolver, sandbox, "--check")[0::2] == (0, "")


def test_check_bad_local_env(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "oops\n")
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err.startswith("INVALID ")


def test_check_unsafe_indexer_export(resolver, sandbox):
    sandbox.stage_ca()
    sandbox.make_indexer_export(credentials="WAZUH_INDEXER_MANAGER_PASSWORD=x\n", mode=0o770)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == f"UNSAFE {sandbox.indexer_export}: group-writable\n"


def _missing(err):
    return {line for line in err.splitlines() if line.startswith("MISSING ")}


def test_check_reports_only_what_prestart_cannot_complete(resolver, sandbox):
    """Nothing supplied anywhere. --prestart will seed and store what it is given, so --check leaves the indexer
    password to it (the keystore is not read before the daemons stop); the CA is created at --install only, so
    --check reports it, with --prestart's own line."""
    code, _, check = run(resolver, sandbox, "--check")
    _, _, prestart = run(resolver, sandbox, "--prestart")
    assert code == 1 and _missing(check) == {f"MISSING {sandbox.conf}/ca/root-ca.pem: the manager's CA is missing; "
                                             f"stage it there (and root-ca.key to issue certificates), or reinstall"}
    assert _missing(check) < _missing(prestart) and "WAZUH_INDEXER_MANAGER_PASSWORD" in prestart


@pytest.mark.parametrize("name", ["remoted", "apid"])
def test_check_reports_an_absent_server_pair(resolver, sandbox, name):
    """Pairs are issued at --install only: an absent one is a MISSING --prestart would report and could not fix, so a
    restart must refuse it before the daemons stop."""
    sandbox.stage_ca()
    for suffix in (".pem", "-key.pem"):
        os.unlink(os.path.join(sandbox.certs, name + suffix))
    code, _, check = run_env(resolver, sandbox, "--check")
    _, _, prestart = run_env(resolver, sandbox, "--prestart")
    assert code == 1 and _missing(check) == {f"MISSING {sandbox.certs}/{name}.pem: run --install to issue it, or "
                                             f"stage the pair"}
    assert _missing(check) <= _missing(prestart)


def test_check_leaves_an_importable_indexer_trust_to_prestart(resolver, sandbox):
    """The indexer's files are absent but its export holds them: --prestart imports them, so --check is quiet."""
    sandbox.stage_ca()
    sandbox.make_indexer_trust()
    for name in ("indexer-ca.pem", "indexer-connector.pem", "indexer-connector-key.pem"):
        path = os.path.join(sandbox.certs, name)
        if os.path.exists(path):
            os.unlink(path)
    assert run_env(resolver, sandbox, "--check")[0::2] == (0, "")
    assert run_env(resolver, sandbox, "--prestart")[0] == 0


def test_check_unsafe_conf(resolver, sandbox):
    os.chmod(sandbox.conf, 0o777)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == f"UNSAFE {sandbox.conf}: world-writable\n"


def test_check_absent_conf(resolver, sandbox):
    shutil.rmtree(sandbox.conf)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == f"INVALID {sandbox.conf}: no such directory\n"


def test_check_changes_nothing(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "A=1\n")
    sandbox.make_indexer_export(credentials="WAZUH_INDEXER_MANAGER_PASSWORD=Idx.Passw0rd-123\n")
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and all(line.startswith("MISSING ") for line in err.splitlines()), err   # the CA, not created
    assert sandbox.tree_state() == before
    assert not os.path.exists(os.path.join(sandbox.conf, "ca"))


# ---------------------------------------------------------------- the whole tree

IDX = {"WAZUH_INDEXER_MANAGER_PASSWORD": "Idx.Passw0rd-789"}


def run_env(resolver, sandbox, *argv):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=dict(IDX), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def installed(resolver, sandbox):
    code, _, err = run_env(resolver, sandbox, "--install")
    assert code == 0 and err == "", err


@pytest.mark.parametrize("case,expected", [
    ("export 0750", "UNSAFE {conf}/export: mode is 0750, not 0700"),
    ("export account-owned", "UNSAFE {conf}/export: owned by uid"),
    ("credentials.env 0640", "UNSAFE {conf}/export/credentials.env: mode is 0640, not 0600"),
    ("ca.pem group-writable", "UNSAFE {conf}/export/ca.pem: group-writable"),
    ("bad line", "INVALID {conf}/export/credentials.env:4: not a NAME=value line"),
])
def test_check_export(resolver, sandbox, case, expected):
    installed(resolver, sandbox)
    export = os.path.join(sandbox.conf, "export")
    if case == "export 0750":
        os.chmod(export, 0o750)
    elif case == "export account-owned":
        os.chown(export, sandbox.account_uid, 0)
    elif case == "credentials.env 0640":
        os.chmod(os.path.join(export, "credentials.env"), 0o640)
    elif case == "ca.pem group-writable":
        os.chmod(os.path.join(export, "ca.pem"), 0o664)
    else:
        with open(os.path.join(export, "credentials.env"), "a") as handle:
            handle.write("not a line\n")
    before = sandbox.tree_state()
    code, _, err = run_env(resolver, sandbox, "--check")
    assert code == 1 and expected.format(conf=sandbox.conf) in err
    assert sandbox.tree_state() == before


@pytest.mark.parametrize("case,flagged", [("account file", True), ("account dir", True), ("root lock", False)])
def test_certs_foreign_entry(resolver, sandbox, case, flagged):
    installed(resolver, sandbox)
    if case == "account file":
        sandbox.plant(os.path.join(sandbox.certs, "extra.pem"))
    elif case == "account dir":
        os.mkdir(os.path.join(sandbox.certs, "extra"))
        os.chown(os.path.join(sandbox.certs, "extra"), sandbox.account_uid, sandbox.account_gid)
    else:
        sandbox.write(os.path.join(sandbox.certs, "root-ca.pem.lock"), b"", mode=0o600)
    code, _, err = run_env(resolver, sandbox, "--check")
    assert (code == 1 and "UNSAFE " in err and "not by root" in err) if flagged else (code == 0 and err == "")


def test_swap_ca_export(resolver, sandbox):
    installed(resolver, sandbox)
    ca, export = os.path.join(sandbox.conf, "ca"), os.path.join(sandbox.conf, "export")
    os.rename(ca, ca + ".x")
    os.rename(export, ca)
    os.rename(ca + ".x", export)
    before = sandbox.tree_state()
    for mode in ("--check", "--prestart"):
        code, _, err = run_env(resolver, sandbox, mode)
        assert code == 1 and f"UNSAFE {ca}: holds" in err and f"UNSAFE {export}: holds" in err, (mode, err)
    assert sandbox.tree_state() == before


def swap_private_dirs(sandbox):
    ca, export = os.path.join(sandbox.conf, "ca"), os.path.join(sandbox.conf, "export")
    os.rename(ca, ca + ".swapping")
    os.rename(export, ca)
    os.rename(ca + ".swapping", export)


@pytest.mark.parametrize("mode,expected", [("--install", 0), ("--upgrade", 0), ("--prestart", 1)])
def test_swapped_private_dirs_do_not_seed_or_write(resolver, sandbox, mode, expected):
    """An unseeded RBAC database must not turn a refused directory swap into a password publication."""
    sandbox.stage_ca()
    os.mkdir(os.path.join(sandbox.conf, "export"), 0o700)
    swap_private_dirs(sandbox)
    before = sandbox.tree_state()
    code, _, err = run_env(resolver, sandbox, mode)
    assert code == expected and "UNSAFE " in err, err
    assert sandbox.tree_state() == before
    assert sandbox.seed_calls() == [] and sandbox.keystore() == {}


@pytest.mark.parametrize("mode,expected", [("--install", 0), ("--upgrade", 0), ("--prestart", 1)])
@pytest.mark.parametrize("boundary,staged_ca", [
    ("before lock", True), ("after lock", True), ("before publication", True),
    ("after lock", False), ("before publication", False),
])
def test_private_dirs_swapped_after_checks(resolver, sandbox, monkeypatch, mode, expected, boundary, staged_ca):
    """A successful path-based preflight cannot authorize a different directory opened for writing later."""
    if staged_ca:
        sandbox.stage_ca()
    else:
        os.mkdir(os.path.join(sandbox.conf, "ca"), 0o700)
    os.mkdir(os.path.join(sandbox.conf, "export"), 0o700)
    before = []

    def attack():
        swap_private_dirs(sandbox)
        before.append(sandbox.tree_state())

    if boundary == "before lock":
        real = resolver.acquire_lock

        def acquire(*args, **kwargs):
            attack()
            return real(*args, **kwargs)
        monkeypatch.setattr(resolver, "acquire_lock", acquire)
    elif boundary == "after lock":
        real = resolver.acquire_lock

        def acquire(*args, **kwargs):
            directory = real(*args, **kwargs)
            attack()
            return directory
        monkeypatch.setattr(resolver, "acquire_lock", acquire)
    else:
        real = resolver.ensure_dir

        def ensure(parent, name, spec):
            if name == "export" and not before:
                attack()
            return real(parent, name, spec)
        monkeypatch.setattr(resolver, "ensure_dir", ensure)

    code, _, err = run_env(resolver, sandbox, mode)
    assert before and code == expected and "UNSAFE " in err, err
    assert sandbox.tree_state() == before[0]
    assert sandbox.seed_calls() == [] and sandbox.keystore() == {}


@pytest.mark.parametrize("mode,expected", [("--install", 0), ("--upgrade", 0), ("--prestart", 1)])
@pytest.mark.parametrize("entry", ["local.env", "certs", "indexer export", "published passwords"])
def test_unsafe_tree_does_not_initialize_state(resolver, sandbox, mode, expected, entry):
    """An unsafe input is refused before lock creation, password publication or any keystore operation."""
    if entry == "local.env":
        sandbox.plant(os.path.join(sandbox.conf, "local.env"), "A=1\n")
    elif entry == "certs":
        os.chown(sandbox.certs, sandbox.account_uid, sandbox.account_gid)
    elif entry == "indexer export":
        os.chmod(sandbox.indexer_export, 0o770)
    else:
        export = os.path.join(sandbox.conf, "export")
        os.mkdir(export, 0o700)
        sandbox.write(os.path.join(export, "credentials.env"), "A=1\n", mode=0o640)
    before = sandbox.tree_state()
    code, _, err = run_env(resolver, sandbox, mode)
    assert code == expected and "UNSAFE " in err, err
    assert sandbox.tree_state() == before
    assert sandbox.seed_calls() == [] and sandbox.keystore() == {}


def test_private_dirs_swapped_before_ca_publication(resolver, sandbox, monkeypatch):
    """When RBAC is already seeded, CA publication must still check its own export descriptor."""
    installed(resolver, sandbox)
    real = resolver.ensure_dir
    before = []

    def ensure(parent, name, spec):
        if name == "export" and not before:
            swap_private_dirs(sandbox)
            before.append(sandbox.tree_state())
        return real(parent, name, spec)
    monkeypatch.setattr(resolver, "ensure_dir", ensure)
    code, _, err = run_env(resolver, sandbox, "--install")
    assert before and code == 0 and "UNSAFE " in err, err
    assert sandbox.tree_state() == before[0]


def test_swap_certs_ca(resolver, sandbox):
    installed(resolver, sandbox)
    ca = os.path.join(sandbox.conf, "ca")
    os.rename(sandbox.certs, ca + ".x")
    os.rename(ca, sandbox.certs)
    os.rename(ca + ".x", ca)
    before = sandbox.tree_state()
    code, _, err = run_env(resolver, sandbox, "--prestart")
    assert code == 1 and f"UNSAFE {sandbox.certs}: " in err and f"UNSAFE {ca}: " in err
    assert sandbox.tree_state() == before


@pytest.mark.parametrize("mode", ["--prestart", "--upgrade"])
def test_export_ca_stale(resolver, sandbox, mode):
    """The CA staged again by hand: the publication is stale, not attacked. --check lets the start go on and every
    writing mode publishes it again."""
    installed(resolver, sandbox)
    os.unlink(os.path.join(sandbox.conf, "ca", ".wazuh-manager-bootstrap-ca"))
    published = os.path.join(sandbox.conf, "export", "ca.pem")
    with open(published, "ab") as handle:
        handle.write(b"\n")
    before = sandbox.tree_state()
    code, out, err = run_env(resolver, sandbox, "--check")
    assert (code, err) == (0, "") and f"{published} differs from" in out and "--prestart publishes it again" in out
    assert sandbox.tree_state() == before
    code, out, err = run_env(resolver, sandbox, mode)
    assert (code, err) == (0, "") and f"published {published} again" in out
    with open(os.path.join(sandbox.conf, "ca", "root-ca.pem"), "rb") as own, open(published, "rb") as copy:
        assert copy.read() == own.read()
    st = os.stat(published)
    assert (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (0, 0, 0o644)
    code, out, err = run_env(resolver, sandbox, "--check")
    assert (code, err) == (0, "") and "differs from" not in out


def _break_five_ways(resolver, sandbox):
    installed(resolver, sandbox)
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "WAZUH_MANAGER_APID_CERT_SANS=DNS:bad_name\nnope\n")
    os.chmod(os.path.join(sandbox.conf, "export", "credentials.env"), 0o644)
    sandbox.plant(os.path.join(sandbox.certs, "planted.pem"))
    os.unlink(os.path.join(sandbox.certs, "apid-key.pem"))
    os.chmod(sandbox.indexer_export, 0o770)


def test_each_problem_once(resolver, sandbox):
    _break_five_ways(resolver, sandbox)
    code, _, err = run_env(resolver, sandbox, "--prestart")
    lines = [line for line in err.splitlines() if line.split(" ", 1)[0] in ("MISSING", "INVALID", "UNSAFE")]
    assert code == 1 and len(lines) >= 5
    assert len(lines) == len(set(lines)), err


def test_check_equals_prestart(resolver, sandbox):
    _break_five_ways(resolver, sandbox)
    _, _, check_err = run_env(resolver, sandbox, "--check")
    _, _, prestart_err = run_env(resolver, sandbox, "--prestart")
    problems = lambda text: {line for line in text.splitlines() if line.split(" ", 1)[0] in ("INVALID", "UNSAFE")}
    assert "MISSING" not in check_err
    assert problems(check_err) <= problems(prestart_err)


def test_prestart_checks_first(resolver, sandbox):
    """A first start with certs/ already replaced by the account's directory: --prestart refuses, and nothing is
    minted, issued or imported through it."""
    os.mkdir(sandbox.certs + ".account", 0o770)
    os.chown(sandbox.certs + ".account", sandbox.account_uid, sandbox.account_gid)
    shutil.rmtree(sandbox.certs)
    os.rename(sandbox.certs + ".account", sandbox.certs)
    sandbox.plant(os.path.join(sandbox.certs, "root-ca.pem"))
    code, _, err = run_env(resolver, sandbox, "--prestart")
    assert code == 1 and f"UNSAFE {sandbox.certs}: owned by uid" in err, err
    assert os.listdir(sandbox.certs) == ["root-ca.pem"]
    assert not os.path.exists(os.path.join(sandbox.conf, "ca", "root-ca.pem"))
    assert not os.path.exists(os.path.join(sandbox.conf, "export", "ca.pem"))
