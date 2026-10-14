# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""--clear: refused while the manager runs; removes what the resolver made, keeps what it was given, and walks
every directory without following a link."""

import errno
import fcntl
import hashlib
import io
import os
import shutil
import subprocess

import pytest

IDX = {"WAZUH_INDEXER_MANAGER_PASSWORD": "Idx.Passw0rd-789"}

# What a complete --install leaves that --clear must remove, relative to the sandbox.
MADE_BY_INSTALL = {
    "conf/certs/remoted.pem", "conf/certs/remoted-key.pem", "conf/certs/apid.pem", "conf/certs/apid-key.pem",
    "conf/certs/root-ca.pem",
    "conf/certs/indexer-ca.pem", "conf/certs/.indexer-ca.imported",
    "conf/certs/indexer-connector.pem", "conf/certs/indexer-connector-key.pem", "conf/certs/.indexer-connector.imported",
    "conf/ca/root-ca.pem", "conf/ca/root-ca.key", "conf/ca/.wazuh-manager-bootstrap-ca",
    "conf/export/credentials.env", "conf/export/ca.pem",
    "home/api/configuration/security/rbac.db",
    "home/queue/keystore/keystore.json",
}


def run(resolver, sandbox, *argv):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=dict(IDX), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def install(resolver, sandbox):
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == "", err


def digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def pidfile(sandbox, name, owner="root"):
    path = os.path.join(sandbox.home, "var", "run", name)
    if owner == "root":
        sandbox.write(path, b"", mode=0o640)
    else:
        sandbox.plant(path, b"")
    return path


def live_in_proc(sandbox, pid):
    os.makedirs(os.path.join(sandbox.proc, str(pid)), exist_ok=True)


def test_clear_after_install(resolver, sandbox):
    install(resolver, sandbox)
    before = set(sandbox.tree_state())
    code, out, err = run(resolver, sandbox, "--clear")
    assert code == 0 and err == "", err
    assert before - set(sandbox.tree_state()) == MADE_BY_INSTALL
    for directory in ("conf/ca", "conf/export", "conf/certs", "home/queue/keystore",
                      "home/api/configuration/security"):
        assert os.path.isdir(sandbox.path(directory)), directory
    assert "every Server API user, role and policy" in out
    assert out.rstrip().endswith("cleared; the next --install resolves from nothing")


def test_rbac_temporary_removed(resolver, sandbox):
    install(resolver, sandbox)
    sandbox.write(sandbox.rbac_db + ".tmp", b"partial")
    assert run(resolver, sandbox, "--clear")[0] == 0
    assert not os.path.exists(sandbox.rbac_db + ".tmp")


def test_install_after_clear(resolver, sandbox):
    install(resolver, sandbox)
    first_ca = digest(sandbox.path("conf", "ca", "root-ca.pem"))
    first_published = open(sandbox.path("conf", "export", "credentials.env")).read()
    seeds = len(sandbox.seed_calls())
    assert run(resolver, sandbox, "--clear")[0] == 0
    assert sandbox.keystore() == {}
    install(resolver, sandbox)
    assert digest(sandbox.path("conf", "ca", "root-ca.pem")) != first_ca
    assert open(sandbox.path("conf", "export", "credentials.env")).read() != first_published
    assert len(sandbox.seed_calls()) == seeds + 1 and os.path.getsize(sandbox.rbac_db) > 0
    assert sandbox.keystore()["indexer/password"] == IDX["WAZUH_INDEXER_MANAGER_PASSWORD"]
    assert run(resolver, sandbox, "--prestart")[0] == 0


def _reaped_pid():
    child = subprocess.Popen(["/bin/true"])        # a pid that existed and is gone
    child.wait()
    return child.pid


@pytest.mark.parametrize("case,refused", [("running", True), ("no proc entry", False), ("reaped", False)])
def test_refused_while_running(resolver, sandbox, case, refused):
    install(resolver, sandbox)
    pid = _reaped_pid() if case == "reaped" else os.getpid()
    if case != "no proc entry":
        live_in_proc(sandbox, pid)
    path = pidfile(sandbox, f"wazuh-manager-remoted-{pid}.pid")
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--clear")
    if refused:
        assert code == 1 and f"--clear refused: {path} names the running process {pid}" in err
        assert "wazuh-manager-control stop" in err
        assert sandbox.tree_state() == before
    else:
        assert code == 0, err


def test_planted_pidfile_only_blocks(resolver, sandbox):
    """The service account can write var/run: a pidfile naming a live process makes --clear refuse, nothing more."""
    install(resolver, sandbox)
    live_in_proc(sandbox, 1)
    pidfile(sandbox, "x-1.pid", owner="account")
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--clear")
    assert code == 1 and "names the running process 1" in err
    assert sandbox.tree_state() == before


@pytest.mark.parametrize("name", ["x-0.pid", "x-abc.pid", "x.pid", "x-99999999.pid", "x-4194305.pid", "dir"])
def test_pidfile_names_ignored(resolver, sandbox, name):
    install(resolver, sandbox)
    live_in_proc(sandbox, 0)
    if name == "dir":
        os.mkdir(os.path.join(sandbox.home, "var", "run", f"remoted-ca-bundle-{os.getpid()}.pid"))
        live_in_proc(sandbox, os.getpid())
        # A directory named like a pidfile still names a live pid: only the name counts, which only blocks.
        assert run(resolver, sandbox, "--clear")[0] == 1
        return
    pidfile(sandbox, name)
    code, _, err = run(resolver, sandbox, "--clear")
    assert code == 0, err


@pytest.mark.parametrize("key", [True, False], ids=["signing", "anchor-only"])
def test_staged_ca_kept(resolver, sandbox, key):
    sandbox.stage_ca(key=key)
    run(resolver, sandbox, "--install")
    ca = sandbox.path("conf", "ca")
    kept = {name: digest(os.path.join(ca, name)) for name in os.listdir(ca)}
    code, out, err = run(resolver, sandbox, "--clear")
    assert code == 0, err
    assert {name: digest(os.path.join(ca, name)) for name in os.listdir(ca)} == kept
    assert f"kept {ca}/root-ca.pem: staged by the operator, no mint marker" in out
    for name in ("remoted.pem", "remoted-key.pem", "apid.pem", "apid-key.pem", "root-ca.pem"):
        assert not os.path.exists(os.path.join(sandbox.certs, name)), name


def test_stamped_bundle_removed(resolver, sandbox):
    """The reset removes the agents' bundle even when it carries rotation CAs and a publication block."""
    install(resolver, sandbox)
    bundle = os.path.join(sandbox.certs, "root-ca.pem")
    data = (b"## published by wazuh-manager-certs\n" + open(bundle, "rb").read()      # plus a second CA
            + open(os.path.join(sandbox.indexer_export, "ca.pem"), "rb").read())
    sandbox.write(bundle, data, mode=0o640, gid=sandbox.account_gid)
    assert run(resolver, sandbox, "--clear")[0] == 0
    assert not os.path.exists(bundle)


def test_staged_imports_kept(resolver, sandbox):
    install(resolver, sandbox)
    for marker in (".indexer-ca.imported", ".indexer-connector.imported"):
        os.unlink(os.path.join(sandbox.certs, marker))
    names = ("indexer-ca.pem", "indexer-connector.pem", "indexer-connector-key.pem")
    kept = {name: digest(os.path.join(sandbox.certs, name)) for name in names}
    code, out, err = run(resolver, sandbox, "--clear")
    assert code == 0, err
    assert {name: digest(os.path.join(sandbox.certs, name)) for name in names} == kept
    for name in names:
        assert f"kept {sandbox.certs}/{name}: staged, no import marker" in out


def test_marker_only_and_half_pair(resolver, sandbox):
    install(resolver, sandbox)
    os.unlink(os.path.join(sandbox.certs, "indexer-ca.pem"))
    os.unlink(os.path.join(sandbox.certs, "indexer-connector-key.pem"))
    code, _, err = run(resolver, sandbox, "--clear")
    assert code == 0, err
    left = set(os.listdir(sandbox.certs))
    assert not left & {".indexer-ca.imported", ".indexer-connector.imported", "indexer-connector.pem"}


def _account_certs(sandbox):
    os.rename(sandbox.certs, sandbox.certs + ".real")
    os.mkdir(sandbox.certs, 0o750)
    os.chown(sandbox.certs, sandbox.account_uid, sandbox.account_gid)
    sandbox.plant(os.path.join(sandbox.certs, "root-ca.pem"))


def _swap_ca_export(sandbox):
    ca, export = sandbox.path("conf", "ca"), sandbox.path("conf", "export")
    os.rename(ca, ca + ".x")
    os.rename(export, ca)
    os.rename(ca + ".x", export)


def _run_symlink(sandbox):
    run_dir = os.path.join(sandbox.home, "var", "run")
    os.rename(run_dir, run_dir + ".real")
    os.symlink(run_dir + ".real", run_dir)


@pytest.mark.parametrize("attack", [_account_certs, _swap_ca_export, _run_symlink],
                         ids=["certs account dir", "ca export swapped", "var/run symlink"])
def test_unsafe_refuses_all(resolver, sandbox, attack):
    install(resolver, sandbox)
    attack(sandbox)
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--clear")
    assert code == 1 and "UNSAFE " in err, err
    assert sandbox.tree_state() == before


@pytest.mark.parametrize("parts", [("queue", "keystore"), ("api", "configuration", "security")],
                         ids=["keystore", "security"])
def test_home_paths_not_followed(resolver, sandbox, parts):
    install(resolver, sandbox)
    target = os.path.join(sandbox.home, *parts)
    decoy = sandbox.path("decoy")
    os.mkdir(decoy, 0o700)
    for name in ("rbac.db", "keystore.json", "CURRENT"):
        sandbox.write(os.path.join(decoy, name), b"decoy")
    shutil.rmtree(target)
    os.symlink(decoy, target)
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--clear")
    assert code == 1 and f"UNSAFE {target}: a symbolic link" in err, err
    assert sandbox.tree_state() == before


def test_swap_around_open_refuses(resolver, sandbox, monkeypatch):
    """ca/ and export/ swapped by name just before export/ is opened and swapped back right after: every test by
    name then sees a clean tree, but the descriptor --clear would empty is the real ca/. The tests on the open
    descriptors catch it, and the CA is not removed."""
    install(resolver, sandbox)
    real_open = resolver._open_optional_dir
    calls = []

    def open_swapped(conf, name, spec, report):
        calls.append(name)
        if calls.count("export") != 1 or name != "export":       # only the descriptor the removals would use
            return real_open(conf, name, spec, report)
        _swap_ca_export(sandbox)
        try:
            return real_open(conf, name, spec, report)
        finally:
            _swap_ca_export(sandbox)
    monkeypatch.setattr(resolver, "_open_optional_dir", open_swapped)
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--clear")
    assert code == 1 and f"UNSAFE {sandbox.path('conf', 'export')}: holds root-ca.key, which belongs in ca/" in err, err
    assert sandbox.tree_state() == before


def test_failed_removal_reported(resolver, sandbox, monkeypatch):
    install(resolver, sandbox)
    real_unlink = os.unlink

    def unlink(name, *args, **kwargs):
        if name == "apid-key.pem":
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_unlink(name, *args, **kwargs)
    monkeypatch.setattr(resolver.os, "unlink", unlink)
    code, out, err = run(resolver, sandbox, "--clear")
    assert code == 1
    assert f"INVALID {sandbox.certs}/apid-key.pem: could not remove it (Permission denied)" in err
    assert "cleared;" not in out


def test_local_env_kept(resolver, sandbox):
    local_env = sandbox.write(os.path.join(sandbox.conf, "local.env"), "WAZUH_MANAGER_REMOTED_CERT_SANS=DNS:a.b\n")
    install(resolver, sandbox)
    kept = digest(local_env)
    code, out, _ = run(resolver, sandbox, "--clear")
    assert code == 0 and digest(local_env) == kept
    assert f"kept {local_env}" in out


def test_clear_takes_lock(resolver, sandbox, monkeypatch):
    install(resolver, sandbox)
    monkeypatch.setattr(resolver, "LOCK_TIMEOUT", 0.5)
    holder = os.open(sandbox.path("conf", "ca"), os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        before = sandbox.tree_state()
        code, _, err = run(resolver, sandbox, "--clear")
        assert code == 2 and "another resolve-credentials run holds" in err
        assert sandbox.tree_state() == before
    finally:
        os.close(holder)


def test_clear_nothing(resolver, sandbox):
    code, out, err = run(resolver, sandbox, "--clear")
    assert code == 0 and err == "", err
    assert "cleared;" in out
