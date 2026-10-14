# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The service account against the resolver, at the level of the file primitives.

The attacker is the service account (`daemon` here), which can create, rename and unlink entries of <CONF> at any
moment. Each test interposes the attack at an exact point of a run by wrapping an `os` call of the loaded program;
the program itself has no hook for it. What it may achieve is a refusal, never a write through a planted
entry, the use of content it wrote, or a secret.
"""

import io
import os
import stat

import pytest

SECRET = "Pl4nted.Or-Leaked"


def run(resolver, sandbox, *argv, environ=None):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=environ or {}, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def open_conf(resolver, sandbox):
    return resolver.open_top(sandbox.conf, resolver.conf_spec(sandbox.paths))


def plant_dir(sandbox, path):
    """A directory the service account created."""
    os.mkdir(path, 0o770)
    os.chown(path, sandbox.account_uid, sandbox.account_gid)
    return path


# ---------------------------------------------------------------- local.env

@pytest.mark.parametrize("variant", ["account-owned", "symlink", "fifo", "directory", "group-writable"])
def test_local_env_planted(resolver, sandbox, variant):
    path = os.path.join(sandbox.conf, "local.env")
    if variant == "account-owned":
        sandbox.plant(path, f"WAZUH_MANAGER_API_PASSWORD={SECRET}\n", mode=0o600)
    elif variant == "symlink":
        os.symlink(sandbox.write(sandbox.path("evil.env"), f"A={SECRET}\n"), path)
    elif variant == "fifo":
        os.mkfifo(path, 0o600)
    elif variant == "directory":
        plant_dir(sandbox, path)
    else:
        sandbox.write(path, f"A={SECRET}\n", mode=0o660, gid=sandbox.account_gid)
    code, out, err = run(resolver, sandbox, "--check")
    assert code == 1
    assert err.startswith(f"UNSAFE {path}: ")
    assert SECRET not in out + err


def test_local_env_replaced_by_another_root_file(resolver, sandbox):
    """The account renames a root-owned file of <CONF> (here, internal options) over local.env: it passes rule 1,
    so its content decides, and it is not a .env file."""
    other = sandbox.write(os.path.join(sandbox.conf, "wazuh-manager-internal-options.conf"),
                          "# options\nremoted.debug=2\n", mode=0o640, gid=sandbox.account_gid)
    os.rename(other, os.path.join(sandbox.conf, "local.env"))
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err.startswith(f"INVALID {sandbox.conf}/local.env:2: ")


def test_hard_link_as_local_env(resolver, sandbox):
    """With fs.protected_hardlinks off the account could link a root file; the link count gives it away."""
    other = sandbox.write(sandbox.path("root-file"), "A=1\n")
    os.link(other, os.path.join(sandbox.conf, "local.env"))
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and "UNSAFE" in err and "2 hard links" in err


# ---------------------------------------------------------------- the indexer's export

@pytest.mark.parametrize("variant", ["group-writable dir", "account-owned file", "symlinked dir"])
def test_indexer_export_unsafe(resolver, sandbox, variant):
    secret_line = f"WAZUH_INDEXER_MANAGER_PASSWORD={SECRET}\n"
    if variant == "symlinked dir":
        real = sandbox.path("real-export")
        os.mkdir(real, 0o750)
        sandbox.write(os.path.join(real, "credentials.env"), secret_line)
        os.symlink(real, sandbox.indexer_export)
    else:
        sandbox.make_indexer_export(mode=0o770 if variant == "group-writable dir" else 0o750)
        target = os.path.join(sandbox.indexer_export, "credentials.env")
        if variant == "account-owned file":
            sandbox.plant(target, secret_line, mode=0o600)
        else:
            sandbox.write(target, secret_line)
    report = resolver.Report(quiet=True, out=io.StringIO(), err=io.StringIO())
    with open_conf(resolver, sandbox) as conf:
        lookup = resolver.build_lookup(sandbox.paths, conf, report, {})
    assert lookup.get("WAZUH_INDEXER_MANAGER_PASSWORD") is None
    assert report.has("UNSAFE")


# ---------------------------------------------------------------- entries swapped after they were opened

def test_export_swapped_after_open(resolver, sandbox, monkeypatch):
    """export/ is renamed and an account directory planted under its name between the resolver opening it and
    writing the secret: the secret lands in the original root 0700 directory only."""
    real_open = os.open
    export = os.path.join(sandbox.conf, "export")

    def attack(name, flags, mode=0o777, *, dir_fd=None):
        if isinstance(name, str) and name.startswith(".credentials.env."):
            os.rename(export, export + ".moved")
            plant_dir(sandbox, export)
        return real_open(name, flags, mode, dir_fd=dir_fd)
    with open_conf(resolver, sandbox) as conf:
        with resolver.ensure_dir(conf, "export", resolver.Spec("dir", uid=0, gid=0, mode=0o700)) as target:
            monkeypatch.setattr(resolver.os, "open", attack)
            resolver.write_file(target, "credentials.env", f"K={SECRET}\n".encode(), 0o600, 0, 0)
    assert os.listdir(export) == []
    moved = os.path.join(sandbox.conf, "export.moved")
    st = os.lstat(os.path.join(moved, "credentials.env"))
    assert stat.S_IMODE(st.st_mode) == 0o600 and (st.st_uid, st.st_gid) == (0, 0)
    assert stat.S_IMODE(os.lstat(moved).st_mode) == 0o700 and os.lstat(moved).st_uid == 0


def test_certs_swapped_before_rename(resolver, sandbox, monkeypatch):
    certs = os.path.join(sandbox.conf, "certs")
    os.mkdir(certs, 0o750)
    os.chown(certs, 0, sandbox.account_gid)
    real_rename = os.rename

    def attack(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        real_rename(certs, certs + ".moved")
        plant_dir(sandbox, certs)
        monkeypatch.setattr(resolver.os, "rename", real_rename)
        return real_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
    spec = resolver.Spec("dir", uid=0, gid=sandbox.account_gid, forbid=0o022)
    with open_conf(resolver, sandbox) as conf:
        with resolver.open_dir(conf, "certs", spec) as target:
            monkeypatch.setattr(resolver.os, "rename", attack)
            resolver.write_file(target, "remoted.pem", b"PEM\n", 0o640, 0, sandbox.account_gid)
    assert os.listdir(certs) == []
    assert os.listdir(certs + ".moved") == ["remoted.pem"]


def test_input_replaced_after_open(resolver, sandbox, monkeypatch):
    local = os.path.join(sandbox.conf, "local.env")
    sandbox.write(local, "A=original\n")
    evil = sandbox.write(os.path.join(sandbox.conf, "evil"), f"A={SECRET}\n")
    real_read = os.read
    swapped = []

    def attack(fd, size):
        if not swapped:
            swapped.append(1)
            os.rename(evil, local)
        return real_read(fd, size)
    monkeypatch.setattr(resolver.os, "read", attack)
    report = resolver.Report(quiet=True, out=io.StringIO(), err=io.StringIO())
    with open_conf(resolver, sandbox) as conf:
        lookup = resolver.build_lookup(sandbox.paths, conf, report, {})
    assert swapped and lookup.get("A")[0] == "original"


# ---------------------------------------------------------------- what root creates in <CONF>

@pytest.mark.parametrize("variant", ["account directory", "symlink to a root directory"])
def test_ca_preplanted(resolver, sandbox, variant):
    ca = os.path.join(sandbox.conf, "ca")
    if variant == "account directory":
        plant_dir(sandbox, ca)
    else:
        target = sandbox.path("root-dir")
        os.mkdir(target, 0o700)
        os.symlink(target, ca)
    before = os.lstat(ca)
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0                                   # --install never fails the package transaction...
    assert f"UNSAFE {ca}: " in err                     # ...but says why nothing was done
    after = os.lstat(ca)
    assert (after.st_uid, after.st_gid, after.st_mode) == (before.st_uid, before.st_gid, before.st_mode)


def test_ca_replaced_while_created(resolver, sandbox, monkeypatch):
    """The account swaps in its own directory between root's mkdir and open: refused, never chowned."""
    ca = os.path.join(sandbox.conf, "ca")
    real_mkdir = os.mkdir

    def attack(name, mode=0o777, *, dir_fd=None):
        real_mkdir(name, mode, dir_fd=dir_fd)
        if name == "ca":
            os.rename(ca, ca + ".root")
            plant_dir(sandbox, ca)
    monkeypatch.setattr(resolver.os, "mkdir", attack)
    with open_conf(resolver, sandbox) as conf:
        with pytest.raises(resolver.UnsafeEntry, match="replaced while it was being created"):
            resolver.acquire_lock(conf, timeout=0)
    assert os.lstat(ca).st_uid == sandbox.account_uid


@pytest.mark.parametrize("mode", ["--install", "--upgrade", "--prestart"])
def test_only_ca_is_created(resolver, sandbox, mode):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "A=1\n")
    before = set(os.listdir(sandbox.conf))
    code, _, _ = run(resolver, sandbox, mode)
    assert code == 0
    assert set(os.listdir(sandbox.conf)) - before == {"ca"}
    st = os.lstat(os.path.join(sandbox.conf, "ca"))
    assert stat.S_IMODE(st.st_mode) == 0o700 and (st.st_uid, st.st_gid) == (0, 0)
    assert not [n for n in os.listdir(sandbox.conf) if n.startswith(".")]
