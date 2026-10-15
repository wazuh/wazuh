# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The safe file-system primitives (rules 1-3 of #40339) and the specification of <CONF>: root's, the service
group's, never world-writable."""

import os
import stat

import pytest


def open_conf(resolver, sandbox):
    return resolver.open_top(sandbox.conf, resolver.conf_spec(sandbox.paths))


def test_read_regular_ok(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), b"A=1\n")
    with open_conf(resolver, sandbox) as conf:
        assert resolver.read_file(conf, "local.env", resolver.ROOT_FILE) == b"A=1\n"


def _symlink(sandbox, target_name):
    target = sandbox.write(sandbox.path("elsewhere"), b"A=1\n")
    os.symlink(target, os.path.join(sandbox.conf, target_name))


def _directory(sandbox, name):
    os.mkdir(os.path.join(sandbox.conf, name), 0o700)


def _fifo(sandbox, name):
    os.mkfifo(os.path.join(sandbox.conf, name), 0o600)


def _account_owned(sandbox, name):
    sandbox.plant(os.path.join(sandbox.conf, name), b"A=1\n", mode=0o600)


def _group_writable(sandbox, name):
    sandbox.write(os.path.join(sandbox.conf, name), b"A=1\n", mode=0o620)


def _world_writable(sandbox, name):
    sandbox.write(os.path.join(sandbox.conf, name), b"A=1\n", mode=0o602)


def _hardlink(sandbox, name):
    other = sandbox.write(sandbox.path("other"), b"A=1\n")
    os.link(other, os.path.join(sandbox.conf, name))


@pytest.mark.parametrize("make,reason", [
    (_symlink, "a symbolic link"),
    (_directory, "not a regular file"),
    (_fifo, "not a regular file"),
    (_account_owned, "owned by uid"),
    (_group_writable, "group-writable"),
    (_world_writable, "world-writable"),
    (_hardlink, "2 hard links"),
])
def test_read_refuses(resolver, sandbox, make, reason):
    make(sandbox, "local.env")
    with open_conf(resolver, sandbox) as conf:
        with pytest.raises(resolver.UnsafeEntry) as caught:
            resolver.read_file(conf, "local.env", resolver.ROOT_FILE)
    assert caught.value.path == os.path.join(sandbox.conf, "local.env")
    assert reason in caught.value.reason


def test_read_refuses_oversized(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), b"#" * (resolver.MAX_INPUT_SIZE + 1))
    with open_conf(resolver, sandbox) as conf:
        with pytest.raises(resolver.UnsafeEntry, match="larger than"):
            resolver.read_file(conf, "local.env", resolver.ROOT_FILE)


@pytest.mark.parametrize("mode,owner,group,link,expected", [
    (0o770, "root", "service", False, None),
    (0o1770, "root", "service", False, None),
    (0o750, "root", "service", False, "mode is 0750, missing 0020"),     # the daemons write in <CONF>
    (0o710, "root", "service", False, "mode is 0710, missing 0060"),
    (0o700, "root", "service", False, "mode is 0700, missing 0070"),     # nor could they reach certs/
    (0o777, "root", "service", False, "world-writable"),
    (0o770, "account", "service", False, "owned by uid"),
    (0o770, "root", "root", False, "group is root"),
    (0o770, "root", "service", True, "a symbolic link"),
])
def test_conf_spec(resolver, sandbox, mode, owner, group, link, expected):
    os.chmod(sandbox.conf, mode)
    os.chown(sandbox.conf, sandbox.account_uid if owner == "account" else 0,
             sandbox.account_gid if group == "service" else 0)
    target = sandbox.conf
    if link:
        real = sandbox.conf + ".real"
        os.rename(sandbox.conf, real)
        os.symlink(real, sandbox.conf)
        target = sandbox.conf
    if expected is None:
        open_conf(resolver, sandbox).close()
        return
    with pytest.raises(resolver.UnsafeEntry) as caught:
        open_conf(resolver, sandbox)
    assert caught.value.path == target and expected in caught.value.reason


def test_write_atomic_modes(resolver, sandbox):
    with open_conf(resolver, sandbox) as conf:
        resolver.write_file(conf, "out.pem", b"content\n", 0o640, 0, sandbox.account_gid)
    path = os.path.join(sandbox.conf, "out.pem")
    st = os.lstat(path)
    assert stat.S_IMODE(st.st_mode) == 0o640 and (st.st_uid, st.st_gid) == (0, sandbox.account_gid)
    assert open(path, "rb").read() == b"content\n"
    assert [n for n in os.listdir(sandbox.conf) if n.startswith(".out.pem.")] == []


def test_write_replaces_atomically(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "out.pem"), b"old\n", mode=0o644)
    with open_conf(resolver, sandbox) as conf:
        resolver.write_file(conf, "out.pem", b"new\n", 0o600, 0, 0)
    st = os.lstat(os.path.join(sandbox.conf, "out.pem"))
    assert stat.S_IMODE(st.st_mode) == 0o600
    assert open(os.path.join(sandbox.conf, "out.pem"), "rb").read() == b"new\n"


def test_write_refuses_swapped_dir(resolver, sandbox):
    """The target directory is replaced by a symlink after it was opened: the write still lands in the directory
    that was opened and checked, never at the symlink's target."""
    with open_conf(resolver, sandbox) as conf:
        target = resolver.ensure_dir(conf, "export", resolver.Spec("dir", uid=0, gid=0, mode=0o700))
        elsewhere = sandbox.path("elsewhere")
        os.mkdir(elsewhere, 0o777)
        os.rename(os.path.join(sandbox.conf, "export"), os.path.join(sandbox.conf, "export.moved"))
        os.symlink(elsewhere, os.path.join(sandbox.conf, "export"))
        with target:
            resolver.write_file(target, "credentials.env", b"K=v\n", 0o600, 0, 0)
    assert os.listdir(elsewhere) == []
    assert os.listdir(os.path.join(sandbox.conf, "export.moved")) == ["credentials.env"]


def test_write_cleans_temp_on_error(resolver, sandbox, monkeypatch):
    sandbox.write(os.path.join(sandbox.conf, "out.pem"), b"old\n", mode=0o644)

    def fail(*args):
        raise PermissionError(1, "Operation not permitted")
    with open_conf(resolver, sandbox) as conf:
        monkeypatch.setattr(resolver.os, "fchown", fail)
        with pytest.raises(PermissionError):
            resolver.write_file(conf, "out.pem", b"new\n", 0o640, 0, 0)
    assert [n for n in os.listdir(sandbox.conf) if n.startswith(".out.pem.")] == []
    assert open(os.path.join(sandbox.conf, "out.pem"), "rb").read() == b"old\n"


def test_ensure_dir_by_fd(resolver, sandbox):
    spec = resolver.Spec("dir", uid=0, gid=0, mode=0o700)
    with open_conf(resolver, sandbox) as conf:
        resolver.ensure_dir(conf, "ca", spec).close()
        st = os.lstat(os.path.join(sandbox.conf, "ca"))
        assert stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700 and (st.st_uid, st.st_gid) == (0, 0)
        resolver.ensure_dir(conf, "ca", spec).close()          # present and right: accepted
        os.chmod(os.path.join(sandbox.conf, "ca"), 0o755)
        with pytest.raises(resolver.UnsafeEntry, match="mode is 0755"):
            resolver.ensure_dir(conf, "ca", spec)
    assert stat.S_IMODE(os.lstat(os.path.join(sandbox.conf, "ca")).st_mode) == 0o755   # not repaired


def test_remove_entry_never_follows(resolver, sandbox):
    target = sandbox.write(sandbox.path("keep"), b"x")
    os.symlink(target, os.path.join(sandbox.conf, "link"))
    with open_conf(resolver, sandbox) as conf:
        assert resolver.remove_entry(conf, "link") is True
        assert resolver.remove_entry(conf, "link") is False
    assert os.path.exists(target)


@pytest.mark.parametrize("mode,expected", [
    (0o750, None),
    (0o700, "mode is 0700, not 0750"),               # the daemons could not open the pairs
    (0o710, "mode is 0710, not 0750"),
    (0o740, "mode is 0740, not 0750"),
    (0o755, "mode is 0755, not 0750"),
])
def test_certs_spec(resolver, sandbox, mode, expected):
    """certs/ is exactly 0750: the service group opens its files by name and never writes there."""
    os.chmod(sandbox.certs, mode)
    with open_conf(resolver, sandbox) as conf:
        if expected is None:
            resolver.open_dir(conf, "certs", resolver.certs_spec(sandbox.paths)).close()
            return
        with pytest.raises(resolver.UnsafeEntry, match=expected):
            resolver.open_dir(conf, "certs", resolver.certs_spec(sandbox.paths))

