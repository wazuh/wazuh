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
import importlib.machinery
import importlib.util
import os
import pwd
import shutil
import stat
import tempfile

import pytest

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
        self.paths = resolver.Paths(home=self.home, conf=self.conf, indexer_export=self.indexer_export,
                                    service_user=ACCOUNT, service_group=ACCOUNT)

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


@pytest.fixture
def sandbox(resolver):
    base = tempfile.mkdtemp(prefix="wazuh-resolver-tests.", dir="/root")
    os.chmod(base, 0o700)
    try:
        yield Sandbox(resolver, base)
    finally:
        shutil.rmtree(base, ignore_errors=True)
