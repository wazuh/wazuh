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
import json
import importlib.machinery
import importlib.util
import os
import pwd
import shutil
import stat
import sys
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


# Stand-ins for the three Wazuh programs the resolver drives. They read their behaviour from <home>/stub-control.json
# and record what they were given, so tests can assert on it. Values on stdin are recorded too: the stubs are the
# only place a test may look at a password.
KEYSTORE_STUB = """
import json, os, sys
home = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
control = json.load(open(os.path.join(home, "stub-control.json")))
store_path = os.path.join(home, "keystore.json")
store = json.load(open(store_path)) if os.path.exists(store_path) else {}
args = sys.argv[1:]
family, key, get = args[args.index("-f") + 1], args[args.index("-k") + 1], "-g" in args
entry = f"{family}/{key}"
if get:
    if store.get(entry):
        print(store[entry])
        sys.exit(0)
    sys.exit(1)
if control.get("keystore_fail"):
    print("Error storing the value.", file=sys.stderr)
    sys.exit(1)
value = sys.stdin.readline().rstrip("\\n")
if not value:
    print("Error reading from stdin.", file=sys.stderr)
    sys.exit(1)
store[entry] = value
json.dump(store, open(store_path, "w"))
"""

CONF_STUB = """
import json, os, sys
home = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
control = json.load(open(os.path.join(home, "stub-control.json")))
with open(os.path.join(home, "conf-calls.log"), "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
code = control.get("conf_exit", 0)
if code == 0:
    print(control.get("role", "master"))
sys.exit(code)
"""

RBAC_STUB = """
import json, os, sys
home = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))))
control_path = os.path.join(home, "stub-control.json")
control = json.load(open(control_path))
assert sys.argv[1:] == ["seed", "--passwords-file", "-"], sys.argv
received = json.loads(sys.stdin.read())
with open(os.path.join(home, "seed-calls.json"), "a") as log:
    log.write(json.dumps(received) + "\\n")
if control.get("rbac_fail_times", 0) > 0:
    control["rbac_fail_times"] -= 1
    json.dump(control, open(control_path, "w"))
    print("\\tInternal error: database is locked")
    sys.exit(1)
db = os.path.join(home, "api", "configuration", "security", "rbac.db")
os.makedirs(os.path.dirname(db), exist_ok=True)
with open(db, "w") as handle:
    handle.write("seeded")
print(f"\\t{db} created")
"""


def install_stubs(sandbox):
    """Put the three stand-ins where Paths expects the real programs."""
    home = sandbox.home
    for directory in ("bin", "framework/python/bin", "framework/scripts"):
        os.makedirs(os.path.join(home, directory), exist_ok=True)
    shebang = f"#!{sys.executable} -I\n"
    sandbox.write(os.path.join(home, "bin", "wazuh-manager-keystore"), shebang + KEYSTORE_STUB, mode=0o750)
    sandbox.write(os.path.join(home, "bin", "wazuh-manager-conf"), shebang + CONF_STUB, mode=0o750)
    os.symlink(sys.executable, os.path.join(home, "framework", "python", "bin", "python3"))
    sandbox.write(os.path.join(home, "framework", "scripts", "rbac_control.py"), RBAC_STUB, mode=0o640)
    sandbox.control()


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
        install_stubs(self)

    def control(self, **settings):
        """Set the stubs' behaviour: role, conf_exit, keystore_fail, rbac_fail_times."""
        with open(os.path.join(self.home, "stub-control.json"), "w") as handle:
            json.dump(settings, handle)

    def keystore(self):
        path = os.path.join(self.home, "keystore.json")
        return json.load(open(path)) if os.path.exists(path) else {}

    def seed_calls(self):
        path = os.path.join(self.home, "seed-calls.json")
        return [json.loads(line) for line in open(path)] if os.path.exists(path) else []

    def conf_calls(self):
        path = os.path.join(self.home, "conf-calls.log")
        return [json.loads(line) for line in open(path)] if os.path.exists(path) else []

    @property
    def rbac_db(self):
        return os.path.join(self.home, "api", "configuration", "security", "rbac.db")

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
