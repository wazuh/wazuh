#!/var/wazuh-manager/framework/python/bin/python3 -I
# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# wazuh-manager-resolve-credentials: sets up the manager's passwords and trust material at
# installation and checks them before every start. Runs as root, on the bundled interpreter, in
# isolated mode (-I: no user site, no PYTHON* variables, no script directory on sys.path), with the
# standard library and `cryptography` only. It calls no host tool and never touches /etc/wazuh.
#
# This must stay the first statement: OpenSSL probes the CPU when its library loads, and some arm64
# hypervisors advertise SVE they do not implement, so the probe dies with SIGILL. Every other Python
# entry point gets the same guard from framework/wrappers/generic_wrapper.sh; this one has no wrapper,
# and `secrets` (through `hmac`) or `cryptography` would load OpenSSL on import.
import os
os.environ["OPENSSL_armcap"] = "0"

import argparse  # noqa: E402
import dataclasses  # noqa: E402
import datetime  # noqa: E402
import errno  # noqa: E402
import fcntl  # noqa: E402
import grp  # noqa: E402
import hashlib  # noqa: E402
import io  # noqa: E402
import ipaddress  # noqa: E402
import json  # noqa: E402
import pwd  # noqa: E402
import re  # noqa: E402
import secrets  # noqa: E402
import socket  # noqa: E402
import stat  # noqa: E402
import struct  # noqa: E402
# Only Wazuh's own programs are run, by absolute path, with a fixed argv and an empty environment.
import subprocess  # noqa: E402 # nosec B404
import sys  # noqa: E402
import time  # noqa: E402
from typing import Dict, List, Mapping, Optional, Tuple  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402
from cryptography.x509.verification import (Criticality, ExtensionPolicy, PolicyBuilder, Store,  # noqa: E402
                                            VerificationError)

# ================================================== Constants ==================================================

# The manager's configuration directory. Fixed: a custom installation home moves the home only. Kept identical
# with WAZUH_MANAGER_CONF_DIR in src/shared/include/defs.h, Utils::MANAGER_CONF_DIR in
# src/shared_modules/utils/managerConfDir.hpp, the engine's base/managerConfig.hpp, MANAGER_CONF_DIR in
# framework/wazuh/core/common.py (its CONF_PATH is computed, and points into a source tree when run from one) and
# CONF_DIR in src/init/shared.sh. tests/test_framework_parity.py holds it equal to MANAGER_CONF_DIR.
CONF_DIR = "/etc/wazuh-manager"
DEFAULT_HOME = "/var/wazuh-manager"
# What the indexer publishes for its consumers on this host (read only).
INDEXER_EXPORT_DIR = "/etc/wazuh-indexer/export"
SERVICE_USER = "wazuh-manager"
SERVICE_GROUP = "wazuh-manager"

LOCAL_ENV = "local.env"
CA_DIR = "ca"
EXPORT_DIR = "export"
CERTS_DIR = "certs"
CREDENTIALS_ENV = "credentials.env"

# Only WAZUH_INDEXER_MANAGER_PASSWORD may come from the indexer's export.
INDEXER_EXPORTED = frozenset({"WAZUH_INDEXER_MANAGER_PASSWORD"})

# No input file root reads is larger than this; a bigger one is refused rather than read.
MAX_INPUT_SIZE = 64 * 1024
# How long a writing run waits for another one to release the lock on <CONF>/ca.
LOCK_TIMEOUT = 60.0
LOCK_POLL = 0.2
SUBPROCESS_TIMEOUT = 60
# The exact environment of every subprocess: nothing inherited.
SUBPROCESS_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

LOG_TAG = "resolve-credentials"
MODES = ("install", "upgrade", "prestart", "check", "clear")

API_VAR = "WAZUH_MANAGER_API_PASSWORD"          # user `wazuh` (ID 1)
WUI_VAR = "WAZUH_MANAGER_WUI_PASSWORD"          # user `wazuh-internal-client` (ID 2), the dashboard's
INDEXER_VAR = "WAZUH_INDEXER_MANAGER_PASSWORD"  # stored in the keystore, never generated
API_USERS = {API_VAR: "wazuh", WUI_VAR: "wazuh-internal-client"}
INDEXER_USERNAME = "wazuh-manager"

# The alphabet the three central packages share for passwords: what they generate and what they accept when one
# is supplied. Every value it allows also meets the Server API's own rule (framework/wazuh/security.py).
CHARS_LOWER = "abcdefghijklmnopqrstuvwxyz"
CHARS_UPPER = CHARS_LOWER.upper()
CHARS_DIGITS = "0123456789"
CHARS_SYMBOLS = ".,_+:@%^=~-"
PASSWORD_ALPHABET = CHARS_UPPER + CHARS_LOWER + CHARS_DIGITS + CHARS_SYMBOLS
PASSWORD_LENGTH = 32
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 64
PUBLISHED_HEADER = "# Published by wazuh-manager. Read by the dashboard on this host. Do not edit."

CA_CERT = "root-ca.pem"
CA_KEY = "root-ca.key"
# Present only when this installation minted the CA: --clear removes a CA it minted, never one staged by the operator.
CA_MARKER = ".wazuh-manager-bootstrap-ca"
EXPORT_CA = "ca.pem"
DASHBOARD_CERT = "dashboard-client.pem"            # export/: a client pair for the dashboard to import later
DASHBOARD_KEY = "dashboard-client-key.pem"
DASHBOARD_MARKER = ".dashboard-client.issued"      # fingerprints of the pair the resolver wrote
DASHBOARD_CN = "wazuh-dashboard"
BUNDLE = "root-ca.pem"                    # certs/root-ca.pem: the agents' CA bundle, which remoted serves
SERVER_PAIR_FILES = ("remoted.pem", "remoted-key.pem", "apid.pem", "apid-key.pem")
NODE_NAME_VAR = "WAZUH_MANAGER_NODE_NAME"
CA_COMMON_NAME_PREFIX = "wazuh-manager-"
COMMON_NAME_MAX = 64                       # X.520 ub-common-name: what cryptography accepts in a CN
CERT_VALIDITY_DAYS = 3650
CERT_BACKDATE = datetime.timedelta(days=1)
REMOTED_SANS_VAR = "WAZUH_MANAGER_REMOTED_CERT_SANS"   # the agent listener's pair
APID_SANS_VAR = "WAZUH_MANAGER_APID_CERT_SANS"         # the Server API's pair; never inherits remoted's list
OLD_SANS_VAR = "WAZUH_MANAGER_CERT_SANS"               # named the indexer pair, which the manager no longer issues
# The indexer's CA and the client pair it issues for this manager: their names in certs/, the import markers, and
# the files the indexer publishes in its export/.
INDEXER_CA = "indexer-ca.pem"
CONNECTOR = "indexer-connector.pem"
CONNECTOR_KEY = "indexer-connector-key.pem"
INDEXER_CA_MARKER = ".indexer-ca.imported"
CONNECTOR_MARKER = ".indexer-connector.imported"
SOURCE_CA = "ca.pem"
SOURCE_CLIENT = "manager-client.pem"
SOURCE_CLIENT_KEY = "manager-client-key.pem"
# Interface addresses: one RTM_GETADDR dump over NETLINK_ROUTE, the request `ip -o addr show` makes. socket exports
# none of these numbers (linux/netlink.h, linux/rtnetlink.h, linux/if_addr.h).
NLMSG_ERROR, NLMSG_DONE = 2, 3
RTM_NEWADDR, RTM_GETADDR = 20, 22
NLM_F_REQUEST, NLM_F_DUMP = 0x1, 0x300
IFA_ADDRESS, IFA_LOCAL, IFA_FLAGS = 1, 2, 8
RT_SCOPE_UNIVERSE = 0                                   # what `ip` prints as "scope global"
NLMSG_HEADER = struct.Struct("=LHHLL")                  # length, type, flags, sequence, port
IFADDRMSG = struct.Struct("=BBBBI")                     # family, prefix length, flags, scope, interface index
RTATTR = struct.Struct("=HH")                           # length, type
NETLINK_REPLY_MAX = 1 << 20                             # bytes of one dump's reply; hundreds of addresses fit
NETLINK_TIMEOUT = 5                                     # seconds for each part of the reply
# Address flags (ifa_flags, or IFA_FLAGS when present) of addresses a certificate must not name.
IFA_F_DEPRECATED, IFA_F_TENTATIVE, IFA_F_DADFAILED = 0x20, 0x40, 0x08

# Chain building for a pair whose leaf an intermediate CA issued. The WebPKI defaults of x509.verification would
# also demand an authorityKeyIdentifier and a subjectAltName, which the client certificates of other tooling may
# lack; the verifier is only asked to build the path (signatures, validity windows, CA:TRUE, path lengths). What
# the resolver requires of the leaf, and keyCertSign on every CA of the path, it checks itself.
CHAIN_CA_POLICY = ExtensionPolicy.permit_all().require_present(x509.BasicConstraints, Criticality.AGNOSTIC, None)
CHAIN_LEAF_POLICY = ExtensionPolicy.permit_all()
PURPOSE_NAMES = {ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth", ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth"}

MISSING = "MISSING"
INVALID = "INVALID"
UNSAFE = "UNSAFE"

# ================================================== Paths ======================================================


@dataclasses.dataclass(frozen=True)
class Paths:
    """Every location the resolver uses. `main()` takes one so that tests can point it at a private tree; there
    is deliberately no command-line option or environment variable for the configuration directory."""

    home: str = DEFAULT_HOME
    conf: str = CONF_DIR
    indexer_export: str = INDEXER_EXPORT_DIR
    service_user: str = SERVICE_USER
    service_group: str = SERVICE_GROUP
    proc: str = "/proc"

    @property
    def keystore_bin(self) -> str:
        return os.path.join(self.home, "bin", "wazuh-manager-keystore")

    @property
    def conf_bin(self) -> str:
        return os.path.join(self.home, "bin", "wazuh-manager-conf")

    @property
    def python_bin(self) -> str:
        return os.path.join(self.home, "framework", "python", "bin", "python3")

    @property
    def rbac_control_script(self) -> str:
        return os.path.join(self.home, "framework", "scripts", "rbac_control.py")

    @property
    def rbac_db(self) -> str:
        return os.path.join(self.home, "api", "configuration", "security", "rbac.db")

    @property
    def keystore_dir(self) -> str:
        return os.path.join(self.home, "queue", "keystore")

    @property
    def run_dir(self) -> str:
        return os.path.join(self.home, "var", "run")

    def service_gid(self) -> int:
        """Return the service group's gid.

        Raises
        ------
        KeyError
            The group does not exist.
        """
        return grp.getgrnam(self.service_group).gr_gid

    def service_uid(self) -> int:
        return pwd.getpwnam(self.service_user).pw_uid


# ================================================== Report =====================================================


class Report:
    """Progress lines go to stdout, prefixed, and `-q` drops them. Each problem is one line on stderr,
    `MISSING|INVALID|UNSAFE <path or variable>: <reason>`, printed once, in the order found. No line ever carries
    a secret value: callers pass paths, variable names and rules only."""

    def __init__(self, quiet: bool = False, out=None, err=None):
        self.quiet = quiet
        self.out = out if out is not None else sys.stdout
        self.err = err if err is not None else sys.stderr
        self.problems: List[Tuple[str, str, str]] = []
        self.warnings: List[str] = []

    def progress(self, message: str) -> None:
        if not self.quiet:
            print(f"{LOG_TAG}: {message}", file=self.out, flush=True)

    def warning(self, message: str) -> None:
        """A warning stops nothing and does not change the exit status; each one is printed once."""
        if message in self.warnings:
            return
        self.warnings.append(message)
        print(f"{LOG_TAG}: WARNING: {message}", file=self.err, flush=True)

    def problem(self, kind: str, subject: str, reason: str) -> None:
        entry = (kind, subject, reason)
        if entry in self.problems:
            return
        self.problems.append(entry)
        print(f"{kind} {subject}: {reason}", file=self.err, flush=True)

    def unsafe(self, exc: "UnsafeEntry") -> None:
        self.problem(UNSAFE, exc.path, exc.reason)

    def has(self, *kinds: str) -> bool:
        return any(kind in kinds for kind, _, _ in self.problems) if kinds else bool(self.problems)

    def exit_code(self, mode: str) -> int:
        """--install and --upgrade never fail the package transaction; --check and --prestart fail on any
        problem."""
        if mode in ("install", "upgrade"):
            return 0
        return 1 if self.problems else 0


# ============================================ Safe file-system layer ============================================
#
# Everything below <CONF> and the indexer's export is reached through a descriptor of its parent, opened with
# O_NOFOLLOW and checked with fstat on that descriptor. Each entry is resolved by name once per run; after that it
# is used only through its own descriptor, so renaming it later redirects nothing. Nothing is ever repaired,
# chowned or followed: anything that does not match its specification is reported as UNSAFE.


class UnsafeEntry(Exception):
    """An entry that does not meet its specification. Carries the path to report and the reason."""

    def __init__(self, path: str, reason: str):
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


class LockTimeout(Exception):
    """Another run holds the lock."""


@dataclasses.dataclass(frozen=True)
class Spec:
    """What an entry must be.

    kind: "dir" or "file". uid: owner, or None for any. gid: exact group, or None for any. mode: exact permission
    bits, or None. forbid: permission bits that must be clear (default: group and other write). require: permission
    bits that must be set, for a directory the daemons have to reach. For files, the link count must be 1, so a hard
    link to another file cannot pass for this one.
    """

    kind: str
    uid: Optional[int] = 0
    gid: Optional[int] = None
    mode: Optional[int] = None
    forbid: int = 0o022
    require: int = 0


def _group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def check_stat(st: os.stat_result, spec: Spec, path: str) -> None:
    """Raise UnsafeEntry when `st` does not meet `spec`."""
    if spec.kind == "dir" and not stat.S_ISDIR(st.st_mode):
        raise UnsafeEntry(path, "not a directory")
    if spec.kind == "file" and not stat.S_ISREG(st.st_mode):
        raise UnsafeEntry(path, "not a regular file")
    if spec.uid is not None and st.st_uid != spec.uid:
        raise UnsafeEntry(path, f"owned by uid {st.st_uid}, not by {'root' if spec.uid == 0 else spec.uid}")
    if spec.gid is not None and st.st_gid != spec.gid:
        raise UnsafeEntry(path, f"group is {_group_name(st.st_gid)}, not {_group_name(spec.gid)}")
    perms = stat.S_IMODE(st.st_mode)
    if spec.mode is not None and perms != spec.mode:
        raise UnsafeEntry(path, f"mode is {perms:04o}, not {spec.mode:04o}")
    missing = spec.require & ~perms
    if missing:
        raise UnsafeEntry(path, f"mode is {perms:04o}, missing {missing:04o}")
    violated = perms & spec.forbid
    if violated & 0o002:
        raise UnsafeEntry(path, "world-writable")
    if violated & 0o020:
        raise UnsafeEntry(path, "group-writable")
    if violated:
        raise UnsafeEntry(path, "readable by others than root")
    if spec.kind == "file" and st.st_nlink != 1:
        raise UnsafeEntry(path, f"has {st.st_nlink} hard links")


class Dir:
    """An open, checked directory: its descriptor and the path used in messages."""

    def __init__(self, fd: int, path: str, st: os.stat_result):
        self.fd = fd
        self.path = path
        self.st = st

    def child(self, name: str) -> str:
        return os.path.join(self.path, name)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "Dir":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_dir_fd(name: str, dir_fd: Optional[int], path: str) -> int:
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafeEntry(path, "a symbolic link") from None
        if exc.errno == errno.ENOTDIR:
            # O_DIRECTORY|O_NOFOLLOW on a symbolic link fails with ENOTDIR, not ELOOP. Tell the two apart for the
            # message only: the entry is refused either way and never followed.
            raise UnsafeEntry(path, "a symbolic link" if _is_symlink(name, dir_fd) else "not a directory") from None
        raise


def _is_symlink(name: str, dir_fd: Optional[int]) -> bool:
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def open_top(path: str, spec: Spec) -> Dir:
    """Open an absolute directory (<CONF>, the indexer's export) as the root of a walk.

    Raises
    ------
    FileNotFoundError
        It does not exist.
    UnsafeEntry
        It is a symbolic link or does not meet `spec`.
    """
    fd = _open_dir_fd(path, None, path)
    try:
        st = os.fstat(fd)
        check_stat(st, spec, path)
    except BaseException:
        os.close(fd)
        raise
    return Dir(fd, path, st)


def open_dir(parent: Dir, name: str, spec: Spec) -> Dir:
    """Open `name` below `parent` without following a link, and check it.

    Raises
    ------
    FileNotFoundError
        It does not exist.
    UnsafeEntry
        It is not a directory meeting `spec`.
    """
    path = parent.child(name)
    fd = _open_dir_fd(name, parent.fd, path)
    try:
        st = os.fstat(fd)
        check_stat(st, spec, path)
    except BaseException:
        os.close(fd)
        raise
    return Dir(fd, path, st)


def read_file(parent: Dir, name: str, spec: Spec, limit: int = MAX_INPUT_SIZE) -> bytes:
    """Read a whole file below `parent` that meets `spec` (rule 1). Never blocks on a FIFO, never follows a link,
    never reads more than `limit` bytes.

    Raises
    ------
    FileNotFoundError
        It does not exist.
    UnsafeEntry
        It does not meet `spec` or is larger than `limit`.
    """
    path = parent.child(name)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent.fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafeEntry(path, "a symbolic link") from None
        if exc.errno in (errno.ENXIO, errno.EOPNOTSUPP):
            raise UnsafeEntry(path, "not a regular file") from None
        raise
    try:
        st = os.fstat(fd)
        check_stat(st, spec, path)
        chunks = []
        size = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise UnsafeEntry(path, f"larger than {limit} bytes")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_file(parent: Dir, name: str, data: bytes, mode: int, uid: int, gid: int) -> None:
    """Replace `name` below `parent` atomically (rule 2): a new temporary created with O_EXCL in that same
    directory, owner and mode set through its descriptor before any content, written, synced, then renamed over
    the target through the directory's descriptor. On any failure the temporary is removed and the target is
    left as it was. `parent` must come from open_top/open_dir/ensure_dir, so it is a checked root directory."""
    tmp = f".{name}.{os.urandom(8).hex()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent.fd)
    try:
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=parent.fd)
        except OSError:
            pass
        raise
    os.fsync(parent.fd)


def ensure_dir(parent: Dir, name: str, spec: Spec) -> Dir:
    """Return `name` below `parent`, creating it when absent (rule 3). A directory this call creates gets its
    owner and mode through its own descriptor, after checking that it is still the empty root-owned directory
    just made; an existing one must already meet `spec` and is never repaired.

    Raises
    ------
    UnsafeEntry
        The existing entry, or what replaced the new one before it was opened, does not meet `spec`.
    """
    path = parent.child(name)
    try:
        os.mkdir(name, 0o700, dir_fd=parent.fd)
        created = True
    except FileExistsError:
        created = False
    fd = _open_dir_fd(name, parent.fd, path)
    try:
        st = os.fstat(fd)
        if created:
            # Root made it a moment ago. Anything else under that name now was planted in between.
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or os.listdir(fd):
                raise UnsafeEntry(path, "replaced while it was being created")
            os.fchown(fd, spec.uid, spec.gid if spec.gid is not None else 0)
            if spec.mode is not None:
                os.fchmod(fd, spec.mode)
            st = os.fstat(fd)
        check_stat(st, spec, path)
    except BaseException:
        os.close(fd)
        raise
    return Dir(fd, path, st)


def remove_entry(parent: Dir, name: str) -> bool:
    """Unlink `name` below `parent`; a symbolic link is removed, never followed. Return whether it existed."""
    try:
        os.unlink(name, dir_fd=parent.fd)
        return True
    except FileNotFoundError:
        return False


# ================================================ .env and lookup ==============================================


class EnvSyntaxError(Exception):
    """A line of a .env file that is not `NAME=value`. Carries the path and line number, never the line."""

    def __init__(self, path: str, line: int):
        super().__init__(f"{path}:{line}")
        self.path = path
        self.line = line


_ENV_LINE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", re.DOTALL)


def parse_env(data: bytes, path: str) -> Dict[str, Tuple[str, int]]:
    """Parse `NAME=value` lines: surrounding whitespace trimmed, `#` comments and blank lines skipped, one pair of
    matching surrounding double or single quotes stripped, nothing expanded or unescaped. Any other line, an
    unbalanced quote, or a name given twice is an error naming the file and line.

    Returns
    -------
    dict
        name -> (value, line number).

    Raises
    ------
    EnvSyntaxError
    """
    values: Dict[str, Tuple[str, int]] = {}
    for number, raw in enumerate(data.split(b"\n"), start=1):
        try:
            line = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise EnvSyntaxError(path, number) from None
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.fullmatch(line)
        if not match:
            raise EnvSyntaxError(path, number)
        name, value = match.group(1), match.group(2)
        if value[:1] in ("'", '"') or value[-1:] in ("'", '"'):
            if len(value) < 2 or value[0] != value[-1]:
                raise EnvSyntaxError(path, number)
            value = value[1:-1]
        if name in values:
            raise EnvSyntaxError(path, number)
        values[name] = (value, number)
    return values


class Lookup:
    """Where a value comes from, first hit wins: the process environment, then <CONF>/local.env, then the
    indexer's export (WAZUH_INDEXER_MANAGER_PASSWORD only)."""

    def __init__(self, environ: Mapping[str, str], local: Optional[Dict[str, Tuple[str, int]]],
                 indexer: Optional[Dict[str, Tuple[str, int]]], local_path: str, indexer_path: str):
        self.environ = environ
        # An absent file contributes an empty dict; None means the entire input was rejected.
        self.local_accepted = local is not None
        self.inputs_accepted = self.local_accepted and indexer is not None
        self.local = local or {}
        self.indexer = indexer or {}
        self.local_path = local_path
        self.indexer_path = indexer_path

    def get(self, name: str, empty_is_unset: bool = True) -> Optional[Tuple[str, str]]:
        """Return (value, source) or None. `source` names the environment or the file, for messages."""
        if name in self.environ and (self.environ[name] or not empty_is_unset):
            return self.environ[name], "the environment"
        if not self.local_accepted:
            return None  # Never fall through a rejected override file to the indexer export.
        if name in self.local and (self.local[name][0] or not empty_is_unset):
            return self.local[name][0], f"{self.local_path}:{self.local[name][1]}"
        if name in INDEXER_EXPORTED and name in self.indexer and (self.indexer[name][0] or not empty_is_unset):
            return self.indexer[name][0], f"{self.indexer_path}:{self.indexer[name][1]}"
        return None


def conf_spec(paths: Paths) -> Spec:
    """<CONF> is root:<service group>, group-writable by design (authd, remoted and the API write there), never
    world-writable. Being group-writable is the documented exception to rule 1 of #40339: nothing in it is
    trusted unless it is root's and meets its own specification. The group must keep rwx: without them the daemons
    can neither write there nor reach certs/ (0770 as installed; 1770 passes too)."""
    return Spec("dir", uid=0, gid=paths.service_gid(), forbid=0o002, require=0o070)


ROOT_FILE = Spec("file")                    # rule 1: root's, not group/world-writable, one link
PRIVATE_FILE = Spec("file", forbid=0o077)   # a secret: root's, no group or other bit at all (0600 or 0400)
INDEXER_EXPORT = Spec("dir")                # root-owned, any group (wazuh-indexer), not group/world-writable


def open_conf(paths: Paths, report: Report) -> Optional[Dir]:
    """Open and check <CONF>; report and return None when it cannot be trusted."""
    try:
        return open_top(paths.conf, conf_spec(paths))
    except UnsafeEntry as exc:
        report.unsafe(exc)
    except KeyError:
        report.problem(INVALID, paths.conf, f"the group {paths.service_group} does not exist")
    except FileNotFoundError:
        report.problem(INVALID, paths.conf, "no such directory")
    return None


def load_env_file(parent: Dir, name: str, report: Report) -> Optional[Dict[str, Tuple[str, int]]]:
    """Read and parse one .env file below `parent`: a secret, so root's with no group or other bit. An absent
    file returns {}; an unsafe or malformed one is reported and returns None. Rejected input must never be treated
    as permission to generate defaults."""
    try:
        data = read_file(parent, name, PRIVATE_FILE)
    except FileNotFoundError:
        return {}
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return None
    try:
        return parse_env(data, parent.child(name))
    except EnvSyntaxError as exc:
        report.problem(INVALID, f"{exc.path}:{exc.line}", "not a NAME=value line")
        return None


def load_indexer_env(paths: Paths, report: Report) -> Optional[Dict[str, Tuple[str, int]]]:
    """The indexer's export/credentials.env, when the indexer is on this host."""
    try:
        export = open_top(paths.indexer_export, INDEXER_EXPORT)
    except FileNotFoundError:
        return {}
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return None
    with export:
        return load_env_file(export, CREDENTIALS_ENV, report)


def build_lookup(paths: Paths, conf: Dir, report: Report, environ: Mapping[str, str]) -> Lookup:
    local = load_env_file(conf, LOCAL_ENV, report)
    indexer = load_indexer_env(paths, report)
    return Lookup(environ, local, indexer, os.path.join(paths.conf, LOCAL_ENV),
                  os.path.join(paths.indexer_export, CREDENTIALS_ENV))


# ============================================= Wazuh subprocesses ==============================================


def subprocess_env(paths: Paths) -> Dict[str, str]:
    """The whole environment of a subprocess: nothing is inherited from the caller."""
    return {"WAZUH_MANAGER_HOME": paths.home, "OPENSSL_armcap": "0", "PATH": SUBPROCESS_PATH, "LC_ALL": "C"}


def run_wazuh(paths: Paths, argv: List[str], stdin: Optional[bytes] = None,
              want_stdout: bool = False) -> subprocess.CompletedProcess:
    """Run one of Wazuh's own programs. Secrets travel on stdin only; stdout is discarded unless asked for (the
    keystore prints a stored secret on `-g`)."""
    if not os.path.isabs(argv[0]):
        raise ValueError("run_wazuh needs an absolute program path")
    # A fixed argv of Wazuh's own binaries, never a shell.
    return subprocess.run(  # nosec B603
        argv, input=stdin if stdin is not None else b"", stdout=subprocess.PIPE if want_stdout else subprocess.DEVNULL,
        stderr=subprocess.PIPE, env=subprocess_env(paths), cwd="/", close_fds=True, timeout=SUBPROCESS_TIMEOUT,
        check=False)


# ================================================== Passwords ==================================================


def generate_password() -> str:
    """32 characters from the shared alphabet with each of the four classes present, from `secrets`."""
    rng = secrets.SystemRandom()
    chars = [secrets.choice(PASSWORD_ALPHABET) for _ in range(PASSWORD_LENGTH)]
    for position, pool in zip(rng.sample(range(PASSWORD_LENGTH), 4),
                              (CHARS_LOWER, CHARS_UPPER, CHARS_DIGITS, CHARS_SYMBOLS)):
        chars[position] = secrets.choice(pool)
    password = "".join(chars)
    if password_problem(password) is not None:  # Impossible by construction; never hand out a bad one.
        raise RuntimeError("generated password does not meet the policy")
    return password


def password_problem(value: str) -> Optional[str]:
    """Return the rule a supplied password breaks, or None. The text never includes the value."""
    if not PASSWORD_MIN_LENGTH <= len(value) <= PASSWORD_MAX_LENGTH:
        return f"must be {PASSWORD_MIN_LENGTH} to {PASSWORD_MAX_LENGTH} characters"
    if any(char not in PASSWORD_ALPHABET for char in value):
        return f"may only use A-Z a-z 0-9 and {' '.join(CHARS_SYMBOLS)}"
    if not all(any(char in pool for char in value)
               for pool in (CHARS_LOWER, CHARS_UPPER, CHARS_DIGITS, CHARS_SYMBOLS)):
        return f"needs a lowercase letter, an uppercase letter, a digit and one of {' '.join(CHARS_SYMBOLS)}"
    return None


def supplied_password(lookup: Lookup, name: str, report: Report) -> Tuple[str, Optional[str], str]:
    """The value the lookup supplies for `name`.

    Returns
    -------
    tuple
        (state, value, source) with state "absent", "invalid" or "ok". An invalid value is reported once, naming the
        rule and where it came from, and is never replaced by a generated one.
    """
    found = lookup.get(name)
    if found is None:
        return "absent", None, ""
    value, source = found
    rule = password_problem(value)
    if rule is not None:
        report.problem(INVALID, name, f"{rule} (set in {source})")
        return "invalid", None, source
    return "ok", value, source


def validate_supplied(lookup: Lookup, report: Report) -> None:
    """--check's and every mode's test of the supplied passwords: the value each lookup would use. No subprocess,
    so neither the node's role nor the keystore is consulted."""
    for name in (API_VAR, WUI_VAR, INDEXER_VAR):
        supplied_password(lookup, name, report)


# ================================================ Server API passwords ==========================================

EXPORT_SPEC = Spec("dir", uid=0, gid=0, mode=0o700)


def rbac_seeded(paths: Paths) -> bool:
    """The test rbac_control and apid apply: rbac.db exists and is not empty (an empty file is a failed creation)."""
    try:
        st = os.stat(paths.rbac_db, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_size > 0


@dataclasses.dataclass(frozen=True)
class Published:
    """export/credentials.env as found: "absent", "valid" (with the passwords that pass the rule), "malformed" (with
    the line that is not NAME=value), or "unsafe" (reported)."""

    kind: str
    values: Dict[str, str] = dataclasses.field(default_factory=dict)
    line: int = 0


PUBLISHED_SPEC = Spec("file", mode=0o600)


def published_passwords(export: Dir, report: Report) -> Published:
    """The one reading of export/credentials.env that --check and the writing modes share."""
    try:
        data = read_file(export, CREDENTIALS_ENV, PUBLISHED_SPEC)
    except FileNotFoundError:
        return Published("absent")
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return Published("unsafe")
    try:
        parsed = parse_env(data, export.child(CREDENTIALS_ENV))
    except EnvSyntaxError as exc:
        return Published("malformed", line=exc.line)
    return Published("valid", {name: value for name, (value, _) in parsed.items()
                               if name in API_USERS and password_problem(value) is None})


def report_published(paths: Paths, export: Dir, published: Published, report: Report) -> None:
    """The verdict on a malformed publication: while rbac.db is not seeded the next writing run publishes it again
    (the seed has not happened, so the passwords are generated or supplied again); once it is seeded the passwords
    cannot be recovered from it, and it is INVALID."""
    if published.kind != "malformed":
        return
    path = export.child(CREDENTIALS_ENV)
    if rbac_seeded(paths):
        report.problem(INVALID, f"{path}:{published.line}", "not a NAME=value line")
    else:
        report.warning(f"ignoring {path} (line {published.line} is not NAME=value); it will be published again")


def publish_api_passwords(export: Dir, values: Mapping[str, str]) -> None:
    lines = [PUBLISHED_HEADER] + [f"{name}={values[name]}" for name in (API_VAR, WUI_VAR)]
    write_file(export, CREDENTIALS_ENV, ("\n".join(lines) + "\n").encode(), 0o600, 0, 0)


def seed_rbac(paths: Paths, values: Mapping[str, str], report: Report) -> bool:
    """Seed rbac.db through the bundled interpreter running rbac_control.py directly: bin/rbac_control is a shell
    wrapper that runs dirname, basename and sed. The passwords travel on stdin only."""
    missing = [p for p in (paths.python_bin, paths.rbac_control_script) if not os.path.exists(p)]
    if missing:
        report.problem(MISSING, paths.rbac_db, f"the Server API database could not be created ({missing[0]} is missing)")
        return False
    payload = json.dumps({API_USERS[name]: values[name] for name in (API_VAR, WUI_VAR)}).encode()
    result = run_wazuh(paths, [paths.python_bin, "-I", paths.rbac_control_script, "seed", "--passwords-file", "-"],
                       stdin=payload, want_stdout=True)
    if result.returncode == 0:
        return True
    # rbac_control prints user names, paths and rules, never a password.
    for line in (result.stdout + result.stderr).decode(errors="replace").splitlines():
        if line.strip():
            print(f"{LOG_TAG}: rbac_control: {line.strip()}", file=report.err)
    report.problem(MISSING, paths.rbac_db, "the Server API database could not be created")
    return False


def step_api_passwords(paths: Paths, conf: Dir, ca: Dir, lookup: Lookup, report: Report, names: "TlsNames") -> None:
    """Seed rbac.db on a master. The role is the configuration's, read once per run with every other setting; when
    the configuration could not be read (already reported) nothing is seeded, because seeding a worker would publish
    passwords for an API that runs on the master."""
    if rbac_seeded(paths):
        report.progress(f"{paths.rbac_db} is already seeded; the Server API passwords are left as they are")
        return
    role = names.role
    if role is None:
        return
    if role == "worker":
        report.progress("cluster worker: the Server API runs on the master, nothing to seed or publish here")
        return
    supplied = {name: supplied_password(lookup, name, report) for name in (API_VAR, WUI_VAR)}
    if any(state == "invalid" for state, _, _ in supplied.values()):
        return  # Never fall back to a generated value: the operator meant to set this one.
    try:
        export = ensure_dir(conf, EXPORT_DIR, EXPORT_SPEC)
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return
    with export:
        check_private_dir_roles(ca, export, report)
        if report.has(UNSAFE):
            return
        found = published_passwords(export, report)
        report_published(paths, export, found, report)
        if report.has(UNSAFE):
            return
        published = found.values
        values = {}
        for name, (state, value, source) in supplied.items():
            if state == "ok":
                values[name], origin = value, f"supplied ({source})"
            elif name in published:
                values[name], origin = published[name], "kept from an earlier publication"
            else:
                values[name], origin = generate_password(), "generated"
            report.progress(f"{name}: {origin}")
        if values != published:
            publish_api_passwords(export, values)
        if seed_rbac(paths, values, report):
            report.progress(f"seeded {paths.rbac_db}; the passwords are in {export.child(CREDENTIALS_ENV)}")


# ================================================ Indexer password =============================================


def keystore_has(paths: Paths, key: str) -> bool:
    """Whether the keystore holds a non-empty value. `-g` prints the secret: its output is discarded."""
    return run_wazuh(paths, [paths.keystore_bin, "-f", "indexer", "-k", key, "-g"]).returncode == 0


def keystore_set(paths: Paths, key: str, value: str) -> bool:
    return run_wazuh(paths, [paths.keystore_bin, "-f", "indexer", "-k", key],
                     stdin=(value + "\n").encode()).returncode == 0


def step_indexer_password(paths: Paths, lookup: Lookup, report: Report) -> None:
    if not os.access(paths.keystore_bin, os.X_OK):
        report.problem(MISSING, INDEXER_VAR, f"cannot reach the keystore ({paths.keystore_bin} is missing)")
        return
    if keystore_has(paths, "password"):
        if not keystore_has(paths, "username") and not keystore_set(paths, "username", INDEXER_USERNAME):
            report.problem(MISSING, INDEXER_VAR, "the keystore did not accept the indexer username")
            return
        report.progress("the indexer password is in the keystore")
        return
    state, value, source = supplied_password(lookup, INDEXER_VAR, report)
    if state == "invalid":
        return
    if state == "absent":
        report.problem(MISSING, INDEXER_VAR,
                       f"set it in {os.path.join(paths.conf, LOCAL_ENV)} (copy it from the indexer's "
                       f"{os.path.join(paths.indexer_export, CREDENTIALS_ENV)}), or install wazuh-indexer on this "
                       "host first")
        return
    if not keystore_has(paths, "username") and not keystore_set(paths, "username", INDEXER_USERNAME):
        report.problem(MISSING, INDEXER_VAR, "the keystore did not accept the indexer username")
        return
    if not keystore_set(paths, "password", value):
        report.problem(MISSING, INDEXER_VAR, "the keystore did not accept it")
        return
    report.progress(f"stored the indexer password from {source} in the keystore")


# ============================================= Configured TLS files ============================================
#
# The daemons serve the files their configuration names, so those are the files checked: remoted's and authd's pairs
# and the agents' bundle (wazuh-manager.conf), the Server API's pair (api.yaml). Both configuration files are writable
# by the service account, so a configured name is followed only directly inside <CONF>/certs, which only root
# writes and whose files every step already checks; anything else is refused, never opened.

CONF_FILE = "wazuh-manager.conf"
CONF_DUMP_LIMIT = 1024 * 1024
API_CONFIG_DIR = ("api", "configuration")
API_YAML = "api.yaml"
API_FILE = Spec("file", uid=None, forbid=0)    # the account's own file by design: only its type and size count
DEFAULT_PAIRS = {"remoted": ("remoted.pem", "remoted-key.pem"), "apid": ("apid.pem", "apid-key.pem")}


@dataclasses.dataclass(frozen=True)
class ServerPair:
    """One pair a listener serves: its file names in certs/, where they are configured, and what it chains to
    ("bundle": the agents' bundle alone, like remoted's GET /cacerts; "ca": the manager's CA). `kind` is "remoted" or
    "apid" when the names are the ones --install issues, with that pair's SAN list; None otherwise. `on` is False for
    a listener that is turned off: its pair is issued when its names are the default ones, never checked."""

    cert: str
    key: str
    keys: str
    source: str
    anchors: str
    kind: Optional[str]
    on: bool


@dataclasses.dataclass(frozen=True)
class IndexerNames:
    """The indexer connection's files (indexer.ssl.*), as names in certs/. `cas` holds the listed CA files that were
    not refused; `listed` says whether the list named any file at all (an empty list: the connector trusts the system
    store). `cert`/`key` are None when no client pair is configured, or when it was refused (reported)."""

    cas: Tuple[str, ...]
    listed: bool
    cert: Optional[str]
    key: Optional[str]
    source: str


@dataclasses.dataclass(frozen=True)
class TlsNames:
    pairs: Tuple[ServerPair, ...]
    bundle: Optional[str]                 # None: the configured bundle was refused
    bundle_source: str
    indexer: IndexerNames
    role: Optional[str] = "master"        # cluster.node_type; None when the configuration could not be read

    @property
    def names(self) -> Tuple[str, ...]:
        """Every configured name in certs/: a CA is never minted beside any of them."""
        found = [name for pair in self.pairs for name in (pair.cert, pair.key)]
        return tuple(dict.fromkeys(found + ([self.bundle] if self.bundle else [])))


def default_tls_names(paths: Paths) -> TlsNames:
    """The installed configuration's names: what --clear's safety pass uses, which reads no configuration."""
    conf_file = os.path.join(paths.conf, CONF_FILE)
    api_file = os.path.join(paths.home, *API_CONFIG_DIR, API_YAML)
    return TlsNames((ServerPair(*DEFAULT_PAIRS["remoted"], "remote.https.certificate", conf_file, "bundle", "remoted",
                                True),
                     ServerPair(*DEFAULT_PAIRS["apid"], "https.cert", api_file, "ca", "apid", True)),
                    BUNDLE, conf_file, IndexerNames((INDEXER_CA,), True, CONNECTOR, CONNECTOR_KEY, conf_file))


def read_manager_conf(paths: Paths, report: Report) -> dict:
    """The effective configuration, defaults applied, as wazuh-manager-conf prints it; {} (reported) when it cannot
    be read, and the default names are then used. --skip-file-checks: the files it names are what is being checked."""
    conf_file = os.path.join(paths.conf, CONF_FILE)
    problem = None
    if not os.access(paths.conf_bin, os.X_OK):
        problem = f"{paths.conf_bin} is missing"
    else:
        try:
            result = run_wazuh(paths, [paths.conf_bin, "-H", paths.home, "-f", conf_file, "--skip-file-checks", "dump"],
                               want_stdout=True)
        except subprocess.TimeoutExpired:
            # subprocess.run() kills the reader before raising: one that hangs is one that did not answer.
            problem = f"wazuh-manager-conf did not answer within {SUBPROCESS_TIMEOUT} seconds"
        else:
            if result.returncode != 0:
                problem = f"wazuh-manager-conf exited with {result.returncode}"
            elif len(result.stdout) > CONF_DUMP_LIMIT:
                problem = f"its output is larger than {CONF_DUMP_LIMIT} bytes"
            else:
                try:
                    document = json.loads(result.stdout)
                except ValueError:
                    document = None
                if isinstance(document, dict):
                    return document
                problem = "its output is not a JSON object"
    report.problem(INVALID, conf_file, f"cannot read the TLS paths ({problem}); run wazuh-manager-conf validate")
    return {}


def read_api_https(paths: Paths, report: Report) -> Dict[str, object]:
    """The Server API's https.enabled/cert/key from api.yaml, with the API's defaults (api/api/configuration.py) for
    what it does not set. A file that is absent means the defaults; one that cannot be read means the defaults and a
    verdict."""
    values: Dict[str, object] = {"enabled": True, "cert": DEFAULT_PAIRS["apid"][0], "key": DEFAULT_PAIRS["apid"][1]}
    path = os.path.join(paths.home, *API_CONFIG_DIR, API_YAML)
    try:
        fd = _open_dir_fd(paths.home, None, paths.home)
        with Dir(fd, paths.home, os.fstat(fd)) as home:
            directory = walk_path(home, API_CONFIG_DIR)
            if directory is None:
                return values
            with directory:
                data = read_file(directory, API_YAML, API_FILE)
    except FileNotFoundError:
        return values
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return values
    import yaml  # PyYAML, bundled with the manager's interpreter (framework/requirements.txt)
    try:
        document = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        report.problem(INVALID, path, "not valid YAML" + (f" (line {mark.line + 1})" if mark is not None else ""))
        return values
    https = document.get("https") if isinstance(document, dict) else None
    if document is not None and not isinstance(document, dict) or https is not None and not isinstance(https, dict):
        report.problem(INVALID, path, "not a mapping of options" if not isinstance(document, dict) else
                                      "https: not a mapping of options")
        return values
    for name, kind in (("enabled", bool), ("cert", str), ("key", str)):
        value = (https or {}).get(name)
        if value is None:
            continue
        if isinstance(value, str) and value.lower() in ("yes", "no"):
            # As the Server API reads the file (replace_bools() in api/api/configuration.py): the strings yes and no,
            # in any case, are booleans, wherever they appear.
            value = value.lower() == "yes"
        if not isinstance(value, kind) or kind is str and not value:
            report.problem(INVALID, path, f"https.{name}: not {'true or false' if kind is bool else 'a file name'}")
            return {"enabled": True, "cert": DEFAULT_PAIRS["apid"][0], "key": DEFAULT_PAIRS["apid"][1]}
        values[name] = value
    return values


def certs_name(paths: Paths, key: str, value: str, base: str, source: str, report: Report) -> Optional[str]:
    """The name in certs/ of a configured file, resolved the way its consumer resolves it (relative to `base`), or
    None (reported) when it is not directly inside <CONF>/certs. No component may be empty, "." or "..": the kernel
    would resolve those through directories the account can rename."""
    path = value if value.startswith("/") else os.path.join(base, value)
    certs = os.path.join(paths.conf, CERTS_DIR)
    components = path.split("/")[1:]
    if any(part in ("", ".", "..") for part in components) or os.path.dirname(path) != certs:
        report.problem(INVALID, key, f"{path} is outside {certs}, the only place the resolver checks "
                                     f"(set in {source})")
        return None
    return os.path.basename(path)


def _conf_value(document: dict, dotted: str, kind: type, default):
    value = document
    for part in dotted.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value if isinstance(value, kind) else default


def tls_names(paths: Paths, report: Report) -> TlsNames:
    """Read both configuration files once per run and resolve every configured name. A refused name leaves its pair
    out (reported); a pair with one name refused is left out whole."""
    conf_file = os.path.join(paths.conf, CONF_FILE)
    api_file = os.path.join(paths.home, *API_CONFIG_DIR, API_YAML)
    certs = os.path.join(paths.conf, CERTS_DIR)
    document = read_manager_conf(paths, report)
    api = read_api_https(paths, report)

    def configured(key, default, base, source):
        value = _conf_value(document, key, str, os.path.join(certs, default)) if source == conf_file \
            else api[key.split(".")[1]]
        return certs_name(paths, key, value, base, source, report)

    pairs = []
    remoted_on, authd_on = True, not _conf_value(document, "auth.disabled", bool, False)
    for cert_key, key_key, defaults, source, anchors, on in (
            ("remote.https.certificate", "remote.https.key", DEFAULT_PAIRS["remoted"], conf_file, "bundle", remoted_on),
            ("auth.ssl_manager_cert", "auth.ssl_manager_key", DEFAULT_PAIRS["remoted"], conf_file, "bundle", authd_on),
            ("https.cert", "https.key", DEFAULT_PAIRS["apid"], api_file, "ca", bool(api["enabled"]))):
        base = paths.home if source == conf_file else certs
        cert = configured(cert_key, defaults[0], base, source)
        key = configured(key_key, defaults[1], base, source)
        if cert is None or key is None:
            continue
        kind = next((name for name, names in DEFAULT_PAIRS.items() if names == (cert, key)), None)
        pair = ServerPair(cert, key, cert_key, source, anchors, kind, on)
        same = next((i for i, other in enumerate(pairs)
                     if (other.cert, other.key, other.anchors) == (cert, key, anchors)), None)
        if same is None:
            pairs.append(pair)
        elif on and not pairs[same].on:
            pairs[same] = pair
    bundle = configured("remote.https.ca_certificate", BUNDLE, paths.home, conf_file)
    role = (_conf_value(document, "cluster.node_type", str, "master") or "master") if document else None
    return TlsNames(tuple(pairs), bundle, conf_file, indexer_names(paths, document, conf_file, report), role)


def indexer_names(paths: Paths, document: dict, conf_file: str, report: Report) -> IndexerNames:
    """indexer.ssl.*, resolved against the home as the connector resolves them. The certificate and its key are set
    together or not at all (both empty: no client certificate)."""
    certs = os.path.join(paths.conf, CERTS_DIR)
    listed = [value for value in _conf_value(document, "indexer.ssl.certificate_authorities", list,
                                             [os.path.join(certs, INDEXER_CA)]) if isinstance(value, str) and value]
    cas = []
    for value in listed:
        name = certs_name(paths, "indexer.ssl.certificate_authorities", value, paths.home, conf_file, report)
        if name is not None and name not in cas:
            cas.append(name)
    values = {part: _conf_value(document, f"indexer.ssl.{part}", str, os.path.join(certs, default))
              for part, default in (("certificate", CONNECTOR), ("key", CONNECTOR_KEY))}
    cert = key = None
    if bool(values["certificate"]) != bool(values["key"]):
        empty, other = ("key", "certificate") if values["certificate"] else ("certificate", "key")
        report.problem(INVALID, f"indexer.ssl.{empty}", f"must be set together with indexer.ssl.{other} (set in "
                                                        f"{conf_file})")
    elif values["certificate"]:
        cert = certs_name(paths, "indexer.ssl.certificate", values["certificate"], paths.home, conf_file, report)
        key = certs_name(paths, "indexer.ssl.key", values["key"], paths.home, conf_file, report)
        if cert is None or key is None:
            cert = key = None
    return IndexerNames(tuple(cas), bool(listed), cert, key, conf_file)


# ==================================================== Own CA ===================================================

CA_CERT_SPEC = Spec("file")                       # rule 1
CA_KEY_SPEC = Spec("file", forbid=0o077)          # root's private file: no group or other bit at all


def certs_spec(paths: Paths) -> Spec:
    """certs/: a real directory owned by root (rule 4), exactly 0750 as installed: the daemons open its files by name
    through the service group, which must never write there."""
    return Spec("dir", uid=0, gid=paths.service_gid(), mode=0o750)


def certs_file_spec(paths: Paths) -> Spec:
    """What root writes in certs/: root:<service group> 0640. The daemons read it after dropping their
    supplementary groups (clusterd, apid), so the group has to be exactly the service group."""
    return Spec("file", uid=0, gid=paths.service_gid(), mode=0o640)


_DNS_LABEL = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def valid_dns_name(name: str) -> bool:
    """The shell resolver's DNS rules: at most 253 characters, labels of 1 to 63 letters, digits and inner hyphens."""
    return 0 < len(name) <= 253 and all(_DNS_LABEL.fullmatch(label) for label in name.split("."))


def node_name(lookup: Lookup, report: Report) -> Optional[str]:
    """The name certificates carry: WAZUH_MANAGER_NODE_NAME when supplied, else the short host name."""
    found = lookup.get(NODE_NAME_VAR)
    if found is not None:
        name, source = found
        if valid_dns_name(name):
            return name
        report.problem(INVALID, NODE_NAME_VAR, f"not a valid DNS name (set in {source})")
        return None
    host = socket.gethostname().split(".")[0]
    if valid_dns_name(host):
        return host
    report.problem(INVALID, NODE_NAME_VAR, f"unset, and the host name {host!r} is not a valid DNS name; set it")
    return None


def read_optional(parent: Dir, name: str, spec: Spec, report: Report) -> Tuple[bool, Optional[bytes]]:
    """(present, content). An entry that is present but unsafe is reported and comes back as (True, None)."""
    try:
        return True, read_file(parent, name, spec)
    except FileNotFoundError:
        return False, None
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return True, None


@dataclasses.dataclass
class CaState:
    """kind: "absent", "signing" (certificate and key) or "anchor-only" (certificate, no key: pairs are staged)."""

    kind: str
    cert: Optional[x509.Certificate] = None
    key: Optional[rsa.RSAPrivateKey] = None
    cert_bytes: bytes = b""


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _spki(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def parse_problem(certs: List[x509.Certificate]) -> Optional[str]:
    """Whether every certificate parses completely. cryptography reads extensions lazily, so a malformed or
    duplicated one only fails on first access; asking here turns that into a verdict on the file instead of an
    exception in the middle of a step."""
    for cert in certs:
        try:
            cert.extensions
        except (ValueError, x509.DuplicateExtension) as exc:
            return f"a certificate it holds cannot be parsed ({exc})"
    return None


# The keys x509.verification accepts, and so the only ones a certificate the resolver checks may carry: any other
# (Ed25519, Ed448, DSA, a short RSA key, another curve) fails every chain check it takes part in.
ACCEPTED_KEY_TYPES = "use RSA of 2048 bits or more, or ECDSA on P-256, P-384 or P-521"
ACCEPTED_CURVES = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)


def key_type_problem(public_key) -> Optional[str]:
    """None for a key the certificate checks accept; otherwise what it is, in words."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return None if public_key.key_size >= 2048 else f"an RSA key of {public_key.key_size} bits"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return None if isinstance(public_key.curve, ACCEPTED_CURVES) else f"an ECDSA key on {public_key.curve.name}"
    for kind, text in ((ed25519.Ed25519PublicKey, "an Ed25519 key"), (ed448.Ed448PublicKey, "an Ed448 key"),
                       (dsa.DSAPublicKey, "a DSA key")):
        if isinstance(public_key, kind):
            return text
    return f"a {type(public_key).__name__} key"


def ca_certificate_problem(data: bytes) -> Tuple[Optional[x509.Certificate], Optional[str]]:
    """Parse a CA file: exactly one certificate, self-signed, CA:TRUE, on a key the certificate checks accept, inside
    its validity window. The key type comes before anything is signed with it: a key the resolver cannot sign
    certificates with, or that the checks of what it issues would refuse, makes the CA unusable."""
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        return None, "not a PEM certificate"
    if len(certs) != 1:
        return None, f"holds {len(certs)} certificates, not one"
    problem = parse_problem(certs)
    if problem:
        return None, problem
    cert = certs[0]
    try:
        if cert.subject != cert.issuer:
            raise InvalidSignature
        cert.verify_directly_issued_by(cert)
    except (InvalidSignature, ValueError, TypeError):
        return None, "not self-signed"
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        return None, "not a CA certificate (basicConstraints CA:TRUE missing)"
    problem = key_type_problem(cert.public_key())
    if problem:
        return None, f"{problem}; {ACCEPTED_KEY_TYPES}"
    now = _now()
    if now < cert.not_valid_before_utc:
        return None, "not valid yet"
    if now > cert.not_valid_after_utc:
        return None, "expired"
    return cert, None


def ca_key_problem(data: bytes, cert: x509.Certificate):
    """Load an unencrypted private key and check it is the certificate's."""
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        return None, "encrypted; it has to be unencrypted to issue certificates"
    except (ValueError, UnsupportedAlgorithm):
        return None, "not a PEM private key"
    if _spki(key.public_key()) != _spki(cert.public_key()):
        return None, f"does not match {CA_CERT}"
    return key, None


def load_ca(ca: Dir, report: Report) -> Optional[CaState]:
    """The CA in <CONF>/ca, validated. None when something there is unsafe or invalid (reported)."""
    has_cert, cert_bytes = read_optional(ca, CA_CERT, CA_CERT_SPEC, report)
    has_key, key_bytes = read_optional(ca, CA_KEY, CA_KEY_SPEC, report)
    if (has_cert and cert_bytes is None) or (has_key and key_bytes is None):
        return None
    if not has_cert and not has_key:
        return CaState("absent")
    if not has_cert:
        report.problem(INVALID, ca.child(CA_KEY), f"no certificate beside it ({CA_CERT})")
        return None
    cert, problem = ca_certificate_problem(cert_bytes)
    if problem:
        report.problem(INVALID, ca.child(CA_CERT), problem)
        return None
    if not has_key:
        return CaState("anchor-only", cert, None, cert_bytes)
    key, problem = ca_key_problem(key_bytes, cert)
    if problem:
        report.problem(INVALID, ca.child(CA_KEY), problem)
        return None
    return CaState("signing", cert, key, cert_bytes)


def ca_name(node: str) -> x509.Name:
    """In ASN.1 order C, L, O, OU, CN, like the server pairs."""
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                      x509.NameAttribute(NameOID.LOCALITY_NAME, "California"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wazuh"),
                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Wazuh"),
                      x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME_PREFIX + node)])


def mint_ca(ca: Dir, node: str) -> CaState:
    """Mint the manager's CA: RSA 2048, SHA-256, ten years backdated one day. The key goes first and the marker
    last: a crash leaves either a lone key (refused at the next run) or an unmarked CA, which --clear keeps."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = ca_name(node)
    now = _now()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CERT_BACKDATE)
            .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    write_file(ca, CA_KEY, key_bytes, 0o400, 0, 0)
    write_file(ca, CA_CERT, cert_bytes, 0o644, 0, 0)
    write_file(ca, CA_MARKER, b"", 0o600, 0, 0)
    return CaState("signing", cert, key, cert_bytes)


def server_material_present(certs: Dir, names: TlsNames) -> bool:
    """Whether any server pair file or the bundle, by default or configured name, is already in certs/: a CA is never
    minted beside them."""
    for name in tuple(dict.fromkeys(SERVER_PAIR_FILES + (BUNDLE,) + names.names)):
        try:
            os.stat(name, dir_fd=certs.fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            continue
    return False


def bundle_contains(data: bytes, cert: x509.Certificate) -> bool:
    """Whether a bundle holds `cert` among its certificates. The publication block wazuh-manager-certs writes (`##`
    lines) and any rotation CA are tolerated: the bytes are never rewritten."""
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        return False
    der = cert.public_bytes(serialization.Encoding.DER)
    return any(candidate.public_bytes(serialization.Encoding.DER) == der for candidate in certs)


def open_certs(paths: Paths, conf: Dir, report: Report) -> Optional[Dir]:
    try:
        return open_dir(conf, CERTS_DIR, certs_spec(paths))
    except FileNotFoundError:
        report.problem(INVALID, conf.child(CERTS_DIR), "no such directory (the installer creates it)")
    except UnsafeEntry as exc:
        report.unsafe(exc)
    return None


def check_bundle(paths: Paths, certs: Dir, state: CaState, report: Report, mode: str, names: TlsNames) -> None:
    """The agents' bundle (certs/root-ca.pem, or the configured name): the default one is created from the CA when
    absent at --install; a present one is validated and kept as it is."""
    bundle = names.bundle
    if bundle is None:
        return                                           # its configured name was refused
    present, data = read_optional(certs, bundle, certs_file_spec(paths), report)
    if present and data is None:
        return
    if not present:
        # Only --install writes it; at --check this is the MISSING --prestart would report and cannot complete.
        if mode == "install" and bundle == BUNDLE:
            write_file(certs, BUNDLE, state.cert_bytes, 0o640, 0, paths.service_gid())
            report.progress(f"wrote {certs.child(BUNDLE)} (the manager's CA)")
        elif bundle != BUNDLE:
            report.problem(MISSING, certs.child(bundle), f"configured as remote.https.ca_certificate in "
                                                         f"{names.bundle_source}; stage the agents' CA bundle there")
        else:
            report.problem(MISSING, certs.child(BUNDLE), "the agents' CA bundle is missing; reinstall, or stage it")
        return
    try:
        problem = parse_problem(x509.load_pem_x509_certificates(data))
    except ValueError:
        problem = None                                   # bundle_contains reports a bundle with no certificate
    if problem:
        report.problem(INVALID, certs.child(bundle), problem)
    elif not bundle_contains(data, state.cert):
        report.problem(INVALID, certs.child(bundle), f"does not contain {os.path.join(paths.conf, CA_DIR, CA_CERT)}")


def published_ca(export: Dir, own: bytes, report: Report) -> str:
    """export/ca.pem against the CA's own bytes: "absent", "current", "stale" (the CA was staged again or rotated;
    every writing mode publishes it again), or "unsafe" (reported, never replaced)."""
    present, published = read_optional(export, EXPORT_CA, ROOT_FILE, report)
    if not present:
        return "absent"
    if published is None:
        return "unsafe"
    return "current" if published == own else "stale"


def _missing_ca(path: str, report: Report) -> None:
    """Only --install mints a CA, and only when nothing else is there: every other mode reports it missing."""
    report.problem(MISSING, path, f"the manager's CA is missing; stage it there (and {CA_KEY} to issue certificates), "
                                  f"or reinstall")


def step_own_ca(paths: Paths, conf: Dir, certs: Dir, ca: Dir, lookup: Lookup, report: Report,
                mode: str, names: TlsNames) -> Optional[CaState]:
    """--install mints or validates the CA; every writing mode publishes it in export/ca.pem when the copy there is
    absent or differs (the CA staged again by hand). `certs` is opened once by the caller and shared with the server
    pairs step."""
    state = load_ca(ca, report)
    if state is None:
        return None
    if state.kind == "absent":
        if mode != "install":
            _missing_ca(ca.child(CA_CERT), report)
            return None
        if server_material_present(certs, names):
            report.problem(MISSING, ca.child(CA_CERT), "stage the CA that issued the pairs")
            return None
        node = node_name(lookup, report)
        if node is None:
            return None
        if len(CA_COMMON_NAME_PREFIX + node) > COMMON_NAME_MAX:
            report.problem(INVALID, NODE_NAME_VAR, "too long for the CA's common name (64 characters at most)")
            return None
        state = mint_ca(ca, node)
        origin = "minted"
    elif _exists(ca, CA_MARKER):
        origin = "minted earlier"              # by this host: --clear removes it
    else:
        origin = "staged" if state.kind == "signing" else "staged without its key (pairs cannot be issued here)"
    report.progress(f"CA {state.cert.subject.rfc4514_string()}: {origin}")
    try:
        with ensure_dir(conf, EXPORT_DIR, EXPORT_SPEC) as export:
            check_private_dir_roles(ca, export, report)
            if report.has(UNSAFE):
                return None
            publication = published_ca(export, state.cert_bytes, report)
            if publication in ("absent", "stale"):
                write_file(export, EXPORT_CA, state.cert_bytes, 0o644, 0, 0)
                if publication == "stale":
                    report.progress(f"published {export.child(EXPORT_CA)} again: it differed from {ca.child(CA_CERT)}")
    except UnsafeEntry as exc:
        report.unsafe(exc)
    if report.has(UNSAFE):
        return None
    check_bundle(paths, certs, state, report, mode, names)
    return state


def check_own_ca(paths: Paths, conf: Dir, lookup: Lookup, report: Report, names: TlsNames) -> None:
    """--check's part: validate whatever CA and bundle exist, without creating ca/ or writing anything, and report
    as MISSING what only --install creates (the CA, the bundle, the server pairs): --prestart would report it and
    could not complete it, and on a restart --check is what runs before the daemons are stopped."""
    try:
        ca = open_dir(conf, CA_DIR, CA_SPEC)
    except FileNotFoundError:
        ca = None
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return
    certs = open_certs(paths, conf, report)
    try:
        state = load_ca(ca, report) if ca is not None else CaState("absent")
        if state is not None and state.kind == "absent":
            _missing_ca(os.path.join(paths.conf, CA_DIR, CA_CERT), report)
        if certs is not None and state is not None and state.kind != "absent":
            check_bundle(paths, certs, state, report, "check", names)
        if certs is not None:
            check_server_pairs(paths, certs, state, lookup, report, names)
    finally:
        for opened in (ca, certs):
            if opened is not None:
                opened.close()


# ============================================ Dashboard client pair ============================================
#
# A client pair the dashboard will import later from export/, issued by the manager's CA on a master. Nothing uses it
# yet: client certificates are not required anywhere, so its absence, or a defect in one the operator provided, is
# never a reason to refuse a start. The marker records the fingerprints of the files the resolver wrote, so its own
# pair (and only its own) is reissued when the CA changes or it expires, and removed by --clear; a pair whose content
# matches no recorded fingerprint, or that has no marker, is the operator's and is never written.

DASHBOARD_FILES = (DASHBOARD_KEY, DASHBOARD_CERT)          # written in this order, after the marker
DASHBOARD_SPECS = {DASHBOARD_KEY: PRIVATE_FILE, DASHBOARD_CERT: ROOT_FILE}
DASHBOARD_NOT_USED = "nothing uses it yet: the dashboard does not present a client certificate"


def issue_dashboard_pair(ca: CaState) -> Dict[str, bytes]:
    """The server pairs' profile for a client: CN=wazuh-dashboard, clientAuth only, no subjectAltName, a fresh key.
    The certificate file carries the leaf, a blank line, then the CA file."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _now()
    cert = (x509.CertificateBuilder()
            .subject_name(server_name(DASHBOARD_CN)).issuer_name(ca.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CERT_BACKDATE)
            .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.cert.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca.key, hashes.SHA256()))
    return {DASHBOARD_CERT: cert.public_bytes(serialization.Encoding.PEM) + b"\n" + ca.cert_bytes,
            DASHBOARD_KEY: key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption())}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _marker_bytes(new: Mapping[str, bytes], previous: Mapping[str, Optional[bytes]]) -> bytes:
    """One line per file: `<name> <sha256 of what is being written> <sha256 of what it replaces, or ->`. The previous
    fingerprint keeps a rewrite that stops halfway recognisable: every file is replaced atomically, so each one holds
    either the old or the new content."""
    lines = []
    for name in DASHBOARD_FILES:
        old = previous.get(name)
        lines.append(f"{name} {_digest(new[name])} {_digest(old) if old is not None else '-'}")
    return ("\n".join(lines) + "\n").encode()


def _parse_marker(data: bytes) -> Optional[Dict[str, Tuple[str, str]]]:
    recorded = {}
    for line in data.decode("ascii", errors="replace").splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] not in DASHBOARD_FILES:
            return None
        recorded[parts[0]] = (parts[1], parts[2])
    return recorded if set(recorded) == set(DASHBOARD_FILES) else None


@dataclasses.dataclass
class DashboardPair:
    """owner: "none" (no file), "ours" (the marker accounts for every present file), "operator", or "unsafe"
    (reported). `complete`: ours, both files present and the new fingerprints."""

    owner: str
    files: Dict[str, Optional[bytes]] = dataclasses.field(default_factory=dict)
    complete: bool = False
    marker: bool = False


def dashboard_pair_state(export: Dir, report: Report) -> DashboardPair:
    files: Dict[str, Optional[bytes]] = {}
    for name in DASHBOARD_FILES:
        present, data = read_optional(export, name, DASHBOARD_SPECS[name], report)
        if present and data is None:
            return DashboardPair("unsafe")
        files[name] = data
    marker_present, marker = read_optional(export, DASHBOARD_MARKER, PRIVATE_FILE, report)
    if marker_present and marker is None:
        return DashboardPair("unsafe")
    recorded = _parse_marker(marker) if marker is not None else None
    if recorded is None:
        owner = "operator" if any(data is not None for data in files.values()) else "none"
        return DashboardPair(owner, files, marker=marker_present)
    for name, data in files.items():
        if data is not None and _digest(data) not in recorded[name]:
            return DashboardPair("operator", files, marker=True)
    complete = all(data is not None and _digest(data) == recorded[name][0] for name, data in files.items())
    return DashboardPair("ours", files, complete, marker=True)


def dashboard_pair_problem(files: Mapping[str, Optional[bytes]], ca_cert: Optional[x509.Certificate],
                           forbidden: Mapping[str, bytes]) -> Optional[str]:
    """Why the pair could not serve the dashboard, or None: the files parse, the key matches, the leaf is no CA, has
    clientAuth, is inside its window and chains to the manager's CA (through intermediates after it), and its key is
    neither the CA's nor another one the manager uses (`forbidden`: label -> public key DER)."""
    present = [name for name in DASHBOARD_FILES if files.get(name) is not None]
    if len(present) == 1:
        missing = [name for name in DASHBOARD_FILES if name not in present][0]
        return f"half a pair ({missing} is missing)"
    try:
        leaf, *intermediates = x509.load_pem_x509_certificates(files[DASHBOARD_CERT])
    except ValueError:
        return "not a PEM certificate"
    problem = parse_problem([leaf, *intermediates])
    if problem:
        return problem
    _, problem = ca_key_problem(files[DASHBOARD_KEY], leaf)
    if problem:
        return "its key does not match it" if "match" in problem else f"its key is {problem}"
    for label, spki in forbidden.items():
        if _spki(leaf.public_key()) == spki:
            return f"its key is {label}"
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return "a CA certificate, not a client certificate"
    except x509.ExtensionNotFound:
        pass
    try:
        usages = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usages = []
    if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
        return "has no extendedKeyUsage with clientAuth"
    now = _now()
    if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
        return f"expired on {_utc(leaf.not_valid_after_utc)}" if now > leaf.not_valid_after_utc \
            else f"not valid until {_utc(leaf.not_valid_before_utc)}"
    if ca_cert is None:
        return None
    return chain_problem(leaf, intermediates, [ca_cert], "the manager's CA", now, ExtendedKeyUsageOID.CLIENT_AUTH)


def _forbidden_keys(paths: Paths, certs: Optional[Dir], ca_cert: Optional[x509.Certificate],
                    names: TlsNames) -> Dict[str, bytes]:
    """The keys the dashboard's pair must not share: the CA's and the Server API's (read, problems ignored: those
    files are judged by their own steps)."""
    keys = {}
    if ca_cert is not None:
        keys["the manager CA's key"] = _spki(ca_cert.public_key())
    if certs is not None:
        for pair in names.pairs:
            if pair.anchors != "ca":
                continue
            try:
                cert = x509.load_pem_x509_certificates(read_file(certs, pair.cert, certs_file_spec(paths)))[0]
                keys[f"the Server API's key ({pair.key})"] = _spki(cert.public_key())
            except (OSError, UnsafeEntry, ValueError):
                pass
    return keys


def _operator_warning(export: Dir, problem: str) -> str:
    return f"{export.child(DASHBOARD_CERT)}: {problem}; provided by the operator, kept as it is ({DASHBOARD_NOT_USED})"


@dataclasses.dataclass
class DashboardDiagnosis:
    """What the dashboard pair needs, decided once for --check and the writing modes. action: "skip" (a worker, or
    an unsafe entry, reported), "keep", "issue", "reissue" (the resolver's own pair no longer serves: `reason`),
    "operator" (kept; `reason` is its defect, if any), "no-key" (absent, or `reason` for one that needs reissuing,
    and the CA has no key)."""

    action: str
    pair: Optional[DashboardPair] = None
    reason: Optional[str] = None


def diagnose_dashboard_pair(paths: Paths, export: Dir, ca_state: Optional[CaState], certs: Optional[Dir],
                            names: TlsNames, report: Report) -> DashboardDiagnosis:
    if names.role != "master":
        return DashboardDiagnosis("skip")
    pair = dashboard_pair_state(export, report)
    if pair.owner == "unsafe":
        return DashboardDiagnosis("skip", pair)
    ca_cert = ca_state.cert if ca_state is not None else None
    signing = ca_state is not None and ca_state.kind == "signing"
    forbidden = _forbidden_keys(paths, certs, ca_cert, names)
    if pair.owner == "operator":
        return DashboardDiagnosis("operator", pair, dashboard_pair_problem(pair.files, ca_cert, forbidden))
    reason = None
    if pair.owner == "ours":
        reason = "an earlier write was interrupted" if not pair.complete \
            else dashboard_pair_problem(pair.files, ca_cert, forbidden)
        if reason is None:
            return DashboardDiagnosis("keep", pair)
    if not signing:
        return DashboardDiagnosis("no-key", pair, reason)
    return DashboardDiagnosis("reissue" if pair.owner == "ours" else "issue", pair, reason)


def _no_key_warning(ca_dir_path: str, export: Dir, diagnosis: DashboardDiagnosis) -> str:
    if diagnosis.reason is None:
        return (f"dashboard client pair not generated: {ca_dir_path} has no key; provision it externally in "
                f"{export.path}")
    return f"{export.child(DASHBOARD_CERT)}: {diagnosis.reason}; not reissued: {ca_dir_path} has no key"


def step_dashboard_pair(paths: Paths, conf: Dir, ca_dir: Dir, certs: Optional[Dir], state: CaState, names: TlsNames,
                        report: Report) -> None:
    """On a master, act on the pair's diagnosis: issue it, reissue the resolver's own, keep the operator's (warning
    about its defects). Nothing here refuses a start."""
    if names.role != "master":
        return
    try:
        with ensure_dir(conf, EXPORT_DIR, EXPORT_SPEC) as export:
            check_private_dir_roles(ca_dir, export, report)
            if report.has(UNSAFE):
                return
            diagnosis = diagnose_dashboard_pair(paths, export, state, certs, names, report)
            cert_path = export.child(DASHBOARD_CERT)
            if diagnosis.action == "skip":
                return
            if diagnosis.action == "keep":
                report.progress(f"{cert_path}: kept")
                return
            if diagnosis.action == "operator":
                if diagnosis.reason:
                    report.warning(_operator_warning(export, diagnosis.reason))
                report.progress(f"{cert_path}: provided by the operator; kept as it is")
                return
            if diagnosis.action == "no-key":
                report.warning(_no_key_warning(ca_dir.path, export, diagnosis))
                return
            pair = diagnosis.pair
            new = issue_dashboard_pair(state)
            write_file(export, DASHBOARD_MARKER, _marker_bytes(new, pair.files), 0o600, 0, 0)
            write_file(export, DASHBOARD_KEY, new[DASHBOARD_KEY], 0o600, 0, 0)
            write_file(export, DASHBOARD_CERT, new[DASHBOARD_CERT], 0o644, 0, 0)
            leaf = x509.load_pem_x509_certificates(new[DASHBOARD_CERT])[0]
            if any(data is not None for data in pair.files.values()):
                report.progress(f"{cert_path}: reissued ({diagnosis.reason}); the dashboard must import it again")
            else:
                report.progress(f"{cert_path}: issued; DN {leaf.subject.rfc4514_string()}; the dashboard imports it "
                                f"from here")
    except UnsafeEntry as exc:
        report.unsafe(exc)


def check_dashboard_pair(paths: Paths, conf: Dir, report: Report, names: TlsNames) -> None:
    """--check's part, read-only: the same diagnosis, reported. Absence is said only when no pair can be issued."""
    if names.role != "master":
        return
    export = _open_optional_dir(conf, EXPORT_DIR, EXPORT_SPEC, report)
    if export is None:
        return
    quiet = Report(quiet=True, out=io.StringIO(), err=io.StringIO())
    ca_dir = _open_optional_dir(conf, CA_DIR, CA_SPEC, report)
    certs = _open_optional_dir(conf, CERTS_DIR, certs_spec(paths), quiet)
    try:
        state = load_ca(ca_dir, quiet) if ca_dir is not None else None
        diagnosis = diagnose_dashboard_pair(paths, export, state, certs, names, report)
        cert_path = export.child(DASHBOARD_CERT)
        if diagnosis.action == "operator" and diagnosis.reason:
            report.warning(_operator_warning(export, diagnosis.reason))
        elif diagnosis.action == "reissue":
            report.progress(f"{cert_path}: {diagnosis.reason}; the next start reissues it")
        elif diagnosis.action == "no-key" and state is not None and state.kind != "absent":
            report.warning(_no_key_warning(conf.child(CA_DIR), export, diagnosis))
    finally:
        for opened in (export, ca_dir, certs):
            if opened is not None:
                opened.close()


# ================================================= Server pairs ================================================


@dataclasses.dataclass(frozen=True)
class San:
    """One subject alternative name: kind "DNS" or "IP", and its value (an IP in its canonical text form)."""

    kind: str
    value: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"

    def key(self):
        return (self.kind, self.value.lower() if self.kind == "DNS" else ipaddress.ip_address(self.value))

    def general_name(self) -> x509.GeneralName:
        if self.kind == "DNS":
            return x509.DNSName(self.value)
        return x509.IPAddress(ipaddress.ip_address(self.value))


LOOPBACK_SANS = (San("DNS", "localhost"), San("IP", "127.0.0.1"), San("IP", "::1"))


def parse_san_entry(text: str) -> Tuple[Optional[San], Optional[str]]:
    """`DNS:name`, `IP:address`, or a bare one classified as the shell resolver did: an address when it holds a colon
    or only digits and dots, a DNS name otherwise. Zone ids, prefixes, leading zeros and wildcards are refused."""
    entry = text.strip()
    if not entry:
        return None, "empty SAN entry"
    if entry[:4] in ("DNS:", "dns:"):
        kind, value = "DNS", entry[4:]
    elif entry[:3] in ("IP:", "ip:"):
        kind, value = "IP", entry[3:]
    elif ":" in entry or re.fullmatch(r"[0-9.]+", entry):
        kind, value = "IP", entry
    else:
        kind, value = "DNS", entry
    if kind == "DNS":
        return (San("DNS", value), None) if valid_dns_name(value) else (None, f"{entry}: not a valid DNS name")
    if "%" in value or "/" in value:
        return None, f"{entry}: not a valid IP address"
    try:
        return San("IP", str(ipaddress.ip_address(value))), None
    except ValueError:
        return None, f"{entry}: not a valid IP address"


def finish_sans(sans: List[San]) -> List[San]:
    """Append the loopback names and drop duplicates (DNS case-insensitively, addresses by value), keeping order."""
    seen, result = set(), []
    for san in list(sans) + list(LOOPBACK_SANS):
        if san.key() not in seen:
            seen.add(san.key())
            result.append(san)
    return result


def parse_san_list(value: str) -> Tuple[Optional[List[San]], Optional[str]]:
    if not value.strip():
        return None, "empty"
    sans = []
    for entry in value.split(","):
        san, problem = parse_san_entry(entry)
        if problem:
            return None, problem
        sans.append(san)
    return finish_sans(sans), None


@dataclasses.dataclass(frozen=True)
class InterfaceAddress:
    index: int                   # the interface's index
    family: int                  # socket.AF_INET or socket.AF_INET6
    address: str
    scope: int                   # RT_SCOPE_UNIVERSE is global
    flags: int                   # IFA_F_*


def _netlink_align(length: int) -> int:
    return (length + 3) & ~3


def _malformed_reply() -> OSError:
    return OSError(errno.EPROTO, "malformed netlink reply")


def _parse_address(body: bytes) -> Optional[InterfaceAddress]:
    """One RTM_NEWADDR body: ifaddrmsg, then attributes. The address is IFA_LOCAL when present (IFA_ADDRESS is the
    peer on a point-to-point link), as `ip` prints it; the flags are IFA_FLAGS when present (ifa_flags holds 8 bits).
    None for a family or an address length this resolver does not name."""
    if len(body) < IFADDRMSG.size:
        raise _malformed_reply()
    family, _, flags, scope, index = IFADDRMSG.unpack_from(body)
    attributes, offset = {}, IFADDRMSG.size
    while offset + RTATTR.size <= len(body):
        length, kind = RTATTR.unpack_from(body, offset)
        if length < RTATTR.size or offset + length > len(body):
            raise _malformed_reply()
        attributes[kind] = body[offset + RTATTR.size:offset + length]
        offset += _netlink_align(length)
    if len(attributes.get(IFA_FLAGS, b"")) == 4:
        flags = struct.unpack("=I", attributes[IFA_FLAGS])[0]
    raw = attributes.get(IFA_LOCAL) or attributes.get(IFA_ADDRESS)
    size = {socket.AF_INET: 4, socket.AF_INET6: 16}.get(family)
    if size is None or raw is None or len(raw) != size:
        return None
    return InterfaceAddress(index, family, socket.inet_ntop(family, raw), scope, flags)


def parse_address_messages(data: bytes, seq: int) -> Tuple[List[InterfaceAddress], bool]:
    """The addresses in one buffer of an RTM_GETADDR dump's reply, and whether the buffer ends the dump. Messages of
    another type or sequence are skipped; an error message, or a length that leaves the buffer, raises OSError."""
    entries, offset = [], 0
    while offset < len(data):
        if len(data) - offset < NLMSG_HEADER.size:
            raise _malformed_reply()
        length, kind, _, sequence, _ = NLMSG_HEADER.unpack_from(data, offset)
        if length < NLMSG_HEADER.size or offset + length > len(data):
            raise _malformed_reply()
        body = data[offset + NLMSG_HEADER.size:offset + length]
        if sequence == seq:
            if kind == NLMSG_DONE:
                return entries, True
            if kind == NLMSG_ERROR:
                if len(body) < 4:
                    raise _malformed_reply()
                code = -struct.unpack_from("=i", body)[0]
                if code:
                    raise OSError(code, os.strerror(code))
            elif kind == RTM_NEWADDR:
                entry = _parse_address(body)
                if entry is not None:
                    entries.append(entry)
        offset += _netlink_align(length)
    return entries, False


def interface_addresses() -> List[InterfaceAddress]:
    """Every address of every interface, from one RTM_GETADDR dump over NETLINK_ROUTE (what `ip -o addr show` asks
    the kernel), ordered by interface index, IPv4 before IPv6 within one, as `ip` prints them. Raises OSError when the
    kernel cannot be asked or does not answer as expected."""
    seq = 1
    request = (NLMSG_HEADER.pack(NLMSG_HEADER.size + IFADDRMSG.size, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, seq, 0)
               + IFADDRMSG.pack(socket.AF_UNSPEC, 0, 0, 0, 0))
    entries, received = [], 0
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
        sock.settimeout(NETLINK_TIMEOUT)
        sock.bind((0, 0))
        sock.send(request)
        while True:
            data = sock.recv(65536)
            received += len(data)
            if not data:
                raise OSError(errno.EPROTO, "empty netlink reply")
            if received > NETLINK_REPLY_MAX:
                raise OSError(errno.EMSGSIZE, f"netlink reply over {NETLINK_REPLY_MAX} bytes")
            found, done = parse_address_messages(data, seq)
            entries.extend(found)
            if done:
                return sorted(entries, key=lambda entry: entry.index)


def canonical_name(host: str) -> Optional[str]:
    """What `hostname -f` prints: the canonical name of the host from the resolver, or None."""
    try:
        return socket.getaddrinfo(host, None, flags=socket.AI_CANONNAME)[0][3] or None
    except (OSError, IndexError):
        return None


def discover_sans(node: str) -> Tuple[List[San], bool, Optional[str]]:
    """Node name, FQDN when it differs, every global address of every interface (also off the default route,
    virtual or down, as the shell resolver named them from `ip -o addr show`), then loopback. Returns the list,
    whether any address was found, and why the addresses could not be listed (None when they could)."""
    sans = [San("DNS", node)]
    fqdn = canonical_name(socket.gethostname())
    if fqdn and fqdn.lower() != node.lower() and valid_dns_name(fqdn):
        sans.append(San("DNS", fqdn))
    try:
        found = interface_addresses()
    except OSError as err:
        return finish_sans(sans), False, err.strerror or str(err)
    addresses = []
    for entry in found:
        # The kernel's "global" scope: private networks included (most managers live on one). Loopback and
        # link-local addresses are left out even when configured with that scope, and IPv6 addresses that are
        # deprecated or not usable yet.
        address = ipaddress.ip_address(entry.address)
        if entry.scope != RT_SCOPE_UNIVERSE or address.is_loopback or address.is_link_local:
            continue
        if entry.family == socket.AF_INET6 and entry.flags & (IFA_F_DEPRECATED | IFA_F_TENTATIVE | IFA_F_DADFAILED):
            continue
        addresses.append(San("IP", str(address)))
    return finish_sans(sans + addresses), bool(addresses), None


def resolve_san_lists(lookup: Lookup, node: str, pairs: List[str],
                      report: Report) -> Optional[Dict[str, List[San]]]:
    """Each pair's list: explicit, or discovered. Every explicit list is validated before any leaf is issued; one
    bad list stops them all."""
    if lookup.get(OLD_SANS_VAR, empty_is_unset=False) is not None:
        report.warning(f"{OLD_SANS_VAR} is ignored: it named the indexer client pair, which now comes from the indexer")
    lists, discovered_for, ok = {}, [], True
    for pair, var in (("remoted", REMOTED_SANS_VAR), ("apid", APID_SANS_VAR)):
        found = lookup.get(var, empty_is_unset=False)
        if found is None:
            discovered_for.append((pair, var))
            continue
        sans, problem = parse_san_list(found[0])
        if problem:
            report.problem(INVALID, var, f"{problem} (set in {found[1]})")
            ok = False
        else:
            lists[pair] = sans
    if not ok:
        return None
    needed = [(pair, var) for pair, var in discovered_for if pair in pairs]
    if needed:
        sans, found_address, problem = discover_sans(node)
        if problem is not None or not found_address:
            why = f"cannot list the interface addresses ({problem})" if problem is not None \
                else "no global interface address"
            report.warning(f"{why}; the certificates name this node only by name and loopback. "
                           f"Set {' and '.join(var for _, var in needed)} to add its addresses")
        for pair, _ in needed:
            lists[pair] = sans
    return lists


def server_name(node: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                      x509.NameAttribute(NameOID.LOCALITY_NAME, "California"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wazuh"),
                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Wazuh"),
                      x509.NameAttribute(NameOID.COMMON_NAME, node)])


def issue_server_pair(ca: CaState, node: str, sans: List[San]) -> Tuple[bytes, bytes]:
    """One function, one profile for both server pairs, as the shell's _wmc_generate_server_pair: the certificate
    file carries the leaf, a blank line, then the CA file."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _now()
    cert = (x509.CertificateBuilder()
            .subject_name(server_name(node)).issuer_name(ca.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CERT_BACKDATE)
            .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.cert.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([san.general_name() for san in sans]), critical=False)
            .sign(ca.key, hashes.SHA256()))
    key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM) + b"\n" + ca.cert_bytes, key_bytes


SAN_LABELS = ((x509.DNSName, "DNS"), (x509.IPAddress, "IP"), (x509.RFC822Name, "email"),
              (x509.UniformResourceIdentifier, "URI"))


def describe_leaf(cert: x509.Certificate) -> str:
    """`DN <subject>; SANs <list>`, each name labelled by its type, or `SANs none`: a client certificate may have
    no subjectAltName at all."""
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        names = []
    labelled = []
    for name in names:
        label = next((text for kind, text in SAN_LABELS if isinstance(name, kind)), type(name).__name__)
        labelled.append(f"{label}:{name.value}")
    return f"DN {cert.subject.rfc4514_string()}; SANs {', '.join(labelled) or 'none'}"


def pair_problem(paths: Paths, certs: Dir, pair: ServerPair, anchors: Optional[List[x509.Certificate]],
                 bundle: str) -> Tuple[Optional[x509.Certificate], Optional[str]]:
    """Whether a present pair is usable. Raises UnsafeEntry for a file root may not trust. The Server API's file holds
    the leaf, then any intermediate CAs that lead to one of `anchors`; a leaf agents verify (remoted, authd) must chain
    to `anchors` (the agents' bundle, file `bundle`) on its own. `anchors` None skips the chain test (--check with no
    CA to test against)."""
    spec = certs_file_spec(paths)
    cert_data = read_file(certs, pair.cert, spec)
    key_data = read_file(certs, pair.key, spec)
    try:
        leaf, *intermediates = x509.load_pem_x509_certificates(cert_data)
    except ValueError:
        return None, "not a PEM certificate"
    problem = parse_problem([leaf, *intermediates])
    if problem:
        return None, problem
    key, problem = ca_key_problem(key_data, leaf)
    if problem:
        return leaf, f"its key {pair.key} does not match it" if "match" in problem else f"the key is {problem}"
    now = _now()
    if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
        return leaf, "expired" if now > leaf.not_valid_after_utc else "not valid yet"
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return leaf, "a CA certificate, not a server certificate"
    except x509.ExtensionNotFound:
        return leaf, "needs an explicit basicConstraints CA:FALSE"
    try:
        if ExtendedKeyUsageOID.SERVER_AUTH not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            return leaf, "its extendedKeyUsage does not include serverAuth"
    except x509.ExtensionNotFound:
        pass
    try:
        leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return leaf, "has no subjectAltName"
    if anchors is not None:
        if pair.anchors == "bundle":
            # remoted hands agents the bundle (GET /cacerts) only when the leaf chains to it with nothing else, and an
            # agent holds nothing else: the intermediates of the pair's file do not count.
            return leaf, chain_problem(leaf, [], anchors, "the manager's CA", now, ExtendedKeyUsageOID.SERVER_AUTH,
                                       no_path=f"agents are handed {certs.child(bundle)} alone: an intermediate CA "
                                               f"that issued it belongs in that file")
        return leaf, chain_problem(leaf, intermediates, anchors, "the manager's CA", now,
                                   ExtendedKeyUsageOID.SERVER_AUTH)
    return leaf, None


def issuer_problem(issuer: x509.Certificate, now: datetime.datetime, purpose: x509.ObjectIdentifier,
                   window: bool = True) -> Optional[str]:
    """A CA on a leaf's path must be valid now (unless `window` is False), authorized to sign certificates and, when
    it restricts its extendedKeyUsage, allowed the leaf's purpose. That last rule is OpenSSL's, which every client of
    these certificates applies along the chain: anyExtendedKeyUsage alone does not grant a purpose."""
    if window and not issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc:
        return "expired" if now > issuer.not_valid_after_utc else "not valid yet"
    try:
        is_ca = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        return "not a CA certificate (basicConstraints CA:TRUE missing)"
    try:
        if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
            return "keyUsage does not include keyCertSign"
    except x509.ExtensionNotFound:
        pass
    try:
        if purpose not in issuer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            return f"its extendedKeyUsage does not include {PURPOSE_NAMES[purpose]}"
    except x509.ExtensionNotFound:
        pass
    return None


def _self_signed(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer and _issued_by(cert, cert)


def chain_problem(leaf: x509.Certificate, intermediates: List[x509.Certificate], anchors: List[x509.Certificate],
                  issuer_label: str, now: datetime.datetime, purpose: x509.ObjectIdentifier,
                  no_path: str = "no path to it from the certificates in the file") -> Optional[str]:
    """Whether `leaf` chains to one of `anchors`, directly or through `intermediates` (the certificates that follow
    it in its file, never trusted on their own), with every CA of that path, the anchor included, valid now, allowed
    to sign and allowed `purpose`. Historical CAs may remain among the anchors: the path is built through one that is
    usable now, so a renewed CA is not refused because an expired certificate with the same name and key is listed
    too. A self-signed certificate in the file is not offered as an intermediate: it could only be an anchor, and
    one with an anchor's name sends the path builder round in circles."""
    problem = key_type_problem(leaf.public_key())
    if problem:
        return f"{problem}; {ACCEPTED_KEY_TYPES}"
    intermediates = [cert for cert in intermediates if not _self_signed(cert)]
    verifier = (PolicyBuilder().store(Store(anchors)).time(now)
                .extension_policies(ca_policy=CHAIN_CA_POLICY, ee_policy=CHAIN_LEAF_POLICY)
                .build_client_verifier())
    try:
        chain = verifier.verify(leaf, intermediates).chain
    except VerificationError as exc:
        # No usable path. When an anchor signed the leaf itself, say what is wrong with that anchor: it is the
        # certificate the operator has to replace.
        signers = [anchor for anchor in anchors if _issued_by(leaf, anchor)]
        problems = [problem for problem in (issuer_problem(signer, now, purpose) for signer in signers) if problem]
        if problems:
            return f"issuer CA: {problems[0]}"
        reason = str(exc).split("validation failed: ", 1)[-1].split(" (encountered processing", 1)[0].strip()
        reason = reason.removeprefix("candidates exhausted: ")
        if "Forbidden public key algorithm" in reason or "RSA key is too weak" in reason:
            # A CA of the path on a key the checks do not accept: name it, in words.
            issuers = {leaf.issuer, *(cert.issuer for cert in intermediates)}
            for ca in (*intermediates, *anchors):
                problem = key_type_problem(ca.public_key()) if ca.subject in issuers else None
                if problem:
                    return f"issuer CA ({ca.subject.rfc4514_string()}): {problem}; {ACCEPTED_KEY_TYPES}"
        # The verifier's own text may end in a Rust debug rendering of the algorithm: keep the sentence only.
        reason = reason.split(": AlgorithmIdentifier", 1)[0]
        if not reason or reason.startswith("all candidates exhausted"):
            reason = no_path
        return f"not issued by {issuer_label} ({reason})"
    for ca in chain[1:]:
        problem = issuer_problem(ca, now, purpose)
        if problem:
            return f"issuer CA: {problem}"
    return None


# The longest path timeless_chain_problem() builds, CAs above the leaf: far more than any deployment uses, and a bound
# on the search through a file of many intermediates.
TIMELESS_PATH_DEPTH = 8


def timeless_chain_problem(leaf: x509.Certificate, intermediates: List[x509.Certificate],
                           anchors: List[x509.Certificate], issuer_label: str, now: datetime.datetime,
                           purpose: x509.ObjectIdentifier,
                           no_path: str = "no path to it from the certificates in the file") -> Optional[str]:
    """chain_problem() with every validity window left out. The path builder of x509.verification judges every
    certificate of a path against one moment, and no moment fits a CA renewed in place (same name and key) after the
    leaf it issued expired: their windows do not overlap. So the path is built here, by name and signature, with
    every CA of it a CA (basicConstraints CA:TRUE), allowed to sign certificates, allowed `purpose`, and its
    pathLenConstraint not exceeded by the CAs below it; only the dates are not looked at."""
    problem = key_type_problem(leaf.public_key())
    if problem:
        return f"{problem}; {ACCEPTED_KEY_TYPES}"
    pool = [cert for cert in intermediates if not _self_signed(cert)]
    found: List[str] = []

    def ca_problem(ca: x509.Certificate, below: int) -> Optional[str]:
        problem = issuer_problem(ca, now, purpose, window=False)
        if problem:
            return problem
        problem = key_type_problem(ca.public_key())
        if problem:
            return f"{problem}; {ACCEPTED_KEY_TYPES}"
        limit = ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
        if limit is not None and below > limit:
            return f"its pathLenConstraint ({limit}) does not allow the {below} CA(s) below it"
        return None

    def walk(cert: x509.Certificate, path: List[x509.Certificate]) -> bool:
        # `path`: the CAs above the leaf so far; the next one has len(path) CAs below it.
        for anchor in anchors:
            if _issued_by(cert, anchor):
                problem = ca_problem(anchor, len(path))
                if problem is None:
                    return True
                found.append(problem)
        if len(path) >= TIMELESS_PATH_DEPTH:
            return False
        for middle in pool:
            if middle in path or not _issued_by(cert, middle):
                continue
            problem = ca_problem(middle, len(path))
            if problem is not None:
                found.append(problem)
                continue
            if walk(middle, [*path, middle]):
                return True
        return False

    if walk(leaf, []):
        return None
    if found:
        return f"issuer CA: {found[0]}"
    if any(ca.subject == leaf.issuer for ca in (*anchors, *pool)):
        # A CA of the leaf's issuer name is there, but its key did not sign the leaf.
        return f"not issued by {issuer_label} (signature does not match)"
    return f"not issued by {issuer_label} ({no_path})"


def _issued_by(leaf: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        return leaf.issuer == issuer.subject and leaf.verify_directly_issued_by(issuer) is None
    except (InvalidSignature, ValueError, TypeError):
        return False


def _exists(parent: Dir, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def pair_anchors(paths: Paths, certs: Dir, ca: CaState, names: TlsNames) -> Dict[str, List[x509.Certificate]]:
    """A pair agents verify must chain to a certificate of the agents' bundle (it may hold rotation CAs); the Server
    API's to the manager's CA, the one export/ca.pem hands the dashboard."""
    bundle = [ca.cert]
    try:
        if names.bundle is not None:
            certificates = x509.load_pem_x509_certificates(read_file(certs, names.bundle, certs_file_spec(paths)))
            # A certificate of the bundle that does not parse is left out (check_bundle reports the bundle), so the
            # chain test never reads it.
            bundle = [cert for cert in certificates if parse_problem([cert]) is None] or bundle
    except (FileNotFoundError, UnsafeEntry, ValueError):
        pass
    return {"bundle": bundle, "ca": [ca.cert]}


def _missing_pair(certs: Dir, pair: ServerPair, report: Report) -> None:
    if pair.kind is None:
        issued = ", ".join(DEFAULT_PAIRS["remoted"] + DEFAULT_PAIRS["apid"])
        report.problem(MISSING, certs.child(pair.cert), f"configured as {pair.keys} in {pair.source}; stage the pair "
                                                       f"(the resolver issues only {issued})")
    else:
        report.problem(MISSING, certs.child(pair.cert), "run --install to issue it, or stage the pair")


def _judge_present(paths: Paths, certs: Dir, pair: ServerPair, anchors: Optional[Dict[str, List[x509.Certificate]]],
                   names: TlsNames, report: Report, kept_line: bool = True) -> Optional[bool]:
    """Report a present pair's verdict: True when it is complete and usable, False when it was refused, None when
    neither of its files exists. `kept_line`: say what was kept (the writing modes do; --check does not)."""
    has_cert, has_key = _exists(certs, pair.cert), _exists(certs, pair.key)
    if has_cert and has_key:
        try:
            leaf, problem = pair_problem(paths, certs, pair, anchors[pair.anchors] if anchors else None,
                                         names.bundle or BUNDLE)
        except UnsafeEntry as exc:
            report.unsafe(exc)
            return False
        if problem:
            report.problem(INVALID, certs.child(pair.cert), problem)
            return False
        if kept_line:
            report.progress(f"{certs.child(pair.cert)}: kept; {describe_leaf(leaf)}")
        return True
    if has_cert or has_key:
        present, other = (pair.cert, pair.key) if has_cert else (pair.key, pair.cert)
        report.problem(INVALID, certs.child(present), f"half a pair ({other} is missing)")
        return False
    return None


def step_server_pairs(paths: Paths, certs: Dir, ca: CaState, lookup: Lookup, report: Report, mode: str,
                      names: TlsNames) -> None:
    """Keep a usable pair, refuse a broken or half one, issue an absent one at --install with a signing CA when its
    names are the default ones. A turned-off listener's pair is issued like any other, never judged."""
    anchors = pair_anchors(paths, certs, ca, names)
    to_issue = []
    for pair in names.pairs:
        if pair.on and _judge_present(paths, certs, pair, anchors, names, report) is not None:
            continue
        if _exists(certs, pair.cert) or _exists(certs, pair.key):
            continue                                     # a turned-off listener's present files are not judged
        if mode != "install" or pair.kind is None:
            if pair.on:
                _missing_pair(certs, pair, report)
        elif ca.kind != "signing":
            if pair.on:
                report.problem(MISSING, certs.child(pair.cert), f"no CA key to issue it; stage the pair or the CA in "
                                                               f"{os.path.join(paths.conf, CA_DIR)}")
        elif pair.kind not in to_issue:
            to_issue.append(pair.kind)
    if not to_issue or report.has(UNSAFE):
        return
    node = node_name(lookup, report)
    if node is None:
        return
    if len(node) > COMMON_NAME_MAX:
        # Only WAZUH_MANAGER_NODE_NAME can get here: a discovered host name is one DNS label (63 at most).
        found = lookup.get(NODE_NAME_VAR)
        source = f"; set in {found[1]}" if found is not None else ""
        report.problem(INVALID, NODE_NAME_VAR,
                       f"too long for a certificate's common name ({COMMON_NAME_MAX} characters at most{source})")
        return
    lists = resolve_san_lists(lookup, node, to_issue, report)
    if lists is None:
        return
    gid = paths.service_gid()
    for name in to_issue:
        cert_name, key_name = DEFAULT_PAIRS[name]
        cert_bytes, key_bytes = issue_server_pair(ca, node, lists[name])
        write_file(certs, key_name, key_bytes, 0o640, 0, gid)
        write_file(certs, cert_name, cert_bytes, 0o640, 0, gid)
        leaf = x509.load_pem_x509_certificates(cert_bytes)[0]
        report.progress(f"{certs.child(cert_name)}: issued; {describe_leaf(leaf)}")


def check_server_pairs(paths: Paths, certs: Dir, ca: Optional[CaState], lookup: Lookup, report: Report,
                       names: TlsNames) -> None:
    """--check's part: validate the present pairs of the listeners that are on, and report an absent one as MISSING
    as --prestart would (pairs are issued at --install only). With no CA, --prestart stops at the CA, and so does
    this. No write."""
    anchors = pair_anchors(paths, certs, ca, names) if ca is not None and ca.kind != "absent" else None
    for pair in names.pairs:
        if pair.on and _judge_present(paths, certs, pair, anchors, names, report, kept_line=False) is None \
                and ca is not None and ca.kind != "absent":
            _missing_pair(certs, pair, report)


def validate_san_lists(lookup: Lookup, report: Report) -> None:
    """Every mode's test of the explicit SAN lists, whether or not a pair is about to be issued: --prestart runs the
    same tests as --check."""
    for var in (REMOTED_SANS_VAR, APID_SANS_VAR):
        found = lookup.get(var, empty_is_unset=False)
        if found is not None:
            _, problem = parse_san_list(found[0])
            if problem:
                report.problem(INVALID, var, f"{problem} (set in {found[1]})")


# ================================================= Indexer trust ===============================================


@dataclasses.dataclass(frozen=True)
class ImportUnit:
    """Files imported together from the indexer's export: `files[i]` in certs/ comes from `sources[i]`, in the
    order they are written (a key before its certificate). The marker says this manager imported them."""

    label: str
    files: Tuple[str, ...]
    sources: Tuple[str, ...]
    marker: Optional[str]                 # None: a unit under configured names, never imported, only staged
    missing: str


CA_UNIT = ImportUnit("the indexer CA", (INDEXER_CA,), (SOURCE_CA,), INDEXER_CA_MARKER,
                     "install wazuh-indexer on this host first, or stage the indexer's export/ca.pem there")
PAIR_UNIT = ImportUnit("the indexer client pair", (CONNECTOR_KEY, CONNECTOR), (SOURCE_CLIENT_KEY, SOURCE_CLIENT),
                       CONNECTOR_MARKER, "install wazuh-indexer on this host first, or stage a pair issued by the "
                                         "indexer's CA for this node")


def indexer_ca_problem(data: bytes, now: Optional[datetime.datetime] = None,
                       windows: bool = True) -> Tuple[Optional[List[x509.Certificate]], Optional[str]]:
    """The indexer's CA file: one or more CA certificates, each inside its validity window at `now` (unless
    `windows` is False, which tests everything but time)."""
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        return None, "not a PEM certificate"
    problem = parse_problem(certs)
    if problem:
        return None, problem
    now = now if now is not None else _now()
    for cert in certs:
        try:
            is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca:
            return None, "not a CA certificate (basicConstraints CA:TRUE missing)"
        problem = key_type_problem(cert.public_key())
        if problem:
            return None, f"a CA it holds ({cert.subject.rfc4514_string()}) has {problem}; {ACCEPTED_KEY_TYPES}"
        if windows and not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            return None, "expired" if now > cert.not_valid_after_utc else "not valid yet"
    return certs, None


def connector_problem(cert_data: bytes, key_data: bytes, cas: Optional[List[x509.Certificate]],
                      ca_path: str, now: Optional[datetime.datetime] = None, windows: bool = True) -> Optional[str]:
    """The client pair the manager presents to the indexer: the leaf, then any intermediate CAs, chaining to a
    certificate of the indexer's CA file; the leaf inside its window, not a CA, with an extendedKeyUsage that
    includes clientAuth, and matching its key. Checked here because nothing else looks at it before the first
    handshake. `cas` None: no CA is configured (the connector trusts the system store), so there is no chain to test.
    `windows` False: everything but the validity windows, of the leaf and of every CA on its path."""
    try:
        leaf, *intermediates = x509.load_pem_x509_certificates(cert_data)
    except ValueError:
        return "not a PEM certificate"
    problem = parse_problem([leaf, *intermediates])
    if problem:
        return problem
    _, problem = ca_key_problem(key_data, leaf)
    if problem:
        return "its key does not match it" if "match" in problem else f"its key is {problem}"
    now = now if now is not None else _now()
    if windows and not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
        return "expired" if now > leaf.not_valid_after_utc else "not valid yet"
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return "a CA certificate, not a client certificate"
    except x509.ExtensionNotFound:
        pass
    try:
        usages = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usages = []
    if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
        return "has no extendedKeyUsage with clientAuth"
    if cas is None:
        return None
    if not windows:
        return timeless_chain_problem(leaf, intermediates, cas, ca_path, now, ExtendedKeyUsageOID.CLIENT_AUTH)
    return chain_problem(leaf, intermediates, cas, ca_path, now, ExtendedKeyUsageOID.CLIENT_AUTH)


# The indexer's material is judged twice: as it stands now, and with every validity window left out. A defect that
# only the clock decides (expired, not valid yet, in the file or on the path) does not stop the start: the connection
# fails until the material is renewed or the clock is right, and the connector keeps validating TLS itself. Anything
# else is refused as before.

TIME_ONLY_CONSEQUENCE = "the indexer connection fails until it is renewed or the clock is right"


@dataclasses.dataclass(frozen=True)
class Verdict:
    """`problem` None: usable. `time_only`: the only defect is a validity window, reported as a WARNING."""

    problem: Optional[str] = None
    time_only: bool = False


def _utc(moment: datetime.datetime) -> str:
    return f"{moment:%Y-%m-%d %H:%M:%S} UTC"


def _window_text(certs: List[x509.Certificate], now: datetime.datetime, first_is_leaf: bool) -> str:
    """Which certificate is outside its window, and since or until when."""
    for index, cert in enumerate(certs):
        if now > cert.not_valid_after_utc:
            what = f"expired on {_utc(cert.not_valid_after_utc)}"
        elif now < cert.not_valid_before_utc:
            what = f"not valid until {_utc(cert.not_valid_before_utc)}"
        else:
            continue
        if index == 0 and first_is_leaf:
            return what
        return f"{'a CA on its path' if first_is_leaf else 'a CA it holds'} ({cert.subject.rfc4514_string()}) {what}"
    return "outside its validity window"


def indexer_ca_verdict(data: bytes) -> Tuple[Optional[List[x509.Certificate]], Verdict]:
    """The CA file's certificates (also when only time refuses them, so they still count as trust) and its verdict."""
    cas, problem = indexer_ca_problem(data)
    if problem is None:
        return cas, Verdict()
    timeless, structural = indexer_ca_problem(data, windows=False)
    if structural is None:
        return timeless, Verdict(_window_text(timeless, _now(), first_is_leaf=False), True)
    return None, Verdict(structural)


def connector_verdict(cert_data: bytes, key_data: bytes, cas: Optional[List[x509.Certificate]],
                      ca_path: str) -> Verdict:
    """The client pair's verdict. When it fails now, only time refuses it if it passes with every validity window
    left out: an expired or not-yet-valid leaf, intermediate or CA, a clock behind or ahead of all of them, or a CA
    renewed in place after the leaf it issued expired, whose windows share no moment at all. Otherwise the reason
    given is the one with the windows left out, so a structural defect is named, not a date."""
    problem = connector_problem(cert_data, key_data, cas, ca_path)
    if problem is None:
        return Verdict()
    try:
        leaf, *intermediates = x509.load_pem_x509_certificates(cert_data)
    except ValueError:
        return Verdict(problem)
    now = _now()
    structural = connector_problem(cert_data, key_data, cas, ca_path, now, windows=False)
    if structural is None:
        issuers = {cert.issuer for cert in (leaf, *intermediates)}
        anchors = [ca for ca in (cas or []) if ca.subject in issuers]
        return Verdict(_window_text([leaf, *intermediates, *anchors], now, first_is_leaf=True), True)
    return Verdict(structural)


def report_verdict(report: Report, path: str, verdict: Verdict) -> None:
    if verdict.time_only:
        report.warning(f"{path}: {verdict.problem}; {TIME_ONLY_CONSEQUENCE}")
    elif verdict.problem:
        report.problem(INVALID, path, verdict.problem)


def open_indexer_source(paths: Paths, report: Report):
    """The indexer's export/ as a Dir; None when it does not exist; "unsafe" (reported) when root may not trust it."""
    try:
        return open_top(paths.indexer_export, INDEXER_EXPORT)
    except FileNotFoundError:
        return None
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return "unsafe"


def read_source(source, unit: ImportUnit, report: Report):
    """The unit's files from the export, keyed by their names in certs/: None when any is absent, "unsafe" when any
    fails rule 1 (reported)."""
    if source is None or source == "unsafe" or not unit.sources:
        return None if not unit.sources else source
    contents = {}
    for name, target in zip(unit.sources, unit.files):
        try:
            # The client key is a secret: root's, no group or other bit; the certificates only must not be writable.
            contents[target] = read_file(source, name, PRIVATE_FILE if name == SOURCE_CLIENT_KEY else ROOT_FILE)
        except FileNotFoundError:
            return None
        except UnsafeEntry as exc:
            report.unsafe(exc)
            return "unsafe"
    return contents


def import_state(certs: Dir, unit: ImportUnit) -> str:
    """imported (the marker is there) · staged (every file, no marker) · half (some files, no marker) · absent."""
    if unit.marker is not None and _exists(certs, unit.marker):
        return "imported"
    present = [_exists(certs, name) for name in unit.files]
    if all(present):
        return "staged"
    return "half" if any(present) else "absent"


def _write_unit(paths: Paths, certs: Dir, unit: ImportUnit, contents: Dict[str, bytes], marker_present: bool) -> None:
    """The marker first: a run interrupted after it finds a marked, incomplete unit and imports it again, where an
    unmarked one would pass for staged and never be replaced."""
    gid = paths.service_gid()
    if not marker_present:
        write_file(certs, unit.marker, b"", 0o640, 0, gid)
    for name in unit.files:
        write_file(certs, name, contents[name], 0o640, 0, gid)


@dataclasses.dataclass(frozen=True)
class Selection:
    """What a unit will hold after this run. `contents` (name -> bytes) is None when the unit is refused or missing;
    `candidate` is what was validated, kept even when it failed; `origin` says where it comes from: staged, kept
    (imported earlier), incoming (from the export, still to be written), missing, or None (refused, unsafe);
    `pending` holds the write still to do for an incoming unit, as (marker already present, progress line)."""

    contents: Optional[Dict[str, bytes]]
    origin: Optional[str]
    candidate: Optional[Dict[str, bytes]] = None
    pending: Optional[Tuple[bool, str]] = None


def _select_unit(paths: Paths, certs: Dir, source, unit: ImportUnit, validate, report: Report) -> Selection:
    """Apply the import rule to one unit and report what it finds, without writing anything: the caller decides
    which selections are written, once it knows they fit together. `validate` returns a Verdict: material that only
    time refuses is kept with a WARNING, and imported from the export only into a gap -- when nothing in place is
    usable now -- never over material that is."""
    state = import_state(certs, unit)
    if state == "imported":
        try:
            read_file(certs, unit.marker, certs_file_spec(paths))
        except UnsafeEntry as exc:
            report.unsafe(exc)
            return Selection(None, None)
    if state == "half":
        present = [n for n in unit.files if _exists(certs, n)][0]
        missing = [n for n in unit.files if not _exists(certs, n)][0]
        report.problem(INVALID, certs.child(present), f"half a pair ({missing} is missing)")
        return Selection(None, None)
    complete = all(_exists(certs, name) for name in unit.files)
    current = None
    if complete:
        try:
            current = {name: read_file(certs, name, certs_file_spec(paths)) for name in unit.files}
        except UnsafeEntry as exc:
            report.unsafe(exc)
            return Selection(None, None)
    blamed = certs.child(unit.files[-1])
    if state == "staged":
        verdict = validate(current)
        report_verdict(report, blamed, verdict)
        if verdict.problem and not verdict.time_only:
            return Selection(None, "staged", current)
        report.progress(f"{blamed}: staged; kept as it is")
        return Selection(current, "staged", current)
    incoming = read_source(source, unit, report)
    if complete and state == "imported" and (not isinstance(incoming, dict) or incoming == current):
        verdict = validate(current)
        report_verdict(report, blamed, verdict)
        if verdict.problem and not verdict.time_only:
            return Selection(None, "kept", current)
        report.progress(f"{blamed}: imported earlier; unchanged")
        return Selection(current, "kept", current)
    if isinstance(incoming, dict):
        source_path = os.path.join(paths.indexer_export, unit.sources[-1])
        verdict = validate(incoming)
        if verdict.problem and not verdict.time_only:
            report_verdict(report, source_path, verdict)
            return Selection(None, "incoming", incoming)
        if verdict.time_only:
            report_verdict(report, source_path, verdict)
            if complete and validate(current).problem is None:
                # Never over material that is usable now: an export the clock refuses must not break a connector.
                report.progress(f"{blamed}: kept; the export is not imported over a pair valid now")
                return Selection(current, "kept", current)
        verb = "re-imported" if complete else "imported"
        return Selection(incoming, "incoming", incoming,
                         (state == "imported", f"{blamed}: {verb} from {paths.indexer_export}"))
    if incoming is None:
        report.problem(MISSING, blamed, unit.missing)
        return Selection(None, "missing")
    return Selection(None, None)


def indexer_units(names: IndexerNames) -> Tuple[Optional[ImportUnit], Optional[ImportUnit], Tuple[str, ...]]:
    """What the configuration asks for: the CA unit when the list names indexer-ca.pem, the client pair unit (the
    imported one under the default names, a staged-only one under any other), and the other listed CA files, which
    are only ever staged."""
    ca_unit = CA_UNIT if INDEXER_CA in names.cas else None
    extra = tuple(name for name in names.cas if name != INDEXER_CA)
    if names.cert is None:
        pair_unit = None
    elif (names.key, names.cert) == PAIR_UNIT.files:
        pair_unit = PAIR_UNIT
    else:
        missing = (f"configured as indexer.ssl.certificate in {names.source}; stage a pair issued by the indexer's "
                   f"CA for this node (the resolver imports only {CONNECTOR} and {CONNECTOR_KEY})")
        pair_unit = ImportUnit(PAIR_UNIT.label, (names.key, names.cert), (), None, missing)
    return ca_unit, pair_unit, extra


def extra_ca_trust(paths: Paths, certs: Dir, names: IndexerNames, extra: Tuple[str, ...], report: Report, *,
                   missing: bool) -> List[x509.Certificate]:
    """The certificates of the listed CA files other than indexer-ca.pem, which are the operator's: validated,
    never written; MISSING when absent if `missing`."""
    trust: List[x509.Certificate] = []
    for name in extra:
        present, data = read_optional(certs, name, certs_file_spec(paths), report)
        if not present:
            if missing:
                report.problem(MISSING, certs.child(name), f"configured in indexer.ssl.certificate_authorities in "
                                                           f"{names.source}; stage the indexer's CA there")
            continue
        if data is None:
            continue                                     # unsafe, reported
        cas, verdict = indexer_ca_verdict(data)
        report_verdict(report, certs.child(name), verdict)
        if cas is not None:
            trust.extend(cas)
    return trust


def _trust_label(certs: Dir, names: IndexerNames) -> str:
    return certs.child(names.cas[0]) if len(names.cas) == 1 else "the CAs of indexer.ssl.certificate_authorities"


def _chains_to_current_ca(paths: Paths, certs: Dir, pair: Dict[str, bytes], unit: ImportUnit,
                          extra_cas: List[x509.Certificate], label: str) -> bool:
    """Whether `pair` is a valid client pair under the indexer-ca.pem in place now and the other listed CA files (read
    only, problems ignored)."""
    trust = list(extra_cas)
    if _exists(certs, INDEXER_CA):
        try:
            cas, _ = indexer_ca_verdict(read_file(certs, INDEXER_CA, certs_file_spec(paths)))
        except (UnsafeEntry, OSError):
            cas = None
        if cas is not None:
            trust.extend(cas)
    if not trust:
        return False
    verdict = connector_verdict(pair[unit.files[1]], pair[unit.files[0]], trust, label)
    return verdict.problem is None or verdict.time_only


POSTPONED_ROTATION = "not imported over the indexer CA and client pair in place, which are valid now"


def _postponed_rotation(paths: Paths, certs: Dir, source: "Dir", extra_cas: List[x509.Certificate], label: str,
                        report: Report) -> bool:
    """An export with a new CA is a rotation, judged as a set: the CA and pair in place against each other, and the
    export's CA and pair against each other. While the set in place is usable now and the export's set is refused
    only by the clock, none of the three files is replaced -- the CA alone would leave the pair in place without its
    issuer, and the whole set would break a working connector until it is valid. Each refused file gets a WARNING
    and the rotation happens on a later run, once the export's set is valid. False when this rule does not apply (no
    new CA, a set incomplete, unsafe or refused for something other than time): the import rule decides."""
    if import_state(certs, CA_UNIT) != "imported" or import_state(certs, PAIR_UNIT) != "imported" \
            or not all(_exists(certs, name) for name in (*CA_UNIT.files, *PAIR_UNIT.files)):
        return False                                      # an interrupted import is the import rule's to finish
    quiet = Report(quiet=True, out=io.StringIO(), err=io.StringIO())
    incoming_ca, incoming_pair = read_source(source, CA_UNIT, quiet), read_source(source, PAIR_UNIT, quiet)
    if not isinstance(incoming_ca, dict) or not isinstance(incoming_pair, dict):
        return False
    spec = certs_file_spec(paths)
    try:
        for unit in (CA_UNIT, PAIR_UNIT):
            read_file(certs, unit.marker, spec)
        current_ca = {INDEXER_CA: read_file(certs, INDEXER_CA, spec)}
        current_pair = {name: read_file(certs, name, spec) for name in PAIR_UNIT.files}
    except (UnsafeEntry, FileNotFoundError):
        return False                                      # the import rule reports it
    if incoming_ca == current_ca:
        return False
    installed_cas, installed = indexer_ca_verdict(current_ca[INDEXER_CA])
    if installed.problem or connector_verdict(current_pair[CONNECTOR], current_pair[CONNECTOR_KEY],
                                              installed_cas + extra_cas, label).problem:
        return False                                      # nothing usable in place: a gap, imported as such
    new_cas, new_ca = indexer_ca_verdict(incoming_ca[INDEXER_CA])
    new_pair = connector_verdict(incoming_pair[CONNECTOR], incoming_pair[CONNECTOR_KEY], (new_cas or []) + extra_cas,
                                 label)
    verdicts = ((SOURCE_CA, new_ca), (SOURCE_CLIENT, new_pair))
    if any(verdict.problem and not verdict.time_only for _, verdict in verdicts) \
            or not any(verdict.problem for _, verdict in verdicts):
        return False                                      # refused outright, or usable now: the import rule decides
    for source_name, verdict in verdicts:
        if verdict.problem:
            report.warning(f"{os.path.join(paths.indexer_export, source_name)}: {verdict.problem}; "
                           f"{POSTPONED_ROTATION}")
    for name in (INDEXER_CA, CONNECTOR):
        report.progress(f"{certs.child(name)}: kept; the export's new CA and client pair are imported together "
                        f"once both are valid")
    try:
        leaf = x509.load_pem_x509_certificates(current_pair[CONNECTOR])[0]
        report.progress(f"{certs.child(CONNECTOR)}: {describe_leaf(leaf)}")
    except ValueError:
        pass
    return True


def step_indexer_trust(paths: Paths, certs: Dir, report: Report, names: IndexerNames, *, write: bool = True) -> None:
    """The indexer's CA and the client pair, selected first and written only as a combination that is valid: the
    pair that will be in place must chain to the CAs that will be in place. An export whose new CA does not issue the
    pair in place, or whose own pair is refused, changes nothing, so a working connector is never broken by an
    import. Each written unit still gets its marker before its files, so an interrupted import is finished later.
    Only the default names are imported, and only while the configuration names them; other configured files are
    staged. An empty CA list leaves the pair to the leaf checks: the connector then trusts the system store.
    With write=False, the same selection and the same report, nothing written."""
    ca_unit, pair_unit, extra = indexer_units(names)
    source = open_indexer_source(paths, report)
    # An export holding a single file root may not trust is suspect as a whole: nothing is imported from it in
    # this run, and what is already in certs/ stays (a CA imported alone could leave the kept pair without its issuer).
    if isinstance(source, Dir) and "unsafe" in (read_source(source, CA_UNIT, report),
                                                 read_source(source, PAIR_UNIT, report)):
        source.close()
        source = "unsafe"
    try:
        extra_cas = extra_ca_trust(paths, certs, names, extra, report, missing=True)
        label = _trust_label(certs, names)
        if ca_unit is not None and pair_unit is PAIR_UNIT and isinstance(source, Dir) \
                and _postponed_rotation(paths, certs, source, extra_cas, label, report):
            return
        ca = None
        trust: Optional[List[x509.Certificate]] = None
        if ca_unit is not None:
            ca = _select_unit(paths, certs, source, CA_UNIT, lambda c: indexer_ca_verdict(c[INDEXER_CA])[1], report)
            if ca.contents is not None:
                trust = (indexer_ca_verdict(ca.contents[INDEXER_CA])[0] or []) + extra_cas
        elif extra_cas:
            trust = extra_cas
        if names.listed and trust is None:
            # No usable CA: the pair cannot be judged, only found missing.
            if pair_unit is not None and import_state(certs, pair_unit) == "absent" \
                    and read_source(source, pair_unit, report) is None:
                report.problem(MISSING, certs.child(pair_unit.files[-1]), pair_unit.missing)
            return
        pair = None
        if pair_unit is not None:
            cert_name, key_name = pair_unit.files[1], pair_unit.files[0]

            def validate_pair(c):
                return connector_verdict(c[cert_name], c[key_name], trust, label)

            if ca is not None and ca.pending:
                # Decide before reporting: a pair in place that only the current CA issues is the new CA's problem.
                probe = _select_unit(paths, certs, source, pair_unit, validate_pair,
                                     Report(quiet=True, out=io.StringIO(), err=io.StringIO()))
                if probe.contents is None and probe.origin in ("staged", "kept") \
                        and _chains_to_current_ca(paths, certs, probe.candidate, pair_unit, extra_cas, label):
                    report.problem(INVALID, os.path.join(paths.indexer_export, SOURCE_CA),
                                   f"does not issue the {probe.origin} {certs.child(cert_name)}; nothing was imported")
                    return
            pair = _select_unit(paths, certs, source, pair_unit, validate_pair, report)
            if ca is not None and ca.pending and pair.contents is None and pair.origin != "missing":
                report.progress(f"{certs.child(INDEXER_CA)}: kept; the indexer's CA is imported only with a client "
                                f"pair it issued")
                return
        for unit, selection in ((CA_UNIT, ca), (pair_unit, pair)):
            if selection is not None and selection.pending:
                marker_present, line = selection.pending
                if write:
                    _write_unit(paths, certs, unit, selection.contents, marker_present)
                report.progress(line)
        if pair is not None and pair.contents is not None:
            # Which identity the connector will present, as the server pairs say theirs.
            try:
                leaf = x509.load_pem_x509_certificates(pair.contents[pair_unit.files[1]])[0]
                report.progress(f"{certs.child(pair_unit.files[1])}: {describe_leaf(leaf)}")
            except ValueError:
                pass
    finally:
        if isinstance(source, Dir):
            source.close()


def _check_indexer_current(paths: Paths, certs: Dir, report: Report, names: IndexerNames) -> None:
    """Validate the files currently in certs/ and the export's safety; never MISSING, no write."""
    ca_unit, pair_unit, extra = indexer_units(names)
    source = open_indexer_source(paths, report)
    try:
        for unit in (CA_UNIT, PAIR_UNIT):
            read_optional(certs, unit.marker, certs_file_spec(paths), report)
            read_source(source, unit, report)              # rule 1 on the export's files, reported if unsafe
        cas = None
        if ca_unit is not None:
            state = import_state(certs, CA_UNIT)
            if state in ("staged", "imported") and _exists(certs, INDEXER_CA):
                try:
                    cas, verdict = indexer_ca_verdict(read_file(certs, INDEXER_CA, certs_file_spec(paths)))
                except UnsafeEntry as exc:
                    report.unsafe(exc)
                    verdict = Verdict()
                report_verdict(report, certs.child(INDEXER_CA), verdict)
        extra_cas = extra_ca_trust(paths, certs, names, extra, report, missing=False)
        trust = None if cas is None and not extra_cas else (cas or []) + extra_cas
        if pair_unit is None:
            return
        state = import_state(certs, pair_unit)
        if state == "half":
            present = [n for n in pair_unit.files if _exists(certs, n)][0]
            missing = [n for n in pair_unit.files if not _exists(certs, n)][0]
            report.problem(INVALID, certs.child(present), f"half a pair ({missing} is missing)")
        elif (trust is not None or not names.listed) and all(_exists(certs, n) for n in pair_unit.files):
            key_name, cert_name = pair_unit.files
            try:
                spec = certs_file_spec(paths)
                verdict = connector_verdict(read_file(certs, cert_name, spec), read_file(certs, key_name, spec),
                                            trust, _trust_label(certs, names))
            except UnsafeEntry as exc:
                report.unsafe(exc)
                verdict = Verdict()
            report_verdict(report, certs.child(cert_name), verdict)
    finally:
        if isinstance(source, Dir):
            source.close()


def check_indexer_trust(paths: Paths, certs: Dir, report: Report, names: IndexerNames) -> None:
    """--check's verdict on the indexer trust equals --prestart's: the same selection runs without writing, and
    whatever it would refuse is refused here, before a restart stops anything. Its MISSING lines included: the
    selection reports a file missing only when the export has nothing to import into it, so --prestart could not
    complete it either. A broken imported generation that the selection repairs (an interrupted import) is let
    through."""
    current = Report(quiet=True, out=io.StringIO(), err=io.StringIO())
    _check_indexer_current(paths, certs, current, names)
    selection = Report(quiet=True, out=io.StringIO(), err=io.StringIO())
    step_indexer_trust(paths, certs, selection, names, write=False)
    refused = list(selection.problems)
    for warning in current.warnings + selection.warnings:
        report.warning(warning)
    if current.has(INVALID) and not current.has(UNSAFE) and not refused:
        report.progress("indexer trust: interrupted import can be recovered at --prestart")
        return
    for kind, subject, reason in current.problems + refused:
        report.problem(kind, subject, reason)


# =============================================== Whole-tree checks =============================================

EXPORT_FILES = (CREDENTIALS_ENV, EXPORT_CA, DASHBOARD_CERT, DASHBOARD_KEY, DASHBOARD_MARKER)
CA_FILES = (CA_CERT, CA_KEY, CA_MARKER)


def _open_optional_dir(conf: Dir, name: str, spec: Spec, report: Report) -> Optional[Dir]:
    try:
        return open_dir(conf, name, spec)
    except FileNotFoundError:
        return None
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return None


def check_export(paths: Paths, conf: Dir, report: Report) -> None:
    """export/: root's 0700 directory; credentials.env root's 0600, judged as the writing modes judge it; ca.pem
    root's."""
    export = _open_optional_dir(conf, EXPORT_DIR, EXPORT_SPEC, report)
    if export is None:
        return
    with export:
        report_published(paths, export, published_passwords(export, report), report)
        read_optional(export, EXPORT_CA, ROOT_FILE, report)


def check_certs_entries(certs: Dir, report: Report) -> None:
    """Nothing in certs/ may belong to anyone but root: certs/ itself is root's, so such an entry could only have
    come from a planted directory. Root-owned entries the resolver does not manage (wazuh-manager-certs' lock and
    temporaries) are left alone."""
    for name in sorted(os.listdir(certs.fd)):
        try:
            st = os.stat(name, dir_fd=certs.fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if st.st_uid != 0:
            report.problem(UNSAFE, certs.child(name), f"owned by uid {st.st_uid}, not by root")


def check_private_dir_roles(ca: Optional[Dir], export: Optional[Dir], report: Report) -> None:
    """Check the identities of already-open private directories before using their descriptors to write.
    Their ownership and mode are identical, so only their contents reveal a ca/ and export/ swap."""
    if ca is not None and export is not None and (ca.st.st_dev, ca.st.st_ino) == (export.st.st_dev, export.st.st_ino):
        report.problem(UNSAFE, export.path, f"the same directory as the opened {ca.path}")
    for opened, foreign, owner in ((ca, EXPORT_FILES, EXPORT_DIR), (export, CA_FILES, CA_DIR)):
        if opened is not None:
            for name in sorted(set(os.listdir(opened.fd)) & set(foreign)):
                report.problem(UNSAFE, opened.path, f"holds {name}, which belongs in {owner}/")


def check_swaps(conf: Dir, report: Report) -> None:
    """ca/ and export/ are both root:root 0700, so a swap between them passes their specs: their contents tell them
    apart. A publication that merely went stale (the CA was staged again by hand) is not a swap, nor a problem: every
    writing mode publishes it again."""
    ca = _open_optional_dir(conf, CA_DIR, CA_SPEC, report)
    export = _open_optional_dir(conf, EXPORT_DIR, EXPORT_SPEC, report)
    try:
        check_private_dir_roles(ca, export, report)
        if ca is not None and export is not None and _exists(ca, CA_CERT):
            try:
                own = read_file(ca, CA_CERT, CA_CERT_SPEC)
            except UnsafeEntry:
                return                                       # already reported by the other checks
            quiet = Report(quiet=True, out=io.StringIO(), err=io.StringIO())   # unsafe: reported by check_export
            if published_ca(export, own, quiet) == "stale":
                report.progress(f"{export.child(EXPORT_CA)} differs from {ca.child(CA_CERT)}; --prestart publishes it "
                                f"again")
    finally:
        for opened in (ca, export):
            if opened is not None:
                opened.close()


def run_checks(paths: Paths, conf: Dir, lookup: Lookup, report: Report, *, indexer_validity: bool = True,
               names: Optional[TlsNames] = None) -> None:
    """Every read-only test, as --check runs them and --prestart runs them before anything else. No lock, no
    subprocess, nothing written; `names` are the configured file names, read by the caller (default: the installed
    configuration's). --prestart defers indexer validity until after its import step; safety is
    always checked before any writes. Other steps report the same texts, so each is printed once."""
    names = names if names is not None else default_tls_names(paths)
    check_own_ca(paths, conf, lookup, report, names)
    check_export(paths, conf, report)
    if indexer_validity:
        check_dashboard_pair(paths, conf, report, names)
    else:
        # The writing modes judge the pair in their own step; only an unsafe entry stops them before any write.
        safety = Report(quiet=True, out=io.StringIO(), err=io.StringIO())
        check_dashboard_pair(paths, conf, safety, names)
        for kind, subject, reason in safety.problems:
            if kind == UNSAFE:
                report.problem(kind, subject, reason)
    certs = _open_optional_dir(conf, CERTS_DIR, certs_spec(paths), report)
    if certs is not None:
        with certs:
            check_certs_entries(certs, report)
            if indexer_validity:
                check_indexer_trust(paths, certs, report, names.indexer)
            else:
                safety = Report(quiet=True, out=io.StringIO(), err=io.StringIO())
                _check_indexer_current(paths, certs, safety, names.indexer)
                for kind, subject, reason in safety.problems:
                    if kind == UNSAFE:
                        report.problem(kind, subject, reason)
    check_swaps(conf, report)


# ==================================================== Lock =====================================================

CA_SPEC = Spec("dir", uid=0, gid=0, mode=0o700)


def acquire_lock(conf: Dir, timeout: Optional[float] = None) -> Dir:
    """One writing run at a time: an exclusive flock on <CONF>/ca, root's 0700 directory, which the service
    account cannot open. Created when absent. Returns the open ca/ directory; the lock lasts while it is open.

    Raises
    ------
    UnsafeEntry
        ca/ exists but is not root's 0700 directory.
    LockTimeout
        Another run held the lock for longer than `timeout` seconds.
    """
    ca = ensure_dir(conf, CA_DIR, CA_SPEC)
    deadline = time.monotonic() + (LOCK_TIMEOUT if timeout is None else timeout)
    while True:
        try:
            fcntl.flock(ca.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return ca
        except BlockingIOError:
            if time.monotonic() >= deadline:
                ca.close()
                raise LockTimeout(ca.path) from None
            time.sleep(LOCK_POLL)


# ==================================================== Modes ====================================================


def preflight(paths: Paths, report: Report, environ: Mapping[str, str]) -> Optional[Tuple[Dir, Lookup]]:
    """The read-only tests every mode starts with. Returns the open <CONF> and the lookup, or None when <CONF>
    itself cannot be trusted (nothing else is then read)."""
    conf = open_conf(paths, report)
    if conf is None:
        return None
    lookup = build_lookup(paths, conf, report, environ)
    validate_supplied(lookup, report)
    validate_san_lists(lookup, report)
    return conf, lookup


def mode_check(paths: Paths, report: Report, environ: Mapping[str, str]) -> int:
    """--check: read-only. No lock, nothing created or changed, and no subprocess but the configuration reader
    (wazuh-manager-conf dump). Reports UNSAFE and INVALID, and MISSING only for what --prestart could not complete
    either: the CA, the bundle and the server pairs (created at --install only) and indexer files with nothing in
    the export to import. What --prestart completes (a seed, the keystore, an import) is left to it; the indexer
    password, kept in the keystore, is not looked for, since the keystore is not read here."""
    result = preflight(paths, report, environ)
    if result is not None:
        with result[0] as conf:
            run_checks(paths, conf, result[1], report, names=tls_names(paths, report))
    if not report.has():
        warned = f" ({len(report.warnings)} warnings)" if report.warnings else ""
        report.progress(f"check: no problem found{warned}")
    return report.exit_code("check")


def _writing_mode(mode: str):
    def run(paths: Paths, report: Report, environ: Mapping[str, str]) -> int:
        result = preflight(paths, report, environ)
        if result is None:
            return report.exit_code(mode)
        conf, lookup = result
        with conf:
            # All writing modes must refuse an unsafe tree before creating even the lock directory. Only
            # --prestart keeps non-indexer validity verdicts; indexer imports are validated after recovery.
            # --install may also refresh stale publications.
            checks = report if mode == "prestart" else Report(quiet=True, out=io.StringIO(), err=io.StringIO())
            names = tls_names(paths, report)
            run_checks(paths, conf, lookup, checks, indexer_validity=False, names=names)
            if checks is not report:
                for kind, subject, reason in checks.problems:
                    if kind == UNSAFE:
                        report.problem(kind, subject, reason)
            # A rejected .env may contain passwords or certificate settings we could not accept.
            # Preserve the diagnostic and installer exit contract, but do not initialize from defaults.
            if report.has(UNSAFE) or not lookup.inputs_accepted:
                return report.exit_code(mode)
            try:
                ca = acquire_lock(conf)
            except UnsafeEntry as exc:
                report.unsafe(exc)
                return report.exit_code(mode)
            with ca:
                # The account can rename entries of <CONF> after preflight. Check the locked CA itself,
                # and check export again through its actual write descriptor in each publication step.
                export = _open_optional_dir(conf, EXPORT_DIR, EXPORT_SPEC, report)
                try:
                    check_private_dir_roles(ca, export, report)
                finally:
                    if export is not None:
                        export.close()
                certs = open_certs(paths, conf, report)
                try:
                    if certs is not None:
                        check_certs_entries(certs, report)
                    if report.has(UNSAFE):
                        return report.exit_code(mode)
                    step_api_passwords(paths, conf, ca, lookup, report, names)
                    if report.has(UNSAFE):
                        return report.exit_code(mode)
                    step_indexer_password(paths, lookup, report)
                    if certs is not None:
                        state = step_own_ca(paths, conf, certs, ca, lookup, report, mode, names)
                        if report.has(UNSAFE):
                            return report.exit_code(mode)
                        if state is not None:
                            step_server_pairs(paths, certs, state, lookup, report, mode, names)
                            if not report.has(UNSAFE):
                                step_dashboard_pair(paths, conf, ca, certs, state, names, report)
                        if report.has(UNSAFE):
                            return report.exit_code(mode)
                        step_indexer_trust(paths, certs, report, names.indexer)
                        if mode == "prestart":
                            _check_indexer_current(paths, certs, report, names.indexer)
                finally:
                    if certs is not None:
                        certs.close()
                if mode == "prestart" and not report.has(UNSAFE):
                    # What the steps completed is judged again by the read-only diagnosis --check runs, so a start
                    # never goes on with material the check would refuse. Each line is printed once.
                    result = Report(quiet=True, out=io.StringIO(), err=io.StringIO())
                    run_checks(paths, conf, lookup, result, names=names)
                    for kind, subject, reason in result.problems:
                        report.problem(kind, subject, reason)
                    for warning in result.warnings:
                        report.warning(warning)
        return report.exit_code(mode)
    return run


# ==================================================== Clear ====================================================
#
# --clear resets a host, or an image built by installing the package, so that the next --install resolves from
# nothing. It removes what the resolver made and keeps what it was given. Below the home it crosses directories
# the service account can write: there it only deletes, which gives the account nothing it could not do itself,
# so their owner is not checked; what must never happen is following a link out of the tree, and every
# directory is entered through its parent's descriptor with O_NOFOLLOW.

PIDFILE = re.compile(r"^.+-([0-9]{1,7})\.pid$")       # <daemon>-<pid>.pid, as the daemons name them
PID_MAX = 4194304                                     # the kernel's ceiling for pid_max
RBAC_FILES = ("rbac.db", "rbac.db.tmp")
SECURITY_DIR = ("api", "configuration", "security")
KEYSTORE_DIR = ("queue", "keystore")
RUN_DIR = ("var", "run")


def walk_dir(parent: Dir, name: str) -> Dir:
    """Open the directory `name` below `parent`, whoever owns it, never through a symbolic link.

    Raises
    ------
    FileNotFoundError
        It does not exist.
    UnsafeEntry
        It is a symbolic link or not a directory.
    """
    path = parent.child(name)
    fd = _open_dir_fd(name, parent.fd, path)
    return Dir(fd, path, os.fstat(fd))


def walk_path(top: Dir, parts: Tuple[str, ...]) -> Optional[Dir]:
    """`walk_dir` component by component; None when one is absent."""
    current = top
    try:
        for name in parts:
            child = walk_dir(current, name)
            if current is not top:
                current.close()
            current = child
    except FileNotFoundError:
        if current is not top:
            current.close()
        return None
    except BaseException:
        if current is not top:
            current.close()
        raise
    return current


def running_daemons(paths: Paths, home: Dir) -> List[Tuple[str, int]]:
    """The pidfiles in <home>/var/run that name a live process. Only names are read: the pid is the one in the
    file name, so nothing in that service-writable directory is opened. A planted pidfile can only block --clear.

    Raises
    ------
    UnsafeEntry
        var/run, or a directory above it, is a symbolic link or not a directory.
    """
    run = walk_path(home, RUN_DIR)
    if run is None:
        return []
    with run:
        names = sorted(os.listdir(run.fd))
    live = []
    for name in names:
        match = PIDFILE.match(name)
        if match is None:
            continue
        pid = int(match.group(1))
        if not 1 <= pid <= PID_MAX:            # never kill(0) or kill(-1): those name process groups
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except PermissionError:
            pass                               # it exists, it is just not ours to signal
        if os.path.isdir(os.path.join(paths.proc, str(pid))):
            live.append((os.path.join(run.path, name), pid))
    return live


def _remove(parent: Dir, name: str, report: Report) -> bool:
    """Remove one entry and say so. A failure is a problem: a clear that did not happen is never claimed."""
    try:
        if remove_entry(parent, name):
            report.progress(f"removed {parent.child(name)}")
        return True
    except OSError as exc:
        report.problem(INVALID, parent.child(name), f"could not remove it ({exc.strerror})")
        return False


def empty_dir(directory: Dir, report: Report) -> int:
    """Remove every entry of `directory` through its descriptor, subdirectories included; the directory stays.
    Returns how many entries were removed; failures are reported."""
    removed = 0
    for name in sorted(os.listdir(directory.fd)):
        path = directory.child(name)
        try:
            st = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                with walk_dir(directory, name) as sub:
                    removed += empty_dir(sub, report)
                os.rmdir(name, dir_fd=directory.fd)
            else:
                os.unlink(name, dir_fd=directory.fd)
            removed += 1
        except FileNotFoundError:
            continue
        except UnsafeEntry as exc:
            report.unsafe(exc)
        except OSError as exc:
            report.problem(INVALID, path, f"could not remove it ({exc.strerror})")
    return removed


def clear_certs(certs: Dir, report: Report) -> None:
    """The server pairs and the agents' bundle always; the indexer's files only when this manager imported them."""
    for name in SERVER_PAIR_FILES + (BUNDLE,):
        _remove(certs, name, report)
    for unit in (CA_UNIT, PAIR_UNIT):
        if import_state(certs, unit) == "imported":
            # Files first, the marker last: an interrupted clear leaves a marked unit, which the next clear finishes.
            if all([_remove(certs, name, report) for name in unit.files]):
                _remove(certs, unit.marker, report)
            continue
        for name in unit.files:
            if _exists(certs, name):
                report.progress(f"kept {certs.child(name)}: staged, no import marker")


def clear_ca(ca: Dir, report: Report) -> None:
    """The CA this host minted (its marker says so); a CA the operator staged is not ours to destroy."""
    if _exists(ca, CA_MARKER):
        if all([_remove(ca, name, report) for name in (CA_KEY, CA_CERT)]):
            _remove(ca, CA_MARKER, report)
        return
    for name in (CA_CERT, CA_KEY):
        if _exists(ca, name):
            report.progress(f"kept {ca.child(name)}: staged by the operator, no mint marker")


def clear_preconditions(paths: Paths, conf: Dir, ca: Dir, export: Optional[Dir], certs: Optional[Dir],
                        environ: Mapping[str, str], report: Report) -> None:
    """--check's safety tests, keeping only UNSAFE: invalid material is about to go, and is no reason to refuse.
    The swap and ownership tests are repeated on the descriptors the removals will use, because ca/ and export/ can
    be renamed in <CONF> between a test by name and the opening of the lock."""
    scratch = Report(quiet=True, out=io.StringIO(), err=io.StringIO())
    run_checks(paths, conf, build_lookup(paths, conf, scratch, environ), scratch)
    for kind, subject, reason in scratch.problems:
        if kind == UNSAFE:
            report.problem(kind, subject, reason)
    check_private_dir_roles(ca, export, report)
    if certs is not None:
        check_certs_entries(certs, report)


def mode_clear(paths: Paths, report: Report, environ: Mapping[str, str]) -> int:
    try:
        home = open_top(paths.home, Spec("dir"))
    except FileNotFoundError:
        report.problem(INVALID, paths.home, "no such directory")
        return 1
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return 1
    opened: List[Dir] = [home]
    try:
        try:
            live = running_daemons(paths, home)
        except UnsafeEntry as exc:
            report.unsafe(exc)
            return 1
        if live:
            for pidfile, pid in live:
                print(f"{LOG_TAG}: --clear refused: {pidfile} names the running process {pid}", file=report.err)
            print(f"{LOG_TAG}: stop the manager first: wazuh-manager-control stop", file=report.err)
            return 1
        conf = open_conf(paths, report)
        if conf is None:
            return 1
        opened.append(conf)
        try:
            ca = acquire_lock(conf)
        except UnsafeEntry as exc:
            report.unsafe(exc)
            return 1
        opened.append(ca)
        export = _open_optional_dir(conf, EXPORT_DIR, EXPORT_SPEC, report)
        certs = _open_optional_dir(conf, CERTS_DIR, certs_spec(paths), report)
        opened.extend(d for d in (export, certs) if d is not None)
        security = keystore = None
        try:
            security = walk_path(home, SECURITY_DIR)
            if security is not None:
                opened.append(security)
            keystore = walk_path(home, KEYSTORE_DIR)
            if keystore is not None:
                opened.append(keystore)
        except UnsafeEntry as exc:
            report.unsafe(exc)
        clear_preconditions(paths, conf, ca, export, certs, environ, report)
        if report.has(UNSAFE):
            report.progress("nothing was removed")
            return 1

        if certs is not None:
            clear_certs(certs, report)
        clear_ca(ca, report)
        if export is not None:
            # The dashboard's client pair goes only when it is the resolver's own; an operator's stays.
            dashboard = dashboard_pair_state(export, report)
            kept = DASHBOARD_FILES if dashboard.owner == "operator" else ()
            for name in sorted(os.listdir(export.fd)):
                if name in kept:
                    if _exists(export, name):
                        report.progress(f"kept {export.child(name)} (provided by the operator)")
                    continue
                _remove(export, name, report)
        if security is not None:
            for name in RBAC_FILES:
                if _exists(security, name):
                    if _remove(security, name, report) and name == RBAC_FILES[0]:
                        report.progress("every Server API user, role and policy it held is gone, not only the "
                                        "default users")
        if keystore is not None:
            count = empty_dir(keystore, report)
            if count:
                report.progress(f"emptied {keystore.path} ({count} entries): the indexer password is gone")
        if _exists(conf, LOCAL_ENV):
            report.progress(f"kept {conf.child(LOCAL_ENV)}")
        if report.has():
            return 1
        report.progress("cleared; the next --install resolves from nothing")
        return 0
    finally:
        for directory in reversed(opened):
            directory.close()


MODE_HANDLERS = {
    "install": _writing_mode("install"),
    "upgrade": _writing_mode("upgrade"),
    "prestart": _writing_mode("prestart"),
    "check": mode_check,
    "clear": mode_clear,
}


# ===================================================== Main ====================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wazuh-manager-resolve-credentials",
        description="Set up and check the manager's passwords and trust material. Runs as root.")
    modes = parser.add_mutually_exclusive_group()
    for mode, text in (("install", "fresh installation (package postinst/%%post, install.sh); always exits 0"),
                       ("upgrade", "upgrade of an installed manager; always exits 0"),
                       ("prestart", "before every start (default): check, then complete what is missing"),
                       ("check", "read-only checks of every file; exits 1 on any problem"),
                       ("clear", "remove the material this manager created (manager stopped)")):
        modes.add_argument(f"--{mode}", dest="mode", action="store_const", const=mode, help=text)
    parser.add_argument("-q", dest="quiet", action="store_true", help="print problems only")
    parser.add_argument("-H", dest="home", metavar="HOME", help=f"installation home (default {DEFAULT_HOME})")
    parser.set_defaults(mode="prestart")
    return parser


def main(argv: Optional[List[str]] = None, paths: Optional[Paths] = None,
         environ: Optional[Mapping[str, str]] = None, out=None, err=None) -> int:
    """Entry point. `paths` and `environ` exist for the tests; the program passes neither.

    Returns
    -------
    int
        0 or 1 as the mode defines; 2 for a usage error, a non-root caller, a held lock or an internal error.
    """
    err = err if err is not None else sys.stderr
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    if args.home is not None and not os.path.isabs(args.home):
        print(f"{LOG_TAG}: -H needs an absolute directory", file=err)
        return 2
    if os.geteuid() != 0:
        print(f"{LOG_TAG}: must run as root", file=err)
        return 2
    paths = paths if paths is not None else Paths()
    if args.home is not None:
        paths = dataclasses.replace(paths, home=os.path.normpath(args.home))
    report = Report(args.quiet, out=out, err=err)
    try:
        return MODE_HANDLERS[args.mode](paths, report, os.environ if environ is None else environ)
    except LockTimeout as exc:
        print(f"{LOG_TAG}: another resolve-credentials run holds {exc}", file=err)
        return 2
    except Exception as exc:  # pylint: disable=broad-except
        # Type, and for an OS error its errno text and file: never a value.
        detail = f"{exc.strerror} ({exc.filename})" if isinstance(exc, OSError) and exc.strerror else ""
        print(f"{LOG_TAG}: internal error: {type(exc).__name__} {detail}".rstrip(), file=err)
        return 2


if __name__ == "__main__":
    sys.exit(main())
