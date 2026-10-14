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
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

# ================================================== Constants ==================================================

# The manager's configuration directory. Fixed: a custom installation home moves the home only. Kept identical
# with WAZUH_MANAGER_CONF_DIR in src/shared/include/defs.h, Utils::MANAGER_CONF_DIR in
# src/shared_modules/utils/managerConfDir.hpp, the engine's base/managerConfig.hpp, CONF_PATH in
# framework/wazuh/core/common.py and CONF_DIR in src/init/shared.sh.
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
BUNDLE = "root-ca.pem"                    # certs/root-ca.pem: the agents' CA bundle, which remoted serves
SERVER_PAIR_FILES = ("remoted.pem", "remoted-key.pem", "apid.pem", "apid-key.pem")
NODE_NAME_VAR = "WAZUH_MANAGER_NODE_NAME"
CA_COMMON_NAME_PREFIX = "wazuh-manager-"
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
# Read with ioctl(2) per interface: the primary IPv4 address. socket does not export the constant.
SIOCGIFADDR = 0x8915
# /proc/net/if_inet6 flags of addresses a certificate must not name.
IFA_F_DEPRECATED, IFA_F_TENTATIVE, IFA_F_DADFAILED = 0x20, 0x40, 0x08

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

    def progress(self, message: str) -> None:
        if not self.quiet:
            print(f"{LOG_TAG}: {message}", file=self.out, flush=True)

    def warning(self, message: str) -> None:
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

    kind: "dir" or "file". uid: owner. gid: exact group, or None for any. mode: exact permission bits, or None.
    forbid: permission bits that must be clear (default: group and other write). For files, the link count must
    be 1, so a hard link to another file cannot pass for this one.
    """

    kind: str
    uid: int = 0
    gid: Optional[int] = None
    mode: Optional[int] = None
    forbid: int = 0o022


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
    if st.st_uid != spec.uid:
        raise UnsafeEntry(path, f"owned by uid {st.st_uid}, not by {'root' if spec.uid == 0 else spec.uid}")
    if spec.gid is not None and st.st_gid != spec.gid:
        raise UnsafeEntry(path, f"group is {_group_name(st.st_gid)}, not {_group_name(spec.gid)}")
    perms = stat.S_IMODE(st.st_mode)
    if spec.mode is not None and perms != spec.mode:
        raise UnsafeEntry(path, f"mode is {perms:04o}, not {spec.mode:04o}")
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
        self.local = local or {}
        self.indexer = indexer or {}
        self.local_path = local_path
        self.indexer_path = indexer_path

    def get(self, name: str, empty_is_unset: bool = True) -> Optional[Tuple[str, str]]:
        """Return (value, source) or None. `source` names the environment or the file, for messages."""
        if name in self.environ and (self.environ[name] or not empty_is_unset):
            return self.environ[name], "the environment"
        if name in self.local and (self.local[name][0] or not empty_is_unset):
            return self.local[name][0], f"{self.local_path}:{self.local[name][1]}"
        if name in INDEXER_EXPORTED and name in self.indexer and (self.indexer[name][0] or not empty_is_unset):
            return self.indexer[name][0], f"{self.indexer_path}:{self.indexer[name][1]}"
        return None


def conf_spec(paths: Paths) -> Spec:
    """<CONF> is root:<service group>, group-writable by design (authd, remoted and the API write there), never
    world-writable. Being group-writable is the documented exception to rule 1 of #40339: nothing in it is
    trusted unless it is root's and meets its own specification."""
    return Spec("dir", uid=0, gid=paths.service_gid(), forbid=0o002)


ROOT_FILE = Spec("file")                    # rule 1: root's, not group/world-writable, one link
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
    """Read and parse one .env file below `parent`. An absent file is no values; an unsafe or malformed one is
    reported and none of its values is used."""
    try:
        data = read_file(parent, name, ROOT_FILE)
    except FileNotFoundError:
        return None
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
        return None
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


def node_role(paths: Paths, report: Report) -> Optional[str]:
    """"worker" or "master", or None (reported) when the configuration cannot answer: then nothing is seeded,
    because seeding a worker would publish passwords for an API that runs on the master."""
    conf_file = os.path.join(paths.conf, "wazuh-manager.conf")
    if not os.access(paths.conf_bin, os.X_OK):
        report.problem(INVALID, conf_file, f"cannot read cluster.node_type ({paths.conf_bin} is missing)")
        return None
    # --skip-file-checks: at install time the certificates the file names do not exist yet, and without it the
    # whole document is refused (exit 1), which made the shell resolver read a worker as a master.
    result = run_wazuh(paths, [paths.conf_bin, "-H", paths.home, "-f", conf_file, "--skip-file-checks", "get",
                               "cluster.node_type"], want_stdout=True)
    if result.returncode == 0:
        return "worker" if result.stdout.decode(errors="replace").strip() == "worker" else "master"
    if result.returncode == 2:  # Not set: the schema default is master.
        return "master"
    report.problem(INVALID, conf_file, "cannot read cluster.node_type")
    return None


def read_published(export: Dir, report: Report) -> Dict[str, str]:
    """The passwords already published, if they are valid: what a seed that failed after publishing left behind.
    Malformed content can be published again, but an unsafe file must never be replaced."""
    try:
        data = read_file(export, CREDENTIALS_ENV, Spec("file", mode=0o600))
        parsed = parse_env(data, export.child(CREDENTIALS_ENV))
    except FileNotFoundError:
        return {}
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return {}
    except EnvSyntaxError as exc:
        report.warning(f"ignoring {export.child(CREDENTIALS_ENV)} ({exc}); it will be published again")
        return {}
    return {name: value for name, (value, _) in parsed.items()
            if name in API_USERS and password_problem(value) is None}


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


def step_api_passwords(paths: Paths, conf: Dir, ca: Dir, lookup: Lookup, report: Report) -> None:
    if rbac_seeded(paths):
        report.progress(f"{paths.rbac_db} is already seeded; the Server API passwords are left as they are")
        return
    role = node_role(paths, report)
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
        published = read_published(export, report)
        if report.has(UNSAFE):
            return
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


# ==================================================== Own CA ===================================================

CA_CERT_SPEC = Spec("file")                       # rule 1
CA_KEY_SPEC = Spec("file", forbid=0o077)          # root's private file: no group or other bit at all


def certs_spec(paths: Paths) -> Spec:
    """certs/: a real directory owned by root (rule 4), readable through the service group, never writable by it."""
    return Spec("dir", uid=0, gid=paths.service_gid(), forbid=0o022)


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


def ca_certificate_problem(data: bytes) -> Tuple[Optional[x509.Certificate], Optional[str]]:
    """Parse a CA file: exactly one certificate, self-signed, CA:TRUE, inside its validity window."""
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        return None, "not a PEM certificate"
    if len(certs) != 1:
        return None, f"holds {len(certs)} certificates, not one"
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


def server_material_present(certs: Dir) -> bool:
    """Whether any server pair file or the bundle is already in certs/: a CA is never minted beside them."""
    for name in SERVER_PAIR_FILES + (BUNDLE,):
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


def check_bundle(paths: Paths, certs: Dir, state: CaState, report: Report, mode: str) -> None:
    """certs/root-ca.pem: created from the CA when absent at --install, otherwise validated and kept as it is."""
    present, data = read_optional(certs, BUNDLE, certs_file_spec(paths), report)
    if present and data is None:
        return
    if not present:
        if mode == "install":
            write_file(certs, BUNDLE, state.cert_bytes, 0o640, 0, paths.service_gid())
            report.progress(f"wrote {certs.child(BUNDLE)} (the manager's CA)")
        elif mode != "check":
            report.problem(MISSING, certs.child(BUNDLE), "the agents' CA bundle is missing; reinstall, or stage it")
        return
    if not bundle_contains(data, state.cert):
        report.problem(INVALID, certs.child(BUNDLE), f"does not contain {os.path.join(paths.conf, CA_DIR, CA_CERT)}")


def step_own_ca(paths: Paths, conf: Dir, certs: Dir, ca: Dir, lookup: Lookup, report: Report,
                mode: str) -> Optional[CaState]:
    """--install mints or validates the CA and publishes it; --upgrade and --prestart only validate. `certs` is opened
    once by the caller and shared with the server pairs step."""
    state = load_ca(ca, report)
    if state is None:
        return None
    if state.kind == "absent":
        if mode != "install":
            report.problem(MISSING, ca.child(CA_CERT), "the manager's CA is missing; stage it there "
                                                       f"(and {CA_KEY} to issue certificates), or reinstall")
            return None
        if server_material_present(certs):
            report.problem(MISSING, ca.child(CA_CERT), "stage the CA that issued the pairs")
            return None
        node = node_name(lookup, report)
        if node is None:
            return None
        if len(CA_COMMON_NAME_PREFIX + node) > 64:
            report.problem(INVALID, NODE_NAME_VAR, "too long for the CA's common name (64 characters at most)")
            return None
        state = mint_ca(ca, node)
        origin = "minted"
    elif _exists(ca, CA_MARKER):
        origin = "minted earlier"              # by this host: --clear removes it
    else:
        origin = "staged" if state.kind == "signing" else "staged without its key (pairs cannot be issued here)"
    report.progress(f"CA {state.cert.subject.rfc4514_string()}: {origin}")
    if mode == "install":
        try:
            with ensure_dir(conf, EXPORT_DIR, EXPORT_SPEC) as export:
                check_private_dir_roles(ca, export, report)
                if report.has(UNSAFE):
                    return None
                present, current = read_optional(export, EXPORT_CA, ROOT_FILE, report)
                if current != state.cert_bytes and not (present and current is None):
                    write_file(export, EXPORT_CA, state.cert_bytes, 0o644, 0, 0)
        except UnsafeEntry as exc:
            report.unsafe(exc)
        if report.has(UNSAFE):
            return None
    check_bundle(paths, certs, state, report, mode)
    return state


def check_own_ca(paths: Paths, conf: Dir, lookup: Lookup, report: Report) -> None:
    """--check's part: validate whatever CA and bundle exist, without creating ca/ or writing anything."""
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
        if certs is not None and state is not None and state.kind != "absent":
            check_bundle(paths, certs, state, report, "check")
        if certs is not None:
            check_server_pairs(paths, certs, state, lookup, report)
            check_indexer_trust(paths, certs, report)
    finally:
        for opened in (ca, certs):
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


def interface_ipv4(name: str) -> Optional[str]:
    """The primary IPv4 address of an interface, or None. Secondary addresses are not seen: name them in the list."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            data = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, struct.pack("256s", name.encode()[:15]))
        except OSError:
            return None
    return socket.inet_ntoa(data[20:24])


def canonical_name(host: str) -> Optional[str]:
    """What `hostname -f` prints: the canonical name of the host from the resolver, or None."""
    try:
        return socket.getaddrinfo(host, None, flags=socket.AI_CANONNAME)[0][3] or None
    except (OSError, IndexError):
        return None


def _proc_lines(paths: Paths, name: str) -> List[List[str]]:
    try:
        with open(os.path.join(paths.proc, "net", name)) as handle:
            return [line.split() for line in handle if line.strip()]
    except OSError:
        return []


def default_route_interfaces(paths: Paths) -> Tuple[List[str], List[str]]:
    """The interfaces that carry a default route, IPv4 and IPv6, in the order the kernel lists them."""
    v4 = []
    for fields in _proc_lines(paths, "route")[1:]:
        if len(fields) >= 8 and fields[1] == "00000000" and fields[7] == "00000000" and fields[0] not in v4:
            v4.append(fields[0])
    v6 = []
    for fields in _proc_lines(paths, "ipv6_route"):
        if len(fields) >= 10 and fields[0] == "0" * 32 and fields[1] == "00" and fields[9] != "lo" \
                and fields[9] not in v6:
            v6.append(fields[9])
    return v4, v6


def discover_sans(paths: Paths, node: str) -> Tuple[List[San], bool]:
    """Node name, FQDN when it differs, every global address of the default-route interfaces, then loopback.
    Returns the list and whether any address was found."""
    sans = [San("DNS", node)]
    fqdn = canonical_name(socket.gethostname())
    if fqdn and fqdn.lower() != node.lower() and valid_dns_name(fqdn):
        sans.append(San("DNS", fqdn))
    v4, v6 = default_route_interfaces(paths)
    addresses = []
    for name in v4:
        address = interface_ipv4(name)
        # The kernel's "global" scope, as `ip addr` showed it to the shell resolver: private networks included (most
        # managers live on one); only loopback and link-local addresses are left out.
        if address and not (ipaddress.ip_address(address).is_loopback or ipaddress.ip_address(address).is_link_local):
            addresses.append(San("IP", address))
    for fields in _proc_lines(paths, "if_inet6"):
        if len(fields) < 6 or fields[5] not in v6 or fields[3] != "00":
            continue
        if int(fields[4], 16) & (IFA_F_DEPRECATED | IFA_F_TENTATIVE | IFA_F_DADFAILED):
            continue
        addresses.append(San("IP", str(ipaddress.IPv6Address(int(fields[0], 16)))))
    return finish_sans(sans + addresses), bool(addresses)


def resolve_san_lists(paths: Paths, lookup: Lookup, node: str, pairs: List[str],
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
        sans, found_address = discover_sans(paths, node)
        if not found_address:
            report.warning("no global address on a default-route interface; the certificates name this node only by "
                           f"name and loopback. Set {' and '.join(var for _, var in needed)} to add its addresses")
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


def describe_leaf(cert: x509.Certificate) -> str:
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = ", ".join(f"DNS:{n.value}" if isinstance(n, x509.DNSName) else f"IP:{n.value}" for n in names)
    except x509.ExtensionNotFound:
        sans = "none"
    return f"DN {cert.subject.rfc4514_string()}; SANs {sans}"


def pair_problem(paths: Paths, certs: Dir, name: str,
                 anchors: Optional[List[x509.Certificate]]) -> Tuple[Optional[x509.Certificate], Optional[str]]:
    """Whether a present pair is usable. Raises UnsafeEntry for a file root may not trust. `anchors` None skips the
    chain test (--check with no CA to test against)."""
    spec = certs_file_spec(paths)
    cert_data = read_file(certs, f"{name}.pem", spec)
    key_data = read_file(certs, f"{name}-key.pem", spec)
    try:
        leaf = x509.load_pem_x509_certificates(cert_data)[0]
    except ValueError:
        return None, "not a PEM certificate"
    key, problem = ca_key_problem(key_data, leaf)
    if problem:
        return leaf, problem.replace(CA_CERT, f"{name}.pem") if "match" in problem else f"the key is {problem}"
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
    if anchors is not None and not any(_issued_by(leaf, anchor) for anchor in anchors):
        return leaf, "not issued by the manager's CA"
    return leaf, None


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


def pair_anchors(paths: Paths, certs: Dir, ca: CaState) -> Dict[str, List[x509.Certificate]]:
    """remoted must chain to a certificate of the agents' bundle (it may hold rotation CAs); apid to the manager's
    CA, the one export/ca.pem hands the dashboard."""
    remoted = [ca.cert]
    try:
        remoted = x509.load_pem_x509_certificates(read_file(certs, BUNDLE, certs_file_spec(paths))) or remoted
    except (FileNotFoundError, UnsafeEntry, ValueError):
        pass
    return {"remoted": remoted, "apid": [ca.cert]}


def step_server_pairs(paths: Paths, certs: Dir, ca: CaState, lookup: Lookup, report: Report, mode: str) -> None:
    """Keep a usable pair, refuse a broken or half one, issue an absent one at --install with a signing CA."""
    anchors = pair_anchors(paths, certs, ca)
    to_issue = []
    for name in ("remoted", "apid"):
        cert_path = certs.child(f"{name}.pem")
        has_cert, has_key = _exists(certs, f"{name}.pem"), _exists(certs, f"{name}-key.pem")
        if has_cert and has_key:
            try:
                leaf, problem = pair_problem(paths, certs, name, anchors[name])
            except UnsafeEntry as exc:
                report.unsafe(exc)
                continue
            if problem:
                report.problem(INVALID, cert_path, problem)
            else:
                report.progress(f"{cert_path}: kept; {describe_leaf(leaf)}")
        elif has_cert or has_key:
            present, other = (f"{name}.pem", f"{name}-key.pem") if has_cert else (f"{name}-key.pem", f"{name}.pem")
            report.problem(INVALID, certs.child(present), f"half a pair ({other} is missing)")
        elif mode != "install":
            report.problem(MISSING, cert_path, "run --install to issue it, or stage the pair")
        elif ca.kind != "signing":
            report.problem(MISSING, cert_path, f"no CA key to issue it; stage the pair or the CA in "
                                               f"{os.path.join(paths.conf, CA_DIR)}")
        else:
            to_issue.append(name)
    if not to_issue or report.has(UNSAFE):
        return
    node = node_name(lookup, report)
    if node is None:
        return
    lists = resolve_san_lists(paths, lookup, node, to_issue, report)
    if lists is None:
        return
    gid = paths.service_gid()
    for name in to_issue:
        cert_bytes, key_bytes = issue_server_pair(ca, node, lists[name])
        write_file(certs, f"{name}-key.pem", key_bytes, 0o640, 0, gid)
        write_file(certs, f"{name}.pem", cert_bytes, 0o640, 0, gid)
        leaf = x509.load_pem_x509_certificates(cert_bytes)[0]
        report.progress(f"{certs.child(f'{name}.pem')}: issued; {describe_leaf(leaf)}")


def check_server_pairs(paths: Paths, certs: Dir, ca: Optional[CaState], lookup: Lookup, report: Report) -> None:
    """--check's part: validate present pairs; never MISSING, no write."""
    anchors = pair_anchors(paths, certs, ca) if ca is not None and ca.kind != "absent" else None
    for name in ("remoted", "apid"):
        has_cert, has_key = _exists(certs, f"{name}.pem"), _exists(certs, f"{name}-key.pem")
        if has_cert and has_key:
            try:
                _, problem = pair_problem(paths, certs, name, anchors[name] if anchors else None)
            except UnsafeEntry as exc:
                report.unsafe(exc)
                continue
            if problem:
                report.problem(INVALID, certs.child(f"{name}.pem"), problem)
        elif has_cert or has_key:
            present, other = (f"{name}.pem", f"{name}-key.pem") if has_cert else (f"{name}-key.pem", f"{name}.pem")
            report.problem(INVALID, certs.child(present), f"half a pair ({other} is missing)")


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
    marker: str
    missing: str


CA_UNIT = ImportUnit("the indexer CA", (INDEXER_CA,), (SOURCE_CA,), INDEXER_CA_MARKER,
                     "install wazuh-indexer on this host first, or stage the indexer's export/ca.pem there")
PAIR_UNIT = ImportUnit("the indexer client pair", (CONNECTOR_KEY, CONNECTOR), (SOURCE_CLIENT_KEY, SOURCE_CLIENT),
                       CONNECTOR_MARKER, "install wazuh-indexer on this host first, or stage a pair issued by the "
                                         "indexer's CA for this node")


def indexer_ca_problem(data: bytes) -> Tuple[Optional[List[x509.Certificate]], Optional[str]]:
    """The indexer's CA file: one or more CA certificates, each inside its validity window."""
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        return None, "not a PEM certificate"
    now = _now()
    for cert in certs:
        try:
            is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca:
            return None, "not a CA certificate (basicConstraints CA:TRUE missing)"
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            return None, "expired" if now > cert.not_valid_after_utc else "not valid yet"
    return certs, None


def connector_problem(cert_data: bytes, key_data: bytes, cas: List[x509.Certificate],
                      ca_path: str) -> Optional[str]:
    """The client pair the manager presents to the indexer: directly issued by the indexer's CA, inside its window,
    not a CA, with an extendedKeyUsage that includes clientAuth, and matching its key. Checked here because nothing
    else looks at it before the first handshake."""
    try:
        leaf = x509.load_pem_x509_certificates(cert_data)[0]
    except ValueError:
        return "not a PEM certificate"
    _, problem = ca_key_problem(key_data, leaf)
    if problem:
        return "its key does not match it" if "match" in problem else f"its key is {problem}"
    now = _now()
    if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
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
    if not any(_issued_by(leaf, ca) for ca in cas):
        return f"not issued by {ca_path}"
    return None


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
    if source is None or source == "unsafe":
        return source
    contents = {}
    for name, target in zip(unit.sources, unit.files):
        try:
            contents[target] = read_file(source, name, ROOT_FILE)
        except FileNotFoundError:
            return None
        except UnsafeEntry as exc:
            report.unsafe(exc)
            return "unsafe"
    return contents


def import_state(certs: Dir, unit: ImportUnit) -> str:
    """imported (the marker is there) · staged (every file, no marker) · half (some files, no marker) · absent."""
    if _exists(certs, unit.marker):
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


def _handle_unit(paths: Paths, certs: Dir, source, unit: ImportUnit, validate, report: Report):
    """Apply the import rule to one unit. Returns its validated contents in certs/ (name -> bytes), or None."""
    state = import_state(certs, unit)
    if state == "half":
        present = [n for n in unit.files if _exists(certs, n)][0]
        missing = [n for n in unit.files if not _exists(certs, n)][0]
        report.problem(INVALID, certs.child(present), f"half a pair ({missing} is missing)")
        return None
    complete = all(_exists(certs, name) for name in unit.files)
    current = None
    if complete:
        try:
            current = {name: read_file(certs, name, certs_file_spec(paths)) for name in unit.files}
        except UnsafeEntry as exc:
            report.unsafe(exc)
            return None
    blamed = certs.child(unit.files[-1])
    if state == "staged":
        problem = validate(current)
        if problem:
            report.problem(INVALID, blamed, problem)
            return None
        report.progress(f"{blamed}: staged; kept as it is")
        return current
    incoming = read_source(source, unit, report)
    source_cert = os.path.join(paths.indexer_export, unit.sources[-1])
    if complete and state == "imported" and (not isinstance(incoming, dict) or incoming == current):
        problem = validate(current)
        if problem:
            report.problem(INVALID, blamed, problem)
            return None
        report.progress(f"{blamed}: imported earlier; unchanged")
        return current
    if isinstance(incoming, dict):
        problem = validate(incoming)
        if problem:
            report.problem(INVALID, source_cert, problem)
            return None
        _write_unit(paths, certs, unit, incoming, state == "imported")
        report.progress(f"{blamed}: {'re-imported' if complete else 'imported'} from {paths.indexer_export}")
        return incoming
    if incoming is None:
        report.problem(MISSING, blamed, unit.missing)
    return None


def step_indexer_trust(paths: Paths, certs: Dir, report: Report) -> None:
    """The indexer's CA, then the client pair checked against whichever CA is now in place (staged or imported)."""
    source = open_indexer_source(paths, report)
    # An export holding a single file root may not trust is suspect as a whole: nothing is imported from it in
    # this run, and what is already in certs/ stays (a CA imported alone could leave the kept pair without its issuer).
    if isinstance(source, Dir) and "unsafe" in (read_source(source, CA_UNIT, report),
                                                 read_source(source, PAIR_UNIT, report)):
        source.close()
        source = "unsafe"
    try:
        ca_path = certs.child(INDEXER_CA)
        ca_contents = _handle_unit(paths, certs, source, CA_UNIT,
                                   lambda c: indexer_ca_problem(c[INDEXER_CA])[1], report)
        if ca_contents is None:
            if import_state(certs, PAIR_UNIT) == "absent" and read_source(source, PAIR_UNIT, report) is None:
                report.problem(MISSING, certs.child(CONNECTOR), PAIR_UNIT.missing)
            return
        cas, _ = indexer_ca_problem(ca_contents[INDEXER_CA])
        _handle_unit(paths, certs, source, PAIR_UNIT,
                     lambda c: connector_problem(c[CONNECTOR], c[CONNECTOR_KEY], cas, ca_path), report)
    finally:
        if isinstance(source, Dir):
            source.close()


def check_indexer_trust(paths: Paths, certs: Dir, report: Report) -> None:
    """--check's part: validate what is in certs/ and the export's safety; never MISSING, no write."""
    source = open_indexer_source(paths, report)
    try:
        for unit in (CA_UNIT, PAIR_UNIT):
            read_source(source, unit, report)              # rule 1 on the export's files, reported if unsafe
        cas = None
        state = import_state(certs, CA_UNIT)
        if state in ("staged", "imported") and _exists(certs, INDEXER_CA):
            try:
                cas, problem = indexer_ca_problem(read_file(certs, INDEXER_CA, certs_file_spec(paths)))
            except UnsafeEntry as exc:
                report.unsafe(exc)
                problem = None
            if problem:
                report.problem(INVALID, certs.child(INDEXER_CA), problem)
        state = import_state(certs, PAIR_UNIT)
        if state == "half":
            present = [n for n in PAIR_UNIT.files if _exists(certs, n)][0]
            missing = [n for n in PAIR_UNIT.files if not _exists(certs, n)][0]
            report.problem(INVALID, certs.child(present), f"half a pair ({missing} is missing)")
        elif cas is not None and all(_exists(certs, n) for n in PAIR_UNIT.files):
            try:
                spec = certs_file_spec(paths)
                problem = connector_problem(read_file(certs, CONNECTOR, spec), read_file(certs, CONNECTOR_KEY, spec),
                                            cas, certs.child(INDEXER_CA))
            except UnsafeEntry as exc:
                report.unsafe(exc)
                problem = None
            if problem:
                report.problem(INVALID, certs.child(CONNECTOR), problem)
    finally:
        if isinstance(source, Dir):
            source.close()


# =============================================== Whole-tree checks =============================================

EXPORT_FILES = (CREDENTIALS_ENV, EXPORT_CA)
CA_FILES = (CA_CERT, CA_KEY, CA_MARKER)


def _open_optional_dir(conf: Dir, name: str, spec: Spec, report: Report) -> Optional[Dir]:
    try:
        return open_dir(conf, name, spec)
    except FileNotFoundError:
        return None
    except UnsafeEntry as exc:
        report.unsafe(exc)
        return None


def check_export(conf: Dir, report: Report) -> None:
    """export/: root's 0700 directory; credentials.env root's 0600 and well formed; ca.pem root's."""
    export = _open_optional_dir(conf, EXPORT_DIR, EXPORT_SPEC, report)
    if export is None:
        return
    with export:
        present, data = read_optional(export, CREDENTIALS_ENV, Spec("file", mode=0o600), report)
        if present and data is not None:
            try:
                parse_env(data, export.child(CREDENTIALS_ENV))
            except EnvSyntaxError as exc:
                report.problem(INVALID, f"{exc.path}:{exc.line}", "not a NAME=value line")
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
    apart. A publication that merely went stale (the CA was staged again by hand) is not a swap: it is INVALID, with
    the remedy."""
    ca = _open_optional_dir(conf, CA_DIR, CA_SPEC, report)
    export = _open_optional_dir(conf, EXPORT_DIR, EXPORT_SPEC, report)
    try:
        check_private_dir_roles(ca, export, report)
        if ca is not None and export is not None and _exists(ca, CA_CERT) and _exists(export, EXPORT_CA):
            try:
                own = read_file(ca, CA_CERT, CA_CERT_SPEC)
                published = read_file(export, EXPORT_CA, ROOT_FILE)
            except UnsafeEntry:
                return                                       # already reported by the other checks
            if own != published:
                report.problem(INVALID, export.child(EXPORT_CA),
                               f"differs from {ca.child(CA_CERT)}; run --install to publish it again")
    finally:
        for opened in (ca, export):
            if opened is not None:
                opened.close()


def run_checks(paths: Paths, conf: Dir, lookup: Lookup, report: Report) -> None:
    """Every read-only test, as --check runs them and --prestart runs them before anything else. No lock, no
    subprocess, nothing written. The steps report problems with the same texts, so each is printed once."""
    check_own_ca(paths, conf, lookup, report)
    check_export(conf, report)
    certs = _open_optional_dir(conf, CERTS_DIR, certs_spec(paths), report)
    if certs is not None:
        with certs:
            check_certs_entries(certs, report)
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
    """--check: read-only. No lock, no subprocess, nothing created or changed. Reports UNSAFE and INVALID, never
    MISSING: what is absent is --prestart's to complete and to judge."""
    result = preflight(paths, report, environ)
    if result is not None:
        with result[0] as conf:
            run_checks(paths, conf, result[1], report)
    if not report.has():
        report.progress("check: no problem found")
    return report.exit_code("check")


def _writing_mode(mode: str):
    def run(paths: Paths, report: Report, environ: Mapping[str, str]) -> int:
        result = preflight(paths, report, environ)
        if result is None:
            return report.exit_code(mode)
        conf, lookup = result
        with conf:
            # All writing modes must refuse an unsafe tree before creating even the lock directory. Only
            # --prestart keeps the validity verdicts: --install may refresh stale publications and imports.
            checks = report if mode == "prestart" else Report(quiet=True, out=io.StringIO(), err=io.StringIO())
            run_checks(paths, conf, lookup, checks)
            if checks is not report:
                for kind, subject, reason in checks.problems:
                    if kind == UNSAFE:
                        report.problem(kind, subject, reason)
            if report.has(UNSAFE):
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
                    step_api_passwords(paths, conf, ca, lookup, report)
                    if report.has(UNSAFE):
                        return report.exit_code(mode)
                    step_indexer_password(paths, lookup, report)
                    if certs is not None:
                        state = step_own_ca(paths, conf, certs, ca, lookup, report, mode)
                        if report.has(UNSAFE):
                            return report.exit_code(mode)
                        if state is not None:
                            step_server_pairs(paths, certs, state, lookup, report, mode)
                        if report.has(UNSAFE):
                            return report.exit_code(mode)
                        step_indexer_trust(paths, certs, report)
                finally:
                    if certs is not None:
                        certs.close()
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
            for name in sorted(os.listdir(export.fd)):
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
