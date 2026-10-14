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
import errno  # noqa: E402
import fcntl  # noqa: E402
import grp  # noqa: E402
import json  # noqa: E402
import pwd  # noqa: E402
import re  # noqa: E402
import secrets  # noqa: E402
import stat  # noqa: E402
# Only Wazuh's own programs are run, by absolute path, with a fixed argv and an empty environment.
import subprocess  # noqa: E402 # nosec B404
import sys  # noqa: E402
import time  # noqa: E402
from typing import Dict, List, Mapping, Optional, Tuple  # noqa: E402

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
    Anything unreadable here is replaced by the next publication, so it is a warning, never a stop."""
    try:
        data = read_file(export, CREDENTIALS_ENV, ROOT_FILE)
        parsed = parse_env(data, export.child(CREDENTIALS_ENV))
    except FileNotFoundError:
        return {}
    except (UnsafeEntry, EnvSyntaxError) as exc:
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


def step_api_passwords(paths: Paths, conf: Dir, lookup: Lookup, report: Report) -> None:
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
        published = read_published(export, report)
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
    return conf, lookup


def mode_check(paths: Paths, report: Report, environ: Mapping[str, str]) -> int:
    """--check: read-only. No lock, no subprocess, nothing created or changed. Reports UNSAFE and INVALID, never
    MISSING: what is absent is --prestart's to complete and to judge."""
    result = preflight(paths, report, environ)
    if result is not None:
        result[0].close()
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
            try:
                ca = acquire_lock(conf)
            except UnsafeEntry as exc:
                report.unsafe(exc)
                return report.exit_code(mode)
            with ca:
                step_api_passwords(paths, conf, lookup, report)
                step_indexer_password(paths, lookup, report)
                # The CA, the server pairs and the indexer trust are added by later stages.
        return report.exit_code(mode)
    return run


def mode_clear(paths: Paths, report: Report, environ: Mapping[str, str]) -> int:
    print(f"{LOG_TAG}: --clear is not implemented yet", file=report.err)
    return 2


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
