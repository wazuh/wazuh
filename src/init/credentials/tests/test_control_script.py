# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""wazuh-manager-control (src/init/wazuh-server.sh) around the resolver: the single JSON document of `-j`, the
manager log lines it writes for the resolver, the checks `reload` runs, the `check` action, and that it acts on the
daemons itself.

The script runs in a scratch home with stub daemons, a stub `wazuh-manager-conf` and a stub resolver; nothing of
the host's manager is read or touched. A stub `systemctl` on the PATH records any call, so a test can assert the
script never goes through it.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCRIPT = os.path.join(REPO, "src", "init", "wazuh-server.sh")
DAEMONS = ("clusterd", "modulesd", "remoted", "db", "authd", "apid")
ALL = tuple(f"wazuh-manager-{name}" for name in ("clusterd", "modulesd", "remoted", "analysisd", "db", "authd",
                                                 "apid"))

# `get` answers only with --skip-file-checks, as the real CLI does when a configured certificate is missing.
CONF_STUB = """#!/bin/sh
skip=no
for a in "$@"; do [ "$a" = --skip-file-checks ] && skip=yes; done
case " $* " in
    *" validate"*)
        [ -n "$FAIL_VALIDATE" ] && { echo "(1244): Invalid configuration at '/remote': bad." >&2; exit 1; }
        exit 0 ;;
    *" get cluster.node_type"*) [ $skip = yes ] || exit 1; echo master ;;
    *" get auth.disabled"*) [ $skip = yes ] || exit 1; echo false ;;
esac
"""

# A daemon: -t talks on stdout (as some do) and fails when FAIL_T names it; otherwise it leaves a sleeper and its
# pid file behind.
DAEMON_STUB = """#!/bin/sh
home=$(cd "$(dirname "$0")/.." && pwd)
if [ "$1" = -t ]; then
    echo "{name}: configuration test output"
    [ "$FAIL_T" = "{name}" ] && exit 1
    exit 0
fi
sleep 1000 < /dev/null > /dev/null 2>&1 &
echo $! > "$home/var/run/wazuh-manager-{name}-$!.pid"
"""

# The engine: answers GET /status on its API socket, which is what the script waits for.
ENGINE_STUB = """#!/bin/sh
home=$(cd "$(dirname "$0")/.." && pwd)
[ "$1" = -t ] && exit 0
echo "engine output on stdout"
"{python}" - "$home" > /dev/null 2>&1 <<'PY' &
import http.server, os, socketserver, sys
home = sys.argv[1]
if os.fork():
    sys.exit(0)
os.setsid()
path = home + "/queue/sockets/engine-api-http.sock"
if os.path.exists(path):
    os.unlink(path)
class Handler(http.server.BaseHTTPRequestHandler):
    def address_string(self):
        return "local"
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass
server = socketserver.UnixStreamServer(path, Handler)
open(home + "/var/run/wazuh-manager-analysisd-%d.pid" % os.getpid(), "w").write(str(os.getpid()))
server.serve_forever()
PY
"""

RESOLVER_STUB = """#!/bin/sh
case "$1" in
    --check)
        [ -n "$UNSAFE" ] && { echo "UNSAFE /etc/wazuh-manager/local.env: mode is 0644, not 0600" >&2; exit 1; }
        exit 0 ;;
    --prestart)
        [ -z "$NO_PASSWORD" ] && exit 0
        echo "resolve-credentials: importing the indexer trust"
        echo "resolve-credentials: WARNING: something only the clock refuses"
        echo "MISSING WAZUH_INDEXER_MANAGER_PASSWORD: set it in /etc/wazuh-manager/local.env" >&2
        exit 1 ;;
esac
"""

# Records every call: the script must never hand an action over to systemd.
SYSTEMCTL_STUB = """#!/bin/sh
echo "$*" >> "{base}/systemctl.log"
"""


def _write(path, text, mode=0o755):
    with open(path, "w") as handle:
        handle.write(text)
    os.chmod(path, mode)


class Manager:
    """A scratch installation: <base>/home is the home, <base>/bin holds the stub systemctl."""

    def __init__(self, base):
        self.base = base
        self.home = os.path.join(base, "home")
        for sub in ("bin", "var/run", "logs", "tmp", "queue/sockets", "framework/python/bin"):
            os.makedirs(os.path.join(self.home, sub))
        # On a real install logs/ and var/run/ belong to the service account, and service_write drops to it
        # before writing. Mirror that when the suite runs as root and the account exists, so the drop can
        # create its files; without the account (e.g. a bare CI runner) service_write writes without dropping.
        if os.geteuid() == 0:
            try:
                import grp
                import pwd
                uid = pwd.getpwnam("wazuh-manager").pw_uid
                gid = grp.getgrnam("wazuh-manager").gr_gid
            except KeyError:
                uid = gid = None
            if uid is not None:
                # The account must reach and write logs/ and var/run/ after the drop: make the scratch base
                # traversable (not listable, so the short socket path stays private) and give it those dirs.
                os.chmod(self.base, 0o711)
                for sub in ("logs", "var/run", "tmp"):
                    os.chown(os.path.join(self.home, sub), uid, gid)
        os.symlink(sys.executable, os.path.join(self.home, "framework/python/bin/python3"))
        shutil.copy(SCRIPT, self.control)
        os.chmod(self.control, 0o750)
        _write(self.bin("wazuh-manager-conf"), CONF_STUB)
        _write(self.bin("wazuh-manager-resolve-credentials"), RESOLVER_STUB)
        for name in DAEMONS:
            _write(self.bin(f"wazuh-manager-{name}"), DAEMON_STUB.format(name=name))
        _write(self.bin("wazuh-manager-analysisd"), ENGINE_STUB.format(python=sys.executable))
        os.makedirs(os.path.join(base, "bin"))
        _write(os.path.join(base, "bin", "systemctl"), SYSTEMCTL_STUB.format(base=base))

    @property
    def control(self):
        return self.bin("wazuh-manager-control")

    def bin(self, name):
        return os.path.join(self.home, "bin", name)

    def run(self, *argv, systemctl=False, **env):
        environ = {key: value for key, value in os.environ.items() if key != "INVOCATION_ID"}
        if systemctl:
            environ["PATH"] = os.path.join(self.base, "bin") + os.pathsep + environ.get("PATH", "")
        environ.update(env)
        return subprocess.run([self.control, *argv], capture_output=True, text=True, env=environ, timeout=120)

    def log(self):
        try:
            with open(os.path.join(self.home, "logs", "wazuh-manager.log")) as handle:
                return handle.read()
        except FileNotFoundError:
            return ""

    def systemctl_calls(self):
        try:
            with open(os.path.join(self.base, "systemctl.log")) as handle:
                return handle.read().splitlines()
        except FileNotFoundError:
            return []

    def kill_all(self):
        run_dir = os.path.join(self.home, "var", "run")
        for name in os.listdir(run_dir):
            if name.endswith(".pid"):
                try:
                    os.kill(int(name.rsplit("-", 1)[1][:-4]), 9)
                except (ValueError, ProcessLookupError):
                    pass


@pytest.fixture
def manager():
    # Short and private: the engine stub binds a Unix socket under the home (108 bytes at most).
    base = tempfile.mkdtemp(prefix="wmc.", dir="/tmp")
    os.chmod(base, 0o700)
    instance = Manager(base)
    yield instance
    instance.kill_all()
    shutil.rmtree(base, ignore_errors=True)


def one_document(stdout):
    """stdout holds exactly one JSON document and nothing else."""
    return json.loads(stdout)


@pytest.mark.parametrize("flag, key, value", [("-v", "WAZUH_VERSION", None), ("-r", "WAZUH_REVISION", None),
                                              ("-t", "WAZUH_TYPE", "manager")])
def test_json_info_single_value(manager, flag, key, value):
    result = manager.run("-j", "info", flag)
    document = one_document(result.stdout)
    assert result.returncode == 0 and document["error"] == 0
    assert list(document["data"][0]) == [key]
    if value is not None:
        assert document["data"][0][key] == value
    assert manager.run("info", flag).stdout.strip() == document["data"][0][key]


def test_json_info_unknown_flag(manager):
    result = manager.run("-j", "info", "-q")
    assert result.returncode == 1
    assert one_document(result.stdout) == {"error": 1, "message": "Invalid flag: -q."}


def test_json_start_is_one_document(manager):
    """Each daemon's -t and the engine talk on stdout; with -j none of it may precede or follow the document."""
    result = manager.run("-j", "start")
    assert result.returncode == 0, result.stderr
    document = one_document(result.stdout)
    assert document["error"] == 0
    assert {entry["daemon"] for entry in document["data"]} == set(ALL)
    assert "configuration test output" in result.stderr


@pytest.mark.parametrize("action", ["reload", "restart"])
def test_reload_runs_remoted_test(manager, action):
    """reload keeps remoted running but still runs its -t: a remote change it refuses is refused now."""
    assert manager.run("start").returncode == 0
    result = manager.run("-j", action, FAIL_T="remoted")
    assert result.returncode == 1
    assert one_document(result.stdout) == {"error": 20, "message": "wazuh-manager-remoted: Configuration error."}


def test_status_lists_apid_when_a_certificate_is_missing(manager):
    """The role is read without file checks: a missing certificate must not hide a running apid."""
    assert manager.run("start").returncode == 0
    result = manager.run("-j", "status")
    assert result.returncode == 0
    daemons = {entry["daemon"]: entry["status"] for entry in one_document(result.stdout)["data"]}
    assert daemons.get("wazuh-manager-apid") == "running"


def test_resolver_lines_are_logged_in_the_log_format(manager):
    result = manager.run("start", NO_PASSWORD="1")
    assert result.returncode == 1 and "Unresolved credentials. Exiting" in result.stdout
    lines = manager.log().splitlines()
    assert lines, "nothing logged"
    for line in lines:
        date, clock, tag, rest = line.split(" ", 3)
        assert len(date) == 10 and len(clock) == 8 and tag == "wazuh-manager-control:", line
    assert any(line.endswith("wazuh-manager-control: ERROR: MISSING WAZUH_INDEXER_MANAGER_PASSWORD: set it in "
                             "/etc/wazuh-manager/local.env") for line in lines), lines
    assert any(line.endswith("wazuh-manager-control: WARNING: something only the clock refuses") for line in lines)
    assert any(line.endswith("wazuh-manager-control: INFO: importing the indexer trust") for line in lines)


@pytest.mark.parametrize("action", ["start", "restart", "reload", "stop"])
def test_actions_never_go_through_systemctl(manager, action):
    """Typed in a shell, every action runs here, on the daemons themselves: a start relaunches whatever is down
    even while the unit is active, and the caller's environment (WAZUH_CONF, the resolver's inputs) and stderr
    reach the checks."""
    if action != "start":
        assert manager.run("start").returncode == 0
    assert manager.run(action, systemctl=True).returncode == 0
    assert manager.systemctl_calls() == []


def test_start_relaunches_a_daemon_that_died(manager):
    assert manager.run("start").returncode == 0
    run_dir = os.path.join(manager.home, "var", "run")
    pid_file = next(name for name in os.listdir(run_dir) if name.startswith("wazuh-manager-apid-"))
    os.kill(int(pid_file.rsplit("-", 1)[1][:-4]), 9)
    os.unlink(os.path.join(run_dir, pid_file))
    assert manager.run("start", systemctl=True).returncode == 0
    assert any(name.startswith("wazuh-manager-apid-") for name in os.listdir(run_dir))
    assert manager.systemctl_calls() == []


def _pid_files(manager):
    return sorted(name for name in os.listdir(os.path.join(manager.home, "var", "run")) if name.endswith(".pid"))


def test_check_passes_without_starting_anything(manager):
    result = manager.run("-j", "check", systemctl=True)
    assert result.returncode == 0, result.stderr
    assert one_document(result.stdout) == {"error": 0, "data": []}
    assert "configuration test output" in result.stderr
    assert _pid_files(manager) == []
    assert manager.systemctl_calls() == []
    plain = manager.run("check")
    assert plain.returncode == 0 and plain.stdout.strip() == "Configuration and credentials checks passed."


@pytest.mark.parametrize("env, document", [
    ({"FAIL_VALIDATE": "1"}, {"error": 20, "message": "wazuh-manager.conf: Configuration error."}),
    ({"UNSAFE": "1"}, {"error": 22, "message": "Unsafe credentials."}),
    ({"FAIL_T": "remoted"}, {"error": 20, "message": "wazuh-manager-remoted: Configuration error."}),
])
def test_check_refuses_as_a_start_would(manager, env, document):
    """Same refusal, same -j code as the start, and the same text without -j."""
    result = manager.run("-j", "check", **env)
    assert result.returncode == 1
    assert one_document(result.stdout) == document
    plain = manager.run("check", **env)
    assert plain.returncode == 1
    assert plain.stdout.strip() == document["message"][:-1] + ". Exiting"
    start = manager.run("-j", "start", **env)
    assert start.returncode == 1 and one_document(start.stdout) == document


def test_check_leaves_a_running_manager_alone(manager):
    """A refused check stops nothing, removes no marker and releases no lock it never took."""
    assert manager.run("start").returncode == 0
    running = _pid_files(manager)
    run_dir = os.path.join(manager.home, "var", "run")
    _write(os.path.join(run_dir, "wazuh-manager-authd.failed"), "start\n", mode=0o644)
    lock = os.path.join(manager.home, "var", "start-script-lock")
    os.makedirs(lock)
    _write(os.path.join(lock, "pid"), f"{os.getpid()}\n", mode=0o644)

    result = manager.run("-j", "check", FAIL_T="remoted")
    assert result.returncode == 1
    assert _pid_files(manager) == running
    assert os.path.isdir(lock)
    assert not os.path.exists(os.path.join(run_dir, "wazuh-manager-remoted.failed"))
    assert os.path.exists(os.path.join(run_dir, "wazuh-manager-authd.failed"))
    assert manager.run("check").returncode == 0
    assert os.path.exists(os.path.join(run_dir, "wazuh-manager-authd.failed"))
    shutil.rmtree(lock)


def test_check_logs_its_refusal(manager):
    assert manager.run("check", FAIL_VALIDATE="1").returncode == 1
    assert "wazuh-manager-control: ERROR: (1244): Invalid configuration at '/remote': bad." in manager.log()


@pytest.mark.parametrize("argv, message", [(("-j", "bogus"), "Invalid action: bogus."),
                                           (("-j",), "Missing action.")])
def test_json_invalid_action_is_one_document(manager, argv, message):
    result = manager.run(*argv)
    assert result.returncode == 1
    assert one_document(result.stdout) == {"error": 1, "message": message}


def test_disable_usage(manager):
    result = manager.run("disable")
    assert result.returncode == 1
    assert "Usage: " in result.stdout and "disable debug]" not in result.stdout


def _lock_held(manager):
    return os.path.exists(os.path.join(manager.home, "var", "start-script-lock"))


@pytest.mark.parametrize("action", ["enable", "disable"])
@pytest.mark.parametrize("option", [None, "bogus"])
def test_toggle_refusal_releases_the_lock(manager, action, option):
    argv = (action,) if option is None else (action, option)
    result = manager.run(*argv)
    assert result.returncode == 1 and "Usage: " in result.stdout
    assert not _lock_held(manager)
    assert not os.path.exists(manager.bin(".process_list"))


@pytest.mark.parametrize("argv, message", [
    (("-j", "enable"), "Missing enable option."),
    (("-j", "disable", "bogus"), "Invalid disable option: bogus."),
])
def test_json_toggle_refusal_is_one_document(manager, argv, message):
    result = manager.run(*argv)
    assert result.returncode == 1
    document = one_document(result.stdout)
    assert document["error"] == 1 and document["message"].startswith(message)
    assert not _lock_held(manager)


@pytest.mark.parametrize("action, line", [("enable", 'DEBUG_CLI="-d"'), ("disable", 'DEBUG_CLI=""')])
def test_json_toggle_is_one_document(manager, action, line):
    result = manager.run("-j", action, "debug")
    assert result.returncode == 0
    assert one_document(result.stdout) == {"error": 0, "data": []}
    assert not _lock_held(manager)
    with open(manager.bin(".process_list")) as handle:
        assert handle.read().splitlines()[-1] == line


def test_json_help_is_one_document(manager):
    result = manager.run("-j", "help")
    assert result.returncode == 1
    assert one_document(result.stdout)["message"].startswith("Usage: ")


@pytest.mark.parametrize("argv, message", [
    (("-j", 'a"b\\c\td'), 'Invalid action: a"b\\c d.'),
    (("-j", "info", '-q"'), 'Invalid flag: -q".'),
    (("-j", "enable", 'x"y'), 'Invalid enable option: x"y.'),
])
def test_json_escapes_the_argument(manager, argv, message):
    result = manager.run(*argv)
    assert result.returncode == 1
    assert one_document(result.stdout)["message"].startswith(message)
