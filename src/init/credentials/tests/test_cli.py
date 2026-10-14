# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Command line, exit codes and output of the credential resolver."""

import ast
import io
import os
import subprocess
import sys

import pytest

from conftest import PROGRAM

BUNDLED_PYTHON = "/var/wazuh-manager/framework/python/bin/python3"


def interpreter():
    return BUNDLED_PYTHON if os.access(BUNDLED_PYTHON, os.X_OK) else sys.executable


def run_main(resolver, argv, sandbox=None, environ=None):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(argv, paths=sandbox.paths if sandbox else None, environ=environ or {}, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_shebang_is_the_bundled_interpreter_in_isolated_mode():
    with open(PROGRAM) as handle:
        assert handle.readline().rstrip("\n") == "#!/var/wazuh-manager/framework/python/bin/python3 -I"


def test_armcap_first():
    """OPENSSL_armcap must be set before anything can load OpenSSL (the generic wrapper's SIGILL guard)."""
    with open(PROGRAM) as handle:
        body = ast.parse(handle.read()).body
    first, second = body[0], body[1]
    assert isinstance(first, ast.Import) and [alias.name for alias in first.names] == ["os"]
    assert isinstance(second, ast.Assign)
    assert ast.unparse(second) == "os.environ['OPENSSL_armcap'] = '0'"


def test_help():
    result = subprocess.run([interpreter(), "-I", PROGRAM, "-h"], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    for mode in ("--install", "--upgrade", "--prestart", "--check", "--clear"):
        assert mode in result.stdout


@pytest.mark.parametrize("argv", [["--install", "--check"], ["--bogus"], ["-H"], ["-H", "relative/home"]])
def test_usage_errors_exit_2(resolver, sandbox, argv):
    before = sandbox.tree_state()
    code, _, _ = run_main(resolver, argv, sandbox)
    assert code == 2
    assert sandbox.tree_state() == before


@pytest.mark.parametrize("mode", ["--install", "--upgrade", "--prestart", "--check", "--clear", None])
def test_non_root(resolver, sandbox, monkeypatch, mode):
    monkeypatch.setattr(resolver.os, "geteuid", lambda: 1000)
    before = sandbox.tree_state()
    code, _, err = run_main(resolver, [mode] if mode else [], sandbox)
    assert code == 2
    assert "must run as root" in err
    assert sandbox.tree_state() == before


def test_default_mode_is_prestart(resolver, sandbox, monkeypatch):
    called = []
    monkeypatch.setitem(resolver.MODE_HANDLERS, "prestart", lambda paths, report, environ: called.append(1) or 0)
    code, _, _ = run_main(resolver, [], sandbox)
    assert code == 0 and called == [1]


def test_H_sets_the_home_only(resolver, sandbox, monkeypatch):
    seen = []
    monkeypatch.setitem(resolver.MODE_HANDLERS, "check", lambda paths, report, environ: seen.append(paths) or 0)
    run_main(resolver, ["--check", "-H", "/opt/wazuh-manager"], sandbox)
    assert seen[0].home == "/opt/wazuh-manager"
    assert seen[0].conf == sandbox.conf


def test_default_paths(resolver):
    paths = resolver.Paths()
    assert (paths.home, paths.conf, paths.indexer_export) == (
        "/var/wazuh-manager", "/etc/wazuh-manager", "/etc/wazuh-indexer/export")


def test_quiet(resolver, sandbox):
    code, out, err = run_main(resolver, ["--check"], sandbox)
    assert code == 0 and out.startswith("resolve-credentials: ") and err == ""
    code, out, err = run_main(resolver, ["--check", "-q"], sandbox)
    assert code == 0 and out == ""
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "not a line\n")
    code, out, err = run_main(resolver, ["--check", "-q"], sandbox)
    assert code == 1 and out == "" and err.startswith("INVALID ")


def test_internal_error_prints_no_value(resolver, sandbox, monkeypatch):
    secret = "S3cret.Value-123"

    def boom(paths, report, environ):
        raise RuntimeError(secret)
    monkeypatch.setitem(resolver.MODE_HANDLERS, "check", boom)
    code, out, err = run_main(resolver, ["--check"], sandbox)
    assert code == 2 and "internal error: RuntimeError" in err
    assert secret not in out + err


def test_clear_not_implemented_yet(resolver, sandbox):
    code, _, err = run_main(resolver, ["--clear"], sandbox)
    assert code == 2 and "not implemented" in err


@pytest.mark.parametrize("mode,expected", [("install", 0), ("upgrade", 0), ("prestart", 1), ("check", 1)])
def test_exit_contract_with_a_problem(resolver, sandbox, mode, expected):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "X\n")
    code, _, err = run_main(resolver, [f"--{mode}"], sandbox)
    assert code == expected
    assert f"INVALID {sandbox.conf}/local.env:1: " in err
