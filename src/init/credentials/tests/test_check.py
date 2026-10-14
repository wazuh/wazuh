# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""--check: read-only, it reports UNSAFE and INVALID and never MISSING, which is --prestart's to judge."""

import io
import os


def run(resolver, sandbox, *argv):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ={}, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_check_clean_sandbox(resolver, sandbox):
    assert run(resolver, sandbox, "--check")[0] == 0


def test_check_bad_local_env(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "oops\n")
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err.startswith("INVALID ")


def test_check_unsafe_indexer_export(resolver, sandbox):
    sandbox.make_indexer_export(credentials="WAZUH_INDEXER_MANAGER_PASSWORD=x\n", mode=0o770)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == f"UNSAFE {sandbox.indexer_export}: group-writable\n"


def test_check_never_reports_missing(resolver, sandbox):
    """Nothing supplied anywhere: --prestart will have things to complete, --check has nothing to say."""
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 0 and "MISSING" not in err


def test_check_unsafe_conf(resolver, sandbox):
    os.chmod(sandbox.conf, 0o777)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == f"UNSAFE {sandbox.conf}: world-writable\n"


def test_check_absent_conf(resolver, sandbox):
    os.rmdir(sandbox.conf)
    code, _, err = run(resolver, sandbox, "--check")
    assert code == 1 and err == f"INVALID {sandbox.conf}: no such directory\n"


def test_check_changes_nothing(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "A=1\n")
    sandbox.make_indexer_export(credentials="WAZUH_INDEXER_MANAGER_PASSWORD=x\n")
    before = sandbox.tree_state()
    assert run(resolver, sandbox, "--check")[0] == 0
    assert sandbox.tree_state() == before
    assert not os.path.exists(os.path.join(sandbox.conf, "ca"))
