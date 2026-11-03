# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The subprocess runner: absolute programs, a fixed environment, secrets on stdin only."""

import json
import os
import sys

import pytest


def stub(sandbox, body):
    path = os.path.join(sandbox.home, "stub")
    sandbox.write(path, f"#!{sys.executable} -I\n{body}\n", mode=0o700)
    return path


def test_env_exact(resolver, sandbox):
    program = stub(sandbox, "import json, os; print(json.dumps(dict(os.environ)))")
    result = resolver.run_wazuh(sandbox.paths, [program], want_stdout=True)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"WAZUH_MANAGER_HOME": sandbox.home, "OPENSSL_armcap": "0",
                                         "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def test_stdin_in_stdout_discarded(resolver, sandbox):
    program = stub(sandbox, "import sys; data = sys.stdin.read(); print(data); sys.exit(0 if data == 'pw' else 3)")
    result = resolver.run_wazuh(sandbox.paths, [program], stdin=b"pw")
    assert result.returncode == 0 and result.stdout is None


def test_relative_program_refused(resolver, sandbox):
    with pytest.raises(ValueError):
        resolver.run_wazuh(sandbox.paths, ["bin/wazuh-manager-keystore"])
