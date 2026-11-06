# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the
# terms of GPLv2

"""Regression tests for https://github.com/wazuh/wazuh/issues/40733.

When `boto3` is missing, importing any AWS wodle module must reach the
dedicated check in `wazuh_integration` (exit code 4, "ERROR: boto3 module is
required.") instead of dying with an uncaught `ModuleNotFoundError` for
`botocore`, which the manager then reports only as `Unknown error.`

Each case runs in a fresh subprocess: `sys.modules` entries set to `None`
make `import boto3` / `import botocore` raise `ImportError` even on a system
where both packages are installed, so the test exercises the import order
itself rather than the environment. The `subscribers` cases additionally stub
`pyarrow`, which `s3_log_handler` requires under its own exit code (10):
that dependency is out of scope here and must not mask the `boto3` result.
"""

import os
import subprocess
import sys

import pytest

AWS_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')

IMPORT_SCRIPT = r'''
import sys, types

# Block both packages: importing either must raise ImportError.
sys.modules['boto3'] = None
sys.modules['botocore'] = None
sys.modules['botocore.exceptions'] = None
{pyarrow_stub}
sys.path.insert(0, {aws_dir!r})
{extra_path}
import {target}
print('IMPORTED')
'''

PYARROW_STUB = r'''
# `s3_log_handler` requires pyarrow under its own exit code; stub it so only
# the boto3 ordering is under test here.
pyarrow = types.ModuleType('pyarrow')
parquet = types.ModuleType('pyarrow.parquet')
pyarrow.parquet = parquet
sys.modules['pyarrow'] = pyarrow
sys.modules['pyarrow.parquet'] = parquet
'''


def run_import(target, subdir=None, stub_pyarrow=False):
    extra_path = ''
    if subdir:
        extra_path = "sys.path.insert(0, {0!r})".format(os.path.join(AWS_DIR, subdir))
    script = IMPORT_SCRIPT.format(
        pyarrow_stub=PYARROW_STUB if stub_pyarrow else '',
        aws_dir=AWS_DIR,
        extra_path=extra_path,
        target=target,
    )
    result = subprocess.run(
        [sys.executable, '-c', script],
        cwd=AWS_DIR,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result


@pytest.mark.parametrize('target,subdir,stub_pyarrow', [
    ('buckets_s3', None, False),
    ('subscribers', None, True),
    ('aws_bucket', 'buckets_s3', False),
    ('server_access', 'buckets_s3', False),
    ('cloudwatchlogs', 'services', False),
    ('sqs_queue', 'subscribers', True),
])
def test_missing_boto3_reports_the_missing_dependency(target, subdir, stub_pyarrow):
    """Importing the module without boto3 exits 4 with the dedicated message."""
    result = run_import(target, subdir, stub_pyarrow)
    assert result.returncode == 4, (
        f'importing {target} without boto3 exited with {result.returncode} '
        f'instead of 4.\nstdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'ERROR: boto3 module is required.' in result.stdout
