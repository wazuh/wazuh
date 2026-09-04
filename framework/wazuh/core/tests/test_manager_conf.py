# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Tests for wazuh.core.manager_conf: the consumer of bin/wazuh-manager-conf.

The unit cases mock the CLI (subprocess.run); one parity case runs the real binary of a repository
build (src/build/bin) against the fixture and compares with the frozen effective document.
"""

import json
import os
import stat
import subprocess
from unittest.mock import patch

import pytest

from wazuh.core import common
from wazuh.core import manager_conf
from wazuh.core.exception import WazuhError

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'configuration')
FIXTURE = os.path.join(TEST_DATA_PATH, 'wazuh-manager.conf')
EFFECTIVE = os.path.join(TEST_DATA_PATH, 'wazuh-manager.effective.json')
REAL_CLI = os.path.join(common.WAZUH_PATH, 'src', 'build', 'bin', 'wazuh-manager-conf')


def _completed(returncode: int, stdout: str = '', stderr: str = '') -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_load_manager_conf_returns_the_effective_document():
    """load_manager_conf() is `dump` of the CLI: same JSON, --skip-file-checks like the daemons' loader."""
    with open(EFFECTIVE) as f:
        effective_text = f.read()

    with patch('wazuh.core.manager_conf.subprocess.run', return_value=_completed(0, stdout=effective_text)) as run:
        document = manager_conf.load_manager_conf()

    assert document == json.loads(effective_text)
    argv = run.call_args.args[0]
    assert argv[0] == manager_conf.cli_path()
    assert argv[1:] == ['-H', common.WAZUH_PATH, '-f', common.MANAGER_CONF, '--skip-file-checks', 'dump']


def test_load_manager_conf_missing_file_is_1101():
    stderr = "(1239): Configuration file not found: 'etc/wazuh-manager.conf'.\n"
    with patch('wazuh.core.manager_conf.subprocess.run', return_value=_completed(1, stderr=stderr)):
        with pytest.raises(WazuhError, match='.* 1101 .*'):
            manager_conf.load_manager_conf()


def test_load_manager_conf_syntax_error_is_1131():
    # The real CLI renders a structural error with the bare root '/' as the subject (no pointer,
    # no file path) -- reportInvalid() defaults the empty pointer to "/".
    stderr = "(1244): Invalid configuration at '/': invalid XML: Start-end tags mismatch (line 2).\n"
    with patch('wazuh.core.manager_conf.subprocess.run', return_value=_completed(1, stderr=stderr)):
        with pytest.raises(WazuhError, match='.* 1131 .*') as exc:
            manager_conf.load_manager_conf()
    assert 'line 2' in exc.value.message
    # The meaningless '/' subject is dropped, not kept as a fake pointer prefix.
    assert '/: ' not in exc.value.message


def test_load_manager_conf_schema_error_is_1130_with_the_pointer():
    stderr = ("(1244): Invalid configuration at '/auth/use_password': wrong value type "
              "(does not satisfy 'type'); booleans are yes/no [schema /properties/auth/properties/use_password].\n")
    with patch('wazuh.core.manager_conf.subprocess.run', return_value=_completed(1, stderr=stderr)):
        with pytest.raises(WazuhError, match='.* 1130 .*') as exc:
            manager_conf.load_manager_conf()
    assert '/auth/use_password: ' in exc.value.message  # the pointer is kept, the boilerplate prefix is not
    assert 'Invalid configuration at' not in exc.value.message


@pytest.mark.parametrize('problem', [OSError('no such file'), subprocess.TimeoutExpired(cmd='x', timeout=30)])
def test_load_manager_conf_cli_unavailable_is_1908(problem):
    with patch('wazuh.core.manager_conf.subprocess.run', side_effect=problem):
        with pytest.raises(WazuhError, match='.* 1908 .*'):
            manager_conf.load_manager_conf()


def test_load_manager_conf_unexpected_exit_is_1908():
    with patch('wazuh.core.manager_conf.subprocess.run', return_value=_completed(2, stderr='key not set')):
        with pytest.raises(WazuhError, match='.* 1908 .*'):
            manager_conf.load_manager_conf()


def test_load_manager_conf_text_runs_the_cli_on_a_temporary_file(tmp_path):
    """The uploaded text reaches the CLI through a temporary file that never survives the call."""
    seen = {}

    def fake_run(argv, **_):
        tmp_file = argv[argv.index('-f') + 1]
        with open(tmp_file) as f:
            seen['text'] = f.read()
        seen['file'] = tmp_file
        return _completed(0, stdout='{"cluster": {"name": "wazuh"}}')

    with patch('wazuh.core.common.OSSEC_TMP_PATH', new=str(tmp_path)), \
            patch('wazuh.core.manager_conf.subprocess.run', side_effect=fake_run):
        document = manager_conf.load_manager_conf_text('<wazuh_config/>')

    assert document == {'cluster': {'name': 'wazuh'}}
    assert seen['text'] == '<wazuh_config/>'
    assert not os.path.exists(seen['file'])


def test_load_manager_conf_text_schema_error_is_1130(tmp_path):
    stderr = "(1244): Invalid configuration at '/remote/connection': unknown option (does not satisfy 'additionalProperties') [schema /properties/remote].\n"
    with patch('wazuh.core.common.OSSEC_TMP_PATH', new=str(tmp_path)), \
            patch('wazuh.core.manager_conf.subprocess.run', return_value=_completed(1, stderr=stderr)):
        with pytest.raises(WazuhError, match='.* 1130 .*') as exc:
            manager_conf.load_manager_conf_text('<wazuh_config><remote><connection>secure</connection></remote></wazuh_config>')
    assert '/remote/connection: unknown option' in exc.value.message
    assert [p for p in tmp_path.iterdir()] == []


@pytest.mark.skipif(not os.path.isfile(REAL_CLI), reason='src/build/bin/wazuh-manager-conf not built')
def test_parity_with_the_real_cli():
    """The wrapper returns exactly what the built CLI prints for the fixture (frozen in the effective file)."""
    with patch('wazuh.core.manager_conf.cli_path', return_value=REAL_CLI):
        document = manager_conf.load_manager_conf(FIXTURE)

    with open(EFFECTIVE) as f:
        assert document == json.load(f)


def test_write_manager_conf_is_atomic(tmp_path):
    target = tmp_path / 'wazuh-manager.conf'
    target.write_text('<wazuh_config/>\n')
    os.chmod(target, 0o660)

    new_text = '<wazuh_config>\n  <cluster>\n    <key>9d273b53510fef702b54a92e9cffc82e</key>\n  </cluster>\n</wazuh_config>\n'
    with patch('wazuh.core.common.OSSEC_TMP_PATH', new=str(tmp_path)):
        manager_conf.write_manager_conf(new_text, str(target))

    assert target.read_text() == new_text
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o660
    assert [p.name for p in tmp_path.iterdir()] == ['wazuh-manager.conf']  # no temporary file left behind


def test_write_manager_conf_failure_is_1126(tmp_path):
    with patch('wazuh.core.common.OSSEC_TMP_PATH', new=str(tmp_path)), \
            patch('wazuh.core.manager_conf.safe_move', side_effect=OSError('disk full')):
        with pytest.raises(WazuhError, match='.* 1126 .*'):
            manager_conf.write_manager_conf('<wazuh_config/>\n', str(tmp_path / 'wazuh-manager.conf'))


def test_schema_path_falls_back_to_the_repository_source():
    """Without the installed copy, the schema comes from src/shared_modules (a development checkout)."""
    manager_conf._resolved_schema_paths.clear()
    try:
        with patch('wazuh.core.common.MANAGER_CONF_SCHEMA', new='/nonexistent/wazuh-manager.schema.json'):
            resolved = manager_conf.schema_path()
            assert resolved.endswith(os.path.join('schema', 'wazuh-manager.schema.json'))
            assert os.path.isfile(resolved)
            assert 'properties' in manager_conf.schema()
    finally:
        manager_conf._resolved_schema_paths.clear()
