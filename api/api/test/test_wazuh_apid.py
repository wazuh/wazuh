# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from api.validator import security_config_schema

WAZUH_UID = WAZUH_GID = 999
CERTIFICATE = '-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUJ8\nZm9v\n-----END CERTIFICATE-----\n'
PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n'

# The script has no package and binds these names when it runs as a program.
spec = importlib.util.spec_from_file_location('wazuh_apid', Path(__file__).parents[2] / 'scripts' / 'wazuh_apid.py')
wazuh_apid = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wazuh_apid)
wazuh_apid.common = SimpleNamespace(wazuh_uid=lambda: WAZUH_UID, wazuh_gid=lambda: WAZUH_GID)
wazuh_apid.yaml = yaml
wazuh_apid.security_config_schema = security_config_schema


@pytest.fixture
def ownership():
    """Report every file as owned by root, except the given paths and the ones assigned to wazuh during the test.

    Returns
    -------
    function
        Receives the paths owned by wazuh and returns the list that collects the paths assigned to it.
    """
    real_stat, real_fstat = os.stat, os.fstat
    wazuh_inodes, assigned = set(), []

    def faked(result):
        return SimpleNamespace(st_mode=result.st_mode, st_nlink=result.st_nlink, st_size=result.st_size,
                               st_uid=WAZUH_UID if result.st_ino in wazuh_inodes else 0)

    def fchown(fd, uid, gid):
        assert (uid, gid) == (WAZUH_UID, WAZUH_GID)
        wazuh_inodes.add(real_fstat(fd).st_ino)
        assigned.append(os.readlink(f'/proc/self/fd/{fd}'))

    def owned_by_wazuh(*paths):
        wazuh_inodes.update(real_stat(path).st_ino for path in paths)
        return assigned

    with patch.object(wazuh_apid.os, 'stat', lambda *args, **kwargs: faked(real_stat(*args, **kwargs))), \
            patch.object(wazuh_apid.os, 'fstat', lambda fd: faked(real_fstat(fd))), \
            patch.object(wazuh_apid.os, 'fchown', fchown):
        yield owned_by_wazuh


@pytest.fixture
def logs(tmp_path):
    """Create `logs/api/2026/Nov` with one rotated log and a directory outside it holding a root-only file."""
    month = tmp_path / 'logs' / 'api' / '2026' / 'Nov'
    month.mkdir(parents=True)
    (month / 'api.log-11_1.gz').touch()
    (tmp_path / 'outside').mkdir()
    (tmp_path / 'outside' / 'sslmanager.key').touch()
    with patch.object(wazuh_apid, 'API_LOG_PATH', str(tmp_path / 'logs' / 'api'), create=True):
        yield month


def test_hand_back_rotated_logs(logs, ownership):
    """Check that a month directory with rotated logs and its year directory are assigned to wazuh."""
    assigned = ownership()
    wazuh_apid.hand_back_rotated_logs()
    assert assigned == [str(logs), str(logs.parent)]


def test_hand_back_rotated_logs_already_assigned(logs, ownership):
    """Check that directories already owned by wazuh are left alone."""
    assigned = ownership(logs, logs.parent)
    wazuh_apid.hand_back_rotated_logs()
    assert assigned == []


def test_hand_back_rotated_logs_missing():
    """Check that a missing log directory is not an error."""
    with patch.object(wazuh_apid, 'API_LOG_PATH', '/nonexistent/logs/api', create=True):
        wazuh_apid.hand_back_rotated_logs()


@pytest.mark.parametrize('plant', [
    lambda month, outside: (outside / 'sslmanager.key').rename(month / 'sslmanager.key'),
    lambda month, outside: (month / 'api.log-11_2.gz').symlink_to(outside / 'sslmanager.key'),
    lambda month, outside: (month / 'api.log-11_2.gz').mkdir(),
])
def test_hand_back_rotated_logs_unexpected_entry(plant, logs, ownership):
    """Check that a month directory holding anything but rotated log files is not assigned, nor is its year."""
    plant(logs, logs.parents[3] / 'outside')
    assigned = ownership()
    wazuh_apid.hand_back_rotated_logs()
    assert assigned == []


def test_hand_back_rotated_logs_unexpected_year_entry(logs, ownership):
    """Check that a year directory holding anything but assigned month directories keeps its owner."""
    (logs.parent / 'Dec').touch()
    assigned = ownership()
    wazuh_apid.hand_back_rotated_logs()
    assert assigned == [str(logs)]


@pytest.mark.parametrize('link', ['2026/Dec', '2027'])
def test_hand_back_rotated_logs_symlink(link, logs, ownership):
    """Check that a symbolic link in place of a month or year directory is not followed."""
    outside = logs.parents[3] / 'outside'
    (outside / 'api.log-11_1.gz').touch()
    (outside / 'sslmanager.key').unlink()
    (logs.parents[1] / link).symlink_to(outside, target_is_directory=True)
    assigned = ownership()
    wazuh_apid.hand_back_rotated_logs()
    assert str(outside) not in assigned and str(logs) in assigned


@pytest.fixture
def security_config(tmp_path):
    """Patch `SECURITY_CONFIG_PATH` with a path in a temporary directory."""
    path = tmp_path / 'security.yaml'
    with patch.object(wazuh_apid, 'SECURITY_CONFIG_PATH', str(path), create=True):
        yield path


def test_hand_back_security_config(security_config, ownership):
    """Check that a `security.yaml` holding security options is assigned to wazuh."""
    security_config.write_text('auth_token_exp_timeout: 900\nrbac_mode: white\n')
    assigned = ownership()
    wazuh_apid.hand_back_security_config()
    assert assigned == [str(security_config)]


def test_hand_back_security_config_already_assigned(security_config, ownership):
    """Check that a `security.yaml` already owned by wazuh is left alone."""
    security_config.write_text('rbac_mode: white\n')
    assigned = ownership(security_config)
    wazuh_apid.hand_back_security_config()
    assert assigned == []


def test_hand_back_security_config_missing(security_config, ownership):
    """Check that a missing `security.yaml` is not an error."""
    assigned = ownership()
    wazuh_apid.hand_back_security_config()
    assert assigned == []


@pytest.mark.parametrize('content', [
    PRIVATE_KEY,
    'rbac_mode: white\ndrop_privileges: no\n',
    '- rbac_mode\n',
    'rbac_mode: [white\n',
    'a' * 4097,
])
def test_hand_back_security_config_other_content(content, security_config, ownership):
    """Check that a file that does not hold security options alone keeps its owner."""
    security_config.write_text(content)
    assigned = ownership()
    wazuh_apid.hand_back_security_config()
    assert assigned == []


def test_hand_back_security_config_hard_link(security_config, ownership):
    """Check that a `security.yaml` with another name in the file system keeps its owner."""
    security_config.write_text('rbac_mode: white\n')
    os.link(security_config, security_config.with_name('other'))
    assigned = ownership()
    wazuh_apid.hand_back_security_config()
    assert assigned == []


def test_hand_back_security_config_symlink(security_config, ownership):
    """Check that a symbolic link in place of `security.yaml` is not followed."""
    target = security_config.with_name('target')
    target.write_text('rbac_mode: white\n')
    security_config.symlink_to(target)
    assigned = ownership()
    with pytest.raises(OSError):
        wazuh_apid.hand_back_security_config()
    assert assigned == []


@pytest.fixture
def ca(tmp_path):
    """Patch the API configuration with HTTPS and `use_ca` enabled and a CA path in a temporary directory."""
    path = tmp_path / 'ca.crt'
    https = {'enabled': True, 'use_ca': True, 'ca': str(path)}
    with patch.object(wazuh_apid, 'api_conf', {'https': https}, create=True):
        yield path


@pytest.mark.parametrize('content', [CERTIFICATE, f'\n{CERTIFICATE}\n{CERTIFICATE}'])
def test_hand_back_ca(content, ca, ownership):
    """Check that a CA file holding certificates alone is assigned to wazuh."""
    ca.write_text(content)
    assigned = ownership()
    wazuh_apid.hand_back_ca()
    assert assigned == [str(ca)]


@pytest.mark.parametrize('enabled, use_ca', [(False, True), (True, False)])
def test_hand_back_ca_unused(enabled, use_ca, ca, ownership):
    """Check that the CA file keeps its owner when the API does not use it."""
    ca.write_text(CERTIFICATE)
    wazuh_apid.api_conf['https'].update(enabled=enabled, use_ca=use_ca)
    assigned = ownership()
    wazuh_apid.hand_back_ca()
    assert assigned == []


def test_hand_back_ca_already_assigned(ca, ownership):
    """Check that a CA file already owned by wazuh is left alone."""
    ca.write_text(CERTIFICATE)
    assigned = ownership(ca)
    wazuh_apid.hand_back_ca()
    assert assigned == []


def test_hand_back_ca_missing(ca, ownership):
    """Check that a missing CA file is not an error."""
    assigned = ownership()
    wazuh_apid.hand_back_ca()
    assert assigned == []


@pytest.mark.parametrize('content', [PRIVATE_KEY, CERTIFICATE + PRIVATE_KEY, f'# comment\n{CERTIFICATE}', ''])
def test_hand_back_ca_other_content(content, ca, ownership):
    """Check that a file that does not hold certificates alone keeps its owner."""
    ca.write_text(content)
    assigned = ownership()
    wazuh_apid.hand_back_ca()
    assert assigned == []


def test_hand_back_ca_hard_link(ca, ownership):
    """Check that a CA file with another name in the file system keeps its owner."""
    ca.write_text(CERTIFICATE)
    os.link(ca, ca.with_name('other'))
    assigned = ownership()
    wazuh_apid.hand_back_ca()
    assert assigned == []


def test_hand_back_ca_symlink(ca, ownership):
    """Check that a symbolic link in place of the CA file is not followed."""
    target = ca.with_name('target')
    target.write_text(CERTIFICATE)
    ca.symlink_to(target)
    assigned = ownership()
    with pytest.raises(OSError):
        wazuh_apid.hand_back_ca()
    assert assigned == []
