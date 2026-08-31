# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""wazuh.core.manager_conf: the Python twin of shared_modules/manager_config (YAML 1.2 loader, schema, defaults)."""

import json
import os
import stat
from unittest.mock import patch

import pytest
import yaml

from wazuh.core.exception import WazuhError
from wazuh.core import manager_conf

tests_dir = os.path.dirname(os.path.realpath(__file__))
data_dir = os.path.join(tests_dir, 'data', 'configuration')
repo_dir = os.path.abspath(os.path.join(tests_dir, '..', '..', '..', '..'))
# Single source of truth: the schema the C++ library embeds and the installer copies to etc/wazuh-manager.schema.json
SCHEMA_PATH = os.path.join(repo_dir, 'src', 'shared_modules', 'manager_config', 'schema', 'wazuh-manager.schema.json')
VECTORS_DIR = os.path.join(repo_dir, 'src', 'shared_modules', 'manager_config', 'tests', 'vectors')
FIXTURE = os.path.join(data_dir, 'wazuh-manager.yml')
FIXTURE_EFFECTIVE = os.path.join(data_dir, 'wazuh-manager.effective.json')


@pytest.fixture(autouse=True)
def installed_schema():
    with patch('wazuh.core.common.MANAGER_CONF_SCHEMA', new=SCHEMA_PATH):
        yield


@pytest.mark.parametrize('text, expected', [
    ('a: yes', {'a': 'yes'}),
    ('a: no', {'a': 'no'}),
    ('a: on', {'a': 'on'}),
    ('a: true', {'a': True}),
    ('a: False', {'a': False}),
    ('a: 1516', {'a': 1516}),
    ('a: 15m', {'a': '15m'}),
    ('a: 0.0.0.0', {'a': '0.0.0.0'}),
    ('a: ~', {'a': None}),
    ('', {}),
    ('# only a comment\n', {}),
])
def test_load_yaml_text_yaml12_scalars(text, expected):
    """Only true/false are booleans (YAML 1.2 core schema); everything PyYAML 1.1 would coerce stays a string."""
    assert manager_conf.load_yaml_text(text) == expected


@pytest.mark.parametrize('text, fragment', [
    ('a: &x 1\nb: *x\n', 'anchors and aliases'),
    ('a: &x 1\n', 'anchors and aliases'),
    ('a: !!str 1\n', 'tags are not allowed'),
    ('a: 1\n---\nb: 2\n', 'exactly one YAML document'),
    ('- 1\n- 2\n', 'root must be a mapping'),
    ('a: [\n', ':'),
])
def test_load_yaml_text_rejects_alias_tag_multidoc_and_syntax(text, fragment):
    with pytest.raises(WazuhError, match='.* 1131 .*') as exc:
        manager_conf.load_yaml_text(text)
    assert fragment in str(exc.value)


def test_load_yaml_text_syntax_error_has_line_and_column():
    with pytest.raises(WazuhError) as exc:
        manager_conf.load_yaml_text('cluster:\n  name: wazuh\n  port: [1516\n')
    assert exc.value.code == 1131
    assert '3:' in str(exc.value) or '4:' in str(exc.value)


def _expected_vectors():
    for name in sorted(os.listdir(os.path.join(VECTORS_DIR, 'invalid'))):
        stem = os.path.splitext(name)[0]
        with open(os.path.join(VECTORS_DIR, 'expected', f'{stem}.json')) as f:
            yield name, json.load(f)


@pytest.mark.parametrize('name, expected', list(_expected_vectors()))
def test_first_schema_error_pointer_parity(name, expected):
    """Every invalid vector of the C++ library is rejected by the framework with the same pointer and keyword."""
    with open(os.path.join(VECTORS_DIR, 'invalid', name)) as f:
        text = f.read()

    if expected['keyword'] == 'yaml' or (expected['pointer'] == '' and expected['keyword'] == 'type'):
        # Rejected by the loader itself (aliases, tags, several documents, or a root that is not a mapping)
        with pytest.raises(WazuhError, match='.* 1131 .*'):
            manager_conf.load_yaml_text(text)
        return

    document = manager_conf.load_yaml_text(text)
    error = manager_conf.first_schema_error(document)
    if expected['keyword'] == 'semantics':
        # Cross-field rules live in the C++ library only (validate_manager_conf runs the CLI): the schema accepts them
        assert error is None, f'{name}: the schema alone must accept a semantics-only vector'
        return
    assert error is not None, f'{name}: accepted by the schema'
    pointer, keyword, _ = error
    assert (pointer, keyword) == (expected['pointer'], expected['keyword']), name

    with pytest.raises(WazuhError, match='.* 1130 .*') as exc:
        manager_conf.validate_document(document)
    assert expected['pointer'] in str(exc.value)


def test_valid_vectors_load_and_validate():
    for name in sorted(os.listdir(os.path.join(VECTORS_DIR, 'valid'))):
        with open(os.path.join(VECTORS_DIR, 'valid', name)) as f:
            document = manager_conf.load_yaml_text(f.read())
        manager_conf.validate_document(document)
        assert manager_conf.first_schema_error(document) is None, name


def test_apply_defaults_matches_cli_dump():
    """The effective document equals `wazuh-manager-conf dump` of the same fixture (frozen in wazuh-manager.effective.json)."""
    with open(FIXTURE_EFFECTIVE) as f:
        expected = json.load(f)

    assert manager_conf.load_manager_conf(FIXTURE) == expected


def test_apply_defaults_creates_object_sections():
    document = manager_conf.apply_defaults({})

    assert set(document) == set(manager_conf.schema()['properties'])
    assert document['indexer'] == {'hosts': [], 'ssl': {'certificate_authorities': [], 'certificate': '', 'key': ''}}
    assert document['remote']['legacy']['enabled'] is False
    assert document['cluster']['node_type'] == 'master'
    assert document['auth']['agents']['allow_higher_versions'] is False
    assert 'key' not in document['cluster']  # required, no default
    assert 'wpk_repository' not in document['agent-upgrade']  # no default on purpose


def test_apply_defaults_keeps_user_values():
    document = manager_conf.apply_defaults({'cluster': {'name': 'mine', 'hidden': True}, 'remote': {'https': {'port': 1600}}})

    assert document['cluster']['name'] == 'mine'
    assert document['cluster']['hidden'] is True
    assert document['cluster']['port'] == 1516
    assert document['remote']['https']['port'] == 1600
    assert 'certificate' in document['remote']['https']


def test_load_manager_conf_errors(tmp_path):
    with pytest.raises(WazuhError, match='.* 1101 .*'):
        manager_conf.load_manager_conf(str(tmp_path / 'missing.yml'))

    bad = tmp_path / 'bad.yml'
    bad.write_text('cluster:\n  key: 9d273b53510fef702b54a92e9cffc82e\n  port: 70000\n')
    with pytest.raises(WazuhError, match='.* 1130 .*') as exc:
        manager_conf.load_manager_conf(str(bad))
    assert '/cluster/port' in str(exc.value)

    unknown = tmp_path / 'unknown.yml'
    unknown.write_text('cluster:\n  key: 9d273b53510fef702b54a92e9cffc82e\n  colour: blue\n')
    with pytest.raises(WazuhError, match='.* 1130 .*') as exc:
        manager_conf.load_manager_conf(str(unknown))
    assert '/cluster/colour' in str(exc.value)

    syntax = tmp_path / 'syntax.yml'
    syntax.write_text('cluster: [\n')
    with pytest.raises(WazuhError, match='.* 1131 .*'):
        manager_conf.load_manager_conf(str(syntax))


def test_write_manager_conf_is_atomic(tmp_path):
    target = tmp_path / 'wazuh-manager.yml'
    target.write_text('old: true\n')
    os.chmod(target, 0o660)

    with patch('wazuh.core.common.OSSEC_TMP_PATH', new=str(tmp_path)):
        manager_conf.write_manager_conf('cluster:\n  key: 9d273b53510fef702b54a92e9cffc82e\n', str(target))

    assert target.read_text() == 'cluster:\n  key: 9d273b53510fef702b54a92e9cffc82e\n'
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o660
    assert [p.name for p in tmp_path.iterdir()] == ['wazuh-manager.yml']  # no temporary file left behind


def test_write_manager_conf_failure_is_1126(tmp_path):
    with patch('wazuh.core.common.OSSEC_TMP_PATH', new=str(tmp_path)), \
            patch('wazuh.core.manager_conf.safe_move', side_effect=OSError('disk full')):
        with pytest.raises(WazuhError, match='.* 1126 .*'):
            manager_conf.write_manager_conf('a: 1\n', str(tmp_path / 'wazuh-manager.yml'))


def test_fixture_is_yaml12_clean():
    """The fixture must not rely on YAML 1.1 coercions (guards the fixture itself)."""
    with open(FIXTURE) as f:
        text = f.read()
    assert yaml.safe_load(text) == manager_conf.load_yaml_text(text)
