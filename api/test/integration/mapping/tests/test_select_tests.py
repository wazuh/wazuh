# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from os import path

import pytest

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import select_tests  # noqa: E402


@pytest.fixture(scope='module')
def rules():
    return select_tests.load_rules()


@pytest.fixture(scope='module')
def groups():
    return select_tests.load_groups()


@pytest.fixture(scope='module')
def workflow_paths():
    return select_tests.load_workflow_paths()


@pytest.fixture(scope='module')
def all_tests(groups):
    return sorted(t for tests in groups.values() for t in tests)


@pytest.mark.parametrize('pattern, file, expected', [
    ('src/**', 'src/a/b.c', True),
    ('src/**/tests/**', 'src/tests/a.c', True),
    ('src/**/tests/**', 'src/x/y/tests/a.c', True),
    ('**/*.md', 'README.md', True),
    ('**/*.md', 'a/b/README.md', True),
    ('api/api/*.py', 'api/api/middlewares.py', True),
    ('api/api/*.py', 'api/api/controllers/util.py', False),
    ('api/*', 'api/setup.py', True),
    ('api/*', 'api/api/spec/spec.yaml', False),
    ('api/test/integration/test_*.tavern.yaml', 'api/test/integration/test_a_endpoints.tavern.yaml', True),
])
def test_glob(pattern, file, expected):
    assert select_tests.matches(pattern, file) is expected


def test_braces_refused():
    with pytest.raises(ValueError):
        select_tests.glob_to_regex('src/{a,b}/**')


def test_last_matching_workflow_pattern_decides():
    paths = ['src/**', '!src/**/tests/**', 'src/keep/tests/**']
    assert select_tests.triggers_workflow('src/a.c', paths)
    assert not select_tests.triggers_workflow('src/x/tests/a.c', paths)
    assert select_tests.triggers_workflow('src/keep/tests/a.c', paths)
    assert not select_tests.triggers_workflow('docs/a.md', paths)


def test_group_names(groups):
    assert set(groups['agent']) == {f'test_agent_{m}_endpoints.tavern.yaml' for m in ('GET', 'POST', 'PUT', 'DELETE')}
    assert groups['rbac_black_agent'] == ['test_rbac_black_agent_endpoints.tavern.yaml']
    assert groups['rbac_white_all'] == ['test_rbac_white_all_endpoints.tavern.yaml']


def select(files, rules, groups, workflow_paths):
    return select_tests.select(files, rules, groups, workflow_paths)


def test_module_file_selects_its_tests(rules, groups, workflow_paths):
    assert select(['framework/wazuh/mitre.py'], rules, groups, workflow_paths) == [
        'test_mitre_endpoints.tavern.yaml', 'test_rbac_black_mitre_endpoints.tavern.yaml',
        'test_rbac_white_all_endpoints.tavern.yaml', 'test_rbac_white_mitre_endpoints.tavern.yaml']


@pytest.mark.parametrize('file', [
    'api/api/spec/spec.yaml', 'api/api/middlewares.py', 'api/api/authentication.py',
    'framework/wazuh/core/cluster/dapi/dapi.py', 'framework/wazuh/rbac/decorators.py',
    'src/wazuh_db/main.c', 'install.sh', 'api/test/integration/conftest.py',
    'api/test/integration/env/docker-compose.yml', '.github/workflows/5_testintegration_api-endpoints.yml',
])
def test_cross_cutting_file_selects_everything(file, rules, groups, workflow_paths, all_tests):
    assert select([file], rules, groups, workflow_paths) == all_tests


def test_rbac_defaults_select_security_and_every_rbac_file(rules, groups, workflow_paths):
    selected = select(['framework/wazuh/rbac/default/policies.yaml'], rules, groups, workflow_paths)
    assert 'test_security_GET_endpoints.tavern.yaml' in selected
    assert {t for t in selected if t.startswith('test_rbac_')} == {t for ts in groups.values() for t in ts
                                                                    if t.startswith('test_rbac_')}


def test_mixed_change_is_the_union(rules, groups, workflow_paths, all_tests):
    assert select(['framework/wazuh/mitre.py', 'src/remoted/main.c'], rules, groups, workflow_paths) == all_tests


@pytest.mark.parametrize('file', [
    'framework/wazuh/tests/test_agent.py', 'api/api/test/test_middlewares.py', 'docs/ref/index.md',
    'api/test/integration/README.md', 'src/wazuh_db/tests/test_x.cpp', 'src/engine/test/x.cpp',
    'api/test/integration/mapping/endpoint_coverage.py', 'api/test/integration/_test_smoke.tavern.yaml',
])
def test_files_that_select_nothing(file, rules, groups, workflow_paths):
    assert select([file], rules, groups, workflow_paths) == []


def test_unknown_file_inside_the_paths_selects_everything(rules, groups, workflow_paths, all_tests):
    assert select(['framework/brand_new_dir/x.py'], rules, groups, workflow_paths) == all_tests


def test_changed_tavern_file_selects_itself(rules, groups, workflow_paths):
    file = 'api/test/integration/test_cluster_endpoints.tavern.yaml'
    assert select([file], rules, groups, workflow_paths) == ['test_cluster_endpoints.tavern.yaml']


def test_deleted_tavern_file_selects_nothing(rules, groups, workflow_paths):
    assert select(['api/test/integration/test_gone_endpoints.tavern.yaml'], rules, groups, workflow_paths) == []


def test_changed_files_keeps_both_sides_of_a_rename(monkeypatch):
    outputs = iter(['base\n', 'R090\tframework/wazuh/old.py\tframework/wazuh/new.py\nD\tapi/api/gone.py\n'])
    monkeypatch.setattr(select_tests.subprocess, 'check_output', lambda *a, **k: next(outputs))
    assert select_tests.changed_files('origin/x') == ['framework/wazuh/old.py', 'framework/wazuh/new.py',
                                                      'api/api/gone.py']


def test_test_list(groups):
    assert select_tests.resolve_test_list('agent_get_endpoints, Cluster_endpoints', groups) == [
        'test_agent_GET_endpoints.tavern.yaml', 'test_cluster_endpoints.tavern.yaml']
    with pytest.raises(ValueError):
        select_tests.resolve_test_list('nope', groups)


def test_repository_rules_are_consistent(rules, groups, workflow_paths):
    """Every rule is live, every group reachable, and the rules agree with the workflow paths."""
    assert select_tests.validate(rules, groups, workflow_paths, select_tests.tracked_files()) == []
