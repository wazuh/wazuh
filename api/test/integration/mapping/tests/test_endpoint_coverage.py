# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from os import path

import pytest

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import endpoint_coverage as coverage  # noqa: E402

DATA = path.join(path.dirname(path.abspath(__file__)), 'data')


@pytest.fixture
def operations():
    return coverage.load_operations(path.join(DATA, 'spec.yaml'))


@pytest.fixture
def stages():
    return coverage.load_stages(path.join(DATA, 'tavern'))


def by_key(operations):
    return {op.key: op for op in operations}


def test_required_buckets(operations):
    ops = by_key(operations)
    assert ops['GET /'].required == {'ok', 'method_not_allowed', 'unauthorized'}
    assert ops['GET /agents'].required == {'ok', 'method_not_allowed', 'unauthorized', 'bad_request', 'forbidden'}
    assert ops['POST /agents'].required == {'ok', 'method_not_allowed', 'unauthorized', 'bad_request', 'too_large',
                                            'unsupported_media_type'}
    assert ops['GET /agents/{agent_id}'].required == {'ok', 'method_not_allowed', 'unauthorized', 'bad_request',
                                                      'not_found'}
    # security: [] overrides the global scheme
    assert 'unauthorized' not in ops['POST /login'].required


def test_parametrize_is_expanded_and_lines_kept(stages):
    parametrized = [s for s in stages if s.status_codes == (405,)]
    assert {(s.method, s.url_path) for s in parametrized} == {('DELETE', '/agents/001'), ('PATCH', '/agents')}
    assert all(s.line > 0 for s in stages)


def test_default_method_and_query_string(stages):
    bad_limit = next(s for s in stages if s.status_codes == (400,))
    assert (bad_limit.method, bad_limit.url_path) == ('GET', '/agents')


def test_literal_segments_win(operations):
    assert {op.key for op in coverage.match_path(operations, '/agents/group')} == {'PUT /agents/group'}
    assert {op.key for op in coverage.match_path(operations, '/agents/001')} == {'GET /agents/{agent_id}'}
    assert coverage.match_path(operations, '/nope') == []


def test_evaluate_fills_buckets(operations, stages):
    errors = coverage.evaluate(operations, stages, [])
    ops = by_key(operations)
    assert set(ops['GET /agents'].covered) == {'ok', 'bad_request', 'forbidden', 'method_not_allowed'}
    # Only the 403 of the rbac file counts
    assert ops['GET /agents'].covered['forbidden'] == {'test_rbac_white_sample_endpoints.tavern.yaml'}
    # A status list fills every bucket in it
    assert {'ok', 'not_found', 'method_not_allowed'} <= set(ops['GET /agents/{agent_id}'].covered)
    # A 405 on a path covers every operation of that path
    assert 'method_not_allowed' in ops['POST /agents'].covered
    # The unknown route 404 is accepted, everything missing is reported
    assert not any('matches no spec path' in e for e in errors)
    assert 'GET /agents: missing a 401 stage; required for every operation with an auth scheme' in errors
    assert any(e.startswith('POST /agents: missing a 413') for e in errors)


def test_unmatched_and_misplaced_stages(operations):
    stages = [coverage.Stage('test_x_endpoints.tavern.yaml', 3, 'GET', '/nope', (200,)),
              coverage.Stage('test_x_endpoints.tavern.yaml', 9, 'DELETE', '/agents', (200,)),
              coverage.Stage('test_x_endpoints.tavern.yaml', 12, 'GET', '/agents', (405,))]
    stages.append(coverage.Stage('test_x_endpoints.tavern.yaml', 15, 'OPTIONS', '/agents', (200,)))
    errors = coverage.evaluate(operations, stages, [])
    assert 'test_x_endpoints.tavern.yaml:3: GET /nope matches no spec path' in errors
    # A CORS preflight calls no operation
    assert not any(':15:' in e for e in errors)
    assert any(e.startswith('test_x_endpoints.tavern.yaml:9: DELETE is not declared for /agents') for e in errors)
    assert 'test_x_endpoints.tavern.yaml:12: 405 asserted on the declared operation GET /agents' in errors


@pytest.mark.parametrize('exception, message', [
    ({'operation': 'GET /nope', 'bucket': 'ok', 'reason': 'x'}, 'no such operation'),
    ({'operation': 'GET /agents', 'bucket': 'nope', 'reason': 'x'}, 'unknown bucket'),
    ({'operation': 'GET /agents', 'bucket': 'unauthorized', 'reason': ''}, 'a reason is required'),
    ({'operation': 'GET /agents', 'bucket': 'too_large', 'reason': 'x'}, 'stale, the bucket is not required'),
    ({'operation': 'GET /agents', 'bucket': 'ok', 'reason': 'x'}, 'stale, covered by'),
])
def test_bad_exceptions(operations, stages, exception, message):
    errors = coverage.evaluate(operations, stages, [exception])
    assert any(message in e for e in errors), errors


def test_exception_silences_a_bucket(operations, stages):
    exception = {'operation': 'GET /agents', 'bucket': 'unauthorized', 'reason': 'x', 'pending': True}
    errors = coverage.evaluate(operations, stages, [exception])
    assert not any(e.startswith('GET /agents: missing a 401') for e in errors)
    report = coverage.render_report(operations, [exception])
    assert '| `GET /agents` | ✓ | ✓ | pending | ✓ | · | ✓ | · | · |' in report


def test_repository_is_covered():
    """The real spec, tavern files and exceptions: the same check CI runs."""
    operations = coverage.load_operations()
    exceptions = coverage.load_exceptions()
    errors = coverage.evaluate(operations, coverage.load_stages(), exceptions)
    assert errors == []
    with open(coverage.REPORT_PATH) as f:
        assert f.read() == coverage.render_report(operations, exceptions), 'run coverage.py --write'


@pytest.mark.parametrize('args', [[], ['--check']])
def test_cli_check(args, monkeypatch):
    """The workflow runs `--check`; with no argument the script checks too."""
    monkeypatch.setattr(sys, 'argv', ['endpoint_coverage.py'] + args)
    assert coverage.main() == 0


def test_cli_check_and_write_are_exclusive(monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['endpoint_coverage.py', '--check', '--write'])
    with pytest.raises(SystemExit):
        coverage.main()

