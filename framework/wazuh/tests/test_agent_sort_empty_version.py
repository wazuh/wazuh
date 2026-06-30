#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Test for agent sorting with empty/NULL version strings.

This test validates the fix for the issue where sorting agents by version
would fail with TypeError when agents have empty version strings.

Issue: TypeError: '<' not supported between instances of 'str' and 'tuple'
Fix: Handle empty strings in addition to None when generating sort keys
"""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.agent import get_agents
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh.core.utils import parse_wazuh_agent_version, check_if_wazuh_agent_version
        from wazuh.core.agent import format_fields


def mock_db_query_with_empty_versions(*args, **kwargs):
    """Mock database query that returns agents with various version values."""
    class MockQuery:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def run(self):
            # Simulate agents with different version values
            return {
                'items': [
                    {'id': '001', 'name': 'agent001', 'version': 'Wazuh v4.13.1', 'group': ['default']},
                    {'id': '002', 'name': 'agent002', 'version': '', 'group': ['default']},  # Empty string
                    {'id': '003', 'name': 'agent003', 'version': 'Wazuh v4.14.5', 'group': ['default']},
                    {'id': '004', 'name': 'agent004', 'version': None, 'group': ['default']},  # None
                    {'id': '005', 'name': 'agent005', 'version': 'Wazuh v4.10.1', 'group': ['default']},
                    {'id': '006', 'name': 'agent006', 'version': '', 'group': ['default']},  # Empty string
                ],
                'totalItems': 6
            }

    return MockQuery()


@pytest.mark.parametrize('sort_order', ['asc', 'desc'])
@patch('wazuh.agent.WazuhDBQueryAgents', side_effect=mock_db_query_with_empty_versions)
@patch('wazuh.agent.get_agents_info', return_value=['001', '002', '003', '004', '005', '006'])
@patch('wazuh.agent.get_rbac_filters', return_value={})
def test_get_agents_sort_with_empty_version(mock_rbac, mock_agents_info, mock_query, sort_order):
    """
    Test that get_agents can sort by version when some agents have empty/NULL versions.

    This test validates the fix for the TypeError that occurred when:
    - Some agents have valid versions (e.g., "Wazuh v4.13.1")
    - Some agents have empty versions ("")
    - Some agents have NULL versions (None)

    The fix ensures all agents get consistent tuple-based sort keys:
    - Valid version: ((4, 13, 1),)
    - Empty/None version: ((0, 0, 0),)

    Parameters
    ----------
    sort_order : str
        Sort order ('asc' or 'desc')
    """
    # Test sorting by version
    result = get_agents(
        agent_list=['001', '002', '003', '004', '005', '006'],
        sort={'fields': ['version'], 'order': sort_order},
        select=['id', 'name', 'version']
    )

    # Verify result is successful
    assert isinstance(result, AffectedItemsWazuhResult), 'Result should be AffectedItemsWazuhResult'
    assert len(result.affected_items) == 6, 'Should return all 6 agents'
    assert len(result.failed_items) == 0, 'Should have no failed items'

    # Verify agents are sorted
    versions = [agent.get('version') for agent in result.affected_items]

    if sort_order == 'asc':
        # Empty/None versions should come first (treated as 0.0.0)
        # Then versions in ascending order
        expected_order = [
            '', None, '',  # Empty/None versions first
            'Wazuh v4.10.1', 'Wazuh v4.13.1', 'Wazuh v4.14.5'  # Then sorted versions
        ]
    else:
        # Descending order
        expected_order = [
            'Wazuh v4.14.5', 'Wazuh v4.13.1', 'Wazuh v4.10.1',  # Versions descending
            '', None, ''  # Empty/None versions last
        ]

    # Check that empty/None versions are grouped correctly
    non_empty_versions = [v for v in versions if v not in ('', None)]
    empty_versions = [v for v in versions if v in ('', None)]

    if sort_order == 'asc':
        # Empty versions should be at the beginning
        assert versions[:3] == ['', None, ''] or set(versions[:3]) == {'', None}
        # Non-empty versions should be sorted
        assert non_empty_versions == ['Wazuh v4.10.1', 'Wazuh v4.13.1', 'Wazuh v4.14.5']
    else:
        # Empty versions should be at the end
        assert versions[-3:] == ['', None, ''] or set(versions[-3:]) == {'', None}
        # Non-empty versions should be sorted descending
        assert non_empty_versions == ['Wazuh v4.14.5', 'Wazuh v4.13.1', 'Wazuh v4.10.1']


def test_sort_key_generation_with_empty_versions():
    """
    Test the sort key generation logic directly.

    This unit test validates that the sort key lambda function
    generates consistent tuple keys for all version values.
    """
    # Test data with various version values
    test_agents = [
        {'version': 'Wazuh v4.13.1'},
        {'version': ''},
        {'version': None},
        {'version': 'Wazuh v4.14.5'},
    ]

    sort = {'fields': ['version'], 'order': 'asc'}

    # Generate sort keys using the fixed logic
    keys = []
    for o in test_agents:
        key = tuple(
            parse_wazuh_agent_version(o.get(a)) if a == 'version' and check_if_wazuh_agent_version(o.get(a))
            else (0, 0, 0) if (o.get(a) is None or o.get(a) == '') and a == 'version'  # The fix
            else o.get(a).lower() if type(o.get(a)) == str else o.get(a)
            for a in sort['fields']
        )
        keys.append(key)

    # Verify all keys are tuples containing tuples (consistent types)
    assert all(isinstance(key, tuple) for key in keys), 'All keys should be tuples'
    assert all(isinstance(key[0], tuple) for key in keys), 'All key elements should be tuples'

    # Verify specific key values
    assert keys[0] == ((4, 13, 1),), 'Valid version should parse correctly'
    assert keys[1] == ((0, 0, 0),), 'Empty string should be treated as (0, 0, 0)'
    assert keys[2] == ((0, 0, 0),), 'None should be treated as (0, 0, 0)'
    assert keys[3] == ((4, 14, 5),), 'Another valid version should parse correctly'

    # Most importantly: verify we can sort without TypeError
    try:
        sorted_keys = sorted(keys)
        assert True, 'Sorting should succeed without TypeError'
    except TypeError as e:
        pytest.fail(f"Sorting failed with TypeError: {e}")


def test_backwards_compatibility():
    """
    Test that the fix maintains backwards compatibility.

    Ensure that agents with valid versions are still sorted correctly.
    """
    test_agents = [
        {'version': 'Wazuh v4.13.1'},
        {'version': 'Wazuh v4.10.1'},
        {'version': 'Wazuh v4.14.5'},
        {'version': 'Wazuh v3.9.0'},
    ]

    sort = {'fields': ['version'], 'order': 'asc'}

    sorted_agents = sorted(test_agents,
                  key=lambda o: tuple(
                      parse_wazuh_agent_version(o.get(a)) if a == 'version' and check_if_wazuh_agent_version(o.get(a))
                      else (0, 0, 0) if (o.get(a) is None or o.get(a) == '') and a == 'version'
                      else o.get(a).lower() if type(o.get(a)) == str else o.get(a)
                      for a in sort['fields']),
                  reverse=False)

    # Verify correct sort order
    expected_order = ['Wazuh v3.9.0', 'Wazuh v4.10.1', 'Wazuh v4.13.1', 'Wazuh v4.14.5']
    actual_order = [agent['version'] for agent in sorted_agents]

    assert actual_order == expected_order, f"Expected {expected_order}, got {actual_order}"


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v'])
