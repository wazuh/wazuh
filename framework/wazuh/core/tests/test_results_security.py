#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.results import AffectedItemsWazuhResult, merge
        from wazuh import WazuhException


class TestSortCastingValidation:
    """Test suite to verify sort_casting validation prevents arbitrary code execution."""

    @pytest.mark.parametrize('malicious_type', [
        'exec',
        'eval',
        'compile',
        '__import__',
        'open',
        'getattr',
        'setattr',
        'delattr',
        'breakpoint',
        'input',
        'exit',
        'quit',
    ])
    def test_decode_json_rejects_malicious_types(self, malicious_type):
        """Verify decode_json rejects dangerous builtin names in sort_casting."""
        malicious_obj = {
            'affected_items': [{'id': '001'}],
            'sort_fields': ['id'],
            'sort_casting': [malicious_type],  # Malicious type
            'sort_ascending': [True],
            'total_affected_items': 1,
            'dikt': {},
            'all_msg': '',
            'some_msg': '',
            'none_msg': '',
            'failed_items_keys': [],
            'failed_items_values': []
        }

        with pytest.raises(WazuhException, match=f"Invalid sort_casting type '{malicious_type}'"):
            AffectedItemsWazuhResult.decode_json(malicious_obj)

    @pytest.mark.parametrize('valid_type', [
        'int',
        'str',
        'float',
        'bool',
    ])
    def test_decode_json_accepts_valid_types(self, valid_type):
        """Verify decode_json accepts legitimate type caster names."""
        valid_obj = {
            'affected_items': [{'id': '001'}],
            'sort_fields': ['id'],
            'sort_casting': [valid_type],
            'sort_ascending': [True],
            'total_affected_items': 1,
            'dikt': {},
            'all_msg': '',
            'some_msg': '',
            'none_msg': '',
            'failed_items_keys': [],
            'failed_items_values': []
        }

        result = AffectedItemsWazuhResult.decode_json(valid_obj)
        assert result.sort_casting == [valid_type]

    def test_decode_json_rejects_non_string_types(self):
        """Verify decode_json rejects non-string values in sort_casting."""
        invalid_obj = {
            'affected_items': [],
            'sort_fields': None,
            'sort_casting': [int],  # Type object instead of string
            'sort_ascending': [True],
            'total_affected_items': 0,
            'dikt': {},
            'all_msg': '',
            'some_msg': '',
            'none_msg': '',
            'failed_items_keys': [],
            'failed_items_values': []
        }

        with pytest.raises(WazuhException, match="sort_casting type must be a string"):
            AffectedItemsWazuhResult.decode_json(invalid_obj)

    def test_decode_json_rejects_non_list_sort_casting(self):
        """Verify decode_json rejects non-list sort_casting values."""
        invalid_obj = {
            'affected_items': [],
            'sort_fields': None,
            'sort_casting': 'int',  # String instead of list
            'sort_ascending': [True],
            'total_affected_items': 0,
            'dikt': {},
            'all_msg': '',
            'some_msg': '',
            'none_msg': '',
            'failed_items_keys': [],
            'failed_items_values': []
        }

        with pytest.raises(WazuhException, match="sort_casting must be a list"):
            AffectedItemsWazuhResult.decode_json(invalid_obj)

    @pytest.mark.parametrize('malicious_type', [
        'exec',
        'eval',
        '__import__',
    ])
    def test_merge_rejects_malicious_types(self, malicious_type):
        """Verify merge() rejects dangerous type names."""
        list1 = [{'id': '001'}]
        list2 = [{'id': '002'}]

        with pytest.raises(WazuhException, match=f"Invalid sort_casting type '{malicious_type}'"):
            merge(list1, list2, criteria=['id'], ascending=[True], types=[malicious_type])

    @pytest.mark.parametrize('valid_type', [
        'int',
        'str',
        'float',
        'bool',
    ])
    def test_merge_accepts_valid_types(self, valid_type):
        """Verify merge() accepts legitimate type names."""
        list1 = ['001', '002']
        list2 = ['003', '004']

        result = merge(list1, list2, criteria=None, ascending=[True], types=[valid_type])
        assert len(result) == 4

    def test_rce_payload_blocked_in_decode_json(self):
        """Verify that a realistic RCE payload is blocked at deserialization."""
        rce_payload = {
            'affected_items': [{'__x__': "import os; os.system('id > /tmp/pwned')"}],
            'sort_fields': ['__x__'],
            'sort_casting': ['exec'],  # Would execute code if not blocked
            'sort_ascending': [True],
            'total_affected_items': 1,
            'dikt': {},
            'all_msg': '',
            'some_msg': '',
            'none_msg': '',
            'failed_items_keys': [],
            'failed_items_values': []
        }

        with pytest.raises(WazuhException, match="Invalid sort_casting type 'exec'"):
            AffectedItemsWazuhResult.decode_json(rce_payload)

    def test_multiple_malicious_types_in_list(self):
        """Verify that multiple malicious types in sort_casting are all rejected."""
        malicious_obj = {
            'affected_items': [],
            'sort_fields': None,
            'sort_casting': ['int', 'exec', 'str'],  # Mixed valid and invalid
            'sort_ascending': [True],
            'total_affected_items': 0,
            'dikt': {},
            'all_msg': '',
            'some_msg': '',
            'none_msg': '',
            'failed_items_keys': [],
            'failed_items_values': []
        }

        with pytest.raises(WazuhException, match="Invalid sort_casting type 'exec'"):
            AffectedItemsWazuhResult.decode_json(malicious_obj)

    def test_merge_integration_with_valid_types(self):
        """Integration test: merge results with valid sort_casting types."""
        result1 = AffectedItemsWazuhResult(
            affected_items=[{'id': '003', 'name': 'agent3'}],
            sort_fields=['id'],
            sort_casting=['int'],
            sort_ascending=[True]
        )
        result2 = AffectedItemsWazuhResult(
            affected_items=[{'id': '001', 'name': 'agent1'}],
            sort_fields=['id'],
            sort_casting=['int'],
            sort_ascending=[True]
        )

        merged = result1 | result2

        # Verify merge succeeded and items are sorted correctly
        assert len(merged.affected_items) == 2
        assert merged.affected_items[0]['id'] == '001'
        assert merged.affected_items[1]['id'] == '003'
