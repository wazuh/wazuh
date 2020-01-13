#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from functools import wraps
from unittest.mock import patch, MagicMock
import os
import pytest
import sys

with patch('wazuh.common.getgrnam'):
    with patch('wazuh.common.getpwnam'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        sys.modules['api'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        def RBAC_bypasser(**kwargs):
            def decorator(f):
                @wraps(f)
                def wrapper(*args, **kwargs):
                    return f(*args, **kwargs)
                return wrapper
            return decorator
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
        from cdb_list import get_lists, get_path_lists
from wazuh.results import AffectedItemsWazuhResult
from wazuh import common


# Variables

DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
PATH_FILE_DATA_1 = os.path.join(DATA_PATH, "test_lists")
PATH_FILE_DATA_2 = os.path.join(DATA_PATH, "test_lists_2")
RESULT_GET_LIST_FILE_1 = [{'items': [{'key': 'test-wazuh-w', 'value': 'write'},
                                     {'key': 'test-wazuh-r', 'value': 'read'},
                                     {'key': 'test-wazuh-a', 'value': 'attribute'},
                                     {'key': 'test-wazuh-x', 'value': 'execute'},
                                     {'key': 'test-wazuh-c', 'value': 'command'}],
                           'path': PATH_FILE_DATA_1
                           }]
RESULT_GET_LIST_FILE_2 = [{'items': [{'key': 'test-ossec-w', 'value': 'write'},
                                     {'key': 'test-ossec-r', 'value': 'read'},
                                     {'key': 'test-ossec-x', 'value': 'execute'}],
                           'path': PATH_FILE_DATA_2
                           }]
PATHS_FILES_DATA = [PATH_FILE_DATA_1, PATH_FILE_DATA_2]
RESULTS_GET_LIST = RESULT_GET_LIST_FILE_1 + RESULT_GET_LIST_FILE_2

ETC_PATH = os.path.join("etc", "lists")
PATH_FILE_ETC_1 = os.path.join(ETC_PATH, "audit-keys")
PATH_FILE_ETC_2 = os.path.join(ETC_PATH, "amazon", "aws-eventnames")
RESULT_GET_PATH_LIST_FILE_1 = [{'folder': ETC_PATH,
                                'name': "audit-keys",
                                'path': PATH_FILE_ETC_1}]
RESULT_GET_PATH_LIST_FILE_2 = [{'folder': os.path.join(ETC_PATH, "amazon"),
                                'name': "aws-eventnames",
                                'path': PATH_FILE_ETC_2}]
PATHS_FILES_ETC = [PATH_FILE_ETC_1, PATH_FILE_ETC_2]
RESULTS_GET_PATH_LIST = RESULT_GET_PATH_LIST_FILE_1 + RESULT_GET_PATH_LIST_FILE_2


# Tests

@pytest.mark.parametrize("paths, expected_result", [
    ([PATH_FILE_DATA_1], RESULT_GET_LIST_FILE_1),
    (PATHS_FILES_DATA, RESULTS_GET_LIST)
])
def test_get_lists(paths, expected_result):
    result = get_lists(path=paths)
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.affected_items == expected_result
    assert result.total_affected_items == len(paths)


@pytest.mark.parametrize("limit", [1, 2])
def test_get_lists_limit(limit):
    result = get_lists(path=PATHS_FILES_DATA, limit=limit)
    assert limit > 0
    assert result.total_affected_items == limit
    assert result.affected_items == RESULTS_GET_LIST[:limit]


@pytest.mark.parametrize("offset", [0, 1])
def test_get_lists_offset(offset):
    result = get_lists(path=PATHS_FILES_DATA, offset=offset)
    assert result.total_affected_items == len(PATHS_FILES_DATA) - offset
    assert result.affected_items == RESULTS_GET_LIST[offset:]


@pytest.mark.parametrize("search_text, complementary_search, search_in_fields, path, expected_result", [
    ("command", False, None, PATHS_FILES_DATA, RESULT_GET_LIST_FILE_1),
    ("test-ossec-w", False, None, PATHS_FILES_DATA, RESULT_GET_LIST_FILE_2),
    ("command", False, None, [PATH_FILE_DATA_2], []),
    ("command", False, None, PATHS_FILES_DATA, RESULT_GET_LIST_FILE_1),
    ("command", False, "items", [PATH_FILE_DATA_2], []),
    ("write", False, "items", PATHS_FILES_DATA, RESULTS_GET_LIST),
    ("test-wazuh-w", False, "items", PATHS_FILES_DATA, RESULT_GET_LIST_FILE_1),
    ("test-ossec-w", False, "items", PATHS_FILES_DATA, RESULT_GET_LIST_FILE_2),
    ("test-wazuh-w", False, "items", [PATH_FILE_DATA_2], []),
    ("command", True, None, PATHS_FILES_DATA, RESULT_GET_LIST_FILE_2),
    ("test-ossec-w", True, None, PATHS_FILES_DATA, RESULT_GET_LIST_FILE_1),
    ("command", True, None, [PATH_FILE_DATA_2], RESULT_GET_LIST_FILE_2),
    ("command", True, "items", PATHS_FILES_DATA, RESULT_GET_LIST_FILE_2),
    ("command", True, "items", [PATH_FILE_DATA_2], RESULT_GET_LIST_FILE_2),
    ("command", True, "items", [PATH_FILE_DATA_1], []),
    ("write", True, "items", PATHS_FILES_DATA, []),
    ("test-wazuh-w", True, "items", PATHS_FILES_DATA, RESULT_GET_LIST_FILE_2),
    ("test-ossec-w", True, "items", PATHS_FILES_DATA, RESULT_GET_LIST_FILE_1),
    ("test-wazuh-w", True, "items", [PATH_FILE_DATA_2], RESULT_GET_LIST_FILE_2),
])
def test_get_lists_search(search_text, complementary_search, search_in_fields, path, expected_result):
    result = get_lists(path=path, search_text=search_text, complementary_search=complementary_search,
                       search_in_fields=search_in_fields)
    assert result.total_affected_items == len(expected_result)
    assert result.affected_items == expected_result


def test_get_lists_sort():
    result_a = get_lists(path=PATHS_FILES_DATA, sort_by=['path'], sort_ascending=True)
    result_b = get_lists(path=PATHS_FILES_DATA, sort_by=['path'], sort_ascending=False)

    assert result_a.affected_items != result_b.affected_items
    assert result_a.affected_items == RESULT_GET_LIST_FILE_1 + RESULT_GET_LIST_FILE_2
    assert result_b.affected_items == RESULT_GET_LIST_FILE_2 + RESULT_GET_LIST_FILE_1


def test_get_path_lists():
    common.reset_context_cache()
    result = get_path_lists(path=[PATH_FILE_ETC_1])
    assert result.affected_items == RESULT_GET_PATH_LIST_FILE_1


@pytest.mark.parametrize("limit", [1, 2])
def test_get_path_lists_limit(limit):
    common.reset_context_cache()
    result = get_path_lists(path=PATHS_FILES_ETC, limit=limit)
    assert limit > 0
    assert result.total_affected_items == limit
    assert result.affected_items == RESULTS_GET_PATH_LIST[:limit]


@pytest.mark.parametrize("offset", [0, 1])
def test_get_path_lists_offset(offset):
    common.reset_context_cache()
    result = get_path_lists(path=PATHS_FILES_ETC, offset=offset)
    assert result.total_affected_items == len(PATHS_FILES_ETC) - offset
    assert result.affected_items == RESULTS_GET_PATH_LIST[offset:]


@pytest.mark.parametrize("search_text, complementary_search, search_in_fields, path, expected_result", [
    ("audit", False, None, PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_1),
    ("aws", False, None, PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_2),
    ("invalid", False, None, PATHS_FILES_ETC, []),
    ("audit", False, "path", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_1),
    ("aws", False, "path", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_2),
    ("invalid", False, "path", PATHS_FILES_ETC, []),
    ("audit", False, "name", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_1),
    ("aws", False, "name", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_2),
    ("invalid", False, "name", PATHS_FILES_ETC, []),
    ("amazon", False, "folder", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_2),

    ("audit", True, None, PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_2),
    ("aws", True, None, PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_1),
    ("invalid", True, None, PATHS_FILES_ETC, RESULTS_GET_PATH_LIST),
    ("audit", True, "path", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_2),
    ("aws", True, "path", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_1),
    ("invalid", True, "path", PATHS_FILES_ETC, RESULTS_GET_PATH_LIST),
    ("audit", True, "name", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_2),
    ("aws", True, "name", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_1),
    ("invalid", True, "name", PATHS_FILES_ETC, RESULTS_GET_PATH_LIST),
    ("amazon", True, "folder", PATHS_FILES_ETC, RESULT_GET_PATH_LIST_FILE_1)
])
def test_get_path_lists_search(search_text, complementary_search, search_in_fields, path, expected_result):
    common.reset_context_cache()
    result = get_path_lists(path=path, search_text=search_text, complementary_search=complementary_search,
                            search_in_fields=search_in_fields)
    assert result.total_affected_items == len(expected_result)
    assert result.affected_items == expected_result


def test_get_path_lists_sort():
    result_a = get_path_lists(path=PATHS_FILES_ETC, sort_by=['name'], sort_ascending=True)
    result_b = get_path_lists(path=PATHS_FILES_ETC, sort_by=['name'], sort_ascending=False)

    assert result_a.affected_items != result_b.affected_items
    assert result_a.affected_items == RESULT_GET_PATH_LIST_FILE_1 + RESULT_GET_PATH_LIST_FILE_2
    assert result_b.affected_items == RESULT_GET_PATH_LIST_FILE_2 + RESULT_GET_PATH_LIST_FILE_1
