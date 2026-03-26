#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import jsonschema as js
import pytest

from api.validator import (
    check_exp,
    check_xml,
    _alphanumeric_param,
    _hashes,
    _names,
    _numbers,
    _wazuh_key,
    _paths,
    _search_param,
    _sort_param,
    _timeframe_type,
    allowed_fields,
    is_safe_path,
    _wazuh_version,
    _symbols_alphanumeric_param,
    _base64,
    _group_names,
    _group_names_or_all,
    _iso8601_date,
    _iso8601_date_time,
    _numbers_or_all,
    check_component_configuration_pair,
    _wpk_path,
)
from wazuh import WazuhError

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")


@pytest.mark.parametrize(
    "exp, regex_name",
    [
        # numbers
        ("54355", _numbers),
        (100, _alphanumeric_param),
        (1234567890, _numbers_or_all),
        ("all", _numbers_or_all),
        # names
        ("alphanumeric1_param2", _alphanumeric_param),
        ("file%1-test_name1", _names),
        ("[(Random_symbols-string123)],<>!.+:\"'|=~#", _symbols_alphanumeric_param),
        ("Group_name-2", _group_names),
        (".group-2", _group_names),
        ("...", _group_names),
        ("Group_name-2", _group_names_or_all),
        (".Group_name-2", _group_names_or_all),
        ("...", _group_names_or_all),
        ("all", _group_names_or_all),
        # IPs
        # hashes
        ("e4d909c290d0fb1ca068ffaddf22cbd0", _hashes),
        ("449e3b6ffd9b484c5c645321edd4d610", _wazuh_key),
        # date
        ("2021-04-28", _iso8601_date),
        ("2021-11-04T18:14:04Z", _iso8601_date_time),
        # time
        ("1d", _timeframe_type),
        ("12h", _timeframe_type),
        ("40m", _timeframe_type),
        ("60s", _timeframe_type),
        # sort and search parameters
        ("sort param-", _sort_param),
        ("search param3", _search_param),
        # paths
        ("/var/wazuh-manager/etc/internal_options", _paths),
        ("correct.wpk", _wpk_path),
        # version
        ("v4.4.0", _wazuh_version),
        ("4.4.0", _wazuh_version),
        ("wazuh 4.4.0", _wazuh_version),
        ("wazuh v4.4.0", _wazuh_version),
        # miscellaneous
        ("aHR0cHM6Ly9zdGFja2FidXNlLmNvbS90YWcvamF2YS8=", _base64),
    ],
)
def test_validation_check_exp_ok(exp, regex_name):
    """Verify that check_exp() returns True with correct params"""
    assert check_exp(exp, regex_name)


@pytest.mark.parametrize(
    "exp, regex_name",
    [
        # numbers
        ("543a", _numbers),
        ("number", _numbers_or_all),
        ("2380234all", _numbers_or_all),
        # names
        ("alphanumeric1_$param2", _alphanumeric_param),
        ("all", _group_names),
        (".", _group_names),
        ("..", _group_names),
        ("解放加大了看", _group_names),
        ("тестирование", _group_names),
        ("בדיקה", _group_names),
        (".", _group_names_or_all),
        ("..", _group_names_or_all),
        # query parameters
        ("sort param@", _sort_param),
        ("search param;", _search_param),
        # hashes
        ("$$d909c290d0fb1ca068ffaddf22cbd0", _hashes),
        ("449e3b6ffd9b484c5c645321edd4d61$", _wazuh_key),
        # date
        ("2021-13-28", _iso8601_date),
        ("2021-10-35", _iso8601_date),
        ("2021-11-04Z18:14:04T", _iso8601_date_time),
        # time
        ("1j", _timeframe_type),
        ("12x", _timeframe_type),
        # paths
        ("/var/wazuh-manager/etc/internal_options$", _paths),
        ("incorrect.txt", _wpk_path),
        (".wpk", _wpk_path),
        # version
        ("v4.4", _wazuh_version),
        ("4.4", _wazuh_version),
        ("wazuh 4.4", _wazuh_version),
        ("wazuh v4.4", _wazuh_version),
        # miscellaneous
        ("aDhjasdh3=", _base64),
    ],
)
def test_validation_check_exp_ko(exp, regex_name):
    """Verify that check_exp() returns False with incorrect params"""
    assert not check_exp(exp, regex_name)


@pytest.mark.parametrize(
    "xml_file", [(os.path.join(test_data_path, "test_xml_1.xml")), (os.path.join(test_data_path, "test_xml_2.xml"))]
)
def test_validation_xml_ok(xml_file):
    """Verify that check_xml() returns True with well-formed XML files."""
    with open(xml_file) as f:
        xml_content = f.read()
    assert check_xml(xml_content)


@pytest.mark.parametrize(
    "xml_file",
    [(os.path.join(test_data_path, "test_xml_ko_1.xml")), (os.path.join(test_data_path, "test_xml_ko_2.xml"))],
)
def test_validation_xml_ko(xml_file):
    """Verify that check_xml() returns True with malformed XML files."""
    with open(xml_file) as f:
        xml_content = f.read()
    assert not check_xml(xml_content)


def test_allowed_fields():
    """Verify that allowed_fields() returns list with allowed fields from a dict"""
    result = allowed_fields({"field0": "value0", "field1": "value1"})
    assert isinstance(result, list)


def test_is_safe_path():
    """Verify that is_safe_path() works as expected"""
    assert is_safe_path("/api/configuration/api.yaml")
    assert is_safe_path("c:\\api\\configuration\\api.yaml")
    assert is_safe_path("etc/wazuh-manager.conf", relative=True)
    assert not is_safe_path("/api/configuration/api.yaml", basedir="non-existent", relative=False)
    assert not is_safe_path("/..")
    assert not is_safe_path("\\..")

@pytest.mark.parametrize(
    "value, format",
    [
        ("test.33alphanumeric:", "alphanumeric"),
        ("cGVwZQ==", "base64"),
        ("AB0264EA00FD9BCDCF1A5B88BC1BDEA4", "hash"),
        ("file_test-33.xml", "names"),
        ("651403650840", "numbers"),
        ("/var/wazuh/test", "path"),
        ("test,.", "search"),
        ("+field", "sort"),
        ("-field,+field.subfield", "sort"),
        ("7d", "timeframe"),
        ("1s", "timeframe"),
        ("7m", "timeframe"),
        ("asdfASD0101", "wazuh_key"),
        ("2019-02-26", "date"),
        ("2020-06-24T17:02:53Z", "date-time"),
        ("group_name.test", "group_names"),
    ],
)
def test_validation_json_ok(value, format):
    """Verify that each value is of the indicated format."""
    assert (
        js.validate(
            {"key": value},
            schema={"type": "object", "properties": {"key": {"type": "string", "format": format}}},
            format_checker=js.Draft4Validator.FORMAT_CHECKER,
        )
        is None
    )


@pytest.mark.parametrize(
    "value, format",
    [
        ("~test.33alphanumeric:", "alphanumeric"),
        ("cGVwZQ===", "base64"),
        ("AB0264EA00FD9BCDCF1A5B88BC1BDEA4.", "hash"),
        ("../../file_test-33.xml", "names"),
        ("a651403650840", "numbers"),
        ("!/var/wazuh/test", "path"),
        ("test,.&", "search"),
        ("+field&", "sort"),
        ("-field;+field.subfield", "sort"),
        ("7a", "timeframe"),
        ("s1", "timeframe"),
        ("asdfASD0101!", "wazuh_key"),
        ("2019-02-26-test", "date"),
        ("2020-06-24 17:02:53.034374", "date-time"),
        ("group_name.test ", "group_names"),
    ],
)
def test_validation_json_ko(value, format):
    """Verify that each value is not of the indicated format."""
    with pytest.raises(js.ValidationError):
        js.validate(
            {"key": value},
            schema={"type": "object", "properties": {"key": {"type": "string", "format": format}}},
            format_checker=js.Draft4Validator.FORMAT_CHECKER,
        )


@pytest.mark.parametrize(
    "component, configuration, expected_response",
    [("agent", "client", None), ("agent", "labels", WazuhError(1128)), ("agent", "wmodules", WazuhError(1128))]
)
def test_check_component_configuration_pair(component, configuration, expected_response):
    """Verify that `check_component_configuration_pair` function returns an exception when the configuration does
    not belong to a Wazuh component."""
    response = check_component_configuration_pair(component, configuration)
    if isinstance(response, Exception):
        assert isinstance(response, expected_response.__class__)
        assert response.code == expected_response.code
    else:
        assert response is expected_response
