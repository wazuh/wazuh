#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import jsonschema as js
import os
import pytest

from api.validator import check_cdb_list, check_exp, check_xml, format_etc_path, _alphanumeric_param, \
    _array_numbers, _array_names, _base64, _boolean, _cdb_list, _dates, _empty_boolean, _hashes,\
    _ips, _names, _numbers, _wazuh_key, _paths, _query_param, _ranges, _etc_path, _search_param,\
    _sort_param, _timeframe_type, _type_format, _yes_no_boolean


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.mark.parametrize('exp, regex_name', [
    # numbers
    ('43,21,34', _array_numbers),
    ('20190226', _dates),
    ('54355', _numbers),
    # names
    ('alphanumeric1_param2', _alphanumeric_param),
    ('file_1,file_2,file-3', _array_names),
    ('file-test_name1', _names),
    # IPs
    ('192.168.122.255', _ips),
    ('any', _ips),
    # hashes
    ('e4d909c290d0fb1ca068ffaddf22cbd0', _hashes),
    ('449e3b6ffd9b484c5c645321edd4d610', _wazuh_key),
    # time
    ('1d', _timeframe_type),
    ('12h', _timeframe_type),
    ('40m', _timeframe_type),
    ('60s', _timeframe_type),
    # boolean
    ('true', _boolean),
    ('false', _boolean),
    ('', _empty_boolean),
    ('true', _empty_boolean),
    ('false', _empty_boolean),
    ('yes', _yes_no_boolean),
    ('no', _yes_no_boolean),
    # query parameters
    ('field1=3;field2!=4', _query_param),
    ('sort param-', _sort_param),
    ('search param3', _search_param),
    # ranges
    ('5-35', _ranges),
    # format
    ('xml', _type_format),
    ('json', _type_format),
    # paths
    ('/var/ossec/etc/internal_options', _paths),
    ('/var/ossec/etc/rules/local_rules.xml', _paths),
    # relative paths
    ('etc/ossec.conf', _etc_path),
    ('etc/rules/new_rules2.xml', _etc_path),
    ('etc/lists/new_lists3', _etc_path)
])
def test_validation_check_exp_ok(exp, regex_name):
    assert check_exp(exp, regex_name)


@pytest.mark.parametrize('exp, regex_name', [
    # numbers
    ('43a,21,34', _array_numbers),
    ('2019-02-26', _dates),
    ('543a', _numbers),
    # names
    ('alphanumeric1_$param2', _alphanumeric_param),
    ('file-$', 'names'),
    ('file_1$,file_2#,file-3', _array_names),
    # IPs
    ('192.168.122.256', _ips),
    ('192.266.1.1', _ips),
    # query parameters
    ('sort param@', _sort_param),
    ('search param;', _search_param),
    # hashes
    ('$$d909c290d0fb1ca068ffaddf22cbd0', _hashes),
    ('449e3b6ffd9b484c5c645321edd4d61$', _wazuh_key),
    # time
    ('1j', _timeframe_type),
    ('12x', _timeframe_type),
    # boolean
    ('correct', _boolean),
    ('wrong', _boolean),
    ('yes', _empty_boolean),
    ('truee', _empty_boolean),
    ('true', _yes_no_boolean),
    ('false', _yes_no_boolean),
    # ranges
    ('5-35-32', _ranges),
    ('param1,param2,param3', _query_param),
    # format
    ('txt', _type_format),
    ('exe', _type_format),
    # paths
    ('/var/ossec/etc/internal_options$', _paths),
    ('/var/ossec/etc/rules/local_rules.xml()', _paths),
    # relative paths
    ('etc/internal_options', _etc_path),
    ('../../path', _etc_path),
    ('/var/ossec/etc/lists/new_lists3', _etc_path),
    ('../ossec', _etc_path),
    ('etc/rules/../../../dir', _etc_path)
])
def test_validation_check_exp_ko(exp, regex_name):
    assert not check_exp(exp, regex_name)


@pytest.mark.parametrize('relative_path', [
    ('etc/rules/new_rule.xml'),
    ('etc/decoders/new_decoder.xml'),
    ('etc/lists/new_list'),
    ('etc/ossec.conf')
])
def test_validation_paths_ok(relative_path):
    assert format_etc_path(relative_path)


@pytest.mark.parametrize('relative_path', [
    ('etc/rules/new_rule'),
    ('../../bin'),
    ('etc/decoders/decoder'),
    ('etc/internal_options')
])
def test_validation_paths_ko(relative_path):
    assert not format_etc_path(relative_path)


@pytest.mark.parametrize('cdb_list', [
    ('audit-wazuh-w:write \n audit-wazuh-r:read \n audit-wazuh-a:attribute \n'
     'audit-wazuh-x:execute \n audit-wazuh-c:command')
])
def test_validation_cdb_list_ok(cdb_list):
    assert check_cdb_list(cdb_list)


@pytest.mark.parametrize('cdb_list', [
    (':write \n audit-wazuh-r:read \n audit-wazuh-a:attribute'),
    ('audit-wazuh:write \n $variable:read \n audit-wazuh-a:attribute')
])
def test_validation_cdb_list_ko(cdb_list):
    assert not check_cdb_list(cdb_list)


@pytest.mark.parametrize('xml_file', [
    (os.path.join(test_data_path, 'test_xml_1.xml')),
    (os.path.join(test_data_path, 'test_xml_2.xml'))
])
def test_validation_xml_ok(xml_file):
    with open(xml_file) as f:
        xml_content = f.read()
    assert check_xml(xml_content)


@pytest.mark.parametrize('xml_file', [
    (os.path.join(test_data_path, 'test_xml_ko_1.xml')),
    (os.path.join(test_data_path, 'test_xml_ko_2.xml'))
])
def test_validation_xml_ko(xml_file):
    with open(xml_file) as f:
        xml_content = f.read()
    assert not check_xml(xml_content)


@pytest.mark.parametrize('value, format', [
    ("test.33alphanumeric:", "alphanumeric"),
    ("cGVwZQ==", "base64"),
    ("etc/lists/list.csv", "etc_path"),
    ("etc/decoders/dec35.xml", "etc_path"),
    ("etc/decoders/test/dec35.xml", "etc_path"),
    ("AB0264EA00FD9BCDCF1A5B88BC1BDEA4", "hash"),
    ("file_test-33.xml", "names"),
    ("651403650840", "numbers"),
    ("/var/wazuh/test", "path"),
    ("field=0", "query"),
    ("field=0,field2!=3;field3~hi", "query"),
    ("34", "range"),
    ("34-36", "range"),
    ("test,.", "search"),
    ("+field", "sort"),
    ("-field,+field.subfield", "sort"),
    ("7d", "timeframe"),
    ("1s", "timeframe"),
    ("7m", "timeframe"),
    ("asdfASD0101", "wazuh_key")
])
def test_validation_json_ok(value, format):
    assert(js.validate({"key": value},
                       schema={'type': 'object', 'properties': {'key': {'type': 'string', 'format': format}}},
                       format_checker=js.draft4_format_checker) is None)


@pytest.mark.parametrize('value, format', [
    ("~test.33alphanumeric:", "alphanumeric"),
    ("cGVwZQ===", "base64"),
    ("etc/../lists/list.csv", "etc_path"),
    ("/etc/decoders/dec35.xml", "etc_path"),
    ("AB0264EA00FD9BCDCF1A5B88BC1BDEA4.", "hash"),
    ("../../file_test-33.xml", "names"),
    ("a651403650840", "numbers"),
    ("!/var/wazuh/test", "path"),
    #("field=0", "query"),
    ("34-", "range"),
    ("34-36-9", "range"),
    ("test,.&", "search"),
    ("+field&", "sort"),
    ("-field;+field.subfield", "sort"),
    ("7a", "timeframe"),
    ("s1", "timeframe"),
    ("asdfASD0101!", "wazuh_key")
])
def test_validation_json_ko(value, format):
    with pytest.raises(js.ValidationError):
        js.validate({"key": value},
                    schema={'type': 'object',
                            'properties': {'key': {'type': 'string', 'format': format}}},
                    format_checker=js.draft4_format_checker)
