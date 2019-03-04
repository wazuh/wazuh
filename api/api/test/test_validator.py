#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from api import validator


@pytest.mark.parametrize('exp, regex_name', [
    ('54355', 'numbers'),
    ('43,21,34', 'array_numbers'),
    ('file-test_name1', 'names'),
    ('file_1,file_2,file-3', 'array_names'),
    ('/var/ossec/etc/internal_options', 'paths'),
    ('/var/ossec/etc/rules/local_rules.xml', 'paths'),
    ('20190226', 'dates'),
    ('192.168.122.255', 'ips'),
    ('any', 'ips'),
    ('alphanumeric1_param2', 'alphanumeric_param'),
    ('sort param-', 'sort_param'),
    ('search param3', 'search_param'),
    ('select_param2', 'select_param'),
    ('5-35', 'ranges'),
    ('e4d909c290d0fb1ca068ffaddf22cbd0', 'hashes'),
    ('449e3b6ffd9b484c5c645321edd4d610', 'ossec_key'),
    ('1d', 'timeframe_type'),
    ('12h', 'timeframe_type'),
    ('40m', 'timeframe_type'),
    ('60s', 'timeframe_type'),
    ('', 'empty_boolean'),
    ('true', 'empty_boolean'),
    ('false', 'empty_boolean'),
    ('yes', 'yes_no_boolean'),
    ('no', 'yes_no_boolean'),
    ('true', 'boolean'),
    ('false', 'boolean'),
    ('param1 param2 param3', 'query_param'),
    ('xml', 'type_format'),
    ('json', 'type_format'),
    ('etc/ossec.conf', 'relative_paths'),
    ('etc/rules/new_rules2.xml', 'relative_paths'),
    ('etc/lists/new_lists3', 'relative_paths')
])
def test_validation_check_exp_ok(exp, regex_name):
    assert validator.check_exp(exp, regex_name)


@pytest.mark.parametrize('exp, regex_name', [
    ('543a', 'numbers'),
    ('43a,21,34', 'array_numbers'),
    ('file-$', 'names'),
    ('file_1$,file_2#,file-3', 'array_names'),
    ('/var/ossec/etc/internal_options$', 'paths'),
    ('/var/ossec/etc/rules/local_rules.xml()', 'paths'),
    ('2019-02-26', 'dates'),
    ('192.168.122.256', 'ips'),
    ('192.266.1.1', 'ips'),
    ('alphanumeric1_$param2', 'alphanumeric_param'),
    ('sort param@', 'sort_param'),
    ('search param;', 'search_param'),
    ('select_param2;', 'select_param'),
    ('5-35-32', 'ranges'),
    ('$$d909c290d0fb1ca068ffaddf22cbd0', 'hashes'),
    ('449e3b6ffd9b484c5c645321edd4d61$', 'ossec_key'),
    ('1j', 'timeframe_type'),
    ('12x', 'timeframe_type'),
    ('yes', 'empty_boolean'),
    ('truee', 'empty_boolean'),
    ('true', 'yes_no_boolean'),
    ('false', 'yes_no_boolean'),
    ('correct', 'boolean'),
    ('wrong', 'boolean'),
    ('param1,param2,param3', 'query_param'),
    ('txt', 'type_format'),
    ('exe', 'type_format'),
    ('etc/internal_options', 'relative_paths'),
    ('../../path', 'relative_paths'),
    ('/var/ossec/etc/lists/new_lists3', 'relative_paths')
])
def test_validation_check_exp_ko(exp, regex_name):
    assert not validator.check_exp(exp, regex_name)


@pytest.mark.parametrize('relative_path', [
    ('etc/rules/new_rule.xml'),
    ('etc/decoders/new_decoder.xml'),
    ('etc/lists/new_list'),
    ('etc/ossec.conf')
])
def test_validation_paths_ok(relative_path):
    assert validator.check_path(relative_path)


@pytest.mark.parametrize('relative_path', [
    ('etc/rules/new_rule'),
    ('../../bin'),
    ('etc/decoders/decoder'),
    ('etc/internal_options')
])
def test_validation_paths_ko(relative_path):
    assert not validator.check_path(relative_path)


@pytest.mark.parametrize('parameters, filters', [
    ({'path': 'etc/rules/rule.xml', 'offset': '32', 'format': 'xml'},
     {'path': 'paths', 'offset': 'numbers', 'limit': 'numbers', 'format': 'type_format'}),
    ({'offset': '2', 'limit': '3', 'sort': '-agent_id'},
     {'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param'}),
    ({'ip': '192.168.122.15', 'os.name': 'CentOS Linux', 'os.version': '7.1'},
     {'ip': 'ips', 'os.name': 'alphanumeric_param', 'os.version': 'alphanumeric_param'}),
    ({'use_http': 'true', 'force': '1', 'agent_id': '004'},
     {'use_http': 'boolean', 'force': 'numbers', 'agent_id': 'numbers'})
])
def test_validation_check_parms_ok(parameters, filters):
    assert validator.check_params(parameters, filters)


@pytest.mark.parametrize('parameters, filters', [
    ({'path': 'etc/internal_options', 'offset': '32', 'format': 'xml'},
     {'path': 'relative_paths', 'offset': 'numbers', 'limit': 'numbers', 'format': 'type_format'}),
    ({'offset': '2', 'limit': '3', 'sort': '-agent_id', 'path': 'etc/rules/local_rules.xml'},
     {'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param'}),
    ({'ip': '192.168.122.345', 'os.name': 'CentOS Linux', 'os.version': '7.1'},
     {'ip': 'ips', 'os.name': 'alphanumeric_param', 'os.version': 'alphanumeric_param'}),
    ({'use_http': 'true', 'force': '1', 'agent_id': '004'},
     {'use_http': 'boolean', 'force': 'numbers'})
])
def test_validation_check_parms_ko(parameters, filters):
    assert not validator.check_params(parameters, filters)


@pytest.mark.parametrize('cdb_list', [
    ('audit-wazuh-w:write \n audit-wazuh-r:read \n audit-wazuh-a:attribute \n'
     'audit-wazuh-x:execute \n audit-wazuh-c:command')
])
def test_validation_cdb_list_ok(cdb_list):
    assert validator.check_cdb_list(cdb_list)


@pytest.mark.parametrize('cdb_list', [
    (':write \n audit-wazuh-r:read \n audit-wazuh-a:attribute'),
    ('audit-wazuh:write \n $variable:read \n audit-wazuh-a:attribute')
])
def test_validation_cdb_list_ko(cdb_list):
    assert not validator.check_cdb_list(cdb_list)


@pytest.mark.parametrize('xml_file', [
    (os.path.join(os.getcwd(), 'test/data/test_xml_1.xml')),
    (os.path.join(os.getcwd(), 'test/data/test_xml_2.xml'))
])
def test_validation_xml_ok(xml_file):
    with open(xml_file) as f:
        xml_content = f.readlines()
    assert validator.check_xml(xml_content)


@pytest.mark.parametrize('xml_file', [
    (os.path.join(os.getcwd(), 'test/data/test_xml_ko_1.xml')),
    (os.path.join(os.getcwd(), 'test/data/test_xml_ko_2.xml'))
])
def test_validation_xml_ko(xml_file):
    with open(xml_file) as f:
        xml_content = f.readlines()
    assert not validator.check_xml(xml_content)
