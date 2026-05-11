# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from importlib import reload

from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.tests.utils import init_db

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('api.constants.SECURITY_PATH', new=test_data_path):
                    import wazuh.rbac.decorators as decorator

    init_db('schema_security_test.sql', test_data_path)
    reload(decorator)

    yield decorator


permissions = list()
results = list()
with open(test_data_path + 'RBAC_decorators_permissions_white.json') as f:
    configurations_white = [(config['decorator_params'],
                             config['function_params'],
                             config['rbac'],
                             config['fake_system_resources'],
                             config['allowed_resources'],
                             config.get('result', None),
                             'white') for config in json.load(f)]
with open(test_data_path + 'RBAC_decorators_permissions_black.json') as f:
    configurations_black = [(config['decorator_params'],
                             config['function_params'],
                             config['rbac'],
                             config['fake_system_resources'],
                             config['allowed_resources'],
                             config.get('result', None),
                             'black') for config in json.load(f)]

with open(test_data_path + 'RBAC_decorators_resourceless_white.json') as f:
    configurations_resourceless_white = [(config['decorator_params'],
                                          config['rbac'],
                                          config['allowed'],
                                          'white') for config in json.load(f)]
with open(test_data_path + 'RBAC_decorators_resourceless_black.json') as f:
    configurations_resourceless_black = [(config['decorator_params'],
                                          config['rbac'],
                                          config['allowed'],
                                          'black') for config in json.load(f)]


def get_identifier(resources):
    list_params = list()
    for resource in resources:
        resource = resource.split('&')
        for r in resource:
            try:
                list_params.append(re.search(r'^([a-z*]+:[a-z*]+:)(\*|{(\w+)})$', r).group(3))
            except AttributeError:
                pass

    return list_params


@pytest.mark.parametrize('decorator_params, function_params, rbac, '
                         'fake_system_resources, allowed_resources, result, mode',
                         configurations_black + configurations_white)
def test_expose_resources(db_setup, decorator_params, function_params, rbac, fake_system_resources, allowed_resources,
                          result, mode):
    rbac['rbac_mode'] = mode
    db_setup.rbac.set(rbac)

    def mock_expand_resource(resource):
        fake_values = fake_system_resources.get(resource, resource.split(':')[-1])
        return {fake_values} if isinstance(fake_values, str) else set(fake_values)

    with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
        @db_setup.expose_resources(**decorator_params)
        def framework_dummy(**kwargs):
            for target_param, allowed_resource in zip(get_identifier(decorator_params['resources']), allowed_resources):
                assert set(kwargs[target_param]) == set(allowed_resource)
                assert 'call_func' not in kwargs
                return True

        try:
            output = framework_dummy(**function_params)
            assert (result is None or result == "allow")
            assert output == function_params.get('call_func', True) or isinstance(output, AffectedItemsWazuhResult)
        except WazuhError as e:
            assert (result is None or result == "deny")
            for allowed_resource in allowed_resources:
                assert (len(allowed_resource) == 0)
            assert (e.code == 4000)


@pytest.mark.parametrize('decorator_params, rbac, allowed, mode',
                         configurations_resourceless_white + configurations_resourceless_black)
def test_expose_resourcesless(db_setup, decorator_params, rbac, allowed, mode):
    rbac['rbac_mode'] = mode
    db_setup.rbac.set(rbac)

    def mock_expand_resource(resource):
        return {'*'}

    with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
        @db_setup.expose_resources(**decorator_params)
        def framework_dummy():
            pass

        try:
            framework_dummy()
            assert allowed
        except WazuhError as e:
            assert (not allowed)
            assert (e.code == 4000)


def _conf_payload():
    return {
        "auth": {
            "use_password": "yes",
            "ssl_manager_key": "etc/sslmanager.key"
        },
        "integration": {
            "secret": "topsecret",
            "token": "abcd-1234"
        },
        "authd.pass": "P4ssW0rd!"
    }


def _conf_result_payload():
    r = AffectedItemsWazuhResult(all_msg="ok", some_msg="ok", none_msg="ok")
    r.affected_items.append({
        "auth": {"use_password": "no", "ssl_manager_key": "etc/sslmanager.key"},
        "integration": {"secret": "topsecret"},
        "authd.pass": "P4ssW0rd!"
    })
    r.total_affected_items = 1
    return r


def test_mask_sensitive_config_without_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    result = get_conf()
    assert result["authd.pass"] == "*****"
    assert result["integration"]["secret"] == "topsecret"


def test_mask_sensitive_config_with_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    result = get_conf()
    assert result["authd.pass"] == "P4ssW0rd!"


def test_mask_sensitive_config_on_affected_items_result(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _conf_result_payload()

    res = get_conf_result()
    item = res.affected_items[0]
    assert item["authd.pass"] == "*****"
    assert item["integration"]["secret"] == "topsecret"


# ---------------------------------------------------------------------------
# Tests for _has_update_permissions (the RBAC gate for masking)
# ---------------------------------------------------------------------------

def test_has_update_permissions_no_perms(db_setup):
    """Returns False when RBAC context holds no relevant action."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_with_manager_update_config(db_setup):
    """Returns True when manager:update_config is granted."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})
    assert db_setup._has_update_permissions() is True


def test_has_update_permissions_with_cluster_update_config(db_setup):
    """Returns True when cluster:update_config is granted."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:update_config': {'node:id:master-node': 'allow'}})
    assert db_setup._has_update_permissions() is True


def test_has_update_permissions_read_only_role(db_setup):
    """Returns False for a user that only holds :read — the readonly-role CVE attack vector."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:read': {'*:*': 'allow'}})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_empty_action_dict(db_setup):
    """Returns False when update_config key exists but the resource map is empty."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {}})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_non_dict_action_value(db_setup):
    """Returns False when the action value is not a dict (malformed RBAC token)."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': None})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_none_rbac(db_setup):
    """Returns False gracefully when the RBAC context variable returns None."""
    db_setup.rbac.set(None)
    assert db_setup._has_update_permissions() is False


# ---------------------------------------------------------------------------
# Tests for raw XML masking ( _mask_payload str branch)
# ---------------------------------------------------------------------------

_XML_WITH_CLUSTER_KEY = """\
<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>master-node</node_name>
    <key>SECRETCLUSTERKEY</key>
    <port>1516</port>
  </cluster>
  <global>
    <key>this_should_not_be_masked</key>
  </global>
</ossec_config>"""

_XML_WITHOUT_CLUSTER_KEY = """\
<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>master-node</node_name>
  </cluster>
</ossec_config>"""

_XML_MULTIPLE_CLUSTER_BLOCKS = """\
<ossec_config>
  <cluster>
    <key>FIRSTKEY</key>
  </cluster>
  <cluster>
    <key>SECONDKEY</key>
  </cluster>
</ossec_config>"""

_XML_MULTILINE_KEY = """\
<ossec_config>
  <cluster>
    <key>
      MULTILINE
      SECRET
    </key>
  </cluster>
</ossec_config>"""


# --- mask_sensitive_config with raw XML payload ---

def test_mask_sensitive_config_raw_xml_without_permissions(db_setup):
    """Raw XML cluster key is masked for unprivileged users."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert isinstance(result, str)
    assert "SECRETCLUSTERKEY" not in result
    assert "<key>*****</key>" in result
    # Non-cluster <key> must survive
    assert "this_should_not_be_masked" in result


def test_mask_sensitive_config_raw_xml_with_permissions(db_setup):
    """Raw XML is returned unmodified for users with update-config permissions."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert result == _XML_WITH_CLUSTER_KEY


def test_mask_sensitive_config_raw_xml_cluster_perm(db_setup):
    """cluster:update_config is also accepted as a privileged permission."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert result == _XML_WITH_CLUSTER_KEY


def test_mask_sensitive_config_raw_xml_no_cluster_block(db_setup):
    """XML without a <cluster> block is returned unmodified (no masking needed)."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITHOUT_CLUSTER_KEY

    result = get_conf_raw()
    assert result == _XML_WITHOUT_CLUSTER_KEY


def test_mask_sensitive_config_does_not_raise_on_masking_error(db_setup):
    """If masking raises internally the endpoint must still return a result."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    with patch.object(db_setup, '_mask_payload', side_effect=RuntimeError("boom")):
        @db_setup.mask_sensitive_config()
        def get_conf():
            return _conf_payload()

        # Should NOT raise; the decorator catches the error gracefully.
        result = get_conf()
        assert result is not None
