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
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
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
            "ssl_manager_key": "etc/sslmanager.key",
            "key_request": {"enabled": "no"}
        },
        "integration": [{
            "name": "slack",
            "hook_url": "https://hooks.slack.com/services/T000/B000/XXXX"
        }],
        "authd.pass": "P4ssW0rd!"
    }


def _conf_result_payload():
    r = AffectedItemsWazuhResult(all_msg="ok", some_msg="ok", none_msg="ok")
    r.affected_items.append({
        "auth": {"use_password": "no", "ssl_manager_key": "etc/sslmanager.key"},
        "integration": [{"name": "virustotal", "api_key": "VTAPIKEY"}],
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
    assert result["integration"] == [{"name": "slack", "hook_url": "*****"}]


def test_mask_sensitive_config_with_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    result = get_conf()
    assert result["authd.pass"] == "P4ssW0rd!"
    assert result["integration"][0]["hook_url"] == "https://hooks.slack.com/services/T000/B000/XXXX"


def test_mask_sensitive_config_on_affected_items_result(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _conf_result_payload()

    res = get_conf_result()
    item = res.affected_items[0]
    assert item["authd.pass"] == "*****"
    assert item["integration"] == [{"name": "virustotal", "api_key": "*****"}]


def _agent_conf_wazuh_result_payload():
    """Shape returned by `get_agent_config`: the active configuration under 'data'."""
    return WazuhResult({'data': {
        "name": "wazuh",
        "node_name": "node01",
        "node_type": "master",
        "key": "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH",
        "port": 1516,
        "authd.pass": "P4ssW0rd!"
    }})


def _labels_wazuh_result_payload():
    """Shape returned by `get_agent_config` for the agent/labels pair, where 'key' is a label name."""
    return WazuhResult({'data': {
        "labels": [{"value": "north", "key": "site"}, {"value": "prod", "key": "env"}]
    }})


def test_mask_sensitive_config_on_wazuh_result(db_setup):
    """Sensitive values under 'data' are masked; a WazuhResult is a MutableMapping, not a dict."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _agent_conf_wazuh_result_payload()

    res = get_conf_result()
    assert res['data']["key"] == "*****"
    assert res['data']["authd.pass"] == "*****"
    assert res['data']["node_name"] == "node01"


def test_mask_sensitive_config_on_wazuh_result_with_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _agent_conf_wazuh_result_payload()

    res = get_conf_result()
    assert res['data']["key"] == "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"


def test_mask_sensitive_config_keeps_label_names(db_setup):
    """Label names are members called 'key' that carry no secret and must survive masking."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _labels_wazuh_result_payload()

    res = get_conf_result()
    assert [label["key"] for label in res['data']["labels"]] == ["site", "env"]


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


def test_has_update_permissions_deny_manager_update_config(db_setup):
    """Returns False when manager:update_config has effect=deny."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'deny'}})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_deny_cluster_update_config(db_setup):
    """Returns False when cluster:update_config has effect=deny."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:update_config': {'node:id:master-node': 'deny'}})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_mixed_deny_allow_allows(db_setup):
    """Returns True when at least one resource carries allow, even if others carry deny."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'manager:update_config': {
            'node:id:worker-1': 'deny',
            'node:id:master': 'allow'
        }
    })
    assert db_setup._has_update_permissions() is True


def test_has_update_permissions_all_deny(db_setup):
    """Returns False when all resources carry deny."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'manager:update_config': {
            'node:id:worker-1': 'deny',
            'node:id:worker-2': 'deny'
        }
    })
    assert db_setup._has_update_permissions() is False


def test_mask_sensitive_config_raw_xml_with_deny_rule(db_setup):
    """Verifies that cluster.key is masked when user has manager:update_config deny rule."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'manager:read': {'*:*': 'allow'},
        'manager:update_config': {'*:*': 'deny'}
    })

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result
    assert "<key>*****</key>" in result


def test_mask_sensitive_config_raw_xml_with_cluster_deny_rule(db_setup):
    """Verifies that cluster.key is masked when user has cluster:update_config deny rule."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'cluster:read': {'*:*': 'allow'},
        'cluster:update_config': {'node:id:master-node': 'deny'}
    })

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result
    assert "<key>*****</key>" in result


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


_CREDENTIAL_JSON = {"wmodules": [
    {"aws-s3": {"buckets": [{"access_key": "S", "secret_key": "S", "aws_profile": "default"},
                            {"access_key": "S", "secret_key": "S"}]}},
    {"azure-logs": {"content": [{"application_id": "id", "application_key": "S"}, {"account_key": "S"}]}},
    {"office365": {"api_auth": [{"client_id": "id", "client_secret": "S"}]}},
    {"github": {"api_auth": [{"org_name": "org", "api_token": "S"}]}},
    {"ms-graph": {"api_auth": {"client_id": "id", "secret_value": "S"}}},
    {"fluent-forward": {"shared_key": "S", "user": "user", "password": "S"}},
    {"integration": [{"name": "slack", "hook_url": "S", "api_key": "S"}]},
    {"cluster": {"haproxy_helper": {"haproxy_user": "user", "haproxy_password": "S",
                                    "client_cert_password": "S"}}}
]}

_XML_WITH_CREDENTIALS = """\
<ossec_config>
  <wodle name="aws-s3">
    <bucket type="cloudtrail">
      <aws_profile>default</aws_profile>
      <access_key>S</access_key>
      <secret_key>S</secret_key>
    </bucket>
    <bucket type="guardduty">
      <access_key>S</access_key>
      <secret_key>S</secret_key>
    </bucket>
  </wodle>
  <wodle name="azure-logs">
    <log_analytics><application_key>S</application_key></log_analytics>
    <storage><account_key>S</account_key></storage>
  </wodle>
  <office365><api_auth><client_secret>S</client_secret></api_auth></office365>
  <github><api_auth><org_name>org</org_name><api_token>S</api_token></api_auth></github>
  <ms-graph><api_auth><secret_value>S</secret_value></api_auth></ms-graph>
  <fluent-forward><shared_key>S</shared_key><user>user</user><password>S</password></fluent-forward>
  <integration><name>slack</name><hook_url>S</hook_url><api_key>S</api_key></integration>
  <cluster><haproxy_helper><haproxy_password>S</haproxy_password>
    <client_cert_password>S</client_cert_password></haproxy_helper></cluster>
</ossec_config>"""


@pytest.mark.parametrize('payload', [
    pytest.param(lambda: json.loads(json.dumps(_CREDENTIAL_JSON)), id='json'),
    pytest.param(lambda: WazuhResult({'data': json.loads(json.dumps(_CREDENTIAL_JSON))}), id='wazuh_result'),
    pytest.param(lambda: _XML_WITH_CREDENTIALS, id='raw_xml'),
])
def test_mask_sensitive_config_masks_credential_fields(db_setup, payload):
    """Every credential field is masked wherever each module nests it; its siblings survive."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:read': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return payload()

    result = get_conf()
    text = result if isinstance(result, str) else json.dumps(result.render() if isinstance(result, WazuhResult)
                                                             else result)
    assert '"S"' not in text and '>S<' not in text
    for name in db_setup.SENSITIVE_FIELD_NAMES:
        assert f'"{name}"' in text or f'<{name}>' in text
    for name, value in (('aws_profile', 'default'), ('name', 'slack'), ('org_name', 'org'), ('user', 'user')):
        assert f'"{name}": "{value}"' in text or f'<{name}>{value}</{name}>' in text


_GROUP_UPDATE = {'update_actions': ['group:update_config'], 'update_resources': ['group:id:{group_list}']}


@pytest.mark.parametrize('group_perms, group_list, expected', [
    ({'group:update_config': {'group:id:A': 'allow'}}, ['A'], True),
    ({'group:update_config': {'group:id:A': 'allow'}}, ['B'], False),
    ({'group:update_config': {'group:id:*': 'allow'}}, ['B'], True),
    ({'group:update_config': {'group:id:*': 'allow', 'group:id:B': 'deny'}}, ['B'], False),
    ({'manager:update_config': {'*:*:*': 'allow'}, 'cluster:update_config': {'node:id:*': 'allow'}}, ['A'], False),
    ({'group:update_config': {'group:id:A': 'allow'}}, None, False),
    ({'group:update_config': {'group:id:A': 'allow'}}, [], False),
])
def test_has_update_permissions_per_resource(db_setup, group_perms, group_list, expected):
    """With update_actions, the user must hold them on every requested resource, not on any resource."""
    db_setup.rbac.set({'rbac_mode': 'white', **group_perms})
    with patch.object(db_setup, 'get_groups', return_value={'A', 'B'}):
        assert db_setup._has_update_permissions(**_GROUP_UPDATE, group_list=group_list) is expected


@pytest.mark.parametrize('data', [
    pytest.param(lambda: _XML_WITH_CREDENTIALS, id='raw'),
    pytest.param(lambda: [{'file_name': 'agent.conf', 'file_size': 1, 'file_content': _XML_WITH_CREDENTIALS}],
                 id='merged_mg_json'),
])
@pytest.mark.parametrize('group_perms, masked', [
    ({'group:read': {'group:id:*': 'allow'}}, True),
    ({'group:update_config': {'group:id:default': 'allow'}}, False),
])
def test_mask_sensitive_config_group_file(db_setup, group_perms, masked, data):
    """A group file under 'data', raw or packed in merged.mg, is masked unless the user can update that group."""
    db_setup.rbac.set({'rbac_mode': 'white', **group_perms})

    @db_setup.mask_sensitive_config(**_GROUP_UPDATE)
    def get_file_conf(group_list=None):
        return WazuhResult({'data': data()})

    result = get_file_conf(group_list=['default'])
    text = result['data'] if isinstance(result['data'], str) else result['data'][0]['file_content']
    assert ('>S<' not in text) is masked
    assert '<aws_profile>default</aws_profile>' in text


def test_has_update_permissions_without_resources(db_setup):
    """update_actions with no resource to check never lifts the mask."""
    db_setup.rbac.set({'rbac_mode': 'white', 'group:update_config': {'group:id:A': 'allow'}})
    assert db_setup._has_update_permissions(['group:update_config'], [], group_list=['A']) is False


def test_mask_sensitive_config_raw_xml_escaped_less_than(db_setup):
    """A value holding the '\\<' escape accepted by os_xml is masked whole."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return '<ossec_config><fluent-forward><password>ab\\<cd</password></fluent-forward></ossec_config>'

    assert get_conf_raw() == '<ossec_config><fluent-forward><password>*****</password></fluent-forward></ossec_config>'


@pytest.mark.parametrize('disabled, perms, expected', [
    (True, {}, True),
    (True, {'manager:update_config': {'*:*:*': 'deny'}}, False),
    (True, {'cluster:update_config': {'node:id:*': 'deny'}}, True),
    (False, {}, True),
    (False, {'cluster:update_config': {'node:id:*': 'deny'}}, False),
    (False, {'cluster:update_config': {'node:id:master-node': 'deny'}}, False),
    (False, {'cluster:update_config': {'node:id:worker1': 'deny'}}, True),
    (False, {'manager:update_config': {'*:*:*': 'deny'}}, True),
])
def test_has_update_permissions_black_mode(db_setup, disabled, perms, expected):
    """In black mode the mask follows the permission update_ossec_conf checks, granted unless a policy denies it."""
    db_setup.rbac.set({'rbac_mode': 'black', **perms})
    with patch.object(db_setup, 'read_config', return_value={'disabled': disabled, 'node_name': 'master-node'}):
        assert db_setup._has_update_permissions() is expected


def test_mask_sensitive_config_raw_xml_black_mode_without_deny(db_setup):
    """A black mode user that may update the configuration reads it unmasked, so saving it back keeps the values."""
    db_setup.rbac.set({'rbac_mode': 'black'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CREDENTIALS

    with patch.object(db_setup, 'read_config', return_value={'disabled': True, 'node_name': 'node01'}):
        assert get_conf_raw() == _XML_WITH_CREDENTIALS

