# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
import time
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from importlib import reload

from wazuh.core.exception import WazuhError, WazuhInternalError
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
    # The secrets gate resolves the node it serves from the cluster configuration. Pin it here:
    # what these tests are about is which node a permission was granted on, not where they run.
    decorator._node_id = 'master-node'

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
            "ssl_manager_key": "etc/certs/remoted-key.pem"
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
        "auth": {"use_password": "no", "ssl_manager_key": "etc/certs/remoted-key.pem"},
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


@pytest.mark.parametrize('wrap', [False, True])
def test_mask_sensitive_config_haproxy_helper_passwords(db_setup, wrap):
    """HAProxy helper passwords are masked with and without the "cluster" wrapper."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    helper = {"haproxy_password": "HAPROXYSECRET", "client_cert_password": "CERTSECRET", "port": 5555}

    @db_setup.mask_sensitive_config()
    def get_conf():
        return {"cluster": {"haproxy_helper": helper}} if wrap else {"haproxy_helper": helper}

    result = get_conf()
    result = result["cluster"]["haproxy_helper"] if wrap else result["haproxy_helper"]
    assert result["haproxy_password"] == "*****"
    assert result["client_cert_password"] == "*****"
    assert result["port"] == 5555


def test_mask_sensitive_config_raw_xml_haproxy_helper_password_with_escaped_lt(db_setup):
    """A backslash-escaped '<' is part of the value, so the whole password is masked."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    xml = (
        "<ossec_config><cluster><haproxy_helper><haproxy_password>Xy7\\<%kLTAIL</haproxy_password>"
        "</haproxy_helper></cluster></ossec_config>"
    )

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml

    result = get_conf_raw()
    assert "Xy7" not in result and "TAIL" not in result
    assert "<haproxy_password>*****</haproxy_password>" in result


def test_mask_sensitive_config_raw_xml_haproxy_helper_password_ending_in_backslash(db_setup):
    """A value ending in a backslash right before the closing tag is still masked."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    xml = (
        "<ossec_config><cluster><haproxy_helper><haproxy_password>Xy7\\</haproxy_password>"
        "</haproxy_helper></cluster></ossec_config>"
    )

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml

    result = get_conf_raw()
    assert "Xy7" not in result
    assert "<haproxy_password>*****</haproxy_password>" in result


def test_mask_sensitive_config_raw_xml_haproxy_helper_passwords(db_setup):
    """HAProxy helper passwords are masked in raw XML for unprivileged users."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    xml = (
        "<ossec_config><cluster><haproxy_helper><haproxy_password>HAPROXYSECRET</haproxy_password>"
        "<client_cert_password>CERTSECRET</client_cert_password></haproxy_helper></cluster></ossec_config>"
    )

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml

    result = get_conf_raw()
    assert "HAPROXYSECRET" not in result and "CERTSECRET" not in result
    assert "<haproxy_password>*****</haproxy_password>" in result


def test_mask_sensitive_config_with_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:master-node': 'allow'}})

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
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:master-node': 'allow'}})

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
# Tests for can_read_secrets (the RBAC gate for masking: an action of its own, over ONE node)
# ---------------------------------------------------------------------------

def test_can_read_secrets_no_perms(db_setup):
    """Returns False when RBAC context holds no relevant action."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    assert db_setup.can_read_secrets() is False


def test_can_read_secrets_on_the_served_node(db_setup):
    """Returns True when cluster:read_secrets is granted over the node being served."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:master-node': 'allow'}})
    assert db_setup.can_read_secrets() is True


def test_can_read_secrets_on_another_node(db_setup):
    """Returns False when the grant is over a DIFFERENT node.

    These endpoints run on the node they answer for -- the two node-configuration ones inside the
    target worker's clusterd -- so an allow scoped to the master must not uncover a worker's
    secrets, however many nodes the caller can otherwise reach.
    """
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:worker1': 'allow'}})
    assert db_setup.can_read_secrets() is False


def test_can_read_secrets_on_every_node(db_setup):
    """Returns True for the shipped `secrets_read` policy, which grants it over node:id:*."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:*': 'allow'}})
    assert db_setup.can_read_secrets() is True


def test_can_read_secrets_denied_on_the_served_node(db_setup):
    """A deny over the served node wins over an allow on every node, as everywhere else in RBAC."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'cluster:read_secrets': {
            'node:id:*': 'allow',
            'node:id:master-node': 'deny'
        }
    })
    assert db_setup.can_read_secrets() is False


def test_can_read_secrets_denied_on_another_node(db_setup):
    """A deny over a different node leaves the served one alone."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'cluster:read_secrets': {
            'node:id:*': 'allow',
            'node:id:worker1': 'deny'
        }
    })
    assert db_setup.can_read_secrets() is True


def test_can_read_secrets_black_mode_without_the_action(db_setup):
    """`black` means everything not denied is allowed, and this gate is no exception."""
    db_setup.rbac.set({'rbac_mode': 'black'})
    assert db_setup.can_read_secrets() is True


def test_can_read_secrets_black_mode_with_a_deny(db_setup):
    """...and a deny over the served node still masks in black mode."""
    db_setup.rbac.set({'rbac_mode': 'black', 'cluster:read_secrets': {'node:id:master-node': 'deny'}})
    assert db_setup.can_read_secrets() is False


def test_can_read_secrets_manager_action_is_not_a_key(db_setup):
    """`manager:read_secrets` is in no catalog and no policy: it no longer lifts the mask."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:read_secrets': {'node:id:master-node': 'allow'}})
    assert db_setup.can_read_secrets() is False


def test_can_read_secrets_read_only_role(db_setup):
    """Returns False for a user that only holds :read -- the readonly-role CVE attack vector."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:read': {'*:*:*': 'allow'}})
    assert db_setup.can_read_secrets() is False


def test_can_read_secrets_empty_action_dict(db_setup):
    """Returns False when the action key exists but the resource map is empty."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {}})
    assert db_setup.can_read_secrets() is False


def test_can_read_secrets_non_dict_action_value(db_setup):
    """Returns False when the action value is not a dict (malformed RBAC token)."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': None})
    assert db_setup.can_read_secrets() is False


def test_can_read_secrets_none_rbac(db_setup):
    """Returns False gracefully when the RBAC context variable returns None."""
    db_setup.rbac.set(None)
    assert db_setup.can_read_secrets() is False


def test_can_read_secrets_masks_when_the_node_cannot_be_resolved(db_setup):
    """No node to check the permission against means no permission: the values stay masked."""
    db_setup._node_id = None
    db_setup.rbac.set({'rbac_mode': 'black'})

    with patch('wazuh.core.cluster.cluster.get_node', side_effect=WazuhError(3006)):
        assert db_setup.can_read_secrets() is False


def test_local_node_id_is_read_once_from_the_cluster_configuration(db_setup):
    """The node is the one this process serves, resolved lazily and cached."""
    db_setup._node_id = None

    with patch('wazuh.core.cluster.cluster.get_node', return_value={'node': 'worker1'}) as get_node:
        assert db_setup._local_node_id() == 'worker1'
        assert db_setup._local_node_id() == 'worker1'

    get_node.assert_called_once()


# ---------------------------------------------------------------------------
# Tests for _audit_logger (the audit line has to be written by whoever is running)
# ---------------------------------------------------------------------------

def test_audit_logger_is_the_api_one_when_it_is_configured(db_setup):
    """In the API process 'wazuh-api' has handlers and the line belongs next to the request line."""
    with patch.object(db_setup.logger, 'hasHandlers', return_value=True):
        assert db_setup._audit_logger() is db_setup.logger


def test_audit_logger_falls_back_where_the_api_logger_is_unconfigured(db_setup):
    """A forwarded read runs in wazuh-manager-clusterd, which only configures 'wazuh'.

    Without the fallback the record is dropped before reaching a file and the disclosure that
    matters most -- the one on another node -- is the one that leaves no trace.
    """
    with patch.object(db_setup.logger, 'hasHandlers', return_value=False):
        assert db_setup._audit_logger() is db_setup.framework_logger


def test_secret_read_is_audited_through_the_fallback_logger(db_setup):
    """The line is written whichever process served it."""
    db_setup.current_user.set('auditor')
    audit = MagicMock()

    with patch.object(db_setup.logger, 'hasHandlers', return_value=False), \
            patch.object(db_setup, 'framework_logger', audit):
        db_setup._audit_secret_read(_conf_payload())

    audit.info.assert_called_once()
    assert 'secret_read' in audit.info.call_args[0][0]


def test_agent_keys_read_is_audited(db_setup):
    """The key endpoint answers with the secret itself, so it records its own disclosure."""
    db_setup.current_user.set('auditor')
    audit = MagicMock()

    with patch.object(db_setup.logger, 'hasHandlers', return_value=False), \
            patch.object(db_setup, 'framework_logger', audit):
        db_setup.audit_agent_keys_read(['001', '003'])

    audit.info.assert_called_once()
    line = audit.info.call_args[0][0]
    assert 'secret_read' in line and "user='auditor'" in line and 'agent.key (001, 003)' in line


def test_no_agent_key_served_is_not_audited(db_setup):
    """A denied or empty read discloses nothing, so it must not leave a disclosure line."""
    audit = MagicMock()

    with patch.object(db_setup.logger, 'hasHandlers', return_value=False), \
            patch.object(db_setup, 'framework_logger', audit):
        db_setup.audit_agent_keys_read([])

    audit.info.assert_not_called()


def test_mask_sensitive_config_raw_xml_with_deny_rule(db_setup):
    """Verifies that cluster.key is masked when the read-secrets action is denied."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'manager:read': {'*:*:*': 'allow'},
        'cluster:read_secrets': {'node:id:*': 'deny'}
    })

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result
    assert "<key>*****</key>" in result


def test_mask_sensitive_config_raw_xml_with_cluster_deny_rule(db_setup):
    """Verifies that cluster.key is masked when user has cluster:read_secrets deny rule."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'cluster:read': {'*:*': 'allow'},
        'cluster:read_secrets': {'node:id:master-node': 'deny'}
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
    """Raw XML is returned unmodified for users holding the read-secrets action."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:master-node': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert result == _XML_WITH_CLUSTER_KEY


def test_mask_sensitive_config_raw_xml_cluster_perm(db_setup):
    """The wildcard grant of the shipped policy also lifts the mask."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:*': 'allow'}})

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


def test_mask_sensitive_config_fails_closed_on_masking_error(db_setup):
    """If masking raises internally the request fails; the unmasked payload is never returned.

    This used to be the opposite: the decorator swallowed the error and handed the caller the
    payload it had failed to mask, which is the one outcome the masking exists to prevent.
    """
    db_setup.rbac.set({'rbac_mode': 'white'})

    with patch.object(db_setup, '_mask_payload', side_effect=RuntimeError("boom")):
        @db_setup.mask_sensitive_config()
        def get_conf():
            return _conf_payload()

        with pytest.raises(WazuhInternalError, match='.*1000.*'):
            get_conf()


def test_update_config_no_longer_lifts_the_mask(db_setup):
    """Being allowed to WRITE the configuration is no longer a way to read the secrets in it."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*:*': 'allow'},
                       'cluster:update_config': {'node:id:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    assert get_conf()["authd.pass"] == "*****"


def test_secret_read_is_audited_with_the_user_and_never_the_value(db_setup):
    """Serving a secret in clear leaves a line naming who read what, and not what it was."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:master-node': 'allow'}})
    db_setup.current_user.set('auditor')

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    with patch.object(db_setup.logger, 'info') as mock_info:
        result = get_conf()

    assert result["authd.pass"] == "P4ssW0rd!"
    mock_info.assert_called_once()
    line = mock_info.call_args[0][0]
    assert 'secret_read' in line and "user='auditor'" in line and 'authd.pass' in line
    assert 'P4ssW0rd!' not in line


def test_no_audit_line_when_nothing_sensitive_was_served(db_setup):
    """The action alone is not a disclosure: a payload without secrets is not audited."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:master-node': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return {"auth": {"use_password": "no"}}

    with patch.object(db_setup.logger, 'info') as mock_info:
        get_conf()

    mock_info.assert_not_called()


def test_no_audit_line_when_the_payload_was_masked(db_setup):
    """A caller without the action gets the mask and leaves no secret_read behind."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    with patch.object(db_setup.logger, 'info') as mock_info:
        assert get_conf()["authd.pass"] == "*****"

    mock_info.assert_not_called()


def test_secret_read_is_audited_on_raw_xml_and_on_affected_items(db_setup):
    """The detector follows the same shapes the masking does: strings and AffectedItemsWazuhResult."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:master-node': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_result():
        return _conf_result_payload()

    with patch.object(db_setup.logger, 'info') as mock_info:
        assert get_result().affected_items[0]["authd.pass"] == "P4ssW0rd!"

    assert 'secret_read' in mock_info.call_args[0][0]


def test_secret_read_is_audited_for_the_bare_cluster_key(db_setup):
    """`GET /cluster/local/config` answers a flat object whose `key` is the cluster key.

    That member is masked by a rule of its own, not by a dotted path, so the audit has to know about
    it too: without this the one endpoint that always carries a secret was the one never recorded.
    """
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:read_secrets': {'node:id:master-node': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_cluster_conf():
        return {"name": "wazuh", "node_name": "master", "key": "264ae8ec9f19"}

    with patch.object(db_setup.logger, 'info') as mock_info:
        result = get_cluster_conf()

    assert result["key"] == "264ae8ec9f19"
    line = mock_info.call_args[0][0]
    assert 'secret_read' in line and 'cluster.key' in line and '264ae8ec9f19' not in line


# Tests for unmask_xml_by_path (the write-side twin of the masking)

_UNMASK_KEY = 'c98b62a9b6169ac5f67dae55ae4a9088'
_UNMASK_XML = ("<wazuh_config>\n  <indexer>\n    <ssl>\n      <key>etc/certs/indexer-connector-key.pem</key>\n"
               "    </ssl>\n  </indexer>\n  <cluster>\n    <name>wazuh</name>\n    <key>" + _UNMASK_KEY +
               "</key>\n  </cluster>\n</wazuh_config>\n")


def test_unmask_xml_by_path_reverts_the_mask(db_setup):
    """What the read side masks, the write side restores: GET then PUT unchanged keeps the text byte for byte."""
    masked = db_setup._mask_all_sensitive_fields(_UNMASK_XML, db_setup.MASK_DEFAULT)
    assert _UNMASK_KEY not in masked

    assert db_setup.unmask_xml_by_path(masked, 'cluster.key', _UNMASK_KEY) == _UNMASK_XML


def test_unmask_xml_by_path_tolerates_whitespace_around_the_mask(db_setup):
    masked = _UNMASK_XML.replace(f'<key>{_UNMASK_KEY}</key>', f'<key> {db_setup.MASK_DEFAULT}\n</key>')

    assert db_setup.unmask_xml_by_path(masked, 'cluster.key', _UNMASK_KEY) == _UNMASK_XML


@pytest.mark.parametrize('sent', [
    'd4f1e0a57c2b9368a1e4f7c0b2d85e19',
    '',
    '****',
    '*****x',
])
def test_unmask_xml_by_path_leaves_any_other_value_alone(db_setup, sent):
    """Only the exact mask is replaced: a real value, or anything that merely resembles the mask, reaches the
    caller's checks as written."""
    text = _UNMASK_XML.replace(_UNMASK_KEY, sent)

    assert db_setup.unmask_xml_by_path(text, 'cluster.key', _UNMASK_KEY) == text


def test_unmask_xml_by_path_without_the_field(db_setup):
    text = "<wazuh_config>\n  <cluster>\n    <name>wazuh</name>\n  </cluster>\n</wazuh_config>\n"

    assert db_setup.unmask_xml_by_path(text, 'cluster.key', _UNMASK_KEY) == text


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


@pytest.mark.parametrize('data', [
    pytest.param(lambda: _XML_WITH_CREDENTIALS, id='raw'),
    pytest.param(lambda: [{'file_name': 'agent.conf', 'file_size': 1, 'file_content': _XML_WITH_CREDENTIALS}],
                 id='merged_mg_json'),
])
@pytest.mark.parametrize('group_perms, masked', [
    ({'group:read': {'group:id:*': 'allow'}}, True),
    ({'group:update_config': {'group:id:default': 'allow'}}, True),
    ({'cluster:read_secrets': {'node:id:master-node': 'allow'}}, False),
])
def test_mask_sensitive_config_group_file(db_setup, group_perms, masked, data):
    """A group file under 'data', raw or packed in merged.mg, is masked unless the user can read the secrets.

    Being allowed to update the group is not enough: only 'cluster:read_secrets' lifts the mask.
    """
    db_setup.rbac.set({'rbac_mode': 'white', **group_perms})

    @db_setup.mask_sensitive_config()
    def get_file_conf(group_list=None):
        return WazuhResult({'data': data()})

    result = get_file_conf(group_list=['default'])
    text = result['data'] if isinstance(result['data'], str) else result['data'][0]['file_content']
    assert ('>S<' not in text) is masked
    assert '<aws_profile>default</aws_profile>' in text


def test_mask_sensitive_config_raw_xml_escaped_less_than(db_setup):
    """A value holding the '\\<' escape accepted by os_xml is masked whole."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return '<ossec_config><fluent-forward><password>ab\\<cd</password></fluent-forward></ossec_config>'

    assert get_conf_raw() == '<ossec_config><fluent-forward><password>*****</password></fluent-forward></ossec_config>'


def test_mask_sensitive_config_raw_xml_black_mode_without_deny(db_setup):
    """A black mode user no policy denies 'cluster:read_secrets' over this node reads it unmasked."""
    db_setup.rbac.set({'rbac_mode': 'black'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CREDENTIALS

    assert get_conf_raw() == _XML_WITH_CREDENTIALS


@pytest.mark.parametrize('repeated', ['<cluster>' * 40000, '\\<api_key>' * 10000], ids=['parent_tag', 'escaped_leaf'])
def test_mask_all_sensitive_fields_repeated_open_tags_is_linear(db_setup, repeated):
    """Many openings of a path's parent tag, or escaped openings of a leaf, must not make the masking quadratic."""
    payload = '<agent_config><!--' + repeated + '--></agent_config>'

    start = time.perf_counter()
    result = db_setup._mask_all_sensitive_fields(payload, '*****')

    assert time.perf_counter() - start < 2.0
    assert result == payload


def test_mask_sensitive_config_xml_inside_nested_list(db_setup):
    """XML carried by a string element of a nested list is masked like any other embedded XML."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return {'files': [['<api_key>SECRET</api_key>']]}

    assert get_conf() == {'files': [['<api_key>*****</api_key>']]}


# ---------------------------------------------------------------------------
# Tests for whitespace/attribute variants of the masked tags (regression for
# the mask regex missing tags written as <cluster >, <cluster\t> or with
# attributes, which the manager's own XML parser still treats as <cluster>)
# ---------------------------------------------------------------------------

_XML_CLUSTER_TAG_WITH_SPACE = """\
<ossec_config>
  <cluster >
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_CLUSTER_TAG_WITH_TAB = "<ossec_config>\n  <cluster\t>\n    <key>SECRETCLUSTERKEY</key>\n  </cluster>\n</ossec_config>"

_XML_CLUSTER_TAG_WITH_ATTRIBUTE = """\
<ossec_config>
  <cluster foo="bar">
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_KEY_TAG_WITH_SPACE = """\
<ossec_config>
  <cluster>
    <key >SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_CLUSTER_TAG_WITH_LT_IN_ATTRIBUTE = """\
<ossec_config>
  <cluster note="a < b">
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_KEY_TAG_WITH_LT_IN_ATTRIBUTE = """\
<ossec_config>
  <cluster>
    <key note="<">SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_DECOY_TAG_WITH_CLUSTER_PREFIX = """\
<ossec_config>
  <clusterx>
    <key>NOTSECRET</key>
  </clusterx>
</ossec_config>"""


@pytest.mark.parametrize('xml_payload', [
    _XML_CLUSTER_TAG_WITH_SPACE,
    _XML_CLUSTER_TAG_WITH_TAB,
    _XML_CLUSTER_TAG_WITH_ATTRIBUTE,
    _XML_KEY_TAG_WITH_SPACE,
    _XML_CLUSTER_TAG_WITH_LT_IN_ATTRIBUTE,
    _XML_KEY_TAG_WITH_LT_IN_ATTRIBUTE,
])
def test_mask_sensitive_config_raw_xml_tag_whitespace_variants(db_setup, xml_payload):
    """Whitespace/attributes on the opening tag must not bypass the mask, and the mask must land in place."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml_payload

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result
    assert "<key" in result and "</key" in result
    assert "*****" in result


def test_mask_sensitive_config_raw_xml_decoy_tag_not_masked(db_setup):
    """A different tag sharing the `cluster` prefix must not be matched."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_DECOY_TAG_WITH_CLUSTER_PREFIX

    result = get_conf_raw()
    assert result == _XML_DECOY_TAG_WITH_CLUSTER_PREFIX


_XML_COMMENTED_KEY_BEFORE_REAL_KEY = """\
<ossec_config>
  <cluster>
    <!-- <key note>OLDKEY</key> -->
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_DUPLICATE_KEY_TAGS = """\
<ossec_config>
  <cluster>
    <key>OLDKEY</key>
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_KEY_VALUE_WITH_EMBEDDED_COMMENT = """\
<ossec_config>
  <cluster>
    <key>SECRETCLUSTERKEY<!-- rotate me --></key>
  </cluster>
</ossec_config>"""

_XML_KEY_CLOSING_TAG_WITH_SPACE = """\
<ossec_config>
  <cluster>
    <key>SECRETCLUSTERKEY</key >
  </cluster>
</ossec_config>"""

_XML_COMMENT_WITH_APOSTROPHE_BEFORE_REAL_KEY = """\
<ossec_config>
  <cluster>
    <!-- <key is the cluster's shared secret -->
    <key>SECRETCLUSTERKEY</key>
  </cluster>
  <indexer>
    <ssl>
      <key>/etc/filebeat/certs/filebeat-key.pem<!-- don't move --></key>
    </ssl>
  </indexer>
  <!-- <cluster></cluster> -->
</ossec_config>"""


@pytest.mark.parametrize('xml_payload', [
    _XML_COMMENTED_KEY_BEFORE_REAL_KEY,
    _XML_DUPLICATE_KEY_TAGS,
    _XML_KEY_VALUE_WITH_EMBEDDED_COMMENT,
    _XML_KEY_CLOSING_TAG_WITH_SPACE,
    _XML_COMMENT_WITH_APOSTROPHE_BEFORE_REAL_KEY,
])
def test_mask_sensitive_config_raw_xml_all_key_occurrences_masked(db_setup, xml_payload):
    """A prior <key> (commented-out or duplicated) or a comment inside the value must not leave the real key in clear text."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml_payload

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result
    assert "OLDKEY" not in result


@pytest.mark.parametrize('xml_payload, secrets', [
    (_XML_MULTIPLE_CLUSTER_BLOCKS, ('FIRSTKEY', 'SECONDKEY')),
    (_XML_MULTILINE_KEY, ('MULTILINE', 'SECRET')),
])
def test_mask_sensitive_config_raw_xml_every_block_masked(db_setup, xml_payload, secrets):
    """Every <cluster> block is masked, and a key value spanning several lines is masked whole."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml_payload

    result = get_conf_raw()
    assert all(secret not in result for secret in secrets)


@pytest.mark.parametrize('payload', [
    "<ossec_config><cluster><!-- " + "<key><!" * 8000 + " --></cluster></ossec_config>",
    "<ossec_config><cluster><node_name>" + "\\<key>" * 8000 + "</node_name></cluster></ossec_config>",
], ids=['inside_comment', 'escaped'])
def test_mask_sensitive_config_raw_xml_repeated_leaf_openings_are_linear(db_setup, payload):
    """Leaf openings inside a comment or after a backslash must not make every match attempt rescan the block."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return payload

    start = time.perf_counter()
    assert get_conf_raw() == payload
    assert time.perf_counter() - start < 2.0


_XML_CLUSTER_NEVER_CLOSES = """\
<ossec_config>
  <cluster>
    <key>SECRETCLUSTERKEY</key>
"""

_XML_CLUSTER_CLOSING_TAG_TYPO = """\
<ossec_config>
  <cluster>
    <key>SECRETCLUSTERKEY</key>
  </clustr>
</ossec_config>"""

_XML_CLUSTER_CLOSE_INSIDE_COMMENT = """\
<ossec_config>
  <cluster>
    <!-- old block: </cluster> -->
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_CLUSTER_NESTED_IN_NODES = """\
<ossec_config>
  <cluster>
    <nodes><cluster>10.0.0.1</cluster></nodes>
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""


@pytest.mark.parametrize('xml_payload', [
    _XML_CLUSTER_NEVER_CLOSES,
    _XML_CLUSTER_CLOSING_TAG_TYPO,
    _XML_CLUSTER_CLOSE_INSIDE_COMMENT,
    _XML_CLUSTER_NESTED_IN_NODES,
])
def test_mask_sensitive_config_raw_xml_missing_or_fake_block_close(db_setup, xml_payload):
    """A missing, misspelled, or commented-out </cluster> must not leave the whole block unmasked."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml_payload

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result


_XML_MIXED_CASE_TAGS = """\
<ossec_config>
  <Cluster>
    <Key>SECRETCLUSTERKEY</Key>
  </Cluster>
</ossec_config>"""


def test_mask_sensitive_config_raw_xml_mixed_case_tags(db_setup):
    """<Cluster>/<Key> must mask too: configuration.py lowercases tags when it reads them back."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_MIXED_CASE_TAGS

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result


def test_mask_sensitive_config_raw_xml_unclosed_key_many_comments_is_fast(db_setup):
    """An unclosed <key> followed by many comments must not trigger catastrophic regex backtracking (ReDoS guard)."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    payload = "<ossec_config><cluster><key>" + "<!--c-->" * 40 + "</cluster></ossec_config>"

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return payload

    start = time.perf_counter()
    get_conf_raw()
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0


_XML_CLUSTER_CLOSE_INSIDE_OSXML_COMMENT = """\
<ossec_config>
  <cluster>
    <! old block: </cluster> !>
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""


def test_mask_sensitive_config_raw_xml_close_inside_osxml_style_comment(db_setup):
    """A </cluster> written inside an os_xml-style <! ... !> comment must not truncate the block early.

    os_xml's own comment reader (_oscomment) closes a comment opened with '<!' at the first
    '-->' or '!>', not only the W3C '-->' form.
    """
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_CLUSTER_CLOSE_INSIDE_OSXML_COMMENT

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result


def test_mask_xml_by_path_three_level_path_missing_middle_tag_is_fast(db_setup):
    """A 3-tag path whose middle tag is absent from the block must not backtrack exponentially over trailing
    comments (ReDoS guard for the cluster.haproxy_helper.* paths)."""
    payload = "<cluster>" + "<!--c-->" * 40

    start = time.perf_counter()
    result = db_setup._mask_xml_by_path(payload, "cluster.haproxy_helper.haproxy_password", "*****")
    elapsed = time.perf_counter() - start

    assert elapsed < 2.0
    assert result == payload


@pytest.mark.parametrize('spelling', ['5', '05', '5\n', ' 5 ', '٥', '５', '+5', '0_5'])
def test_canonicalize_dynamic_ids_maps_every_int_spelling_to_the_denied_id(db_setup, spelling):
    """Every spelling int() reads as 5 must reach the matcher as '5', so a deny on user:id:5 applies to it."""
    kwargs = {'user_ids': [spelling, '6'], 'user_id': spelling}
    db_setup._canonicalize_dynamic_ids(['user:id:{user_ids}', 'user:id:{user_id}'], kwargs)

    assert kwargs == {'user_ids': ['5', '6'], 'user_id': '5'}
