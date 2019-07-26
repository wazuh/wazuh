# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

import wazuh.rbac
from wazuh.exception import WazuhError, WazuhInternalError

# MOCK DATA
mock_jwt = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ3YXp1aCIsImlhdCI6MTU1ODY5ODM2NiwiZXhwI" \
           "joxNTU4Njk4OTY2LCJzdWIiOiJmb28iLCJyYmFjX3BvbGljaWVzIjpbeyJhY3Rpb25zIjpbImRlY29kZXI6Z2V0Il0sInJ" \
           "lc291cmNlcyI6WyJkZWNvZGVyOm5hbWU6d2luZG93c19maWVsZHMiLCJkZWNvZGVyOm5hbWU6KiJdLCJlZmZlY3QiOiJhb" \
           "GxvdyJ9XSwibW9kZSI6ZmFsc2V9.Pve6eh1AgqWVvST-ewBfST2IMb8c7_vVm6XD_RQ52v4"

mock_rbac_policies = [
    {
        "actions": ["decoder:get"],
        "resources": ["decoder:name:windows_fields", "decoder:name:*"],
        "effect": "allow"
    }
]

mock_payload = {
    "rbac_policies": mock_rbac_policies,
    "mode": False
}

mocked_user1 = [{
    "actions": ["mock_action:get"],  # 1st policy
    "resources": ["mock_resources:name:mock_name"],
    "effect": "allow"
}]

mocked_user2 = [{
    "actions": ["mock_action:get"],  # 1st policy
    "resources": ["mock_resources:name:mock_name"],
    "effect": "deny"
}]

mocked_user3 = [{
    "actions": ["mock_action:get"],  # 1st policy
    "resources": ["agent:id:mock_agent"],
    "effect": "allow"
}]

mocked_user4 = [{
    "actions": ["mock_action:get"],  # 1st policy
    "resources": ["mock_resources:name:*"],
    "effect": "allow"
}]


@pytest.mark.parametrize('mock_actions', [
    ['mock_action:get',
     'mock_action:delete']
])
@pytest.mark.parametrize('mock_resources', [
    'mock_resources:name:{name}',  # dynamic resources
    'mock_resources:name:mock_name'  # static resources
])
@pytest.mark.parametrize('mock_names', [
    'mock_file1.xml',  # params is a str
    ['mock_file1.xml', 'mock_file2.xml']  # params is a list
])
def test_get_required_permissions(mock_names, mock_resources, mock_actions):
    permissions = wazuh.rbac.get_required_permissions(actions=mock_actions, resources=mock_resources, name=mock_names)
    assert isinstance(permissions, dict)
    for action in mock_actions:
        assert action in permissions.keys()


def test_get_required_permissions_exception():
    with pytest.raises(WazuhInternalError, match='.* 4001 .*'):
        wazuh.rbac.get_required_permissions(actions=['mock_action:get'], resources='mock_resources:name:{name}',
                                            wrong='mock_file1.xml')


@pytest.mark.parametrize('mock_req', [
    {
        'mock_action:get': {'mock_resources:name:mock_name'}
    }
])
@pytest.mark.parametrize('mock_user', [
    [{  # 1st user permissions
        "actions": ["mock_action:get"],  # 1st policy
        "resources": ["mock_resources:name:mock_name"],
        "effect": "deny"
    }],
    [{  # 2nd user permissions
        "actions": ["mock_action:update"],  # 1st policy
        "resources": ["mock_resources:name:wrong"],
        "effect": "deny"
    }],
    [{  # 3rd user permissions
        "actions": ["mock_action:get"],  # 1st policy
        "resources": ["mock_resources:name:mock_name"],
        "effect": "allow"
    },
        {
            "actions": ["mock_action:update"],  # 2nd policy
            "resources": ["mock_resources:name:mock_name"],
            "effect": "deny"
        },
    ]
])
@pytest.mark.parametrize('mock_modes', [
    False,  # white_list mode
    True  # black_list mode
])
def test_match_pairs(mock_modes, mock_user, mock_req):
    allowed = wazuh.rbac.match_permissions(rbac=[mock_modes, mock_user], req_permissions=mock_req)
    assert isinstance(allowed, bool)


@pytest.mark.parametrize('mocked_rbac', [
    [False, mocked_user1],
    [False, mocked_user2],
    [False, mocked_user3],
    [False, mocked_user4]
])
def test_matches_privileges(mocked_rbac):
    # First and second stages
    @wazuh.rbac.matches_privileges(actions=["mock_action:get"], resources="mock_resources:name:mock_name")
    def framework_dummy():
        return True
    if mocked_rbac[1] == mocked_user2:
        with pytest.raises(WazuhError, match='.* 4000 .*'):
            framework_dummy(rbac=mocked_rbac)
    elif mocked_rbac[1] == mocked_user1:
        assert framework_dummy(rbac=mocked_rbac) is True

    # Third stage
    if mocked_rbac[1] == mocked_user3:
        @wazuh.rbac.matches_privileges(actions=["mock_action:get"], resources="agent:id:mock_agent")
        def framework_dummy_2():
            return True
        with patch("wazuh.rbac.get_groups_resources", return_value=['agent:id:*', 'agent:group:*',
                                                                    'agent:group:default', 'agent:group:group1']):
            assert framework_dummy_2(rbac=mocked_rbac) is True

    # Fourth stage
    if mocked_rbac[1] == mocked_user4:
        @wazuh.rbac.matches_privileges(actions=["mock_action:get"], resources="mock_resources:name:*")
        def framework_dummy_3():
            return True
        assert framework_dummy_3(rbac=mocked_rbac) is True


@pytest.mark.parametrize('mocked_agent', [
    '001',
    '*'
])
@patch("wazuh.rbac.Connection.fetch_all", return_value=[['default'], ['group1']])
@patch("wazuh.rbac.Connection.execute", return_value=None)
@patch("wazuh.rbac.Connection.__init__", return_value=None)
@patch("wazuh.rbac.glob")
def test_get_groups_resources(mocked_glob, mocked_connection, mocked_execute, mocked_fetch_all, mocked_agent):
    # Answer should be Error code 1600 is there is no db_global
    mocked_glob.return_value = None
    with pytest.raises(WazuhInternalError, match='.* 1600 .*'):
        wazuh.rbac.get_groups_resources('001')

    # Answer should extract groups from the agents for any id and *
    mocked_glob.return_value = [""]
    result = wazuh.rbac.get_groups_resources(mocked_agent)
    assert isinstance(result, list)
    for item in result:
        assert item in ['agent:id:*', 'agent:group:*', 'agent:group:default', 'agent:group:group1']
