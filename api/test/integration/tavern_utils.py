# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import ast
import json
import re
import subprocess
import time
from base64 import b64decode
from datetime import datetime
from json import loads

from box import Box


def get_values(o):
    strings = []

    try:
        obj = o.to_dict()
    except:
        obj = o

    if type(obj) is list:
        for o in obj:
            strings.extend(get_values(o))
    elif type(obj) is dict:
        for key in obj:
            strings.extend(get_values(obj[key]))
    else:
        strings.append(obj.lower() if isinstance(obj, str) or isinstance(obj, str) else str(obj))

    return strings


def test_distinct_key(response):
    """
    :param response: Request response
    :return: True if all request response items are unique
    """
    assert not any(
        response.json()["data"]["affected_items"].count(item) > 1 for item in response.json()["data"]["affected_items"])


def test_token_raw_format(response):
    """
    :param response: Request response
    """
    assert type(response.text) is str


def test_select_key_affected_items(response, select_key, flag_nested_key_list=False):
    """Check that all items in response have no other keys than those specified in 'select_key'.

    Absence of 'select_key' in response does not raise any error. However, extra keys in response (not specified
    in 'select_key') will raise assertion error.

    Some keys like 'id', 'agent_id', etc. are accepted even if not specified in 'select_key' since
    they ignore the 'select' param in API.

    Parameters
    ----------
    response : Request response
    select_key : str
        Keys requested in select parameter. Lists and nested fields accepted e.g: id,cpu.mhz,json
    flag_nested_key_list : bool
        Flag used to indicate that the nested key contains a list.
    """
    main_keys = set()
    nested_keys = dict()

    for key in select_key.split(','):
        if '.' in key:
            main_keys.update({key.split('.')[0]})
            left_key, right_key = key.split('.')

            if left_key in nested_keys:
                nested_keys[left_key].update({right_key})
            else:
                nested_keys[left_key] = {right_key}
        else:
            main_keys.update({key})

    for item in response.json()['data']['affected_items']:
        # Get keys in response that are not specified in 'select_keys'
        set1 = main_keys.symmetric_difference(set(item.keys()))

        # Check if there are keys in response that were not specified in 'select_keys', apart from those which can be
        # mandatory (id, agent_id, etc).
        assert (set1 == set() or set1 == set1.intersection(
            {'id', 'agent_id', 'file', 'task_id',
             'policy_id'} | main_keys)), f'Select keys are {main_keys}, but the response contains these keys: {set1}'

        for nested_key in nested_keys.items():
            # nested_key = compliance, value
            try:
                if not flag_nested_key_list:
                    set2 = nested_key[1].symmetric_difference(set(item[nested_key[0]].keys()))

                # If we are using select in endpoints like GET /sca/{agent_id}/checks/{policy_id},
                # the nested field contains a list
                else:
                    set2 = nested_key[1].symmetric_difference(set(item[nested_key[0]][0].keys()))

                assert set2 == set(), f'Nested select keys are {nested_key[1]}, but this one is different {set2}'
            except KeyError:
                assert nested_key[0] in main_keys


def test_select_distinct_nested_sca_checks(response, select_key):
    """Check that all items in response have no other keys than those specified in 'select_key'.

    This function is specifically used for the SCA checks endpoint, when distinct=True and select contains a nested
    field.

    This function does not take into account min select fields.

    Absence of 'select_key' in response does not raise any error. However, extra keys in response (not specified
    in 'select_key') will raise assertion error.

    Parameters
    ----------
    response : Request response
    select_key : str
        Keys requested in select parameter. Lists and nested fields accepted e.g: id,cpu.mhz,json
    """
    main_keys = set(select_key.split(','))

    for item in response.json()['data']['affected_items']:
        # Check that there are no keys in the item that are not specified in 'select_keys'
        set1 = main_keys.symmetric_difference(set(item.keys()))
        assert set1 == set() or set1 == set1.intersection(main_keys), \
            f'Select keys are {main_keys}, but an item contains the keys: {set(item.keys())}'


def test_select_key_affected_items_with_agent_id(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        expected_keys_level0 = {'agent_id', select_key.split('.')[0]}
        expected_keys_level1 = {select_key.split('.')[1]}
        assert set(response.json()["data"]["affected_items"][0].keys()) == expected_keys_level0
        assert set(
            response.json()["data"]["affected_items"][0][select_key.split('.')[0]].keys()) == expected_keys_level1
    else:
        expected_keys = {'agent_id', select_key}
        assert set(response.json()["data"]["affected_items"][0].keys()) == expected_keys


def test_sort_response(response, key=None, reverse=False):
    """Check that the response's affected items are sorted by the specified key or keys.

    Parameters
    ----------
    response : Request response
    key : str
        Key or keys expected to sort by.
    reverse : bool
        Indicate if the expected order is ascending (False) or descending (True). Default: False

    Returns
    -------
    bool
        True if the response's items are sorted by the key or keys.
    """

    def get_val_from_dict(dictionary, keys):
        """Get value from dictionary dynamically, given a list of keys.
        E.g. get_val_from_dict(d, ['field1','field2']) will return d['field1']['field2']

        Parameters
        ----------
        dictionary : dict
            Dictionary to get the value from.
        keys : list
            List of keys used to find the value in the dictionary. If the list length is more than 1, the value to find
            is a nested one.

        Returns
        -------
        Value of the dictionary for key `keys`.
        """
        try:
            for key in keys:
                dictionary = dictionary[key]
        except KeyError:
            return ''

        if isinstance(dictionary, str) and not dictionary.startswith('/') and not dictionary.startswith('\\'):
            return dictionary.lower()

        return dictionary

    affected_items = response.json()['data']['affected_items']

    # If not key, we are sorting a list of strings
    if not key:
        # key is None in 'sorted' as affected_items is a list of strings instead of dictionaries
        assert affected_items == sorted(affected_items, reverse=reverse)
    # If key, we are sorting a list of dictionaries
    else:
        # If key is a list of keys, split key
        # If key is only one key, transform it into a list
        keys = key.split(',')

        sorted_items = affected_items
        keys.reverse()
        for k in keys:
            # Split key in case it is a nested key
            split_key = k.split('.')

            # Update sorted_items
            # split_key will be similar to ['name'] in the basic cases
            # split_key will be similar to ['os', 'name'] in nested cases
            sorted_items = sorted(sorted_items, key=(lambda item: get_val_from_dict(item, split_key)), reverse=reverse)

        # Change position of items without the key we are sorting by
        # Our sql query considers an item not having the key < an item having the key
        # The 'sorted' function considers an item not having the key > an item having the key
        list_no_keys = [item for item in sorted_items if not any(get_val_from_dict(item, key.split('.'))
                                                                 for key in keys)]
        for item in list_no_keys:
            sorted_items.remove(item)
        sorted_items = sorted_items + list_no_keys if reverse else list_no_keys + sorted_items

        assert affected_items == sorted_items


def test_validate_data_dict_field(response, fields_dict):
    assert fields_dict, "Fields dict is empty"
    for field, dikt in fields_dict.items():
        field_list = response.json()['data'][field]

        for element in field_list:
            try:
                assert (isinstance(element[key], ast.literal_eval(value)) for key, value in dikt.items())
            except KeyError:
                assert len(element) == 1
                assert isinstance(element['count'], int)


def test_count_elements(response, n_expected_items):
    """
    :param response: Request response
    :param n_expected_items: Expected number of elements in affected_items
    """
    assert len(response.json()['data']['affected_items']) == n_expected_items


def test_expected_value(response, key, expected_values, empty_response_possible=False):
    """Iterate all items in the response and check that <key> value is within <expected_values>.

    Parameters
    ----------
    response : Request response
        API response to request.
    key : str
        Key whose value is checked.
    expected_values : str, list
        List of values which are allowed.
    empty_response_possible : bool
        Indicates whether the response could be empty or not. Set to True when the key value does not depend on the
        test itself, for instance, node. Default: `False`
    """
    expected_values = set(expected_values.split(',')) if not isinstance(expected_values, list) else set(expected_values)
    affected_items = response.json()['data']['affected_items']

    if not affected_items and not empty_response_possible:
        raise Exception("No items found in the response")

    for item in affected_items:
        response_set = set(map(str, item[key])) if isinstance(item[key], list) else {str(item[key])}
        assert bool(expected_values.intersection(response_set)), \
            f'Expected values {expected_values} not found in {item[key]}'


def test_response_is_different(response, response_value, unexpected_value):
    """
    :param response_value: Value to compare
    :param unexpected_value: Response value should be different to this.
    """
    assert response_value != unexpected_value, f"{response_value} and {unexpected_value} shouldn't be the same"


def test_save_token_raw_format(response):
    return Box({'login_token': response.text})


def test_save_response_data(response):
    return Box({'response_data': response.json()['data']})


def test_validate_auth_context(response, expected_roles=None):
    """Check that the authorization context has been matched with the correct rules

    Parameters
    ----------
    response : Request response
    expected_roles : list
        List of expected roles after checking the authorization context
    """
    token = response.json()['data']['token'].split('.')[1]
    payload = loads(b64decode(token + '===').decode())
    assert payload['rbac_roles'] == expected_roles


def test_validate_group_configuration(response, expected_field, expected_value):
    response_json = response.json()
    assert len(response_json['data']['affected_items']) > 0 and \
           'config' in response_json['data']['affected_items'][0] and \
           'localfile' in response_json['data']['affected_items'][0]['config'], \
        'No config or localfile fields were found in the affected_items. Response: {}'.format(response_json)

    response_config = response_json['data']['affected_items'][0]['config']['localfile'][0]
    assert expected_field in set(response_config.keys()), \
        'The expected config key is not present in the received response.'

    assert response_config[expected_field] == expected_value, \
        'The received value for query does not match with the expected one. ' \
        'Received: {}. Expected: {}'.format(response_config[expected_field], expected_value)


def test_validate_search(response, search_param):
    search_param = search_param.lower()
    response_json = response.json()
    for item in response_json['data']['affected_items']:
        values = get_values(item)
        if not any(filter(lambda x: search_param in x, values)):
            raise ValueError(f'{search_param} not present in {values}')


def test_validate_key_not_in_response(response, key):
    assert all(key not in item for item in response.json()["data"]["affected_items"])


def test_validate_vd_scans(response, first_node_name, first_node_count, second_node_name, second_node_count,
                           third_node_name, third_node_count):
    nodes = []
    if first_node_count > 0:
        nodes.append(first_node_name)
    if second_node_count > 0:
        nodes.append(second_node_name)
    if third_node_count > 0:
        nodes.append(third_node_name)

    # All the names in nodes must be in the response
    assert all(node in response.json()["data"]["affected_items"] for node in nodes)


def check_agentd_started(response, agents_list):
    """Wait until all the agents have their agentd process started correctly. This will avoid race conditions caused by
    agents reconnections before restarting.

    Parameters
    ----------
    response : Request response
    agents_list : list
        List of expected agents to be restarted.
    """
    timestamp_regex = re.compile(r'^\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d')
    agentd_started_regex = re.compile(r'agentd.+Started')

    def get_timestamp(log):
        """Get timestamp from log.

        Parameters
        ----------
        log : str
            String representing the log to get the timestamp from.

        Returns
        -------
        datetime
            Datetime object representing the timestamp got.
        """
        timestamp = timestamp_regex.search(string=log).group(0)
        return datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")

    # Save the time when the restart command was sent
    restart_request_time = datetime.utcnow().replace(microsecond=0) - response.elapsed

    for agent_id in agents_list:
        tries = 0
        while tries < 80:
            try:
                # Save agentd logs in a list
                command = f"docker exec env-wazuh-agent{int(agent_id)}-1 grep agentd /var/ossec/logs/ossec.log"
                output = subprocess.check_output(command.split()).decode().strip().split('\n')
            except subprocess.SubprocessError as exc:
                raise subprocess.SubprocessError(f"Error while trying to get logs from agent {agent_id}") from exc

            # Ignore agentd logs before restart_request_time
            logs_after_restart = [agentd_log for agentd_log in output if
                                  get_timestamp(agentd_log).timestamp() >= restart_request_time.timestamp()]

            # Check the log indicating agentd started is in the agent's ossec.log (after the restart request)
            if any(agentd_started_regex.search(string=agentd_log) for agentd_log in logs_after_restart):
                break

            tries += 1
            time.sleep(1)
        else:
            raise ProcessLookupError("The wazuh-agentd daemon was not started after requesting the restart")


def check_agent_active_status(agents_list):
    """Wait until all the agents have active status in the global.db. This will avoid race conditions caused by
    non-active agents in following test cases.

    Parameters
    ----------
    agents_list : list
        List of expected agents to be restarted.
    """
    active_agents_script_path = "/tools/print_active_agents.py"
    id_active_agents = []
    tries = 0
    while tries < 25:
        try:
            # Get active agents
            output = subprocess.check_output(f"docker exec env-wazuh-master-1 /var/ossec/framework/python/bin/python3 "
                                             f"{active_agents_script_path}".split()).decode().strip()
        except subprocess.SubprocessError as exc:
            raise subprocess.SubprocessError("Error while trying to get agents") from exc

        # Transform string representation of list to list and save agents id
        id_active_agents = [agent['id'] for agent in ast.literal_eval(output)]

        if all(a in id_active_agents for a in agents_list):
            break

        tries += 1
        time.sleep(1)
    else:
        non_active_agents = [a for a in agents_list if a not in id_active_agents]
        raise SystemError(f"Agents {non_active_agents} have a status different to active after restarting")


def healthcheck_agent_restart(response, agents_list):
    """Wait until the restart process is finished for every agent in the given list.

    Parameters
    ----------
    response : Request response
    agents_list : list
        List of expected agents to be restarted.
    """
    # Wait for agentd daemon start (up to 80 seconds)
    check_agentd_started(response, agents_list)
    # Wait for cluster synchronization process (20 seconds)
    time.sleep(20)
    # Wait for active agent status (up to 25 seconds)
    check_agent_active_status(agents_list)


def validate_update_check_response(response, current_version, update_check):
    """Check that the update check response contains the expected fields, and verify if the 'last_available_*'
    dictionaries have the correct keys and values.

    Parameters
    ----------
    response : Request response
    """
    error_code = response.json()['error']
    if response.status_code == 500:
        assert error_code == 2100
        return

    available_update_keys = ["last_available_major", "last_available_minor", "last_available_patch"]
    keys_to_check = [
        ("tag", str), ("description", (str, type(None))), ("title", str), ("published_date", str), ("semver", dict)
    ]

    data = response.json()['data']

    assert error_code == 0
    assert data['current_version'] == current_version
    assert data['update_check'] == update_check
    assert data['uuid'] is not None
    last_check_date = data['last_check_date']
    if update_check:
        assert last_check_date is not None
    else:
        assert last_check_date == ''

    for available_update in available_update_keys:
        available_update_data = data[available_update]

        assert isinstance(available_update_data, dict)

        if available_update_data != {}:
            for key, value_type in keys_to_check:
                assert isinstance(available_update_data[key], value_type)
