import json
import re
import time
from base64 import b64decode
from json import loads

from box import Box


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


def test_select_key_affected_items(response, select_key):
    """
    :param response: Request response
    :param select_key: Keys requested in select parameter.
        Lists and nested fields accepted e.g: id,cpu.mhz,json
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
        set1 = main_keys.symmetric_difference(set(item.keys()))
        assert set1 == set() or set1.intersection({'id', 'agent_id'}), \
            f'Select keys are {main_keys}, but this one is different {set1}'

        for nested_key in nested_keys.items():
            set2 = nested_key[1].symmetric_difference(set(item[nested_key[0]].keys()))
            assert set2 == set(), f'Nested select keys are {nested_key[1]}, but this one is different {set2}'


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


def test_sort_response(response, affected_items):
    """
    :param response: Request response
    :param affected_items: List of agent
    :return: True if request response have this items
    """
    affected_items = affected_items.replace("'", '"')
    affected_items = json.loads(affected_items)
    reverse_index = len(affected_items) - 1
    for index, item_response in enumerate(response.json()['data']['affected_items']):
        assert item_response == affected_items[reverse_index - index]


def test_validate_data_dict_field(response, fields_dict):
    assert fields_dict, f'Fields dict is empty'
    for field, dikt in fields_dict.items():
        field_list = response.json()['data'][field]

        for element in field_list:
            try:
                assert (isinstance(element[key], eval(value)) for key, value in dikt.items())
            except KeyError:
                assert len(element) == 1
                assert isinstance(element['count'], int)


def test_count_elements(response, n_expected_items):
    """
    :param response: Request response
    :param n_expected_items: Expected number of elements in affected_items
    """
    assert len(response.json()['data']['affected_items']) == n_expected_items


def test_expected_value(response, key, expected_values):
    """
    :param response: Request response
    :param key: Key whose value to compare.
    :param expected_values: Values to be found inside response.
    """
    expected_values = set(expected_values.split(',')) if not isinstance(expected_values, list) else set(expected_values)

    for item in response.json()['data']['affected_items']:
        response_set = set(item[key]) if isinstance(item[key], list) else {item[key]}
        assert bool(expected_values.intersection(response_set)), \
            f'Expected values {expected_values} not found in {item[key]}'


def test_response_is_different(response, response_value, unexpected_value):
    """
    :param response_value: Value to compare
    :param unexpected_value: Response value should be different to this.
    """
    assert response_value != unexpected_value, f"{response_value} and {unexpected_value} shouldn't be the same"


def test_save_response_data(response):
    return Box({'response_data': response.json()['data']})


def test_validate_restart_by_node(response, data):
    data = json.loads(data.replace("'", '"'))
    affected_items = list()
    failed_items = list()
    for item in data['affected_items']:
        if item['status'] == 'active':
            affected_items.append(item['id'])
        else:
            failed_items.append(item['id'])
    assert response.json()['data']['affected_items'] == affected_items
    assert response.json()['data']['failed_items'] == failed_items


def test_validate_restart_by_node_rbac(response, permitted_agents):
    data = response.json().get('data', None)
    if data:
        if data['affected_items']:
            for agent in data['affected_items']:
                assert agent in permitted_agents
        else:
            assert data['total_affected_items'] == 0
    else:
        assert response.status_code == 403
        assert response.json()['error'] == 4000
        assert 'agent:id' in response.json()['detail']


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


def test_validate_syscollector_hotfix(response, hotfix_filter=None, experimental=False):
    hotfixes_keys = {'hotfix', 'scan_id', 'scan_time'}
    if experimental:
        hotfixes_keys.add('agent_id')
    affected_items = response.json()['data']['affected_items']
    if affected_items:
        for item in affected_items:
            assert set(item.keys()) == hotfixes_keys
            if hotfix_filter:
                assert item['hotfix'] == hotfix_filter


def test_validate_group_configuration(response, expected_field, expected_value):
    response_json = response.json()
    assert len(response_json['data']['affected_items']) > 0 and\
           'config' in response_json['data']['affected_items'][0] and \
           'localfile' in response_json['data']['affected_items'][0]['config'],\
           'No config or localfile fields were found in the affected_items. Response: {}'.format(response_json)

    response_config = response_json['data']['affected_items'][0]['config']['localfile'][0]
    assert expected_field in set(response_config.keys()), \
        'The expected config key is not present in the received response.'

    assert response_config[expected_field] == expected_value, \
        'The received value for query does not match with the expected one. ' \
        'Received: {}. Expected: {}'.format(response_config[expected_field], expected_value)
