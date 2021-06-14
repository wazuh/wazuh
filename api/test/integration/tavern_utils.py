import json
from base64 import b64decode
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


def test_select_key_affected_items(response, select_key):
    """Check that all items in response have no other keys than those specified in 'select_key'.

    Absence of 'select_key' in response does not raise any error. However, extra keys in response (not specified
    in 'select_key') will raise assertion error.

    Some keys like 'id', 'agent_id', etc. are accepted even if not specified in 'select_key' since
    they ignore the 'select' param in API.

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
        # Get keys in response that are not specified in 'select_keys'
        set1 = main_keys.symmetric_difference(set(item.keys()))

        # Check if there are keys in response that were not specified in 'select_keys', apart from those which can be
        # mandatory (id, agent_id, etc).
        assert (set1 == set() or set1 == set1.intersection({'id', 'agent_id', 'file', 'task_id'} | main_keys)), \
            f'Select keys are {main_keys}, but the response contains these keys: {set1}'

        for nested_key in nested_keys.items():
            try:
                set2 = nested_key[1].symmetric_difference(set(item[nested_key[0]].keys()))
                assert set2 == set(), f'Nested select keys are {nested_key[1]}, but this one is different {set2}'
            except KeyError:
                assert nested_key[0] in main_keys


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
    """Iterate all items in the response and check that <key> value is within <expected_values>.

    Parameters
    ----------
    response : Request response
        API response to request.
    key : str
        Key whose value is checked.
    expected_values : str, list
        List of values which are allowed.
    """
    expected_values = set(expected_values.split(',')) if not isinstance(expected_values, list) else set(expected_values)

    for item in response.json()['data']['affected_items']:
        response_set = set(map(str, item[key])) if isinstance(item[key], list) else {str(item[key])}
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


def test_save_response_data_mitre(response, fields):
    response = response.json()['data']
    fields_response = list()
    for r in response['affected_items']:
        fields_response.append({k: r[k] for k in fields})

    return Box({'response_data': fields_response})


def test_validate_mitre(response, data, index=0):
    data = json.loads(data.replace("'", '"'))
    for element in data:
        for k, v in element.items():
            assert v == response.json()['data']['affected_items'][index][k]


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
