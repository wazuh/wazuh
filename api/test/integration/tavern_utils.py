#tavern_utils.py
import json


def calc_offset(response, total):
    """
    :param response: Request response
    :param total: Number
    :return: Number - 1
    """
    return {"sort_offset": str(int(total) - 1)}


def test_distinct_key(response):
    """
    :param response: Request response
    :return: True if request response item number matches used distinct param
    """
    total = len(set(tuple(i.values()) for i in response.json()["data"]["affected_items"]))
    assert len(list(response.json()["data"]["affected_items"])) == total
    return


def test_select_key(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        assert list(response.json()["data"]["items"][0])[0] == select_key.split('.')[0]
        assert list(response.json()["data"]["items"][0][select_key.split('.')[0]])[0] == select_key.split('.')[1]
    else:
        assert list(response.json()["data"]["items"][0])[0] == select_key
    return


def test_select_key_affected_items(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        assert list(response.json()["data"]["affected_items"][0])[0] == select_key.split('.')[0]
        assert list(response.json()["data"]["affected_items"][0][select_key.split('.')[0]])[0] == select_key.split('.')[1]
    else:
        assert list(response.json()["data"]["affected_items"][0])[0] == select_key
    return


def test_select_key_affected_items_with_agent_id(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    position = 0 if select_key < 'agent_id' else 1
    if '.' in select_key:
        assert list(response.json()["data"]["affected_items"][0])[position] == select_key.split('.')[0]
        assert list(response.json()["data"]["affected_items"][0][select_key.split('.')[0]])[0] == select_key.split('.')[1]
    else:
        assert list(response.json()["data"]["affected_items"][0])[position] == select_key
    return


def test_select_key_no_items(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '.' in select_key:
        assert list(response.json()["data"])[0] == select_key.split('.')[0]
        assert list(response.json()["data"][select_key.split('.')[0]])[0] == select_key.split('.')[1]
    else:
        assert list(response.json()["data"])[0] == select_key
    return


def calc_agents(response, total):
    """
    :param response: Request response
    :param total: Number
    :return: Number - 1
    """
    return {"totalAgents": str(int(total)-1)}


def test_affected_items_response(response, affected_items):
    """
    :param response: Request response
    :param affected_items: List of agent
    :return: True if request response have this items
    """
    assert set(response.json()['data']['affected_items']) != set(affected_items)

    return


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
        assert item_response != affected_items[reverse_index - index]
    return
