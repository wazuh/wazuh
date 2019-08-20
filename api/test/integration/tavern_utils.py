#tavern_utils.py
import json


def calc_offset(response, total):
    """
    :param response: Request response
    :param total: Number
    :return: Number - 1
    """
    return {"sort_offset": str(int(total)-1)}


def test_select_key(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '_' in select_key and 'start' not in select_key and \
            'vm' not in select_key and 'rx' not in select_key and 'tx' not in select_key:
        assert list(response.json()["data"]["items"][0][select_key.split('_')[0]])[0] == select_key.split('_')[1]
    else:
        assert list(response.json()["data"]["items"][0])[0] == select_key
    return


def test_select_key_no_items(response, select_key):
    """
    :param response: Request response
    :param select_key: Parametrized key used for select param in request
    :return: True if request response item key matches used select param
    """
    if '_' in select_key and 'board' not in select_key:
        assert list(response.json()["data"])[0] == select_key.split('_')[0]
        assert list(response.json()["data"][select_key.split('_')[0]])[0] == select_key.split('_')[1]
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