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
    assert list(response.json()["data"]["items"][0])[0] == select_key
    return
