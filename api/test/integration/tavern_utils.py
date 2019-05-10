#tavern_utils.py
import json


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
    print(list(affected_items))
    print(response.json()["data"]["affected_items"])
    assert list(response.json()["data"]["affected_items"]) == list(affected_items)
    return