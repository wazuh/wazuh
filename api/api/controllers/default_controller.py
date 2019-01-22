import connexion
import six

from api.models.inline_response200 import InlineResponse200  # noqa: E501
from api.models.inline_response2001 import InlineResponse2001  # noqa: E501
from api import util


def delete_agents(ids=None, purge=None, status=None, older_than=None):  # noqa: E501
    """Delete agents

    Removes agents, using a list of them or a criterion based on the status or time of the last connection. The Wazuh API must be restarted after removing an agent.  # noqa: E501

    :param ids: Array of agent ID’s
    :type ids: List[str]
    :param purge: Delete an agent from the key store
    :type purge: bool
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :type status: List[str]
    :param older_than: Filters out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’, ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never connected agents, uses the register date. 
    :type older_than: str

    :rtype: InlineResponse2001
    """
    return 'do some magic!'


def get_all_agents(offset=None, limit=None, select=None, sort=None, search=None, status=None, q=None, older_than=None,
                   os_platform=None, os_version=None, os_name=None, manager=None, version=None, group=None,
                   node_name=None, name=None, ip=None):  # noqa: E501
    """Get all agents

    Returns a list with the available agents. # noqa: E501

    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order. 
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :type status: List[str]
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;Active&amp;quot;
    :type q: str
    :param older_than: Filters out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’, ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never connected agents, uses the register date. 
    :type older_than: str
    :param os_platform: Filters by OS platform.
    :type os_platform: str
    :param os_version: Filters by OS version.
    :type os_version: str
    :param os_name: Filters by OS name.
    :type os_name: str
    :param manager: Filters by manager hostname to which agents are connected.
    :type manager: str
    :param version: Filters by agents version.
    :type version: str
    :param group: Filters by group of agents.
    :type group: str
    :param node_name: Filters by node name.
    :type node_name: str
    :param name: Filters by agent name.
    :type name: str
    :param ip: Filters by agent IP
    :type ip: str

    :rtype: InlineResponse200
    """




    return 'do some magic!'
