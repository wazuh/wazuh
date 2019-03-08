# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

def get_rootcheck_agent(agent_id, pretty=False, wait_for_complete=False, offset=0, limit=None, 
                        select=None, sort=None, search=None, q='', status=None, pci='all', 
                        cis='all'):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
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
    :param status: Filter by scan status.
    :type status: str
    :param pci: Filters by PCI requirement.
    :type pci: str
    :param cis: Filters by CIS requirement.
    :type cis: str
    """
    pass


def put_rootcheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    pass


def delete_rootcheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    pass
