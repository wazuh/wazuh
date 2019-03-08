# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

def put_syscheck(pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    """
    pass


def get_syscheck_agent(agent_id, pretty=False, wait_for_complete=False, offset=0, limit=None, 
                       select=None, sort=None, search=None, file=None, type=None, summary=False,
                       md5=None, sha1=None, sha256=None, hash=None):
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
    :param file: Filters by filename.
    :type file: str
    :param type: Filters by file type.
    :type type: str
    :param summary: Returns a summary grouping by filename.
    :type summary: bool
    :param md5: Filters files with the specified MD5 checksum.
    :type md5: str
    :param sha1: Filters files with the specified SHA1 checksum.
    :type sha1: str
    :param sha256: Filters files with the specified SHA256 checksum.
    :type sha256: str
    :param hash: Filters files with the specified checksum (MD5, SHA256 or SHA1)
    :type md5: str
    """
    pass


def put_syscheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    pass


def delete_syscheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    pass
