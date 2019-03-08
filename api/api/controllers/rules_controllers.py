# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


def get_rules(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, 
              search=None, status=None, group=None, level=None, file=None, path=None,
              pci=None, gdpr=None):
    """
    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order. 
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param status: Filters by rules status.
    :type status: List[str]
    :param group: Filters by rule group.
    :type group: str
    :param level: Filters by rule level. Can be a single level (4) or an interval (2-4)
    :type level: str
    :param file: Filters by filename.
    :type file: str
    :param pci: Filters by PCI requirement name.
    :type pci: str
    :param gdpr: Filters by GDPR requirement.
    :type gdpr: str
    """
    pass

