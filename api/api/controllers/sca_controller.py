# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import asyncio
import connexion
import datetime
import logging

from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh import common
from wazuh.cluster.dapi.dapi import DistributedAPI
import wazuh.security_configuration_assessment as sca

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_sca_agent(agent_id=None, pretty=False, wait_for_complete=False,
                  name=None, description=None, references=None, offset=0,
                  limit=None, sort=None, search=None, q=None):
    """Get security configuration assessment (SCA) database

    Returns the security SCA database of an agent

    :param agent_id: Agent ID. All possible values since 000 onwards.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param name: Filters by policy name
    :param description: Filters by policy description
    :param references: Filters by references
    :param offset:First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). 
    Use +/- at the beginning to list in ascending or descending order
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. This is specially useful to filter by 
    total checks passed, failed or total score (fields pass, fail, score)
    """
    filters = {'name': name,
               'description': description,
               'references': references}

    f_kwargs = {'agent_id': agent_id,
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'q': q,
                'filters': filters}

    dapi = DistributedAPI(f=sca.get_sca_list,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_sca_checks(agent_id=None, pretty=False, wait_for_complete=False,
                   policy_id=None, title=None, description=None,
                   rationale=None, remediation=None, process=None,
                   directory=None, registry=None, references=None, result=None,
                   offset=0, limit=None, sort=None, search=None, q=None):
    """Get policy monitoring alerts for a given policy

    Returns the policy monitoring alerts for a given policy

    :param agent_id: Agent ID. All possible values since 000 onwards
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param policy_id: Filters by policy id
    :param title: Filters by title
    :param description: Filters by policy description
    :param rationale: Filters by rationale
    :param remediation: Filters by remediation
    :param file: Filters by file
    :param process: Filters by process
    :param directory: Filters by directory
    :param registry: Filters by registry
    :param references: Filters by references
    :param result: Filters by result
    :param offset:First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. This is specially useful to filter by total checks passed, failed or total score (fields pass, fail, score)
    """
    # get file parameter from query
    file_ = connexion.request.args.get('file', None)

    filters = {'title': title,
               'description': description,
               'rationale': rationale,
               'remediation': remediation,
               'file': file_,
               'process': process,
               'directory': directory,
               'registry': registry,
               'references': references,
               'result': result}

    f_kwargs = {'policy_id': policy_id,
                'agent_id': agent_id,
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'q': q,
                'filters': filters}

    dapi = DistributedAPI(f=sca.get_sca_checks,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200

