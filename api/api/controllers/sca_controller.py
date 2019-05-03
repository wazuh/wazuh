# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import asyncio
import connexion
import datetime
import logging

from api.util import remove_nones_to_dict, exception_handler, parse_api_param, format_data
from wazuh import common
from wazuh.cluster.dapi.dapi import DistributedAPI
import wazuh.security_configuration_assessment as sca

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_sca_agent(agent_id=None, pretty=False, wait_for_complete=False,
                  name=None, description=None, references=None, offset=0,
                  limit=None, sort=None, search=None, query=None):
    """Get security configuration assessment (SCA) database

    Returns the security SCA database of an agent

    :param agent_id:
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param name:
    :param description:
    :param references:
    :param offset:
    :param limit:
    :param sort:
    :param search:
    :param query:
    """
    f_kwargs = {'agent_id': agent_id,
                'name': name,
                'description': description,
                'references': references,
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'query': query}

    dapi = DistributedAPI(f=sca.get_sca_checks,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = format_data(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_sca_checks(agent_id=None, pretty=False, wait_for_complete=False,
                   policy_id=None, title=None, description=None,
                   rationale=None, remediation=None, process=None,
                   directory=None, registry=None, references=None, result=None,
                   offset=0, limit=None, sort=None, search=None, query=None):
    """Get policy monitoring alerts for a given policy

    Returns the policy monitoring alerts for a given policy

    :param agent_id:
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param policy_id:
    :param title
    :param description:
    :param rationale:
    :param remediation:
    :param file
    :param process
    :param directory
    :param registry
    :param references:
    :param result:
    :param offset:
    :param limit:
    :param sort:
    :param search:
    :param query:
    """
    # get file parameter from query
    file_ = connexion.request.args.get('file', None)

    f_kwargs = {'agent_id': agent_id,
                'policy_id': policy_id,
                'title': title,
                'description': description,
                'rationale': rationale,
                'remediation': remediation,
                'file': file_,
                'process': process,
                'directory': directory,
                'registry': registry,
                'references': references,
                'result': result,
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'query': query}

    dapi = DistributedAPI(f=sca.get_sca_checks,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = format_data(loop.run_until_complete(dapi.distribute_function()))

    return data, 200
