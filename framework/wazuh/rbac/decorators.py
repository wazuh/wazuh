# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import re
from functools import wraps

from wazuh.exception import WazuhError, WazuhInternalError
from wazuh.fcore.core_utils import get_agents_info, expand_group

agents = None


def _get_required_permissions(actions: list = None, resources: str = None, **kwargs):
    """Obtain action:resource pairs exposed by the framework function

    :param actions: List of exposed actions
    :param resources: List of exposed resources
    :param kwargs: Function kwargs to look for dynamic resources
    :return: Dictionary with required actions as keys and a list of required resources as values
    """
    # We expose required resources for the request
    m = re.search(r'^(\w+:\w+:)(\w+|\*|{(\w+)})$', resources)
    res_list = list()
    res_base = m.group(1)
    # If we find a '{' in the regex we obtain the dynamic resource/s
    if '{' in m.group(2):
        try:
            # Dynamic resources ids are found within the {}
            params = kwargs[m.group(3)]
            # We check if params is a list of resources or a single one in a string
            if isinstance(params, list):
                for param in params:
                    res_list.append("{0}{1}".format(res_base, param))
            else:
                res_list.append("{0}{1}".format(res_base, params))
        # KeyError occurs if required dynamic resources can't be found within request parameters
        except KeyError as e:
            raise WazuhInternalError(4014, extra_message=str(e))
    # If we don't find a regex match we obtain the static resource/s
    else:
        res_list.append(resources)

    # Create dict of required policies with action: list(resources) pairs
    req_permissions = dict()
    for action in actions:
        req_permissions[action] = res_list

    return req_permissions


def _expand_permissions(mode, odict):
    def _to_set(permissions):
        permissions['allow'] = set(permissions['allow'])
        permissions['deny'] = set(permissions['deny'])

    def _update_set(index, key_effect, agents_ids_to_add, remove=True):
        op_key = 'deny' if key_effect == 'allow' else 'allow'
        if remove:
            odict[index][key_effect].remove('*')
        for agent_id in agents_ids_to_add:
            if agent_id not in odict[index][op_key]:
                odict[index][key_effect].add(agent_id)

    def _cleaner(odict_clean, list_to_delete):
        for key_to_delete in list_to_delete:
            odict_clean.pop(key_to_delete)

    global agents
    if agents is None:
        agents = get_agents_info()
    agents_ids = list()
    for agent in agents:
        agents_ids.append(str(agent['id']).zfill(3))

    # At the moment it is only used for groups
    clean = set()

    for key in odict:
        if key == 'agent:id':
            _to_set(odict[key])
            _update_set(key, 'allow', agents_ids) if '*' in odict[key]['allow'] \
                else _update_set(key, 'deny', agents_ids)
        elif key == 'agent:group':
            clean.add(key)
            _to_set(odict[key])
            if 'agent:id' not in odict.keys():
                odict['agent:id'] = {
                    'allow': set(),
                    'deny': set()
                }
            expand_group(odict['agent:group'], odict['agent:id'])

    _update_set('agent:id', 'allow', agents_ids, False) if mode \
        else _update_set('agent:id', 'deny', agents_ids, False)
    _cleaner(odict, clean)

    return odict


def _match_permissions(req_permissions: dict = None, rbac: list = None):
    """Try to match function required permissions against user permissions to allow or deny execution

    :param req_permissions: Required permissions to allow function execution
    :param rbac: User permissions
    :return: Allow or deny
    """
    mode, user_permissions = rbac
    allow_match = list()
    for req_action, req_resources in req_permissions.items():
        agent_expand = False
        for req_resource in req_resources:
            try:
                user_resources = user_permissions[req_action]
                m = re.search(r'^(\w+:\w+)(:)([\w\-./]+|\*)$', req_resource)
                if m.group(1) == 'agent:id' or m.group(1) == 'agent:group':
                    # Expand * for agent:id and agent:group
                    if not agent_expand:
                        _expand_permissions(mode, user_resources)
                        agent_expand = True
                    if req_resource.split(':')[-1] == '*':  # Expand
                        reqs = user_resources[m.group(1)]['allow']
                    else:
                        reqs = [req_resource]
                    for req in reqs:
                        split_req = req.split(':')[-1]
                        if split_req in user_resources['agent:id']['allow'] and \
                                split_req not in user_resources['agent:id']['deny']:
                            allow_match.append(split_req)
                elif m.group(3) != '*':
                    allow_match.append(m.group(3) in user_resources[m.group(1)]['allow']) or \
                                ('*' in user_resources[m.group(1)]['allow'])
                else:
                    allow_match.append('*' in user_resources[m.group(1)]['allow'])
            except KeyError:
                if mode:  # For black mode, if the resource is not specified, it will be allow
                    allow_match.append('*')
                    break
    return allow_match


def expose_resources(actions: list = None, resources: str = None, resource_name: str = None):
    """Decorator to apply user permissions on a Wazuh framework function based on exposed action:resource pairs.

    :param actions: List of actions exposed by the framework function
    :param resources: List of resources exposed by the framework function
    :param resource_name: Name of the input parameter used to calculate resource access
    :return: Allow or deny framework function execution
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            req_permissions = _get_required_permissions(actions=actions, resources=resources, **kwargs)
            allow = _match_permissions(req_permissions=req_permissions, rbac=copy.deepcopy(kwargs['rbac']))
            if len(allow) > 0:
                del kwargs['rbac']
                kwargs[resource_name] = allow
                return func(*args, **kwargs)
            else:
                raise WazuhError(4000)
        return wrapper
    return decorator
