# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import re
from functools import wraps

from wazuh.exception import WazuhError
from wazuh.core.core_utils import get_agents_info, expand_group
from wazuh.rbac.orm import RolesManager, PoliciesManager

agents = None
roles = None
policies = None


def _get_required_permissions(actions: list = None, resources: list = None, **kwargs):
    """Obtain action:resource pairs exposed by the framework function

    :param actions: List of exposed actions
    :param resources: List of exposed resources
    :param kwargs: Function kwargs to look for dynamic resources
    :return: Dictionary with required actions as keys and a list of required resources as values
    """
    # We expose required resources for the request
    res_list = list()
    for resource in resources:
        m = re.search(r'^(\w+:\w+:)(\w+|\*|{(\w+)})$', resource)
        res_base = m.group(1)
        # If we find a '{' in the regex we obtain the dynamic resource/s
        if '{' in m.group(2):
            try:
                # Dynamic resources ids are found within the {}
                params = kwargs[m.group(3)]
                # We check if params is a list of resources or a single one in a string
                if isinstance(params, list):
                    if len(params) == 0:
                        raise WazuhError(4015, extra_message={'param': m.group(3)})
                    for param in params:
                        res_list.append("{0}{1}".format(res_base, param))
                else:
                    res_list.append("{0}{1}".format(res_base, params))
            # KeyError occurs if required dynamic resources can't be found within request parameters
            except KeyError as e:
                raise WazuhError(4014, extra_message={'param': m.group(3)})
        # If we don't find a regex match we obtain the static resource/s
        else:
            res_list.append(resource)

    # Create dict of required policies with action: list(resources) pairs
    req_permissions = dict()
    for action in actions:
        req_permissions[action] = res_list

    return req_permissions


def _update_set(index, key_effect, to_add, odict, remove=True):
    op_key = 'deny' if key_effect == 'allow' else 'allow'
    try:
        if remove:
            odict[index][key_effect].remove('*')
        for element in to_add:
            if element not in odict[index][op_key]:
                odict[index][key_effect].add(element)
    except:
        pass


def _normalization(key, permissions):
    for resource in permissions:
        permissions[resource]['allow'] = set(permissions[resource]['allow'])
        permissions[resource]['deny'] = set(permissions[resource]['deny'])
    if key not in permissions.keys():
        permissions[key] = {
            'allow': set(),
            'deny': set()
        }


def _agent_expand_permissions(mode, odict):
    def _cleaner(odict_clean, list_to_delete):
        for key_to_delete in list_to_delete:
            odict_clean.pop(key_to_delete)

    global agents
    if agents is None:
        agents = get_agents_info()
        agents_ids = set()
        for agent in agents:
            agents_ids.add(str(agent['id']).zfill(3))
        agents = agents_ids

    # At the moment it is only used for groups
    clean = set()
    _normalization('agent:id', odict)

    for key in odict:
        if key == 'agent:id':
            _update_set(key, 'allow', agents, odict) if '*' in odict[key]['allow'] \
                else _update_set(key, 'deny', agents, odict)
        elif key == 'agent:group':
            clean.add(key)
            expand_group(odict['agent:group'], odict['agent:id'])

    _update_set('agent:id', 'allow', agents, odict, False) if mode \
        else _update_set('agent:id', 'deny', agents, odict, False)
    _cleaner(odict, clean)

    return odict


def _role_policy_expand_permissions(mode, odict, resource_prefix):
    global roles
    if roles is None:
        with RolesManager() as rm:
            roles = rm.get_roles()
    roles_ids = set()
    for role in roles:
        roles_ids.add(str(role.id))
    global policies
    if policies is None:
        with PoliciesManager() as pm:
            policies = pm.get_policies()
    policies_ids = set()
    for policy in policies:
        policies_ids.add(str(policy.id))

    _normalization(resource_prefix, odict)

    for key in odict:
        _update_set(key, 'allow', roles_ids, odict) if '*' in odict[key]['allow'] \
            else _update_set(key, 'deny', roles_ids, odict)
        _update_set(key, 'allow', policies_ids, odict) if '*' in odict[key]['allow'] \
            else _update_set(key, 'deny', policies_ids, odict)

    _update_set('role:id', 'allow', roles_ids, odict, False) if mode \
        else _update_set('role:id', 'deny', roles_ids, odict, False)
    _update_set('role:id', 'allow', policies_ids, odict, False) if mode \
        else _update_set('role:id', 'deny', policies_ids, odict, False)

    return odict


def _match_permissions(req_permissions: dict = None, rbac: list = None):
    """Try to match function required permissions against user permissions to allow or deny execution

    :param req_permissions: Required permissions to allow function execution
    :param rbac: User permissions
    :return: Allow or deny
    """
    mode, user_permissions = rbac
    # allow_match = list()
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    allow_match = [list() * len(req_permissions)]
    actual_index = 0
    for req_action, req_resources in req_permissions.items():
        agent_expand = False
        role_policy_expand = False
        for req_resource in req_resources:
            try:
                user_resources = user_permissions[req_action]
                m = re.search(r'^(\w+:\w+)(:)([\w\-./]+|\*)$', req_resource)
                action = ''
                final_user_permissions = set()
                if m.group(1) == 'agent:id' or m.group(1) == 'agent:group':
                    # Expand * for agent:id and agent:group
                    if not agent_expand:
                        _agent_expand_permissions(mode, user_resources)
                        agent_expand = True
                    action = 'agent:id'
                    global agents
                    if req_resource.split(':')[-1] != '*' and req_resource.split(':')[-1] not in agents:
                        final_user_permissions.add(req_resource.split(':')[-1])
                # Provisional
                elif m.group(1) == 'role:id' or m.group(1) == 'policy:id':
                    if not role_policy_expand:
                        _role_policy_expand_permissions(mode, user_resources, m.group(1))
                        role_policy_expand = True
                    action = m.group(1)
                final_user_permissions.update(user_resources[action]['allow'] - user_resources[action]['deny'])
                reqs = user_resources[action]['allow'] if req_resource.split(':')[-1] == '*' else [req_resource]
                for req in reqs:
                    split_req = req.split(':')[-1]
                    if split_req in final_user_permissions:
                        allow_match[actual_index].append(split_req)
            except KeyError:
                if mode:  # For black mode, if the resource is not specified, it will be allow
                    allow_match.append('*')
                    break
        actual_index += 1
    return allow_match


def expose_resources(actions: list = None, resources: list = None, target_param: list = None):
    """Decorator to apply user permissions on a Wazuh framework function based on exposed action:resource pairs.

    :param actions: List of actions exposed by the framework function
    :param resources: List of resources exposed by the framework function
    :param target_param: Name of the input parameter used to calculate resource access
    :return: Allow or deny framework function execution
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            req_permissions = _get_required_permissions(actions=actions, resources=resources, **kwargs)
            import pydevd_pycharm
            pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
            allow = _match_permissions(req_permissions=req_permissions, rbac=copy.deepcopy(kwargs['rbac']))
            del kwargs['rbac']
            for index, target in enumerate(target_param):
                try:
                    if len(allow[index]) == 0:
                        raise Exception
                    kwargs[target] = allow[index]
                except Exception:
                    raise WazuhError(4000)
            return func(*args, **kwargs)
        return wrapper
    return decorator
