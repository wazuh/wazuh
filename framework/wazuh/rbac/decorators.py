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
agent_expand = False
role_expand = False
policy_expand = False


class Resource:
    def __init__(self, resource):
        split_resource = resource.split(':')
        self.name_identifier = ':'.join(split_resource[0:2])
        self.value = split_resource[2]
        self.resource_function = None
        global agents, roles, policies, agent_expand, role_expand, policy_expand
        if 'agent' in self.name_identifier and not agent_expand:
            self.resource_function = _agent_expand_permissions
            agent_expand = True
            if agents is None:
                agents = get_agents_info()
                agents_ids = set()
                for agent in agents:
                    agents_ids.add(str(agent['id']).zfill(3))
                agents = agents_ids
        elif 'role' in self.name_identifier and not role_expand:
            self.resource_function = _role_expand_permissions
            role_expand = True
            roles_ids = set()
            with RolesManager() as rm:
                roles = rm.get_roles()
            for role in roles:
                roles_ids.add(str(role.id))
            roles = roles_ids
        elif 'policy' in self.name_identifier and not policy_expand:
            self.resource_function = _policy_expand_permissions
            policy_expand = True
            policy_ids = set()
            with PoliciesManager() as pm:
                policies = pm.get_policies()
            for policy in policies:
                policy_ids.add(str(policy.id))
            policies = policy_ids

    def get_name_identifier(self):
        return self.name_identifier

    def get_value(self):
        return self.value

    def get_function(self, mode, odict):
        try:
            return self.resource_function(mode, odict)
        except Exception:
            pass


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

    # At the moment it is only used for groups
    global agents
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


def _role_expand_permissions(mode, odict):
    global roles
    _normalization('role:id', odict)

    for role_key in odict:
        _update_set(role_key, 'allow', roles, odict) if '*' in odict[role_key]['allow'] \
            else _update_set(role_key, 'deny', roles, odict)

    _update_set('role:id', 'allow', roles, odict, False) if mode \
        else _update_set('role:id', 'deny', roles, odict, False)

    return odict


def _policy_expand_permissions(mode, odict):
    global policies
    _normalization('policy:id', odict)

    for policy_key in odict:
        _update_set(policy_key, 'allow', policies, odict) if '*' in odict[policy_key]['allow'] \
            else _update_set(policy_key, 'deny', policies, odict)

    _update_set('role:id', 'allow', policies, odict, False) if mode \
        else _update_set('role:id', 'deny', policies, odict, False)

    return odict


def _match_permissions(req_permissions: dict = None, rbac: list = None):
    """Try to match function required permissions against user permissions to allow or deny execution

    :param req_permissions: Required permissions to allow function execution
    :param rbac: User permissions
    :return: Allow or deny
    """
    mode, user_permissions = rbac
    allow_match = dict()
    for req_action, req_resources in req_permissions.items():
        actual_index = 0
        for req_resource in req_resources:
            try:
                final_user_permissions = set()
                user_resources = user_permissions[req_action]
                r_resource = Resource(req_resource)
                r_resource.get_function(mode, user_resources)
                final_user_permissions.update(
                    set(user_resources[r_resource.get_name_identifier()]['allow']) -
                    set(user_resources[r_resource.get_name_identifier()]['deny']))
                reqs = user_resources[r_resource.get_name_identifier()]['allow'] if req_resource.split(':')[-1] == '*'\
                    else [req_resource]
                if r_resource.get_name_identifier() not in allow_match.keys():
                    allow_match[r_resource.get_name_identifier()] = list()
                for req in reqs:
                    split_req = req.split(':')[-1]
                    if split_req in final_user_permissions:
                        allow_match[r_resource.get_name_identifier()].append(split_req)
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
            allow = _match_permissions(req_permissions=req_permissions, rbac=copy.deepcopy(kwargs['rbac']))
            del kwargs['rbac']
            for index, target in enumerate(target_param):
                try:
                    if len(allow[list(allow.keys())[index]]) == 0:
                        raise Exception
                    kwargs[target] = allow[list(allow.keys())[index]]
                except Exception:
                    raise WazuhError(4000)
            return func(*args, **kwargs)
        return wrapper
    return decorator
