# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import re
from functools import wraps

from wazuh.exception import WazuhError, create_exception_dic
from wazuh.core.core_utils import get_agents_info, expand_group
from wazuh.rbac.orm import RolesManager, PoliciesManager
from wazuh.results import WazuhResult


mode = 'white'


class Resource:
    def __init__(self, resource):
        split_resource = resource.split(':')
        self.name_identifier = ':'.join(split_resource[0:2])
        self.value = split_resource[2]
        if 'agent' in self.name_identifier:
            self.agents = get_agents_info()
        elif 'role' in self.name_identifier:
            roles_ids = set()
            with RolesManager() as rm:
                roles = rm.get_roles()
            for role in roles:
                roles_ids.add(str(role.id))
            self.roles = roles_ids
        elif 'policy' in self.name_identifier:
            policy_ids = set()
            with PoliciesManager() as pm:
                policies = pm.get_policies()
            for policy in policies:
                policy_ids.add(str(policy.id))
            self.policies = policy_ids

    def get_name_identifier(self):
        return self.name_identifier

    def get_value(self):
        return self.value

    def exec_expand_function(self, rbac_mode, final_permissions, odict):
        if self.name_identifier not in final_permissions.keys():
            final_permissions[self.name_identifier] = set()
        if self.name_identifier == 'agent:id' or self.name_identifier == 'agent:group':
            self._agent_expand_permissions(rbac_mode, final_permissions[self.name_identifier], odict)
        elif self.name_identifier == 'role:id':
            final_permissions[self.name_identifier] = self._role_policy_expand_permissions(
                rbac_mode, final_permissions[self.name_identifier], odict, 'role')
        elif self.name_identifier == 'policy:id':
            self._role_policy_expand_permissions(rbac_mode, final_permissions[self.name_identifier], odict,
                                                 'policy')

    def _agent_expand_permissions(self, rbac_mode, final_permissions, odict):
        for key, value in odict.items():
            if key.startswith('agent:group'):
                expanded_group = expand_group(key.split(':')[-1])
                for agent in expanded_group:
                    final_permissions.add(agent) if value == 'allow' and agent == self.value \
                        else final_permissions.discard(agent)
            elif key.startswith('agent:id:*'):
                for agent in self.agents:
                    final_permissions.add(agent) if value == 'allow' and agent == self.value \
                        else final_permissions.discard(agent)
                if value == 'allow':
                    final_permissions.add(self.value)
            elif key.startswith('agent:id'):
                if value == 'allow' and self.value == key.split(':')[-1]:
                    final_permissions.add(key.split(':')[-1])
                elif value == 'deny':
                    final_permissions.discard(key.split(':')[-1])
        if rbac_mode == 'black':
            for agent in self.agents:
                final_permissions.add(agent)

        return final_permissions

    def _role_policy_expand_permissions(self, rbac_mode, final_permissions, odict, resource_type):
        system_resources = self.roles if resource_type == 'role' else self.policies
        for key, value in odict.items():
            if key.startswith(resource_type + ':id:*'):
                for role_policy in system_resources:
                    final_permissions.add(role_policy) if value == 'allow' and self.value == role_policy \
                        else final_permissions.discard(role_policy)
                if value == 'allow':
                    final_permissions.add(self.value)
            elif key.startswith(resource_type + ':id'):
                final_permissions.add(key.split(':')[-1]) if value == 'allow' and self.value == key.split(':')[-1] \
                    else final_permissions.discard(key.split(':')[-1])
        if rbac_mode == 'black':
            for policy in system_resources:
                final_permissions.add(policy)

        return final_permissions


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
            except KeyError:
                raise WazuhError(4014, extra_message={'param': m.group(3)})
        # If we don't find a regex match we obtain the static resource/s
        else:
            res_list.append(resource)

    # Create dict of required policies with action: list(resources) pairs
    req_permissions = dict()
    for action in actions:
        req_permissions[action] = res_list

    return req_permissions


def _match_permissions(req_permissions: dict = None, rbac: list = None):
    """Try to match function required permissions against user permissions to allow or deny execution
    :param req_permissions: Required permissions to allow function execution
    :param rbac: User permissions
    :return: Allow or deny
    """
    import pydevd_pycharm
    pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    allow_match = dict()
    black_counter = 0
    if mode == 'black':  # Black
        if len(rbac.keys()) == 0:
            allow_match['black:mode'] = '*'
            return allow_match
    for req_action, req_resources in req_permissions.items():
        actual_actions = list()
        for user_action, user_resources in rbac.items():
            if req_action == user_action:
                actual_actions.append(req_action)
            elif req_action.split(':')[0] == user_action.split(':')[0] and user_action.split(':')[1] == '*':
                actual_actions.append(req_action.split(':')[0] + ':*')
        for action in actual_actions:
            for req_resource in req_resources:
                r_resource = Resource(req_resource)
                r_resource.exec_expand_function(mode, allow_match, rbac[action])
        else:
            if mode == 'black':
                black_counter += 1
                if len(req_resources) == black_counter:
                    allow_match['black:mode'] = '*'
            else:
                break
    return allow_match


def expose_resources(actions: list = None, resources: list = None, target_params: list = None,
                     post_proc_func: callable = None, post_proc_kwargs: dict = None):
    """Decorator to apply user permissions on a Wazuh framework function based on exposed action:resource pairs.

    :param actions: List of actions exposed by the framework function
    :param resources: List of resources exposed by the framework function
    :param target_params: Name of the input parameters used to calculate resource access
    :param post_proc_func: Name of the function to use in response post processing
    :param post_proc_kwargs: Extra parameters used in post processing
    :return: Allow or deny framework function execution
    """
    if post_proc_kwargs is None:
        post_proc_kwargs = dict()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            req_permissions = _get_required_permissions(actions=actions, resources=resources, **kwargs)
            allow = _match_permissions(req_permissions=req_permissions, rbac=copy.deepcopy(kwargs['rbac']))
            del kwargs['rbac']
            original_kwargs = copy.deepcopy(kwargs)
            if 'black:mode' not in allow.keys():  # Black flag not in allow
                for index, target in enumerate(target_params):
                    try:
                        if len(allow[list(allow.keys())[index]]) == 0:
                            raise Exception
                        kwargs[target] = list(allow[list(allow.keys())[index]])
                    except Exception:
                        raise WazuhError(4000)
            result = func(*args, **kwargs)
            if post_proc_func is None:
                return result
            else:
                return post_proc_func(result, original=original_kwargs, allowed=allow, target=target_params,
                                      **post_proc_kwargs)
        return wrapper
    return decorator


def list_handler_with_denied(result, original: dict = None, allowed: dict = None, target: list = None,
                             **post_proc_kwargs):
    """ Post processor for framework list responses with affected items and failed items

    :param result: Dict with affected_items, failed_items and str_priority
    :param original: Original input call parameter values
    :param allowed: Allowed input call parameter values
    :param target: Name of the input parameters used to calculate resource access
    :return: WazuhResult
    """
    if len(target) == 1:
        original_kwargs = original[target[0]] if isinstance(original[target[0]], list) else [original[target[0]]]
        difference = list(set(original_kwargs) - set(list(allowed[list(allowed.keys())[0]])))
        if len(difference) > 0:
            result['failed_items'].append(create_exception_dic(difference, WazuhError(4000)))
    else:
        original_kwargs = original[target[1]] if isinstance(original[target[1]], list) else [original[target[1]]]
        difference = list(set(original_kwargs) - set(list(allowed[list(allowed.keys())[1]])))
        if len(difference) > 0:
            result['failed_items'].append(
                create_exception_dic('{}:{}'.format(original[target[0]], difference), WazuhError(4000)))

    return data_response_builder(result, original, **post_proc_kwargs)


def list_handler_no_denied(result, original: dict = None, allowed: dict = None, target: list = None,
                           **post_proc_kwargs):
    """ Post processor for framework list responses with only affected items

    :param result: List with affected_items, failed_items and str_priority
    :param original: Original input call parameter values
    :return: WazuhResult
    """
    return data_response_builder(result, original, **post_proc_kwargs)


def data_response_builder(result, original: dict = None, **post_proc_kwargs):
    """

    :param result: List with affected_items, failed_items and str_priority
    :param original: Original input call parameter values
    :return: WazuhResult
    """
    final_dict = {'data': {'affected_items': result['affected_items'],
                           'total_affected_items': len(result['affected_items'])}
                  }
    if result['failed_items']:
        final_dict['data']['failed_items'] = result['failed_items']
        final_dict['data']['total_failed_items'] = len(result['failed_items'])
        final_dict['message'] = result['str_priority'][2] if not result['affected_items'] else result['str_priority'][1]
    else:
        final_dict['message'] = result['str_priority'][2] if not result['affected_items'] else result['str_priority'][0]
    if 'extra_fields' in post_proc_kwargs.keys():
        for item in post_proc_kwargs['extra_fields']:
            final_dict['data'][item] = original[item]

    return WazuhResult(final_dict, str_priority=result['str_priority'])
