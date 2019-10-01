# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import re
from functools import wraps

from api.authentication import AuthenticationManager
from wazuh.core.core_utils import get_agents_info, expand_group
from wazuh.exception import WazuhError, create_exception_dic
from wazuh.rbac.orm import RolesManager, PoliciesManager
from wazuh.results import WazuhResult

mode = 'white'


class Resource:
    def __init__(self, resource):
        split_resource = resource.split(':')
        self.name = split_resource[0]
        self.name_identifier = ':'.join(split_resource[0:2])
        self.value = split_resource[2]
        self.resources = set()
        if 'agent' in self.name_identifier:
            self.resources = get_agents_info()
        elif 'role' in self.name_identifier:
            with RolesManager() as rm:
                roles = rm.get_roles()
            for role in roles:
                self.resources.add(str(role.id))
        elif 'policy' in self.name_identifier:
            with PoliciesManager() as pm:
                policies = pm.get_policies()
            for policy in policies:
                self.resources.add(str(policy.id))
        elif 'user' in self.name_identifier:
            with AuthenticationManager() as auth:
                users = auth.get_users()
            for user in users:
                self.resources.add(user['username'])

    def get_name_identifier(self):
        return self.name_identifier

    def get_value(self):
        return self.value

    def expand_permissions(self, rbac_mode, final_permissions, odict):
        for key, value in odict.items():
            if key.startswith('agent:group'):
                expanded_group = expand_group(key.split(':')[-1])
                for agent in expanded_group:
                    final_permissions.add(agent) if value == 'allow' and agent == self.value \
                        else final_permissions.discard(agent)
            elif key.startswith(self.name + ':id:*'):
                for resource in self.resources:
                    if value == 'allow':
                        if self.value == resource:
                            final_permissions.add(resource)
                        elif self.value == '*':
                            final_permissions.update(self.resources)
                            break
                    else:
                        final_permissions.discard(resource)
                if value == 'allow' and self.value != '*':
                    final_permissions.add(self.value)
            elif key.startswith(self.name + ':id'):
                if value == 'allow' and (self.value == key.split(':')[-1] or self.value == '*'):
                    final_permissions.add(key.split(':')[-1])
                else:
                    final_permissions.discard(key.split(':')[-1])
        if rbac_mode == 'black':
            for resource in self.resources:
                final_permissions.add(resource)

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
    :return: Dictionary with final permissions
    """
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
                if r_resource.get_name_identifier() not in allow_match.keys():
                    allow_match[r_resource.get_name_identifier()] = set()
                r_resource.expand_permissions(mode, allow_match[r_resource.get_name_identifier()], rbac[action])
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


def merge_errors(failed_items):
    code_ids = dict()
    for index, failed_item in enumerate(failed_items):
        if failed_item['error']['code'] not in code_ids.keys():
            code_ids[failed_item['error']['code']] = dict()
            code_ids[failed_item['error']['code']]['ids'] = list()
            code_ids[failed_item['error']['code']]['index'] = index
        code_ids[failed_item['error']['code']]['ids'].append(failed_item['id'])
    final_errors_list = list()
    error_count = 0
    for key, error_code in code_ids.items():
        final_errors_list.append(failed_items[error_code['index']])
        for item_id in error_code['ids']:
            if not isinstance(final_errors_list[-1]['id'], list):
                final_errors_list[-1]['id'] = list()
            final_errors_list[-1]['id'].append(item_id)
        error_count += len(error_code['ids'])

    return final_errors_list, error_count


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
        for item in set(original_kwargs) - set(list(allowed[list(allowed.keys())[0]])):
            result['failed_items'].append(create_exception_dic(item, WazuhError(4000)))
    else:
        original_kwargs = original[target[1]] if isinstance(original[target[1]], list) else list(original[target[1]])
        for item in set(original_kwargs) - set(list(allowed[list(allowed.keys())[1]])):
            result['failed_items'].append(create_exception_dic('{}:{}'.format(original[target[0]], item),
                                                               WazuhError(4000)))

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
        failed_result = merge_errors(result['failed_items'])
        final_dict['data']['failed_items'] = failed_result[0]
        final_dict['data']['total_failed_items'] = failed_result[1]
        final_dict['message'] = result['str_priority'][2] if not result['affected_items'] else result['str_priority'][1]
    else:
        final_dict['message'] = result['str_priority'][2] if not result['affected_items'] else result['str_priority'][0]
    if 'extra_fields' in post_proc_kwargs.keys():
        for item in post_proc_kwargs['extra_fields']:
            final_dict['data'][item] = original[item]

    return WazuhResult(final_dict, str_priority=result['str_priority'])
