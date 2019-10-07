# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import re
from functools import wraps

from api.authentication import AuthenticationManager
from wazuh.core.core_utils import get_agents_info, expand_group, get_groups
from wazuh.exception import WazuhError, create_exception_dic
from wazuh.rbac.orm import RolesManager, PoliciesManager
from wazuh.results import WazuhResult

mode = 'white'


def mode_changer(m):
    if m != 'white' and m != 'black':
        raise TypeError
    global mode
    mode = m


def _expand_resource(resource):
    name, attribute, value = resource.split(':')
    resource_type = ':'.join([name, attribute])

    if resource_type == 'agent:group':
        return expand_group(value)

    if value == '*':
        if resource_type == 'agent:id':
            return get_agents_info()
        elif resource_type == 'group:id':
            return get_groups()
        elif resource_type == 'role:id':
            with RolesManager() as rm:
                return rm.get_roles()
        elif resource_type == 'policy:id':
            with PoliciesManager() as pm:
                return pm.get_policies()
        elif resource_type == 'user:id':
            users_system = set()
            with AuthenticationManager() as auth:
                users = auth.get_users()
            for user in users:
                users_system.add(user['username'])
            return users_system
    else:
        return {value}


def use_expanded_resource(effect, final_permissions, expanded_resource, req_resources_value, delete):
    if '*' not in req_resources_value:
        expanded_resource = expanded_resource.intersection(req_resources_value)
    if effect == 'allow':
        final_permissions.update(expanded_resource)
    elif delete:
        final_permissions.clear()
    else:
        final_permissions.difference_update(expanded_resource)


def expand_permissions(req_resources, user_permissions_for_resource, final_user_permissions):
    req_resources_value = dict()
    for element in req_resources:
        if ':'.join(element.split(':')[:-1]) not in req_resources_value.keys():
            req_resources_value[':'.join(element.split(':')[:-1])] = set()
        req_resources_value[':'.join(element.split(':')[:-1])].add(element.split(':')[-1])
    for user_resource, user_resource_effect in user_permissions_for_resource.items():
        name, attribute, value = user_resource.split(':')
        identifier = name + ':' + attribute
        if name + ':' + attribute == 'agent:group':
            identifier = 'agent:id'
        if identifier not in final_user_permissions.keys():
            final_user_permissions[identifier] = set()

        if mode == 'black':
            final_user_permissions[identifier] = _expand_resource(identifier + ':*')
        expanded_resource = _expand_resource(user_resource)
        try:
            if user_resource_effect == 'allow' and '*' not in req_resources_value[identifier] and value == '*':
                final_user_permissions[identifier].update(req_resources_value[identifier] - expanded_resource)
            use_expanded_resource(user_resource_effect, final_user_permissions[identifier],
                                  expanded_resource, req_resources_value[identifier],
                                  value == '*' and user_resource_effect == 'deny')
        except KeyError:  # Multiples resources in action and only one is required
            if len(final_user_permissions[identifier]) == 0:
                final_user_permissions.pop(identifier)
        if mode == 'black':
            try:
                if value in final_user_permissions[identifier]:
                    final_user_permissions[identifier] = {value}
                elif '*' not in req_resources_value[identifier] and \
                        not final_user_permissions[identifier].issubset(req_resources_value[identifier]):
                    final_user_permissions[identifier] = set()
            except KeyError:
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
                if len(params) == 0:
                    raise WazuhError(4015, extra_message={'param': m.group(3)})
                for param in params:
                    res_list.append("{0}{1}".format(res_base, param))
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
    for req_action, req_resources in req_permissions.items():
        if req_action in rbac.keys():
            expand_permissions(req_resources, rbac[req_action], allow_match)
        else:
            for req_resource in req_resources:
                allow_match[':'.join(req_resource.split(':')[:-1])] = _expand_resource(req_resource)
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
            import pydevd_pycharm
            pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
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
