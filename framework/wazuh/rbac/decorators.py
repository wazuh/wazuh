# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import copy
import re
from functools import wraps

from api.authentication import AuthenticationManager
from wazuh.common import rbac, system_agents, system_groups, broadcast
from wazuh.core.core_utils import get_agents_info, expand_group, get_groups
from wazuh.exception import WazuhError, create_exception_dic
from wazuh.rbac.orm import RolesManager, PoliciesManager
from wazuh.results import AffectedItemsWazuhResult

#mode = configuration.read_api_config()['rbac']['mode']
mode = 'white'


def switch_mode(m):
    """This function is used to change the RBAC's mode
    :param m: New RBAC's mode (white or black)
    """
    if m != 'white' and m != 'black':
        raise TypeError
    global mode
    mode = m


def _expand_resource(resource):
    """This function expand a specified resource depending of it type.
    :param resource: Resource to be expanded
    :return expanded_resource: Returns the result of the resource expansion
    """
    name, attribute, value = resource.split(':')
    resource_type = ':'.join([name, attribute])

    # Set agents context variable
    if resource_type == 'agent:id':
        system_agents.set(get_agents_info())

    # This is the special case, expand_group can receive * or the name of the group. That's why it' s always called
    if resource_type == 'agent:group':
        system_agents.set(get_agents_info())
        return expand_group(value)

    # Set groups context variable
    if resource_type == 'group:id':
        system_groups.set(get_groups())

    # We need to transform the wildcard * to the resource of the system
    if value == '*':
        if resource_type == 'agent:id':
            return system_agents.get()
        elif resource_type == 'group:id':
            return system_groups.get()
        elif resource_type == 'role:id':
            with RolesManager() as rm:
                roles = rm.get_roles()
            return [role_id.id for role_id in roles]
        elif resource_type == 'policy:id':
            with PoliciesManager() as pm:
                policies = pm.get_policies()
            return [policy_id.id for policy_id in policies]
        elif resource_type == 'user:id':
            users_system = set()
            with AuthenticationManager() as auth:
                users = auth.get_users()
            for user in users:
                users_system.add(user['username'])
            return users_system
        return set()
    # We return the value casted to set
    else:
        return {value}


def _use_expanded_resource(effect, final_permissions, expanded_resource, req_resources_value, delete):
    """After expanding the user permissions, depending on the effect of these we will introduce
    them or not in the list of final permissions.
    :param effect: This is the effect of these permissions (allow/deny)
    :param final_permissions: Dictionary with the final permissions of the user
    :param expanded_resource: Dictionary with the result of the permissions's expansion
    :param req_resources_value: Dictionary with the required permissions for the input of the user
    :param delete: (True/False) Flag that indicates if the actual permission is deny all (True -> Delete permissions) or
    is allow (False -> No delete permissions)
    """
    # If the wildcard * not in required resource, we must do an intersection for obtain only the required permissions
    # between all the user' resources
    if '*' not in req_resources_value:
        expanded_resource = expanded_resource.intersection(req_resources_value)
    # If the effect is allow, we insert the expanded resource in the final user permissions
    if effect == 'allow':
        final_permissions.update(expanded_resource)
    # If the policy is deny the resource, the final permissions must be cleared
    elif delete:
        final_permissions.clear()
    # If the effect is deny, we are left with only the elements in final permissions and no in expanded resource
    else:
        final_permissions.difference_update(expanded_resource)


def _black_mode_expansion(final_user_permissions, identifier, black_negation):
    """We can see the black mode as a white mode in which the first of the policies is all allowed.
    Thus the white mode has become the black mode by allowing everything.
    Basically the black mode is the logical negation of the white mode.
    :param final_user_permissions: Dictionary with the final permissions of the user
    :param identifier: Resource identifier. Ex: agent:id
    :param black_negation: Set of already negative resources
    """
    if identifier not in black_negation:
        final_user_permissions[identifier] = _expand_resource(identifier + ':*')
        black_negation.add(identifier)


def _black_mode_sanitize(final_user_permissions, req_resources_value):
    """This function is responsible for sanitizing the output of the user's final permissions
    in black mode. Due to the logical negation of the white mode in order to have the black mode,
    we have that the final permissions have extra resources.
    Ex: The user want to read the agent 001 and its permissions are:
    agent:read {
        agent:id:005: allow
    }
    Due the RBAC is in black mode, the user can read all the users but he only want to see the agent 001, this function
    remove all the extra resources
    :param final_user_permissions: Dictionary with the final permissions of the user
    :param req_resources_value: Dictionary with the required permissions for the input of the user
    """
    for user_key in list(final_user_permissions.keys()):
        if user_key not in req_resources_value.keys():
            final_user_permissions.pop(user_key)
        elif req_resources_value[user_key] != {'*'}:
            final_user_permissions[user_key] = final_user_permissions[user_key].intersection(
                req_resources_value[user_key])


def _permissions_processing(req_resources, user_permissions_for_resource, final_user_permissions):
    """Given some required resources and the user's permissions on that resource,
    we extract the user's final permissions on the resource.
    :param req_resources: List of required resources
    :param user_permissions_for_resource: List of the users's permissions over the specified resource
    :param final_user_permissions: Dictionary where the final permissions will be inserted
    """
    req_resources_value = dict()
    for element in req_resources:
        if ':'.join(element.split(':')[:-1]) not in req_resources_value.keys():
            req_resources_value[':'.join(element.split(':')[:-1])] = set()
        req_resources_value[':'.join(element.split(':')[:-1])].add(element.split(':')[-1])
    # If RBAC policies is empty and the RBAC's mode is black, we have the permission over the required resource
    # or if we can't expand the resource, the action is resourceless
    if len(user_permissions_for_resource.keys()) == 0 and mode == 'black':
        for req_resource in req_resources:
            identifier = ':'.join(req_resource.split(':')[:-1])
            if identifier == '*:*':
                final_user_permissions['*:*'] = {'*'}
            else:
                expanded_resource = _expand_resource(req_resource)
                if identifier not in final_user_permissions.keys():
                    final_user_permissions[identifier] = set()
                final_user_permissions[identifier].update(expanded_resource)
    # RBAC policies are not empty or the mode is not black
    else:
        # With this set we know if a resource is already "deny"
        black_negation = set()
        for user_resource, user_resource_effect in user_permissions_for_resource.items():
            name, attribute, value = user_resource.split(':')
            identifier = name + ':' + attribute
            if identifier == 'agent:group':
                identifier = 'agent:id'
            if identifier not in final_user_permissions.keys():
                final_user_permissions[identifier] = set()
            # We expand the resource for the black mode, in this way,
            # we allow all permissions for the resource (black mode)
            mode == 'black' and _black_mode_expansion(final_user_permissions, identifier, black_negation)
            expanded_resource = _expand_resource(user_resource)
            try:
                if identifier == '*:*' or (user_resource_effect == 'allow' and
                                           '*' not in req_resources_value[identifier] and value == '*'):
                    final_user_permissions[identifier].update(req_resources_value[identifier] - expanded_resource)
                _use_expanded_resource(user_resource_effect, final_user_permissions[identifier],
                                       expanded_resource, req_resources_value[identifier],
                                       value == '*' and user_resource_effect == 'deny')
            except KeyError:  # Multiples resources in action and only one is required
                if len(final_user_permissions[identifier]) == 0:
                    final_user_permissions.pop(identifier)
        # If the black mode is enabled we need to sanity the output due the initial expansion
        # (allow all permissions over the resource)
        mode == 'black' and _black_mode_sanitize(final_user_permissions, req_resources_value)


def _get_required_permissions(actions: list = None, resources: list = None, **kwargs):
    """Resource pairs exposed by the framework function
    :param actions: List of exposed actions
    :param resources: List of exposed resources
    :param kwargs: Function kwargs to look for dynamic resources
    :return: Dictionary with required actions as keys and a list of required resources as values
    """
    # We expose required resources for the request
    res_list = list()
    target_params = dict()
    add_denied = True
    for resource in resources:
        m = re.search(r'^([a-z*]+:[a-z*]+):(\w+|\*|{(\w+)})$', resource)
        res_base = m.group(1)
        # If we find a '{' in the regex we obtain the dynamic resource/s
        if '{' in m.group(2):
            target_params[m.group(1)] = m.group(3)
            if m.group(3) in kwargs:
                # Dynamic resources ids are found within the {}
                params = kwargs[m.group(3)]
                if isinstance(params, list):
                    # We check if params is a list of resources or a single one in a string
                    if len(params) == 0:
                        raise WazuhError(4015, extra_message={'param': m.group(3)})
                    for param in params:
                        res_list.append("{0}:{1}".format(res_base, param))
                    add_denied = not broadcast.get()
                else:
                    if params is None or params == '*':
                        add_denied = True
                        params = '*'
                    else:
                        add_denied = not broadcast.get()
                    res_list.append("{0}:{1}".format(res_base, params))
            # KeyError occurs if required dynamic resources can't be found within request parameters
            else:
                add_denied = False
                params = '*'
                res_list.append("{0}:{1}".format(res_base, params))
        # If we don't find a regex match we obtain the static resource/s
        else:
            target_params[m.group(1)] = m.group(2)
            res_list.append(resource)
    # Create dict of required policies with action: list(resources) pairs
    req_permissions = dict()
    for action in actions:
        req_permissions[action] = res_list
    return target_params, req_permissions, add_denied


def _match_permissions(req_permissions: dict = None):
    """Try to match function required permissions against user permissions to allow or deny execution
    :param req_permissions: Required permissions to allow function execution
    :return: Dictionary with final permissions
    """
    allow_match = dict()
    for req_action, req_resources in req_permissions.items():
        try:
            _permissions_processing(req_resources, rbac.get()[req_action], allow_match)
        except KeyError:
            _permissions_processing(req_resources, dict(), allow_match)
    return allow_match


def list_handler(result: AffectedItemsWazuhResult, original: dict = None, allowed: dict = None, target: dict = None,
                 add_denied: bool = False,
                 **post_proc_kwargs):
    """ Post processor for framework list responses with affected items and optional denied items

    :param result: Dict with affected_items, failed_items and str_priority
    :param original: Original input call parameter values
    :param allowed: Allowed input call parameter values
    :param target: Name of the input parameters used to calculate resource access
    :param add_denied: Flag to add denied permissions to answer
    :return: WazuhResult
    """
    if add_denied:
        for res_id, target_param in target.items():
            try:
                denied = set(original[target_param]) - allowed[res_id]
            except KeyError:
                denied = set()
            for denied_item in denied:
                result.add_failed_item(id_=denied_item, error=WazuhError(4000,
                                                                         extra_message=f'Resource type: {res_id}'))
    else:
        if 'exclude_codes' in post_proc_kwargs:
            result.remove_failed_items(post_proc_kwargs['exclude_codes'])

    return result


def expose_resources(actions: list = None, resources: list = None, post_proc_func: callable = list_handler,
                     post_proc_kwargs: dict = None):
    """Decorator to apply user permissions on a Wazuh framework function
    based on exposed action:resource pairs.
    :param actions: List of actions exposed by the framework function
    :param resources: List of resources exposed by the framework function
    :param post_proc_func: Name of the function to use in response post processing
    :param post_proc_kwargs: Extra parameters used in post processing
    :return: Allow or deny framework function execution
    """
    if post_proc_kwargs is None:
        post_proc_kwargs = dict()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            target_params, req_permissions, add_denied = \
                _get_required_permissions(actions=actions, resources=resources, **kwargs)
            allow = _match_permissions(req_permissions=req_permissions)
            original_kwargs = copy.deepcopy(kwargs)

            for res_id, target_param in target_params.items():
                try:
                    # We don't have any permissions over the required resources
                    if len(allow[res_id]) == 0 and \
                            original_kwargs.get(target_param, None) is not None and \
                            len(original_kwargs[target_param]) != 0:
                        raise Exception
                    if target_param != '*':  # No resourceless
                        kwargs[target_param] = list(allow[res_id])
                    elif len(allow[res_id]) == 0:
                        raise Exception
                except Exception:
                    raise WazuhError(4000)
            result = func(*args, **kwargs)
            if post_proc_func is None:
                return result
            else:
                return post_proc_func(result, original=original_kwargs, allowed=allow, target=target_params,
                                      add_denied=add_denied, **post_proc_kwargs)

        return wrapper

    return decorator
