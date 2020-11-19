# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import os
import re
from collections import defaultdict
from functools import wraps

from wazuh.core.common import rbac, broadcast, cluster_nodes
from wazuh.core.configuration import get_ossec_conf
from wazuh.core.cdb_list import iterate_lists
from wazuh.core.utils import get_files
from wazuh.core.agent import get_agents_info, get_groups, expand_group
from wazuh.core.rule import format_rule_decoder_file, Status
from wazuh.core.exception import WazuhPermissionError
from wazuh.rbac.orm import RolesManager, PoliciesManager, AuthenticationManager, RulesManager
from wazuh.core.results import AffectedItemsWazuhResult


integer_resources = ['user:id', 'role:id', 'rule:id', 'policy:id']


def _expand_resource(resource):
    """This function expand a specified resource depending of it type.

    :param resource: Resource to be expanded
    :return expanded_resource: Returns the result of the resource expansion
    """
    name, attribute, value = resource.split(':')
    resource_type = ':'.join([name, attribute])

    # This is the special case, expand_group can receive * or the name of the group. That's why it' s always called
    if resource_type == 'agent:group':
        return expand_group(value)

    # We need to transform the wildcard * to the resource of the system
    if value == '*':
        if resource_type == 'agent:id':
            return get_agents_info()
        elif resource_type == 'group:id':
            return get_groups()
        elif resource_type == 'role:id':
            with RolesManager() as rm:
                roles = rm.get_roles()
            return {str(role_id.id) for role_id in roles}
        elif resource_type == 'policy:id':
            with PoliciesManager() as pm:
                policies = pm.get_policies()
            return {str(policy_id.id) for policy_id in policies}
        elif resource_type == 'user:id':
            users_system = set()
            with AuthenticationManager() as auth:
                users = auth.get_users()
            for user in users:
                users_system.add(str(user['user_id']))
            return users_system
        elif resource_type == 'rule:id':
            with RulesManager() as rum:
                rules = rum.get_rules()
            return {str(rule_id.id) for rule_id in rules}
        elif resource_type == 'rule:file':
            tags = ['rule_include', 'rule_exclude', 'rule_dir']
            format_rules = format_rule_decoder_file(
                get_ossec_conf(section='ruleset')['ruleset'],
                {'status': Status.S_ALL.value, 'relative_dirname': None, 'filename': None},
                tags)
            return {rule['filename'] for rule in format_rules}
        elif resource_type == 'decoder:file':
            tags = ['decoder_include', 'decoder_exclude', 'decoder_dir']
            format_decoders = format_rule_decoder_file(
                get_ossec_conf(section='ruleset')['ruleset'],
                {'status': Status.S_ALL.value, 'relative_dirname': None, 'filename': None},
                tags)
            return {decoder['filename'] for decoder in format_decoders}
        elif resource_type == 'list:path':
            return {os.path.join(cdb_list['relative_dirname'], cdb_list['filename'])
                    for cdb_list in iterate_lists(only_names=True)}
        elif resource_type == 'node:id':
            return set(cluster_nodes.get())
        elif resource_type == 'file:path':
            return get_files()
        elif resource_type == '*:*':  # Resourceless
            return {'*'}
        return set()
    # We return the value casted to set
    else:
        return {value}


def _combination_defined_rbac(needed_resources, user_resources):
    """This function avoids that the combinations of resources are processed as a individuals resources

    :param needed_resources: These are the needed resources for the framework's function
    :param user_resources: These are the user's resources for the actions
    :return: True if the resource combination match with the required resource combination, otherwise False
    """
    for needed_resource in needed_resources:
        split_needed_resource = needed_resource.split('&')
        split_user_resource = user_resources.split('&')
        if len(split_user_resource) != len(split_needed_resource):
            return False
        counter = 0
        for index, element in enumerate(split_needed_resource):
            user_resource_identifier = ':'.join(split_user_resource[index].split(':')[:-1])
            needed_resource_identifier = ':'.join(split_needed_resource[index].split(':')[:-1])
            if user_resource_identifier != needed_resource_identifier:  # Not the same resource
                return False
            # * wildcard founded in RBAC permissions for the required resource
            if split_user_resource[index].split(':')[-1] == '*':
                counter += 1
            else:
                if split_user_resource[index] == element or element.split(':')[-1] == '*':
                    counter += 1
                else:
                    break

        return counter == len(split_needed_resource)
    return False


def _optimize_resources(req_resources):
    """This function creates an optimized data structure for a more easy processing
    Example:
        ["node:id:master-node",            {
        "node:id:worker1",         -->         "node:id": {"master", "worker1", "worker2"}
        "node:id:worker2"]                 }

    :param req_resources: Resource to be optimized
    :return expanded_resource: Returns the result of the resource expansion
    """
    resources_value_odict = defaultdict(set)
    for element in req_resources:
        resources_value_odict[':'.join(element.split(':')[:-1])].add(element.split(':')[-1])

    return resources_value_odict


def _black_expansion(req_resources, final_user_permissions):
    """If RBAC policies is empty and the RBAC's mode is black, we have the permission over the required resource
    or if we can't expand the resource, the action is resourceless

    :param req_resources: Required resource for the framework's function
    :param final_user_permissions: Final user's permissions after processing the combinations of resources
    """
    for req_resource in req_resources:
        split_combination = req_resource.split('&')
        for chunk in split_combination:
            identifier = ':'.join(chunk.split(':')[:-1])
            # Modify the identifier agent:group by agent:id in the resources required by the system
            if identifier == 'agent:group':
                identifier = 'agent:id'
            if identifier == '*:*':
                final_user_permissions['*:*'] = {'*'}
            else:
                expanded_resource = _expand_resource(chunk)
                final_user_permissions[identifier].update(expanded_resource)


def _process_effect(effect, identifier, value, final_user_permissions, expanded_resource):
    """This function will add or remove resources from the final permissions depending on the effect of the permission

    :param effect: Allow or Deny
    :param identifier: Resource identifier. Ex: "node:id"
    :param value: Value of the resource. Ex: "master-node"
    :param final_user_permissions: Dictionary that contains the user's final permissions
    :param expanded_resource: The expansion of the user_resource. Ex: Value= "*" -> ["mater-node", "worker1", "worker2"]
    """
    if effect == 'allow':
        if value == '*':
            final_user_permissions[identifier].update(expanded_resource)
        else:
            final_user_permissions[identifier].update(expanded_resource.intersection({value}))
    else:
        if value == '*':
            final_user_permissions[identifier].difference_update(expanded_resource)
        else:
            final_user_permissions[identifier].difference_update(expanded_resource.intersection({value}))


def _single_processor(req_resources, user_permissions_for_resource, final_user_permissions):
    """This function process the individual resources.

    :param req_resources: Required resource for the framework's function
    :param user_permissions_for_resource: User's defined resources in his RBAC permissions
    :param final_user_permissions: Final user's permissions after processing the combinations of resources
    :return expanded_resource: Returns the result of the resource expansion
    """
    req_resources = _optimize_resources(req_resources)
    for user_resource, user_resource_effect in user_permissions_for_resource.items():
        # Skip combined resources
        if '&' in user_resource:
            continue
        user_resource_identifier = ':'.join(user_resource.split(':')[:-1])
        # Modify the identifier agent:group by agent:id in the user's resources
        if user_resource_identifier == 'agent:group':
            user_resource_identifier = 'agent:id'
        wildcard_expansion = user_resource.split(':')[-1] == '*'
        expanded_resource = _expand_resource(user_resource)
        for value in req_resources.get(user_resource_identifier, list()):
            if wildcard_expansion and value != '*':
                expanded_resource |= _expand_resource(user_resource_identifier + ':' + value)
            _process_effect(user_resource_effect, user_resource_identifier,
                            value, final_user_permissions, expanded_resource)


def _combination_processor(req_resources, user_permissions_for_resource, final_user_permissions):
    """This function process the combinations of resources.
    Checks how the API is currently running and depending on the API and
    the resources defined for the user, will return a dictionary with the final permissions.

    :param req_resources: Required resource for the framework's function
    :param user_permissions_for_resource: User's defined resources in his RBAC permissions
    :param final_user_permissions: Final user's permissions after processing the combinations of resources
    :return expanded_resource: Returns the result of the resource expansion
    """
    for user_resource, user_resource_effect in user_permissions_for_resource.items():
        # _combination_defined_rbac: This function prevents pairs from being treated individually
        if _combination_defined_rbac(req_resources, user_resource):
            split_user_resource = user_resource.split('&')
            for req_resource in req_resources:  # Normally this loop will iterate two times
                for r, split_req_resource in zip(split_user_resource, req_resource.split('&')):
                    split_chunk_resource = split_req_resource.split(':')
                    identifier = ':'.join(split_chunk_resource[:-1])
                    value = split_chunk_resource[-1]
                    expanded_resource = _expand_resource(r)
                    if r.split(':')[-1] == '*':
                        expanded_resource |= _expand_resource(identifier + ':' + value)
                    _process_effect(user_resource_effect, identifier,
                                    value, final_user_permissions, expanded_resource)


def _match_permissions(req_permissions: dict = None, rbac_mode: str = 'white'):
    """Try to match function required permissions against user permissions to allow or deny execution

    :param req_permissions: Required permissions to allow function execution
    :return: Dictionary with final permissions
    """
    allow_match = defaultdict(set)
    for req_action, req_resources in req_permissions.items():
        is_combination = any('&' in req_resource for req_resource in req_resources)
        rbac_mode == 'black' and _black_expansion(req_resources, allow_match)
        if not is_combination or len(req_resources) == 0:
            _single_processor(req_resources, rbac.get().get(req_action, dict()), allow_match)
        else:
            _combination_processor(req_resources, rbac.get().get(req_action, dict()), allow_match)
    return allow_match


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
    combination = False
    for resource in resources:
        split_resource = resource.split('&')
        if len(split_resource) > 1:
            combination = True
        for r in split_resource:
            m = re.search(r'^([a-z*]+:[a-z*]+):([^{\}]+|\*|{(\w+)})$', r)
            res_base = m.group(1)
            # If we find a '{' in the regex we obtain the dynamic resource/s
            if '{' in m.group(2):
                target_params[m.group(1)] = m.group(3)
                if m.group(3) in kwargs:
                    # Dynamic resources ids are found within the {}
                    params = kwargs[m.group(3)]
                    if isinstance(params, list):
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
                target_params[m.group(1)] = '*'
                add_denied = not broadcast.get()
                res_list.append(r)
    # Create dict of required policies with action: list(resources) pairs
    req_permissions = dict()
    for action in actions:
        if combination:
            req_permissions[action] = ['&'.join(res_list)]
        else:
            req_permissions[action] = res_list
    return target_params, req_permissions, add_denied


def _get_denied(original, allowed, target_param, res_id, resources=None):
    """This function compare the original kwargs and the processed kwargs,
    the difference between both should be the denied resources

    :param original: The original function's kwargs
    :param allowed: The processed list of resources after RBAC
    :param target_param: Element of kwargs that was processed
    :param res_id: Involved resource
    :param resources: List of the required resources for the function
    :return:
    """
    try:
        return {original[target_param]} - allowed[res_id]
    except TypeError:
        return set(original[target_param]) - allowed[res_id]
    except KeyError:
        return {res.split(':')[2] for res in resources} if resources is not None else {}


async def async_list_handler(result: asyncio.coroutine, **kwargs):
    """This function makes list_handler async
    """
    result = await result
    return list_handler(result, **kwargs)


def list_handler(result: AffectedItemsWazuhResult, original: dict = None, allowed: dict = None, target: dict = None,
                 add_denied: bool = False, **post_proc_kwargs):
    """ Post processor for framework list responses with affected items and optional denied items

    :param result: Dict with affected_items, failed_items and str_priority
    :param original: Original input call parameter values
    :param allowed: Allowed input call parameter values
    :param target: Name of the input parameters used to calculate resource access
    :param add_denied: Flag to add denied permissions to answer
    :return: AffectedItemsWazuhResult
    """
    if add_denied:
        for res_id, target_param in target.items():
            denied = _get_denied(original, allowed, target_param, res_id)
            if res_id in integer_resources:
                denied = {int(i) if i.isdigit() else i for i in denied}
            for denied_item in denied:
                result.add_failed_item(id_=denied_item,
                                       error=WazuhPermissionError(4000, extra_message=f'Resource type: {res_id}',
                                                                  ids=denied))
    else:
        if 'default_result_kwargs' in post_proc_kwargs and result is None:
            return AffectedItemsWazuhResult(**post_proc_kwargs['default_result_kwargs'])
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
            original_kwargs = dict(kwargs)
            target_params, req_permissions, add_denied = \
                _get_required_permissions(actions=actions, resources=resources, **kwargs)
            allow = _match_permissions(req_permissions=req_permissions, rbac_mode=rbac.get()['rbac_mode'])
            skip_execution = False

            for res_id, target_param in target_params.items():
                try:
                    if target_param in original_kwargs and not isinstance(original_kwargs[target_param], list):
                        if original_kwargs[target_param] is not None:
                            original_kwargs[target_param] = [original_kwargs[target_param]]
                    # We don't have any permissions over the required resources
                    if len(allow[res_id]) == 0 and \
                            original_kwargs.get(target_param, None) is not None and \
                            len(original_kwargs[target_param]) != 0:
                        raise Exception
                    if target_param != '*':  # No resourceless and not static
                        if target_param in original_kwargs and original_kwargs[target_param] is not None:
                            kwargs[target_param] = list(filter(lambda x: x in allow[res_id],
                                                               original_kwargs[target_param]))
                        else:
                            kwargs[target_param] = list(allow[res_id])
                    elif len(allow[res_id]) == 0:
                        raise Exception
                except Exception:
                    if add_denied:
                        denied = _get_denied(original_kwargs, allow, target_param, res_id, resources=resources)
                        if res_id in integer_resources:
                            denied = {int(i) if i.isdigit() else i for i in denied}
                        raise WazuhPermissionError(4000,
                                                   extra_message=f'Resource type: {res_id}',
                                                   ids=denied, title="Permission Denied")
                    else:
                        if target_param != '*':
                            kwargs[target_param] = list()
                        else:
                            skip_execution = True
            result = func(*args, **kwargs) if not skip_execution else None
            if post_proc_func is None:
                return result
            else:
                return post_proc_func(result, original=original_kwargs, allowed=allow, target=target_params,
                                      add_denied=add_denied, **post_proc_kwargs)

        return wrapper

    return decorator
