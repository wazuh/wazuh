# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import re
from collections import defaultdict
from contextlib import contextmanager
from functools import wraps
from typing import Iterator

from wazuh.core.agent import expand_group, get_agents_info, get_groups
from wazuh.core.common import broadcast, rbac, rbac_manager
from wazuh.core.exception import WazuhPermissionError
from wazuh.core.rbac import RBACManager
from wazuh.core.results import AffectedItemsWazuhResult

integer_resources = ['user:id', 'role:id', 'rule:id', 'policy:id']


async def _expand_resource(resource: str) -> set:  # noqa: C901
    """Expand a specified resource depending on its type.

    Parameters
    ----------
    resource : str
        Resource to be expanded.

    Returns
    -------
    set
        Result of the resource expansion.
    """
    name, attribute, value = resource.split(':')
    resource_type = ':'.join([name, attribute])

    # This is the special case, expand_group can receive * or the name of the group. That's why it' s always called
    if resource_type == 'agent:group':
        return await expand_group(value)

    manager: RBACManager = rbac_manager.get()

    # We need to transform the wildcard * to the resource of the system
    if value == '*':
        if resource_type == 'agent:id':
            return await get_agents_info()
        elif resource_type == 'group:id':
            return get_groups()
        elif resource_type == 'role:id':
            roles = manager.get_roles()
            return {role.name for role in roles}
        elif resource_type == 'policy:id':
            policies = manager.get_policies()
            return {policy.name for policy in policies}
        elif resource_type == 'user:id':
            users = manager.get_users()
            return {user.id for user in users}
        elif resource_type == 'rule:id':
            rules = manager.get_rules()
            return {rule.name for rule in rules}
        elif resource_type == '*:*':  # Resourceless
            return {'*'}
        return set()
    # We return the value casted to set
    else:
        return {value}


def _combination_defined_rbac(needed_resources: list, user_resources: str) -> bool:
    """Combine resources to avoid that the combinations of them are processed individually.

    Parameters
    ----------
    needed_resources : list
        These are the needed resources for the framework's function.
    user_resources : str
        These are the user's resources for the actions.

    Returns
    -------
    bool
        True if the resource combination matches with the required resource combination, False otherwise.
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


def _optimize_resources(req_resources: list) -> defaultdict:
    """Create an optimized data structure for an easier processing.
    Example:
        ["node:id:master-node",            {
        "node:id:worker1",         -->         "node:id": {"master", "worker1", "worker2"}
        "node:id:worker2"]                 }.

    Parameters
    ----------
    req_resources : list
        Resource to be optimized.

    Returns
    -------
    defaultdict
        Returns the result of the resource expansion.
    """
    resources_value_odict = defaultdict(set)
    for element in req_resources:
        resources_value_odict[':'.join(element.split(':')[:-1])].add(element.split(':')[-1])

    return resources_value_odict


async def _black_expansion(req_resources: list, final_user_permissions: dict):
    """If RBAC policies is empty and the RBAC's mode is black, we have the permission over the required resource,
    or if we can't expand the resource, the action is resourceless.

    Parameters
    ----------
    req_resources : list
        Required resource for the framework's function.
    final_user_permissions : dict
        Final user's permissions after processing the combinations of resources.
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
                expanded_resource = await _expand_resource(chunk)
                final_user_permissions[identifier].update(expanded_resource)


def _process_effect(effect: str, identifier: str, value: str, final_user_permissions: dict, expanded_resource: set):
    """Add or remove resources from the final permissions depending on the effect of the permission.

    Parameters
    ----------
    effect : str
        Allow or Deny.
    identifier: str
        Resource identifier. Ex: "node:id"
    value : str
        Value of the resource. Ex: "master-node"
    final_user_permissions : dict
        Dictionary that contains the user's final permissions.
    expanded_resource : set
        The expansion of the user_resource. Ex: Value= "*" -> ["mater-node", "worker1", "worker2"]
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


async def _single_processor(req_resources: list, user_permissions_for_resource: dict, final_user_permissions: dict):
    """Process individual resources.

    Parameters
    ----------
    req_resources : list
        Required resource for the framework's function.
    user_permissions_for_resource : dict
        User's defined resources in his RBAC permissions.
    final_user_permissions : dict
        Final user's permissions after processing the combinations of resources
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
        expanded_resource = await _expand_resource(user_resource)
        for value in req_resources.get(user_resource_identifier, list()):
            if wildcard_expansion and value != '*':
                expanded_resource |= await _expand_resource(user_resource_identifier + ':' + value)
            _process_effect(
                user_resource_effect, user_resource_identifier, value, final_user_permissions, expanded_resource
            )


async def _combination_processor(
    req_resources: list, user_permissions_for_resource: dict, final_user_permissions: dict
):
    """Process the combinations of resources.
    Checks how the API is currently running and depending on the API and the resources defined for the user, will return
    a dictionary with the final permissions.

    Parameters
    ----------
    req_resources : list
        Required resource for the framework's function.
    user_permissions_for_resource : dict
        User's defined resources in his RBAC permissions.
    final_user_permissions : dict
        Final user's permissions after processing the combinations of resources.
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
                    expanded_resource = await _expand_resource(r)
                    if r.split(':')[-1] == '*':
                        expanded_resource |= await _expand_resource(identifier + ':' + value)
                    _process_effect(user_resource_effect, identifier, value, final_user_permissions, expanded_resource)


async def _match_permissions(req_permissions: dict = None, rbac_mode: str = 'white') -> dict:
    """Try to match function required permissions against user permissions to allow or deny execution.

    Parameters
    ----------
    req_permissions : dict
        Required permissions to allow function execution.
    rbac_mode : str
        RBAC mode (white or black).

    Returns
    -------
    dict
        Dictionary with final permissions.
    """
    allow_match = defaultdict(set)
    for req_action, req_resources in req_permissions.items():
        is_combination = any('&' in req_resource for req_resource in req_resources)
        rbac_mode == 'black' and await _black_expansion(req_resources, allow_match)
        if not is_combination or len(req_resources) == 0:
            await _single_processor(req_resources, rbac.get().get(req_action, dict()), allow_match)
        else:
            await _combination_processor(req_resources, rbac.get().get(req_action, dict()), allow_match)
    return allow_match


def _get_required_permissions(actions: list = None, resources: list = None, **kwargs: dict) -> tuple:  # noqa: C901
    """Resource pairs exposed by the framework function.

    Parameters
    ----------
    actions : list
        List of exposed actions.
    resources : list
        List of exposed resources.
    kwargs : dict
        Function kwargs to look for dynamic resources.

    Returns
    -------
    tuple
        Dictionary with required actions as keys and a list of required resources as values
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
                            res_list.append('{0}:{1}'.format(res_base, param))
                        add_denied = not broadcast.get()
                    else:
                        if params is None or params == '*':
                            add_denied = True
                            params = '*'
                        else:
                            add_denied = not broadcast.get()
                        res_list.append('{0}:{1}'.format(res_base, params))
                # KeyError occurs if required dynamic resources can't be found within request parameters
                else:
                    add_denied = False
                    params = '*'
                    res_list.append('{0}:{1}'.format(res_base, params))
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


def _get_denied(original: dict, allowed: list, target_param: str, res_id: int, resources: list = None) -> set:
    """Compare the original kwargs and the processed kwargs, the difference between both should be the
    denied resources.

    Parameters
    ----------
    original : dict
        The original function's kwargs.
    allowed : list
        The processed list of resources after RBAC.
    target_param : str
        Element of kwargs that was processed.
    res_id : int
        Involved resource.
    resources : list
        List of the required resources for the function.

    Returns
    -------
    set
        Difference between the original kwargs and the processed ones.
    """
    try:
        return {original[target_param]} - allowed[res_id]
    except TypeError:
        return set(original[target_param]) - allowed[res_id]
    except KeyError:
        return {res.split(':')[2] for res in resources} if resources is not None else {}


async def async_list_handler(result: asyncio.coroutine, **kwargs):
    """Make list_handler async."""
    result = await result
    return list_handler(result, **kwargs)


def list_handler(
    result: AffectedItemsWazuhResult,
    original: dict = None,
    allowed: dict = None,
    target: dict = None,
    add_denied: bool = False,
    **post_proc_kwargs: dict,
) -> AffectedItemsWazuhResult:
    """Post processor for framework list responses with affected items and optional denied items.

    Parameters
    ----------
    result : AffectedItemsWazuhResult
        Dict with affected_items, failed_items and str_priority.
    original : dict
        Original input call parameter values.
    allowed : dict
        Allowed input call parameter values.
    target : dict
        Name of the input parameters used to calculate resource access.
    add_denied : bool
        Flag to add denied permissions to answer.
    post_proc_kwargs : dict
        Additional kwargs used in post-processing.

    Returns
    -------
    AffectedItemsWazuhResult
        Framework responses.
    """
    if add_denied:
        for res_id, target_param in target.items():
            denied = _get_denied(original, allowed, target_param, res_id)
            if res_id in integer_resources:
                denied = {int(i) if i.isdigit() else i for i in denied}
            for denied_item in denied:
                result.add_failed_item(
                    id_=denied_item,
                    error=WazuhPermissionError(4000, extra_message=f'Resource type: {res_id}', ids=denied),
                )
    if not add_denied or post_proc_kwargs.get('force'):
        # Apply post processing exclusion/default values if the main resource was not explicit or
        # `force` parameter exists in `post_proc_kwargs` and is True
        if 'default_result_kwargs' in post_proc_kwargs and result is None:
            return AffectedItemsWazuhResult(**post_proc_kwargs['default_result_kwargs'])
        if 'exclude_codes' in post_proc_kwargs:
            result.remove_failed_items(post_proc_kwargs['exclude_codes'])

    return result


def expose_resources(  # noqa: C901
    actions: list = None, resources: list = None, post_proc_func: callable = list_handler, post_proc_kwargs: dict = None
):
    """Apply user permissions on a Wazuh framework function based on exposed action:resource pairs.

    Parameters
    ----------
    actions : list
        List of actions exposed by the framework function.
    resources : list
        List of resources exposed by the framework function.
    post_proc_func : callable
        Name of the function to use in response post processing.
    post_proc_kwargs : dict
        Extra parameters used in post processing.

    Returns
    -------
    Allow or deny framework function execution.
    """
    if post_proc_kwargs is None:
        post_proc_kwargs = dict()

    def decorator(func):  # noqa: C901
        @wraps(func)
        async def wrapper(*args, **kwargs):  # noqa: C901
            original_kwargs = dict(kwargs)
            target_params, req_permissions, add_denied = _get_required_permissions(
                actions=actions, resources=resources, **kwargs
            )
            allow = await _match_permissions(req_permissions=req_permissions, rbac_mode=rbac.get()['rbac_mode'])
            skip_execution = False

            for res_id, target_param in target_params.items():
                try:
                    if target_param in original_kwargs and not isinstance(original_kwargs[target_param], list):
                        if original_kwargs[target_param] is not None:
                            original_kwargs[target_param] = [original_kwargs[target_param]]
                    # We don't have any permissions over the required resources
                    if (
                        len(allow[res_id]) == 0
                        and original_kwargs.get(target_param, None) is not None
                        and len(original_kwargs[target_param]) != 0
                    ):
                        raise Exception
                    if target_param != '*':  # No resourceless and not static
                        if target_param in original_kwargs and original_kwargs[target_param] is not None:
                            kwargs[target_param] = list(
                                filter(lambda x: x in allow[res_id], original_kwargs[target_param])
                            )
                        else:
                            kwargs[target_param] = list(allow[res_id])
                    elif len(allow[res_id]) == 0:
                        raise Exception
                except Exception:
                    if add_denied:
                        denied = _get_denied(original_kwargs, allow, target_param, res_id, resources=resources)
                        if res_id in integer_resources:
                            denied = {int(i) if i.isdigit() else i for i in denied}
                        raise WazuhPermissionError(
                            4000, extra_message=f'Resource type: {res_id}', ids=denied, title='Permission Denied'
                        )
                    else:
                        if target_param != '*':
                            kwargs[target_param] = list()
                        else:
                            skip_execution = True

            # If func is still decorated by expose_resources, do not remove 'call_func'
            if hasattr(func, '__wrapped__') or kwargs.pop('call_func', True):
                result = await func(*args, **kwargs) if not skip_execution else None
            else:
                result = AffectedItemsWazuhResult()

            if post_proc_func is None:
                return result
            else:
                return post_proc_func(
                    result,
                    original=original_kwargs,
                    allowed=allow,
                    target=target_params,
                    add_denied=add_denied,
                    **post_proc_kwargs,
                )

        return wrapper

    return decorator


@contextmanager
def get_rbac_manager() -> Iterator[RBACManager]:
    """Get RBAC manager from the context and iterate over it."""
    manager: RBACManager = rbac_manager.get()

    try:
        yield manager
    finally:
        pass
