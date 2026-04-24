# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from collections import defaultdict
from functools import wraps
from typing import Awaitable, Any

from wazuh.core.agent import get_agents_info, get_groups, expand_group
from wazuh.core.common import rbac, broadcast, cluster_nodes
from wazuh.core.exception import WazuhPermissionError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.orm import RolesManager, PoliciesManager, AuthenticationManager, RulesManager

SENSITIVE_FIELD_PATHS = ("authd.pass", "cluster.key")

MASK_DEFAULT = "*****"

integer_resources = ['user:id', 'role:id', 'rule:id', 'policy:id']


def _expand_resource(resource: str) -> set:
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

    # We need to transform the wildcard * to the resource of the system
    if value == '*':
        if resource_type == 'agent:id' or resource_type == 'agent:group':
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
        elif resource_type == 'node:id':
            return set(cluster_nodes.get())
        elif resource_type == '*:*':  # Resourceless
            return {'*'}
        return set()
    else:
        if resource_type == 'agent:group':
            return expand_group(value)

        # We return the value casted to set
        return {value}


def _combination_defined_rbac(needed_resources: list, user_resources: str) -> bool:
    """This function avoids that the combinations of resources are processed as individuals resources.

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
    """This function creates an optimized data structure for an easier processing.
    Example:
        ["node:id:master-node",            {
        "node:id:worker1",         -->         "node:id": {"master", "worker1", "worker2"}
        "node:id:worker2"]                 }

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


def _black_expansion(req_resources: list, final_user_permissions: dict):
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
                expanded_resource = _expand_resource(chunk)
                final_user_permissions[identifier].update(expanded_resource)


def _process_effect(effect: str, identifier: str, value: str, final_user_permissions: dict, expanded_resource: set):
    """This function will add or remove resources from the final permissions depending on the effect of the permission.

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


def _single_processor(req_resources: list, user_permissions_for_resource: dict, final_user_permissions: dict):
    """This function processes the individual resources.

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
        expanded_resource = _expand_resource(user_resource)
        for value in req_resources.get(user_resource_identifier, list()):
            if wildcard_expansion and value != '*':
                expanded_resource |= _expand_resource(user_resource_identifier + ':' + value)
            _process_effect(user_resource_effect, user_resource_identifier,
                            value, final_user_permissions, expanded_resource)


def _combination_processor(req_resources: list, user_permissions_for_resource: dict, final_user_permissions: dict):
    """This function processes the combinations of resources.
    Checks how the API is currently running and depending on the API and the resources defined for the user, will return
    a dictionary with the final permissions.

    Parameters
    ---------
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
                    expanded_resource = _expand_resource(r)
                    if r.split(':')[-1] == '*':
                        expanded_resource |= _expand_resource(identifier + ':' + value)
                    _process_effect(user_resource_effect, identifier,
                                    value, final_user_permissions, expanded_resource)


def _match_permissions(req_permissions: dict = None, rbac_mode: str = 'white') -> dict:
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
        rbac_mode == 'black' and _black_expansion(req_resources, allow_match)
        if not is_combination or len(req_resources) == 0:
            _single_processor(req_resources, rbac.get().get(req_action, dict()), allow_match)
        else:
            _combination_processor(req_resources, rbac.get().get(req_action, dict()), allow_match)
    return allow_match


def _get_required_permissions(actions: list = None, resources: list = None, **kwargs: dict) -> tuple:
    """Resource pairs exposed by the framework function

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


def _get_denied(original: dict, allowed: list, target_param: str, res_id: int, resources: list = None) -> set:
    """This function compares the original kwargs and the processed kwargs, the difference between both should be the
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


async def async_list_handler(result: Awaitable[Any], **kwargs):
    """This function makes list_handler async."""
    result = await result
    return list_handler(result, **kwargs)


def list_handler(result: AffectedItemsWazuhResult, original: dict = None, allowed: dict = None, target: dict = None,
                 add_denied: bool = False, **post_proc_kwargs: dict) -> AffectedItemsWazuhResult:
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
                result.add_failed_item(id_=denied_item,
                                       error=WazuhPermissionError(4000, extra_message=f'Resource type: {res_id}',
                                                                  ids=denied))
    if not add_denied or post_proc_kwargs.get('force'):
        # Apply post processing exclusion/default values if the main resource was not explicit or
        # `force` parameter exists in `post_proc_kwargs` and is True
        if 'default_result_kwargs' in post_proc_kwargs and result is None:
            return AffectedItemsWazuhResult(**post_proc_kwargs['default_result_kwargs'])
        if 'exclude_codes' in post_proc_kwargs:
            result.remove_failed_items(post_proc_kwargs['exclude_codes'])

    return result


def expose_resources(actions: list = None, resources: list = None, post_proc_func: callable = list_handler,
                     post_proc_kwargs: dict = None):
    """Decorator to apply user permissions on a Wazuh framework function based on exposed action:resource pairs.

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

            # If func is still decorated by expose_resources, do not remove 'call_func'
            if hasattr(func, '__wrapped__') or kwargs.pop('call_func', True):
                result = func(*args, **kwargs) if not skip_execution else None
            else:
                result = AffectedItemsWazuhResult()

            if post_proc_func is None:
                return result
            else:
                return post_proc_func(result, original=original_kwargs, allowed=allow, target=target_params,
                                      add_denied=add_denied, **post_proc_kwargs)
        wrapper.__wazuh_exposed__ = True
        return wrapper

    return decorator


def _has_update_permissions() -> bool:
    """Check if current user holds update-config permissions.

    Returns
    -------
    bool
        True if user has 'manager:update_config' or 'cluster:update_config', False otherwise.
    """
    perms = rbac.get() or {}
    for action in ("manager:update_config", "cluster:update_config"):
        action_map = perms.get(action)
        if isinstance(action_map, dict) and len(action_map) > 0:
            return True
    return False


def _build_xml_mask_pattern(path: str) -> re.Pattern:
    """Build a compiled regex pattern to locate a value in a nested XML structure.

    The dotted ``path`` is converted into a sequence of nested XML tags. The
    resulting pattern captures three groups:

    - Group 1: opening tags up to and including the innermost tag.
    - Group 2: the text content to be replaced (between the innermost tags).
    - Group 3: the closing tag of the innermost element.

    Parameters
    ----------
    path : str
        Dotted path representing nested XML tags, e.g. ``"cluster.key"``
        maps to ``<cluster>...<key>value</key>``.

    Returns
    -------
    re.Pattern
        Compiled regular expression with ``re.DOTALL`` flag enabled so that
        ``.*?`` matches across newlines.
    """
    tags = path.split('.')
    prefix_pattern = ''.join(f'<{tag}>.*?' for tag in tags[:-1]) + f'<{tags[-1]}>'
    full_pattern = rf'({prefix_pattern})([^<]*)(</{tags[-1]}>)'
    return re.compile(full_pattern, re.DOTALL)


def _mask_xml_by_path(text: str, path: str, mask_text: str) -> str:
    """Replace the value at a nested XML path with a mask string.

    Builds a pattern via `_build_xml_mask_pattern` and substitutes the text
    content found between the innermost tags with ``mask_text``. If the pattern
    is not present in ``text``, the original string is returned unchanged.

    Parameters
    ----------
    text : str
        Input XML string to process.
    path : str
        Dotted path representing nested XML tags, e.g. ``"cluster.key"``.
    mask_text : str
        Replacement string to place between the innermost tags.

    Returns
    -------
    str
        A new string with the matched content replaced by ``mask_text``.
    """
    pattern = _build_xml_mask_pattern(path)
    return pattern.sub(rf'\1{mask_text}\3', text)

def _mask_all_sensitive_fields(text: str, mask_text: str = "***") -> str:
    """Apply XML masking for every path defined in ``SENSITIVE_FIELD_PATHS``.

    Iterates over all sensitive field paths and delegates each substitution to
    `_mask_xml_by_path`, chaining the results so that every sensitive field in
    the string is masked.

    Parameters
    ----------
    text : str
        Input XML string that may contain one or more sensitive fields.
    mask_text : str, optional
        Replacement string for all matched values. Defaults to ``"***"``.

    Returns
    -------
    str
        A new string with all sensitive XML field values replaced by
        ``mask_text``.
    """
    for path in SENSITIVE_FIELD_PATHS:
        text = _mask_xml_by_path(text, path, mask_text)
    return text


def _mask_paths_in_object(obj, dotted_path: str, mask_text: str):
    """Mask a value at a dotted path inside dict/list.

    Parameters
    ----------
    obj : dict | list
        Object to process.
    dotted_path : str
        Path in dotted notation (e.g. "authd.pass").
    mask_text : str
        Replacement text.
    """
    if isinstance(obj, dict) and dotted_path in obj:
        obj[dotted_path] = mask_text
        return
    elif isinstance(obj, list):
        for el in obj:
            _mask_paths_in_object(el, dotted_path, mask_text)
        return
    elif not isinstance(obj, dict):
        return

    head, *tail = dotted_path.split('.', 1)
    if head not in obj:
        return
    elif not tail:
        obj[head] = mask_text
    else:
        _mask_paths_in_object(obj[head], tail[0], mask_text)


def _mask_payload(payload, mask_text: str = MASK_DEFAULT):
    """
    Recursively mask sensitive data in a payload in-place.

    The function traverses dictionaries, lists, and AffectedItemsWazuhResult
    objects, applying masking to:
    - Paths defined in the global `SENSITIVE_FIELD_PATHS` (via `_mask_paths_in_object`).
    - The literal key ``'key'`` (its value is replaced entirely by `mask`).
    - Any string element that matches the XML pattern handled by `_mask_xml_string`
      (the content between `<key>` tags is replaced by `mask`).

    The operation modifies the input object directly; it does not return a value.
    Unsupported types (e.g., int, str, None) are silently ignored.

    Parameters
    ----------
    payload : dict, list, AffectedItemsWazuhResult, or other
        Data structure to be masked. Only dict, list, and AffectedItemsWazuhResult
        are processed; other types are ignored.
    mask : str
        Replacement text used for all masked values.

    Returns
    -------
    None
    """
    if isinstance(payload, dict):
        for path in SENSITIVE_FIELD_PATHS:
            _mask_paths_in_object(payload, path, mask_text)
        if "key" in payload:
            payload["key"] = mask_text
    elif isinstance(payload, list):
        for i, item in enumerate(payload):
            if isinstance(item, str):
                payload[i] = _mask_all_sensitive_fields(item, mask_text)
            else:
                _mask_payload(item, mask_text)
    elif isinstance(payload, AffectedItemsWazuhResult):
        for item in payload.affected_items:
            _mask_payload(item, mask_text)


def mask_sensitive_config(mask_text: str = MASK_DEFAULT):
    """
    Decorator to mask sensitive fields in config responses for users without update permissions.

    The decorator post‑processes the return value of the wrapped function.
    - If the user lacks update‑config permissions, sensitive fields are masked **in‑place**
      (or for XML strings, a masked copy is created).
    - If an exception occurs during masking, it is silently swallowed to avoid breaking the endpoint.

    Parameters
    ----------
    mask_text : str, optional
        Replacement text for sensitive values. Defaults to `MASK_DEFAULT`.

    Returns
    -------
    callable
        Decorated function that applies masking when necessary.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            try:
                # Only mask if user LACKS update-config permissions
                if not _has_update_permissions():
                    if isinstance(result, str):
                        string_wrapper = [result]
                        _mask_payload(string_wrapper, mask_text=mask_text)
                        result = string_wrapper[0]
                    else:
                        _mask_payload(result, mask_text=mask_text)
            except Exception:
                # Never break the endpoint if masking fails for any reason
                pass
            return result

        return wrapper

    return decorator
