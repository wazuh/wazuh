# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhError, create_exception_dic
from wazuh.results import WazuhResult


def list_handler(result, original: dict = None, allowed: dict = None, target: list = None, add_denied: bool = False,
                 **post_proc_kwargs):
    """ Post processor for framework list responses with affected items and optional denied items

    :param result: Dict with affected_items, failed_items and str_priority
    :param original: Original input call parameter values
    :param allowed: Allowed input call parameter values
    :param target: Name of the input parameters used to calculate resource access
    :param add_denied: Flag to add denied permissions to answer
    :return: WazuhResult
    """
    if add_denied and '*' not in target:
        if len(target) == 1:
            original_kwargs = original[target[0]] if isinstance(original[target[0]], list) else [original[target[0]]]
            for item in set(original_kwargs) - set(list(allowed[list(allowed.keys())[0]])):
                result['failed_items'].append(create_exception_dic(item, WazuhError(4000)))
        else:
            original_kwargs = original[target[1]] if isinstance(original[target[1]], list) else list(
                original[target[1]])
            for item in set(original_kwargs) - set(list(allowed[list(allowed.keys())[1]])):
                result['failed_items'].append(create_exception_dic('{}:{}'.format(original[target[0]], item),
                                                                   WazuhError(4000)))

    return data_response_builder(result, original=original, add_denied=add_denied, **post_proc_kwargs)


def _merge_errors(failed_items, add_denied, **kwargs):
    """ Merges common errors into one, where a list of identifiers of the affected resource appears

    :param failed_items: Dictionary with the errors occurred
    :return: Final error list
    """
    code_ids = dict()
    error_count = 0
    for index, failed_item in enumerate(failed_items):
        if not ('exclude_codes' in kwargs and
                failed_item['error']['code'] in kwargs['exclude_codes'] and
                add_denied is False):
            if failed_item['error']['code'] not in code_ids.keys():
                code_ids[failed_item['error']['code']] = dict()
                code_ids[failed_item['error']['code']]['ids'] = list()
                code_ids[failed_item['error']['code']]['index'] = index
            code_ids[failed_item['error']['code']]['ids'].append(failed_item['id'])
            error_count += 1
    final_errors_list = list()
    code_ids = dict(sorted(code_ids.items()))
    for key, error_code in code_ids.items():
        final_errors_list.append(failed_items[error_code['index']])
        try:
            final_errors_list[-1]['id'] = sorted(error_code['ids'], key=int)
        except ValueError:
            final_errors_list[-1]['id'] = sorted(error_code['ids'])

    return final_errors_list, error_count


def data_response_builder(result, original: dict = None, add_denied: bool = False, **post_proc_kwargs):
    """

    :param result: List with affected_items, failed_items and str_priority
    :param original: Original input call parameter values
    :param add_denied: Flag to add denied permissions to answer
    :return: WazuhResult
    """
    try:
        affected = sorted(result['affected_items'], key=int)
    except ValueError:
        affected = sorted(result['affected_items'])
    except TypeError:
        affected = result['affected_items']
    final_dict = {'data': {'affected_items': affected, 'total_affected_items': len(result['affected_items'])}}

    failed_result, error_count = _merge_errors(result['failed_items'], add_denied, **post_proc_kwargs)
    if error_count > 0:
        final_dict['data']['failed_items'] = failed_result
        final_dict['data']['total_failed_items'] = error_count
        final_dict['message'] = result['str_priority'][2] if not result['affected_items'] else result['str_priority'][1]
    else:
        final_dict['message'] = result['str_priority'][2] if not result['affected_items'] else result['str_priority'][0]
    if 'extra_fields' in post_proc_kwargs:
        for item in post_proc_kwargs['extra_fields']:
            final_dict['data'][item] = original[item]
    if 'extra_affected' in post_proc_kwargs:
        final_dict['data'][post_proc_kwargs['extra_affected']] = result[post_proc_kwargs['extra_affected']]

    return WazuhResult(final_dict, str_priority=result['str_priority'])
