# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Options of etc/wazuh-manager.conf the API refuses to change unless api.yaml `upload_configuration` allows it.

Declarative replacement of the XML checks (check_indexer, check_agents_allow_higher_versions): each protected subtree
is a JSON pointer into the effective document, compared between the new and the current configuration.
"""

from api import configuration as api_configuration
from wazuh.core.exception import WazuhError

# (JSON pointer, path of the knob inside api_conf['upload_configuration'], error code when the subtree changes)
PROTECTED_SECTIONS = (
    ('/indexer', ('indexer', 'allow'), 1127),
    ('/auth/agents/allow_higher_versions', ('agents', 'allow_higher_versions', 'allow'), 1129),
    ('/remote/agents/allow_higher_versions', ('agents', 'allow_higher_versions', 'allow'), 1129),
)


def _resolve_pointer(document: dict, pointer: str):
    node = document
    for part in pointer.strip('/').split('/'):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _knob(upload_configuration: dict, path: tuple) -> bool:
    node = upload_configuration
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return True  # unknown knob: not protected
        node = node[part]
    return bool(node)


def check_protected_sections(new_document: dict, current_document: dict, upload_configuration: dict = None):
    """Raise if a protected subtree differs between the new and the current effective documents.

    Parameters
    ----------
    new_document : dict
        Effective document about to be written (defaults applied).
    current_document : dict
        Effective document currently on disk.
    upload_configuration : dict
        `upload_configuration` block of the API configuration. Default: the running api_conf.

    Raises
    ------
    WazuhError(1127)
        The indexer section was modified and `upload_configuration.indexer.allow` is false.
    WazuhError(1129)
        `agents.allow_higher_versions` (auth or remote) was modified and
        `upload_configuration.agents.allow_higher_versions.allow` is false.
    """
    if upload_configuration is None:
        upload_configuration = api_configuration.api_conf['upload_configuration']

    for pointer, knob, code in PROTECTED_SECTIONS:
        if _knob(upload_configuration, knob):
            continue
        if _resolve_pointer(new_document, pointer) != _resolve_pointer(current_document, pointer):
            raise WazuhError(code, extra_message=pointer)
