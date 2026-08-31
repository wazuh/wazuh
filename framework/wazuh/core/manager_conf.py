# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Reader and writer of the manager configuration file (etc/wazuh-manager.yml).

Python twin of shared_modules/manager_config, the C++ loader the daemons use: the same YAML 1.2 loading rules (only
true/false are booleans; no anchors, aliases, tags or multi-document streams), the same JSON Schema (the installed
copy, etc/wazuh-manager.schema.json) and the same defaults-filling algorithm, so the effective document equals
`bin/wazuh-manager-conf dump`. The cross-field semantics (certificate files, port collisions...) stay in the C++
library: wazuh.core.manager.validate_manager_conf() runs the CLI instead of duplicating them here.
"""

import json
import os
import re
import tempfile
from copy import deepcopy
from functools import lru_cache
from typing import Optional, Tuple

import jsonschema
import yaml

from wazuh.core import common
from wazuh.core.exception import WazuhError
from wazuh.core.utils import safe_move


class Yaml12Loader(yaml.SafeLoader):
    """SafeLoader with the YAML 1.1 bool resolver replaced by the YAML 1.2 core one (`yes`/`no`/`on`/`off` stay strings)."""


Yaml12Loader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers if tag != 'tag:yaml.org,2002:bool']
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
Yaml12Loader.add_implicit_resolver('tag:yaml.org,2002:bool',
                                   re.compile(r'^(?:true|True|TRUE|false|False|FALSE)$'), list('tTfF'))


def _where(event) -> str:
    mark = event.start_mark
    return f'{mark.line + 1}:{mark.column + 1}'


def load_yaml_text(text: str) -> dict:
    """Parse the text of a manager configuration file.

    Parameters
    ----------
    text : str
        YAML text. An empty document (or one with comments only) is the empty mapping: every option takes its default.

    Raises
    ------
    WazuhError(1131)
        Syntax error (with line:column), more than one document, anchors, aliases, tags, or a root that is not a mapping.

    Returns
    -------
    dict
        The document as written (no defaults applied).
    """
    try:
        documents = 0
        for event in yaml.parse(text, Loader=Yaml12Loader):
            if isinstance(event, yaml.DocumentStartEvent):
                documents += 1
                if documents > 1:
                    raise WazuhError(1131, extra_message=f'{_where(event)}: exactly one YAML document is required')
            elif isinstance(event, yaml.AliasEvent):
                raise WazuhError(1131, extra_message=f'{_where(event)}: anchors and aliases are not allowed')
            elif getattr(event, 'anchor', None) is not None:
                raise WazuhError(1131, extra_message=f'{_where(event)}: anchors and aliases are not allowed')
            elif getattr(event, 'tag', None) is not None:
                raise WazuhError(1131, extra_message=f'{_where(event)}: tags are not allowed')
        document = yaml.load(text, Loader=Yaml12Loader)  # nosec B506 - SafeLoader subclass
    except yaml.MarkedYAMLError as e:
        mark = e.problem_mark
        where = f'{mark.line + 1}:{mark.column + 1}: ' if mark is not None else ''
        raise WazuhError(1131, extra_message=f'{where}{e.problem or e}')
    except yaml.YAMLError as e:
        raise WazuhError(1131, extra_message=str(e))

    if document is None:
        return {}
    if not isinstance(document, dict):
        raise WazuhError(1131, extra_message='the document root must be a mapping')
    return document


@lru_cache(maxsize=4)
def _load_schema(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# Where the schema lives in a repository checkout (WAZUH_PATH is then the repository root, see find_wazuh_path()).
_SOURCE_SCHEMA = os.path.join('src', 'shared_modules', 'manager_config', 'schema', 'wazuh-manager.schema.json')


_resolved_schema_paths = {}


def schema_path() -> str:
    """Path of the JSON Schema: the installed copy (etc/wazuh-manager.schema.json), or its source in a development checkout.

    The resolution is remembered per configured path: it happens once per process (usually at import time, through
    wazuh.manager), so patched `os.path.exists`/`open` in unit tests cannot redirect it afterwards.
    """
    configured = common.MANAGER_CONF_SCHEMA
    if configured not in _resolved_schema_paths:
        resolved = configured
        if not os.path.isfile(configured):
            source = os.path.join(common.WAZUH_PATH, _SOURCE_SCHEMA)
            if os.path.isfile(source):
                resolved = source
        _resolved_schema_paths[configured] = resolved
    return _resolved_schema_paths[configured]


def schema() -> dict:
    """The JSON Schema (draft-04) of the manager configuration (cached per resolved path)."""
    return _load_schema(schema_path())


def first_schema_error(document: dict) -> Optional[Tuple[str, str, str]]:
    """First schema violation of a document, as (JSON pointer, keyword, message), or None.

    The pointer follows the convention of the C++ library (rapidjson): it names the offending element, not its
    container (`/remote/https/foo` for an unknown option, `/remote/legacy/protocol/1` for a duplicate).
    """
    validator = jsonschema.Draft4Validator(schema())
    errors = sorted(validator.iter_errors(document), key=lambda e: (len(e.absolute_path), str(e.absolute_path)))
    if not errors:
        return None

    error = errors[0]
    pointer = ''.join(f'/{part}' for part in error.absolute_path)
    if error.validator == 'additionalProperties' and isinstance(error.instance, dict):
        known = set(error.schema.get('properties', {}))
        extra = sorted(k for k in error.instance if k not in known)
        if extra:
            pointer += f'/{extra[0]}'
    elif error.validator == 'uniqueItems' and isinstance(error.instance, list):
        seen = []
        for index, item in enumerate(error.instance):
            if item in seen:
                pointer += f'/{index}'
                break
            seen.append(item)

    return pointer or '/', error.validator, error.message


def validate_document(document: dict):
    """Validate a document against the schema.

    Raises
    ------
    WazuhError(1130)
        "<pointer>: <message> (schema keyword '<keyword>')" for the first violation.
    """
    error = first_schema_error(document)
    if error is not None:
        pointer, keyword, message = error
        raise WazuhError(1130, extra_message=f"{pointer}: {message} (schema keyword '{keyword}')")


def _resolve(node, root):
    """Follow local `$ref`s ("#/definitions/x"), as the C++ library does, or return the schema node itself."""
    while isinstance(node, dict) and isinstance(node.get('$ref'), str) and node['$ref'].startswith('#'):
        target = root
        for part in node['$ref'][1:].strip('/').split('/'):
            if part == '':
                continue
            target = target[part]
        node = target
    return node


def _is_object_schema(node) -> bool:
    return isinstance(node, dict) and ('properties' in node or node.get('type') == 'object')


def _fill_defaults(schema_node, root, node: dict):
    schema_node = _resolve(schema_node, root)
    if not isinstance(node, dict) or not isinstance(schema_node, dict):
        return
    properties = schema_node.get('properties')
    if not isinstance(properties, dict):
        return

    for name, property_schema in properties.items():
        resolved = _resolve(property_schema, root)
        if name not in node:
            if isinstance(property_schema, dict) and 'default' in property_schema:
                node[name] = deepcopy(property_schema['default'])
            elif isinstance(resolved, dict) and 'default' in resolved:
                node[name] = deepcopy(resolved['default'])
            elif _is_object_schema(resolved):
                node[name] = {}
        if isinstance(node.get(name), dict):
            _fill_defaults(resolved, root, node[name])


def apply_defaults(document: dict) -> dict:
    """Fill the document in place with the schema defaults (the effective document) and return it.

    Same algorithm as shared_modules/manager_config (defaults.cpp): a missing property takes its `default` (own or of
    the definition it references); a missing object without one is created empty and filled recursively, so every
    section the schema defines exists in the result.
    """
    root = schema()
    _fill_defaults(root, root, document)
    return document


def load_manager_conf(conf_file: str = None) -> dict:
    """Load the effective manager configuration (parsed, validated, defaults applied).

    Parameters
    ----------
    conf_file : str
        File to read. Default: common.MANAGER_CONF.

    Raises
    ------
    WazuhError(1101)
        The file cannot be read.
    WazuhError(1131)
        YAML syntax error.
    WazuhError(1130)
        Schema violation.
    """
    conf_file = conf_file or common.MANAGER_CONF
    try:
        with open(conf_file) as f:
            text = f.read()
    except OSError as e:
        raise WazuhError(1101, extra_message=str(e))

    document = load_yaml_text(text)
    validate_document(document)
    return apply_defaults(document)


def write_manager_conf(new_conf: str, conf_file: str = None):
    """Replace the manager configuration file atomically, keeping its owner and mode.

    Parameters
    ----------
    new_conf : str
        New file content (validated by the caller).
    conf_file : str
        File to replace. Default: common.MANAGER_CONF.

    Raises
    ------
    WazuhError(1126)
        The file could not be written.
    """
    conf_file = conf_file or common.MANAGER_CONF
    try:
        current = os.stat(conf_file) if os.path.exists(conf_file) else None
        permissions = (current.st_mode & 0o777) if current else 0o660
        # Only root may hand the file to another owner; the API daemon (wazuh-manager) keeps its own uid, the
        # group and the mode are what the other daemons need to read it.
        ownership = None
        if os.geteuid() == 0:
            ownership = (current.st_uid, current.st_gid) if current else (common.wazuh_uid(), common.wazuh_gid())

        fd, tmp_file = tempfile.mkstemp(prefix='wazuh-manager.yml.', dir=common.OSSEC_TMP_PATH)
        with os.fdopen(fd, 'w') as f:
            f.write(new_conf)
        safe_move(tmp_file, conf_file, ownership=ownership, permissions=permissions)
    except Exception as e:
        raise WazuhError(1126, extra_message=str(e))
