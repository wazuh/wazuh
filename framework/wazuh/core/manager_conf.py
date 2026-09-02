# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Reader and writer of the manager configuration file (etc/wazuh-manager.conf).

Consumer of `bin/wazuh-manager-conf`, the CLI of shared_modules/manager_config — the same loader the C
daemons and the engine use — so there is exactly one implementation of the configuration language
(strict XML, JSON Schema, defaults, cross-field semantics): load_manager_conf() returns the effective
document `bin/wazuh-manager-conf dump` prints, and load_manager_conf_text() validates and parses a
candidate text (the API upload) through a temporary file. Like the daemons' own loader
(w_mconf_load), reading here never requires the certificate/key files the document names to exist:
that check belongs to `-t`/wazuh.core.manager.validate_manager_conf(). The schema copy is read only
to enumerate the valid section names (the installed etc/wazuh-manager.schema.json, or its source in a
repository checkout).
"""

import json
import os
import subprocess  # nosec B404 - runs the fixed wazuh-manager-conf CLI with a list argv, never a shell
import tempfile
from functools import lru_cache

from wazuh.core import common
from wazuh.core.exception import WazuhError
from wazuh.core.utils import safe_move

# Detail prefixes of the CLI error line: "(1244): Invalid configuration at '<file>': <detail>." and
# "(1239): Configuration file not found: '<file>'.". Syntax problems carry the "invalid XML" marker
# (with the line embedded); everything else under 1244 is a schema or cross-field violation whose
# detail starts with the JSON pointer of the offending option.
_NOT_FOUND_MARKER = 'Configuration file not found'
_SYNTAX_MARKER = 'invalid XML'


# Where the CLI lives in a repository checkout (WAZUH_PATH is then the repository root, see find_wazuh_path()).
_SOURCE_CLI = os.path.join('src', 'build', 'bin', 'wazuh-manager-conf')


_resolved_cli_paths = {}


def cli_path() -> str:
    """Path of the manager configuration CLI: the installed bin/wazuh-manager-conf, or the built one of a
    development checkout (src/build/bin). Like schema_path(), the resolution is remembered per configured path."""
    configured = os.path.join(common.WAZUH_PATH, 'bin', 'wazuh-manager-conf')
    if configured not in _resolved_cli_paths:
        resolved = configured
        if not os.path.isfile(configured):
            source = os.path.join(common.WAZUH_PATH, _SOURCE_CLI)
            if os.path.isfile(source):
                resolved = source
        _resolved_cli_paths[configured] = resolved
    return _resolved_cli_paths[configured]


def _run_cli(arguments: list) -> subprocess.CompletedProcess:
    """Run the CLI. Raises WazuhError(1908) when it cannot be executed at all."""
    try:
        return subprocess.run([cli_path(), *arguments], capture_output=True, text=True, timeout=30)  # nosec B603
    except (OSError, subprocess.SubprocessError) as e:
        raise WazuhError(1908, extra_message=str(e))


def _error_detail(completed: subprocess.CompletedProcess) -> str:
    """The CLI error line, reduced to '<pointer>: <message>' (validation) or '<message>' (syntax).

    The 1244 contract puts the JSON pointer of the offending option in the quoted subject of
    "Invalid configuration at '<subject>'"; syntax and file problems carry the file path there
    instead, which is dropped (the syntax message embeds the line on its own).
    """
    detail = (completed.stderr or completed.stdout).strip()
    prefix = "Invalid configuration at '"
    start = detail.find(prefix)
    if start != -1:
        rest = detail[start + len(prefix):]
        end = rest.find("': ")
        if end != -1:
            subject, message = rest[:end], rest[end + 3:]
            detail = f'{subject}: {message}' if subject.startswith('/') else message
    return detail.rstrip('.')


def _raise_dump_error(completed: subprocess.CompletedProcess, conf_file: str):
    detail = _error_detail(completed)
    if completed.returncode != 1:
        raise WazuhError(1908, extra_message=detail)
    if _NOT_FOUND_MARKER in detail:
        raise WazuhError(1101, extra_message=conf_file)
    if _SYNTAX_MARKER in detail:
        raise WazuhError(1131, extra_message=detail)
    raise WazuhError(1130, extra_message=detail)


def load_manager_conf(conf_file: str = None) -> dict:
    """Load the effective manager configuration (parsed, validated, defaults applied).

    Parameters
    ----------
    conf_file : str
        File to read. Default: common.MANAGER_CONF.

    Raises
    ------
    WazuhError(1101)
        The file does not exist or cannot be read.
    WazuhError(1131)
        XML syntax error (the message embeds the line).
    WazuhError(1130)
        Schema or cross-field violation (the message starts with the JSON pointer).

    Returns
    -------
    dict
        The effective document, exactly what `bin/wazuh-manager-conf dump` prints.
    """
    conf_file = conf_file or common.MANAGER_CONF
    completed = _run_cli(['-H', common.WAZUH_PATH, '-f', conf_file, '--skip-file-checks', 'dump'])
    if completed.returncode != 0:
        _raise_dump_error(completed, conf_file)
    try:
        return json.loads(completed.stdout)
    except ValueError as e:
        raise WazuhError(1908, extra_message=str(e))


def load_manager_conf_text(text: str) -> dict:
    """Validate and parse the text of a candidate configuration file (the API upload).

    One CLI call checks the syntax and the schema and applies the defaults; the certificate/key files
    the text names are not required to exist yet (they are checked against the written file by
    wazuh.core.manager.validate_manager_conf()).

    Parameters
    ----------
    text : str
        Content of a whole configuration file.

    Raises
    ------
    WazuhError(1131)
        XML syntax error.
    WazuhError(1130)
        Schema or cross-field violation.

    Returns
    -------
    dict
        The effective document of the candidate text.
    """
    fd, tmp_file = tempfile.mkstemp(prefix='wazuh-manager.conf.', dir=common.OSSEC_TMP_PATH)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        completed = _run_cli(['-H', common.WAZUH_PATH, '-f', tmp_file, '--skip-file-checks', 'dump'])
    finally:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)

    if completed.returncode != 0:
        _raise_dump_error(completed, tmp_file)
    try:
        return json.loads(completed.stdout)
    except ValueError as e:
        raise WazuhError(1908, extra_message=str(e))


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

        fd, tmp_file = tempfile.mkstemp(prefix='wazuh-manager.conf.', dir=common.OSSEC_TMP_PATH)
        with os.fdopen(fd, 'w') as f:
            f.write(new_conf)
        safe_move(tmp_file, conf_file, ownership=ownership, permissions=permissions)
    except Exception as e:
        raise WazuhError(1126, extra_message=str(e))
