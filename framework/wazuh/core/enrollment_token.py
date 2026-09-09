# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Enrollment tokens (issue #38993): the framework side of authd's `token_create` / `token_list` /
`token_revoke` local-socket verbs -- the ones `wazuh-manager-authd --create-enrollment-token`,
`--list-enrollment-tokens` and `--revoke-enrollment-token` already speak (os_auth/src/token_cli.c).

authd owns the store (etc/enrollment_tokens.json) and every rule: the address must be one of the
names in the listener certificate, only the master node mints and revokes, a token's credential is
handed out once. This module only shapes the request, normalizes the answer and translates authd's
codes into the API's.
"""

import re

from wazuh.core import common
from wazuh.core.exception import WazuhError, WazuhException, WazuhResourceNotFound
from wazuh.core.utils import get_date_from_timestamp, get_timeframe_in_seconds
from wazuh.core.wazuh_socket import WazuhSocketJSON

# authd's codes for these verbs (os_auth/src/local-server.c, ERRORS[]).
AUTHD_NO_ARGUMENT = 9004      # `address` missing or empty
AUTHD_WORKER_NODE = 9015      # the store is written on the master only
AUTHD_TOKEN_NOT_FOUND = 9022  # unknown id, or one that is not the shape of a token id
AUTHD_MINT_REFUSED = 9025     # the request cannot be honoured; the message carries the detail
_REFUSED_PREFIX = 'Enrollment token refused: '
# The API's `timeframe` format (api/validator.py _timeframe_type), checked here too: get_timeframe_in_seconds()
# alone turns anything with a stray unit letter into 0, which authd would silently replace by its default.
_TIMEFRAME = re.compile(r'^\d+[dhms]?$')

# What purge_tokens() accepts, mirroring authd's own scopes (etoken_purge_t)
_PURGE_SCOPES = ('dead', 'all')


def _authd_request(function: str, arguments: dict = None):
    """Send one token verb to authd's local socket and return its `data`.

    Parameters
    ----------
    function : str
        `token_create`, `token_list`, `token_revoke` or `token_purge`.
    arguments : dict
        The verb's arguments, or None for the argument-less `token_list`.

    Raises
    ------
    WazuhResourceNotFound(1767)
        authd does not know the token (or the id is not the shape of a token id).
    WazuhError(1768)
        authd refused to mint: the message carries authd's detail (the address is not in the listener
        certificate's SAN, the certificate only names loopback, the CA does not sign it...).
    WazuhError(1769)
        This node is a cluster worker: tokens are minted and revoked on the master.
    WazuhException
        Any other authd error, as authd reported it.

    Returns
    -------
    dict or list
        The `data` member of authd's answer.
    """
    msg = {'function': function}
    if arguments is not None:
        msg['arguments'] = arguments

    try:
        authd_socket = WazuhSocketJSON(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()
    except WazuhException as e:
        if e.code == AUTHD_TOKEN_NOT_FOUND:
            raise WazuhResourceNotFound(1767, extra_message=str(arguments.get('id', '')) if arguments else None)
        if e.code == AUTHD_MINT_REFUSED:
            # authd's message is "Enrollment token refused: <detail>": keep only the detail, the code's
            # own text already says "refused".
            detail = str(e.message or '')
            raise WazuhError(1768, extra_message=detail.split(_REFUSED_PREFIX, 1)[-1] or detail)
        if e.code == AUTHD_NO_ARGUMENT:
            raise WazuhError(1768, extra_message='the address is required')
        if e.code == AUTHD_WORKER_NODE:
            raise WazuhError(1769)
        raise e

    return data


def _normalize(entry: dict) -> dict:
    """Shape one authd token record for the API: `adr` becomes `address`, epochs become UTC datetimes."""
    normalized = {}
    for key, value in entry.items():
        if key == 'adr':
            normalized['address'] = value
        elif key in ('created', 'expires') and value is not None:
            normalized[key] = get_date_from_timestamp(value)
        elif key in ('revoked', 'credential'):
            normalized[key] = bool(value)
        else:
            normalized[key] = value
    return normalized


def create_token(address: str, port: int = None, prefix: str = None, ttl: str = None, max_uses: int = None,
                 description: str = None, embed_ca: bool = False, no_credential: bool = False) -> dict:
    """Mint an enrollment token.

    Parameters
    ----------
    address : str
        Name (or IP) the agents connect to. Must be one of the listener certificate's names.
    port : int
        Listener port to write into the token when it differs from the configured one.
    prefix : str
        URL prefix to write into the token when it differs from the configured one.
    ttl : str
        Lifetime as a timeframe (`30d`, `12h`, `45m`, `90s`, or plain seconds). authd's default (30 days)
        when None.
    max_uses : int
        Enrollments the token allows; 0 or None means unlimited.
    description : str
        Free text shown when listing.
    embed_ca : bool
        Carry the CA certificate instead of its pin.
    no_credential : bool
        Token without credential (address and pin only).

    Raises
    ------
    WazuhError(1411)
        `ttl` is not a valid timeframe.

    Returns
    -------
    dict
        `token` (the text the agent pastes -- returned here and never again), `id`, `address`,
        `expires` (UTC datetime) and, unless the CA is embedded, `pin_hex`.
    """
    arguments = {'address': address}
    if port is not None:
        arguments['port'] = int(port)
    if prefix is not None:
        arguments['prefix'] = prefix
    if ttl is not None:
        if not _TIMEFRAME.match(str(ttl)) or get_timeframe_in_seconds(str(ttl)) <= 0:
            raise WazuhError(1411, extra_message=str(ttl))
        arguments['ttl'] = get_timeframe_in_seconds(str(ttl))
    if max_uses is not None:
        arguments['max_uses'] = int(max_uses)
    if description is not None:
        arguments['description'] = description
    if embed_ca:
        arguments['embed_ca'] = True
    if no_credential:
        arguments['no_credential'] = True

    return _normalize(_authd_request('token_create', arguments))


def list_tokens() -> list:
    """List the enrollment tokens as the operator may see them: never their credential or text.

    Returns
    -------
    list
        One dict per token: `id`, `address`, `created`, `expires` (UTC datetimes), `max_uses`, `uses`,
        `revoked`, `credential` (whether it carries one) and `description`.
    """
    return [_normalize(entry) for entry in _authd_request('token_list')]


def revoke_token(token_id: str) -> None:
    """Revoke an enrollment token. Idempotent on an already revoked token.

    Parameters
    ----------
    token_id : str
        The token's id (22 base64url characters).

    Raises
    ------
    WazuhResourceNotFound(1767)
        No token has that id.
    """
    _authd_request('token_revoke', {'id': token_id})


def purge_tokens(scope: str = 'dead') -> list:
    """Remove enrollment tokens from the store, instead of marking them revoked.

    Revoking and purging are different acts: a revoked token stays listed, revoked, and a purged one
    is gone. `dead` removes what can no longer authorise an enrollment (revoked, expired or out of
    uses) and leaves every usable token alone; `all` empties the store.

    Parameters
    ----------
    scope : str
        `dead` (default) or `all`.

    Raises
    ------
    WazuhError(1770)
        The scope is neither `dead` nor `all`.
    WazuhError(1769)
        This node is a cluster worker: the store is written on the master.

    Returns
    -------
    list
        The ids removed, in the order authd removed them.
    """
    if scope not in _PURGE_SCOPES:
        raise WazuhError(1770, extra_message=str(scope))

    data = _authd_request('token_purge', {'scope': scope})

    return data.get('ids', []) if isinstance(data, dict) else []
