# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Tests for the API daemon launcher, `api/scripts/wazuh_manager_apid.py`.

The bind is done by the launcher itself instead of by `uvicorn.run()` because uvicorn turns a
busy port into `sys.exit(1)` inside its own startup, which the launcher cannot catch and retry:
apid then stayed down until someone restarted it by hand even though the port freed up seconds
later. These tests cover the retry loop and the fact that `APIError(2010)` -- previously
unreachable, since the `except OSError` around `uvicorn.run()` never fired -- is now what an
exhausted retry budget actually produces.
"""

import ast
import errno
import importlib.util
import os
import socket
import threading
from unittest.mock import MagicMock, call, patch

import pytest

APID_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'wazuh_manager_apid.py')
)


def _load_apid():
    """Load the launcher script as a module.

    `api/scripts/` is not a package (no `__init__.py`), so the script cannot be imported by name.
    Loading it by path is the same approach `api/api/models/test/test_model.py` already uses. The
    script's heavy imports all live under its `if __name__ == '__main__'` guard, so loading it
    here only defines its functions.
    """
    spec = importlib.util.spec_from_file_location('wazuh_manager_apid', APID_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def apid():
    """Return a freshly loaded launcher module with its logger and shutdown event mocked.

    `_shutdown_event.wait` is mocked in every case so no test ever blocks for a real backoff.
    """
    module = _load_apid()
    module.logger = MagicMock()
    event = MagicMock(spec=threading.Event)
    event.wait.return_value = False
    event.is_set.return_value = False
    module._shutdown_event = event
    return module


def _prepare_start_without_rbac_db(apid, tmp_path, name='rbac.db'):
    """Stub `start()` as `_prepare_start` does, but point DB_FILE at a path that is not a database."""
    api_error = _prepare_start(apid)
    apid.DB_FILE = str(tmp_path / name)
    return api_error


@pytest.mark.parametrize('exists', [False, True], ids=['absent', 'empty'])
def test_start_refuses_to_create_the_rbac_database(apid, tmp_path, exists):
    """`start()` must not create `rbac.db`: it would seed passwords published nowhere.

    Creating it here gives the two default users generated passwords that never reach
    /etc/wazuh/credentials.env or the log, so the API starts and nobody can authenticate. The file
    belongs to the credential resolver; an empty one is a failed creation, not a database.
    """
    api_error = _prepare_start_without_rbac_db(apid, tmp_path)
    if exists:
        open(apid.DB_FILE, 'w').close()

    with pytest.raises(api_error) as error:
        apid.start({'host': ['0.0.0.0'], 'port': 55000, 'server_header': False})

    assert error.value.code == 2012
    apid.check_database_integrity.assert_not_called()
    assert not os.path.exists(apid.DB_FILE) or os.path.getsize(apid.DB_FILE) == 0


def _socket_factory(bind_outcomes):
    """Build a `socket.socket` replacement whose `bind()` follows a scripted list of outcomes.

    Parameters
    ----------
    bind_outcomes : list
        One entry per expected `bind()` call, consumed in order: `None` for success, an
        exception instance to raise.

    Returns
    -------
    tuple of (callable, list)
        The factory and the list it appends every created socket mock to.
    """
    created = []
    outcomes = list(bind_outcomes)

    def factory(family, sock_type=None, *args, **kwargs):
        sock = MagicMock(name=f'socket-{len(created)}')
        sock.family = family

        def bind(address, _sock=sock):
            _sock.bound_address = address
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome

        sock.bind.side_effect = bind
        created.append(sock)
        return sock

    return factory, created


def _in_use():
    return OSError(errno.EADDRINUSE, 'Address already in use')


def test_bind_succeeds_on_first_attempt(apid):
    """A free port is bound once per host, with no retry wait at all."""
    factory, created = _socket_factory([None, None])
    with patch('socket.socket', side_effect=factory):
        sockets = apid._bind_listening_sockets(['0.0.0.0', '::'], 55000)

    assert sockets == created
    assert [sock.bound_address[:2] for sock in created] == [('0.0.0.0', 55000), ('::', 55000)]
    assert [sock.family for sock in created] == [socket.AF_INET, socket.AF_INET6]
    apid._shutdown_event.wait.assert_not_called()
    for sock in created:
        sock.close.assert_not_called()


def test_bind_accepts_a_single_host_string(apid):
    """`host` may be a plain string, not only the dual-stack list the default configuration uses."""
    factory, created = _socket_factory([None])
    with patch('socket.socket', side_effect=factory):
        sockets = apid._bind_listening_sockets('127.0.0.1', 55000)

    assert len(sockets) == 1
    assert created[0].bound_address == ('127.0.0.1', 55000)
    assert created[0].family == socket.AF_INET


def test_bind_rejects_an_empty_host_list(apid):
    """An empty `host` list raises instead of yielding a server that listens on nothing.

    `api/api/validator.py`'s schema accepts `host: []`, and `asyncio.loop.create_server()` --
    what bound these sockets before -- raises `OSError('could not bind on any address out of
    [])` for it. Returning an empty socket list here would instead leave apid running, reported
    as such by `wazuh-manager-control status`, and reachable on nothing.
    """
    with patch('socket.socket') as socket_mock:
        with pytest.raises(OSError, match='could not bind on any address'):
            apid._bind_listening_sockets([], 55000)

    socket_mock.assert_not_called()
    apid._shutdown_event.wait.assert_not_called()


def test_bind_retries_with_increasing_backoff_then_succeeds(apid):
    """A transient busy port is retried, and the wait grows between attempts."""
    factory, created = _socket_factory([_in_use(), _in_use(), None])
    with patch('socket.socket', side_effect=factory):
        sockets = apid._bind_listening_sockets(['0.0.0.0'], 55000)

    assert sockets == [created[2]]
    assert apid._shutdown_event.wait.call_count == 2
    waits = [call.args[0] for call in apid._shutdown_event.wait.call_args_list]
    assert waits[0] < waits[1], f'backoff did not grow between attempts: {waits}'
    # backoff * 2**attempt plus up to a second of jitter.
    assert 2 <= waits[0] < 3
    assert 4 <= waits[1] < 5
    # Every failed attempt logs a warning; nothing is logged as an error until the budget is gone.
    assert apid.logger.warning.call_count == 2
    apid.logger.error.assert_not_called()


def test_bind_raises_after_exhausting_the_retry_budget(apid):
    """The original `OSError` surfaces once every attempt has failed, instead of being swallowed."""
    attempts = apid.BIND_MAX_RETRIES + 1
    factory, created = _socket_factory([_in_use()] * attempts)
    with patch('socket.socket', side_effect=factory):
        with pytest.raises(OSError) as exc_info:
            apid._bind_listening_sockets(['0.0.0.0'], 55000)

    assert exc_info.value.errno == errno.EADDRINUSE
    assert len(created) == attempts
    assert apid._shutdown_event.wait.call_count == apid.BIND_MAX_RETRIES


def test_bind_does_not_retry_a_non_eaddrinuse_error(apid):
    """A permission error on a privileged port fails immediately; retrying it cannot help."""
    factory, created = _socket_factory([OSError(errno.EACCES, 'Permission denied')])
    with patch('socket.socket', side_effect=factory):
        with pytest.raises(OSError) as exc_info:
            apid._bind_listening_sockets(['0.0.0.0'], 443)

    assert exc_info.value.errno == errno.EACCES
    assert len(created) == 1
    apid._shutdown_event.wait.assert_not_called()
    apid.logger.warning.assert_not_called()


def test_bind_closes_the_already_bound_socket_of_a_failed_attempt(apid):
    """Binding is all-or-nothing per attempt: a half-bound pair is never kept or retried onto.

    Without this, a retry would leak the IPv4 socket bound by the previous attempt and the next
    attempt's own IPv4 bind would then fail against apid itself.
    """
    factory, created = _socket_factory([None, _in_use(), None, None])
    with patch('socket.socket', side_effect=factory):
        sockets = apid._bind_listening_sockets(['0.0.0.0', '::'], 55000)

    assert sockets == [created[2], created[3]]
    created[0].close.assert_called_once()
    created[1].close.assert_called_once()
    created[2].close.assert_not_called()
    created[3].close.assert_not_called()


def test_bind_sets_v6only_on_ipv6_sockets_only(apid):
    """The IPv6 socket is bound v6-only, as `asyncio.loop.create_server()` does for a host list.

    Dropping this would let the IPv6 socket serve IPv4 clients as v4-mapped addresses, changing
    the remote address every request-scoped consumer of it sees (access log, brute-force IP
    blocking) from `1.2.3.4` to `::ffff:1.2.3.4`.
    """
    factory, created = _socket_factory([None, None])
    with patch('socket.socket', side_effect=factory):
        apid._bind_listening_sockets(['0.0.0.0', '::'], 55000)

    v6only = (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    assert v6only not in [call.args for call in created[0].setsockopt.call_args_list]
    assert v6only in [call.args for call in created[1].setsockopt.call_args_list]


def test_bind_skips_a_host_whose_address_family_is_unavailable(apid):
    """A host that can't bind because its address family doesn't exist here is skipped, not fatal.

    `asyncio.loop.create_server()` -- what bound these sockets before this function existed --
    tolerates `EADDRNOTAVAIL`/`EAFNOSUPPORT` per host (e.g. IPv6 disabled at the kernel level)
    and proceeds with whatever else binds; this keeps that same tolerance.
    """
    factory, created = _socket_factory([None, OSError(errno.EADDRNOTAVAIL, 'Cannot assign requested address')])
    with patch('socket.socket', side_effect=factory):
        sockets = apid._bind_listening_sockets(['0.0.0.0', '::'], 55000)

    assert sockets == [created[0]]
    created[1].close.assert_called_once()
    apid._shutdown_event.wait.assert_not_called()


def test_bind_skips_a_host_whose_socket_cannot_even_be_created(apid):
    """A family the kernel refuses to open a socket for is skipped, not only one that won't bind.

    A kernel booted with `ipv6.disable=1` fails `socket.socket(AF_INET6, ...)` itself with
    `EAFNOSUPPORT`, before any `bind()`; `net.ipv6.conf.all.disable_ipv6=1` instead opens the
    socket and fails the bind. `asyncio.loop.create_server()` skipped both, and with the default
    `host: ['0.0.0.0', '::']` treating the first as fatal would keep apid from starting at all
    on such a host.
    """
    factory, created = _socket_factory([None])

    def refusing_factory(family, *args, **kwargs):
        if family == socket.AF_INET6:
            raise OSError(errno.EAFNOSUPPORT, 'Address family not supported by protocol')
        return factory(family, *args, **kwargs)

    with patch('socket.socket', side_effect=refusing_factory):
        sockets = apid._bind_listening_sockets(['0.0.0.0', '::'], 55000)

    assert sockets == created
    assert created[0].family == socket.AF_INET
    apid.logger.warning.assert_called_once()
    apid._shutdown_event.wait.assert_not_called()


def test_bind_raises_when_every_host_is_skipped_as_unavailable(apid):
    """If every host's address family is unavailable, the attempt still fails: nothing to serve on."""
    factory, created = _socket_factory([
        OSError(errno.EADDRNOTAVAIL, 'Cannot assign requested address'),
        OSError(errno.EAFNOSUPPORT, 'Address family not supported'),
    ])
    with patch('socket.socket', side_effect=factory):
        with pytest.raises(OSError, match='could not bind on any address'):
            apid._bind_listening_sockets(['0.0.0.0', '::'], 55000)

    apid._shutdown_event.wait.assert_not_called()


def test_bind_resolves_family_via_getaddrinfo_not_a_literal_colon_check(apid):
    """Family comes from `getaddrinfo()`, so a hostname with no ':' can still resolve to IPv6.

    A `':' in host` check -- what this used to be -- would bind an AAAA-only hostname as
    `AF_INET` and fail; mocking `getaddrinfo` to return `AF_INET6` for a plain hostname string
    proves the family is no longer inferred from the string's own spelling.
    """
    factory, created = _socket_factory([None])
    fake_addrinfo = [
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('::1', 55000, 0, 0)),
    ]
    with patch('socket.socket', side_effect=factory), \
         patch('socket.getaddrinfo', return_value=fake_addrinfo) as getaddrinfo_mock:
        sockets = apid._bind_listening_sockets(['api.example.com'], 55000)

    assert sockets == created
    assert created[0].family == socket.AF_INET6
    assert created[0].bound_address == ('::1', 55000, 0, 0)
    getaddrinfo_mock.assert_called_once_with('api.example.com', 55000, type=socket.SOCK_STREAM,
                                             proto=socket.IPPROTO_TCP, flags=socket.AI_PASSIVE)


def test_bind_binds_every_address_a_host_resolves_to(apid):
    """A host with both A and AAAA records is bound on both, as `create_server()` did.

    Keeping only `getaddrinfo()[0]` would have `host: ['localhost']` listen on `::1` alone
    (glibc orders IPv6 first), refusing every client that connects to `127.0.0.1`.
    """
    factory, created = _socket_factory([None, None])
    fake_addrinfo = [
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('::1', 55000, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', 55000)),
    ]
    with patch('socket.socket', side_effect=factory), \
         patch('socket.getaddrinfo', return_value=fake_addrinfo):
        sockets = apid._bind_listening_sockets(['localhost'], 55000)

    assert sockets == created
    assert [sock.bound_address for sock in created] == [('::1', 55000, 0, 0), ('127.0.0.1', 55000)]


def test_bind_does_not_bind_the_same_address_twice(apid):
    """Two hosts resolving to one address share one socket instead of conflicting at listen()."""
    factory, created = _socket_factory([None])
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', 55000)),
    ]
    with patch('socket.socket', side_effect=factory), \
         patch('socket.getaddrinfo', return_value=fake_addrinfo):
        sockets = apid._bind_listening_sockets(['localhost', '127.0.0.1'], 55000)

    assert sockets == created
    assert len(created) == 1


def test_bind_aborts_when_shutdown_is_requested_during_a_retry_wait(apid):
    """A SIGTERM mid-retry aborts startup instead of retrying on with the pidfile already gone.

    `exit_handler` only deletes pidfiles; it never unwinds the process. Without this, a
    `wazuh-manager-control stop` during a retry wait would report apid as stopped while the
    process kept sleeping and retrying for the rest of its budget.
    """
    apid._shutdown_event.wait.return_value = True
    factory, created = _socket_factory([_in_use()])
    with patch('socket.socket', side_effect=factory):
        with pytest.raises(SystemExit) as exc_info:
            apid._bind_listening_sockets(['0.0.0.0'], 55000)

    assert exc_info.value.code == 0
    # Only the first attempt's socket was ever created: the loop did not try to bind again.
    assert len(created) == 1
    apid._shutdown_event.wait.assert_called_once()


def test_bind_against_a_real_kernel(apid):
    """Bind real sockets, with no `socket.socket` mock anywhere, on an ephemeral port.

    Every other case here drives `MagicMock` sockets, which accept any `setsockopt`/`bind`
    ordering. This one proves the real kernel accepts the calls as written: `IPV6_V6ONLY` has to
    be set before the bind to take effect, and `SO_REUSEADDR` before it for the dual-stack pair
    to share the port at all.
    """
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as ipv6_probe:
            ipv6_probe.bind(('::1', 0))
    except OSError as exc:
        pytest.skip(f'IPv6 is not available on this host: {exc}')

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()

    sockets = apid._bind_listening_sockets(['0.0.0.0', '::'], port)  # nosec B104
    try:
        assert [sock.getsockname()[:2] for sock in sockets] == [('0.0.0.0', port), ('::', port)]
        assert sockets[1].getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
        # Non-zero rather than 1: macOS reports the option's own flag value (4) when set.
        assert sockets[0].getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0

        # A listening socket on the same port is the conflict the retry loop exists for.
        sockets[0].listen(1)
        with pytest.raises(OSError) as exc_info:
            apid._bind_listening_sockets(['0.0.0.0'], port, retries=0)  # nosec B104
        assert exc_info.value.errno == errno.EADDRINUSE
    finally:
        for sock in sockets:
            sock.close()


def test_exit_handler_sets_the_shutdown_event_before_deleting_pidfiles(apid):
    """`exit_handler` releases the bind-retry wait, and does so before its pidfile cleanup."""
    calls = []
    apid._shutdown_event.set.side_effect = lambda: calls.append('set')
    pydaemon = MagicMock()
    pydaemon.delete_child_pids.side_effect = lambda *a, **kw: calls.append('delete_child_pids')
    pydaemon.delete_pid.side_effect = lambda *a, **kw: calls.append('delete_pid')
    apid.pyDaemonModule = pydaemon

    apid.exit_handler(15, None)

    assert calls == ['set', 'delete_child_pids', 'delete_pid']


def _prepare_start(apid):
    """Stub out everything `start()` touches except the bind, so its bind branch can be reached.

    A unit test of the helper alone would not show that `APIError(2010)` is reachable: it was
    already present before this change and never fired, because the bind happened inside
    `uvicorn.run()`.
    """

    class FakeAPIError(Exception):
        def __init__(self, code, details=None):
            super().__init__(f'API error {code}')
            self.code = code

    apid.check_database_integrity = MagicMock()
    # start() now refuses to run when rbac.db is absent instead of creating it, so point the guard at
    # a file that exists and is non-empty. APID_PATH is this script itself: any real file will do.
    apid.DB_FILE = APID_PATH
    apid.common = MagicMock()
    apid.common.mp_pools.get.return_value = {'thread_pool': MagicMock()}
    apid.pyDaemonModule = MagicMock()
    apid.asyncio = MagicMock()
    apid.AsyncApp = MagicMock()
    apid.SwaggerUIOptions = MagicMock()
    apid.lifespan_handler = MagicMock()
    apid.APIUriParser = MagicMock()
    apid.WazuhParameterValidator = MagicMock()
    apid.setup_middlewares = MagicMock()
    apid.error_handler = MagicMock()
    apid.ContentSizeExceeded = type('ContentSizeExceeded', (Exception,), {})
    apid.ExpectFailedException = type('ExpectFailedException', (Exception,), {})
    apid.Unauthorized = type('Unauthorized', (Exception,), {})
    apid.HTTPException = type('HTTPException', (Exception,), {})
    apid.ProblemException = type('ProblemException', (Exception,), {})
    apid.api_path = ['/tmp/api']  # nosec B108
    apid.api_conf = {'https': {'enabled': True}}
    apid.security_conf = {}
    apid.uvicorn = MagicMock()
    apid.APIError = FakeAPIError
    return FakeAPIError


def test_start_reports_an_exhausted_bind_as_api_error_2010(apid):
    """An exhausted retry budget reaches the operator as `APIError(2010)`, logged as an error."""
    api_error = _prepare_start(apid)
    in_use = _in_use()
    with patch.object(apid, '_bind_listening_sockets', side_effect=in_use):
        with pytest.raises(api_error) as exc_info:
            apid.start({'host': ['0.0.0.0'], 'port': 55000, 'server_header': False})

    assert exc_info.value.code == 2010
    apid.logger.error.assert_called_once()
    apid.uvicorn.Server.assert_not_called()


def test_start_reraises_a_non_eaddrinuse_bind_error_unchanged(apid):
    """Any other bind failure is logged and re-raised as itself, not relabelled as a busy port."""
    _prepare_start(apid)
    denied = OSError(errno.EACCES, 'Permission denied')
    with patch.object(apid, '_bind_listening_sockets', side_effect=denied):
        with pytest.raises(OSError) as exc_info:
            apid.start({'host': ['0.0.0.0'], 'port': 443, 'server_header': False})

    assert exc_info.value is denied
    apid.uvicorn.Server.assert_not_called()


def test_start_hands_the_bound_sockets_to_uvicorn(apid):
    """The sockets apid bound itself are what uvicorn serves on; host/port are not re-bound.

    Leaving `host`/`port` in the `uvicorn.Config` would be harmless but misleading, since the
    `sockets=` argument is what uvicorn actually listens on.
    """
    _prepare_start(apid)
    bound = [MagicMock(), MagicMock()]
    params = {'host': ['0.0.0.0', '::'], 'port': 55000, 'server_header': False, 'loop': 'uvloop'}
    with patch.object(apid, '_bind_listening_sockets', return_value=bound) as bind_mock:
        apid.start(params)

    bind_mock.assert_called_once_with(['0.0.0.0', '::'], 55000)
    config_kwargs = apid.uvicorn.Config.call_args.kwargs
    assert 'host' not in config_kwargs and 'port' not in config_kwargs
    assert config_kwargs == {'server_header': False, 'loop': 'uvloop', 'proxy_headers': False}
    apid.uvicorn.Server.assert_called_once_with(apid.uvicorn.Config.return_value)
    apid.uvicorn.Server.return_value.run.assert_called_once_with(sockets=bound)


def test_start_ignores_forwarded_headers_from_loopback(apid):
    """uvicorn must not take the client address from X-Forwarded-For.

    With its defaults (proxy_headers=True, FORWARDED_ALLOW_IPS=127.0.0.1) any local user could send
    the header over loopback and choose the address the login lockout, the per-IP rate limits and
    api.log see: unlimited guesses, or another host locked out.
    """
    from uvicorn import Config

    _prepare_start(apid)
    apid.uvicorn.Config.side_effect = lambda app, **kwargs: Config(app, **kwargs)
    with patch.dict(os.environ, {'FORWARDED_ALLOW_IPS': '*'}), \
            patch.object(apid, '_bind_listening_sockets', return_value=[MagicMock()]):
        apid.start({'host': ['0.0.0.0'], 'port': 55000, 'server_header': False})

    config = apid.uvicorn.Server.call_args.args[0]
    assert config.proxy_headers is False


def test_start_exits_when_the_server_never_started(apid):
    """A server that never started still ends the process non-zero, as `uvicorn.run()` did.

    `Server.run()` returns normally in that case, so without this a failed ASGI lifespan startup
    would be indistinguishable from a clean shutdown: apid would exit 0 with its PID files
    tidied up and nothing saying it never served anything.
    """
    _prepare_start(apid)
    apid.uvicorn.Server.return_value.started = False
    with patch.object(apid, '_bind_listening_sockets', return_value=[MagicMock()]):
        with pytest.raises(SystemExit) as exc_info:
            apid.start({'host': ['0.0.0.0'], 'port': 55000, 'server_header': False})

    assert exc_info.value.code == apid.UVICORN_STARTUP_FAILURE
    apid.logger.error.assert_called_once()


def test_start_returns_normally_after_a_clean_shutdown(apid):
    """A server that did start and then shut down is not reported as a startup failure."""
    _prepare_start(apid)
    apid.uvicorn.Server.return_value.started = True
    with patch.object(apid, '_bind_listening_sockets', return_value=[MagicMock()]):
        apid.start({'host': ['0.0.0.0'], 'port': 55000, 'server_header': False})

    apid.logger.error.assert_not_called()


def test_start_aborts_when_shutdown_was_requested_before_the_server_started(apid):
    """A SIGTERM that landed during the bind itself, not during a retry wait, still stops apid.

    `exit_handler` deletes the PID files and returns; only the retry wait observes the event.
    Without this check the bound sockets would be handed to uvicorn and the API would serve
    with wazuh-manager-control unable to see or stop it.
    """
    _prepare_start(apid)
    apid._shutdown_event.is_set.return_value = True
    bound = [MagicMock(), MagicMock()]
    with patch.object(apid, '_bind_listening_sockets', return_value=bound):
        with pytest.raises(SystemExit) as exc_info:
            apid.start({'host': ['0.0.0.0', '::'], 'port': 55000, 'server_header': False})

    assert exc_info.value.code == 0
    for sock in bound:
        sock.close.assert_called_once()
    apid.uvicorn.Server.assert_not_called()


def test_start_logs_an_oserror_raised_by_uvicorn_startup(apid):
    """An `OSError` from uvicorn's own startup (an `ssl.SSLError` from `Config.load()`) is logged.

    `__main__` only print()s the exception, and the process is daemonized with stdout on
    /dev/null by then, so without logging here apid would exit 1 leaving no trace of why.
    """
    _prepare_start(apid)
    ssl_error = OSError('[SSL] PEM lib')
    apid.uvicorn.Server.return_value.run.side_effect = ssl_error
    with patch.object(apid, '_bind_listening_sockets', return_value=[MagicMock()]):
        with pytest.raises(OSError) as exc_info:
            apid.start({'host': ['0.0.0.0'], 'port': 55000, 'server_header': False})

    assert exc_info.value is ssl_error
    apid.logger.error.assert_called_once_with(ssl_error)


def test_drop_privileges_clears_supplementary_groups_before_switching_ids(apid):
    """`drop_privileges()` must clear root's supplementary groups, and must do it while still root.

    `setgid()`/`setuid()` leave the supplementary list untouched, so without `setgroups([])` the
    API would keep root's groups (gid 0 among them). It has to run first: after `setuid()` the
    process can no longer change its groups.
    """
    apid.common = MagicMock()
    apid.common.wazuh_gid.return_value = 998
    apid.common.wazuh_uid.return_value = 997
    apid.api_conf = {'drop_privileges': True}
    calls = MagicMock()
    with patch.object(apid.os, 'setgroups', calls.setgroups), \
            patch.object(apid.os, 'setgid', calls.setgid), \
            patch.object(apid.os, 'setuid', calls.setuid):
        apid.drop_privileges(False)

    assert calls.mock_calls == [call.setgroups([]), call.setgid(998), call.setuid(997)]


# --- configure_ssl / drop_privileges (#40053) -----------------------------------------------------
#
# The API no longer generates its TLS pair: the installer issues it signed by the manager CA. The
# launcher drops privileges first and only then loads the TLS files, still in the foreground, so
# every record of the run -- the start-up announcement or a TLS error -- is written by the service
# user, and a TLS error still reaches the terminal and the exit code. A record written as root
# before setuid() used to let the midnight rotation recreate api.log as root, which the service
# then could not open.


def _write_self_signed_pair(directory, name, passphrase=None):
    """Write an independent self-signed RSA 2048 pair; the API does not verify the chain."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject) \
        .public_key(key.public_key()).serial_number(x509.random_serial_number()) \
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)) \
        .sign(key, hashes.SHA256())
    encryption = serialization.BestAvailableEncryption(passphrase) if passphrase \
        else serialization.NoEncryption()
    cert_path, key_path = directory / f'{name}.pem', directory / f'{name}-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           encryption))
    return str(cert_path), str(key_path)


@pytest.fixture(scope='module')
def pem_pairs(tmp_path_factory):
    """Two unrelated real pairs, so a certificate can be combined with the other pair's key.

    The second pair's certificate doubles as a real client CA file for `use_ca`.
    """
    directory = tmp_path_factory.mktemp('pairs')
    return _write_self_signed_pair(directory, 'apid'), _write_self_signed_pair(directory, 'other')


@pytest.fixture()
def ssl_apid(apid, tmp_path):
    """The launcher with what its `__main__` block would have imported for configure_ssl()."""
    import ssl

    from api.api_exception import APIError

    apid.ssl = ssl
    apid.APIError = APIError
    # api.util.to_relative_path() is relative to WAZUH_PATH; the identity keeps the paths readable.
    apid.to_relative_path = lambda path: path
    apid.api_conf = {
        'https': {'key': str(tmp_path / 'apid-key.pem'), 'cert': str(tmp_path / 'apid.pem'),
                  'use_ca': False, 'ca': str(tmp_path / 'ca.pem'), 'ssl_ciphers': ''},
        'drop_privileges': True,
    }
    apid.common = MagicMock()
    apid.common.wazuh_uid.return_value = 1001
    apid.common.wazuh_gid.return_value = 1002
    return apid


def _use_pair(apid, cert, key):
    apid.api_conf['https']['cert'] = cert
    apid.api_conf['https']['key'] = key


@pytest.mark.parametrize('use_ca', [False, True], ids=['use_ca=False', 'use_ca=True'])
def test_configure_ssl_sets_the_uvicorn_ssl_params(ssl_apid, pem_pairs, use_ca):
    """A present, coherent pair (and a real CA with use_ca) is loaded and handed to uvicorn."""
    (cert, key), (other_cert, _) = pem_pairs
    _use_pair(ssl_apid, cert, key)
    ssl_apid.api_conf['https']['use_ca'] = use_ca
    ssl_apid.api_conf['https']['ca'] = other_cert
    ssl_apid.api_conf['https']['ssl_ciphers'] = 'DEFAULT:!kRSA'
    params = {}

    with patch('os.chown') as chown:
        ssl_apid.configure_ssl(params)

    assert params['ssl_certfile'] == cert
    assert params['ssl_keyfile'] == key
    assert params['ssl_version'] == ssl_apid.ssl.PROTOCOL_TLS_SERVER
    # As written: OpenSSL keywords are case-sensitive, and `!KRSA` would have excluded nothing.
    assert params['ssl_ciphers'] == 'DEFAULT:!kRSA'
    ssl_apid.logger.warning.assert_not_called()
    if use_ca:
        assert params['ssl_cert_reqs'] == ssl_apid.ssl.CERT_REQUIRED
        assert params['ssl_ca_certs'] == other_cert
    else:
        assert 'ssl_cert_reqs' not in params and 'ssl_ca_certs' not in params
    chown.assert_not_called()
    ssl_apid.logger.error.assert_not_called()


@pytest.mark.parametrize('missing', ['key', 'cert'])
def test_configure_ssl_refuses_a_missing_file(ssl_apid, pem_pairs, tmp_path, missing):
    """A missing certificate or key is a 2003 naming it; nothing is generated in its place."""
    import shutil

    (cert, key), _ = pem_pairs
    present = {'cert': cert, 'key': key}
    for which in ('cert', 'key'):
        if which != missing:
            shutil.copy(present[which], ssl_apid.api_conf['https'][which])
    absent = ssl_apid.api_conf['https'][missing]
    before = sorted(os.listdir(tmp_path))

    with pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert absent in str(error.value)
    assert 'not found' in str(error.value)
    # The up-front check names exactly the missing file; the errno 2 fallback of a failed load
    # (ssl gives no filename) could only name both.
    other = ssl_apid.api_conf['https']['cert' if missing == 'key' else 'key']
    assert other not in str(error.value)
    ssl_apid.logger.error.assert_called_once_with(error.value)
    assert sorted(os.listdir(tmp_path)) == before


def test_configure_ssl_refuses_a_missing_client_ca(ssl_apid, pem_pairs):
    """With use_ca, a missing CA file is a 2003 naming the CA, not the pair."""
    (cert, key), _ = pem_pairs
    _use_pair(ssl_apid, cert, key)
    ssl_apid.api_conf['https']['use_ca'] = True
    ca = ssl_apid.api_conf['https']['ca']

    with pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert ca in str(error.value) and cert not in str(error.value) and key not in str(error.value)
    ssl_apid.logger.error.assert_called_once_with(error.value)


def test_configure_ssl_refuses_a_client_ca_that_is_not_pem(ssl_apid, pem_pairs, tmp_path):
    """With use_ca, a CA file that is not PEM is loaded and refused now, naming it, not inside uvicorn."""
    (cert, key), _ = pem_pairs
    _use_pair(ssl_apid, cert, key)
    ca = tmp_path / 'ca.pem'
    ca.write_text('not a certificate\n')
    ssl_apid.api_conf['https'].update(use_ca=True, ca=str(ca))

    with pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert str(ca) in str(error.value)
    ssl_apid.logger.error.assert_called_once_with(error.value)


def test_configure_ssl_refuses_a_key_that_does_not_match(ssl_apid, pem_pairs):
    """A certificate with somebody else's key is a 2003 naming both files."""
    (cert, _), (_, other_key) = pem_pairs
    _use_pair(ssl_apid, cert, other_key)

    with pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert 'does not match' in str(error.value)
    assert cert in str(error.value) and other_key in str(error.value)
    ssl_apid.logger.error.assert_called_once_with(error.value)


def test_configure_ssl_refuses_a_garbage_certificate(ssl_apid, pem_pairs, tmp_path):
    """A certificate file that is not PEM is a 2003 saying so, naming both files."""
    (_, key), _ = pem_pairs
    garbage = tmp_path / 'garbage.pem'
    garbage.write_text('not a certificate\n')
    _use_pair(ssl_apid, str(garbage), key)

    with pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert 'not a valid unencrypted PEM' in str(error.value)
    assert str(garbage) in str(error.value) and key in str(error.value)
    ssl_apid.logger.error.assert_called_once_with(error.value)


def test_configure_ssl_refuses_an_encrypted_key_without_prompting(ssl_apid, tmp_path):
    """An encrypted key fails at once: OpenSSL must not prompt for its passphrase on the terminal.

    Run pytest with stdin from /dev/null too; with a tty and no password callback this would hang.
    """
    cert, key = _write_self_signed_pair(tmp_path, 'encrypted', passphrase=b'secret')
    _use_pair(ssl_apid, cert, key)

    with pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert 'not a valid unencrypted PEM' in str(error.value) and key in str(error.value)


def test_configure_ssl_refuses_a_cipher_string_that_selects_nothing(ssl_apid, pem_pairs):
    """An ssl_ciphers value OpenSSL cannot use is a 2003 naming it, not a key/cert mismatch."""
    (cert, key), _ = pem_pairs
    _use_pair(ssl_apid, cert, key)
    ssl_apid.api_conf['https']['ssl_ciphers'] = 'no-such-cipher'

    with pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert 'no-such-cipher' in str(error.value)
    assert 'does not match' not in str(error.value)
    ssl_apid.logger.error.assert_called_once_with(error.value)


def test_configure_ssl_uppercases_a_lowercase_cipher_list_with_a_warning(ssl_apid, pem_pairs):
    """A list that OpenSSL rejects as written but accepts uppercased still starts, and says so.

    Earlier releases uppercased every cipher string, so `ecdhe+aesgcm` is a configuration that
    works today only because of that; it keeps working, with one warning naming the option.
    """
    (cert, key), _ = pem_pairs
    _use_pair(ssl_apid, cert, key)
    ssl_apid.api_conf['https']['ssl_ciphers'] = 'ecdhe+aesgcm'
    params = {}

    ssl_apid.configure_ssl(params)

    assert params['ssl_ciphers'] == 'ECDHE+AESGCM'
    ssl_apid.logger.warning.assert_called_once()
    warning = ssl_apid.logger.warning.call_args.args[0]
    assert 'ssl_ciphers' in warning and 'ecdhe+aesgcm' in warning and 'ECDHE+AESGCM' in warning
    ssl_apid.logger.error.assert_not_called()


def test_configure_ssl_serves_an_aead_default_when_ssl_ciphers_is_empty(ssl_apid, pem_pairs):
    """An empty ssl_ciphers hands uvicorn the API's own default instead of uvicorn's "TLSv1".

    uvicorn's default left TLS 1.2 with two CBC/SHA-1 suites and no AEAD one. The default selects
    forward-secret AEAD suites only; the TLS 1.3 suites are not chosen by a cipher string.
    """
    (cert, key), _ = pem_pairs
    _use_pair(ssl_apid, cert, key)
    ssl_apid.api_conf['https']['ssl_ciphers'] = ''
    params = {}

    ssl_apid.configure_ssl(params)

    assert params['ssl_ciphers'] == ssl_apid.DEFAULT_SSL_CIPHERS
    ssl_apid.logger.warning.assert_not_called()

    context = ssl_apid.ssl.SSLContext(ssl_apid.ssl.PROTOCOL_TLS_SERVER)
    context.set_ciphers(params['ssl_ciphers'])
    tls12 = [cipher['name'] for cipher in context.get_ciphers() if cipher['protocol'] == 'TLSv1.2']
    assert tls12
    assert all(name.startswith('ECDHE') and ('GCM' in name or 'CHACHA20' in name) for name in tls12)


def _failing_load(apid, exc):
    context = MagicMock()
    context.load_cert_chain.side_effect = exc
    return patch.object(apid.ssl, 'create_default_context', return_value=context)


def test_configure_ssl_reports_an_unreadable_pair(ssl_apid, pem_pairs):
    """A pair the service user cannot read is a 2003 about permissions naming both files."""
    (cert, key), _ = pem_pairs
    _use_pair(ssl_apid, cert, key)

    with _failing_load(ssl_apid, PermissionError(13, 'denied')), pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert 'correct permissions' in str(error.value)
    assert cert in str(error.value) and key in str(error.value)
    ssl_apid.logger.error.assert_called_once_with(error.value)


@pytest.mark.parametrize('filename', ['/p/f', None], ids=['with_filename', 'without_filename'])
def test_configure_ssl_reports_a_file_removed_before_the_load(ssl_apid, pem_pairs, filename):
    """A file gone between the check and the load names it when known, else every file loaded."""
    (cert, key), _ = pem_pairs
    _use_pair(ssl_apid, cert, key)
    exc = FileNotFoundError(2, 'x', filename) if filename else FileNotFoundError(2, 'x')

    with _failing_load(ssl_apid, exc), pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert 'not found' in str(error.value)
    if filename:
        assert filename in str(error.value)
        assert cert not in str(error.value) and key not in str(error.value)
    else:
        assert cert in str(error.value) and key in str(error.value)
    ssl_apid.logger.error.assert_called_once_with(error.value)


def test_configure_ssl_turns_any_other_ioerror_into_api_error(ssl_apid, pem_pairs):
    """Any other I/O failure while loading the pair still leaves configure_ssl() as an APIError."""
    from api.constants import CONFIG_FILE_PATH

    (cert, key), _ = pem_pairs
    _use_pair(ssl_apid, cert, key)
    eio = OSError(5, 'eio')

    with _failing_load(ssl_apid, eio), pytest.raises(ssl_apid.APIError) as error:
        ssl_apid.configure_ssl({})

    assert error.value.code == 2003
    assert CONFIG_FILE_PATH in str(error.value)
    assert error.value.__cause__ is eio
    ssl_apid.logger.error.assert_called_once()


def _drop_privileges_calls(apid, run_as_root):
    parent = MagicMock()
    with patch('os.setgroups') as setgroups, patch('os.setgid') as setgid, patch('os.setuid') as setuid:
        parent.attach_mock(setgroups, 'setgroups')
        parent.attach_mock(setgid, 'setgid')
        parent.attach_mock(setuid, 'setuid')
        parent.attach_mock(apid.logger.info, 'info')
        apid.drop_privileges(run_as_root)
    return parent.mock_calls


def test_drop_privileges_switches_user_without_logging(ssl_apid):
    """The switch logs nothing: the logging configuration is applied only after it."""
    assert _drop_privileges_calls(ssl_apid, run_as_root=False) == [
        call.setgroups([]), call.setgid(1002), call.setuid(1001)]


def test_drop_privileges_keeps_root_when_asked(ssl_apid):
    """-r keeps root."""
    assert _drop_privileges_calls(ssl_apid, run_as_root=True) == []


def test_drop_privileges_honours_drop_privileges_false(ssl_apid):
    """drop_privileges: false in api.yaml keeps the current user."""
    ssl_apid.api_conf['drop_privileges'] = False
    assert _drop_privileges_calls(ssl_apid, run_as_root=False) == []


# --- prepare_log_file ------------------------------------------------------------------------------
#
# It runs as root in logs/, which the service account can write, so a planted symbolic link must
# never redirect the chown/chmod to another file (or create one elsewhere).


@pytest.fixture()
def log_apid(apid):
    """The launcher with the service ids set to the current user, so fchown() needs no privilege."""
    apid.common = MagicMock()
    apid.common.wazuh_uid.return_value = os.getuid()
    apid.common.wazuh_gid.return_value = os.getgid()
    return apid


def test_prepare_log_file_creates_a_missing_file(log_apid, tmp_path):
    """An absent log file is created empty with mode 0660, owned by the service user."""
    path = tmp_path / 'api.log'
    log_apid.prepare_log_file(str(path))

    st = os.lstat(path)
    assert st.st_size == 0
    assert (st.st_mode & 0o7777, st.st_uid, st.st_gid) == (0o660, os.getuid(), os.getgid())


def test_prepare_log_file_keeps_the_content_and_fixes_the_mode(log_apid, tmp_path):
    """An existing log file keeps its records; only its mode is corrected."""
    path = tmp_path / 'api.log'
    path.write_text('previous run\n')
    path.chmod(0o600)
    log_apid.prepare_log_file(str(path))

    assert path.read_text() == 'previous run\n'
    assert os.lstat(path).st_mode & 0o7777 == 0o660


def test_prepare_log_file_chowns_through_the_descriptor(log_apid, tmp_path):
    """A file not owned by the service user is changed with fchown(), never chown() by path."""
    path = tmp_path / 'api.log'
    path.touch()
    log_apid.common.wazuh_uid.return_value = os.getuid() + 1
    with patch('os.fchown') as fchown, patch('os.chown') as chown, patch('os.lchown') as lchown:
        log_apid.prepare_log_file(str(path))

    fchown.assert_called_once()
    assert fchown.call_args.args[1:] == (os.getuid() + 1, os.getgid())
    chown.assert_not_called()
    lchown.assert_not_called()


@pytest.mark.parametrize('target_exists', [True, False], ids=['existing-target', 'dangling'])
def test_prepare_log_file_refuses_a_symbolic_link(log_apid, tmp_path, target_exists):
    """A symbolic link is refused: its target is neither created nor changed."""
    target = tmp_path / 'root-owned'
    if target_exists:
        target.write_text('secret')
        target.chmod(0o600)
    link = tmp_path / 'api.log'
    link.symlink_to(target)

    with patch('os.fchown') as fchown, pytest.raises(OSError) as error:
        log_apid.prepare_log_file(str(link))

    assert error.value.errno == errno.ELOOP
    assert error.value.filename == str(link)
    fchown.assert_not_called()
    if target_exists:
        assert target.read_text() == 'secret'
        assert os.stat(target).st_mode & 0o7777 == 0o600
    else:
        assert not target.exists()


def test_prepare_log_file_refuses_a_hard_link(log_apid, tmp_path):
    """A file with a second link may be another file reached through logs/: it is not changed."""
    target = tmp_path / 'elsewhere'
    target.write_text('secret')
    target.chmod(0o600)
    link = tmp_path / 'api.log'
    os.link(target, link)

    with pytest.raises(OSError) as error:
        log_apid.prepare_log_file(str(link))

    assert error.value.errno == errno.EPERM
    assert os.stat(target).st_mode & 0o7777 == 0o600


def test_prepare_log_file_refuses_a_fifo_without_blocking(log_apid, tmp_path):
    """A FIFO with no reader fails at once (O_NONBLOCK) instead of hanging the start."""
    path = tmp_path / 'api.log'
    os.mkfifo(path)

    with pytest.raises(OSError) as error:
        log_apid.prepare_log_file(str(path))

    assert error.value.errno == errno.ENXIO


def test_prepare_log_file_refuses_a_directory(log_apid, tmp_path):
    """A directory in place of the log file is refused, not changed."""
    path = tmp_path / 'api.log'
    path.mkdir(mode=0o700)

    with pytest.raises(OSError):
        log_apid.prepare_log_file(str(path))

    assert os.stat(path).st_mode & 0o7777 == 0o700


def _call_name(node):
    func = node.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, 'id', None)


# Calls allowed before drop_privileges() in __main__ that touch the filesystem as root. The log
# files are prepared only through prepare_log_file() (no-follow descriptors); everything that opens,
# chowns or chmods by path -- dictConfig() among them -- comes after the switch.
UNSAFE_BEFORE_DROP = {'dictConfig', 'getLogger', 'open', 'chown', 'chmod', 'lchown', 'info', 'error',
                      'assign_wazuh_ownership'}


def test_main_drops_privileges_before_opening_logs_and_any_ssl_work():
    """`__main__` opens no log file before drop_privileges() and checks TLS after it, before daemonizing.

    A log file opened as root keeps root's descriptor after setuid(), and a chown or chmod by path in
    the service-writable logs/ directory follows a planted symbolic link. pyDaemon() exits the first
    parent with 0 and sends stdout/stderr to /dev/null, so a TLS check after it would fail silently
    with exit 0.
    """
    with open(APID_PATH) as source:
        tree = ast.parse(source.read())
    main = next(node for node in tree.body if isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
                and node.test.left.id == '__name__')
    body = ast.Module(body=main.body, type_ignores=[])

    calls = sorted((node for node in ast.walk(body) if isinstance(node, ast.Call)),
                   key=lambda node: (node.lineno, node.col_offset))
    lines = {}
    for node in calls:
        lines.setdefault(_call_name(node), []).append(node.lineno)

    for name in ('prepare_log_file', 'drop_privileges', 'dictConfig', 'configure_ssl', 'pyDaemon'):
        assert len(lines.get(name, [])) == 1, f'{name} must be called exactly once in __main__'

    order = ['set_logging', 'prepare_log_file', 'drop_privileges', 'dictConfig', 'configure_ssl', 'pyDaemon',
             'create_pid']
    first = [lines[name][0] for name in order]
    assert first == sorted(first), dict(zip(order, first))

    before = {_call_name(node) for node in calls if node.lineno < lines['drop_privileges'][0]}
    assert not before & UNSAFE_BEFORE_DROP, before & UNSAFE_BEFORE_DROP

    guard = next(node for node in ast.walk(body) if isinstance(node, ast.If)
                 and any(isinstance(inner, ast.Call) and _call_name(inner) == 'pyDaemon'
                         for stmt in node.body for inner in ast.walk(stmt)))
    assert 'args.foreground' in ast.unparse(guard.test)
