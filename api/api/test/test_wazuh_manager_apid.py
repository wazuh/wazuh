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

import errno
import importlib.util
import os
import socket
import threading
from unittest.mock import MagicMock, patch

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
    module._shutdown_event = event
    return module


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
    assert [sock.bound_address for sock in created] == [('0.0.0.0', 55000), ('::', 55000)]
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
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()

    sockets = apid._bind_listening_sockets(['0.0.0.0', '::'], port)  # nosec B104
    try:
        assert [sock.getsockname()[:2] for sock in sockets] == [('0.0.0.0', port), ('::', port)]
        assert sockets[1].getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
        assert sockets[0].getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 1

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
    apid.get_users_with_default_password = MagicMock(return_value=[])
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
    assert config_kwargs == {'server_header': False, 'loop': 'uvloop'}
    apid.uvicorn.Server.assert_called_once_with(apid.uvicorn.Config.return_value)
    apid.uvicorn.Server.return_value.run.assert_called_once_with(sockets=bound)


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
