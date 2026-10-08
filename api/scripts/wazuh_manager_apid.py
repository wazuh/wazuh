#!/var/wazuh-manager/framework/python/bin/python3

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import errno
import os
import random
import signal
import socket
import stat
import sys
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from functools import partial

logger = None

# Bind retry budget. The worst case waits 2+4+8+16+32 seconds, i.e. roughly a minute, before
# giving up on a busy port.
BIND_MAX_RETRIES = 5
BIND_BACKOFF_BASE_SECONDS = 2

# Exit code uvicorn.run() used when the server never started (uvicorn.main.STARTUP_FAILURE).
UVICORN_STARTUP_FAILURE = 3

# TLS 1.2 cipher list served when https.ssl_ciphers is empty: AEAD suites with forward secrecy only.
# uvicorn's own default for an unset cipher string is "TLSv1", which on TLS 1.2 leaves two CBC/SHA-1
# suites and no GCM one. TLS 1.3 suites are chosen by OpenSSL's ciphersuites list, not by this string.
DEFAULT_SSL_CIPHERS = 'ECDHE+AESGCM:ECDHE+CHACHA20'

# Set by exit_handler(), so a signal arriving while _bind_listening_sockets() waits to retry
# aborts the wait instead of running out the backoff clock with the pidfiles already deleted.
_shutdown_event = threading.Event()


def prepare_log_file(filepath: str):
    """Create the log file if it does not exist, and give it to the service user with mode 0660.

    This runs as root, in `logs/`, a directory the service account can write. Its entries are
    therefore untrusted: a symbolic link planted there would hand any root file to the service
    account if it were followed by a chown or chmod by path. The file is opened without following
    a final symbolic link, checked through the descriptor to be a regular file with a single link,
    and changed through that same descriptor, so what is checked is what is changed. It is never
    written here: the handlers open it only after the privilege drop.

    Parameters
    ----------
    filepath : str
        Log file path.

    Raises
    ------
    OSError
        The path is a symbolic link, is not a regular file, has more than one link, or cannot be
        opened or changed.
    """
    # O_NONBLOCK keeps a planted FIFO from blocking the start (it fails with ENXIO instead).
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(filepath, flags, 0o660)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise OSError(errno.ELOOP, 'Refusing a log file that is a symbolic link', filepath) from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise OSError(errno.EPERM, 'Refusing a log file that is not a regular file with a single link',
                          filepath)
        if st.st_uid != common.wazuh_uid() or st.st_gid != common.wazuh_gid():
            os.fchown(fd, common.wazuh_uid(), common.wazuh_gid())
        os.fchmod(fd, 0o660)  # nosec B103 - the service group writes the API log
    finally:
        os.close(fd)


def configure_ssl(params):
    """Check the API TLS files, and set the uvicorn dictionary configuration keys.

    The pair is never generated here: the installer issues it signed by the manager CA. The files
    are loaded once the way uvicorn will load them (certificate chain, client CA when `use_ca` is
    set, cipher string as written) with the service's uid/gid: this runs after drop_privileges, before
    daemonizing, so a missing, unreadable or invalid file is logged by the service user, printed
    to the terminal and turned into exit code 1 before uvicorn starts.

    Parameters
    ----------
    params : dict
        uvicorn parameter configuration dictionary.

    Raises
    ------
    APIError
        Code 2003 when a file is missing, unreadable or invalid, or the cipher string selects nothing.
    """
    from api.constants import CONFIG_FILE_PATH

    key, cert = api_conf['https']['key'], api_conf['https']['cert']
    use_ca, ca = api_conf['https']['use_ca'], api_conf['https']['ca']
    ciphers = api_conf['https']['ssl_ciphers'] or DEFAULT_SSL_CIPHERS

    def _files(paths):
        return ', '.join(f'WAZUH_PATH/{to_relative_path(path)}' for path in paths)

    def _not_found(paths):
        return APIError(2003, details=f'API certificate or key not found: {_files(paths)}. '
                                      'The installer issues it signed by the manager CA')

    def _fail(error, exc=None):
        logger.error(error)
        if exc is None:
            raise error
        raise error from exc

    for path in (cert, key):
        if not os.path.isfile(path):
            _fail(_not_found([path]))
    if use_ca and not os.path.isfile(ca):
        _fail(APIError(2003, details=f'API client CA certificate not found: {_files([ca])}. '
                                     'It is required by https.use_ca'))

    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # A callback instead of no password: OpenSSL would otherwise prompt for the passphrase of
        # an encrypted key on the terminal (-f) and hang there.
        context.load_cert_chain(certfile=cert, keyfile=key, password=lambda: b'')
        if use_ca:
            context.load_verify_locations(cafile=ca)
    except ssl.SSLError as exc:
        _fail(APIError(2003, details='Private key does not match with the certificate, or a file is not a '
                                     f'valid unencrypted PEM: {_files([cert, key] + ([ca] if use_ca else []))}'),
              exc)
    except IOError as exc:
        if exc.errno == 22:
            _fail(APIError(2003, details='PEM phrase is not correct'), exc)
        elif exc.errno == 13:
            _fail(APIError(2003, details='Ensure the certificates have the correct permissions: '
                                         f'{_files([cert, key] + ([ca] if use_ca else []))}'), exc)
        elif exc.errno == 2:
            # A file removed between the check above and the load; ssl gives no filename.
            _fail(_not_found([exc.filename] if exc.filename else [cert, key] + ([ca] if use_ca else [])), exc)
        else:
            msg = f'Wazuh API SSL ERROR. Please, ensure ' \
                  f'if path to certificates is correct in the configuration ' \
                  f'file WAZUH_PATH/{to_relative_path(CONFIG_FILE_PATH)}'
            print(msg)
            logger.error(msg)
            raise APIError(2003, details=msg) from exc

    try:
        context.set_ciphers(ciphers)
    except ssl.SSLError as exc:
        # OpenSSL cipher keywords are case-sensitive (`!kRSA`, not `!KRSA`). Earlier releases
        # uppercased the whole string, so a lowercase list that only ever worked because of that
        # still starts, uppercased, with a warning.
        try:
            context.set_ciphers(ciphers.upper())
        except ssl.SSLError:
            _fail(APIError(2003, details=f'No usable cipher in https.ssl_ciphers: {ciphers}'), exc)
        logger.warning(f'https.ssl_ciphers "{ciphers}" is not an OpenSSL cipher list as written and was '
                       f'applied as "{ciphers.upper()}". OpenSSL keywords are case-sensitive: write them in '
                       'their exact case')
        ciphers = ciphers.upper()

    params['ssl_version'] = ssl.PROTOCOL_TLS_SERVER

    if use_ca:
        params['ssl_cert_reqs'] = ssl.CERT_REQUIRED
        params['ssl_ca_certs'] = ca

    params['ssl_certfile'] = cert
    params['ssl_keyfile'] = key
    params['ssl_ciphers'] = ciphers


def drop_privileges(run_as_root: bool) -> None:
    """Switch to the service user and group.

    It runs before the logging configuration is applied, so the log handlers open their files as
    the service user: a root-opened descriptor would survive the switch and keep root's access to
    whatever the path pointed to. Root's supplementary groups are cleared first: setgid() and
    setuid() leave them in place, so the dropped process would otherwise keep group access to
    whatever root's groups can read.

    Parameters
    ----------
    run_as_root : bool
        The API keeps running as root (-r).
    """
    if not run_as_root and api_conf['drop_privileges']:
        os.setgroups([])
        os.setgid(common.wazuh_gid())
        os.setuid(common.wazuh_uid())


def _bind_listening_sockets(hosts, port: int, retries: int = BIND_MAX_RETRIES,
                            backoff: int = BIND_BACKOFF_BASE_SECONDS) -> list:
    """Bind one listening socket per configured host, retrying while the port is still in use.

    The bind is done here rather than inside uvicorn because uvicorn turns a failed bind into
    sys.exit(1) from within its own startup, leaving nothing to retry: apid stayed down until
    restarted by hand even when the port freed up seconds later.

    An attempt is all-or-nothing on a real bind failure (the port already in use, or any other
    error): every socket opened by that attempt is closed before retrying or raising. The one
    exception is an address whose family isn't available on this system at all: either
    `socket.socket()` itself fails (a kernel booted with `ipv6.disable=1` refuses to open an
    `AF_INET6` socket with `EAFNOSUPPORT`) or `bind()` fails with `EADDRNOTAVAIL`/`EAFNOSUPPORT`
    (IPv6 disabled through `net.ipv6.conf.all.disable_ipv6`). asyncio.loop.create_server(),
    which bound these sockets before this function existed, tolerates both by skipping that
    address and proceeding with whatever else binds, and that tolerance is kept here. The whole
    attempt still fails if every address is skipped this way.

    Parameters
    ----------
    hosts : str or list of str
        Host or hosts to bind on. Each host is resolved with `socket.getaddrinfo()` and one
        socket is bound per resolved address, the same resolution asyncio.loop.create_server()
        used before this function existed -- so a hostname with both A and AAAA records is
        served on both, and one that only has AAAA records is still bound as IPv6, which a
        literal ':' check on the string would miss.
    port : int
        Port to bind on every host.
    retries : int
        Number of retries after the first attempt.
    backoff : int
        Base wait time, in seconds, for the exponential backoff between attempts.

    Returns
    -------
    list of socket.socket
        The bound sockets, one per resolved address, in the order the hosts were given.

    Raises
    ------
    OSError
        'hosts' is empty, the bind failed for a reason other than the address being in use, or
        every attempt failed with the address in use.
    SystemExit
        A shutdown was requested while waiting to retry.
    """
    hosts = [hosts] if isinstance(hosts, str) else list(hosts)
    if not hosts:
        # api.yaml's schema accepts an empty 'host' list. asyncio.loop.create_server(), which
        # bound these sockets before this function existed, raised for it rather than running a
        # server that listens on nothing; the same message is kept.
        raise OSError(f'could not bind on any address out of {hosts}')

    for attempt in range(retries + 1):
        sockets = []
        bound = set()
        try:
            for host in hosts:
                try:
                    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM,
                                               proto=socket.IPPROTO_TCP, flags=socket.AI_PASSIVE)
                except socket.gaierror as exc:
                    raise OSError(f"could not resolve host '{host}': {exc}") from exc
                for family, sock_type, proto, _, sockaddr in infos:
                    if sockaddr in bound:
                        # Two hosts resolving to the same address (or a repeated entry) would
                        # otherwise conflict with each other at listen().
                        continue
                    try:
                        sock = socket.socket(family, sock_type, proto)
                    except OSError as exc:
                        # The family isn't available on this system at all: a kernel booted with
                        # ipv6.disable=1 fails here, with EAFNOSUPPORT, and never reaches bind().
                        # asyncio.loop.create_server() skips such an address and carries on;
                        # kept here for the same reason.
                        logger.warning(f"Skipping {sockaddr[0]}:{port}, its address family is "
                                       f"not available on this system: {exc}")
                        continue
                    # Tracked before it is bound, so the cleanup below also closes the socket
                    # whose own bind is the one that failed.
                    sockets.append(sock)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if family == socket.AF_INET6:
                        # asyncio.loop.create_server() -- which bound these sockets before this
                        # function existed -- sets this for every IPv6 server socket it opens.
                        # Without it, the IPv6 socket also serves IPv4 clients, and their remote
                        # address reaches the API as a v4-mapped '::ffff:1.2.3.4' instead of
                        # '1.2.3.4'.
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    try:
                        sock.bind(sockaddr)
                    except OSError as exc:
                        if exc.errno in (errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT):
                            # The family is disabled on this host (e.g. IPv6 through
                            # net.ipv6.conf.all.disable_ipv6): the socket opens but nothing can
                            # be bound to it. Skipped for the same reason as above.
                            logger.warning(f"Skipping {sockaddr[0]}:{port}, its address family "
                                           f"is not available on this system: {exc}")
                            sockets.pop()
                            sock.close()
                            continue
                        raise
                    bound.add(sockaddr)
            if not sockets:
                raise OSError(f'could not bind on any address out of {hosts}')
            return sockets
        except OSError as exc:
            for sock in sockets:
                sock.close()
            if exc.errno != errno.EADDRINUSE or attempt == retries:
                raise

            # Exponential backoff with jitter, mirroring create_indexer()'s retry loop in
            # framework/wazuh/core/indexer/indexer.py.
            wait_time = (backoff * 2 ** attempt) + random.random()  # nosec B311
            logger.warning(f'Could not bind {hosts}:{port} (attempt {attempt + 1}/{retries + 1}): '
                           f'{exc}. Retrying in {wait_time:.2f}s.')
            if _shutdown_event.wait(wait_time):
                logger.info('Shutdown requested while waiting to retry the bind. Aborting startup')
                raise SystemExit(0) from exc


def start(params: dict):
    """Run the Wazuh API.

    The function creates the pool processes, the AsyncApp instance, setups the API spec.yaml,
    the middleware classes, the error_handlers, the lifespan, binds the listening sockets and
    runs the uvicorn ASGI server on them.

    Parameters
    ----------
    params : dict
        uvicorn parameter configuration dictionary.

    Raises
    ------
    APIError
        Code 2012 if `rbac.db` is absent or its integrity check fails, or code 2010 if the
        configured port is still in use after every bind attempt.
    SystemExit
        A shutdown was requested before the server started, or the server never started.
    """
    # `rbac.db` belongs to the credential resolver, which seeds it through `rbac_control seed` and
    # publishes the two default users' passwords to /etc/wazuh/credentials.env. Creating it here
    # instead -- which `check_database_integrity()` does when the file is absent -- seeds those users
    # with generated passwords that are published NOWHERE: not to the credentials file, not to the
    # log. The result is an API that starts cleanly and that nobody can authenticate against, with no
    # record of the credential on the host.
    #
    # An empty file is what a failed creation leaves behind, not a database, so it is treated as
    # absent -- the same test `rbac_control seed` applies.
    #
    # Nothing legitimate reaches this with the file missing: `wazuh-manager-control start` runs
    # `resolvecredentials()` before `start_service()`, and refuses the whole start when a credential
    # is unresolved. Failing here names the step that owns the file rather than quietly inventing one.
    if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0:
        raise APIError(
            2012,
            details=f"'{DB_FILE}' does not exist. It is created by the credential resolver, not by "
                    f"the API: start the manager with 'wazuh-manager-control start', or run "
                    f"'{os.path.join(common.WAZUH_PATH, 'bin', 'wazuh-manager-resolve-credentials')} "
                    f"--prestart'",
        )

    try:
        check_database_integrity()
    except Exception as db_integrity_exc:
        raise APIError(2012, details=str(db_integrity_exc)) from db_integrity_exc

    pools = common.mp_pools.get()

    try:
        pools.update({'process_pool': ProcessPoolExecutor(
            max_workers=1,
            initializer=partial(pyDaemonModule.spawn_process_pool_worker, pyDaemonModule.API_LOCAL_REQUEST_PROCESS)
        )})

    # Handle exception when the user running Wazuh cannot access /dev/shm.
    except (FileNotFoundError, PermissionError):
        pools.update({'thread_pool': ThreadPoolExecutor(max_workers=1)})


    # Log the pool creation to force processes creation
    if 'thread_pool' not in common.mp_pools.get():

        async def _warm_up_pools():
            loop = asyncio.get_running_loop()
            await asyncio.gather(*[loop.run_in_executor(pool, logger.debug2, f"Creating '{name}' process pool")
                for name, pool in common.mp_pools.get().items()])

        asyncio.run(_warm_up_pools())

    # Set up API
    app = AsyncApp(
        __name__,
        specification_dir=os.path.join(api_path[0], 'spec'),
        # serve_spec=False avoids exposing the API specification and version at
        # /openapi.json and /openapi.yaml, which connexion serves unauthenticated by default
        swagger_ui_options=SwaggerUIOptions(swagger_ui=False, serve_spec=False),
        pythonic_params=True,
        lifespan=lifespan_handler,
        uri_parser_class=APIUriParser
    )
    app.add_api('spec.yaml',
                arguments={
                    'title': 'Wazuh API',
                    'protocol': 'https' if api_conf['https']['enabled'] else 'http',
                    'host': params['host'],
                    'port': params['port']},
                strict_validation=True,
                validate_responses=False,
                # A rejected parameter is reported by this validator instead of by connexion's,
                # whose message is jsonschema's own exception text: the submitted value followed by
                # the failing subschema as a Python dict literal.
                validator_map={'parameter': WazuhParameterValidator}
                )

    # The order these are registered in is what keeps an oversized body a 413 rather than a 500.
    # Every middleware belongs inside setup_middlewares(), never after it -- see its docstring.
    setup_middlewares(app)

    # Add error handlers to format exceptions
    app.add_error_handler(ContentSizeExceeded, error_handler.content_size_handler)
    app.add_error_handler(ExpectFailedException, error_handler.expect_failed_error_handler)
    app.add_error_handler(Unauthorized, error_handler.unauthorized_error_handler)
    app.add_error_handler(HTTPException, error_handler.http_error_handler)
    app.add_error_handler(ProblemException, error_handler.problem_error_handler)
    app.add_error_handler(403, error_handler.problem_error_handler)
    app.add_error_handler(RecursionError, error_handler.recursion_error_handler)

    # API configuration logging
    logger.debug(f'Loaded API configuration: {api_conf}')
    logger.debug(f'Loaded security API configuration: {security_conf}')

    # Start uvicorn server on sockets this process bound itself, so a transient EADDRINUSE is
    # retried here instead of ending the process inside uvicorn's own startup.
    try:
        sockets = _bind_listening_sockets(params['host'], params['port'])
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            error = APIError(2010)
            logger.error(error)
            raise error from exc
        logger.error(exc)
        raise exc

    if _shutdown_event.is_set():
        # exit_handler() has already deleted the PID files: a SIGTERM that landed while the
        # bind itself was in progress, rather than during a retry wait, would otherwise leave
        # the API serving with wazuh-manager-control unable to see or stop it.
        for sock in sockets:
            sock.close()
        logger.info('Shutdown requested before the API server started. Aborting startup')
        raise SystemExit(0)

    try:
        # proxy_headers=False: uvicorn otherwise replaces the client address with X-Forwarded-For
        # from any peer in FORWARDED_ALLOW_IPS (127.0.0.1 by default), so a local user could pick
        # the address the login lockout, the rate limits and api.log see. Nothing in front of the
        # API is a trusted proxy.
        config = uvicorn.Config(app, **{key: value for key, value in params.items()
                                        if key not in ('host', 'port')}, proxy_headers=False)
        server = uvicorn.Server(config)
        server.run(sockets=sockets)
    except OSError as exc:
        # __main__'s handler only print()s, and pyDaemon() has sent stdout to /dev/null by now,
        # so an OSError raised by uvicorn's own startup (an ssl.SSLError from Config.load(), for
        # example) has to be logged here to leave any trace in api.log.
        logger.error(exc)
        raise

    if not server.started:
        # uvicorn.run() ended the process with this code when the server never started, for
        # example because the ASGI lifespan startup raised. Server.run() on its own returns
        # normally instead, which would make a failed startup look like a clean shutdown.
        logger.error('The API server did not start')
        sys.exit(UVICORN_STARTUP_FAILURE)


def print_version():
    from wazuh.core.cluster import __author__, __licence__, __version__, __wazuh_name__
    print('\n{} {} - {}\n\n{}'.format(__wazuh_name__, __version__, __author__, __licence__))


def test_config(config_file: str):
    """Make an attempt to read the API config file. Exits with 0 code if successful, 1 otherwise.

    Arguments
    ---------
    config_file : str
        Path of the file
    """
    try:
        read_yaml_config(config_file=config_file)
    except Exception as exc:
        print(f"Configuration not valid. ERROR: {exc}")
        sys.exit(1)
    sys.exit(0)


def version():
    """Print API version and exits with 0 code. """
    print_version()
    sys.exit(0)


def exit_handler(signum, frame):
    """Release a pending bind retry, then try to kill API child processes and remove their PID files."""
    # Before the pidfiles go away: a bind retry still waiting would otherwise keep this process
    # alive and invisible to wazuh-manager-control for the rest of its backoff budget.
    # Event.set() takes the Event's own condition lock, which Event.wait() holds only while
    # arming and disarming its waiter, not for the timeout itself -- so replacing this with a
    # plain flag plus a signal-safe wakeup buys nothing and loses the interruptible wait.
    _shutdown_event.set()
    api_pid = os.getpid()
    pyDaemonModule.delete_child_pids(pyDaemonModule.API_MAIN_PROCESS, api_pid, logger)
    pyDaemonModule.delete_pid(pyDaemonModule.API_MAIN_PROCESS, api_pid)


def add_debug2_log_level_and_error():
    """Add a new debug level used by wazuh api and framework."""

    logging.DEBUG2 = 6

    def debug2(self, message, *args, **kws):
        if self.isEnabledFor(logging.DEBUG2):
            self._log(logging.DEBUG2, message, args, **kws)

    def error(self, msg, *args, **kws):
        if self.isEnabledFor(logging.ERROR):
            if 'exc_info' not in kws:
                kws['exc_info'] = self.isEnabledFor(logging.DEBUG2)
            self._log(logging.ERROR, msg, args, **kws)

    logging.addLevelName(logging.DEBUG2, "DEBUG2")

    logging.Logger.debug2 = debug2
    logging.Logger.error = error


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    #########################################################################################
    parser.add_argument('-f', help="Run in foreground",
                        action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version",
                        action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration",
                        action='store_true', dest='test_config')
    parser.add_argument('-r', help="Run as root",
                        action='store_true', dest='root')
    parser.add_argument('-c', help="Configuration file to use",
                        type=str, metavar='config', dest='config_file')
    parser.add_argument('-d', help="Enable debug messages. Use twice to increase verbosity.",
                        action='count',
                        dest='debug_level')
    args = parser.parse_args()

    from api.configuration import read_yaml_config
    if args.version:
        version()
        sys.exit(0)

    elif args.test_config:
        test_config(args.config_file)
        sys.exit(0)

    import asyncio
    import logging
    import logging.config
    import ssl

    import uvicorn
    from connexion import AsyncApp
    from connexion.exceptions import HTTPException, ProblemException, Unauthorized
    from connexion.options import SwaggerUIOptions
    from content_size_limit_asgi.errors import ContentSizeExceeded
    from wazuh.core import common, pyDaemonModule, utils
    from wazuh.rbac.orm import DB_FILE, check_database_integrity

    from api import __path__ as api_path
    from api import error_handler
    from api.alogging import set_logging
    from api.api_exception import APIError, ExpectFailedException
    from api.configuration import api_conf, security_conf
    from api.constants import API_LOG_PATH
    from api.middlewares import setup_middlewares
    from api.parameter_validator import WazuhParameterValidator
    from api.signals import lifespan_handler
    from api.uri_parser import APIUriParser
    from api.util import to_relative_path

    try:
        if args.config_file is not None:
            api_conf.update(read_yaml_config(config_file=args.config_file))
    except APIError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)

    # Configure uvicorn parameters dictionary
    uvicorn_params = {}
    uvicorn_params['host'] = api_conf['host']
    uvicorn_params['port'] = api_conf['port']
    uvicorn_params['loop'] = 'uvloop'
    uvicorn_params['server_header'] = False

    # Set up logger file
    try:
        uvicorn_params['log_config'] = set_logging(log_filepath=API_LOG_PATH,
                                                   log_level=api_conf['logs']['level'].upper(),
                                                   foreground_mode=args.foreground)
    except APIError as api_log_error:
        print(f"Error when trying to start the Wazuh API. {api_log_error}")
        sys.exit(1)

    # Create the log files and give them to the service user, through descriptors that never
    # follow a symbolic link: logs/ is writable by the service account.
    try:
        for handler in uvicorn_params['log_config']['handlers'].values():
            if 'filename' in handler:
                prepare_log_file(handler['filename'])
    except OSError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)

    # Check for unused PID files
    utils.clean_pid_files(pyDaemonModule.API_MAIN_PROCESS)

    # Drop privileges to wazuh before the log handlers open their files and before touching the TLS
    # files. Nothing is logged if it fails: the logging configuration is not applied yet.
    try:
        drop_privileges(args.root)
    except Exception as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)

    # Configure and create the wazuh-api logger. dictConfig() opens the log files, now as the
    # service user.
    add_debug2_log_level_and_error()
    logging.config.dictConfig(uvicorn_params['log_config'])
    logger = logging.getLogger('wazuh-api')

    if args.foreground:
        logger.info('Starting API in foreground')
    if args.root:
        logger.info('Starting API as root')

    # Check the TLS files as the service user while still in the foreground: configure_ssl() logs
    # the error, and the print and the exit code reach the terminal and wazuh-manager-control.
    if api_conf['https']['enabled']:
        try:
            configure_ssl(uvicorn_params)
        except APIError as e:
            print(f"Error when trying to start the Wazuh API. {e}")
            sys.exit(1)

    # Daemonize unless running in the foreground (pyDaemon exits the parent with 0 and sends stdout
    # and stderr to /dev/null, so every start-up check must come before it)
    if not args.foreground:
        pyDaemonModule.pyDaemon()

    pid = os.getpid()
    pyDaemonModule.create_pid(pyDaemonModule.API_MAIN_PROCESS, pid)

    signal.signal(signal.SIGTERM, exit_handler)
    try:
        start(uvicorn_params)
    except APIError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)
    except Exception as e:
        print(f'Internal error when trying to start the Wazuh API. {e}')
        sys.exit(1)
    finally:
        pyDaemonModule.delete_child_pids(pyDaemonModule.API_MAIN_PROCESS, pid, logger)
        pyDaemonModule.delete_pid(pyDaemonModule.API_MAIN_PROCESS, pid)
