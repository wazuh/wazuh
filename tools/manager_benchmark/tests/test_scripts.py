# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest tests/test_scripts.py -v

"""Tests for the manager preparation and agent cleanup scripts.

prepare_manager.sh must never write a configuration the manager refuses (the enrollment cap is an
internal option, not an <auth> child), and cleanup_agents.sh must never fail quietly: a cleanup
that did not run leaves the previous fleet registered and the next enrollment fails.
"""
import http.server
import os
import subprocess
import sys
import threading

import pytest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.join(HERE, '..')
PREPARE = os.path.join(ROOT, 'prepare_manager.sh')
CLEANUP = os.path.join(ROOT, 'cleanup_agents.sh')

CONF = """<wazuh_config>
  <remote>
    <https>
      <enabled>yes</enabled>
    </https>
  </remote>
  <auth>
    <disabled>yes</disabled>
    <max_agents>50</max_agents>
  </auth>
</wazuh_config>
"""


def _env(**extra):
    """A minimal environment: no inherited WAZUH_* value can satisfy what a test checks."""
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'PYTHON': sys.executable}
    env.update(extra)
    return env


def _prepare(tmp_path, *args):
    conf = tmp_path / 'wazuh-manager.conf'
    if not conf.exists():
        conf.write_text(CONF)
    return subprocess.run(['bash', PREPARE, '--conf', str(conf), '--no-restart', '--no-mint', *args],
                          env=_env(), capture_output=True, text=True, timeout=60)


def test_prepare_never_writes_max_agents_into_the_configuration(tmp_path):
    options = tmp_path / 'internal-options.conf'
    options.write_text('# shipped comments\n')

    result = _prepare(tmp_path, '--internal-options', str(options), '--max-agents', '1000')

    assert result.returncode == 0, result.stderr
    conf = (tmp_path / 'wazuh-manager.conf').read_text()
    # The stale element an earlier version wrote is gone, and no new one is added.
    assert '<max_agents>' not in conf
    assert '<disabled>no</disabled>' in conf
    assert '<remote_enrollment>yes</remote_enrollment>' in conf
    assert options.read_text() == '# shipped comments\nauthd.max_agents=1000\n'


def test_prepare_replaces_an_earlier_max_agents_internal_option(tmp_path):
    options = tmp_path / 'internal-options.conf'
    options.write_text('authd.max_agents=5\nauthd.purge_delay=0\n  authd.max_agents = 7\n')

    result = _prepare(tmp_path, '--internal-options', str(options), '--max-agents', '0')

    assert result.returncode == 0, result.stderr
    assert options.read_text() == 'authd.purge_delay=0\nauthd.max_agents=0\n'


def test_prepare_leaves_the_internal_options_alone_without_max_agents(tmp_path):
    options = tmp_path / 'internal-options.conf'
    options.write_text('authd.max_agents=5\n')

    result = _prepare(tmp_path, '--internal-options', str(options))

    assert result.returncode == 0, result.stderr
    assert options.read_text() == 'authd.max_agents=5\n'


@pytest.mark.parametrize('value', ['abc', '-1', '2147483648', '10k'])
def test_prepare_refuses_a_max_agents_authd_would_exit_on(tmp_path, value):
    options = tmp_path / 'internal-options.conf'
    options.write_text('')

    result = _prepare(tmp_path, '--internal-options', str(options), '--max-agents', value)

    assert result.returncode == 1
    assert '--max-agents must be an integer' in result.stderr
    # Refused before anything is written.
    assert (tmp_path / 'wazuh-manager.conf').read_text() == CONF
    assert options.read_text() == ''


def _unused_port():
    import socket
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _cleanup(**extra):
    return subprocess.run(['bash', CLEANUP], env=_env(**extra), capture_output=True, text=True,
                          timeout=60)


def test_cleanup_has_no_default_password():
    # Pointed at a closed port, so even a host whose published credentials.env is readable
    # (a root shell on an installed manager) never reaches a real API from this test.
    result = _cleanup(WAZUH_API_URL=f'http://127.0.0.1:{_unused_port()}')

    assert result.returncode == 1
    assert ('no Server API password' in result.stderr) or ('not reachable' in result.stderr)
    assert 'No agents to remove' not in result.stdout


def test_cleanup_reports_an_unreachable_api():
    result = _cleanup(WAZUH_API_PASS='x', WAZUH_API_URL=f'http://127.0.0.1:{_unused_port()}')

    assert result.returncode == 1
    assert 'is not reachable' in result.stderr


@pytest.fixture
def refusing_api():
    """An API that answers every authentication with 401."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = b'{"title": "Unauthorized", "detail": "Invalid credentials"}'
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_address[1]}'
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize('variable', ['WAZUH_API_PASS', 'WAZUH_MANAGER_API_PASSWORD'])
def test_cleanup_reports_a_refused_password(refusing_api, variable):
    result = _cleanup(WAZUH_API_URL=refusing_api, **{variable: 'wrong'})

    assert result.returncode == 1
    assert 'HTTP 401' in result.stderr
    assert 'WAZUH_MANAGER_API_PASSWORD' in result.stderr
