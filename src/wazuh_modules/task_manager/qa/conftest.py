# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Fixtures for the Task Manager integration suite.

Each test gets a real module, in its own temporary directory, with its own database and socket. The
module is the actual shared object driven through `task_manager_testtool`, not a simulation -- these
tests exist to cover what unit tests structurally cannot: the socket, real concurrency across
threads, and recovery after the process is killed.
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from helpers.task_client import StubConsumer, TaskManagerClient, wait_for_socket  # noqa: E402


def pytest_addoption(parser):
    parser.addoption(
        '--testtool',
        action='store',
        default=None,
        help='Path to task_manager_testtool. Defaults to $WAZUH_BUILD/bin/task_manager_testtool.',
    )


@pytest.fixture(scope='session')
def testtool_path(request) -> Path:
    explicit = request.config.getoption('--testtool')
    if explicit:
        path = Path(explicit)
    else:
        build = os.environ.get('WAZUH_BUILD', 'build')
        path = Path(build) / 'bin' / 'task_manager_testtool'

    if not path.exists():
        pytest.skip(f'task_manager_testtool not found at {path}; build it first')

    return path.resolve()


class ModuleUnderTest:
    """A running task manager, and the handle a test kills or restarts it with."""

    def __init__(self, testtool: Path, workdir: Path, consumer_socket: Path):
        self.testtool = testtool
        self.workdir = workdir
        self.socket_path = workdir / 'task.sock'
        self.db_path = workdir / 'tasks.db'
        self.consumer_socket = consumer_socket
        self.process = None
        self.log_path = workdir / 'module.log'

    def start(self):
        log = open(self.log_path, 'ab')
        self.process = subprocess.Popen(
            [
                str(self.testtool),
                '--socket', str(self.socket_path),
                '--db', str(self.db_path),
                '--consumer', str(self.consumer_socket),
            ],
            stdout=log,
            stderr=log,
            cwd=str(self.workdir),
        )
        wait_for_socket(str(self.socket_path))

    def stop(self, graceful: bool = True):
        """Stop the module.

        `graceful=False` is SIGKILL, which is the whole point of several tests: it leaves rows
        `claimed` with no chance to tidy up, which is exactly the state the next boot's startup
        sweep has to recover from.
        """
        if self.process is None:
            return

        self.process.send_signal(signal.SIGTERM if graceful else signal.SIGKILL)
        try:
            self.process.wait(timeout=35 if graceful else 5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process = None

    def restart(self, graceful: bool = True):
        self.stop(graceful=graceful)
        # The socket file survives an ungraceful stop; the module unlinks a stale one on bind.
        self.start()

    def log(self) -> str:
        return self.log_path.read_text(errors='replace') if self.log_path.exists() else ''

    def client(self) -> TaskManagerClient:
        return TaskManagerClient(str(self.socket_path))


@pytest.fixture
def consumer(tmp_path) -> StubConsumer:
    stub = StubConsumer(str(tmp_path / 'consumer.sock'))
    stub.start()
    yield stub
    stub.stop()


@pytest.fixture
def module(testtool_path, tmp_path, consumer) -> ModuleUnderTest:
    instance = ModuleUnderTest(testtool_path, tmp_path, Path(consumer.socket_path))
    instance.start()
    yield instance
    instance.stop()


@pytest.fixture
def client(module) -> TaskManagerClient:
    with module.client() as instance:
        yield instance


@pytest.fixture
def module_without_consumer(testtool_path, tmp_path) -> ModuleUnderTest:
    """A module whose consumer socket does not exist.

    Its own fixture rather than a flag, because the absence has to be there from the first claim:
    what it produces is the boot race -- connect refused, which must DEFER rather than spend the
    retry budget -- and starting a consumer and then stopping it would not reproduce that.
    """
    instance = ModuleUnderTest(testtool_path, tmp_path, tmp_path / 'nothing-here.sock')
    instance.start()
    yield instance
    instance.stop()


def wait_until(predicate, timeout: float = 20.0, interval: float = 0.1):
    """Poll `predicate` until it is truthy. Returns its value, or raises."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError(f'condition not met within {timeout}s')
