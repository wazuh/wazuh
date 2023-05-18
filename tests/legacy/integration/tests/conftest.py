import sys
import pytest
import os

from wazuh_testing import session_parameters
from wazuh_testing.utils import config, file, services
from wazuh_testing.constants import platforms
from wazuh_testing.constants.paths import ROOT_PREFIX
from wazuh_testing.constants.paths.logs import OSSEC_LOG_PATH, ALERTS_JSON_PATH


@pytest.fixture()
def set_wazuh_configuration(configuration):
    """Set wazuh configuration

    Args:
        configuration (dict): Configuration template data to write in the ossec.config
    """
    # Save current configuration
    backup_config = config.get_wazuh_conf()

    # Configuration for testing
    test_config = config.set_section_wazuh_conf(configuration.get('sections'))

    # Set new configuration
    config.write_wazuh_conf(test_config)

    # Set current configuration
    session_parameters.current_configuration = configuration

    yield

    # Restore previous configuration
    config.write_wazuh_conf(backup_config)


@pytest.fixture
def truncate_monitored_files():
    """Truncate all the log files and json alerts files before and after the test execution"""
    if services.get_service() == 'wazuh-manager':
        log_files = [OSSEC_LOG_PATH, ALERTS_JSON_PATH]
    else:
        log_files = [OSSEC_LOG_PATH]

    for log_file in log_files:
        if os.path.isfile(os.path.join(ROOT_PREFIX, log_file)):
            file.truncate_file(log_file)

    yield

    for log_file in log_files:
        if os.path.isfile(os.path.join(ROOT_PREFIX, log_file)):
            file.truncate_file(log_file)


@pytest.fixture(scope='function')
def restart_wazuh_function(daemon=None):
    """Restart all Wazuh daemons"""
    services.control_service("restart", daemon=daemon)
    yield
    services.control_service('stop', daemon=daemon)


def pytest_addoption(parser):
    parser.addoption(
        "--tier",
        action="append",
        metavar="level",
        default=None,
        type=int,
        help="only run tests with a tier level equal to 'level'",
    )
    parser.addoption(
        "--tier-minimum",
        action="store",
        metavar="minimum_level",
        default=-1,
        type=int,
        help="only run tests with a tier level greater or equal than 'minimum_level'"
    )
    parser.addoption(
        "--tier-maximum",
        action="store",
        metavar="maximum_level",
        default=sys.maxsize,
        type=int,
        help="only run tests with a tier level less or equal than 'minimum_level'"
    )


def pytest_collection_modifyitems(session, config, items):
    selected_tests = []
    deselected_tests = []
    _host_types = set(["server", "agent"])
    _platforms = set([platforms.LINUX,
                      platforms.WINDOWS,
                      platforms.MACOS,
                      platforms.SOLARIS])

    for item in items:
        supported_platforms = _platforms.intersection(
            mark.name for mark in item.iter_markers())
        plat = sys.platform

        selected = True
        if supported_platforms and plat not in supported_platforms:
            selected = False

        host_type = 'agent' if 'agent' in services.get_service() else 'server'
        supported_types = _host_types.intersection(
            mark.name for mark in item.iter_markers())
        if supported_types and host_type not in supported_types:
            selected = False
        # Consider only first mark
        levels = [mark.kwargs['level']
                  for mark in item.iter_markers(name="tier")]
        if levels and len(levels) > 0:
            tiers = item.config.getoption("--tier")
            if tiers is not None and levels[0] not in tiers:
                selected = False
            elif item.config.getoption("--tier-minimum") > levels[0]:
                selected = False
            elif item.config.getoption("--tier-maximum") < levels[0]:
                selected = False
        if selected:
            selected_tests.append(item)
        else:
            deselected_tests.append(item)

    config.hook.pytest_deselected(items=deselected_tests)
    items[:] = selected_tests
