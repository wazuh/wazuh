"""Trailing-NUL handling regression test."""
import time
from pathlib import Path

import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.utils import secure_message
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH


pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

cases_path = Path(TEST_CASES_PATH, 'cases_message_integrity.yaml')
config_path = Path(CONFIGS_PATH, 'config_message_integrity.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}
local_internal_options = {REMOTED_DEBUG: '2'}


def _build_raw_event(agent, payload: bytes) -> bytes:
    """Build an encrypted event."""
    encoded = secure_message.encode(payload)
    encrypted = secure_message.encrypt(encoded, agent.encryption_key, agent.cypher)
    return agent.headers(agent.id, encrypted)


def _read_log_since(start_offset: int) -> str:
    with open(WAZUH_LOG_PATH, 'rb') as fh:
        fh.seek(start_offset)
        return fh.read().decode(errors='replace')


def _log_size() -> int:
    try:
        return Path(WAZUH_LOG_PATH).stat().st_size
    except FileNotFoundError:
        return 0


@pytest.mark.parametrize('test_configuration, test_metadata',
                         zip(test_configuration, test_metadata), ids=cases_ids)
def test_legacy_text_event_with_trailing_null_does_not_reach_engine_with_null(
        test_configuration, test_metadata,
        configure_local_internal_options, truncate_monitored_files,
        set_wazuh_configuration, daemons_handler, simulate_agents):
    agent = simulate_agents[0]
    sender, injector = connect(agent, manager_port='1514', protocol='tcp')

    log_offset = _log_size()
    marker = f"TRAIL-NUL-PROBE-{int(time.time() * 1000)}"
    payload = f"1:syslog:{marker}".encode() + b"\x00"
    sender.send_event(_build_raw_event(agent, payload))

    deadline = time.time() + 15.0
    matching_line = None
    while time.time() < deadline:
        log_window = _read_log_since(log_offset)
        for line in log_window.splitlines():
            if marker in line and "Event not processed" in line:
                matching_line = line
                break
        if matching_line:
            break
        time.sleep(0.5)

    injector.stop_receive()

    assert matching_line is not None, (
        f"Did not observe an 'Event not processed' warning carrying our marker "
        f"{marker!r} within 15s -- the event never made it to analysisd."
    )

    assert "\\u0000" not in matching_line, (
        f"event.original carries a literal \\u0000 escape -- remoted is no "
        f"longer stripping the trailing zero from analysisd-bound text events, "
        f"which is the root-cause symptom of issue #35474. Offending log line: "
        f"{matching_line}"
    )

    expected_original = f'"original":"{marker}"'
    assert expected_original in matching_line, (
        f"event.original does not match expected marker {marker!r}. "
        f"Either remoted stripped too aggressively or some other layer "
        f"mangled the payload. Offending log line: {matching_line}"
    )
