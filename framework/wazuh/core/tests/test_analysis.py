import os.path

import pytest
from unittest.mock import MagicMock, patch

from wazuh.core.analysis import (
    is_ruleset_file,
    log_ruleset_reload_response,
    RulesetReloadResponse,
    send_reload_ruleset_and_get_results
)
from wazuh.core.common import WAZUH_PATH
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.exception import WazuhError

@pytest.mark.parametrize(
    "filename,expected",
    [
        ("etc/lists/file.txt", True),
        ("etc/rules/example.xml", True),
        ("etc/decoders/example.xml", True),
        (os.path.join(WAZUH_PATH, "etc/lists/file.txt"), True),
        (os.path.join(WAZUH_PATH, "etc/rules/file.txt"), True),
        (os.path.join(WAZUH_PATH, "etc/decoders/file.txt"), True),
        ("other/file.txt", False),
        ("", False),
    ]
)
def test_is_ruleset_file(filename, expected):
    """Test `is_ruleset_file` core functionality"""
    assert is_ruleset_file(filename) == expected

@pytest.mark.parametrize(
    "response,expected_success,expected_warnings,expected_errors",
    [
        ({"error": 0, "message": "ok", "data": []}, True, [], []),
        ({"error": 0, "message": "ok", "data": ["(7612): Rule ID '100005' is duplicated."]}, True, ["(7612): Rule ID '100005' is duplicated."], []),
        ({"error": 1, "message": "due", "data": ["(1226): Error reading XML file"]}, False, [], ["(1226): Error reading XML file"]),
    ]
)
def test_ruleset_reload_response(response, expected_success, expected_warnings, expected_errors):
    """Test RulesetReloadResponse parsing and attribute assignment."""
    rrr = RulesetReloadResponse(response)
    assert rrr.success == expected_success
    assert rrr.warnings == expected_warnings
    assert rrr.errors == expected_errors
    assert rrr.is_ok() == expected_success
    assert rrr.has_warnings() == (len(expected_warnings) > 0)

@pytest.mark.parametrize(
    "response_dict,expected_log_method,expected_in_message",
    [
        ({"error": 0, "message": "ok", "data": []}, "info", "Ruleset reload triggered by cluster integrity check"),
        ({"error": 0, "message": "ok", "data": ["(7612): Rule ID '100005' is duplicated."]}, "warning", "Ruleset reloaded with warnings after cluster integrity check"),
        ({"error": 1, "message": "due", "data": ["(1226): Error reading XML file"]}, "error", "Ruleset reload failed after cluster integrity check"),
    ]
)
def test_log_ruleset_reload_response(response_dict, expected_log_method, expected_in_message):
    """Test log_ruleset_reload_response logs the correct message and level."""
    logger = MagicMock()
    response = RulesetReloadResponse(response_dict)
    log_ruleset_reload_response(logger, response)
    log_method = getattr(logger, expected_log_method)
    log_method.assert_called_once()
    assert expected_in_message in log_method.call_args[0][0]

@pytest.mark.parametrize(
    "socket_response_dict,expected_affected,expected_failed,expected_msg",
    [
        ({"error": 0, "message": "ok", "data": []}, 1, 0, "Ruleset reload request sent successfully."),
        ({"error": 0, "message": "ok", "data": ["(7612): Rule ID '100005' is duplicated."]}, 1, 0, "(7612): Rule ID '100005' is duplicated."),
        ({"error": 1, "message": "due", "data": ["(1226): Error reading XML file"]}, 0, 1, "(1226): Error reading XML file"),
    ]
)
def test_send_reload_ruleset_and_get_results(socket_response_dict, expected_affected, expected_failed, expected_msg):
    """Test send_reload_ruleset_and_get_results updates results as expected."""
    node_id = "test-node"
    results = AffectedItemsWazuhResult(all_msg="test")
    with patch("wazuh.core.analysis.send_reload_ruleset_msg") as mock_send:
        mock_send.return_value = RulesetReloadResponse(socket_response_dict)
        updated_results = send_reload_ruleset_and_get_results(node_id, results)
        assert len(updated_results.affected_items) == expected_affected
        assert len(updated_results.failed_items) == expected_failed
        if expected_affected:
            assert updated_results.affected_items[0]['name'] == node_id
            assert expected_msg in updated_results.affected_items[0]['msg']
        if expected_failed:
            found = False
            for error_obj, node_ids in updated_results.failed_items.items():
                if isinstance(error_obj, WazuhError) and node_id in node_ids:
                    assert expected_msg in error_obj._extra_message
                    found = True
            assert found, f"{node_id} not found in failed_items"
