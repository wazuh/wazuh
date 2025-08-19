import os.path

import pytest
from unittest.mock import MagicMock

from wazuh.core.analysis import is_ruleset_file, log_ruleset_reload_response, RulesetReloadResponse
from wazuh.core.common import WAZUH_PATH

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
