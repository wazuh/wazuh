import os.path

import pytest

from wazuh.core.analysis import is_ruleset_file, RulesetReloadResponse
from wazuh.core.common import WAZUH_PATH
from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult

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
    "response,expected_all_msg,should_raise",
    [
        ({"error": 0, "message": "ok", "data": []}, "", False),
        ({"error": 0, "message": "ok", "data": ["Warning 1", "Warning 2"]}, "Warning 1,Warning 2", False),
        ({"error": 1, "message": "fail", "data": ["Error 1"]}, "Error 1", True),
    ]
)
def test_ruleset_update_affected_items(response, expected_all_msg, should_raise):
    """Test RulesetReloadResponse.check_affected_items updates results or raises WazuhError."""
    rrr = RulesetReloadResponse(response)
    results = AffectedItemsWazuhResult(all_msg="")
    error_code = 1234

    if should_raise:
        with pytest.raises(WazuhError) as excinfo:
            rrr.update_affected_items(results, error_code)
        assert str(error_code) in str(excinfo.value)
        assert expected_all_msg in str(excinfo.value)
    else:
        rrr.update_affected_items(results, error_code)
        assert results.all_msg == expected_all_msg
