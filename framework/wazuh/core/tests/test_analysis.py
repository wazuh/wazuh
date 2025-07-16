import os.path

import pytest

from wazuh.core.analysis import is_ruleset_file
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