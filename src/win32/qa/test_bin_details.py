import pytest
import pathlib
import subprocess
import shlex
import json

BIN_PATH = 'C:\\binaries'
VERSION_FILE = '..\\..\\..\VERSION.json'


@pytest.fixture(name='current_bin', scope='module', params=list(map(str, list(pathlib.Path(BIN_PATH).glob('*')))))
def get_bin_path(request):
    return request.param


def read_version():
    """Read the version from VERSION.json and extract the version number."""
    try:
        with open(VERSION_FILE, 'r') as f:
            data = json.load(f)
            product_version = data.get("version", "").strip()

        file_version_raw = product_version.split('.')
        if len(file_version_raw) < 3:
            pytest.fail(f"Invalid version format in {VERSION_FILE}: {product_version}")

        file_version_major, file_version_minor, file_version_build = file_version_raw[:3]
        file_version_revision = '0'

        return product_version, file_version_major, file_version_minor, file_version_build, file_version_revision

    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        pytest.fail(f"Error reading {VERSION_FILE}: {str(e)}")


def test_bin_details(current_bin):
    """Test if binary metadata matches expected values."""
    product_version, file_version_major, file_version_minor, file_version_build, file_version_revision = read_version()

    fields_dict = {
        'FileDescription': 'Wazuh Agent',
        'ProductName': 'Wazuh Windows Agent',
        'ProductVersion': f"v{product_version}",
        'FileVersionRaw.Major': file_version_major,
        'FileVersionRaw.Minor': file_version_minor,
        'FileVersionRaw.Build': file_version_build,
        'FileVersionRaw.Revision': file_version_revision,
        'OriginalFilename': '',
        'LegalCopyright': 'Copyright (C) Wazuh, Inc.',
        'Language': 'English (United States)'
    }

    for key, expected_value in fields_dict.items():
        cmd = f'(Get-Item {shlex.quote(current_bin)}).VersionInfo.{key}'
        result = subprocess.run(
            ["powershell", "-Command", cmd], stdout=subprocess.PIPE, check=True
        )

        assert result.stdout.decode().strip() == expected_value, f"Failed in key: '{key}'"
