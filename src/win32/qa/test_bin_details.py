import pytest
import pathlib
import subprocess

BIN_PATH = 'C:\\binaries'
VERSION_FILE = '..\\..\\VERSION'


@pytest.fixture(name='current_bin', scope='module', params=list(map(str, list(pathlib.Path(BIN_PATH).glob('*')))))
def get_bin_path(request):
    return request.param


def test_bin_details(current_bin):
    # Get version from VERSION file
    product_version = ''
    with open(VERSION_FILE, 'r') as f:
        product_version = f.readline().strip()

    file_version_raw = product_version.replace('v', '').split('.')
    file_version_major = file_version_raw[0]
    file_version_minor = file_version_raw[1]
    file_version_build = file_version_raw[2]
    file_version_revision = '0'

    fields_dict = {'FileDescription': 'Wazuh Agent',
                   'ProductName': 'Wazuh Windows Agent',
                   'ProductVersion': product_version,
                   'FileVersionRaw.Major': file_version_major,
                   'FileVersionRaw.Minor': file_version_minor,
                   'FileVersionRaw.Build': file_version_build,
                   'FileVersionRaw.Revision': file_version_revision,
                   'OriginalFilename': '',
                   'LegalCopyright': 'Copyright (C) Wazuh, Inc.',
                   'Language': 'English (United States)'}

    for key in fields_dict:
        cmd = f'(Get-Item "{current_bin}").VersionInfo.{key}'
        result = subprocess.run(
            ["powershell", "-Command", cmd], stdout=subprocess.PIPE, check=True)

        assert result.stdout.decode().rstrip() == fields_dict[key], f"Failed in key: '{key}'"
