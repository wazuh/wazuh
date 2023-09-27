import pytest
import pathlib
import subprocess

BIN_PATH = 'C:\\binaries'


@pytest.fixture(name='current_bin', scope='module', params=list(map(str, list(pathlib.Path(BIN_PATH).glob('*')))))
def get_bin_path(request):
    return request.param


def test_bin_details(current_bin):
    fields = ['FileDescription', 'ProductName', 'ProductVersion',
              'FileVersion', 'OriginalFilename', 'LegalCopyright', 'Language']

    for field in fields:
        cmd = f"(Get-Item {current_bin}).VersionInfo.{field}"
        result = subprocess.run(
            ["powershell", "-Command", cmd], stdout=subprocess.PIPE, check=True)

        assert result.stdout.decode() == ''
