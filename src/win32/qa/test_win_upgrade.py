import pathlib
import os
import hashlib
import pytest
import subprocess

RELEASED_PATH = 'C:\\win-agent-released\\'
BASE_PATH = 'C:\\win-agent-base\\'
INSTALL_PATH = 'C:\\Program Files (x86)\\ossec-agent\\'
AUTHENTICATED_USERS_SID = 'S-1-5-11'


def populate_dict(dict, files_list):
    for file in files_list:
        # We skip this executable because the 'eventchannel' will be used instead
        if file.name.count('WAZUH_AGENT.EXE') > 0:
            continue

        with open(file, "rb") as f:
            file_hash = hashlib.file_digest(f, "sha256").hexdigest()

        # It's required to normalize the name because the installation process changes it
        dict[file.name.lower().replace('-', '_').replace('c++', 'cpp').replace(
            '_dll', '.dll').replace('wazuh_agent_eventchannel.exe', 'wazuh_agent.exe').replace('libfimdb.dll', 'fimdb.dll')] = file_hash


def test_win_upgrade():
    # Find .msi in released directory
    released_msi = list(pathlib.Path(RELEASED_PATH).glob('*.msi'))
    assert len(released_msi) == 1
    released_msi = released_msi[0]

    # Find .msi in base directory
    base_msi = list(pathlib.Path(BASE_PATH).glob('*.msi'))
    assert len(base_msi) == 1
    base_msi = base_msi[0]

    # Install the released .msi
    os.system(
        f"start /wait msiexec /i {str(released_msi.resolve())} /qn /l*v {RELEASED_PATH}win-agent-released.log")

    # Upgrade Wazuh agent
    os.system(
        f"start /wait msiexec /i {str(base_msi.resolve())} /qn /l*v {BASE_PATH}win-agent-base.log")

    # Unzip base .msi to folder
    os.system(f'7z e {str(base_msi.resolve())} "-o{BASE_PATH}" -y')

    # List all .exe and .dll files in of the unzipped folder
    exe_to_install = list(pathlib.Path(BASE_PATH).glob('*.exe'))
    dll_to_install = list(pathlib.Path(BASE_PATH).glob('*dll'))
    files_to_install = exe_to_install + dll_to_install
    assert len(files_to_install) >= 1

    # Calculate hash of each file to install
    files_to_install_dict = {}
    populate_dict(files_to_install_dict, files_to_install)

    # List all .exe and .dll files in of the installed folder
    installed_exe = list(pathlib.Path(INSTALL_PATH).glob('**/*.exe'))
    installed_dll = list(pathlib.Path(INSTALL_PATH).glob('**/*.dll'))
    installed_files = installed_exe + installed_dll
    assert len(installed_files) >= 1

    # Calculate hash of each file to install
    installed_files_dict = {}
    populate_dict(installed_files_dict, installed_files)

    assert len(installed_files_dict) == len(
        files_to_install_dict), f"Installed files: '{installed_files_dict}'\nFiles to install: '{files_to_install_dict}'"

    success = True
    failed_keys = []
    for key in files_to_install_dict:
        # Compare hashes
        if key not in installed_files_dict:
            pytest.fail(f"File '{key}' not found in '{INSTALL_PATH}'\nInstalled files: '{installed_files_dict}'\nFiles to install: '{files_to_install_dict}'")
        if installed_files_dict[key] != files_to_install_dict[key]:
            success = False
            failed_keys.append(
                tuple((key, installed_files_dict[key], files_to_install_dict[key])))

    assert success, f"The following binaries have a hash mismatch: '{failed_keys}'"


def test_win_upgrade_shared_dir_permissions():
    # Runs after test_win_upgrade, on the upgraded installation. The released version grants
    # Authenticated Users read access to the shared directory, so this also checks that the
    # upgrade strips it from the files that were already there.
    shared_path = INSTALL_PATH + 'shared'
    assert os.path.isdir(shared_path), f"Directory '{shared_path}' not found"

    # Compare by SID: account names are localized. The ACLs are read through .NET instead of
    # Get-Acl so the check does not depend on loading PowerShell modules, which fails when
    # Windows PowerShell is started from a PowerShell 7 session such as the runner's shell.
    script = (
        "$ErrorActionPreference = 'Stop'; "
        f"$root = '{shared_path}'; "
        "$paths = @($root) + @([System.IO.Directory]::GetFileSystemEntries("
        "$root, '*', [System.IO.SearchOption]::AllDirectories)); "
        "foreach ($path in $paths) { "
        "if ([System.IO.Directory]::Exists($path)) { $acl = [System.IO.Directory]::GetAccessControl($path) } "
        "else { $acl = [System.IO.File]::GetAccessControl($path) }; "
        "foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) { "
        f"if ($rule.IdentityReference.Value -eq '{AUTHENTICATED_USERS_SID}') {{ $path }} "
        "} }"
    )
    result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"Failed to read the ACLs under '{shared_path}': {result.stderr}"

    with_entry = sorted(set(line.strip() for line in result.stdout.splitlines() if line.strip()))
    assert not with_entry, f"Authenticated Users still has an entry on: {with_entry}"
