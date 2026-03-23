#!/usr/bin/env python3

import os
import sys
import subprocess
import requests
import glob
import re
import json

upgrade_log = r"C:\win-agent-base\upgraded_version.log"

def check_and_uninstall_wazuh():
    """
    Checks if Wazuh is installed. If so, it uninstalls it before proceeding.
    We use WMIC to look for any product name containing 'Wazuh'.
    """
    print("Checking if Wazuh is already installed...")
    check_cmd = (
        'wmic product where "Name like \'%Wazuh%\'" get Name, Version /format:list'
    )
    result = subprocess.run(check_cmd, capture_output=True, text=True, shell=True)
    if "Name=Wazuh" in result.stdout:
        print("Wazuh is currently installed. Proceeding to uninstall...")
        uninstall_cmd = (
            'wmic product where "Name like \'%Wazuh%\'" call uninstall /nointeractive'
        )
        # Attempt to uninstall
        uninstall_result = subprocess.run(uninstall_cmd, capture_output=True, text=True, shell=True)

        print(uninstall_result.stdout)
        print(uninstall_result.stderr)

        if uninstall_result.returncode == 0:
            print("Uninstallation completed successfully.")
        else:
            print(f"Uninstallation failed with return code {uninstall_result.returncode}.")
            sys.exit(uninstall_result.returncode)
    else:
        print("No existing Wazuh installation found.")
        sys.exit(1)

def download_package(package_url):
    """
    Downloads the old Wazuh MSI package to C:\\old_package.
    """
    old_pkg_dir = r"C:\old_package"
    os.makedirs(old_pkg_dir, exist_ok=True)

    file_name = os.path.basename(package_url)
    destination = os.path.join(old_pkg_dir, file_name)

    try:
        print(f"Downloading old package from: {package_url}")
        response = requests.get(package_url, stream=True)
        response.raise_for_status()
        with open(destination, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    except Exception as e:
        print(f"Error: Failed to download the package from {package_url} -> {e}")
        sys.exit(1)

    return destination

def install_package(package_path):
    """
    Installs the given MSI package with msiexec, in silent mode.
    It captures verbose logs, then appends them to upgraded_version.log.
    """
    if not os.path.exists(package_path):
        print(f"Error: The package to install does not exist at {package_path}")
        sys.exit(1)

    print(f"Installing Wazuh from: {package_path}")

    temp_log_path = r"C:\win-agent-base\msiexec_install.log"
    cmd = ["msiexec", "/i", package_path, "/qn", "/norestart", "/q", "WAZUH_MANAGER=1.1.1.1", "/l", temp_log_path]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error installing: {e}")
        sys.exit(1)

    # Append the msiexec log to upgraded_version.log
    if os.path.exists(temp_log_path):
        try:
            with open(temp_log_path, 'r', encoding='utf-16le') as src:
                log_content = src.read()
            with open(upgrade_log, 'a', encoding='utf-16le') as dst:
                dst.write(f"\n=== Verbose log for {package_path} install ===\n")
                dst.write(log_content)
                dst.write("\n=== End of log ===\n")
            os.remove(temp_log_path)
        except Exception as e:
            print(f"Warning: Unable to process msiexec log file: {e}")

def verify_installation(expected_version):
    success_pattern = "Product: Wazuh Agent -- Installation completed successfully"

    try:
        if not os.path.exists(upgrade_log):
            print(f"Error: Upgrade log not found at {upgrade_log}")
            return False

        with open(upgrade_log, 'r', encoding='utf-16le') as f:
            log_content = f.read()
        sys.stdout.buffer.write(log_content.encode('utf-8', errors='replace'))

        success_count = log_content.count(success_pattern)
        print(f"Found {success_count} occurrences of successful installation in logs.")
        if success_count != 2:
            print("The upgrade could not be completed (expected 2 success messages).")
            return False

        agent_exe = r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"
        if not os.path.exists(agent_exe):
            print(f"Error: Wazuh agent not found at {agent_exe}")
            return False

        print("Starting Wazuh service...")
        subprocess.run(["NET", "START", "Wazuh"], shell=True, check=True)

        print("Checking Wazuh service status...")
        ps_cmd = ["powershell", "-Command", "(Get-Service wazuh).Status"]
        result = subprocess.run(ps_cmd, capture_output=True, text=True)
        service_status = result.stdout.strip()
        print(f"Service status: {service_status}")
        if service_status != "Running":
            print("Wazuh agent service is not running.")
            return False

        version_file_path = r"C:\Program Files (x86)\ossec-agent\version.json"
        if not os.path.exists(version_file_path):
            print(f"Error: Version file not found at {version_file_path}")
            return False

        with open(version_file_path, "r", encoding="utf-8") as vf:
            data = json.load(vf)
            installed_version = data.get("version", None)

        print(f"Installed version: {installed_version}, Expected: {expected_version}")
        if installed_version != expected_version:
            print("Version mismatch.")
            return False

    except Exception as e:
        print(f"Exception during verification: {e}")
        return False

    return True

def main():
    """
    Usage: python smoke_upgrade_test.py <old_package_url> <expected_version>
    """
    if len(sys.argv) < 3:
        print("Error: Missing arguments.\nUsage: python smoke_upgrade_test.py <old_package_url> <expected_version>")
        sys.exit(1)

    old_package_url = sys.argv[1]
    expected_upgrade_version = sys.argv[2]

    os.makedirs(r"C:\win-agent-base", exist_ok=True)
    open(upgrade_log, 'w').close()

    # 1. Uninstall if existing
    check_and_uninstall_wazuh()

    # 2. Download & install old package
    old_package_path = download_package(old_package_url)
    install_package(old_package_path)

    # 3. Find & install new package
    new_pkg_dir = r"C:\win-agent-base"
    pattern = os.path.join(new_pkg_dir, "wazuh*.msi")
    msi_files = glob.glob(pattern)
    msi_files = [f for f in msi_files if not re.search(r"(dbg|debug)", f, re.IGNORECASE)]

    if not msi_files:
        print(f"Error: No Wazuh MSI found in {new_pkg_dir} matching 'wazuh*.msi' (excluding dbg/debug).")
        sys.exit(1)

    new_package_path = msi_files[0]
    install_package(new_package_path)

    # 4. Check upgrade
    print("Performing post-installation checks...")
    if not verify_installation(expected_upgrade_version):
        print("Post-installation checks failed.")
        sys.exit(1)

    print("All checks passed successfully. Upgrade completed!")

if __name__ == "__main__":
    main()
