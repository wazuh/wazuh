import json
import platform
import subprocess
from pathlib import Path

import pytest
import sys
from jsonschema import validate
from jsonschema.exceptions import ValidationError
import re
import os

DPKG_INFO_PATH = "/var/lib/dpkg/info"  # Path to dpkg info directory

def get_dpkg_packages_python():
    """Get the list of Python packages installed from dpkg."""
    python_packages = set()
    list_pattern = re.compile(r"^python.*\.list$")
    python_info_files = [
        (re.compile(r"^.*\.egg-info$"), "/PKG-INFO"),
        (re.compile(r"^.*\.dist-info$"), "/METADATA"),
    ]

    try:
        if not os.path.exists(DPKG_INFO_PATH):
            return python_packages

        for entry in os.scandir(DPKG_INFO_PATH):
            if entry.is_file() and list_pattern.search(entry.name):
                with open(entry.path, "r") as file:
                    for line in file:
                        for pattern, extra_file in python_info_files:
                            match = pattern.search(line)
                            if match:
                                base_info_path = match.group(0)
                                full_path = os.path.join(DPKG_INFO_PATH, base_info_path)
                                if os.path.isfile(full_path):
                                    python_packages.add(full_path)
                                else:
                                    full_path_extra = os.path.join(DPKG_INFO_PATH, base_info_path + extra_file)
                                    if os.path.exists(full_path_extra):
                                        python_packages.add(full_path_extra)
    except OSError as e:
        print(f"Filesystem error: {e}")
    return python_packages

def get_rpm_packages_python():
    """Get the list of Python packages installed from rpm."""
    python_packages = set()
    python_info_files = [
        (re.compile(r"^.*\.egg-info$"), "/PKG-INFO"),
        (re.compile(r"^.*\.dist-info$"), "/METADATA"),
    ]

    try:
        result = subprocess.run(
            "rpm -qa | grep -E 'python.*' | xargs -I {} rpm -ql {} | grep -E '\\.egg-info$|\\.dist-info$'",
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        rpm_output = result.stdout.strip()
        if rpm_output:
            rows = rpm_output.splitlines()
            for row in rows:
                for pattern, extra_file in python_info_files:
                    match = pattern.search(row)
                    if match:
                        base_info_path = match.group(0)
                        if os.path.isfile(base_info_path):
                            python_packages.add(base_info_path)
                        else:
                            full_path = base_info_path + extra_file
                            if os.path.exists(full_path):
                                python_packages.add(full_path)
    except subprocess.CalledProcessError as e:
        print(f"RPM command failed: {e}")
    return python_packages

def get_package_name_from_path(package_path):
    """Extracts the package name from a PKG-INFO or METADATA file."""
    try:
        with open(package_path, "r") as file:
            for line in file:
                if line.startswith("Name: "):
                    return line[6:].strip()
    except FileNotFoundError:
        return None
    return None

def call_binary(binary_path, parameter):
    try:
        command =  f"{binary_path}" if platform.system() == "Windows" else f"sudo {binary_path}"
        # Run the binary and capture its output
        result = subprocess.run(
            [command, parameter], capture_output=True, check=False, text=True, shell=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error while executing the binary: {e}") from e


def validate_packages_json(json_data):
    # Path to the schema file
    schema_file = Path("qa", "packages_schema.json")

    # Load the schema from the file
    with open(schema_file, "r") as f:
        packages_schema = json.load(f)

    try:
        # Validate the JSON data against the schema
        validate(instance=json_data, schema=packages_schema)
    except ValidationError as e:
        # If the validation fails, print the error message
        if len(e.absolute_path) >= 3:
            pkg_name=json_data['packages'][e.absolute_path[1]]['name']
            pkg_format=json_data['packages'][e.absolute_path[1]]['format']
            pytest.fail(f"The output for package '{pkg_name}' with format '{pkg_format}' does not comply with the schema, in the field '{e.absolute_path[2]}': {e}")
        else:
            pytest.fail(f"The output does not comply with the schema: {e}")


def test_json_output():
    # Path to the shared library
    binary_filename = "sysinfo_test_tool.exe" if platform.system() == "Windows" else "sysinfo_test_tool"
    binary_path_folder = "C:\\data_provider" if platform.system() == "Windows" else "build/bin"
    binary_path = Path(binary_path_folder, binary_filename)

    # Ensure the binary exists
    assert binary_path.exists(), f"The binary is not found at {binary_path}"

    # Call the binary and get the JSON output
    output = call_binary(binary_path, "--packages")
    # Verify that the output is valid JSON
    try:
        json_data = json.loads(output)
    except json.JSONDecodeError as e:
        pytest.fail(f"The output is not valid JSON: {e}")

    # Validate that the JSON complies with the schema
    validate_packages_json(json_data)

def test_packages_pypi():
    # Path to the shared library
    binary_filename = "sysinfo_test_tool.exe" if platform.system() == "Windows" else "sysinfo_test_tool"
    binary_path_folder = "C:\\data_provider" if platform.system() == "Windows" else "build/bin"
    binary_path = Path(binary_path_folder, binary_filename)

    # Ensure the binary exists
    assert binary_path.exists(), f"The binary is not found at {binary_path}"

    # Call the binary and get the JSON output
    output = call_binary(binary_path, "--packages")

    # Call pip3 and get the list of installed packages
    result = subprocess.run(
        ["pip3", "list", "--format", "json"], capture_output=True, check=False, text=True)
    pip_output = result.stdout.strip()

    # Get dpkg packages names
    dpkg_package_paths = get_dpkg_packages_python()
    dpkg_packages = {get_package_name_from_path(path) for path in dpkg_package_paths if get_package_name_from_path(path)}

    #Get rpm packages names
    rpm_package_paths = get_rpm_packages_python()
    rpm_packages = {get_package_name_from_path(path) for path in rpm_package_paths if get_package_name_from_path(path)}

    # Combine dpkg and rpm packages
    all_system_packages = dpkg_packages.union(rpm_packages)

    # Compare the list of installed packages with the list from the binary
    try:
        pip_json_data = json.loads(pip_output)
        json_data = json.loads(output)

        # Filter pip_json_data
        filtered_pip_json_data = [pkg for pkg in pip_json_data if pkg['name'] not in all_system_packages]

        # Check if each element of filtered_pip_json_data exists in json_data array.
        for pkg in filtered_pip_json_data:
            found = False
            for pkg2 in json_data['packages']:
                if pkg['name'] == pkg2['name'] and pkg['version'] == pkg2['version']:
                    found = True
                    break
            assert found, f"The package {pkg['name']} is not found in the output of the binary"

    except json.JSONDecodeError as e:
        pytest.fail(f"The output is not valid JSON: {e}")

@pytest.mark.skipif(sys.platform == "win32", reason="test for Linux and macOS only")
def test_packages_npm():
    # Path to the shared library
    binary_filename = "sysinfo_test_tool.exe" if platform.system() == "Windows" else "sysinfo_test_tool"
    binary_path_folder = "C:\\data_provider" if platform.system() == "Windows" else "build/bin"
    binary_path = Path(binary_path_folder, binary_filename)

    # Ensure the binary exists
    assert binary_path.exists(), f"The binary is not found at {binary_path}"

    # Call the binary and get the JSON output
    output = call_binary(binary_path, "--packages")

    # Call npm and get the list of installed packages
    if platform.system() == "Windows":
        result = subprocess.run(
            ["npm", "list", "--json"], capture_output=True, check=False, text=True, shell=True)
    else:
        result = subprocess.run(
            ["npm", "list", "-g","--json"], capture_output=True, check=False, text=True)

    npm_output = result.stdout.strip()

    # Compare the list of installed packages with the list from the binary
    try:
        npm_json_data = json.loads(npm_output)
        json_data = json.loads(output)

        # Check if each element of npm_json_data exists in json_data array.
        for pkg in npm_json_data['dependencies']:
            # Exclude if starts with @
            if pkg.startswith('@'):
                continue
            found = False
            for pkg2 in json_data['packages']:
                if pkg == pkg2['name']:
                    found = True
                    break
            assert found, f"The package {pkg} is not found in the output of the binary"

    except json.JSONDecodeError as e:
        pytest.fail(f"The output is not valid JSON: {e}")
