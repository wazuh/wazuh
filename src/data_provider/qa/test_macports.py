import json
import platform
import subprocess
from pathlib import Path

import pytest
import sys
from jsonschema import validate
from jsonschema.exceptions import ValidationError


def call_binary(binary_path, parameter):
    try:
        # Run the binary and capture its output
        result = subprocess.run(
            [binary_path, parameter], capture_output=True, check=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error while executing the binary: {e}") from e


def validate_json_output(json_data):
    contains_pkg = False
    for package in json_data['packages']:
        if package['format'] == "macports":
            contains_pkg = True
            break
    if not contains_pkg:
        pytest.fail(f"The output does not contain any macports package")


@pytest.mark.skipif(sys.platform != "darwin", reason="test for MacOS only")
def test_json_output():
    # Path to the shared library
    binary_filename = "sysinfo_test_tool"
    binary_path_folder = "build/bin"
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

    # Validate that the JSON output contains macports packages.
    validate_json_output(json_data)
