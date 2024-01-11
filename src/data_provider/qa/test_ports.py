import json
import platform
import subprocess
from pathlib import Path

import pytest
from jsonschema import validate
from jsonschema.exceptions import ValidationError


def call_binary(binary_path):
    """This method runs the binary and capture its output.

    Args:
        binary_path: the path of the binary to run.

    Returns:
        _type_: the standard output of the binary execution.
    """
    command =  f"{binary_path}" if platform.system() == "Windows" else f"sudo {binary_path}"
    result = subprocess.run(command, capture_output=True, check=False, text=True, shell=True)
    if result.returncode != 0 or result.stderr:
        print(result.stdout)
        print(result.stderr)
        pytest.fail("The execution of the test tool failed.")
    return result.stdout.strip()

def validate_ports_json(json_data):
    """Validates the output against the schema.

    Args:
        json_data: the JSON data to validate.
    """
    # Path to the schema file
    schema_file = Path("qa", "ports_schema.json")

    # Load the schema from the file
    with open(schema_file, "r") as f:
        ports_schema = json.load(f)

    try:
        # Validate the JSON data against the schema
        validate(instance=json_data, schema=ports_schema)
    except ValidationError as e:
        # If the validation fails, print the error message
        print(json_data)
        pytest.fail(f"The output does not comply with the schema: {e}")


def test_json_output():
    """This method tests the output of the test tool against the proper schema.
    """
    # Path to the shared library
    binary_filename = "sysinfo_test_tool.exe" if platform.system() == "Windows" else "sysinfo_test_tool"
    binary_path_folder = "C:\\data_provider" if platform.system() == "Windows" else "build/bin"
    binary_path = Path(binary_path_folder, binary_filename)

    # Ensure the binary exists
    assert binary_path.exists(), f"The binary is not found at {binary_path}"

    # Call the binary and get the JSON output
    output = call_binary(binary_path)

    # Verify that the output is valid JSON
    try:
        json_data = json.loads(output)
    except json.JSONDecodeError as e:
        print(output)
        pytest.fail(f"The output is not valid JSON: {e}")

    # Validate that the JSON complies with the schema
    validate_ports_json(json_data)
