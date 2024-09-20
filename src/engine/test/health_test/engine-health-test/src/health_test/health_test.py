#!/usr/bin/env python3
import subprocess
import json
import sys
from pathlib import Path
from typing import List, Tuple, Optional, Union

from engine_handler.handler import EngineHandler


class UnitOutput:
    def __init__(self, index: int, result: Union[str, dict]):
        self.index = index
        if isinstance(result, str):
            self.success = False
            self.error = result
        elif isinstance(result, dict):
            self.success = True
            self.output = result


class EngineTestOutput:
    def __init__(self, name: str, command: str):
        self.name = name
        self.command = command
        self.results: List[UnitOutput] = []

    def add_result(self, result: UnitOutput):
        self.results.append(result)


class UnitResult:
    def __init__(self, index: int, expected: dict, actual: UnitOutput):
        self.index = index
        self.expected = expected
        if not actual.success:
            self.error = actual.error
            self.success = False
        else:
            self.compare(actual.output)

    def compare(self, actual: dict):
        self.diff = {}
        if self.expected == actual:
            self.success = True
            return
        else:
            self.success = False

        # Find the differences between the expected and actual results
        for key in self.expected:
            if key not in actual:
                self.diff[key] = {"info": "Missing key in actual result",
                                  "expected": self.expected[key]}
            elif self.expected[key] != actual[key]:
                self.diff[key] = {"info": "Mismatched value",
                                  "expected": self.expected[key], "actual": actual[key]}
        for key in actual:
            if key not in self.expected:
                self.diff[key] = {"info": "Extra key in actual result",
                                  "actual": actual[key]}


class TestResult:
    def __init__(self, name: str, command: Optional[str] = None):
        self.name = name
        self.results: List[UnitResult] = []
        self.success = True
        self.test_error = None
        self.command = command

    def add_result(self, result: UnitResult):
        self.results.append(result)
        if not result.success:
            self.success = False

    def make_failure(self, error: str):
        self.success = False
        self.test_error = error


class IntegrationResult:
    def __init__(self, name: str):
        self.name = name
        self.results: List[TestResult] = []
        self.success = True
        self.test_error = None

    def add_result(self, result: TestResult):
        self.results.append(result)
        if not result.success:
            self.success = False

    def make_failure(self, error: str):
        self.success = False
        self.test_error = error

    def __str__(self) -> str:
        out = f"{self.name} -> {'Success' if self.success else 'Failure'}"
        if self.test_error:
            out += f"\n  Error: {self.test_error}"
        elif not self.success:
            for result in self.results:
                out += f"\n  {result.name} -> {'Success' if result.success else 'Failure'}"
                if not result.success and result.command:
                    out += f"\n    Command: {result.command}"
                if result.test_error:
                    out += f"\n    Error: {result.test_error}"
                elif not result.success:
                    out += "\n    Event index:"
                    for unit_result in result.results:
                        out += f"\n      {unit_result.index} -> {'Success' if unit_result.success else 'Failure'}"
                        if not unit_result.success:
                            for key, value in unit_result.diff.items():
                                out += f"\n        {key}: {value}"

        return out


def execute(name: str, command: str) -> Tuple[Optional[str], EngineTestOutput]:
    result = EngineTestOutput(name, command)
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.output.decode()}", result

    # Split the output into individual JSON strings
    output_str = output.decode('utf-8')
    json_strings = output_str.strip().split('\n')

    for i, json_string in enumerate(json_strings):
        try:
            parsed_json = json.loads(json_string)
        except json.JSONDecodeError as e:
            result.add_result(UnitOutput(i, f"Error parsing JSON: {e}"))
        else:
            result.add_result(UnitOutput(i, parsed_json))

    return None, result


def compare_results(name: str, expected_file: Path, output: EngineTestOutput) -> Tuple[Optional[str], TestResult]:
    result = TestResult(name)
    with open(expected_file, 'r') as file:
        try:
            expected_json = json.load(file)
        except json.JSONDecodeError as e:
            return f"Error parsing expected JSON: {e}", result

    if len(expected_json) != len(output.results):
        return f"Expected {len(expected_json)} results, but got {len(output.results)}", result

    for i, (expected, actual) in enumerate(zip(expected_json, output.results)):
        result.add_result(UnitResult(i, expected, actual))

    return None, result


def test(input_file: Path, expected_file: Path, command: str) -> TestResult:
    name = input_file.stem.replace("_input", "")
    error, output = execute(name, command)
    result = TestResult(name, command)

    if error:
        print("F", end="", flush=True)
        result.make_failure(error)
        return result
    error, compare_result = compare_results(name, expected_file, output)
    compare_result.command = command
    if error:
        print("F", end="", flush=True)
        result.make_failure(error)
        return result

    if compare_result.success:
        print(".", end="", flush=True)
    else:
        print("F", end="", flush=True)
    return compare_result


def test_integration(integration_path: Path, engine_api_socket: str) -> IntegrationResult:
    # Get the name of the integration
    integration_name = integration_path.name
    result = IntegrationResult(integration_name)

    # Get the path of the test directory
    test_dir = (integration_path / "test").resolve()
    if not test_dir.exists():
        result.make_failure(f"Test directory not found: {test_dir}")
        return result

    # Get the path of the engine-test.conf file
    engine_test_conf = integration_path / "test" / "engine-test.conf"
    if not engine_test_conf.exists():
        result.make_failure(f"engine-test.conf not found: {engine_test_conf}")
        return result

    test_integration_name = integration_name

    for input_file in test_dir.rglob("*_input.*"):
        expected_file = input_file.with_name(
            input_file.stem.replace("_input", "_expected") + ".json")
        if not expected_file.exists():
            result.make_failure(
                f"Expected file not found: {expected_file}")
            return result

        # If the test file is in a subdirectory, the subdirectory must be added in the command integration name
        if input_file.parent != test_dir:
            test_integration_name = f"{integration_name}-{input_file.parent.name}"
        engine_test_command = f"engine-test -c {engine_test_conf.resolve().as_posix()} run {test_integration_name} --api-socket {engine_api_socket} -j"
        command = f"cat {input_file.resolve().as_posix()} | {engine_test_command}"
        test_result = test(input_file, expected_file, command)

        result.add_result(test_result)

    return result


def health_test(env_path: Path, integration_name: Optional[str] = None, skip: Optional[List[str]] = None):
    # Start the engine
    print("Validating environment...")
    conf_path = (env_path / "engine/general.conf").resolve()
    if not conf_path.is_file():
        print(f"Configuration file not found: {conf_path}")
        sys.exit(1)

    bin_path = (env_path / "bin/wazuh-engine").resolve()
    if not bin_path.is_file():
        print(f"Engine binary not found: {bin_path}")
        sys.exit(1)

    integrations_path = (env_path / "ruleset/integrations").resolve()
    if not integrations_path.exists():
        print(f"Integrations directory not found: {integrations_path}")
        sys.exit(1)
    print("Environment validated.")

    print("Starting engine...")
    engine_handler = EngineHandler(bin_path.as_posix(), conf_path.as_posix())

    results: List[IntegrationResult] = []
    integrations: List[Path] = []

    try:
        engine_handler.start()
        print("Engine started.")

        # Run specified test
        if integration_name is not None:
            print(f"Specified integration: {integration_name}")
            integration_path = integrations_path / integration_name
            if not integration_path.exists():
                print(f"Integration {integration_name} not found.")
                sys.exit(1)

            integrations.append(integration_path)

        # Discover and run all integration tests otherwise
        else:
            for integration_path in integrations_path.iterdir():
                if not integration_path.is_dir():
                    continue
                print(f'Discovered integration: {integration_path.name}')
                if skip and integration_path.name in skip:
                    print(f'Skipping integration: {integration_path.name}')
                    continue
                integrations.append(integration_path)

        print("\n\nRunning tests...")
        for integration_path in integrations:
            print(f'[{integration_path.name}]', end=' ', flush=True)
            result = test_integration(
                integration_path, engine_handler.api_socket_path)
            if result.test_error:
                print(f' -> {result.test_error}')
            elif not result.success:
                print(f' -> Failure')
            else:
                print(f' -> Success')

            results.append(result)
    except Exception as e:
        print(f"Error running test: {e}")
    finally:
        print("Stopping engine...")
        engine_handler.stop()
        print("Engine stopped.")

    if len(results) == 0:
        print("No tests run")
        return 1

    print("\n\nSummary:")
    failed = False
    for result in results:
        if not result.success:
            failed = True
        print(result)

    if failed:
        return 1

    return 0


def run(args):
    env_path = Path(args['environment'])
    integration_path = args['integration']
    skip = args['skip']
    return health_test(env_path, integration_path, skip)
