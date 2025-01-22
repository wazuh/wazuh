#!/usr/bin/env python3
from pathlib import Path
import shared.resource_handler as rs
import sys
from typing import List, Tuple, Optional, Union
from engine_handler.handler import EngineHandler
import json
import subprocess


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


class TestResult:
    def __init__(self, name: str, command: Optional[str] = None):
        self.name = name
        self.results: List[UnitOutput] = []
        self.success = True
        self.test_error = None
        self.command = command

    def add_result(self, result: UnitOutput):
        self.results.append(result)
        if not result.success:
            self.success = False

    def make_failure(self, error: str):
        self.success = False
        self.test_error = error


class Result:
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


ASSETS_IN_SYSTEM = ["decoder/core-wazuh-message/0", "decoder/integrations/0",
                    "rule/enrichment/0", "output/file-output-integrations/0"]


def print_coverity_results(asset_traces_by_stage: dict, min_coverity):
    header = "\nCoverity Processing Report by Stages\n"
    header += "=" * 50 + "\n"

    for asset, traces_by_stages in asset_traces_by_stage.items():
        report = header + f"Asset: {asset}\n"
        for stage, traces in traces_by_stages.items():
            report += f"Stage: {stage.capitalize()}\n"
            if not traces:
                report += f"There are no tracks assigned for this stage.\n"
            else:
                only_success_traces = get_only_success_traces(traces)
                only_failure_traces = get_only_failure_traces(traces)
                coverage = len(only_success_traces)/len(traces)*100
                report += f"Coverity: {coverage}. \n"
                report += "Failure Traces:\n"
                for trace in only_failure_traces:
                    report += f"- {trace}\n"
                report += "Success Traces:\n"
                for trace in only_success_traces:
                    report += f"- {trace}\n"
            report += "-" * 50 + "\n"

        print(report)
        report = ""


def get_coverity(traces: list):
    for line in traces:
        total_traces = len(traces)
        success_count = sum(1 for trace in traces if "-> Success" in trace)

    success_percentage = (success_count / total_traces) * 100
    return success_percentage


def print_traces_report(asset_traces_by_stage: dict):
    header = "\nTrace Processing Report by Stages\n"
    header += "=" * 50 + "\n"

    for asset, traces_by_stages in asset_traces_by_stage.items():
        report = header + f"Asset: {asset}\n"
        for stage, stage_traces in traces_by_stages.items():
            report += f"Stage: {stage.capitalize()}\n"
            if stage_traces:
                for i, trace in enumerate(stage_traces, 1):
                    report += f"  {i}. {trace}\n"
            else:
                report += "  There are no tracks assigned for this stage.\n"
            report += "-" * 50 + "\n"

        print(report)
        report = ""


def get_asset(engine_api_socket, asset_name) -> dict:
    namespace = "wazuh"
    if asset_name in ASSETS_IN_SYSTEM:
        namespace = "system"

    command = ["engine-catalog", "-n", namespace, "--api-socket",
               engine_api_socket, "--format", "json", "get", asset_name]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        sys.exit(f"Command {command}: {e.stderr}")


def load_traces_by_stages(asset: dict, traces: list) -> dict:
    trace_index = 0

    traces_by_stages = {
        "check": [],
        "parse": [],
        "map": []
    }

    check_definitions = asset.get("check", [])
    if isinstance(check_definitions, str):
        traces_by_stages["check"].append(traces[trace_index])
        trace_index += 1
    else:
        for _ in check_definitions:
            traces_by_stages["check"].append(traces[trace_index])
            trace_index += 1

    parse_keys = [key for key in asset.keys() if key.startswith("parse|")]
    for parse_key in parse_keys:
        parse_definitions = asset[parse_key]
        for _ in parse_definitions:
            traces_by_stages["parse"].append(traces[trace_index])
            trace_index += 1
            if "-> Success" in traces[trace_index - 1]:
                break

    skip_map = False
    skip_parse = False
    for normalize_entry in asset.get("normalize", []):
        has_map = "map" in normalize_entry
        has_parse = any(key.startswith("parse|") for key in normalize_entry)

        for key, value in normalize_entry.items():
            if key == "map":
                if skip_map:
                    skip_map = False
                    continue

                for map_entry in value:
                    if trace_index < len(traces):
                        traces_by_stages["map"].append(traces[trace_index])
                        trace_index += 1

            elif key.startswith("parse|"):
                if skip_parse:
                    skip_parse = False
                    continue

                for _ in value:
                    if trace_index < len(traces):
                        traces_by_stages["parse"].append(traces[trace_index])
                        trace_index += 1
                        if "-> Success" in traces[trace_index - 1]:
                            break

            else:
                if isinstance(value, str):
                    traces_by_stages["check"].append(traces[trace_index])
                    trace_index += 1
                    if "-> Success" not in traces[trace_index - 1]:
                        skip_map = has_map
                        skip_parse = has_parse
                        continue
                else:
                    for _ in value:
                        if trace_index < len(traces):
                            traces_by_stages["check"].append(traces[trace_index])
                            trace_index += 1
                            if "-> Success" not in traces[trace_index - 1]:
                                skip_map = has_map
                                skip_parse = has_parse
                                continue
    return traces_by_stages


def get_only_success_traces(traces: list) -> list:
    return [trace for trace in traces if "-> Success" in trace]


def get_only_failure_traces(traces: list) -> list:
    return [trace for trace in traces if "-> Success" not in trace]


def update_remnant_traces(first_sample_traces: dict, new_sample_traces: dict):
    merged_traces = {}

    for stage, traces in first_sample_traces.items():
        if stage not in merged_traces:
            merged_traces[stage] = []
        merged_traces[stage].extend(traces)

    for stage, traces in new_sample_traces.items():
        if stage not in merged_traces:
            merged_traces[stage] = []
        merged_traces[stage].extend(traces)

    for stage in merged_traces:
        merged_traces[stage] = list(set(merged_traces[stage]))


def load_asset_trace(output: EngineTestOutput,  engine_api_socket, asset_traces_by_stage: dict):
    for result in output.results:
        trace_arr = result.output.get('traces', [])
        for trace_obj in trace_arr:
            if 'success' in trace_obj:
                asset_name = trace_obj['asset']
                traces = trace_obj['traces']
                asset = json.loads(get_asset(engine_api_socket, asset_name))
                if asset_name in asset_traces_by_stage:
                    update_remnant_traces(asset_traces_by_stage[asset_name], load_traces_by_stages(asset, traces))
                else:
                    asset_traces_by_stage[asset_name] = load_traces_by_stages(asset, traces)


def execute(name: str, command: str) -> Tuple[Optional[str], EngineTestOutput]:
    result = EngineTestOutput(name, command)
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.output.decode()}", result

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


def test(input_file: Path, command: str, engine_api_socket, asset_traces_by_stage: dict) -> TestResult:
    name = input_file.stem.replace("_input", "")
    error, output = execute(name, command)
    result = TestResult(name, command)

    if error:
        print("F", end="", flush=True)
        result.make_failure(error)
        return result
    load_asset_trace(output, engine_api_socket, asset_traces_by_stage)
    if error:
        print("F", end="", flush=True)
        result.make_failure(error)
        return result


def run_test(test_parent_path: Path, engine_api_socket: str, debug_mode: str, target: str, asset_traces_by_stage: dict) -> Result:
    test_parent_name = test_parent_path.name
    result = Result(test_parent_name)

    test_dir = (test_parent_path / "test").resolve()
    if not test_dir.exists():
        result.make_failure(f"Test directory not found: {test_dir}")
        return result

    engine_test_conf = test_parent_path / "test" / "engine-test.conf"
    if not engine_test_conf.exists():
        result.make_failure(f"engine-test.conf not found: {engine_test_conf}")
        return result

    test_name = test_parent_name

    for input_file in test_dir.rglob("*_input.*"):
        print(".", end="", flush=True)

        if input_file.parent != test_dir:
            test_name = f"{test_parent_name}-{input_file.parent.name}"

        ns = "wazuh system" if target == 'rule' else "wazuh"
        engine_test_command = f"engine-test -c {engine_test_conf.resolve().as_posix()} "
        engine_test_command += f"run {test_name} --api-socket {engine_api_socket} -n {ns} {debug_mode} -j"
        command = f"cat {input_file.resolve().as_posix()} | {engine_test_command}"
        test_result = test(input_file, command, engine_api_socket, asset_traces_by_stage)
        if test_result:
            result.add_result(test_result)

    return result


def decoder_health_test(env_path: Path, debug_mode: str, min_coverity, integration_name: Optional[str] = None, skip: Optional[List[str]] = None):
    print("Validating environment...")
    conf_path = (env_path / "config.env").resolve()
    if not conf_path.is_file():
        sys.exit(f"Configuration file not found: {conf_path}")

    bin_path = (env_path / "wazuh-engine").resolve()
    if not bin_path.is_file():
        sys.exit(f"Engine binary not found: {bin_path}")

    integrations_path = (env_path / "ruleset/integrations").resolve()
    if not integrations_path.exists():
        sys.exit(f"Integrations directory not found: {integrations_path}")
    print("Environment validated.")

    print("Starting engine...")
    engine_handler = EngineHandler(bin_path.as_posix(), conf_path.as_posix())

    results: List[Result] = []
    integrations: List[Path] = []
    asset_traces_by_stage = {}

    try:
        if integration_name is not None:
            print(f"Specified integration: {integration_name}")
            integration_path = integrations_path / integration_name
            if not integration_path.exists():
                sys.exit(f"Integration {integration_name} not found.")

            integrations.append(integration_path)
        else:
            for integration_path in integrations_path.iterdir():
                if not integration_path.is_dir():
                    continue
                print(f'Discovered integration: {integration_path.name}')
                if skip and integration_path.name in skip:
                    print(f'Skipping integration: {integration_path.name}')
                    continue
                integrations.append(integration_path)

        engine_handler.start()
        print("Engine started.")

        print("\n\nRunning tests...")
        for integration_path in integrations:
            result = run_test(integration_path, engine_handler.api_socket_path,
                              debug_mode, 'decoder', asset_traces_by_stage)
            results.append(result)

        print_coverity_results(asset_traces_by_stage, min_coverity)

    finally:
        engine_handler.stop()
        print("Engine stopped.")

    print("\n\n")
    for result in results:
        print(result)

    success = True
    for result in results:
        if not result.success:
            success = False

    if success:
        print("All tests passed.")
        sys.exit(0)
    else:
        sys.exit(1)


def rule_health_test(env_path: Path, debug_mode: str, min_coverity, ruleset_name: Optional[str] = None, skip: Optional[List[str]] = None):
    print("Validating environment for rules...")
    conf_path = (env_path / "config.env").resolve()
    if not conf_path.is_file():
        sys.exit(f"Configuration file not found: {conf_path}")

    bin_path = (env_path / "wazuh-engine").resolve()
    if not bin_path.is_file():
        sys.exit(f"Engine binary not found: {bin_path}")

    rules_path = (env_path / "ruleset/rules").resolve()
    if not rules_path.exists():
        sys.exit(f"Rules directory not found: {rules_path}")
    print("Environment validated.")

    print("Starting engine...")
    engine_handler = EngineHandler(bin_path.as_posix(), conf_path.as_posix())

    results: List[Result] = []
    rules: List[Path] = []
    asset_traces_by_stage = {}

    try:
        if ruleset_name is not None:
            print(f"Specific ruleset: {ruleset_name}")
            ruleset_path = rules_path / ruleset_name
            if not ruleset_path.exists():
                sys.exit(f"Ruleset {ruleset_name} not found.")
            rules.append(ruleset_path)
        else:
            for ruleset_path in rules_path.iterdir():
                if not ruleset_path.is_dir():
                    continue
                print(f'Discovered ruleset: {ruleset_path.name}')
                if skip and ruleset_path.name in skip:
                    print(f'Skipping ruleset: {ruleset_path.name}')
                    continue
                rules.append(ruleset_path)

        engine_handler.start()
        print("Engine started.")

        print("\n\nRunning tests...")
        for ruleset_path in rules:
            result = run_test(ruleset_path, engine_handler.api_socket_path, debug_mode, 'rule', asset_traces_by_stage)
            results.append(result)

        print_coverity_results(asset_traces_by_stage, min_coverity)

    finally:
        engine_handler.stop()
        print("Engine stopped.")

    print("\n\n")
    for result in results:
        print(result)

    success = True
    for result in results:
        if not result.success:
            success = False

    if success:
        print("All tests passed.")
        sys.exit(0)
    else:
        sys.exit(1)


def run(args):
    env_path = Path(args['environment'])
    integration_name = args.get('integration')
    rule_folder = args.get('rule_folder')
    target = args.get('target')
    skip = args.get('skip', ['wazuh-core'])
    min_coverity = args.get('coverity', 80)
    debug_mode = "-dd"

    provided_args = sum(
        [bool(integration_name), bool(rule_folder), bool(target)])
    if provided_args > 1:
        sys.exit(
            "It is only possible to specify one of the following arguments: 'target', 'integration' or 'rule_folder'")

    if rule_folder:
        return rule_health_test(env_path, debug_mode, min_coverity, rule_folder, skip)

    elif integration_name:
        return decoder_health_test(env_path, debug_mode, min_coverity, integration_name, skip)

    elif target:
        if target == 'decoder':
            return decoder_health_test(env_path, debug_mode, min_coverity, integration_name, skip)
        elif target == 'rule':
            return rule_health_test(env_path, debug_mode, min_coverity, rule_folder, skip)
        else:
            sys.exit(f"The {target} target is not currently supported")

    else:
        sys.exit(
            "At least one of the following arguments must be specified: 'target', 'integration' or 'rule_folder'")
