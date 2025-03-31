#!/usr/bin/env python3
from typing import List, Tuple, Optional, Union, Dict
from pathlib import Path
import docker
import requests
import json
import time
import sys
import subprocess
from engine_handler.handler import EngineHandler
from shared.default_settings import Constants, CONFIG_ENV_KEYS
import yaml
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import engine_pb2 as api_engine
from api_communication.proto import policy_pb2 as api_policy
from google.protobuf.json_format import ParseDict
from health_test.utils import *

class UnitOutput:
    def __init__(self, index: int, result: Union[str, dict]):
        self.index = index
        if isinstance(result, str):
            self.success = False
            self.error = result
        elif isinstance(result, dict):
            self.success = True
            self.output = result


class UnitResult:
    def __init__(self, index: int, expected: dict, actual: dict):
        self.index = index
        self.expected = expected
        self.setup(actual)

    def setup(self, actual: dict):
        self.diff = {}
        filtered_expected = filter_nested(self.expected)
        filtered_actual  = filter_nested(actual)

        if filtered_expected == filtered_actual:
            self.success = True
            return
        else:
            self.success = False

        for key in filtered_expected:
            if key not in filtered_actual:
                self.diff[key] = {"info": "Missing key in actual result",
                                  "expected": filtered_expected[key]}
                return
            elif filtered_expected[key] != filtered_actual[key]:
                self.diff[key] = {"info": "Mismatched value",
                                  "expected": filtered_expected[key], "actual": filtered_actual[key]}
        for key in filtered_actual:
            if key not in filtered_expected:
                self.diff[key] = {"info": "Extra key in actual result",
                                  "actual": filtered_actual[key]}


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


class OpensearchManagement:
    def __init__(self):
        self.offset = 0

    def stop(self):
        for container in self.client.containers.list():
            try:
                container.stop()
                container.remove()
            except Exception as e:
                print(f"Error stopping or removing container {container.id}: {e}")
        self.client.containers.prune()

    def init_index(self, template_path: Path) -> requests.Response:
        with open(template_path, 'r') as template_file:
            template_json = json.load(template_file)
            headers = {"Content-Type": "application/json"}
            url = f'http://localhost:9200/{Constants.INDEX_PATTERN}'
            response = requests.put(url, data=json.dumps(template_json['template']), headers=headers)
            return response

    def init_opensearch(self, template_path: Path):
        self.client = docker.from_env()
        env_vars = {
            'discovery.type': 'single-node',
            'plugins.security.disabled': 'true',
            'OPENSEARCH_INITIAL_ADMIN_PASSWORD': 'WazuhTest99$',
            'OPENSEARCH_LOG_LEVEL': 'TRACE'
        }
        self.client.containers.run("opensearchproject/opensearch", detach=True, ports={'9200/tcp': 9200},
                                   environment=env_vars, name='opensearch', stdout=True, stderr=True)

        while True:
            try:
                response = requests.get('http://localhost:9200')
                if response.status_code == 200:
                    if self.init_index(template_path).status_code == 200:
                        break
            except requests.exceptions.ConnectionError:
                pass
            time.sleep(1)

        try:
            url_health = 'http://localhost:9200/_cluster/health?wait_for_status=green&timeout=10s'
            response = requests.get(url_health)
            response.raise_for_status()
            assert response.status_code == 200, f"Expected status code 200, but got {response.status_code}"
            assert response.json()['status'] == 'green', f"Expected status 'green', but got {response.json()['status']}"
            counter = 0
            while counter < 10:
                url = 'http://localhost:9200/_cat/indices'
                response = requests.get(url)
                if response.status_code == 200 and Constants.INDEX_PATTERN in response.text:
                    break
                time.sleep(1)
                counter += 1
            assert counter < 10, "The index was not created"

        except requests.RequestException as e:
            print(f"HTTP request error: {e}")
            self.stop()
        except AssertionError as e:
            print(f"Assertion error: {e}")
            self.stop()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            self.stop()

    def read_index(self, result: TestResult, expecteds: List[UnitOutput], retries=6, delay=5) -> bool:
        url_search = f'http://localhost:9200/{Constants.INDEX_PATTERN}/_search'
        headers = {"Content-Type": "application/json"}
        not_found = []

        for i, expected in enumerate(expecteds):
            initial_result_size = len(result.results)
            event_hash = expected.output['event_hash']

            for attempt in range(retries):
                try:
                    query = {
                        "query": {
                            "term": {
                                "event_hash": event_hash
                            }
                        }
                    }

                    response = requests.post(url_search, json=query, headers=headers)
                    response.raise_for_status()
                    hits = response.json()['hits']['hits']

                    if len(hits) > 0:
                        result.add_result(UnitResult(i, hits[0]['_source'], expected.output))
                        break
                except requests.ConnectionError as e:
                    print(f"Connection error: {e}. Retrying...")

                time.sleep(delay)

            if len(result.results) == initial_result_size:
                not_found.append(expected)

        if not_found:
            print("The following 'expected' were not found:")
            for missing in not_found:
                print(f"  - {missing.output}")
            return False

        return True


opensearch_management = OpensearchManagement()


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


def test(input_file: Path, command: str) -> EngineTestOutput:
    name = input_file.stem.replace("_input", "")
    error, output = execute(name, command)

    if error:
        print(error)
        print("F", end="", flush=True)
        output.add_result(UnitOutput(0, error))
    else:
        print(".", end="", flush=True)

    return output


def run_all_tests(test_parent_paths: List[Path], engine_api_socket: str) -> Dict[str, List[EngineTestOutput]]:
    all_outputs_by_integration = {}

    for test_parent_path in test_parent_paths:
        test_parent_name = test_parent_path.name
        test_dir = (test_parent_path / "test").resolve()

        if not test_dir.exists():
            print(f"Test directory not found: {test_dir}")
            continue

        engine_test_conf = test_parent_path / "test" / "engine-test.conf"
        if not engine_test_conf.exists():
            print(f"engine-test.conf not found: {engine_test_conf}")
            continue

        outputs_for_integration = []

        for input_file in test_dir.rglob("*_input.*"):
            test_name = test_parent_name
            if input_file.parent != test_dir:
                test_name = f"{test_parent_name}-{input_file.parent.name}"
            engine_test_command = f"engine-test -c {engine_test_conf.resolve().as_posix()} run {test_name} --api-socket {engine_api_socket} -j"
            command = f"cat {input_file.resolve().as_posix()} | {engine_test_command}"

            output = test(input_file, command)
            outputs_for_integration.append(output)

        all_outputs_by_integration[test_parent_name] = outputs_for_integration

    return all_outputs_by_integration


def validate_all_outputs(all_outputs: List[EngineTestOutput], integration: str) -> Result:
    result = Result(integration)

    for output in all_outputs:
        test_result = TestResult(output.name, output.command)
        success = opensearch_management.read_index(test_result, output.results)

        if not success:
            print("F", end="", flush=True)
            test_result.make_failure("Not all expected were found.")
        else:
            print(".", end="", flush=True)

        result.add_result(test_result)

    return result


def run_test(test_parent_paths: List[Path], engine_api_socket: str) -> List[Result]:
    all_outputs_integration = run_all_tests(test_parent_paths, engine_api_socket)
    results = []

    for integration in all_outputs_integration:
        results.append(validate_all_outputs(all_outputs_integration[integration], integration))

    return results


def exist_index_output(engine_handler: EngineHandler):
    request = api_catalog.ResourceGet_Request()
    request.namespaceid = "system"
    request.name = "output/indexer/0"
    request.format = api_catalog.ResourceFormat.yml
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)

    parsed_response = ParseDict(response, api_catalog.ResourceGet_Response())
    if parsed_response.content != "":
        return True
    return False


def load_indexer_output(engine_handler: EngineHandler) -> None:
    indexer_output = {
        "name": "output/indexer/0",
        "metadata": {
            "title": "Indexer output event",
            "description": "Output integrations events to wazuh-indexer",
            "compatibility": "",
            "versions": [""],
            "references": [""],
            "author": {
                "name": "Wazuh, Inc.",
                "date": "2024/12/01"
            }
        },
        "outputs": [
            {
                "wazuh-indexer": {
                    "index": Constants.INDEX_PATTERN
                }
            }
        ]
    }

    request = api_catalog.ResourcePost_Request()
    request.type = api_catalog.ResourceType.output
    request.namespaceid = "system"
    request.content = json.dumps(indexer_output)
    request.format = api_catalog.ResourceFormat.json
    print(f"Loading indexer output...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)

    parsed_response = ParseDict(
        response, api_engine.GenericStatus_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    print(f"Indexer output loaded.")


def load_indexer_output_in_policy(engine_handler: EngineHandler, stop_on_warn: bool = True) -> None:
    request = api_policy.AssetPost_Request()
    request.asset = "output/indexer/0"
    request.policy = "policy/wazuh/0"
    request.namespace = "system"
    print(f"Adding indexer output to policy...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)
    parsed_response = ParseDict(response, api_policy.AssetPost_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    if len(parsed_response.warning) > 0 and stop_on_warn:
        raise Exception(parsed_response.warning)
    print("indexer output added to policy.")


def delete_indexer_output(engine_handler: EngineHandler) -> None:
    request = api_catalog.ResourceDelete_Request()
    request.name = "output/indexer/0"
    request.namespaceid = "system"
    print(f"Deleting indexer output...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)

    parsed_response = ParseDict(
        response, api_engine.GenericStatus_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    print(f"Indexer output deleted.")


def delete_indexer_output_in_policy(engine_handler: EngineHandler, stop_on_warn: bool = True) -> None:
    request = api_policy.AssetDelete_Request()
    request.asset = "output/indexer/0"
    request.policy = "policy/wazuh/0"
    request.namespace = "system"
    print(f"Deleting indexer output to policy...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)
    parsed_response = ParseDict(response, api_policy.AssetDelete_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)
    if len(parsed_response.warning) > 0 and stop_on_warn:
        raise Exception(parsed_response.warning)
    print("indexer output deleted to policy.")


def update_wazuh_core_message(wazuh_core_message_file, engine_handler):
    request = api_catalog.ResourcePut_Request()
    request.name = "decoder/core-wazuh-message/0"
    request.namespaceid = "system"
    request.content = wazuh_core_message_file.read_text()
    request.format = api_catalog.ResourceFormat.yml
    print(f"Updating wazuh-core-message...\n{request}")
    error, response = engine_handler.api_client.send_recv(request)
    if error:
        raise Exception(error)

    parsed_response = ParseDict(
        response, api_engine.GenericStatus_Response())
    if parsed_response.status == api_engine.ERROR:
        raise Exception(parsed_response.error)


def modify_core_wazuh_decoder(file_path: Path, add_hash: bool = True):
    """
    Modifies the given Wazuh YAML file to add or remove 'event_hash' in 'normalize'.

    Parameters:
    - file_path: Path to the YAML file.
    - add_hash: Boolean indicating whether to add or remove 'event_hash'.
    """
    with file_path.open('r') as file:
        content = yaml.safe_load(file)

    # for entry in content['normalize']:
    #     if 'map' in entry:
    #         if add_hash:
    #             if not any(isinstance(item, dict) and 'event_hash' in item for item in entry['map']):
    #                 entry['map'].append({'event_hash': 'sha1($event.original)'})
    #                 print("Added 'event_hash' mapping.")
    #             else:
    #                 print("'event_hash' already exists.")
    #         else:
    #             entry['map'] = [item for item in entry['map'] if not (isinstance(item, dict) and 'event_hash' in item)]
    #             print("Removed 'event_hash' from normalize.")
    #         break

    entry = content.setdefault('normalize', [{}])[0]
    entry['map'] = entry.get('map', [])

    if add_hash:
        if not any(isinstance(item, dict) and 'event_hash' in item for item in entry['map']):
            entry['map'].append({'event_hash': 'sha1($event.original)'})
            print("Added 'event_hash' mapping.")
        else:
            print("'event_hash' already exists.")
    else:
        del content['normalize']
        print("Removed 'event_hash' from normalize.")

    with file_path.open('w') as file:
        yaml.dump(content, file, default_flow_style=False, sort_keys=False)


def decoder_health_test(env_path: Path, integration_name: Optional[str] = None, skip: Optional[List[str]] = None):
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
    engine_handler = EngineHandler(bin_path.as_posix(), conf_path.as_posix(), override_env={
                                   CONFIG_ENV_KEYS.LOG_LEVEL.value: "warning"})

    integrations: List[Path] = []
    CORE_WAZUH_DECODER_PATH = env_path / 'ruleset' / 'decoders' / 'wazuh-core' / 'core-wazuh-message.yml'
    original_log_level = ""

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

        opensearch_management.init_opensearch(env_path / 'ruleset' / 'schemas' / 'wazuh-template.json')

        log = (env_path / "logs/engine.log").as_posix()
        engine_handler.start(log)
        print("Engine started.")
        print("Update wazuh-core-message decoder")
        if not exist_index_output(engine_handler):
            load_indexer_output(engine_handler)
            load_indexer_output_in_policy(engine_handler)
        modify_core_wazuh_decoder(CORE_WAZUH_DECODER_PATH)
        update_wazuh_core_message(CORE_WAZUH_DECODER_PATH, engine_handler)

        print("\n\nRunning tests...")
        results = run_test(integrations, engine_handler.api_socket_path)

    finally:
        if exist_index_output(engine_handler):
            delete_indexer_output_in_policy(engine_handler)
            delete_indexer_output(engine_handler)
        print("Restart wazuh-core-message decoder changes")
        modify_core_wazuh_decoder(CORE_WAZUH_DECODER_PATH, add_hash=False)
        update_wazuh_core_message(CORE_WAZUH_DECODER_PATH, engine_handler)
        engine_handler.stop()
        opensearch_management.stop()
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


def rule_health_test(env_path: Path, ruleset_name: Optional[str] = None, skip: Optional[List[str]] = None):
    print("Validating environment for rules...")
    conf_path = (env_path / "config.env").resolve()
    if not conf_path.is_file():
        sys.exit(f"Configuration file not found: {conf_path}")

    bin_path = (env_path / "wazuh-engine").resolve()
    if not bin_path.is_file():
        sys.exit(f"Engine binary not found: {bin_path}")

    integration_rule_path = (env_path / "ruleset/integrations-rules").resolve()
    if not integration_rule_path.exists():
        sys.exit(f"Rules directory not found: {integration_rule_path}")
    print("Environment validated.")

    print("Starting engine...")
    engine_handler = EngineHandler(bin_path.as_posix(), conf_path.as_posix(), override_env={
                                   CONFIG_ENV_KEYS.LOG_LEVEL.value: "warning"})

    results: List[Result] = []
    rules: List[Path] = []
    CORE_WAZUH_DECODER_PATH = env_path / 'ruleset' / 'decoders' / 'wazuh-core' / 'core-wazuh-message.yml'
    original_log_level = ""

    try:
        if ruleset_name is not None:
            print(f"Specific ruleset: {ruleset_name}")
            ruleset_path = integration_rule_path / ruleset_name
            if not ruleset_path.exists():
                sys.exit(f"Integration rule {ruleset_name} not found.")
            rules.append(ruleset_path)
        else:
            for ruleset_path in integration_rule_path.iterdir():
                if not ruleset_path.is_dir():
                    continue
                print(f'Discovered ruleset: {ruleset_path.name}')
                if skip and ruleset_path.name in skip:
                    print(f'Skipping ruleset: {ruleset_path.name}')
                    continue
                rules.append(ruleset_path)

        opensearch_management.init_opensearch(env_path / 'ruleset' / 'schemas' / 'wazuh-template.json')

        log = (env_path / "logs/engine.log").as_posix()
        engine_handler.start(log)
        print("Engine started.")
        if not exist_index_output(engine_handler):
            load_indexer_output(engine_handler)
            load_indexer_output_in_policy(engine_handler)
        print("Update wazuh-core-message decoder")
        modify_core_wazuh_decoder(CORE_WAZUH_DECODER_PATH)
        update_wazuh_core_message(CORE_WAZUH_DECODER_PATH, engine_handler)

        print("\n\nRunning tests...")
        results = run_test(rules, engine_handler.api_socket_path)

    finally:
        if exist_index_output(engine_handler):
            delete_indexer_output_in_policy(engine_handler)
            delete_indexer_output(engine_handler)
        print("Restart wazuh-core-message decoder changes")
        modify_core_wazuh_decoder(CORE_WAZUH_DECODER_PATH, add_hash=False)
        update_wazuh_core_message(CORE_WAZUH_DECODER_PATH, engine_handler)
        engine_handler.stop()
        opensearch_management.stop()
        # Restore level log
        subprocess.run(
            ['sed', '-i', f's/server.log_level="warning"/server.log_level="{original_log_level}"/g', conf_path])
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
    integration_rule = args.get('integration_rule')
    target = args.get('target')
    skip = args['skip']

    provided_args = sum([bool(integration_name), bool(integration_rule), bool(target)])
    if provided_args > 1:
        sys.exit("It is only possible to specify one of the following arguments: 'target', 'integration' or 'integration_rule'")

    if integration_rule:
        return rule_health_test(env_path, integration_rule, skip)

    elif integration_name:
        return decoder_health_test(env_path, integration_name, skip)

    elif target:
        if target == 'decoder':
            return decoder_health_test(env_path, integration_name, skip)
        elif target == 'rule':
            return rule_health_test(env_path, integration_rule, skip)
        else:
            sys.exit(f"The {target} target is not currently supported")

    else:
        sys.exit("At least one of the following arguments must be specified: 'target', 'integration' or 'integration_rule'")
