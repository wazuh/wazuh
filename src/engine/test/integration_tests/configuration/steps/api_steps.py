from api_communication.client import APIClient
from google.protobuf.json_format import ParseDict
from api_communication.proto import config_pb2 as api_config
from api_communication.proto import engine_pb2 as api_engine

from behave import given, when, then
import os
import shutil
import ast
import subprocess
import shlex
import signal
import time
from typing import Optional, Tuple, List

ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api"
RULESET_DIR = ENV_DIR + "/engine"
BINARY_PATH = os.environ.get("WAZUH_DIR", "") + "/src/engine/build/main"
CONF_FILE = os.environ.get("CONF_FILE", "")

api_client = APIClient(SOCKET_PATH)

def server_start():

    # Command to execute the binary in the background
    command = f"{BINARY_PATH} --config {CONF_FILE} server --api_timeout 1000 start"

    # Split the command into a list of arguments using shlex
    args = shlex.split(command)

    # Execute the process in the background with subprocess.Popen
    process = subprocess.Popen(args)

    # Wait for a moment to ensure the process has started
    time.sleep(2)

    # Get the PID of the process and store it in the context
    return process.pid

def server_stop(pid):
    try:
        os.kill(pid, signal.SIGINT)
        print(f"Interrupt signal sent to the process with PID {pid}")
    except ProcessLookupError:
        print(f"Could not find the process with PID {pid}")

def send_recv(request, expected_response_type) -> Tuple[Optional[str], dict]:
    error, response = api_client.send_recv(request)
    assert error is None, f"{error}"
    parse_response = ParseDict(response, expected_response_type)
    if parse_response == api_engine.ERROR:
        return parse_response.error, parse_response
    else:
        return None, parse_response

def read_configuration_file(file_name: str, variables: Optional[list]) -> Tuple[Optional[str], list]:
    file_path = ENV_DIR + f"/engine/{file_name}"
    config_data = []

    try:
        with open(file_path, 'r') as file:
            for line in file:
                key_value = line.split('=', 1)
                if len(key_value) == 2:
                    key, value = map(str.strip, key_value)
                    if variables is None or key in variables:
                        config_data.append(value)

            if variables is None or not variables:
                file.seek(0)
                return file.read(), []

    except Exception as e:
        assert False, f"Error reading file"

    return None, config_data

def get_runtime_configuration(name: Optional[str]):
    request = api_config.RuntimeGet_Request()
    if name is not None:
        request.name = name
    error, response = send_recv(request, api_config.RuntimeGet_Response())
    assert error is None, f"{error}"
    return response

def update_runtime_configuration(name: str, content: str):
    request = api_config.RuntimePut_Request()
    request.name = name
    request.content = content
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response

def save_runtime_configuration(path: Optional[str]):
    request = api_config.RuntimeSave_Request()
    if path is not None:
        request.path = path
    error, response = send_recv(request, api_engine.GenericStatus_Response())
    return response

@given('I have a valid configuration file called {file_name}')
def step_impl(context, file_name: str):
    name = "server.log_level"
    content = "error"
    context.result = update_runtime_configuration(name, content)
    file = RULESET_DIR + f"/{file_name}"
    assert os.path.exists(file), f"The file {file} does not exist."

@when('I send a request to save configuration file')
def step_impl(context):
    context.result = save_runtime_configuration(None)

@when('I send a request to save configuration file located in "{path}"')
def step_impl(context, path):
    context.result = save_runtime_configuration(path)
    shutil.rmtree(os.path.dirname((os.path.abspath(path))))

@when('I send a request to get configuration file')
def step_impl(context):
    context.result = get_runtime_configuration(None)

@when('I send a request to get configuration of the following fields {field_list}')
def step_impl(context, field_list: str):
    field_list = eval(field_list)
    result = []
    for field in field_list:
        result.append(get_runtime_configuration(field).content)
    context.result = result

@when('I send a request to update the iteam "{item}" to "{value}" value')
def step_impl(context, item: str, value: str):
    context.result = update_runtime_configuration(item, value)

@when('I send a signal to restart the engine')
def step_impl(context, item: str, value: str):
    context.result = update_runtime_configuration(item, value)

@when('I send a restart to server')
def step_impl(context):
    server_stop(context.pid)
    time.sleep(1)
    context.pid = server_start()

@then('I should receive a {status} response indicating "{response}"')
def step_impl(context, status: str, response: str):
    if status == "failed":
        if isinstance(context.result, str):
            assert context.result == response, f"{context.result}"
        else:
            assert context.result.status == api_engine.ERROR, f"{context.result}"
            assert context.result.error == response, f"{context.result}"

@then('I should receive the same content from {file_name}')
def step_impl(context, file_name: str):
    full_file, partial_file = read_configuration_file(file_name, None)
    assert full_file is not None, f"The content is empty"
    content_clear = '\n'.join(line for line in context.result.content.splitlines() if line.strip())
    full_file_clear = '\n'.join(line for line in full_file.splitlines() if line.strip())
    assert content_clear.strip() == full_file_clear.strip() , f"{content_clear} ---------- {full_file_clear}"

@then('I should receive the same value that {field_list} in {file_name}')
def step_impl(context, file_name: str, field_list: str):
    field_list = ast.literal_eval(field_list)
    full_file, partial_file = read_configuration_file(file_name, field_list)
    assert set(context.result) == set(partial_file), f"{context.result}------{partial_file}"

@then('I should receive "{log_level}" like log_level')
def step_impl(context, log_level: str):
    if context.result[0] != log_level:
        server_stop(context.pid)
        assert False, f"{context.result[0]}"

@then('I should receive a {status} response')
def step_impl(context, status: str):
    if status == "failed":
        assert context.result.status == api_engine.ERROR, f"{context.result}"
    else:
        assert context.result.status == api_engine.OK, f"{context.result}"

@then('I should stop server')
def step_impl(context):
    server_stop(context.pid)
