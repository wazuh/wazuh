from cli_communication import communication #TODO: check on a clean install!
from behave import given, when, then, step
import os
import json

ENGINE_DIR = os.environ.get("ENGINE_DIR", "")
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = ENV_DIR + "/queue/sockets/engine-api"
RULESET_DIR = ENGINE_DIR + "/ruleset"
EXEC_PATH = ENGINE_DIR + "/build/main"

CLI_KVDB = communication.CLIClient(EXEC_PATH, SOCKET_PATH)

# First Scenario
@given('I have access to the KVDB CLI')
def step_impl(context):
    code, output = CLI_KVDB.execute_command("kvdb list")
    assert code == 0, f"{output}"
    kvdbs = output.split('\n')

    for kvdb in kvdbs:
        code, output = CLI_KVDB.execute_command(f"kvdb delete -n {kvdb}")

@when('I run the command "{command}"')
def step_impl(context, command: str):
    context.code, context.output = CLI_KVDB.execute_command(command)

@when('I add using CLI in the database "{database_name}" {i} key-value pairs with the key called "{key_name}"_id and another {j} key-value pairs with the key called "{other_key_name}"_id')
def step_impl(context, database_name:str , i: str, key_name: str, j: str, other_key_name: str):
    CLI_KVDB.execute_command(f"kvdb create -n {database_name}")
    for first in range(int(i)):
        name = key_name + "_" + str(first)
        context.code, context.output = CLI_KVDB.execute_command(f"kvdb insert -n {database_name} -k {name} -v sampleValue")
    for second in range(int(j)):
        name = other_key_name + "_" + str(second)
        context.code, context.output = CLI_KVDB.execute_command(f"kvdb insert -n {database_name} -k {name} -v sampleValue")

@then('I should receive a {response} message')
def step_impl(context, response: str):
    if response == "success":
        assert 0 == context.code, f"{context.output}"
    else:
        assert 7 == context.code, f"{context.output}"

@then('I should receive an error message indicating that "{response}"')
def step_impl(context, response: str):
    assert context.output.strip("\n") == response, f"{repr(context.output)}"

@then('I should receive a JSON of entries with the {size} key-value pairs whose keyname contains the prefix.')
def step_impl(context, size: str):
    kvdbs = eval(context.output)
    assert len(kvdbs) == int(size), f"{context.output}"
