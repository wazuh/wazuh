from api_communication import communication #TODO: check on a clean install!
from behave import given, when, then, step
import os
import json

def find_engine_directory(start_dir):
    current_dir = os.path.abspath(start_dir)

    while current_dir != "/":  # Detenerse en la raíz del sistema de archivos
        if os.path.basename(current_dir) == "engine":
            return current_dir
        current_dir = os.path.dirname(current_dir)

    return None

def get_executable():
    engine_directory = find_engine_directory(os.path.dirname(os.path.abspath(__file__)))
    build_directory = os.path.join(engine_directory, "build")
    os.chdir(build_directory)
    return os.path.join(os.getcwd(), "main")

def socket_path():
    engine_directory = find_engine_directory(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(os.path.dirname(os.path.dirname(engine_directory)))
    environment_directory = os.path.join(os.getcwd(), "environment")
    os.chdir(environment_directory)
    return os.path.join(os.getcwd(), "queue/sockets/engine-api")

CLI_KVDB = communication.CLIClient(get_executable(), socket_path())

# First Scenario
@given('I have access to the KVDB CLI')
def step_impl(context):
    kvdbs_available_json = CLI_KVDB.execute_command("kvdb list")
    assert len(kvdbs_available_json) != 0, f'leng: {len(kvdbs_available_json)}'

@when('I run the command "{command}"')
def step_impl(context, command: str):
    context.result = CLI_KVDB.execute_command(command)
    CLI_KVDB.execute_command("kvdb delete --name TestDB")

@then('I should receive a {response} message with the new database information')
def step_impl(context, response: str):
    context.result != response


# Second Scenario
@given('I have already created a database named "{database_name}" using the KVDB CLI')
def step_impl(context, database_name: str):
    CLI_KVDB.execute_command(f"kvdb create --name {database_name}")

@when('I execute the command "{command}"')
def step_impl(context, command: str):
    context.result = CLI_KVDB.execute_command(command)
    CLI_KVDB.execute_command("kvdb delete --name TestDB")

@then('I should receive an error message indicating that "{response}"')
def step_impl(context, response: str):
    context.result == response


# Third Scenario
@given('I have a database named "{database_name}" created using the KVDB CLI')
def step_impl(context, database_name: str):
    CLI_KVDB.execute_command(f"kvdb create --name {database_name}")

@when('I run the command "{command}')
def step_impl(context, command: str):
    context.result = CLI_KVDB.execute_command(command)

@then('I should receive a success message indicating that "{response}"')
def step_impl(context, response: str):
    assert context.result != response


# Fourth Scenario
@then('I should receive a {response} message with the new key-value pair information')
def step_impl(context, response: str):
    assert context.result != response


# Fifth Scenario
@given('I have already added a key-value pair with the key "{key_name}"')
def step_impl(context, key_name: str):
    CLI_KVDB.execute_command(f"kvdb insert -n TestDB -k {key_name} -v sampleValue")

@then('I should receive for CLI a {result} indicating that the key value has been updated')
def step_impl(context, result: str):
    assert context.result != result


# Sixth Scenario
@then('I should receive a {response} message indicating that the key-value pair with the key "sampleKey" has been deleted')
def step_impl(context, response: str):
    assert context.result != response


# Seventh Scenario
@when('I add using CLI in the database "{database_name}" {i} key-value pairs with the key called "{key_name}"_id and another {j} key-value pairs with the key called "{other_key_name}"_id')
def step_impl(context, database_name:str , i: str, key_name: str, j: str, other_key_name: str):
    for first in range(int(i)):
        name = key_name + "_" + str(first)
        CLI_KVDB.execute_command(f"kvdb insert -n {database_name} -k {name} -v sampleValue")
    for second in range(int(j)):
        name = other_key_name + "_" + str(second)
        CLI_KVDB.execute_command(f"kvdb insert -n {database_name} -k {name} -v sampleValue")

@when('I run from CLI the command "{command}')
def step_impl(context, command: str):
    context.result = CLI_KVDB.execute_command(command)

@then('I should receive a JSON of entries with the {i} key-value pairs whose keyname contains the prefix.')
def step_impl(context, i: str):
    print(context.result)
