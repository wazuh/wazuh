#!/usr/bin/env python3

import argparse
import itertools
import json
import random
import shutil
import sys
from pathlib import Path

import yaml

tests = {"build_test": [], "run_test": []}
reference_counter = 0
maximum_number_of_arguments = 40
id_counter = 0
intup_file = ""


def parse_arguments():
    global input_file

    parser = argparse.ArgumentParser(description="Run Helpers test for Engine.")
    parser.add_argument(
        "-i",
        "--input_file",
        help="Absolute or relative path where the description of the helper function is located",
    )

    args = parser.parse_args()
    input_file = args.input_file


def reset_id():
    global id_counter
    id_counter = 0


def increase_id():
    global id_counter
    id_counter = id_counter + 1
    return id_counter


def convert_string_to_type(str_type: str):
    """
    Convert a string representation of a type to the actual type.

    Args:
        str_type (str): The string representation of the type ('integer' or 'string').

    Returns:
        type: The corresponding type.

    """
    if str_type == "integer":
        return int
    elif str_type == "string":
        return str
    elif str_type == "float":
        return float
    elif str_type == "boolean":
        return bool
    elif str_type == "object":
        return json
    elif str_type == "all":
        return random.choice([int, str, float, list, bool, json])


def load_yaml(file_path):
    """
    Loads data from a YAML file.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        dict: The parsed YAML data.

    """
    with open(file_path, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)


def get_minimum_arguments(yaml_data):
    if "arguments" in yaml_data:
        return len(yaml_data["arguments"])
    return 0


def is_variadic(yaml_data):
    return yaml_data["variadic"]


def get_name(yaml_data):
    return yaml_data["name"]


def get_allowed_values(yaml_data, argument_id):
    allowed_values = {}
    if get_minimum_arguments(yaml_data) != 0:
        for index, argument in enumerate(yaml_data["arguments"].items()):
            if "allowed_values" in argument[1]:
                if index not in allowed_values:
                    allowed_values[index] = []
                allowed_values[index].append(argument[1]["allowed_values"])
    return allowed_values


def get_sources(yaml_data):
    sources = []
    if get_minimum_arguments(yaml_data) != 0:
        for argument in yaml_data["arguments"].values():
            if argument["source"]:
                sources.append(argument["source"])
    return sources


def get_types(yaml_data):
    types = []
    if get_minimum_arguments(yaml_data) != 0:
        for argument in yaml_data["arguments"].values():
            types.append(argument["type"])
    return types


def change_source(source):
    if source == "value":
        return "reference"
    elif source == "reference":
        return "value"
    else:
        return source


def get_is_array(yaml_data):
    is_array = []
    if get_minimum_arguments(yaml_data) != 0:
        if 0 < len(yaml_data["arguments"]):
            for argument in yaml_data["arguments"].values():
                if "is_array" in argument:
                    is_array.append(argument["is_array"])
                else:
                    is_array.append(False)
    return is_array


def change_type(type_):
    data_types = [int, float, str, list, bool, json]
    data_types.remove(type_)
    selected_type = random.choice(data_types)
    return selected_type


def generate_random_value(type_, allowed_values, is_array):
    if not allowed_values:
        if type_ == int:
            if is_array:
                return [random.randint(1, 9)]
            return random.randint(1, 9)
        elif type_ == float:
            if is_array:
                return [random.uniform(1, 9)]
            return random.uniform(1, 9)
        elif type_ == bool:
            if is_array:
                return [True]
            return True
        elif type_ == str:
            if is_array:
                return [
                    "".join(
                        random.choice("abcdefghijklmnopqrstuvwxyz")
                        for _ in range(random.randint(1, 10))
                    )
                ]
            return "".join(
                random.choice("abcdefghijklmnopqrstuvwxyz")
                for _ in range(random.randint(1, 10))
            )
        elif type_ == json:
            if is_array:
                json.dumps([{"key": "value"}])
            return json.dumps({"key": "value"})
        elif type_ == list:
            return [1, 23, 56, 7]
    else:
        return random.choice(allowed_values)


def generate_value(type_, allowed_values, is_array):
    return generate_random_value(type_, allowed_values, is_array)


def generate_reference(type_, allowed_values, is_array):
    global reference_counter
    reference_counter += 1
    return {
        "name": f"ref{reference_counter}",
        "value": generate_random_value(type_, allowed_values, is_array),
    }


def get_target_field_type(yaml_data):
    return yaml_data["target_field"]["type"]


def target_field_is_array(yaml_data):
    return yaml_data["target_field"]["is_array"] == True


def generate_specif_reference(value):
    global reference_counter
    reference_counter += 1
    return {
        "name": f"ref{reference_counter}",
        "value": value,
    }


def generate_argument(type_, source, is_array, allowed_values, only_values):
    if source == "value":
        return generate_value(type_, allowed_values, is_array)
    elif source == "reference":
        return generate_reference(type_, allowed_values, is_array)
    else:
        if only_values:
            argument = generate_value(type_, allowed_values, False)
        else:
            argument = generate_reference(type_, allowed_values, False)
        return argument


def generate_specific_argument(source, type_, is_array):
    if source == "value":
        return generate_value(type_, [], is_array)
    elif source == "reference":
        return generate_reference(type_, [], is_array)


def generate_raw_template(yaml_data, my_sources=[]):
    sources = []
    if not my_sources:
        sources = get_sources(yaml_data)
    else:
        sources = my_sources
    sources_expanded = []
    for source in sources:
        if source == "both":
            sources_expanded.append(["value", "reference"])
        else:
            sources_expanded.append(source)

    # If an element is a list, we treat it as a single element
    data_processed = [x if isinstance(x, list) else [x] for x in sources_expanded]

    # Generate all possible combinations
    combinations = list(itertools.product(*data_processed))
    return combinations


def generate_combination_template(yaml_data, allowed_values):
    # Supongo que generate_raw_template está definida en alguna parte del código.
    combinations = generate_raw_template(yaml_data)

    # Generar las combinaciones para cada argumento con sus valores permitidos.
    expanded_combinations = []

    for combination in combinations:
        # Inicializar con la combinación base.
        new_combinations = [list(combination)]

        for arg_index, values in allowed_values.items():
            temp_combinations = []

            for combo in new_combinations:
                for value in values:
                    new_combo = combo[:]
                    new_combo[arg_index] = value[0]
                    temp_combinations.append(new_combo)

            new_combinations = temp_combinations

        expanded_combinations.extend(new_combinations)

    # Convertir de nuevo a tuplas si es necesario.
    expanded_combinations = [tuple(combo) for combo in expanded_combinations]

    return expanded_combinations


def fewer_arguments_than_the_minimum_required(yaml_data):
    minimum_arguments = get_minimum_arguments(yaml_data)
    # Generate test cases with argument count ranging from 0 to minimum_arguments
    for num_arguments in range(minimum_arguments):
        test_data = {"assets_definition": {}, "should_pass": False, "description": ""}
        parameters = [
            "0"
        ] * num_arguments  # Generate empty strings for the current number of arguments
        helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in parameters)})"
        normalize_list = [{"map": [{"target_field": helper}]}]
        asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

        test_data["assets_definition"] = asset_definition
        test_data["should_pass"] = False
        test_data["description"] = f"Test with fewer parameters for helper function."
        test_data["id"] = increase_id()
        tests["build_test"].append(test_data)


def different_sources(yaml_data):
    sources = get_sources(yaml_data)
    types = get_types(yaml_data)
    is_array = get_is_array(yaml_data)

    for i in range(len(types)):  # Iterating over the number of arguments
        test_data = {"assets_definition": {}}
        new_sources = sources[
            :
        ]  # Copying the list of sources to not modify the original

        # Expected a success result if source is both
        if sources[i] == "both":
            continue

        new_source = change_source(sources[i])  # Changing the source for this argument
        new_sources[i] = new_source  # Updating the new list of sources

        # Fetching unique values allowed for the current argument
        all_allowed_values = get_allowed_values(yaml_data, i)
        allowed_values = None

        # Generating the three arguments with the modified source for one in each iteration
        current_arguments = []
        for j in range(len(types)):
            if j in all_allowed_values:
                allowed_values = all_allowed_values[j][0]

            argument = generate_argument(
                convert_string_to_type(types[j]), new_sources[j], is_array[j], allowed_values, True
            )
            if isinstance(argument, dict):
                current_arguments.append(f"$eventJson.{argument['name']}")
            else:
                current_arguments.append(json.dumps(argument))

        helper = (
            f"{get_name(yaml_data)}({', '.join(str(v) for v in current_arguments)})"
        )
        normalize_list = [{"map": {"target_field": helper}}]

        asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}
        test_data["assets_definition"] = asset_definition
        test_data["should_pass"] = False
        test_data["description"] = "Generate sources other than those allowed"
        test_data["id"] = increase_id()

        if len(test_data["assets_definition"]):
            tests["build_test"].append(test_data)


def filter_invalid_arguments(values):
    type_counts = {}
    for value in values:
        value_type = type(value)
        if value_type in type_counts:
            type_counts[value_type] += 1
        else:
            type_counts[value_type] = 1
    for count in type_counts.values():
        if count > 1:
            return False
    return True


def different_types_values(yaml_data):
    types = get_types(yaml_data)
    if types.count("all") != 0:
        return

    is_array = get_is_array(yaml_data)
    all_types = [str, int, float, list, bool]

    all_allowed_values = get_allowed_values(yaml_data, 0)

    if all_allowed_values:
        template = generate_combination_template(yaml_data, all_allowed_values)
    else:
        template = generate_raw_template(yaml_data)

    for case in template:
        if case.count("reference") == 0:
            for k in range(case.count("value")):
                all_types.remove(convert_string_to_type(types[k]))
                for all_type in all_types:
                    test_data = {
                        "assets_definition": {},
                        "should_pass": False,
                        "description": "",
                    }
                    all_arguments = []
                    for index, (argument, type_) in enumerate(zip(case, types)):
                        if argument == "value":
                            valid_type = convert_string_to_type(type_)
                            if k == index:
                                valid_type = all_type
                            all_arguments.append(
                                generate_specific_argument("value", valid_type, is_array[index])
                            )
                        else:
                            all_arguments.append(argument)

                    if filter_invalid_arguments(all_arguments):
                        helper = f"{get_name(yaml_data)}({', '.join(str(v) if v is not True else 'true' for v in all_arguments)})"
                        normalize_list = [{"map": [{"target_field": helper}]}]

                        asset_definition = {
                            "name": "decoder/test/0",
                            "normalize": normalize_list,
                        }

                        test_data["assets_definition"] = asset_definition
                        test_data["should_pass"] = False
                        test_data["id"] = increase_id()
                        test_data["description"] = (
                            f"Generate types other than those allowed for the source 'value'"
                        )

                        if len(test_data["assets_definition"]):
                            tests["build_test"].append(test_data)

                all_types.append(convert_string_to_type(types[k]))


def same_value_types(dictionary):
    if len(dictionary) < 1:
        return True
    value_types = set(type(value) for value in dictionary.values())
    return len(value_types) > 1


def different_types_references(yaml_data):
    if "reference" not in get_sources(yaml_data):
        return

    helper = None
    types = get_types(yaml_data)
    if types.count("all") != 0:
        return

    is_array = get_is_array(yaml_data)
    all_types = [str, int, float, list, bool, json]

    for i in range(len(types)):
        allowed_values = get_allowed_values(yaml_data, i)
        break

    if allowed_values:
        template = generate_combination_template(yaml_data, allowed_values)
    else:
        template = generate_raw_template(yaml_data)

    for case in template:
        if case.count("value") == 0:
            tc = []
            for k in range(case.count("reference")):
                if convert_string_to_type(types[k]) == str:
                    # all_types.remove(json)
                    all_types.remove(str)
                else:
                    all_types.remove(convert_string_to_type(types[k]))
                for all_type in all_types:
                    test_data = {
                        "assets_definition": {},
                        "test_cases": [],
                        "description": "",
                    }
                    all_arguments = []
                    input = {}
                    for index, (argument, type_) in enumerate(zip(case, types)):
                        if argument == "reference":
                            valid_type = convert_string_to_type(type_)
                            if k == index:
                                valid_type = all_type

                            input[f"ref{index}"] = generate_specific_argument(
                                "value", valid_type, is_array[index]
                            )

                            all_arguments.append(f"$eventJson.ref{index}")
                        else:
                            all_arguments.append(json.dumps(argument))

                    if not same_value_types(input):
                        tc.append(
                            {"input": input, "id": increase_id()}
                        )
                    helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments)})"
                all_types.append(convert_string_to_type(types[k]))

    if target_field_is_array(yaml_data):
        value = generate_specific_argument(
            "value",
            convert_string_to_type(get_target_field_type(yaml_data)),
            False
        )
        if type(value) == list:
            target_field_value = value
        else:
            target_field_value = [value]
    else:
        target_field_value = value = generate_specific_argument(
            "value",
            convert_string_to_type(get_target_field_type(yaml_data)),
            False
        )

    if helper:
        stage_map = {"map": []}
        normalize_list = []
        stage_map["map"].append({"eventJson": "parse_json($event.original)"})
        stage_map["map"].append({"target_field": target_field_value})
        stage_map["map"].append({"target_field": helper})

        normalize_list.append(stage_map)

        asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

        test_data["assets_definition"] = asset_definition
        test_data["test_cases"] = tc
        test_data["description"] = (
            f"Generate types other than those allowed for the source 'reference'"
        )

        if len(test_data["assets_definition"]):
            tests["run_test"].append(test_data)


def different_target_field_type(yaml_data):
    if get_target_field_type(yaml_data) == "all":
        return

    is_array = get_is_array(yaml_data)
    test_data = {
        "assets_definition": {},
        "test_cases": [],
        "description": "",
    }
    normalize_list = []
    tc = []
    input = {}
    # Generate values for the target field
    all_arguments = []
    values = None
    all_allowed_values = get_allowed_values(yaml_data, 0)
    allowed_values = None
    i = 0

    for type_, source in zip(get_types(yaml_data), get_sources(yaml_data)):
        if source == "value":
            if i in all_allowed_values:
                allowed_values = all_allowed_values[i][0]
            argument = json.dumps(generate_argument(convert_string_to_type(
                get_types(yaml_data)[0]), "value", is_array[i], allowed_values, True))
            all_arguments.append(argument)
        elif source == "reference":
            values = generate_specific_argument(
                "reference", convert_string_to_type(get_types(yaml_data)[0]),
                is_array[i]
            )
            all_arguments.append(f"$eventJson.{values['name']}")
            input[values["name"]] = values["value"]
            tc.append({"input": input, "id": increase_id()})
        else:
            values = generate_specific_argument(
                "value", convert_string_to_type(get_types(yaml_data)[0]), is_array[i]
            )
            if isinstance(values, list):
                values = json.dumps(values)
            all_arguments.append(values)
        i = i + 1

    stage_map = {"map": []}
    helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments)})"

    if target_field_is_array(yaml_data):
        value = generate_specific_argument(
            "value",
            change_type(convert_string_to_type(get_target_field_type(yaml_data))),
            False
        )
        if type(value) == list:
            target_field_value = value
        else:
            target_field_value = [value]
    else:
        value = generate_specific_argument(
            "value",
            change_type(convert_string_to_type(get_target_field_type(yaml_data))),
            False
        )

        if type(value) == list:
            target_field_value = value[0]
        else:
            target_field_value = value

    stage_map["map"].append({"target_field": target_field_value})
    stage_map["map"].append({"target_field": helper})

    normalize_list.append(stage_map)

    # Create the new test case
    asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

    test_data["assets_definition"] = asset_definition
    if tc:
        test_data["test_cases"] = tc
    else:
        test_data["test_cases"].append({"id": increase_id()})
    test_data["description"] = "Different target field type"

    if len(test_data["assets_definition"]):
        tests["run_test"].append(test_data)


def variadic(yaml_data):
    if get_minimum_arguments(yaml_data) == 0:
        return

    sources = get_sources(yaml_data)
    types = get_types(yaml_data)
    all_arguments = []
    test_data = {"assets_definition": {}}

    if is_variadic(yaml_data):
        number_of_arguments = maximum_number_of_arguments + 1
    else:
        number_of_arguments = get_minimum_arguments(yaml_data) + 1

    for i in range(number_of_arguments):
        j = i % get_minimum_arguments(yaml_data)
        argument = generate_argument(
            convert_string_to_type(types[j]), sources[j], False, [], i % 2 == 0
        )

        if isinstance(argument, dict):
            all_arguments.append(f"$eventJson.{argument['name']}")
        else:
            all_arguments.append(argument)

    helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments)})"

    normalize_list = [{"target_field": helper}]

    asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

    test_data["assets_definition"] = asset_definition
    test_data["should_pass"] = False
    test_data["description"] = "Generate more arguments than the maximum allowed"
    test_data["id"] = increase_id()

    if len(test_data["assets_definition"]):
        tests["build_test"].append(test_data)


def reference_not_exist(yaml_data):
    if all(source == "value" for source in get_sources(yaml_data)):
        return
    sources = get_sources(yaml_data)
    types = get_types(yaml_data)
    is_array = get_is_array(yaml_data)
    test_data = {"assets_definition": {}, "test_cases": []}
    normalize_list = []
    all_arguments = []
    # Fetching unique values allowed for the current argument
    all_allowed_values = get_allowed_values(yaml_data, 0)
    allowed_values = None

    for i in range(len(sources)):
        if i in all_allowed_values:
            allowed_values = all_allowed_values[i][0]

        argument = generate_argument(
            convert_string_to_type(types[i]), sources[i], is_array[i], allowed_values, False
        )

        if isinstance(argument, dict):
            all_arguments.append(f"$eventJson.{argument['name']}")
        else:
            all_arguments.append(json.dumps(argument))

    stage_map = {"map": []}
    helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments)})"

    if target_field_is_array(yaml_data):
        value = generate_specific_argument(
            "value",
            convert_string_to_type(get_target_field_type(yaml_data)), False
        )
        if type(value) == list:
            target_field_value = value
        else:
            target_field_value = [value]
    else:
        value = generate_specific_argument(
            "value",
            convert_string_to_type(get_target_field_type(yaml_data)), False
        )

        if type(value) == list:
            target_field_value = value[0]
        else:
            target_field_value = value

    stage_map["map"].append({"target_field": target_field_value})
    stage_map["map"].append({"target_field": helper})
    normalize_list.append(stage_map)

    asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

    test_data["assets_definition"] = asset_definition
    test_data["test_cases"].append({"should_pass": False, "id": increase_id()})
    test_data["description"] = "Generate arguments with references that do not exist"

    if len(test_data["assets_definition"]):
        tests["run_test"].append(test_data)


def target_field_not_exist(yaml_data):
    test_data = {"assets_definition": {}, "test_cases": []}
    is_array = get_is_array(yaml_data)
    # Generate values for the target field
    values = [
        generate_specific_argument(
            "value", convert_string_to_type(get_target_field_type(yaml_data)), is_array[i]
        )
        for i in range(get_minimum_arguments(yaml_data))
    ]

    # Prepare normalization list for the test case
    normalize_list = [
        {
            "map": [
                {
                    "target_field": f"{get_name(yaml_data)}({', '.join(str(v) for v in values)})"
                }
            ]
        }
    ]

    # Create the new test case
    asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

    test_data["assets_definition"] = asset_definition
    test_data["test_cases"].append({"should_pass": False, "id": increase_id()})
    test_data["description"] = "Target field not exist"

    if len(test_data["assets_definition"]):
        tests["run_test"].append(test_data)


def generate_test_cases_fail_at_buildtime(yaml_data):
    fewer_arguments_than_the_minimum_required(yaml_data)
    variadic(yaml_data)
    different_sources(yaml_data)
    different_types_values(yaml_data)


def generate_test_cases_fail_at_runtime(yaml_data):
    reference_not_exist(yaml_data)
    different_types_references(yaml_data)
    # target_field_not_exist(yaml_data)
    different_target_field_type(yaml_data)


def generate_test_cases_success_values(yaml_data):
    types = get_types(yaml_data)
    all_types = [str, int, float, list, bool]
    is_array = get_is_array(yaml_data)
    for i, type_ in enumerate(types):
        allowed_values = get_allowed_values(yaml_data, i)
        break

    if allowed_values:
        template = generate_combination_template(yaml_data, allowed_values)
    else:
        template = generate_raw_template(yaml_data)

    for case in template:
        if case.count("reference") == get_minimum_arguments(yaml_data):
            continue
        all_arguments = []
        indx = 0
        for argument, type_ in zip(case, types):
            if type_ == "all":
                for all_type in all_types:
                    if argument == "value":
                        all_arguments.append(
                            generate_specific_argument("value", all_type, is_array[indx])
                        )
                    else:
                        all_arguments.append(argument)
            else:
                if argument == "value":
                    all_arguments.append(
                        generate_specific_argument(
                            "value", convert_string_to_type(type_),
                            is_array[indx]
                        )
                    )
                elif argument == "reference":
                    reference = generate_specific_argument(
                        "reference", convert_string_to_type(type_),
                        is_array[indx]
                    )
                    all_arguments.append(f"$eventJson.{reference['name']}")
                else:
                    all_arguments.append(argument)
            indx = indx + 1

        for index, argument in enumerate(all_arguments):
            test_data = {"assets_definition": {}}
            normalize_list = []
            stage_map = {"map": []}
            if "all" in get_types(yaml_data):
                if argument is True:
                    argument = "true"
                helper = f"{get_name(yaml_data)}({argument})"
            else:
                helper = (
                    f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments)})"
                )

            if target_field_is_array(yaml_data):
                value = generate_specific_argument(
                    "value",
                    convert_string_to_type(get_target_field_type(yaml_data)),
                    is_array[index]
                )
                if type(value) == list:
                    target_field_value = value
                else:
                    target_field_value = [value]
            else:
                value = generate_specific_argument(
                    "value",
                    convert_string_to_type(get_target_field_type(yaml_data)),
                    is_array[index]
                )

                if type(value) == list:
                    target_field_value = value[0]
                else:
                    target_field_value = value

            stage_map["map"].append({"target_field": target_field_value})
            stage_map["map"].append({"target_field": helper})
            normalize_list.append(stage_map)

            asset_definition = {
                "name": "decoder/test/0",
                "normalize": normalize_list,
            }

            test_data["assets_definition"] = asset_definition
            test_data["description"] = "Generate only valid values"
            test_data["id"] = increase_id()
            test_data["should_pass"] = True

            if len(test_data["assets_definition"]):
                tests["build_test"].append(test_data)

            if "all" not in get_types(yaml_data):
                break


def generate_test_cases_success(yaml_data):
    if get_minimum_arguments(yaml_data) == 0:
        return

    types = get_types(yaml_data)
    is_array = get_is_array(yaml_data)
    all_allowed_values = get_allowed_values(yaml_data, 0)

    if all_allowed_values:
        template = generate_combination_template(yaml_data, all_allowed_values)
    else:
        template = generate_raw_template(yaml_data)

    for case in template:
        all_arguments = []
        input = {}
        new_test = {}
        test_data = {"assets_definition": {}, "test_cases": [], "description": ""}
        indx = 0
        for argument, type_ in zip(case, types):
            if argument == "value":
                value = generate_specific_argument(
                    "value", convert_string_to_type(type_), is_array[indx])
                if isinstance(value, list):
                    value = json.dumps(value)
                all_arguments.append(value)
            elif argument == "reference":
                reference = generate_specific_argument(
                    "reference", convert_string_to_type(type_), is_array[indx]
                )
                all_arguments.append(f"$eventJson.{reference['name']}")
                input[reference["name"]] = reference["value"]
            else:
                all_arguments.append(json.dumps(argument))
            indx = indx + 1

        helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments)})"

        if target_field_is_array(yaml_data):
            value = generate_specific_argument(
                "value",
                convert_string_to_type(get_target_field_type(yaml_data)),
                False
            )
            if type(value) == list:
                target_field_value = value
            else:
                target_field_value = [value]
        else:
            value = generate_specific_argument(
                "value",
                convert_string_to_type(get_target_field_type(yaml_data)),
                False
            )

            if type(value) == list:
                target_field_value = value[0]
            else:
                target_field_value = value

        if not input:
            normalize_list = [{"map": [{"target_field": target_field_value}, {"target_field": helper}]}]
        else:
            normalize_list = [
                {
                    "map": [
                        {"eventJson": "parse_json($event.original)"},
                        {"target_field": target_field_value},
                        {"target_field": helper},
                    ]
                }
            ]

        asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}
        test_data["assets_definition"] = asset_definition

        test_data["should_pass"] = True
        test_data["id"] = increase_id()

        test_data["description"] = "Generate valid arguments"

        tests["build_test"].append(test_data)


def format_argument(v):
    if isinstance(v, str):
        if v.strip() == "":
            return f'"{v}"'
        if v.startswith("$"):
            return str(v)
        if len(v.split(" ")) > 1:
            return f'"{v}"'
    return json.dumps(v)


def generate_unit_test(yaml_data):
    if "test" not in yaml_data:
        return

    global reference_counter
    template = None

    sources = get_sources(yaml_data)
    template = generate_raw_template(yaml_data)

    for number_test, test in enumerate(yaml_data["test"]):
        arguments_list = list(test["arguments"].items())

        # Check variadic
        if not is_variadic(yaml_data):
            if get_minimum_arguments(yaml_data) + 1 < len(arguments_list):
                print(
                    f"Helper {get_name(yaml_data)} has an error in test number '{number_test + 1}': it is not a variadic function"
                )
                sys.exit(1)

        if get_minimum_arguments(yaml_data) + 1 < len(arguments_list):
            diff = len(arguments_list) - 1 - get_minimum_arguments(yaml_data)
            for _ in range(diff):
                sources.append(sources[-1])
            template = generate_raw_template(yaml_data, sources)

        for case in template:
            all_arguments = []
            normalize_list = []
            stage_map = {"map": []}
            input = {}
            new_test = {}
            test_data = {"assets_definition": {}, "test_cases": [], "description": ""}
            if not any(isinstance(item[1], dict) and ("source" in item[1]) for item in arguments_list):
                combined = list(itertools.zip_longest(arguments_list, case, fillvalue=None))
                for (id, value), source in combined:
                    target_field_value = None

                    if source == "value":
                        all_arguments.append(value)
                    elif source == "reference":
                        reference_counter = reference_counter + 1
                        reference = {"name": f"ref{reference_counter}", "value": value}
                        input[reference["name"]] = reference["value"]
                        all_arguments.append(f"$eventJson.{reference['name']}")
                    else:
                        if isinstance(value, list):
                            target_field_value = list(value)
                        else:
                            target_field_value = value

                helper = f"{get_name(yaml_data)}({', '.join(format_argument(v) for v in all_arguments)})"

                if not input:
                    stage_map["map"].append({"target_field": target_field_value})
                    stage_map["map"].append({"target_field": helper})
                    normalize_list.append(stage_map)
                else:
                    stage_map["map"].append({"target_field": target_field_value})
                    stage_map["map"].append({"target_field": helper})
                    normalize_list.append(stage_map)
                    normalize_list = [
                        {
                            "map": [
                                {"eventJson": "parse_json($event.original)"},
                                {"target_field": target_field_value},
                                {"target_field": helper},
                            ]
                        }
                    ]
                    new_test = {
                        "input": input,
                        "id": increase_id(),
                        "should_pass": test["should_pass"],
                        "expected": test.get("expected", None),
                    }

                asset_definition = {
                    "name": "decoder/test/0",
                    "normalize": normalize_list,
                }
                test_data["assets_definition"] = asset_definition

                if new_test:
                    test_data["test_cases"].append(new_test)
                else:
                    test_data["should_pass"] = test["should_pass"]
                    test_data["id"] = increase_id()
                    test_data["expected"] = test["expected"]

                test_data["description"] = test["description"]

                if len(test_data["test_cases"]) == 0:
                    del test_data["test_cases"]

                tests["run_test"].append(test_data)

    for test in yaml_data["test"]:
        arguments_list = list(test["arguments"].items())
        if any(isinstance(item[1], dict) for item in arguments_list):
            all_arguments = []
            normalize_list = []
            stage_map = {"map": []}
            input = {}
            new_test = {}
            test_data = {"assets_definition": {}, "test_cases": [], "description": ""}
            for id, data in arguments_list:
                if isinstance(data, dict) and "source" in data:
                    if data["source"] == "value":
                        all_arguments.append(data["value"])
                    elif data["source"] == "reference":
                        reference_counter = reference_counter + 1
                        reference = {"name": f"ref{reference_counter}", "value": data["value"]}
                        if data["value"] is not None:
                            input[reference["name"]] = reference["value"]
                        all_arguments.append(f"$eventJson.{reference['name']}")
                else:
                    if isinstance(data, list):
                        target_field_value = list(data)
                    else:
                        target_field_value = data

            if len(all_arguments) == 0:
                break
            helper = f"{get_name(yaml_data)}({', '.join(format_argument(v) for v in all_arguments)})"

            if not input:
                stage_map["map"].append({"target_field": target_field_value})
                stage_map["map"].append({"target_field": helper})
                normalize_list.append(stage_map)
            else:
                stage_map["map"].append({"target_field": target_field_value})
                stage_map["map"].append({"target_field": helper})
                normalize_list.append(stage_map)
                normalize_list = [
                    {
                        "map": [
                            {"eventJson": "parse_json($event.original)"},
                            {"target_field": target_field_value},
                            {"target_field": helper},
                        ]
                    }
                ]
                new_test = {
                    "input": input,
                    "id": increase_id(),
                    "should_pass": test["should_pass"],
                    "expected": test.get("expected", False),
                }

            asset_definition = {
                "name": "decoder/test/0",
                "normalize": normalize_list,
            }
            test_data["assets_definition"] = asset_definition

            if new_test:
                test_data["test_cases"].append(new_test)
            else:
                test_data["should_pass"] = test["should_pass"]
                test_data["id"] = increase_id()
                test_data["expected"] = test.get("expected", None)

            test_data["description"] = test["description"]

            if len(test_data["test_cases"]) == 0:
                del test_data["test_cases"]

            tests["run_test"].append(test_data)


def main():
    parse_arguments()
    global input_file
    if input_file:
        input_file = Path(input_file)

    # Get the directory where the script is located
    script_dir = Path(__file__).resolve().parent
    yaml_data = None

    # Define the path to the output directory
    output_dir = script_dir / "outputs"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Clean the output directory after processing all files
    for item in output_dir.iterdir():
        if item.is_file() or item.is_symlink():
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)

    # Loop through the files in the directory
    for file_path in script_dir.iterdir():
        if input_file:
            # If input_file is relative, convert it to absolute
            if not input_file.is_absolute():
                input_file = input_file.resolve()
            if input_file == file_path:
                yaml_data = load_yaml(file_path)
                break
        else:
            # Check if the file is a YML type
            if file_path.suffix == ".yml" or file_path.suffix == ".yaml":
                # Load the file and process it
                yaml_data = load_yaml(file_path)

                if yaml_data:
                    reset_id()

                    generate_test_cases_fail_at_buildtime(yaml_data)
                    generate_test_cases_fail_at_runtime(yaml_data)
                    generate_test_cases_success(yaml_data)
                    generate_unit_test(yaml_data)

                    # Save results in YAML file
                    # Define the path to the output directory
                    output_dir = script_dir / "outputs"
                    output_dir.mkdir(
                        parents=True, exist_ok=True
                    )  # Create the "outputs" directory if it doesn't exist

                    # Define the output file path
                    output_file_path = output_dir / f"{get_name(yaml_data)}.yml"
                    tests["helper_type"] = "transformation"
                    with open(output_file_path, "w") as file:
                        yaml.dump(tests, file)

                    tests["build_test"].clear()
                    tests["run_test"].clear()

    if yaml_data:
        reset_id()

        generate_test_cases_fail_at_buildtime(yaml_data)
        generate_test_cases_fail_at_runtime(yaml_data)
        generate_test_cases_success(yaml_data)
        generate_unit_test(yaml_data)

        # Save results in YAML file
        # Define the path to the output directory
        output_dir = script_dir / "outputs"
        output_dir.mkdir(
            parents=True, exist_ok=True
        )  # Create the "outputs" directory if it doesn't exist

        # Define the output file path
        output_file_path = output_dir / f"{get_name(yaml_data)}.yml"
        tests["helper_type"] = "transformation"
        with open(output_file_path, "w") as file:
            yaml.dump(tests, file)

        tests["build_test"].clear()
        tests["run_test"].clear()
    else:
        print(f"File '{input_file}' not exist")


if __name__ == "__main__":
    main()