#!/usr/bin/env python3

import argparse
import itertools
import random
import shutil
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
    elif str_type == "all":
        return random.choice([int, str, float, list, bool])


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
    return len(yaml_data["arguments"])


def is_variadic(yaml_data):
    return yaml_data["variadic"]


def get_name(yaml_data):
    return yaml_data["name"]


def get_allowed_values(yaml_data, argument_id):
    for argument in yaml_data["arguments"]:
        if argument["id"] == argument_id + 1:
            return argument.get("allowed_values", [])
    return []


def get_sources(yaml_data):
    sources = []
    for argument in yaml_data["arguments"]:
        if argument["source"]:
            sources.append(argument["source"])
    return sources


def get_types(yaml_data):
    types = []
    for argument in yaml_data["arguments"]:
        types.append(argument["type"])
    return types


def change_source(source):
    if source == "value":
        return "reference"
    elif source == "reference":
        return "value"
    else:
        return source


def change_type(type_):
    data_types = [int, float, str, list, bool]
    data_types.remove(type_)
    selected_type = random.choice(data_types)
    return selected_type


def generate_random_value(type_, allowed_values):
    if len(allowed_values) == 0:
        if type_ == int:
            return random.randint(1, 9)
        elif type_ == float:
            return random.uniform(1, 9)
        elif type_ == bool:
            return True
        elif type_ == str:
            return "".join(
                random.choice("abcdefghijklmnopqrstuvwxyz")
                for _ in range(random.randint(1, 10))
            )
        elif type_ == list:
            return [1, 23, 56, 7]
    else:
        return random.choice(allowed_values)


def generate_value(type_, allowed_values):
    return generate_random_value(type_, allowed_values)


def generate_reference(type_, allowed_values):
    global reference_counter
    reference_counter += 1
    return {
        "name": f"ref{reference_counter}",
        "value": generate_random_value(type_, allowed_values),
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


def generate_argument(type_, source, allowed_values, only_values):
    if source == "value":
        return generate_value(type_, allowed_values)
    elif source == "reference":
        return generate_reference(type_, allowed_values)
    else:
        if only_values:
            argument = generate_value(type_, allowed_values)
        else:
            argument = generate_reference(type_, allowed_values)
        return argument


def generate_specific_argument(source, type_):
    if source == "value":
        return generate_value(type_, [])
    elif source == "reference":
        return generate_reference(type_, [])


def generate_raw_template(yaml_data):
    sources = get_sources(yaml_data)
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
    combinations = generate_raw_template(yaml_data)

    expected_combinations = [
        replacement + combination[1:]
        for replacement, combination in itertools.product(
            itertools.product(allowed_values), combinations
        )
    ]

    return expected_combinations


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
    test_data = {"assets_definition": {}}
    for i in range(len(types)):  # Iterating over the number of arguments
        all_arguments = []
        new_sources = sources[
            :
        ]  # Copying the list of sources to not modify the original

        # Expected a success result if source is both
        if sources[i] == "both":
            continue

        new_source = change_source(sources[i])  # Changing the source for this argument
        new_sources[i] = new_source  # Updating the new list of sources

        # Fetching unique values allowed for the current argument
        allowed_values = get_allowed_values(yaml_data, i)
        allowed_values_index = None
        if len(allowed_values) != 0:
            allowed_values_index = i
            allowed_values = []

        # Generating the three arguments with the modified source for one in each iteration
        current_arguments = []
        for j in range(len(types)):
            if type(allowed_values_index) != None:
                if i != allowed_values_index:
                    allowed_values = get_allowed_values(yaml_data, j)

            argument = generate_argument(
                convert_string_to_type(types[j]), new_sources[j], allowed_values, True
            )
            if isinstance(argument, dict):
                current_arguments.append(f"$eventJson.{argument['name']}")
            else:
                current_arguments.append(argument)

        all_arguments.append(current_arguments)

        helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments[0])})"
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
    all_types = [str, int, float, list, bool]

    for i in range(len(types)):
        allowed_values = get_allowed_values(yaml_data, i)
        break

    if allowed_values:
        template = generate_combination_template(yaml_data, allowed_values)
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
                                generate_specific_argument("value", valid_type)
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
    types = get_types(yaml_data)
    if types.count("all") != 0:
        return
    all_types = [str, int, float, list, bool]

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
                                "value", valid_type
                            )

                            all_arguments.append(f"$eventJson.ref{index}")
                        else:
                            all_arguments.append(argument)

                    if not same_value_types(input):
                        tc.append(
                            {"input": input, "id": increase_id(), "should_pass": False}
                        )
                    helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments)})"
                all_types.append(convert_string_to_type(types[k]))

    if target_field_is_array(yaml_data):
        value = generate_specific_argument(
            "value",
            convert_string_to_type(get_target_field_type(yaml_data)),
        )
        if type(value) == list:
            target_field_value = value
        else:
            target_field_value = [value]
    else:
        target_field_value = value = generate_specific_argument(
            "value",
            convert_string_to_type(get_target_field_type(yaml_data)),
        )

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

    test_data = {"assets_definition": {}, "test_cases": []}
    normalize_list = []
    # Generate values for the target field
    values = [
        generate_specific_argument(
            "value", convert_string_to_type(get_target_field_type(yaml_data))
        )
        for _ in range(get_minimum_arguments(yaml_data))
    ]

    stage_map = {"map": []}
    helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in values)})"

    if target_field_is_array(yaml_data):
        value = generate_specific_argument(
            "value",
            change_type(convert_string_to_type(get_target_field_type(yaml_data))),
        )
        if type(value) == list:
            target_field_value = value
        else:
            target_field_value = [value]
    else:
        value = generate_specific_argument(
            "value",
            change_type(convert_string_to_type(get_target_field_type(yaml_data))),
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
    test_data["test_cases"].append({"should_pass": False, "id": increase_id()})
    test_data["description"] = "Different target field type"

    if len(test_data["assets_definition"]):
        tests["run_test"].append(test_data)


def variadic(yaml_data):
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
            convert_string_to_type(types[j]), sources[j], [], i % 2 == 0
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
    sources = get_sources(yaml_data)
    types = get_types(yaml_data)
    test_data = {"assets_definition": {}, "test_cases": []}
    normalize_list = []
    all_arguments = []

    for i in range(len(sources)):
        allowed_values = get_allowed_values(yaml_data, i)

        argument = generate_argument(
            convert_string_to_type(types[i]), sources[i], allowed_values, False
        )

        if isinstance(argument, dict):
            all_arguments.append(f"$eventJson.{argument['name']}")
        else:
            all_arguments.append(argument)

    stage_map = {"map": []}
    helper = f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments)})"

    if target_field_is_array(yaml_data):
        value = generate_specific_argument(
            "value",
            convert_string_to_type(get_target_field_type(yaml_data)),
        )
        if type(value) == list:
            target_field_value = value
        else:
            target_field_value = [value]
    else:
        value = generate_specific_argument(
            "value",
            convert_string_to_type(get_target_field_type(yaml_data)),
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
    # Generate values for the target field
    values = [
        generate_specific_argument(
            "value", convert_string_to_type(get_target_field_type(yaml_data))
        )
        for _ in range(get_minimum_arguments(yaml_data))
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

    for i, type_ in enumerate(types):
        allowed_values = get_allowed_values(yaml_data, i)
        break

    if allowed_values:
        template = generate_combination_template(yaml_data, allowed_values)
    else:
        template = generate_raw_template(yaml_data)

    for all_type in all_types:
        for case in template:
            if case.count("reference") == get_minimum_arguments(yaml_data):
                continue
            all_arguments = []
            test_data = {"assets_definition": {}, "test_cases": []}
            normalize_list = []
            for argument, type_ in zip(case, types):
                if argument == "value":
                    all_arguments.append(generate_specific_argument("value", all_type))
                else:
                    all_arguments.append(argument)

            stage_map = {"map": []}
            helper = f"{get_name(yaml_data)}({', '.join(str(v) if v is not True else 'true' for v in all_arguments)})"

            if target_field_is_array(yaml_data):
                value = generate_specific_argument(
                    "value",
                    convert_string_to_type(get_target_field_type(yaml_data)),
                )
                if type(value) == list:
                    target_field_value = value
                else:
                    target_field_value = [value]
            else:
                value = generate_specific_argument(
                    "value",
                    convert_string_to_type(get_target_field_type(yaml_data)),
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


def generate_test_cases_success_reference(yaml_data):
    types = get_types(yaml_data)
    all_types = [str, int, float, list, bool]

    for i, type_ in enumerate(types):
        allowed_values = get_allowed_values(yaml_data, i)
        break

    if allowed_values:
        template = generate_combination_template(yaml_data, allowed_values)
    else:
        template = generate_raw_template(yaml_data)

    test_data = {"assets_definition": {}, "test_cases": []}
    tc = []
    for all_type in all_types:
        input = {}
        for case in template:
            if case.count("values") == get_minimum_arguments(yaml_data):
                continue
            all_arguments = []
            normalize_list = []
            for argument, type_ in zip(case, types):
                if argument == "reference":
                    all_arguments.append(f"$eventJson.ref")
                    input[f"ref"] = generate_random_value(all_type, [])
                    tc.append({"input": input, "id": increase_id()})
                else:
                    all_arguments.append(argument)

            stage_map = {"map": []}
            helper = (
                f"{get_name(yaml_data)}({', '.join(str(v) for v in all_arguments)})"
            )

            if target_field_is_array(yaml_data):
                value = generate_specific_argument(
                    "value",
                    convert_string_to_type(get_target_field_type(yaml_data)),
                )
                if type(value) == list:
                    target_field_value = value
                else:
                    target_field_value = [value]
            else:
                value = generate_specific_argument(
                    "value",
                    convert_string_to_type(get_target_field_type(yaml_data)),
                )

                if type(value) == list:
                    target_field_value = value[0]
                else:
                    target_field_value = value

    stage_map["map"].append({"eventJson": "parse_json($event.original)"})
    stage_map["map"].append({"target_field": target_field_value})

    stage_map["map"].append({"target_field": helper})
    normalize_list.append(stage_map)

    asset_definition = {
        "name": "decoder/test/0",
        "normalize": normalize_list,
    }

    test_data["assets_definition"] = asset_definition
    test_data["test_cases"] = tc
    test_data["description"] = "Generate only valid references"

    if len(test_data["assets_definition"]):
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
        else:
            # Check if the file is a YML type
            if file_path.suffix == ".yml" or file_path.suffix == ".yaml":
                # Load the file and process it
                yaml_data = load_yaml(file_path)

                if yaml_data:
                    reset_id()

                    generate_test_cases_fail_at_buildtime(yaml_data)
                    generate_test_cases_fail_at_runtime(yaml_data)
                    generate_test_cases_success_values(yaml_data)
                    generate_test_cases_success_reference(yaml_data)

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
        generate_test_cases_success_values(yaml_data)
        generate_test_cases_success_reference(yaml_data)

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
