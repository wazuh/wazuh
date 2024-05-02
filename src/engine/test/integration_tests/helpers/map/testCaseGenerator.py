import itertools
import random
from pathlib import Path

import yaml


def generate_value(value_type: type, is_valid=True):
    """
    Generates a random value of the specified type.

    Args:
        value_type (type): The type of value to generate (int, float, str).
        is_valid (bool, optional): Indicates whether the generated value should be valid or not.
            Defaults to True.

    Returns:
        int, float, or str: A randomly generated value of the specified type.

    Raises:
        ValueError: If an invalid value_type is provided.

    Example:
        >>> generate_value(int)
        5
        >>> generate_value(float)
        3.142
        >>> generate_value(str)
        'abcdef'

    """
    if is_valid:
        if value_type == int:
            return random.randint(0, 9)
        elif value_type == str:
            return "".join(
                random.choice("abcdefghijklmnopqrstuvwxyz")
                for _ in range(random.randint(1, 10))
            )
    else:
        data_types = [int, float, str]
        data_types.remove(value_type)
        selected_type = random.choice(data_types)

        if selected_type == int:
            return random.randint(0, 9)
        elif selected_type == float:
            return random.uniform(0, 9)
        elif selected_type == str:
            return "".join(
                random.choice("abcdefghijklmnopqrstuvwxyz")
                for _ in range(random.randint(1, 10))
            )


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


def process_yaml_data(spec):
    """
    Processes YAML data and extracts relevant information.

    Args:
        spec (dict): The YAML data.

    Returns:
        tuple: A tuple containing variadic, name, min_args, parameters, special_parameters, sources, types, and only_values.

    """
    variadic = spec.get("variadic")
    name = spec.get("name")
    min_args = spec.get("minimum_arguments")
    special_parameters = []
    sources = []
    only_values = None

    def special_cases():
        nonlocal special_parameters
        special_cases = spec.get("special_cases", [])
        for case in special_cases:
            special_parameters.append(case["arguments"])

    special_cases()

    if "arguments" in spec:
        for i, argument in enumerate(spec["arguments"]):
            local_source = []
            if argument.get("sources", []) == "both":
                local_source.append("reference")
                local_source.append("value")
            else:
                local_source.append(argument.get("sources", []))
            sources.append(local_source)
            if "only_values" in argument:
                only_values = argument["only_values"]
    else:
        print("No argument specifications found in the YAML file.")

    return variadic, name, min_args, special_parameters, sources, only_values


def generate_operations(repeat, operations=None):
    """
    Generate combinations of operations and value sources.

    Args:
        repeat (int): Number of repetitions for the value sources.
        operations (list, optional): List of operations to include in the combinations.
            Defaults to None.

    Returns:
        list: List of generated combinations of operations and value sources.
    """
    results = []
    value_combinations = list(itertools.product(["reference", "value"], repeat=repeat))
    if operations is not None:
        operation_combination = {operation: False for operation in operations}
        for operation in operations:
            for combo in value_combinations:
                if len(set(combo)) == 1 or (
                    combo[0] != combo[1] and not operation_combination[operation]
                ):
                    results.append((operation,) + combo)
                    if combo[0] != combo[1]:
                        operation_combination[operation] = True
    else:
        for combo in value_combinations:
            results.append(combo)
    return results


def generate_different_value(value):
    """
    Generate a value different from the provided value.

    Args:
        value (list): A list containing the original value.

    Returns:
        int, float, or str: A randomly generated value of the same type as the original value but different.

    """
    new_value = generate_value(type(value[0]))
    while new_value in value:
        new_value = generate_value(type(value[0]))
    return new_value


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


def generate_test_with_fewer_parameters_than_min_args(name, min_args, new_tests):
    """
    Generate a test with fewer parameters than the specified minimum arguments.

    Args:
        min_args (int): The minimum number of arguments required.
        name (str): The name of the function being tested.
        new_tests (list): List to which the generated test will be appended.

    Returns:
        None

    """
    few_parameters = ["0"] * (min_args - 1)
    normalize_list = []
    normalize_list.append({"map": [{"helper": f"{name}({', '.join(few_parameters)})"}]})
    new_test = {
        "helper": f"{name}({', '.join(few_parameters)})",
        "fail": "buildtime",
        "asset_definition": {"normalize": normalize_list},
        "description": "Test with fewer parameters than the minimum required arguments.",
    }
    new_tests.append(new_test)


def generate_test_with_value_not_allowed(
    name, min_args, last_argument, only_values, new_tests
):
    """
    Generate test cases with values not allowed by only_values.

    Returns:
        None

    """
    test_cases = []
    normalize_list = []
    params = []
    if only_values is not None:
        params.append(generate_different_value(only_values))

        if len(params) < min_args:
            diff = min_args - len(params)
            for _ in range(diff):
                params.append(
                    generate_value(
                        convert_string_to_type(last_argument[0].get("type", []))
                    )
                )

        normalize_list = {
            "map": [{"helper": f"{name}({', '.join(map(repr, params))})"}]
        }
        asset = {"name": "decoder/test/0", "normalize": normalize_list}
        test_cases.append(
            {"asset_definition": asset, "expected": {"fail": "buildtime"}}
        )
        new_test = {
            "test_cases": test_cases,
            "description": "Test cases with values not allowed by only_values.",
        }
        new_tests.append(new_test)


def generate_test_with_different_sources(name, min_args, sources, arguments, new_tests):
    """
    Generate test cases with different sources.

    Returns:
        None

    """
    test_cases = []
    params = {}
    normalize_list = []
    values = []
    counter_reference = 0
    for i, source in enumerate(sources):
        if len(source) == 2:
            counter_reference += 1
            values.append(f"$_eventJson.ref_{counter_reference}")
            params[f"ref_{counter_reference}"] = generate_value(
                convert_string_to_type(arguments[i]["type"])
            )
        else:
            if source[0] == "value":
                counter_reference += 1
                values.append(f"$_eventJson.ref_{counter_reference}")
                params[f"ref_{counter_reference}"] = generate_value(
                    convert_string_to_type(arguments[i]["type"])
                )
            else:
                values.append(
                    generate_value(convert_string_to_type(arguments[i]["type"]))
                )

    argument = arguments[-1:]
    if len(params) < min_args:
        diff = min_args - len(values)
        for _ in range(diff):
            source = argument[0].get("source", [])
            if len(source) == 2:
                counter_reference += 1
                values.append(f"$_eventJson.ref_{counter_reference}")
                params[f"ref_{counter_reference}"] = generate_value(
                    convert_string_to_type(arguments[i]["type"])
                )
            else:
                if source == "value":
                    counter_reference += 1
                    values.append(f"$_eventJson.ref_{counter_reference}")
                    params[f"ref_{counter_reference}"] = generate_value(
                        convert_string_to_type(arguments[i]["type"])
                    )
                else:
                    values.append(
                        generate_value(convert_string_to_type(arguments[i]["type"]))
                    )

    if len(params) == 0:
        normalize_list.append(
            {"map": [{"helper": f"{name}({', '.join(map(repr, values))})"}]}
        )
    else:
        normalize_list.append({"map": [{"_eventJson": "parse_json($event.original)"}]})
        normalize_list[0]["map"].append(
            {"helper": f"{name}({', '.join(map(repr, values))})"}
        )

    asset = {"name": "decoder/test/0", "normalize": normalize_list}

    expected = {"fail": "buildtime"}
    if len(sources) == 1:
        if len(sources[0]) == len(["reference", "value"]):
            expected = {"should_pass": True}

    test_cases.append(
        {"asset_definition": asset, "params": params, "expected": expected}
    )
    new_test = {
        "test_cases": test_cases,
        "description": "Test cases with invalid source type for values and references.",
    }
    new_tests.append(new_test)


def generate_test_with_invalid_params_type_in_value_source(
    name, template, repeat, last_argument, special_parameters, new_tests
):
    """
    Generate test cases with valid and invalid parameter types in value sources.

    Returns:
        None

    """
    type = convert_string_to_type(last_argument[0].get("type", []))
    for case in template:
        values_indices = [i for i, val in enumerate(case) if val == "value"]
        if len(values_indices) == repeat:
            replacements = ["valid", "invalid"]
            combinations = itertools.product(replacements, repeat=repeat)
            test_cases = []
            for combination in combinations:
                new_case = list(case)
                for index, new_value in zip(values_indices, combination):
                    new_case[index] = new_value
                values = []
                normalize_list = []
                expected = {}
                count = 0
                for param in new_case:
                    if param == "valid":
                        values.append(generate_value(type))
                        count += 1
                        if count == repeat:
                            expected["should_pass"] = True
                            count = 0
                    elif param == "invalid":
                        values.append(generate_value(type, False))
                    else:
                        values.append(param)

                if any(
                    all(param in values for param in special_parameter)
                    for special_parameter in special_parameters
                ):
                    expected["should_pass"] = False

                if "should_pass" not in expected:
                    expected["should_pass"] = False

                normalize_list.append(
                    {"map": [{"helper": f"{name}({', '.join(map(repr, values))})"}]}
                )
                asset = {"name": "decoder/test/0", "normalize": normalize_list}
                test_cases.append({"asset_definition": asset, "expected": expected})
            new_test = {
                "test_cases": test_cases,
                "description": "Test cases with values containing valid and invalid parameter types in value sources.",
            }
            new_tests.append(new_test)


def generate_test_with_invalid_params_type_in_reference_source(
    name, template, repeat, last_argument, special_parameters, new_tests
):
    """
    Generate test cases with valid and invalid parameter types in reference sources.

    Returns:
        None

    """
    type = convert_string_to_type(last_argument[0].get("type", []))
    for case in template:
        values_indices = [i for i, val in enumerate(case) if val == "reference"]
        if len(values_indices) == repeat:
            replacements = ["valid", "invalid"]
            combinations = itertools.product(replacements, repeat=repeat)
            test_cases = []
            for combination in combinations:
                new_case = list(case)
                for index, new_value in zip(values_indices, combination):
                    new_case[index] = new_value
                values = []
                all_values = []
                normalize_list = []
                params = {}
                count = 0
                for i, param in enumerate(new_case):
                    if param == "valid":
                        value = generate_value(type)
                        values.append(f"$_eventJson.ref_{i}")
                        all_values.append(value)
                        params[f"ref_{i}"] = value
                        count += 1
                        if count == repeat:
                            params["should_pass"] = True
                            count = 0
                    elif param == "invalid":
                        value = generate_value(type, False)
                        values.append(f"$_eventJson.ref_{i}")
                        all_values.append(value)
                        params[f"ref_{i}"] = value
                    else:
                        values.append(param)
                        all_values.append(param)

                if any(
                    all(param in all_values for param in special_parameter)
                    for special_parameter in special_parameters
                ):
                    params["should_pass"] = False

                if "should_pass" not in params:
                    params["should_pass"] = False
                test_cases.append(params)

            normalize_list.append(
                {"map": [{"_eventJson": "parse_json($event.original)"}]}
            )
            normalize_list[0]["map"].append({"helper": f"{name}({', '.join(values)})"})
            new_test = {
                "asset_definition": {
                    "name": "decoder/test/0",
                    "normalize": normalize_list,
                },
                "description": "Test cases with references containing valid and invalid parameter types in reference sources.",
                "test_cases": test_cases,
            }
            new_tests.append(new_test)


def generate_test_with_invalid_params_type_in_value_reference_source(
    name, template, repeat, last_argument, special_parameters, new_tests
):
    """
    Generate test cases with valid and invalid parameter types in value and reference sources.

    Returns:
        None

    """
    type = convert_string_to_type(last_argument[0].get("type", []))
    for case in template:
        if "value" in case and "reference" in case:
            values_indices = [i for i, val in enumerate(case) if val == "value"]
            reference_indices = [i for i, val in enumerate(case) if val == "reference"]

            replacements = ["valid", "invalid"]
            combinations = itertools.product(
                replacements, repeat=len(values_indices) + len(reference_indices)
            )
            test_cases = []

            for combination in combinations:
                new_case = list(case)
                value_combination = combination[: len(values_indices)]
                reference_combination = combination[len(values_indices) :]

                for index, new_value in zip(values_indices, value_combination):
                    new_case[index] = f"value:{new_value}"
                for index, new_value in zip(reference_indices, reference_combination):
                    new_case[index] = f"reference:{new_value}"
                values = []
                normalize_list = []
                all_values = []
                params = {}
                expected = {}
                count = 0
                for i, param in enumerate(new_case):
                    if ":" in param:
                        parts = param.split(":")
                        if parts[1] == "valid":
                            if parts[0] == "value":
                                value = generate_value(type)
                                all_values.append(value)
                                values.append(value)
                            else:
                                value = generate_value(type)
                                values.append(f"$_eventJson.ref{i}")
                                all_values.append(value)
                                params[f"ref{i}"] = value
                            count += 1
                            if count == repeat:
                                expected["should_pass"] = True
                        else:
                            if parts[0] == "value":
                                value = generate_value(type, False)
                                values.append(value)
                                all_values.append(value)
                                expected["fail"] = "buildtime"
                            else:
                                value = generate_value(type, False)
                                values.append(f"$_eventJson.ref{i}")
                                all_values.append(value)
                                params[f"ref{i}"] = value
                                if "fail" not in expected:
                                    expected["fail"] = "runtime"
                    else:
                        values.append(param)
                        all_values.append(param)

                if any(
                    all(param in all_values for param in special_parameter)
                    for special_parameter in special_parameters
                ):
                    if any(
                        all(param in values for param in special_parameter)
                        for special_parameter in special_parameters
                    ):
                        if "fail" not in expected:
                            expected["fail"] = "buildtime"
                        if "should_pass" in expected:
                            expected.pop("should_pass")
                    else:
                        if "fail" not in expected:
                            expected["fail"] = "runtime"
                        if "should_pass" in expected:
                            expected.pop("should_pass")

                normalize_list.append(
                    {"map": [{"_eventJson": "parse_json($event.original)"}]}
                )
                normalize_list[0]["map"].append(
                    {"helper": f"{name}({', '.join(map(repr, values))})"}
                )
                asset = {"name": "decoder/test/0", "normalize": normalize_list}
                test_cases.append(
                    {"asset_definition": asset, "params": params, "expected": expected}
                )
            new_test = {
                "test_cases": test_cases,
                "description": "Test cases with values and references containing valid and invalid parameter types in value and reference sources.",
            }
            new_tests.append(new_test)


def generate_test_with_non_exist_reference(
    name, min_args, template, last_argument, new_tests
):
    """
    Generate test cases with non-existent references.

    Returns:
        None

    """
    type = convert_string_to_type(last_argument[0].get("type", []))
    test_cases = []
    for case in template:
        values = []
        normalize_list = []
        params = {}
        expected = {"fail": "runtime"}
        count = 0
        for i, source in enumerate(case):
            if source == "value":
                values.append(generate_value(type))
                count += 1
                if count == min_args:
                    expected = {"should_pass": True}
            elif source == "reference":
                values.append(f"$ref{i}")
            else:
                values.append(source)

        normalize_list.append(
            {"map": [{"helper": f"{name}({', '.join(map(repr, values))})"}]}
        )
        asset = {"name": "decoder/test/0", "normalize": normalize_list}
        test_cases.append(
            {"asset_definition": asset, "params": params, "expected": expected}
        )
        new_test = {
            "test_cases": test_cases,
            "description": "Test cases with references not found.",
        }
    new_tests.append(new_test)


def main():
    # Get the directory where the script is located
    script_dir = Path(__file__).resolve().parent

    # Loop through the files in the directory
    for file_path in script_dir.iterdir():
        # Check if the file is a YML type
        if file_path.suffix == ".yml" or file_path.suffix == ".yaml":
            # Load the file and process it
            spec = load_yaml(file_path)
            variadic, name, min_args, special_parameters, sources, only_values = (
                process_yaml_data(spec)
            )
            new_tests = []
            repeat = min_args
            template = generate_operations(repeat, only_values)

            generate_test_with_fewer_parameters_than_min_args(name, min_args, new_tests)
            generate_test_with_value_not_allowed(
                name, min_args, spec["arguments"][-1:], only_values, new_tests
            )
            generate_test_with_different_sources(
                name, min_args, sources, spec["arguments"], new_tests
            )
            generate_test_with_invalid_params_type_in_value_source(
                name,
                template,
                repeat,
                spec["arguments"][-1:],
                special_parameters,
                new_tests,
            )
            generate_test_with_invalid_params_type_in_reference_source(
                name,
                template,
                repeat,
                spec["arguments"][-1:],
                special_parameters,
                new_tests,
            )
            generate_test_with_invalid_params_type_in_value_reference_source(
                name,
                template,
                repeat,
                spec["arguments"][-1:],
                special_parameters,
                new_tests,
            )
            generate_test_with_non_exist_reference(
                name, min_args, template, spec["arguments"][-1:], new_tests
            )

            # Save results in YAML file
            output_file_path = script_dir / f"{name}_output.yml"
            with open(output_file_path, "w") as file:
                yaml.dump(new_tests, file)


if __name__ == "__main__":
    main()
