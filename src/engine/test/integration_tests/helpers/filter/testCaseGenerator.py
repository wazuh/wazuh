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

        if selected_type == bool:
            return random.choice([True, False])
        if selected_type == int:
            return random.randint(0, 10)
        elif selected_type == float:
            return random.uniform(0, 10)
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
    target_field_type = convert_string_to_type(spec["target_field"]["type"])
    relationship = ""
    special_parameters = []
    sources = []
    only_values = None

    def special_cases():
        nonlocal relationship
        special_cases = spec.get("special_cases", [])
        for case in special_cases:
            relationship = case["relationship"]

    special_cases()

    def special_parameter():
        nonlocal special_parameters
        special_cases = spec.get("special_cases", [])
        for case in special_cases:
            special_parameters.append(case.get("arguments", []))

    special_parameter()

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

    return (
        variadic,
        name,
        min_args,
        relationship,
        sources,
        only_values,
        target_field_type,
        special_parameters,
    )


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
    normalize_list.append(
        {"check": [{"target_field": f"{name}({', '.join(few_parameters)})"}]}
    )
    new_test = {
        "fail": "buildtime",
        "asset_definition": {"name": "decoder/test/0", "normalize": normalize_list},
        "description": "few parameters",
    }
    new_tests.append(new_test)


def generate_test_with_more_parameters_than_max_args(
    name, min_args, variadic, new_tests
):
    """
    Generates a test case with more parameters than the maximum allowed arguments.

    Args:
        name (str): The name of the function being tested.
        min_args (int): The minimum number of arguments required for the function.
        variadic (bool): Indicates whether the function supports a variable number of arguments.
        new_tests (list): The list to which the generated test case will be appended.

    Returns:
        None

    """
    # Generate parameters exceeding the maximum allowed arguments
    few_parameters = ["0"] * (min_args + 15)

    # Prepare normalization list for the test case
    normalize_list = [
        {"check": [{"target_field": f"{name}({', '.join(few_parameters)})"}]}
    ]

    # Create the new test case
    new_test = {
        "asset_definition": {"name": "decoder/test/0", "normalize": normalize_list},
        "description": "more parameters",
    }

    # Set the test result based on variadic support
    if not variadic:
        new_test["fail"] = "buildtime"
    else:
        new_test["should_pass"] = True

    # Append the new test case to the list of tests
    new_tests.append(new_test)


def generate_test_with_non_exist_target_field(
    name, min_args, target_field_type, new_tests
):
    """
    Generates a test case for a non-existent target field.

    Args:
        name (str): The name of the function being tested.
        min_args (int): The minimum number of arguments required for the function.
        target_field_type (type): The type of the target field.
        new_tests (list): The list to which the generated test case will be appended.

    Returns:
        None

    """
    # Generate values for the target field
    values = [generate_value(target_field_type) for _ in range(min_args)]

    # Prepare normalization list for the test case
    normalize_list = [
        {"check": [{"target_field": f"{name}({', '.join(map(repr, values))})"}]}
    ]

    # Create the new test case
    new_test = {
        "asset_definition": {"name": "decoder/test/0", "normalize": normalize_list},
        "description": "target field non exist",
        "fail": "runtime",
    }

    # Append the new test case to the list of tests
    new_tests.append(new_test)


def generate_test_with_different_sources(
    name, min_args, target_field_type, relationship, sources, arguments, new_tests
):
    """
    Generates test cases with different sources for function arguments.

    Args:
        name (str): The name of the function being tested.
        min_args (int): The minimum number of arguments required for the function.
        target_field_type (type): The type of the target field.
        relationship (str): The relationship between arguments (e.g., "Equal").
        sources (list): The list of argument sources (e.g., ["value", "reference"]).
        arguments (list): The list of function arguments with their specifications.
        new_tests (list): The list to which the generated test cases will be appended.

    Returns:
        None

    """
    test_cases = []
    params = {}
    normalize_list = []
    values = []
    counter_reference = 0

    # Iterate through sources and generate values accordingly
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

    # Handle the case when the number of parameters is less than the minimum required
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

    # Prepare stage map for normalization
    stage_map = {"map": []}
    target_field_value = 0
    if relationship == "Equal":
        target_field_value = values[0]
    else:
        target_field_value = generate_value(target_field_type)

    # Construct the normalization list
    if len(params) == 0:
        stage_map["map"].append({"target_field": target_field_value})
    else:
        stage_map["map"].append({"_eventJson": "parse_json($event.original)"})
        stage_map["map"].append({"target_field": target_field_value})

    normalize_list.append(stage_map)
    normalize_list.append(
        {"check": [{"target_field": f"{name}({', '.join(map(repr, values))})"}]}
    )

    # Define the asset definition
    asset = {"name": "decoder/test/0", "normalize": normalize_list}

    # Define the expected outcome based on the source types
    expected = {"fail": "runtime"}
    if len(sources) == 1:
        if len(sources[0]) == 2:
            expected = {"should_pass": True}

    # Append the test case to the list of test cases
    test_cases.append(
        {"asset_definition": asset, "params": params, "expected": expected}
    )

    # Create the new test
    new_test = {
        "test_cases": test_cases,
        "description": "Value and Reference with invalid source type",
    }

    # Append the new test to the list of tests
    new_tests.append(new_test)


def generate_test_with_invalid_params_type_in_value_source(
    name,
    last_argument,
    template,
    repeat,
    special_parameters,
    relationship,
    target_field_type,
    new_tests,
):
    # Get the type of the last argument
    type = convert_string_to_type(last_argument[0].get("type", []))

    # Iterate over each case in the template
    for case in template:
        # Find the indices where 'value' occurs in the case
        values_indices = [i for i, val in enumerate(case) if val == "value"]

        # Check if the number of 'value's matches the repeat value
        if len(values_indices) == repeat:
            # Generate combinations of 'valid' and 'invalid' values
            replacements = ["valid", "invalid"]
            combinations = itertools.product(replacements, repeat=repeat)
            test_cases = []
            for combination in combinations:
                # Replace 'value' occurrences with 'valid' or 'invalid' values
                new_case = list(case)
                for index, new_value in zip(values_indices, combination):
                    new_case[index] = new_value

                values = []
                normalize_list = []
                expected = {}
                count = 0

                # Generate values based on the new case
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

                if "should_pass" not in expected:
                    expected["should_pass"] = False

                # Prepare stage map for normalization
                stage_map = {"map": []}
                target_field_value = 0
                if relationship == "Equal":
                    target_field_value = values[0]
                else:
                    target_field_value = generate_value(target_field_type)

                stage_map["map"].append({"target_field": target_field_value})
                normalize_list.append(stage_map)
                normalize_list.append(
                    {
                        "check": [
                            {"target_field": f"{name}({', '.join(map(repr, values))})"}
                        ]
                    }
                )

                # Prepare asset definition
                asset = {"name": "decoder/test/0", "normalize": normalize_list}
                test_cases.append({"asset_definition": asset, "expected": expected})

            # Add generated test cases to the list of new tests
            new_test = {
                "test_cases": test_cases,
                "description": "Values with valid and invalid params type",
            }
            new_tests.append(new_test)


def generate_test_with_invalid_params_type_in_reference_source(
    name,
    last_argument,
    template,
    repeat,
    special_parameters,
    relationship,
    target_field_type,
    new_tests,
):
    """
    Generates test cases with invalid parameter types in reference sources.

    Args:
        name (str): The name of the function being tested.
        last_argument (list): The last argument specifications.
        template (list): The template for generating test cases.
        repeat (int): The number of repetitions.
        special_parameters (list): List of special parameters.
        relationship (str): The relationship between arguments (e.g., "Equal").
        target_field_type (type): The type of the target field.
        new_tests (list): The list to which the generated test cases will be appended.

    Returns:
        None

    """
    # Get the type of the last argument
    type = convert_string_to_type(last_argument[0].get("type", []))

    # Iterate over each case in the template
    for case in template:
        # Find the indices where 'reference' occurs in the case
        values_indices = [i for i, val in enumerate(case) if val == "reference"]

        # Check if the number of 'reference's matches the repeat value
        if len(values_indices) == repeat:
            # Generate combinations of 'valid' and 'invalid' values
            replacements = ["valid", "invalid"]
            combinations = itertools.product(replacements, repeat=repeat)
            test_cases = []
            for combination in combinations:
                # Replace 'reference' occurrences with 'valid' or 'invalid' values
                new_case = list(case)
                for index, new_value in zip(values_indices, combination):
                    new_case[index] = new_value

                values = []
                all_values = []
                normalize_list = []
                params = {}
                count = 0

                # Generate values and parameters based on the new case
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

                if "should_pass" not in params:
                    params["should_pass"] = False
                test_cases.append(params)

            # Prepare stage map for normalization
            target_field_value = 0
            if relationship == "Equal":
                target_field_value = values[0]
            else:
                target_field_value = generate_value(target_field_type)

            stage_map = {"map": []}
            stage_map["map"].append({"_eventJson": "parse_json($event.original)"})
            stage_map["map"].append({"target_field": target_field_value})
            normalize_list.append(stage_map)
            normalize_list.append(
                {"check": [{"target_field": f"{name}({', '.join(map(repr, values))})"}]}
            )

            # Prepare asset definition
            new_test = {
                "asset_definition": {
                    "name": "decoder/test/0",
                    "normalize": normalize_list,
                },
                "description": "References with valid and invalid params type",
                "test_cases": test_cases,
            }
            new_tests.append(new_test)


def generate_test_with_invalid_params_type_in_value_reference_source(
    name,
    last_argument,
    template,
    repeat,
    special_parameters,
    relationship,
    target_field_type,
    new_tests,
):
    """
    Generates test cases with invalid parameter types in value and reference sources.

    Args:
        name (str): The name of the function being tested.
        last_argument (list): The last argument specifications.
        template (list): The template for generating test cases.
        repeat (int): The number of repetitions.
        special_parameters (list): List of special parameters.
        relationship (str): The relationship between arguments (e.g., "Equal").
        target_field_type (type): The type of the target field.
        new_tests (list): The list to which the generated test cases will be appended.

    Returns:
        None

    """
    type = convert_string_to_type(last_argument[0].get("type", []))

    # Iterate over each case in the template
    for case in template:
        # Check if the case contains 'value' or 'reference'
        if "value" in case or "reference" in case:
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

                # Generate values and parameters based on the new case
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
                            count = count + 1
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

                # Prepare stage map for normalization
                stage_map = {"map": []}
                target_field_value = 0
                if relationship == "Equal":
                    target_field_value = values[0]
                else:
                    target_field_value = generate_value(target_field_type)
                stage_map["map"].append({"_eventJson": "parse_json($event.original)"})
                stage_map["map"].append({"target_field": target_field_value})
                normalize_list.append(stage_map)
                normalize_list.append(
                    {
                        "check": [
                            {"target_field": f"{name}({', '.join(map(repr, values))})"}
                        ]
                    }
                )
                asset = {"name": "decoder/test/0", "normalize": normalize_list}
                test_cases.append(
                    {"asset_definition": asset, "params": params, "expected": expected}
                )
            new_test = {
                "test_cases": test_cases,
                "description": "Value and reference with valid and invalid params type",
            }
            new_tests.append(new_test)


def generate_test_with_non_exist_reference(
    name, min_args, last_argument, template, relationship, target_field_type, new_tests
):
    """
    Generates test cases with non-existent references.

    Args:
        name (str): The name of the function being tested.
        min_args (int): The minimum number of arguments required.
        last_argument (list): Specifications of the last argument.
        template (list): Template for generating test cases.
        relationship (str): The relationship between arguments (e.g., "Equal").
        target_field_type (type): Type of the target field.
        new_tests (list): List to which the generated test cases will be appended.

    Returns:
        None

    """
    # Convert string type to Python type
    type = convert_string_to_type(last_argument[0].get("type", []))
    test_cases = []

    # Iterate through the template to generate test cases
    for case in template:
        values = []
        normalize_list = []
        params = {}
        expected = {"fail": "runtime"}
        count = 0

        # Generate values and parameters based on the template
        for i, source in enumerate(case):
            if source == "value":
                values.append(generate_value(type))
                count = count + 1
                if count == min_args:
                    expected = {"should_pass": True}
            elif source == "reference":
                values.append(f"$ref{i}")
            else:
                values.append(source)

        # Prepare stage map for normalization
        stage_map = {"map": []}
        target_field_value = generate_value(target_field_type)

        stage_map["map"].append({"target_field": target_field_value})
        normalize_list.append(stage_map)
        normalize_list.append(
            {"check": [{"target_field": f"{name}({', '.join(map(repr, values))})"}]}
        )

        asset = {"name": "decoder/test/0", "normalize": normalize_list}
        test_cases.append(
            {"asset_definition": asset, "params": params, "expected": expected}
        )

    # Prepare the new test case
    new_test = {
        "test_cases": test_cases,
        "description": "References not found",
    }
    new_tests.append(new_test)


def generate_test_with_invalid_special_case(
    name, min_args, relationship, target_field_type, new_tests
):
    """
    Generates a test case with invalid special case.

    Args:
        name (str): The name of the function being tested.
        min_args (int): The minimum number of arguments required.
        relationship (str): The relationship between arguments (e.g., "Equal").
        target_field_type (type): Type of the target field.
        new_tests (list): List to which the generated test case will be appended.

    Returns:
        None

    """
    values = []
    normalize_list = []

    # Generate values based on the target field type
    for _ in range(min_args):
        values.append(generate_value(target_field_type))

    # Prepare stage map for normalization
    stage_map = {"map": []}
    target_field_value = 0

    # Determine target field value based on the relationship
    if relationship == "Equal":
        target_field_value = generate_value(target_field_type)
    else:
        target_field_value = values[0]

    stage_map["map"].append({"target_field": target_field_value})
    normalize_list.append(stage_map)
    normalize_list.append(
        {"check": [{"target_field": f"{name}({', '.join(map(repr, values))})"}]}
    )

    # Create the new test case
    new_test = {
        "asset_definition": {"name": "decoder/test/0", "normalize": normalize_list},
        "description": "Invalid special case",
        "fail": "runtime",
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
            (
                variadic,
                name,
                min_args,
                relationship,
                sources,
                only_values,
                target_field_type,
                special_parameters,
            ) = process_yaml_data(spec)
            new_tests = []
            repeat = min_args
            template = generate_operations(repeat, only_values)

            generate_test_with_fewer_parameters_than_min_args(name, min_args, new_tests)
            generate_test_with_more_parameters_than_max_args(
                name, min_args, variadic, new_tests
            )
            generate_test_with_non_exist_target_field(
                name, min_args, target_field_type, new_tests
            )
            generate_test_with_different_sources(
                name,
                min_args,
                target_field_type,
                relationship,
                sources,
                spec["arguments"],
                new_tests,
            )
            generate_test_with_invalid_params_type_in_value_source(
                name,
                spec["arguments"][-1:],
                template,
                repeat,
                special_parameters,
                relationship,
                target_field_type,
                new_tests,
            )
            generate_test_with_invalid_params_type_in_reference_source(
                name,
                spec["arguments"][-1:],
                template,
                repeat,
                special_parameters,
                relationship,
                target_field_type,
                new_tests,
            )
            generate_test_with_invalid_params_type_in_value_reference_source(
                name,
                spec["arguments"][-1:],
                template,
                repeat,
                special_parameters,
                relationship,
                target_field_type,
                new_tests,
            )
            generate_test_with_non_exist_reference(
                name,
                min_args,
                spec["arguments"][-1:],
                template,
                relationship,
                target_field_type,
                new_tests,
            )

            generate_test_with_invalid_special_case(
                name, min_args, relationship, target_field_type, new_tests
            )

            # Save results in YAML file
            output_file_path = script_dir / f"{name}_output.yml"
            with open(output_file_path, "w") as file:
                yaml.dump(new_tests, file)


if __name__ == "__main__":
    main()
