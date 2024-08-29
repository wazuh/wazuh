#!/usr/bin/env python3

from .parser import Parser
from .validator import Validator

ID_COUNTER = 0


def increase_id():
    """
    Increments and returns the global ID_COUNTER.

    Returns:
        int: The incremented ID.
    """
    global ID_COUNTER
    ID_COUNTER = ID_COUNTER + 1
    return ID_COUNTER


class TestData:
    def __init__(self, parser: Parser, validator: Validator):
        """
        Initializes the TestData class.

        Args:
            parser (Parser): The parser instance.
            validator (Validator): The validator instance.
        """
        self.parser = parser
        self.validator = validator
        self.tests = {"build_test": [], "run_test": []}
        self.asset_definition = {}

    def set_helper_type(self, helper_type: str):
        """
        Sets the helper type.

        Args:
            helper_type (str): The helper type.
        """
        self.helper_type = helper_type

    def get_all_tests(self):
        """
        Returns all tests.

        Returns:
            dict: All tests.
        """
        return self.tests

    def create_asset_for_buildtime(self, arguments: list, target_field_value=None):
        """
        Creates an asset for build-time tests.

        Args:
            arguments (list): The list of arguments.
            target_field_value (optional): The target field value. Defaults to None.
        """
        helper = f"{self.parser.get_name()}({', '.join(str(v) for v in arguments)})"
        if self.helper_type == "map":
            normalize_list = [{"map": [{"helper": helper}]}]
        elif self.helper_type == "filter":
            normalize_list = [{"map": [{"target_field": target_field_value}]}, {"check": [{"target_field": helper}], "map": [
                {"verification_field": "It is used to verify if the check passed correctly"}]}]
        else:
            normalize_list = [{"map": [{"target_field": target_field_value}, {"target_field": helper}]}]
        self.asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

    def push_test_data_for_buildtime(self, description: str, skip_tag=""):
        """
        Pushes test data for build-time tests.

        Args:
            description (str): The test description.
            skip_tag (str, optional): The skip tag. Defaults to "".
        """
        test_data = {
            "assets_definition": self.asset_definition,
            "should_pass": False,
            "description": description,
            "id": increase_id()
        }
        if skip_tag and skip_tag in self.parser.get_skips():
            test_data["skipped"] = True
        self.tests["build_test"].append(test_data)

    def create_asset_for_runtime(self, arguments: list, target_field_value=None):
        """
        Creates an asset for runtime tests.

        Args:
            arguments (list): The list of arguments.
            target_field_value (optional): The target field value. Defaults to None.
        """
        helper = f"{self.parser.get_name()}({', '.join(str(v) for v in arguments)})"
        if self.helper_type == "map":
            normalize_list = [{"map": [{"eventJson": "parse_json($event.original)"}, {"helper": helper}]}]
        elif self.helper_type == "filter":
            normalize_list = [
                {"map": [{"eventJson": "parse_json($event.original)"}, {"target_field": target_field_value}]},
                {"check": [{"target_field": helper}], "map": [{"verification_field": "It is used to verify if the check passed correctly"}]}
            ]
        else:
            normalize_list = [{"map": [{"eventJson": "parse_json($event.original)"}, {"target_field": target_field_value}, {
                "target_field": helper}]}]
        self.asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

    def push_test_data_for_runtime(self, input: dict, description: str, should_pass=False, skip_tag="", expected=None):
        """
        Pushes test data for runtime tests.

        Args:
            input (dict): The input data.
            description (str): The test description.
            should_pass (bool, optional): Whether the test should pass. Defaults to False.
            skip_tag (str, optional): The skip tag. Defaults to "".
            expected (optional): The expected output. Defaults to None.
        """
        test_cases = [{"input": input, "id": increase_id(), "should_pass": should_pass}]
        if skip_tag and skip_tag in self.parser.get_skips():
            test_cases[0]["skipped"] = True
        if expected is not None:
            test_cases[0]["expected"] = expected
        test_data = {
            "assets_definition": self.asset_definition,
            "test_cases": test_cases,
            "description": description
        }
        self.tests["run_test"].append(test_data)

    def push_test_data_for_runtime_deprecated(
            self, input: dict, description: str, should_pass=False, skip=False, expected=None):
        """
        Pushes deprecated test data for runtime tests.

        Args:
            input (dict): The input data.
            description (str): The test description.
            should_pass (bool, optional): Whether the test should pass. Defaults to False.
            skip (bool, optional): Whether to skip the test. Defaults to False.
            expected (optional): The expected output. Defaults to None.
        """
        test_cases = [{"input": input, "id": increase_id(), "should_pass": should_pass}]
        if skip:
            test_cases[0]["skipped"] = True
        if expected is not None:
            test_cases[0]["expected"] = expected
        test_data = {
            "assets_definition": self.asset_definition,
            "test_cases": test_cases,
            "description": description
        }
        self.tests["run_test"].append(test_data)
