#!/usr/bin/env python3

from .parser import Parser
from .validator import Validator

ID_COUNTER = 0


def increase_id():
    global ID_COUNTER
    ID_COUNTER = ID_COUNTER + 1
    return ID_COUNTER


class TestData:
    def __init__(self, parser: Parser, validator: Validator):
        self.parser = parser
        self.validator = validator
        self.tests = {"build_test": [], "run_test": []}
        self.asset_definition = {}

    def set_helper_type(self, helper_type: str):
        self.helper_type = helper_type

    def get_all_tests(self):
        return self.tests

    def create_asset_for_buildtime(self, arguments: list, target_field_value=None):
        helper = f"{self.parser.get_name()}({', '.join(str(v) for v in arguments)})"
        if self.helper_type == "map":
            normalize_list = [{"map": [{"helper": helper}]}]
        elif self.helper_type == "filter":
            normalize_list = [
                {
                    "map": [{"target_field": target_field_value}]
                }
            ]
            normalize_list.append(
                {
                    "check": [
                        {
                            "target_field": helper
                        }
                    ],
                    "map": [
                        {
                            "verification_field": "It is used to verify if the check passed correctly"
                        }
                    ],
                }
            )
        else:
            normalize_list = [
                {
                    "map": [{"target_field": target_field_value}, {"target_field": helper}]
                }
            ]
        self.asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

    def push_test_data_for_buildtime(self, description: str, skip_tag=""):
        test_data = {}
        test_data["assets_definition"] = self.asset_definition
        test_data["should_pass"] = False
        test_data["description"] = description
        test_data["id"] = increase_id()
        if skip_tag:
            if skip_tag in self.parser.get_skips():
                test_data["skipped"] = True
        self.tests["build_test"].append(test_data)

    def create_asset_for_runtime(self, arguments: list, target_field_value=None):
        helper = (f"{self.parser.get_name()}({', '.join(str(v) for v in arguments)})")
        if self.helper_type == "map":
            normalize_list = [{"map": [{"eventJson": "parse_json($event.original)"}, {"helper": helper}]}]
        elif self.helper_type == "filter":
            normalize_list = [{"map": [{"eventJson": "parse_json($event.original)"}, {
                "target_field": target_field_value}]}]
            normalize_list.append(
                {
                    "check": [
                        {
                            "target_field": helper
                        }
                    ],
                    "map": [
                        {
                            "verification_field": "It is used to verify if the check passed correctly"
                        }
                    ],
                }
            )
        else:
            normalize_list = [{"map": [{"eventJson": "parse_json($event.original)"}, {"target_field": target_field_value}, {
                "target_field": helper}]}]
        self.asset_definition = {"name": "decoder/test/0", "normalize": normalize_list}

    def push_test_data_for_runtime(self, input: dict, description: str, should_pass=False, skip_tag="", expected=None):
        test_data = {}
        test_data["assets_definition"] = self.asset_definition
        if skip_tag:
            if skip_tag in self.parser.get_skips():
                test_data["test_cases"] = [
                    {"input": input, "id": increase_id(),
                     "should_pass": should_pass, "skipped": True}]
            else:
                test_data["test_cases"] = [{"input": input, "id": increase_id(), "should_pass": should_pass}]
        else:
            if expected != None:
                test_data["test_cases"] = [
                    {"input": input, "id": increase_id(),
                     "should_pass": should_pass, "expected": expected}]
            else:
                test_data["test_cases"] = [{"input": input, "id": increase_id(), "should_pass": should_pass}]
        test_data["description"] = description
        self.tests["run_test"].append(test_data)

    def push_test_data_for_runtime_deprecated(
            self, input: dict, description: str, should_pass=False, skip=False, expected=None):
        test_data = {}
        test_data["assets_definition"] = self.asset_definition
        if skip:
            test_data["test_cases"] = [
                {"input": input, "id": increase_id(),
                    "should_pass": should_pass, "skipped": True}]
        else:
            if expected != None:
                test_data["test_cases"] = [
                    {"input": input, "id": increase_id(),
                     "should_pass": should_pass, "expected": expected}]
            else:
                test_data["test_cases"] = [{"input": input, "id": increase_id(), "should_pass": should_pass}]
        test_data["description"] = description
        self.tests["run_test"].append(test_data)
