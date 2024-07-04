#!/usr/bin/env python3

import argparse
import shutil
from pathlib import Path
from argument_generator import generator
import yaml
import json
import sys
import itertools

id_counter = 0
maximum_number_of_arguments = 40


def increase_id():
    global id_counter
    id_counter = id_counter + 1
    return id_counter


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Helpers test for Engine.")
    parser.add_argument(
        "-i",
        "--input_file",
        help="Absolute or relative path where the description of the helper function is located",
    )
    return parser.parse_args()


class TestCaseGenerator:
    def __init__(self, current_directory: Path, output_directory: Path, input_file: str = ""):
        self.current_directory = current_directory
        self.output_directory = output_directory
        self.input_file = input_file
        self.parser = generator.Parser()
        self.validator = generator.Validator(self.parser)
        self.tests = {"build_test": [], "run_test": []}
        self.asset_definition = {}

    def clean_output_directory(self):
        for item in self.output_directory.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)

    def scan_and_verify_all_files(self):
        if self.input_file:
            input_file_path = Path(self.input_file).resolve()
            if input_file_path.exists():
                if input_file_path.parent == self.current_directory.resolve():
                    self.validator.evaluator(self.input_file)
            else:
                print(f"Input file {self.input_file} does not exist.")
        else:
            for file_path in self.current_directory.iterdir():
                if file_path.suffix in [".yml", ".yaml"]:
                    self.validator.evaluator(file_path)

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

    def fewer_arguments_than_the_minimum_required(self):
        description = "Test with fewer parameters for helper function."
        minimum_arguments = self.parser.get_minimum_arguments()
        for num_arguments in range(minimum_arguments):
            parameters = [
                "0"
            ] * num_arguments  # Generate empty strings for the current number of arguments
            if self.parser.has_target_field():
                argument = generator.Argument()
                target_field_type = self.parser.get_target_field_type()
                if isinstance(target_field_type, list):
                    for tft in target_field_type:
                        target_field_subtipe = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(tft)
                        for tfs in target_field_subtipe:
                            argument.configure_target_field(tft, tfs)
                else:
                    argument.configure_target_field(
                        self.parser.get_target_field_type(),
                        self.parser.get_target_field_subset())
                self.create_asset_for_buildtime(parameters, argument.get())
            else:
                self.create_asset_for_buildtime(parameters)
            self.push_test_data_for_buildtime(description)

    def more_or_less_arguments_according_to_variadic(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        sources = self.parser.get_sources()
        all_arguments = []
        description = "Generate more arguments than the maximum allowed"
        val = None

        if self.parser.is_variadic():
            number_of_arguments = maximum_number_of_arguments + 1
        else:
            number_of_arguments = self.parser.get_minimum_arguments() + 1

        for i in range(number_of_arguments):
            if self.parser.get_minimum_arguments() == 0:
                argument = generator.Argument("any_value")
                argument.configure_generation(list, str, "reference", [])
                val = argument.get()
            else:
                j = i % self.parser.get_minimum_arguments()
                argument = generator.Argument()
                if not isinstance(types[j], list):
                    argument.configure_generation(types[j], subsets[j], sources[j], [])
                    val = argument.get()

            if val != None:
                if argument.is_reference(val):
                    all_arguments.append(f"$eventJson.{val['name']}")
                else:
                    all_arguments.append(val)

        if self.parser.has_target_field():
            argument = generator.Argument()
            if not isinstance(self.parser.get_target_field_type(), list):
                argument.configure_target_field(
                    self.parser.get_target_field_type(),
                    self.parser.get_target_field_subset())
            else:
                type_ = self.parser.get_target_field_type()[0]
                subset = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_)[0]
                argument.configure_target_field(
                    type_,
                    subset)
            self.create_asset_for_buildtime(all_arguments, argument.get())
        else:
            self.create_asset_for_buildtime(all_arguments)
        self.push_test_data_for_buildtime(description)

    def different_sources(self):
        types = self.parser.get_types()
        sources = self.parser.get_sources()
        subsets = self.parser.get_subset()
        description = "generate a different source than the one defined in the argument"

        for i in range(len(types)):
            new_sources = sources[:]  # Copying the list of sources to not modify the original

            # Expected a success result if source is both
            if sources[i] == "both":
                continue

            new_source = generator.change_source(sources[i])  # Changing the source for this argument
            new_sources[i] = new_source  # Updating the new list of sources

            all_arguments = []
            for j in range(len(types)):
                if not isinstance(types[j], list):
                    argument = generator.Argument()
                    argument.configure_generation(types[j], subsets[j], new_sources[j], [])
                    arg = argument.get()
                    if argument.is_reference(arg):
                        all_arguments.append(f"$eventJson.{arg['name']}")
                    else:
                        all_arguments.append(json.dumps(arg))

            if len(all_arguments) != 0:
                if self.parser.has_target_field():
                    target_field_type = self.parser.get_target_field_type()
                    if not isinstance(target_field_type, list):
                        argument = generator.Argument()
                        argument.configure_target_field(
                            self.parser.get_target_field_type(),
                            self.parser.get_target_field_subset())
                        self.create_asset_for_buildtime(all_arguments, argument.get())
                    else:
                        for tft in target_field_type:
                            target_field_subset = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(tft)
                            for tfs in target_field_subset:
                                argument = generator.Argument()
                                argument.configure_target_field(tft, tfs)
                                self.create_asset_for_buildtime(all_arguments, argument.get())
                else:
                    self.create_asset_for_buildtime(all_arguments)
                self.push_test_data_for_buildtime(description)

    def different_source_with_various_types(self):
        types = self.parser.get_types()
        sources = self.parser.get_sources()
        description = "generate a different source than the one defined in the argument"

        for i in range(len(types)):
            new_sources = sources[:]  # Copying the list of sources to not modify the original

            # Expected a success result if source is both
            if sources[i] == "both":
                continue

            new_source = generator.change_source(sources[i])  # Changing the source for this argument
            new_sources[i] = new_source  # Updating the new list of sources

            all_arguments = []
            for j in range(len(types)):
                if isinstance(types[j], list):
                    argument = generator.Argument()
                    argument.configure_generation(
                        types[j][0],
                        generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(types[j][0])[0],
                        new_sources[j],
                        [])
                    arg = argument.get()
                    if argument.is_reference(arg):
                        all_arguments.append(f"$eventJson.{arg['name']}")
                    else:
                        all_arguments.append(json.dumps(arg))

            if len(all_arguments) != 0:
                if self.parser.has_target_field():
                    target_field_type = self.parser.get_target_field_type()
                    if not isinstance(target_field_type, list):
                        argument = generator.Argument()
                        argument.configure_target_field(
                            self.parser.get_target_field_type(),
                            self.parser.get_target_field_subset())
                        self.create_asset_for_buildtime(all_arguments, argument.get())
                    else:
                        for tft in target_field_type:
                            target_field_subset = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(tft)
                            for tfs in target_field_subset:
                                argument = generator.Argument()
                                argument.configure_target_field(tft, tfs)
                                self.create_asset_for_buildtime(all_arguments, argument.get())
                else:
                    self.create_asset_for_buildtime(all_arguments)
                self.push_test_data_for_buildtime(description)

    def different_types_value_with_various_types(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "generate a different value type than the one defined in the argument"

        template = generator.Template(self.parser)
        for combination in template.generate_template():
            for i, original_type in enumerate(types):
                if isinstance(original_type, list):
                    altered_types = generator.change_type(original_type)
                    for new_type, new_subsets in altered_types.items():
                        for new_subset in new_subsets:
                            all_arguments = []

                            for id, (type_, subset, source, restriction) in enumerate(
                                    zip(types, subsets, combination, restrictions)):
                                if id == i:
                                    aux_source = ""
                                    if type(source) is not tuple:
                                        aux_source = source
                                    else:
                                        aux_source = source[1]
                                    if aux_source == "value":
                                        type_ = new_type
                                        subset = new_subset
                                    else:
                                        break

                                if type(source) is not tuple:  # means this is an allowed restriction
                                    argument = generator.Argument()
                                    if isinstance(type_, list):
                                        argument.configure_generation(
                                            type_[0],
                                            generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[0],
                                            source, restriction)
                                    else:
                                        argument.configure_generation(type_, subset, source, restriction)
                                    val = argument.get()
                                    if id in forbidden:
                                        if isinstance(val, dict):
                                            if "name" in val:  # is a reference
                                                if val["value"] not in forbidden[id]:
                                                    all_arguments.append(f"${val['name']}")
                                        elif val not in forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            all_arguments.append(f"${val['name']}")
                                        else:
                                            all_arguments.append(val)
                                else:
                                    if id == i:
                                        argument = generator.Argument()
                                        # It is also configured to verify that the allowed matches the argument declaration.
                                        if isinstance(type_, list):
                                            argument.configure_generation(
                                                type_[0],
                                                generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[0],
                                                source[1], restriction, ignore_allowed=True)
                                        else:
                                            argument.configure_generation(type_, subset, source[1],
                                                                          restriction, ignore_allowed=True)
                                    else:
                                        argument = generator.Argument(source[0])
                                        if isinstance(type_, list):
                                            argument.configure_generation(
                                                type_[0],
                                                generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[0],
                                                source[1],
                                                restriction)
                                        else:
                                            argument.configure_generation(type_, subset, source[1], restriction)
                                    val = argument.get()
                                    if argument.is_reference(val):
                                        all_arguments.append(f"${val['name']}")
                                    else:
                                        all_arguments.append(val)

                            if len(all_arguments) != len(combination):
                                all_arguments.clear()

                            if len(all_arguments) != 0:
                                if generator.check_restrictions(all_arguments, general_restrictions):
                                    all_arguments.clear()

                            if len(all_arguments) != 0:
                                if self.parser.has_target_field():
                                    argument = generator.Argument()
                                    argument.configure_target_field(
                                        self.parser.get_target_field_type(),
                                        self.parser.get_target_field_subset())
                                    self.create_asset_for_buildtime(all_arguments, argument.get())
                                else:
                                    self.create_asset_for_buildtime(all_arguments)
                                self.push_test_data_for_buildtime(description)

    def different_types_value(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "generate a different value type than the one defined in the argument"

        template = generator.Template(self.parser)
        for combination in template.generate_template():
            if not any(isinstance(t, list) for t in types):
                for i, original_type in enumerate(types):
                    if not isinstance(original_type, list):
                        altered_types = generator.change_type(original_type)
                        for new_type, new_subsets in altered_types.items():
                            for new_subset in new_subsets:
                                all_arguments = []
                                for id, (type_, subset, source, restriction) in enumerate(
                                        zip(types, subsets, combination, restrictions)):
                                    if id == i:
                                        aux_source = ""
                                        if type(source) is not tuple:
                                            aux_source = source
                                        else:
                                            aux_source = source[1]
                                        if aux_source == "value":
                                            type_ = new_type
                                            subset = new_subset
                                        else:
                                            break

                                    if type(source) is not tuple:  # means this is an allowed restriction
                                        argument = generator.Argument()
                                        argument.configure_generation(type_, subset, source, restriction)
                                        val = argument.get()
                                        if id in forbidden:
                                            if isinstance(val, dict):
                                                if "name" in val:  # is a reference
                                                    if val["value"] not in forbidden[id]:
                                                        all_arguments.append(f"${val['name']}")
                                            elif val not in forbidden[id]:
                                                all_arguments.append(val)
                                        else:
                                            if argument.is_reference(val):
                                                all_arguments.append(f"${val['name']}")
                                            else:
                                                all_arguments.append(val)
                                    else:
                                        if id == i:
                                            argument = generator.Argument()
                                            # It is also configured to verify that the allowed matches the argument declaration.
                                            argument.configure_generation(type_, subset, source[1],
                                                                          restriction, ignore_allowed=True)
                                        else:
                                            argument = generator.Argument(source[0])
                                            argument.configure_generation(type_, subset, source[1], restriction)
                                        val = argument.get()
                                        if argument.is_reference(val):
                                            all_arguments.append(f"${val['name']}")
                                        else:
                                            all_arguments.append(val)

                                if len(all_arguments) != len(combination):
                                    all_arguments.clear()

                                if len(all_arguments) != 0:
                                    if generator.check_restrictions(all_arguments, general_restrictions):
                                        all_arguments.clear()

                                if len(all_arguments) != 0:
                                    if self.parser.has_target_field():
                                        target_field_type = self.parser.get_target_field_type()
                                        if not isinstance(target_field_type, list):
                                            argument = generator.Argument()
                                            argument.configure_target_field(
                                                self.parser.get_target_field_type(),
                                                self.parser.get_target_field_subset())
                                            self.create_asset_for_buildtime(all_arguments, argument.get())
                                        else:
                                            for tft in target_field_type:
                                                target_field_subset = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                                                    tft)
                                                for tfs in target_field_subset:
                                                    argument = generator.Argument()
                                                    argument.configure_target_field(tft, tfs)
                                                    self.create_asset_for_buildtime(all_arguments, argument.get())
                                    else:
                                        self.create_asset_for_buildtime(all_arguments)
                                    self.push_test_data_for_buildtime(description)

    def different_types_reference(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "generate a different type in references than the one defined in the argument"

        template = generator.Template(self.parser)
        for combination in template.generate_template():
            for i, original_type in enumerate(types):
                if not isinstance(original_type, list):
                    altered_types = generator.change_type(original_type)
                    for new_type, new_subsets in altered_types.items():
                        for new_subset in new_subsets:
                            all_arguments = []
                            input = {}
                            for id, (type_, subset, source, restriction) in enumerate(
                                    zip(types, subsets, combination, restrictions)):
                                if id == i:
                                    aux_source = ""
                                    if type(source) is not tuple:
                                        aux_source = source
                                    else:
                                        aux_source = source[1]
                                    if aux_source == "reference":
                                        type_ = new_type
                                        subset = new_subset
                                    else:
                                        break

                                if type(source) is not tuple:  # means this is an allowed restriction
                                    argument = generator.Argument()
                                    if isinstance(type_, list):
                                        if len(type_) == 5:
                                            continue
                                    argument.configure_generation(type_, subset, source, restriction)
                                    val = argument.get()
                                    if id in forbidden:
                                        if isinstance(val, dict):
                                            if "name" in val:  # is a reference
                                                if val["value"] not in forbidden[id]:
                                                    input[f"{val['name']}"] = val['value']
                                                    all_arguments.append(f"$eventJson.{val['name']}")
                                        elif val not in forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            input[f"{val['name']}"] = val['value']
                                            all_arguments.append(f"$eventJson.{val['name']}")
                                        else:
                                            all_arguments.append(val)
                                else:
                                    if id == i:
                                        argument = generator.Argument()
                                        # It is also configured to verify that the allowed matches the argument declaration.
                                        argument.configure_generation(
                                            type_, subset, source[1],
                                            restriction, ignore_allowed=True)
                                    else:
                                        argument = generator.Argument(source[0])
                                        argument.configure_generation(type_, subset, source[1], restriction)
                                    val = argument.get()
                                    if argument.is_reference(val):
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(f"$eventJson.{val['name']}")
                                    else:
                                        all_arguments.append(val)

                            if len(all_arguments) != len(combination):
                                all_arguments.clear()

                            if len(all_arguments) != 0:
                                if generator.check_restrictions(all_arguments, general_restrictions):
                                    all_arguments.clear()

                            if len(all_arguments) != 0:
                                if self.parser.has_target_field():
                                    target_field_type = self.parser.get_target_field_type()
                                    if not isinstance(target_field_type, list):
                                        argument = generator.Argument()
                                        argument.configure_target_field(
                                            self.parser.get_target_field_type(),
                                            self.parser.get_target_field_subset())
                                        self.create_asset_for_runtime(all_arguments, argument.get())
                                    else:
                                        for tft in target_field_type:
                                            target_field_subset = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(tft)
                                            for tfs in target_field_subset:
                                                argument = generator.Argument()
                                                argument.configure_target_field(tft, tfs)
                                                self.create_asset_for_runtime(all_arguments, argument.get())
                                else:
                                    self.create_asset_for_runtime(all_arguments)
                                self.push_test_data_for_runtime(input, description, skip_tag="different_type")

    def different_types_reference_with_various_types(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "generate a different type in references than the one defined in the argument"

        template = generator.Template(self.parser)
        for combination in template.generate_template():
            for i, original_type in enumerate(types):
                if isinstance(original_type, list):
                    altered_types = generator.change_type(original_type)
                    for new_type, new_subsets in altered_types.items():
                        for new_subset in new_subsets:
                            all_arguments = []
                            input = {}
                            for id, (type_, subset, source, restriction) in enumerate(
                                    zip(types, subsets, combination, restrictions)):
                                if id == i:
                                    aux_source = ""
                                    if type(source) is not tuple:
                                        aux_source = source
                                    else:
                                        aux_source = source[1]
                                    if aux_source == "reference":
                                        type_ = new_type
                                        subset = new_subset
                                    else:
                                        break

                                if type(source) is not tuple:  # means this is an allowed restriction
                                    argument = generator.Argument()
                                    if isinstance(type_, list):
                                        argument.configure_generation(
                                            type_[0],
                                            generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[0],
                                            source, restriction)
                                    else:
                                        argument.configure_generation(type_, subset, source, restriction)
                                    val = argument.get()
                                    if id in forbidden:
                                        if isinstance(val, dict):
                                            if "name" in val:  # is a reference
                                                if val["value"] not in forbidden[id]:
                                                    input[f"{val['name']}"] = val['value']
                                                    all_arguments.append(f"$eventJson.{val['name']}")
                                        elif val not in forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            input[f"{val['name']}"] = val['value']
                                            all_arguments.append(f"$eventJson.{val['name']}")
                                        else:
                                            all_arguments.append(val)
                                else:
                                    if id == i:
                                        argument = generator.Argument()
                                        # It is also configured to verify that the allowed matches the argument declaration.
                                        if isinstance(type_, list):
                                            argument.configure_generation(
                                                type_[0],
                                                generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[0],
                                                source[1],
                                                restriction, ignore_allowed=True)
                                        else:
                                            argument.configure_generation(
                                                type_, subset, source[1],
                                                restriction, ignore_allowed=True)
                                    else:
                                        argument = generator.Argument(source[0])
                                        if isinstance(type_, list):
                                            argument.configure_generation(
                                                type_[0],
                                                generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[0],
                                                source[1],
                                                restriction)
                                        else:
                                            argument.configure_generation(type_, subset, source[1], restriction)
                                    val = argument.get()
                                    if argument.is_reference(val):
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(f"$eventJson.{val['name']}")
                                    else:
                                        all_arguments.append(val)

                            if len(all_arguments) != len(combination):
                                all_arguments.clear()

                            if len(all_arguments) != 0:
                                if generator.check_restrictions(all_arguments, general_restrictions):
                                    all_arguments.clear()

                            if len(all_arguments) != 0:
                                if self.parser.has_target_field():
                                    argument = generator.Argument()
                                    argument.configure_target_field(
                                        self.parser.get_target_field_type(),
                                        self.parser.get_target_field_subset())
                                    self.create_asset_for_runtime(all_arguments, argument.get())
                                else:
                                    self.create_asset_for_runtime(all_arguments)
                                self.push_test_data_for_runtime(input, description, skip_tag="different_type")

    def different_allowed_values(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        description = "generate a different value allowed than the one defined in the argument"

        template = generator.Template(self.parser)

        for combination in template.generate_template():
            allowed_indices = [i for i, source in enumerate(combination) if isinstance(source, tuple)]

            if not allowed_indices:
                continue

            for index in allowed_indices:
                all_arguments = []
                allowed_applied_as_value = False  # Flag to check if there are any allowed references

                for id, (type_, subset, source, restriction) in enumerate(
                        zip(types, subsets, combination, restrictions)):

                    if not isinstance(type_, list):
                        if id == index and isinstance(source, tuple):
                            argument = generator.Argument()
                            # Handle allowed values
                            argument.configure_generation(type_, subset, source[1], restriction, ignore_allowed=True)
                            val = argument.get()
                        else:
                            argument = generator.Argument()
                            # Handle regular values
                            if isinstance(source, tuple):
                                argument = generator.Argument(source[0])
                                argument.configure_generation(type_, subset, source[1], restriction)
                            else:
                                argument.configure_generation(type_, subset, source, restriction)
                            val = argument.get()

                        if id in forbidden and isinstance(val, dict) and "name" in val:
                            # Handle forbidden values as references
                            if val["value"] not in forbidden[id]:
                                all_arguments.append(f"${val['name']}")
                        elif id in forbidden and val not in forbidden[id]:
                            all_arguments.append(val)
                        elif argument.is_reference(val):
                            all_arguments.append(f"${val['name']}")
                        else:
                            all_arguments.append(val)
                            if id == index and isinstance(source, tuple):
                                allowed_applied_as_value = True

                if not allowed_applied_as_value:
                    all_arguments.clear()

                if all_arguments:
                    if self.parser.has_target_field():
                        target_field_type = self.parser.get_target_field_type()
                        if not isinstance(target_field_type, list):
                            argument = generator.Argument()
                            argument.configure_target_field(
                                self.parser.get_target_field_type(),
                                self.parser.get_target_field_subset())
                            self.create_asset_for_buildtime(all_arguments, argument.get())
                        else:
                            for tft in target_field_type:
                                target_field_subset = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(tft)
                                for tfs in target_field_subset:
                                    argument = generator.Argument()
                                    argument.configure_target_field(tft, tfs)
                                    self.create_asset_for_buildtime(all_arguments, argument.get())
                    else:
                        self.create_asset_for_buildtime(all_arguments)
                    self.push_test_data_for_buildtime(description, skip_tag="allowed")

    def different_allowed_values_with_various_types(self):
        types = self.parser.get_types()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        description = "generate a different value allowed than the one defined in the argument"

        template = generator.Template(self.parser)

        for combination in template.generate_template():
            allowed_indices = [i for i, source in enumerate(combination) if isinstance(source, tuple)]

            if not allowed_indices:
                continue

            for index in allowed_indices:
                all_arguments = []
                allowed_applied_as_value = False  # Flag to check if there are any allowed references

                for id, (type_, source, restriction) in enumerate(zip(types, combination, restrictions)):
                    argument = generator.Argument()

                    if isinstance(type_, list):
                        type_, subset = type_[0], generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[0]

                        if id == index and isinstance(source, tuple):
                            # Handle allowed values
                            argument.configure_generation(type_, subset, source[1], restriction, ignore_allowed=True)
                            val = argument.get()
                        else:
                            # Handle regular values
                            argument.configure_generation(type_, subset, source, restriction)
                            val = argument.get()

                        if id in forbidden and isinstance(val, dict) and "name" in val:
                            # Handle forbidden values as references
                            if val["value"] not in forbidden[id]:
                                all_arguments.append(f"${val['name']}")
                        elif id in forbidden and val not in forbidden[id]:
                            all_arguments.append(val)
                        elif argument.is_reference(val):
                            all_arguments.append(f"${val['name']}")
                        else:
                            all_arguments.append(val)
                            if id == index and isinstance(source, tuple):
                                allowed_applied_as_value = True

                if not allowed_applied_as_value:
                    all_arguments.clear()

                if all_arguments:
                    if self.parser.has_target_field():
                        argument = generator.Argument()
                        argument.configure_target_field(
                            self.parser.get_target_field_type(),
                            self.parser.get_target_field_subset())
                        self.create_asset_for_buildtime(all_arguments, argument.get())
                    else:
                        self.create_asset_for_buildtime(all_arguments)
                    self.push_test_data_for_buildtime(description, skip_tag="allowed")

    def different_allowed_references(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        description = "generate a different reference allowed than the one defined in the argument"

        template = generator.Template(self.parser)

        if any(isinstance(t, list) for t in types):
            return

        for combination in template.generate_template():
            allowed_indices = [i for i, source in enumerate(combination) if isinstance(source, tuple)]

            if not allowed_indices:
                continue

            for index in allowed_indices:
                all_arguments = []
                input = {}
                allowed_applied_as_reference = False  # Flag to check if there are any allowed references

                for id, (type_, subset, source, restriction) in enumerate(
                        zip(types, subsets, combination, restrictions)):

                    if not isinstance(type_, list):
                        if id == index and isinstance(source, tuple):
                            if source[1] == "value":
                                argument = generator.Argument(source[0])
                                argument.configure_generation(type_, subset, source[1], restriction)
                            else:
                                argument = generator.Argument()
                                argument.configure_generation(
                                    type_, subset, source[1],
                                    restriction, ignore_allowed=True)
                                allowed_applied_as_reference = True
                        else:
                            # Handle regular values
                            if isinstance(source, tuple):
                                argument = generator.Argument(source[0])
                                argument.configure_generation(type_, subset, source[1], restriction)
                            else:
                                argument = generator.Argument()
                                argument.configure_generation(type_, subset, source, restriction)

                        val = argument.get()
                        if id in forbidden and isinstance(val, dict) and "name" in val:
                            # Handle forbidden values as references
                            if val["value"] not in forbidden[id]:
                                input[f"{val['name']}"] = val['value']
                                all_arguments.append(f"$eventJson.{val['name']}")
                        elif id in forbidden and val not in forbidden[id]:
                            all_arguments.append(val)
                        elif argument.is_reference(val):
                            input[f"{val['name']}"] = val['value']
                            all_arguments.append(f"$eventJson.{val['name']}")
                        else:
                            all_arguments.append(val)

                if not allowed_applied_as_reference:
                    all_arguments.clear()

                if all_arguments:
                    if self.parser.has_target_field():
                        target_field_type = self.parser.get_target_field_type()
                        if not isinstance(target_field_type, list):
                            argument = generator.Argument()
                            argument.configure_target_field(
                                self.parser.get_target_field_type(),
                                self.parser.get_target_field_subset())
                            self.create_asset_for_runtime(all_arguments, argument.get())
                        else:
                            for tft in target_field_type:
                                target_field_subset = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(tft)
                                for tfs in target_field_subset:
                                    argument = generator.Argument()
                                    argument.configure_target_field(tft, tfs)
                                    self.create_asset_for_runtime(all_arguments, argument.get())
                    else:
                        self.create_asset_for_runtime(all_arguments)
                    self.push_test_data_for_runtime(input, description)

    def generate_general_value_restrictions(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "Generate restrictions of value type"

        template = generator.Template(self.parser)

        for combination in template.generate_exception_arguments():
            all_arguments = []
            restrictions_applied_as_value = False

            for id, (type_, subset, source, restriction) in enumerate(zip(types, subsets, combination, restrictions)):
                if not isinstance(type_, list):
                    if type(source) is not tuple:
                        argument = generator.Argument()
                        argument.configure_generation(type_, subset, source, restriction)
                        val = argument.get()
                        if id in forbidden:
                            if isinstance(val, dict):
                                if "name" in val:  # is a reference
                                    if val["value"] not in forbidden[id]:
                                        all_arguments.append(f"${val['name']}")
                            elif val not in forbidden[id]:
                                all_arguments.append(val)
                        else:
                            if argument.is_reference(val):
                                all_arguments.append(f"${val['name']}")
                            else:
                                all_arguments.append(val)
                    else:
                        argument = generator.Argument(source[0])
                        argument.configure_generation(type_, subset, source[1], restriction)
                        argument.set_general_restrictions(general_restrictions)

                        val = argument.get()
                        if argument.is_reference(val):
                            restrictions_applied_as_value = False
                            all_arguments.append(f"${val['name']}")
                        else:
                            restrictions_applied_as_value = True
                            all_arguments.append(val)

            if not restrictions_applied_as_value:
                all_arguments.clear()

            if len(all_arguments) != 0:
                if self.parser.has_target_field():
                    argument = generator.Argument()
                    argument.configure_target_field(
                        self.parser.get_target_field_type(),
                        self.parser.get_target_field_subset())
                    self.create_asset_for_buildtime(all_arguments, argument.get())
                else:
                    self.create_asset_for_buildtime(all_arguments)
                self.push_test_data_for_buildtime(description)

    def generate_general_reference_restrictions(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "Generate restrictions of reference type"

        template = generator.Template(self.parser)

        for combination in template.generate_exception_arguments():
            all_arguments = []
            input = {}
            restrictions_applied_as_reference = False

            for id, (type_, subset, source, restriction) in enumerate(zip(types, subsets, combination, restrictions)):
                if not isinstance(type_, list):
                    if type(source) is not tuple:
                        argument = generator.Argument()
                        argument.configure_generation(type_, subset, source, restriction)
                        val = argument.get()
                        if id in forbidden:
                            if argument.is_reference(val):
                                if val["value"] not in forbidden[id]:
                                    input[f"{val['name']}"] = val['value']
                                    all_arguments.append(f"$eventJson.{val['name']}")
                            elif val not in forbidden[id]:
                                all_arguments.append(val)
                        else:
                            if argument.is_reference(val):
                                input[f"{val['name']}"] = val['value']
                                all_arguments.append(f"$eventJson.{val['name']}")
                            else:
                                all_arguments.append(val)
                    else:
                        argument = generator.Argument(source[0])
                        argument.configure_generation(type_, subset, source[1], restriction)
                        argument.set_general_restrictions(general_restrictions)

                        val = argument.get()
                        if argument.is_reference(val):
                            input[f"{val['name']}"] = val['value']
                            all_arguments.append(f"$eventJson.{val['name']}")
                            restrictions_applied_as_reference = True
                        else:
                            all_arguments.append(val)

            if not restrictions_applied_as_reference:
                all_arguments.clear()

            if len(all_arguments) != 0:
                if self.parser.has_target_field():
                    argument = generator.Argument()
                    argument.configure_target_field(
                        self.parser.get_target_field_type(),
                        self.parser.get_target_field_subset())
                    self.create_asset_for_runtime(all_arguments, argument.get())
                else:
                    self.create_asset_for_runtime(all_arguments)
                self.push_test_data_for_runtime(input, description)

    def different_target_field_type(self):
        if not self.parser.has_target_field():
            return

        target_field_type = self.parser.get_target_field_type()
        if isinstance(target_field_type, list):
            return

        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "Generate target field with different type"

        template = generator.Template(self.parser)
        for combination in template.generate_template():
            all_arguments = []
            input = {}
            for id, (type_, subset, source, restriction) in enumerate(
                    zip(types, subsets, combination, restrictions)):
                if not isinstance(type_, list):
                    if type(source) is not tuple:  # means this is an allowed restriction
                        argument = generator.Argument()
                        argument.configure_generation(type_, subset, source, restriction)
                        val = argument.get()
                        if id in forbidden:
                            if isinstance(val, dict):
                                if "name" in val:  # is a reference
                                    if val["value"] not in forbidden[id]:
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(f"$eventJson.{val['name']}")
                            elif val not in forbidden[id]:
                                all_arguments.append(val)
                        else:
                            if argument.is_reference(val):
                                input[f"{val['name']}"] = val['value']
                                all_arguments.append(f"$eventJson.{val['name']}")
                            else:
                                all_arguments.append(val)
                    else:
                        argument = generator.Argument(source[0])
                        argument.configure_generation(type_, subset, source[1], restriction)
                        val = argument.get()
                        if argument.is_reference(val):
                            input[f"{val['name']}"] = val['value']
                            all_arguments.append(f"$eventJson.{val['name']}")
                        else:
                            all_arguments.append(val)

            if len(all_arguments) != len(combination):
                all_arguments.clear()

            if len(all_arguments) != 0:
                if generator.check_restrictions(all_arguments, general_restrictions, input):
                    all_arguments.clear()

            if len(all_arguments) != 0 and self.parser.get_minimum_arguments() != 0:
                altered_types = generator.change_type(target_field_type)
                for new_type, new_subsets in altered_types.items():
                    for new_subset in new_subsets:
                        argument = generator.Argument()
                        argument.configure_target_field(new_type, new_subset)
                        val = argument.get(is_target_field=True)
                        self.create_asset_for_runtime(all_arguments, val)
                        if input:
                            self.push_test_data_for_runtime(input, description, skip_tag="different_target_field_type")
                        else:
                            self.push_test_data_for_runtime({}, description, skip_tag="different_target_field_type")

    def different_target_field_type_with_various_types(self):
        if not self.parser.has_target_field():
            return

        target_field_type = self.parser.get_target_field_type()
        if isinstance(target_field_type, list):
            if len(target_field_type) == 5:
                return

        types = self.parser.get_types()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "Generate target field with different type"

        template = generator.Template(self.parser)
        for combination in template.generate_template():
            all_arguments = []
            input = {}
            for id, (type_, source, restriction) in enumerate(
                    zip(types, combination, restrictions)):
                if isinstance(type_, list):
                    for internal_type in type_:
                        for new_subset in generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(internal_type):
                            all_arguments = []
                            input = {}
                            for _ in enumerate(types):
                                if type(source) is not tuple:  # means this is an allowed restriction
                                    argument = generator.Argument()
                                    argument.configure_generation(internal_type, new_subset, source, restriction)
                                    val = argument.get()
                                    if id in forbidden:
                                        if isinstance(val, dict):
                                            if "name" in val:  # is a reference
                                                if val["value"] not in forbidden[id]:
                                                    input[f"{val['name']}"] = val['value']
                                                    all_arguments.append(f"$eventJson.{val['name']}")
                                        elif val not in forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            input[f"{val['name']}"] = val['value']
                                            all_arguments.append(f"$eventJson.{val['name']}")
                                        else:
                                            all_arguments.append(val)
                                else:
                                    argument = generator.Argument(source[0])
                                    argument.configure_generation(internal_type, new_subset, source[1], restriction)
                                    val = argument.get()
                                    if argument.is_reference(val):
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(f"$eventJson.{val['name']}")
                                    else:
                                        all_arguments.append(val)

                            if len(all_arguments) != len(combination):
                                all_arguments.clear()

                            if len(all_arguments) != 0:
                                if generator.check_restrictions(all_arguments, general_restrictions, input):
                                    all_arguments.clear()

                            if len(all_arguments) != 0 and self.parser.get_minimum_arguments() != 0:
                                altered_types = generator.change_type(target_field_type)
                                for new_type, new_subsets in altered_types.items():
                                    for new_subset in new_subsets:
                                        argument = generator.Argument()
                                        argument.configure_target_field(new_type, new_subset)
                                        val = argument.get(is_target_field=True)
                                        self.create_asset_for_runtime(all_arguments, val)
                                        if input:
                                            self.push_test_data_for_runtime(
                                                input, description, skip_tag="different_target_field_type")
                                        else:
                                            self.push_test_data_for_runtime(
                                                {}, description, skip_tag="different_target_field_type")

    def success_cases(self):
        types = self.parser.get_types()
        subsets = self.parser.get_subset()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "Generate success cases"

        template = generator.Template(self.parser)
        for combination in template.generate_template():
            all_arguments = []
            input = {}
            for id, (type_, subset, source, restriction) in enumerate(
                    zip(types, subsets, combination, restrictions)):
                if not isinstance(type_, list):
                    if type(source) is not tuple:  # means this is an allowed restriction
                        argument = generator.Argument()
                        argument.configure_generation(type_, subset, source, restriction)
                        val = argument.get()
                        if id in forbidden:
                            if isinstance(val, dict):
                                if "name" in val:  # is a reference
                                    if val["value"] not in forbidden[id]:
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(f"$eventJson.{val['name']}")
                            elif val not in forbidden[id]:
                                all_arguments.append(val)
                        else:
                            if argument.is_reference(val):
                                input[f"{val['name']}"] = val['value']
                                all_arguments.append(f"$eventJson.{val['name']}")
                            else:
                                all_arguments.append(val)
                    else:
                        argument = generator.Argument(source[0])
                        argument.configure_generation(type_, subset, source[1], restriction)
                        val = argument.get()
                        if argument.is_reference(val):
                            input[f"{val['name']}"] = val['value']
                            all_arguments.append(f"$eventJson.{val['name']}")
                        else:
                            all_arguments.append(val)

            if len(all_arguments) != len(combination):
                all_arguments.clear()

            if len(all_arguments) != 0:
                if generator.check_restrictions(all_arguments, general_restrictions, input):
                    all_arguments.clear()

            if len(all_arguments) != 0 and self.parser.get_minimum_arguments() != 0:
                if self.helper_type == "map":
                    self.create_asset_for_runtime(all_arguments)
                    self.push_test_data_for_runtime(input, description, should_pass=True, skip_tag="success_cases")
                else:
                    target_field_type = self.parser.get_target_field_type()
                    if isinstance(target_field_type, list):
                        for tft in target_field_type:
                            target_field_subset = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(tft)
                            for tfs in target_field_subset:
                                argument = generator.Argument()
                                argument.configure_target_field(tft, tfs)
                                self.create_asset_for_runtime(all_arguments, argument.get(is_target_field=True))
                                self.push_test_data_for_runtime(
                                    input, description, should_pass=True, skip_tag="success_cases")
                    else:
                        argument = generator.Argument()
                        argument.configure_target_field(target_field_type, self.parser.get_target_field_subset())
                        self.create_asset_for_runtime(all_arguments, argument.get(is_target_field=True))
                        self.push_test_data_for_runtime(
                            input, description, should_pass=True, skip_tag="success_cases")

    def success_cases_with_various_types(self):
        types = self.parser.get_types()
        restrictions = self.parser.get_restrictions()
        forbidden = self.parser.get_forbidden_in_dict_format()
        general_restrictions = self.parser.get_general_restrictions()
        description = "Generate success cases"

        template = generator.Template(self.parser)
        for combination in template.generate_template():
            for id, (type_, source, restriction) in enumerate(
                    zip(types, combination, restrictions)):
                if isinstance(type_, list):
                    for internal_type in type_:
                        for new_subset in generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(internal_type):
                            all_arguments = []
                            input = {}
                            for _ in enumerate(types):
                                if type(source) is not tuple:  # means this is an allowed restriction
                                    argument = generator.Argument()
                                    argument.configure_generation(internal_type, new_subset, source, restriction)
                                    val = argument.get()
                                    if id in forbidden:
                                        if isinstance(val, dict):
                                            if "name" in val:  # is a reference
                                                if val["value"] not in forbidden[id]:
                                                    input[f"{val['name']}"] = val['value']
                                                    all_arguments.append(f"$eventJson.{val['name']}")
                                        elif val not in forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            input[f"{val['name']}"] = val['value']
                                            all_arguments.append(f"$eventJson.{val['name']}")
                                        else:
                                            all_arguments.append(val)
                                else:
                                    argument = generator.Argument(source[0])
                                    argument.configure_generation(internal_type, new_subset, source[1], restriction)
                                    val = argument.get()
                                    if argument.is_reference(val):
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(f"$eventJson.{val['name']}")
                                    else:
                                        all_arguments.append(val)

                            if len(all_arguments) != len(combination):
                                all_arguments.clear()

                            if len(all_arguments) != 0:
                                if generator.check_restrictions(all_arguments, general_restrictions):
                                    all_arguments.clear()

                            if len(all_arguments) != 0 and self.parser.get_minimum_arguments() != 0:
                                if self.helper_type == "map":
                                    self.create_asset_for_runtime(all_arguments)
                                    self.push_test_data_for_runtime(
                                        input, description, should_pass=True, skip_tag="success_cases")
                                else:
                                    target_field_type = self.parser.get_target_field_type()
                                    if isinstance(target_field_type, list):
                                        for tft in target_field_type:
                                            target_field_subset = generator.CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(tft)
                                            for tfs in target_field_subset:
                                                argument = generator.Argument()
                                                argument.configure_target_field(tft, tfs)
                                                self.create_asset_for_runtime(all_arguments, argument.get(
                                                    is_target_field=True))
                                                self.push_test_data_for_runtime(
                                                    input, description, should_pass=True, skip_tag="success_cases")
                                    else:
                                        argument = generator.Argument()
                                        argument.configure_target_field(
                                            target_field_type, self.parser.get_target_field_subset())
                                        self.create_asset_for_runtime(all_arguments, argument.get(is_target_field=True))
                                        self.push_test_data_for_runtime(
                                            input, description, should_pass=True, skip_tag="success_cases")

    def generate_unit_test(self):
        if self.parser.get_tests() == None:
            return

        template = generator.Template(self.parser)

        for number_test, test in enumerate(self.parser.get_tests()):
            arguments_list = list(test["arguments"].items())
            sources = self.parser.get_sources()
            # Check variadic
            if not self.parser.is_variadic():
                if self.parser.get_minimum_arguments() + 1 < len(arguments_list):
                    sys.exit(
                        f"Helper {self.parser.get_name()} has an error in test number '{number_test + 1}': it is not a variadic function")

            if self.parser.get_minimum_arguments() < len(arguments_list):
                diff = len(arguments_list) - self.parser.get_minimum_arguments()
                for _ in range(diff):
                    if len(sources) != 0:
                        sources.append(sources[-1])
                    else:
                        sources.append("value")

            for case in template.generate_raw_template(sources):
                if not any(isinstance(item[1], dict) and ("source" in item[1]) for item in arguments_list):
                    combined = list(itertools.zip_longest(arguments_list, case, fillvalue=None))
                    all_arguments = []
                    input = {}
                    for (id, value), source in combined:
                        target_field_value = None
                        if id != "target_field":
                            argument = generator.Argument(value)
                            argument.configure_only_value(source)
                            val = argument.get()

                            if argument.is_reference(val):
                                input[f"{val['name']}"] = val['value']
                                all_arguments.append(f"$eventJson.{val['name']}")
                            elif source == "value":
                                all_arguments.append(val)
                        else:
                            if isinstance(value, list):
                                target_field_value = list(value)
                            else:
                                target_field_value = value

                    self.create_asset_for_runtime(all_arguments, target_field_value)
                    self.push_test_data_for_runtime_deprecated(
                        input, test["description"],
                        should_pass=test["should_pass"],
                        skip=test.get("skipped", False),
                        expected=test.get("expected", None))

        for test in self.parser.get_tests():
            arguments_list = list(test["arguments"].items())
            if any(isinstance(item[1], dict) for item in arguments_list):
                all_arguments = []
                input = {}
                for id, data in arguments_list:
                    if isinstance(data, dict) and "source" in data:
                        argument = generator.Argument(data["value"])
                        argument.configure_only_value(data["source"])
                        val = argument.get()
                        if argument.is_reference(val):
                            if val['value'] != None:
                                input[f"{val['name']}"] = val['value']
                            all_arguments.append(f"$eventJson.{val['name']}")
                        else:
                            all_arguments.append(val)
                    else:
                        if isinstance(data, list):
                            target_field_value = list(data)
                        else:
                            target_field_value = data

                if len(all_arguments) == 0:
                    break

                self.create_asset_for_runtime(all_arguments, target_field_value)
                self.push_test_data_for_runtime_deprecated(
                    input, test["description"],
                    should_pass=test["should_pass"],
                    skip=test.get("skipped", False),
                    expected=test.get("expected", None))

    def generate_output_file(self, helper_type):
        self.helper_type = helper_type
        for valid_data in self.validator.get_all_valid_data():
            self.parser.load_yaml_from_dict(valid_data)
            self.fewer_arguments_than_the_minimum_required()
            self.more_or_less_arguments_according_to_variadic()
            self.different_sources()
            self.different_source_with_various_types()
            self.different_types_value()
            self.different_types_value_with_various_types()
            self.different_types_reference()
            self.different_types_reference_with_various_types()
            self.different_allowed_values()
            self.different_allowed_values_with_various_types()
            self.different_allowed_references()
            self.generate_general_value_restrictions()
            self.generate_general_reference_restrictions()
            self.different_target_field_type()
            self.different_target_field_type_with_various_types()
            self.success_cases()
            self.success_cases_with_various_types()
            self.generate_unit_test()
            output_file_path = self.output_directory / f"{self.parser.get_name()}.yml"
            self.tests["helper_type"] = helper_type
            with open(output_file_path, "w") as file:
                yaml.dump(self.tests, file)

            self.tests["build_test"].clear()
            self.tests["run_test"].clear()


def main():
    args = parse_arguments()
    input_file = args.input_file
    helpers_type = ["map", "filter", "transformation"]

    current_directory = Path(__file__).resolve().parent

    for helper_type in helpers_type:
        output_directory = current_directory / helper_type / "outputs"
        output_directory.mkdir(parents=True, exist_ok=True)
        test_case_generator = TestCaseGenerator(current_directory / helper_type, output_directory, input_file)
        test_case_generator.clean_output_directory()
        test_case_generator.scan_and_verify_all_files()
        test_case_generator.generate_output_file(helper_type)


if __name__ == "__main__":
    main()
