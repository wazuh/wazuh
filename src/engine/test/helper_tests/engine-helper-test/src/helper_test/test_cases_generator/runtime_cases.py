#!/usr/bin/env python3

from helper_test.definition_types.types import *
from helper_test.definition_types.utils import *
from helper_test.test_cases_generator.argument import Argument
from helper_test.test_cases_generator.template import Template
from helper_test.test_cases_generator.parser import Parser
from helper_test.test_cases_generator.test_data import TestData
import itertools


class RuntimeCases:
    def __init__(self, test_data: TestData):
        self.test_data = test_data

    def set_parser(self, parser: Parser):
        self.parser = parser
        self.types = parser.get_types()
        self.subsets = parser.get_subset()
        self.sources = parser.get_sources()
        self.restrictions = parser.get_restrictions()
        self.forbidden = parser.get_forbidden_in_dict_format()
        self.general_restrictions = parser.get_general_restrictions()
        self.helper_type = parser.get_helper_type()

    def different_types_reference(self):
        description = "generate a different type in references than the one defined in the argument"

        template = Template(self.parser)
        for combination in template.generate_template():
            for i, original_type in enumerate(self.types):
                if not isinstance(original_type, list):
                    altered_types = change_type(original_type)
                    for new_type, new_subsets in altered_types.items():
                        for new_subset in new_subsets:
                            all_arguments = []
                            input = {}
                            for id, (type_, subset, source, restriction) in enumerate(
                                    zip(self.types, self.subsets, combination, self.restrictions)):
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

                                # means this is an allowed restriction
                                if type(source) is not tuple:
                                    argument = Argument()
                                    if isinstance(type_, list):
                                        if len(type_) == 5:
                                            continue
                                    argument.configure_generation(
                                        type_, subset, source, restriction)
                                    val = argument.get()
                                    if id in self.forbidden:
                                        if isinstance(val, dict):
                                            if "name" in val:  # is a reference
                                                if val["value"] not in self.forbidden[id]:
                                                    input[f"{val['name']}"] = val['value']
                                                    all_arguments.append(
                                                        f"$eventJson.{val['name']}")
                                        elif val not in self.forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            input[f"{val['name']}"] = val['value']
                                            all_arguments.append(
                                                f"$eventJson.{val['name']}")
                                        else:
                                            all_arguments.append(val)
                                else:
                                    if id == i:
                                        argument = Argument()
                                        # It is also configured to verify that the allowed matches the argument declaration.
                                        argument.configure_generation(
                                            type_, subset, source[1],
                                            restriction, ignore_allowed=True)
                                    else:
                                        argument = Argument(source[0])
                                        argument.configure_generation(
                                            type_, subset, source[1], restriction)
                                    val = argument.get()
                                    if argument.is_reference(val):
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(
                                            f"$eventJson.{val['name']}")
                                    else:
                                        all_arguments.append(val)

                            if len(all_arguments) != len(combination):
                                all_arguments.clear()

                            if len(all_arguments) != 0:
                                if check_restrictions(all_arguments, self.general_restrictions):
                                    all_arguments.clear()

                            if len(all_arguments) != 0:
                                if self.parser.has_target_field():
                                    target_field_type = self.parser.get_target_field_type()
                                    if not isinstance(target_field_type, list):
                                        argument = Argument()
                                        argument.configure_target_field(
                                            self.parser.get_target_field_type(),
                                            self.parser.get_target_field_subset())
                                        self.test_data.create_asset_for_runtime(
                                            all_arguments, argument.get())
                                    else:
                                        for tft in target_field_type:
                                            target_field_subset = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                                                tft)
                                            for tfs in target_field_subset:
                                                argument = Argument()
                                                argument.configure_target_field(
                                                    tft, tfs)
                                                self.test_data.create_asset_for_runtime(
                                                    all_arguments, argument.get())
                                else:
                                    self.test_data.create_asset_for_runtime(
                                        all_arguments)
                                self.test_data.push_test_data_for_runtime(
                                    input, description, skip_tag="different_type")

    def different_types_reference_with_various_types(self):
        description = "generate a different type in references than the one defined in the argument"

        template = Template(self.parser)
        for combination in template.generate_template():
            for i, original_type in enumerate(self.types):
                if isinstance(original_type, list):
                    altered_types = change_type(original_type)
                    for new_type, new_subsets in altered_types.items():
                        for new_subset in new_subsets:
                            all_arguments = []
                            input = {}
                            for id, (type_, subset, source, restriction) in enumerate(
                                    zip(self.types, self.subsets, combination, self.restrictions)):
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

                                # means this is an allowed restriction
                                if type(source) is not tuple:
                                    argument = Argument()
                                    if isinstance(type_, list):
                                        argument.configure_generation(
                                            type_[0],
                                            CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[
                                                0],
                                            source, restriction)
                                    else:
                                        argument.configure_generation(
                                            type_, subset, source, restriction)
                                    val = argument.get()
                                    if id in self.forbidden:
                                        if isinstance(val, dict):
                                            if "name" in val:  # is a reference
                                                if val["value"] not in self.forbidden[id]:
                                                    input[f"{val['name']}"] = val['value']
                                                    all_arguments.append(
                                                        f"$eventJson.{val['name']}")
                                        elif val not in self.forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            input[f"{val['name']}"] = val['value']
                                            all_arguments.append(
                                                f"$eventJson.{val['name']}")
                                        else:
                                            all_arguments.append(val)
                                else:
                                    if id == i:
                                        argument = Argument()
                                        # It is also configured to verify that the allowed matches the argument declaration.
                                        if isinstance(type_, list):
                                            argument.configure_generation(
                                                type_[0],
                                                CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[
                                                    0],
                                                source[1],
                                                restriction, ignore_allowed=True)
                                        else:
                                            argument.configure_generation(
                                                type_, subset, source[1],
                                                restriction, ignore_allowed=True)
                                    else:
                                        argument = Argument(source[0])
                                        if isinstance(type_, list):
                                            argument.configure_generation(
                                                type_[0],
                                                CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[
                                                    0],
                                                source[1],
                                                restriction)
                                        else:
                                            argument.configure_generation(
                                                type_, subset, source[1], restriction)
                                    val = argument.get()
                                    if argument.is_reference(val):
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(
                                            f"$eventJson.{val['name']}")
                                    else:
                                        all_arguments.append(val)

                            if len(all_arguments) != len(combination):
                                all_arguments.clear()

                            if len(all_arguments) != 0:
                                if check_restrictions(all_arguments, self.general_restrictions):
                                    all_arguments.clear()

                            if len(all_arguments) != 0:
                                if self.parser.has_target_field():
                                    argument = Argument()
                                    argument.configure_target_field(
                                        self.parser.get_target_field_type(),
                                        self.parser.get_target_field_subset())
                                    self.test_data.create_asset_for_runtime(
                                        all_arguments, argument.get())
                                else:
                                    self.test_data.create_asset_for_runtime(
                                        all_arguments)
                                self.test_data.push_test_data_for_runtime(
                                    input, description, skip_tag="different_type")

    def different_allowed_references(self):
        description = "generate a different reference allowed than the one defined in the argument"

        template = Template(self.parser)

        if any(isinstance(t, list) for t in self.types):
            return

        for combination in template.generate_template():
            allowed_indices = [i for i, source in enumerate(
                combination) if isinstance(source, tuple)]

            if not allowed_indices:
                continue

            for index in allowed_indices:
                all_arguments = []
                input = {}
                # Flag to check if there are any allowed references
                allowed_applied_as_reference = False

                for id, (type_, subset, source, restriction) in enumerate(
                        zip(self.types, self.subsets, combination, self.restrictions)):

                    if not isinstance(type_, list):
                        if id == index and isinstance(source, tuple):
                            if source[1] == "value":
                                argument = Argument(source[0])
                                argument.configure_generation(
                                    type_, subset, source[1], restriction)
                            else:
                                argument = Argument()
                                argument.configure_generation(
                                    type_, subset, source[1],
                                    restriction, ignore_allowed=True)
                                allowed_applied_as_reference = True
                        else:
                            # Handle regular values
                            if isinstance(source, tuple):
                                argument = Argument(source[0])
                                argument.configure_generation(
                                    type_, subset, source[1], restriction)
                            else:
                                argument = Argument()
                                argument.configure_generation(
                                    type_, subset, source, restriction)

                        val = argument.get()
                        if id in self.forbidden and isinstance(val, dict) and "name" in val:
                            # Handle forbidden values as references
                            if val["value"] not in self.forbidden[id]:
                                input[f"{val['name']}"] = val['value']
                                all_arguments.append(
                                    f"$eventJson.{val['name']}")
                        elif id in self.forbidden and val not in self.forbidden[id]:
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
                            argument = Argument()
                            argument.configure_target_field(
                                self.parser.get_target_field_type(),
                                self.parser.get_target_field_subset())
                            self.test_data.create_asset_for_runtime(
                                all_arguments, argument.get())
                        else:
                            for tft in target_field_type:
                                target_field_subset = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                                    tft)
                                for tfs in target_field_subset:
                                    argument = Argument()
                                    argument.configure_target_field(tft, tfs)
                                    self.test_data.create_asset_for_runtime(
                                        all_arguments, argument.get())
                    else:
                        self.test_data.create_asset_for_runtime(all_arguments)
                    self.test_data.push_test_data_for_runtime(
                        input, description)

    def generate_general_reference_restrictions(self):
        description = "Generate restrictions of reference type"

        template = Template(self.parser)

        for combination in template.generate_exception_arguments():
            all_arguments = []
            input = {}
            restrictions_applied_as_reference = False

            for id, (type_, subset, source, restriction) in enumerate(
                    zip(self.types, self.subsets, combination, self.restrictions)):
                if not isinstance(type_, list):
                    if type(source) is not tuple:
                        argument = Argument()
                        argument.configure_generation(
                            type_, subset, source, restriction)
                        val = argument.get()
                        if id in self.forbidden:
                            if argument.is_reference(val):
                                if val["value"] not in self.forbidden[id]:
                                    input[f"{val['name']}"] = val['value']
                                    all_arguments.append(
                                        f"$eventJson.{val['name']}")
                            elif val not in self.forbidden[id]:
                                all_arguments.append(val)
                        else:
                            if argument.is_reference(val):
                                input[f"{val['name']}"] = val['value']
                                all_arguments.append(
                                    f"$eventJson.{val['name']}")
                            else:
                                all_arguments.append(val)
                    else:
                        argument = Argument(source[0])
                        argument.configure_generation(
                            type_, subset, source[1], restriction)
                        argument.set_general_restrictions(
                            self.general_restrictions)

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
                    argument = Argument()
                    argument.configure_target_field(
                        self.parser.get_target_field_type(),
                        self.parser.get_target_field_subset())
                    self.test_data.create_asset_for_runtime(
                        all_arguments, argument.get())
                else:
                    self.test_data.create_asset_for_runtime(all_arguments)
                self.test_data.push_test_data_for_runtime(input, description)

    def different_target_field_type(self):
        if not self.parser.has_target_field():
            return

        target_field_type = self.parser.get_target_field_type()
        if isinstance(target_field_type, list):
            return

        description = "Generate target field with different type"

        template = Template(self.parser)
        for combination in template.generate_template():
            all_arguments = []
            input = {}
            for id, (type_, subset, source, restriction) in enumerate(
                    zip(self.types, self.subsets, combination, self.restrictions)):
                if not isinstance(type_, list):
                    if type(source) is not tuple:  # means this is an allowed restriction
                        argument = Argument()
                        argument.configure_generation(
                            type_, subset, source, restriction)
                        val = argument.get()
                        if id in self.forbidden:
                            if isinstance(val, dict):
                                if "name" in val:  # is a reference
                                    if val["value"] not in self.forbidden[id]:
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(
                                            f"$eventJson.{val['name']}")
                            elif val not in self.forbidden[id]:
                                all_arguments.append(val)
                        else:
                            if argument.is_reference(val):
                                input[f"{val['name']}"] = val['value']
                                all_arguments.append(
                                    f"$eventJson.{val['name']}")
                            else:
                                all_arguments.append(val)
                    else:
                        argument = Argument(source[0])
                        argument.configure_generation(
                            type_, subset, source[1], restriction)
                        val = argument.get()
                        if argument.is_reference(val):
                            input[f"{val['name']}"] = val['value']
                            all_arguments.append(f"$eventJson.{val['name']}")
                        else:
                            all_arguments.append(val)

            if len(all_arguments) != len(combination):
                all_arguments.clear()

            if len(all_arguments) != 0:
                if check_restrictions(all_arguments, self.general_restrictions, input):
                    all_arguments.clear()

            if len(all_arguments) != 0 and self.parser.get_minimum_arguments() != 0:
                altered_types = change_type(target_field_type)
                for new_type, new_subsets in altered_types.items():
                    for new_subset in new_subsets:
                        argument = Argument()
                        argument.configure_target_field(new_type, new_subset)
                        val = argument.get(is_target_field=True)
                        self.test_data.create_asset_for_runtime(
                            all_arguments, val)
                        if input:
                            self.test_data.push_test_data_for_runtime(
                                input, description, skip_tag="different_target_field_type")
                        else:
                            self.test_data.push_test_data_for_runtime(
                                {}, description, skip_tag="different_target_field_type")

    def different_target_field_type_with_various_types(self):
        if not self.parser.has_target_field():
            return

        target_field_type = self.parser.get_target_field_type()
        if isinstance(target_field_type, list):
            if len(target_field_type) == 5:
                return

        description = "Generate target field with different type"

        template = Template(self.parser)
        for combination in template.generate_template():
            all_arguments = []
            input = {}
            for id, (type_, source, restriction) in enumerate(
                    zip(self.types, combination, self.restrictions)):
                if isinstance(type_, list):
                    for internal_type in type_:
                        for new_subset in CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(internal_type):
                            all_arguments = []
                            input = {}
                            for _ in enumerate(self.types):
                                # means this is an allowed restriction
                                if type(source) is not tuple:
                                    argument = Argument()
                                    argument.configure_generation(
                                        internal_type, new_subset, source, restriction)
                                    val = argument.get()
                                    if id in self.forbidden:
                                        if isinstance(val, dict):
                                            if "name" in val:  # is a reference
                                                if val["value"] not in self.forbidden[id]:
                                                    input[f"{val['name']}"] = val['value']
                                                    all_arguments.append(
                                                        f"$eventJson.{val['name']}")
                                        elif val not in self.forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            input[f"{val['name']}"] = val['value']
                                            all_arguments.append(
                                                f"$eventJson.{val['name']}")
                                        else:
                                            all_arguments.append(val)
                                else:
                                    argument = Argument(source[0])
                                    argument.configure_generation(
                                        internal_type, new_subset, source[1], restriction)
                                    val = argument.get()
                                    if argument.is_reference(val):
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(
                                            f"$eventJson.{val['name']}")
                                    else:
                                        all_arguments.append(val)

                            if len(all_arguments) != len(combination):
                                all_arguments.clear()

                            if len(all_arguments) != 0:
                                if check_restrictions(all_arguments, self.general_restrictions, input):
                                    all_arguments.clear()

                            if len(all_arguments) != 0 and self.parser.get_minimum_arguments() != 0:
                                altered_types = change_type(target_field_type)
                                for new_type, new_subsets in altered_types.items():
                                    for new_subset in new_subsets:
                                        argument = Argument()
                                        argument.configure_target_field(
                                            new_type, new_subset)
                                        val = argument.get(
                                            is_target_field=True)
                                        self.test_data.create_asset_for_runtime(
                                            all_arguments, val)
                                        if input:
                                            self.test_data.push_test_data_for_runtime(
                                                input, description, skip_tag="different_target_field_type")
                                        else:
                                            self.test_data.push_test_data_for_runtime(
                                                {}, description, skip_tag="different_target_field_type")

    def success_cases(self):
        description = "Generate success cases"
        template = Template(self.parser)

        for combination in template.generate_template():
            all_arguments = []
            input = {}
            for id, (type_, subset, source, restriction) in enumerate(
                    zip(self.types, self.subsets, combination, self.restrictions)):
                if not isinstance(type_, list):
                    if type(source) is not tuple:  # means this is an allowed restriction
                        argument = Argument()
                        argument.configure_generation(
                            type_, subset, source, restriction)
                        val = argument.get()
                        if id in self.forbidden:
                            if isinstance(val, dict):
                                if "name" in val:  # is a reference
                                    if val["value"] not in self.forbidden[id]:
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(
                                            f"$eventJson.{val['name']}")
                            elif val not in self.forbidden[id]:
                                all_arguments.append(val)
                        else:
                            if argument.is_reference(val):
                                input[f"{val['name']}"] = val['value']
                                all_arguments.append(
                                    f"$eventJson.{val['name']}")
                            else:
                                all_arguments.append(val)
                    else:
                        argument = Argument(source[0])
                        argument.configure_generation(
                            type_, subset, source[1], restriction)
                        val = argument.get()
                        if argument.is_reference(val):
                            input[f"{val['name']}"] = val['value']
                            all_arguments.append(f"$eventJson.{val['name']}")
                        else:
                            all_arguments.append(val)

            if len(all_arguments) != len(combination):
                all_arguments.clear()

            if len(all_arguments) != 0:
                if check_restrictions(all_arguments, self.general_restrictions, input):
                    all_arguments.clear()

            if len(all_arguments) != 0 and self.parser.get_minimum_arguments() != 0:
                if self.helper_type == "map":
                    self.test_data.create_asset_for_runtime(all_arguments)
                    self.test_data.push_test_data_for_runtime(
                        input, description, should_pass=True, skip_tag="success_cases")
                else:
                    target_field_type = self.parser.get_target_field_type()
                    if isinstance(target_field_type, list):
                        for tft in target_field_type:
                            target_field_subset = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                                tft)
                            for tfs in target_field_subset:
                                argument = Argument()
                                argument.configure_target_field(tft, tfs)
                                self.test_data.create_asset_for_runtime(
                                    all_arguments, argument.get(is_target_field=True))
                                self.test_data.push_test_data_for_runtime(
                                    input, description, should_pass=True, skip_tag="success_cases")
                    else:
                        argument = Argument()
                        argument.configure_target_field(
                            target_field_type, self.parser.get_target_field_subset())
                        self.test_data.create_asset_for_runtime(
                            all_arguments, argument.get(is_target_field=True))
                        self.test_data.push_test_data_for_runtime(
                            input, description, should_pass=True, skip_tag="success_cases")

    def success_cases_with_various_types(self):
        description = "Generate success cases"
        template = Template(self.parser)

        for combination in template.generate_template():
            for id, (type_, source, restriction) in enumerate(
                    zip(self.types, combination, self.restrictions)):
                if isinstance(type_, list):
                    for internal_type in type_:
                        for new_subset in CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(internal_type):
                            all_arguments = []
                            input = {}
                            for _ in enumerate(self.types):
                                # means this is an allowed restriction
                                if type(source) is not tuple:
                                    argument = Argument()
                                    argument.configure_generation(
                                        internal_type, new_subset, source, restriction)
                                    val = argument.get()
                                    if id in self.forbidden:
                                        if isinstance(val, dict):
                                            if "name" in val:  # is a reference
                                                if val["value"] not in self.forbidden[id]:
                                                    input[f"{val['name']}"] = val['value']
                                                    all_arguments.append(
                                                        f"$eventJson.{val['name']}")
                                        elif val not in self.forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            input[f"{val['name']}"] = val['value']
                                            all_arguments.append(
                                                f"$eventJson.{val['name']}")
                                        else:
                                            all_arguments.append(val)
                                else:
                                    argument = Argument(source[0])
                                    argument.configure_generation(
                                        internal_type, new_subset, source[1], restriction)
                                    val = argument.get()
                                    if argument.is_reference(val):
                                        input[f"{val['name']}"] = val['value']
                                        all_arguments.append(
                                            f"$eventJson.{val['name']}")
                                    else:
                                        all_arguments.append(val)

                            if len(all_arguments) != len(combination):
                                all_arguments.clear()

                            if len(all_arguments) != 0:
                                if check_restrictions(all_arguments, self.general_restrictions):
                                    all_arguments.clear()

                            if len(all_arguments) != 0 and self.parser.get_minimum_arguments() != 0:
                                if self.helper_type == "map":
                                    self.test_data.create_asset_for_runtime(
                                        all_arguments)
                                    self.test_data.push_test_data_for_runtime(
                                        input, description, should_pass=True, skip_tag="success_cases")
                                else:
                                    target_field_type = self.parser.get_target_field_type()
                                    if isinstance(target_field_type, list):
                                        for tft in target_field_type:
                                            target_field_subset = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                                                tft)
                                            for tfs in target_field_subset:
                                                argument = Argument()
                                                argument.configure_target_field(
                                                    tft, tfs)
                                                self.test_data.create_asset_for_runtime(
                                                    all_arguments, argument.get(is_target_field=True))
                                                self.test_data.push_test_data_for_runtime(
                                                    input, description, should_pass=True, skip_tag="success_cases")
                                    else:
                                        argument = Argument()
                                        argument.configure_target_field(
                                            target_field_type, self.parser.get_target_field_subset())
                                        self.test_data.create_asset_for_runtime(
                                            all_arguments, argument.get(is_target_field=True))
                                        self.test_data.push_test_data_for_runtime(
                                            input, description, should_pass=True, skip_tag="success_cases")

    def order_argument_list(self, argument_list) -> list:
        id_name_order = self.parser.get_name_id_arguments()

        ordered_arguments_list = sorted(
            [(k, v) for k, v in argument_list if k in id_name_order],
            key=lambda x: id_name_order[x[0]]
        )

        remaining_arguments = [
            (k, v) for k, v in argument_list if k not in id_name_order
        ]
        id_pattern = re.compile(r'_(\d+)$')
        valid_remaining_arguments = sorted(
            [(k, v, int(id_pattern.search(k).group(1)))
             for k, v in remaining_arguments if id_pattern.search(k)],
            key=lambda x: x[2]
        )

        return ordered_arguments_list + [(k, v) for k, v, _ in valid_remaining_arguments]

    def generate_unit_test(self):
        if self.parser.get_tests() == None:
            return

        template = Template(self.parser)
        arguments_list = []
        target_field_value = None

        for test in self.parser.get_tests():
            if "arguments" in test:
                arguments = list(test["arguments"].items())
                arguments_list = self.order_argument_list(arguments)
            sources = self.parser.get_sources()

            target_field = test.get("target_field", None)

            if self.parser.get_minimum_arguments() < len(arguments_list):
                diff = len(arguments_list) - \
                    self.parser.get_minimum_arguments()
                for _ in range(diff):
                    if len(sources) != 0:
                        sources.append(sources[-1])
                    else:
                        sources.append("value")

            for case in template.generate_raw_template(sources):
                if not any(isinstance(item[1], dict) and ("source" in item[1]) for item in arguments_list):
                    combined = list(itertools.zip_longest(
                        arguments_list, case, fillvalue=None))
                    all_arguments = []
                    input = {}
                    for (id, value), source in combined:
                        argument = Argument(value)
                        argument.configure_only_value(source)
                        val = argument.get()

                        if argument.is_reference(val):
                            input[f"{val['name']}"] = val['value']
                            all_arguments.append(f"$eventJson.{val['name']}")
                        elif source == "value":
                            all_arguments.append(val)

                    if target_field != None:
                        if isinstance(target_field, list):
                            target_field_value = list(target_field)
                        else:
                            target_field_value = target_field

                    self.test_data.create_asset_for_runtime(
                        all_arguments, target_field_value)
                    self.test_data.push_test_data_for_runtime_deprecated(
                        input, test["description"],
                        should_pass=test["should_pass"],
                        skip=test.get("skipped", False),
                        expected=test.get("expected", None))

        arguments_list = []
        for test in self.parser.get_tests():
            target_field = test.get("target_field", None)
            if "arguments" in test:
                arguments_list = list(test["arguments"].items())
            if any(isinstance(item[1], dict) for item in arguments_list):
                all_arguments = []
                input = {}
                for id, data in arguments_list:
                    if isinstance(data, dict) and "source" in data:
                        argument = Argument(data["value"])
                        argument.configure_only_value(data["source"])
                        val = argument.get()
                        if argument.is_reference(val):
                            if val['value'] != None:
                                input[f"{val['name']}"] = val['value']
                            all_arguments.append(f"$eventJson.{val['name']}")
                        else:
                            all_arguments.append(val)

                    if target_field != None:
                        if isinstance(target_field, list):
                            target_field_value = list(target_field)
                        else:
                            target_field_value = target_field

                if len(all_arguments) == 0:
                    break

                self.test_data.create_asset_for_runtime(
                    all_arguments, target_field_value)
                self.test_data.push_test_data_for_runtime_deprecated(
                    input, test["description"],
                    should_pass=test["should_pass"],
                    skip=test.get("skipped", False),
                    expected=test.get("expected", None))

    def runner(self):
        self.different_types_reference()
        self.different_types_reference_with_various_types()
        self.different_allowed_references()
        self.generate_general_reference_restrictions()
        self.different_target_field_type()
        self.different_target_field_type_with_various_types()
        self.success_cases()
        self.success_cases_with_various_types()
        self.generate_unit_test()
