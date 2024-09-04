#!/usr/bin/env python3

from helper_test.definition_types.types import *
from helper_test.definition_types.utils import *
from helper_test.test_cases_generator.argument import Argument
from helper_test.test_cases_generator.template import Template
from helper_test.test_cases_generator.parser import Parser
from helper_test.test_cases_generator.test_data import TestData
import json


class BuildtimeCases:
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

    def fewer_arguments_than_the_minimum_required(self):
        description = "Test with fewer parameters for helper function."
        minimum_arguments = self.parser.get_minimum_arguments()
        for num_arguments in range(minimum_arguments):
            parameters = [
                "0"
            ] * num_arguments  # Generate empty strings for the current number of arguments
            if self.parser.has_target_field():
                argument = Argument()
                target_field_type = self.parser.get_target_field_type()
                if isinstance(target_field_type, list):
                    for tft in target_field_type:
                        target_field_subtipe = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                            tft)
                        for tfs in target_field_subtipe:
                            argument.configure_target_field(tft, tfs)
                else:
                    argument.configure_target_field(
                        self.parser.get_target_field_type(),
                        self.parser.get_target_field_subset())
                self.test_data.create_asset_for_buildtime(
                    parameters, argument.get())
            else:
                self.test_data.create_asset_for_buildtime(parameters)
            self.test_data.push_test_data_for_buildtime(description)

    def more_or_less_arguments_according_to_variadic(self):
        all_arguments = []
        description = "Generate more arguments than the maximum allowed"
        val = None

        if self.parser.is_variadic():
            number_of_arguments = MAXIMUM_NUMBER_OF_ARGUMENTS + 1
        else:
            number_of_arguments = self.parser.get_minimum_arguments() + 1

        for i in range(number_of_arguments):
            if self.parser.get_minimum_arguments() == 0:
                argument = Argument("any_value")
                argument.configure_generation(list, str, "reference", [])
                val = argument.get()
            else:
                j = i % self.parser.get_minimum_arguments()
                argument = Argument()
                if not isinstance(self.types[j], list):
                    argument.configure_generation(
                        self.types[j], self.subsets[j], self.sources[j], [])
                    val = argument.get()

            if val != None:
                if argument.is_reference(val):
                    all_arguments.append(f"$eventJson.{val['name']}")
                else:
                    all_arguments.append(val)

        if self.parser.has_target_field():
            argument = Argument()
            if not isinstance(self.parser.get_target_field_type(), list):
                argument.configure_target_field(
                    self.parser.get_target_field_type(),
                    self.parser.get_target_field_subset())
            else:
                type_ = self.parser.get_target_field_type()[0]
                subset = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_)[0]
                argument.configure_target_field(
                    type_,
                    subset)
            self.test_data.create_asset_for_buildtime(
                all_arguments, argument.get())
        else:
            self.test_data.create_asset_for_buildtime(all_arguments)
        self.test_data.push_test_data_for_buildtime(description)

    def different_sources(self):
        description = "generate a different source than the one defined in the argument"

        for i in range(len(self.types)):
            # Copying the list of sources to not modify the original
            new_sources = self.sources[:]

            # Expected a success result if source is both
            if self.sources[i] == "both":
                continue

            # Changing the source for this argument
            new_source = change_source(self.sources[i])
            new_sources[i] = new_source  # Updating the new list of sources

            all_arguments = []
            for j in range(len(self.types)):
                if not isinstance(self.types[j], list):
                    argument = Argument()
                    argument.configure_generation(
                        self.types[j], self.subsets[j], new_sources[j], [])
                    arg = argument.get()
                    if argument.is_reference(arg):
                        all_arguments.append(f"$eventJson.{arg['name']}")
                    else:
                        all_arguments.append(json.dumps(arg))

            if len(all_arguments) != 0:
                if self.parser.has_target_field():
                    target_field_type = self.parser.get_target_field_type()
                    if not isinstance(target_field_type, list):
                        argument = Argument()
                        argument.configure_target_field(
                            self.parser.get_target_field_type(),
                            self.parser.get_target_field_subset())
                        self.test_data.create_asset_for_buildtime(
                            all_arguments, argument.get())
                    else:
                        for tft in target_field_type:
                            target_field_subset = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                                tft)
                            for tfs in target_field_subset:
                                argument = Argument()
                                argument.configure_target_field(tft, tfs)
                                self.test_data.create_asset_for_buildtime(
                                    all_arguments, argument.get())
                else:
                    self.test_data.create_asset_for_buildtime(all_arguments)
                self.test_data.push_test_data_for_buildtime(description)

    def different_source_with_various_types(self):
        description = "generate a different source than the one defined in the argument"

        for i in range(len(self.types)):
            # Copying the list of sources to not modify the original
            new_sources = self.sources[:]

            # Expected a success result if source is both
            if self.sources[i] == "both":
                continue

            # Changing the source for this argument
            new_source = change_source(self.sources[i])
            new_sources[i] = new_source  # Updating the new list of sources

            all_arguments = []
            for j in range(len(self.types)):
                if isinstance(self.types[j], list):
                    argument = Argument()
                    argument.configure_generation(
                        self.types[j][0],
                        CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                            self.types[j][0])[0],
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
                        argument = Argument()
                        argument.configure_target_field(
                            self.parser.get_target_field_type(),
                            self.parser.get_target_field_subset())
                        self.test_data.create_asset_for_buildtime(
                            all_arguments, argument.get())
                    else:
                        for tft in target_field_type:
                            target_field_subset = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                                tft)
                            for tfs in target_field_subset:
                                argument = Argument()
                                argument.configure_target_field(tft, tfs)
                                self.test_data.create_asset_for_buildtime(
                                    all_arguments, argument.get())
                else:
                    self.test_data.create_asset_for_buildtime(all_arguments)
                self.test_data.push_test_data_for_buildtime(description)

    def different_types_value(self):
        description = "generate a different value type than the one defined in the argument"

        template = Template(self.parser)
        for combination in template.generate_template():
            if not any(isinstance(t, list) for t in self.types):
                for i, original_type in enumerate(self.types):
                    if not isinstance(original_type, list):
                        altered_types = change_type(original_type)
                        for new_type, new_subsets in altered_types.items():
                            for new_subset in new_subsets:
                                all_arguments = []
                                for id, (type_, subset, source, restriction) in enumerate(
                                        zip(self.types, self.subsets, combination, self.restrictions)):
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

                                    # means this is an allowed restriction
                                    if type(source) is not tuple:
                                        argument = Argument()
                                        argument.configure_generation(
                                            type_, subset, source, restriction)
                                        val = argument.get()
                                        if id in self.forbidden:
                                            if isinstance(val, dict):
                                                if "name" in val:  # is a reference
                                                    if val["value"] not in self.forbidden[id]:
                                                        all_arguments.append(
                                                            f"${val['name']}")
                                            elif val not in self.forbidden[id]:
                                                all_arguments.append(val)
                                        else:
                                            if argument.is_reference(val):
                                                all_arguments.append(
                                                    f"${val['name']}")
                                            else:
                                                all_arguments.append(val)
                                    else:
                                        if id == i:
                                            argument = Argument()
                                            # It is also configured to verify that the allowed matches the argument declaration.
                                            argument.configure_generation(type_, subset, source[1],
                                                                          restriction, ignore_allowed=True)
                                        else:
                                            argument = Argument(source[0])
                                            argument.configure_generation(
                                                type_, subset, source[1], restriction)
                                        val = argument.get()
                                        if argument.is_reference(val):
                                            all_arguments.append(
                                                f"${val['name']}")
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
                                            self.test_data.create_asset_for_buildtime(
                                                all_arguments, argument.get())
                                        else:
                                            for tft in target_field_type:
                                                target_field_subset = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                                                    tft)
                                                for tfs in target_field_subset:
                                                    argument = Argument()
                                                    argument.configure_target_field(
                                                        tft, tfs)
                                                    self.test_data.create_asset_for_buildtime(
                                                        all_arguments, argument.get())
                                    else:
                                        self.test_data.create_asset_for_buildtime(
                                            all_arguments)
                                    self.test_data.push_test_data_for_buildtime(
                                        description)

    def different_types_value_with_various_types(self):
        description = "generate a different value type than the one defined in the argument"

        template = Template(self.parser)
        for combination in template.generate_template():
            for i, original_type in enumerate(self.types):
                if isinstance(original_type, list):
                    altered_types = change_type(original_type)
                    for new_type, new_subsets in altered_types.items():
                        for new_subset in new_subsets:
                            all_arguments = []

                            for id, (type_, subset, source, restriction) in enumerate(
                                    zip(self.types, self.subsets, combination, self.restrictions)):
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
                                                    all_arguments.append(
                                                        f"${val['name']}")
                                        elif val not in self.forbidden[id]:
                                            all_arguments.append(val)
                                    else:
                                        if argument.is_reference(val):
                                            all_arguments.append(
                                                f"${val['name']}")
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
                                                source[1], restriction, ignore_allowed=True)
                                        else:
                                            argument.configure_generation(type_, subset, source[1],
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
                                        all_arguments.append(f"${val['name']}")
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
                                    self.test_data.create_asset_for_buildtime(
                                        all_arguments, argument.get())
                                else:
                                    self.test_data.create_asset_for_buildtime(
                                        all_arguments)
                                self.test_data.push_test_data_for_buildtime(
                                    description)

    def different_allowed_values(self):
        description = "generate a different value allowed than the one defined in the argument"

        template = Template(self.parser)

        for combination in template.generate_template():
            allowed_indices = [i for i, source in enumerate(
                combination) if isinstance(source, tuple)]

            if not allowed_indices:
                continue

            for index in allowed_indices:
                all_arguments = []
                # Flag to check if there are any allowed references
                allowed_applied_as_value = False

                for id, (type_, subset, source, restriction) in enumerate(
                        zip(self.types, self.subsets, combination, self.restrictions)):

                    if not isinstance(type_, list):
                        if id == index and isinstance(source, tuple):
                            argument = Argument()
                            # Handle allowed values
                            argument.configure_generation(
                                type_, subset, source[1], restriction, ignore_allowed=True)
                            val = argument.get()
                        else:
                            argument = Argument()
                            # Handle regular values
                            if isinstance(source, tuple):
                                argument = Argument(source[0])
                                argument.configure_generation(
                                    type_, subset, source[1], restriction)
                            else:
                                argument.configure_generation(
                                    type_, subset, source, restriction)
                            val = argument.get()

                        if id in self.forbidden and isinstance(val, dict) and "name" in val:
                            # Handle forbidden values as references
                            if val["value"] not in self.forbidden[id]:
                                all_arguments.append(f"${val['name']}")
                        elif id in self.forbidden and val not in self.forbidden[id]:
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
                            argument = Argument()
                            argument.configure_target_field(
                                self.parser.get_target_field_type(),
                                self.parser.get_target_field_subset())
                            self.test_data.create_asset_for_buildtime(
                                all_arguments, argument.get())
                        else:
                            for tft in target_field_type:
                                target_field_subset = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(
                                    tft)
                                for tfs in target_field_subset:
                                    argument = Argument()
                                    argument.configure_target_field(tft, tfs)
                                    self.test_data.create_asset_for_buildtime(
                                        all_arguments, argument.get())
                    else:
                        self.test_data.create_asset_for_buildtime(
                            all_arguments)
                    self.test_data.push_test_data_for_buildtime(
                        description, skip_tag="allowed")

    def different_allowed_values_with_various_types(self):
        description = "generate a different value allowed than the one defined in the argument"

        template = Template(self.parser)

        for combination in template.generate_template():
            allowed_indices = [i for i, source in enumerate(
                combination) if isinstance(source, tuple)]

            if not allowed_indices:
                continue

            for index in allowed_indices:
                all_arguments = []
                # Flag to check if there are any allowed references
                allowed_applied_as_value = False

                for id, (type_, source, restriction) in enumerate(zip(self.types, combination, self.restrictions)):
                    argument = Argument()

                    if isinstance(type_, list):
                        type_, subset = type_[0], CORRESPONDENCE_BETWEEN_TYPE_SUBSET.get(type_[0])[
                            0]

                        if id == index and isinstance(source, tuple):
                            # Handle allowed values
                            argument.configure_generation(
                                type_, subset, source[1], restriction, ignore_allowed=True)
                            val = argument.get()
                        else:
                            # Handle regular values
                            argument.configure_generation(
                                type_, subset, source, restriction)
                            val = argument.get()

                        if id in self.forbidden and isinstance(val, dict) and "name" in val:
                            # Handle forbidden values as references
                            if val["value"] not in self.forbidden[id]:
                                all_arguments.append(f"${val['name']}")
                        elif id in self.forbidden and val not in self.forbidden[id]:
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
                        argument = Argument()
                        argument.configure_target_field(
                            self.parser.get_target_field_type(),
                            self.parser.get_target_field_subset())
                        self.test_data.create_asset_for_buildtime(
                            all_arguments, argument.get())
                    else:
                        self.test_data.create_asset_for_buildtime(
                            all_arguments)
                    self.test_data.push_test_data_for_buildtime(
                        description, skip_tag="allowed")

    def generate_general_value_restrictions(self):
        description = "Generate restrictions of value type"

        template = Template(self.parser)

        for combination in template.generate_exception_arguments():
            all_arguments = []
            restrictions_applied_as_value = False

            for id, (type_, subset, source, restriction) in enumerate(
                    zip(self.types, self.subsets, combination, self.restrictions)):
                if not isinstance(type_, list):
                    if type(source) is not tuple:
                        argument = Argument()
                        argument.configure_generation(
                            type_, subset, source, restriction)
                        val = argument.get()
                        if id in self.forbidden:
                            if isinstance(val, dict):
                                if "name" in val:  # is a reference
                                    if val["value"] not in self.forbidden[id]:
                                        all_arguments.append(f"${val['name']}")
                            elif val not in self.forbidden[id]:
                                all_arguments.append(val)
                        else:
                            if argument.is_reference(val):
                                all_arguments.append(f"${val['name']}")
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
                            restrictions_applied_as_value = False
                            all_arguments.append(f"${val['name']}")
                        else:
                            restrictions_applied_as_value = True
                            all_arguments.append(val)

            if not restrictions_applied_as_value:
                all_arguments.clear()

            if len(all_arguments) != 0:
                if self.parser.has_target_field():
                    argument = Argument()
                    argument.configure_target_field(
                        self.parser.get_target_field_type(),
                        self.parser.get_target_field_subset())
                    self.test_data.create_asset_for_buildtime(
                        all_arguments, argument.get())
                else:
                    self.test_data.create_asset_for_buildtime(all_arguments)
                self.test_data.push_test_data_for_buildtime(description)

    def runner(self):
        self.fewer_arguments_than_the_minimum_required()
        self.more_or_less_arguments_according_to_variadic()
        self.different_sources()
        self.different_source_with_various_types()
        self.different_types_value()
        self.different_types_value_with_various_types()
        self.different_allowed_values()
        self.different_allowed_values_with_various_types()
        self.generate_general_value_restrictions()
