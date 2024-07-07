#!/usr/bin/env python3

from .parser import Parser
from definition_types.utils import *
from pathlib import Path


class Validator:
    def __init__(self, parser: Parser):
        """
        Initializes the Validator with a parser instance.

        Args:
            parser (Parser): The parser instance.
        """
        self.parser = parser
        self.all_valid_data = []

    def get_all_valid_data(self):
        """
        Retrieves all valid data.

        Returns:
            list: All valid data.
        """
        return self.all_valid_data

    def verify_type(self):
        """
        Verifies if all types in the parser are valid.
        """
        for type_ in self.parser.get_types():
            if isinstance(type_, list):
                for internal_type in type_:
                    if internal_type not in TYPE_MAPPING:
                        sys.exit(f"Helper {self.parser.get_name()}: Type '{internal_type}' is not supported")
            else:
                if type_ not in TYPE_MAPPING:
                    sys.exit(f"Helper {self.parser.get_name()}: Type '{type_}' is not supported")

    def verify_subset(self):
        """
        Verifies if all subsets in the parser are valid.
        """
        for subset in self.parser.get_subset():
            if subset not in SUBSET_MAPPING:
                sys.exit(f"Helper {self.parser.get_name()}: Subset '{subset}' is not supported")

    def verify_source(self):
        """
        Verifies if all sources in the parser are valid.
        """
        for source in self.parser.get_sources():
            if source not in SOURCE_MAPPING:
                sys.exit(f"Helper {self.parser.get_name()}: Source '{source}' is not supported")

    def verify_name(self):
        """
        Verifies the name of the parser.
        """
        self.parser.get_name()

    def verify_helper_type(self):
        """
        Verifies the helper type in the parser.
        """
        if not self.parser.has_helper_type():
            sys.exit(f"Helper {self.parser.get_name()}: the helper_type property is required")
        if self.parser.get_helper_type() not in ["map", "filter", "transformation"]:
            sys.exit(
                f"Helper {self.parser.get_name()}: invalid value for helper_type. allowed values are ['map', 'filter'', 'transformation']")

    def verify_skip(self):
        """
        Verifies the skip properties in the parser.
        """
        skips_allowed = ["success_cases", "different_type",
                         "different_source", "different_target_field_type", "allowed"]
        if not isinstance(self.parser.get_skips(), list):
            sys.exit(f"Helper {self.parser.get_name()}: Only array is supported in the skip property")

        for skip in self.parser.get_skips():
            if skip not in skips_allowed:
                sys.exit(f"Helper {self.parser.get_name()}: Skip {skip} is not supported")

    def check_consistency_between_type_and_subset(self) -> None:
        """
        Checks consistency between types and subsets.
        """
        for type_, subset in zip(self.parser.get_types(), self.parser.get_subset()):
            if not isinstance(type_, list):
                new_type_ = convert_string_to_type(type_)
                new_subset = convert_string_to_subset(subset)
                if new_type_ == Number:
                    if new_subset is not int and new_subset is not float and new_subset is not Double:
                        sys.exit(
                            f"Helper {self.parser.get_name()}: There is no consistency between type '{type_}' and subset '{subset}'")
                if new_type_ == String:
                    if new_subset is not Hexadecimal and new_subset is not Regex and new_subset is not Ip and new_subset is not str:
                        sys.exit(
                            f"Helper {self.parser.get_name()}: There is no consistency between type '{type_}' and subset '{subset}'")
                if new_type_ == bool:
                    if len(subset) != 0:
                        sys.exit(
                            f"Helper {self.parser.get_name()}: There is no consistency between type '{type_}' and subset '{subset}'")

    def verify_restrictions(self) -> None:
        """
        Verifies the restrictions in the parser.
        """
        for subset, restriction in zip(self.parser.get_subset(), self.parser.get_restrictions()):
            new_subset = convert_string_to_subset(subset)
            if restriction is not None:
                if "allowed" not in restriction and "forbidden" not in restriction:
                    sys.exit(
                        f"Helper {self.parser.get_name()}: No restrictions were registered, please remove this field from the configuration")

                if "allowed" in restriction and "forbidden" in restriction:
                    sys.exit(
                        f"Helper {self.parser.get_name()}: It is not possible to configure allowed and forbidden values for the same argument")

                if "allowed" in restriction:
                    for allowed in restriction["allowed"]:
                        if type(allowed) != new_subset:
                            sys.exit(
                                f"Helper {self.parser.get_name()}: The allowed value '{allowed}' do not have the same type as the argument")
                elif "forbidden" in restriction:
                    for forbidden in restriction["forbidden"]:
                        if type(forbidden) != new_subset:
                            sys.exit(
                                f"Helper {self.parser.get_name()}: The forbidden value '{forbidden}' do not have the same type as the argument")

    def evaluator(self, file_path: Path):
        """
        Evaluates the configuration file.

        Args:
            file_path (Path): The path to the configuration file.
        """
        self.parser.load_yaml_from_file(file_path)
        self.verify_name()
        self.verify_helper_type()
        self.verify_type()
        self.verify_subset()
        self.verify_source()
        self.check_consistency_between_type_and_subset()
        self.verify_restrictions()
        self.verify_skip()
        self.all_valid_data.append(self.parser.get_yaml_data())
