#!/usr/bin/env python3

from helper_test.test_cases_generator.parser import Parser
from helper_test.definition_types.utils import *
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
                        sys.exit(
                            f"Helper {self.parser.get_name()}: Type '{internal_type}' is not supported")
            else:
                if type_ not in TYPE_MAPPING:
                    sys.exit(
                        f"Helper {self.parser.get_name()}: Type '{type_}' is not supported")

    def verify_subset(self):
        """
        Verifies if all subsets in the parser are valid.
        """
        for subset in self.parser.get_subset():
            if not isinstance(subset, dict):
                if subset != "all":
                    if subset not in SUBSET_MAPPING:
                        sys.exit(
                            f"Helper {self.parser.get_name()}: Subset '{subset}' is not supported")
            else:
                for array_subset in subset.values():
                    for individual_subset in array_subset:
                        if individual_subset not in SUBSET_MAPPING:
                            sys.exit(
                                f"Helper {self.parser.get_name()}: Subset '{individual_subset}' is not supported")

    def verify_source(self):
        """
        Verifies if all sources in the parser are valid.
        """
        for source in self.parser.get_sources():
            if source not in SOURCE_MAPPING:
                sys.exit(
                    f"Helper {self.parser.get_name()}: Source '{source}' is not supported")

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
            sys.exit(
                f"Helper {self.parser.get_name()}: the helper_type property is required")
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
            sys.exit(
                f"Helper {self.parser.get_name()}: Only array is supported in the skip property")

        for skip in self.parser.get_skips():
            if skip not in skips_allowed:
                sys.exit(
                    f"Helper {self.parser.get_name()}: Skip {skip} is not supported")

    def check_consistency_between_type_and_subset(self) -> None:
        """
        Checks consistency between types and subsets.
        """
        for type_, subset in zip(self.parser.get_types(), self.parser.get_subset()):
            if not isinstance(type_, list):
                new_type_ = convert_string_to_type(type_)
                if not isinstance(subset, dict):
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
                else:
                    for key, value in subset.items():
                        if not isinstance(value, list):
                            sys.exit(
                                f"Helper {self.parser.get_name()}: Subset '{subset}' for key '{key}' should be a list.")
                        if new_type_ == Number:
                            for v in value:
                                if convert_string_to_subset(v) not in [int, float, Double]:
                                    sys.exit(
                                        f"Helper {self.parser.get_name()}: There is no consistency between type '{type_}' and subset '{v}' in key '{key}'")
                        elif new_type_ == String:
                            for v in value:
                                if convert_string_to_subset(v) not in [Hexadecimal, Regex, Ip, str]:
                                    sys.exit(
                                        f"Helper {self.parser.get_name()}: There is no consistency between type '{type_}' and subset '{v}' in key '{key}'")
                        elif new_type_ == bool:
                            if value:
                                sys.exit(
                                    f"Helper {self.parser.get_name()}: There is no consistency between type '{type_}' and subset '{value}' in key '{key}'")
                        else:
                            sys.exit(
                                f"Helper {self.parser.get_name()}: Unsupported type '{type_}' for subset '{value}' in key '{key}'")

    def verify_arguments_names_in_all_places(self):
        restrictions = self.parser.get_general_restrictions()
        for restiction in restrictions:
            if restiction:
                for name, value in restiction.items():
                    if name not in self.parser.get_name_id_arguments():
                        sys.exit(
                            f"Helper {self.parser.get_name()}: Name {name} in 'general_restrictions' is not defined in arguments")

        tests = self.parser.get_tests()
        if tests:
            for test in tests:
                count = 0
                for argument in test.get("arguments", []):
                    if argument in self.parser.get_name_id_arguments():
                        count += 1
                if count < self.parser.get_minimum_arguments():
                    sys.exit(
                        f"Helper {self.parser.get_name()}: There are arguments in 'test' that were not defined")

    def verify_output(self):
        output = self.parser.get_output()
        if output:
            if "type" not in output:
                sys.exit(
                    f"Helper {self.parser.get_name()}: Type attribute is required in output")
            if not isinstance(output["type"], list) and not isinstance(output["type"], str):
                sys.exit(
                    f"Helper {self.parser.get_name()}: Type attribute only can only be a list or a value")
        else:
            if self.parser.get_helper_type() == "map":
                sys.exit(
                    f"Helper {self.parser.get_name()}: Is neccesary define output for helpers the map type")

    def check_consistency_between_output_and_expected_type(self) -> None:
        """
        Checks consistency between output and expected type.
        """
        if self.parser.get_helper_type() == "map":
            output = self.parser.get_output()
            new_type_ = convert_string_to_type(output["type"])
            new_subset = convert_string_to_subset(output.get("subset"))
            if not isinstance(new_type_, list):
                if new_type_ == Number:
                    if new_subset is not int and new_subset is not float and new_subset is not Double:
                        sys.exit(
                            f"Helper {self.parser.get_name()}: There is no consistency between type '{new_type_}' and subset '{new_subset}'")
                if new_type_ == String:
                    if new_subset is not Hexadecimal and new_subset is not Regex and new_subset is not Ip and new_subset is not str:
                        sys.exit(
                            f"Helper {self.parser.get_name()}: There is no consistency between type '{new_type_}' and subset '{new_subset}'")
                if new_type_ == bool:
                    if len(new_subset) != 0:
                        sys.exit(
                            f"Helper {self.parser.get_name()}: There is no consistency between type '{new_type_}' and subset '{new_subset}'")

            tests = self.parser.get_tests()
            if tests:
                for test in tests:
                    if "expected" in test:
                        if new_subset == int:
                            if not isinstance(test["expected"], int):
                                sys.exit(
                                    f"Helper {self.parser.get_name()}: There is no consistency between expected type '{type(test['expected'])}' and output type '{new_subset}'")
                        if new_subset == str:
                            if not isinstance(test["expected"], str):
                                sys.exit(
                                    f"Helper {self.parser.get_name()}: There is no consistency between expected type '{type(test['expected'])}' output type '{new_subset}'")
                        if new_type_ == Object:
                            if not isinstance(test["expected"], dict):
                                sys.exit(
                                    f"Helper {self.parser.get_name()}: There is no consistency between expected type '{type(test['expected'])}' output type '{new_type_}'")
                        if new_type_ == list:
                            if not isinstance(test["expected"], list):
                                sys.exit(
                                    f"Helper {self.parser.get_name()}: There is no consistency between expected type '{type(test['expected'])}' output type '{new_type_}'")

    def verify_variadic_in_test(self):
        tests = self.parser.get_tests()
        if tests:
            for number_test, test in enumerate(tests):
                if "arguments" not in test:
                    continue
                arguments_list = list(test["arguments"].items())
                if not self.parser.is_variadic():
                    if self.parser.get_minimum_arguments() < len(arguments_list):
                        sys.exit(
                            f"Helper {self.parser.get_name()}: has an error in test number '{number_test + 1}': it is not a variadic function")

                # Delete the keys that are in id_name_order
                id_name_order = self.parser.get_name_id_arguments()
                filtered_arguments_list = [
                    (k, v) for k, v in arguments_list if k not in id_name_order]

                # Verify that the remaining keys meet the criteria
                if filtered_arguments_list:
                    last_id_name = sorted(
                        id_name_order.items(), key=lambda x: x[1])[-1][0]
                    pattern = re.compile(rf'^{last_id_name}_\d+$')

                    for k, _ in filtered_arguments_list:
                        if not pattern.match(k):
                            sys.exit(
                                f"Argument '{k}' does not match the required pattern '{last_id_name}_<number>'")

    def verify_metadata(self):
        metadata = self.parser.get_metadata()
        if not metadata:
            sys.exit(
                f"Helper {self.parser.get_name()}: It is mandatory to define the 'metadata' property")
        if "description" not in metadata:
            sys.exit(
                f"Helper {self.parser.get_name()}: It is mandatory to define the 'description' property in metadata")

    def verify_restrictions(self) -> None:
        """
        Verifies the restrictions in the parser.
        """
        for subset, restriction in zip(self.parser.get_subset(), self.parser.get_restrictions()):
            if not isinstance(subset, dict):
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
            else:
                for key, value in subset.items():
                    if not isinstance(value, list):
                        sys.exit(
                            f"Helper {self.parser.get_name()}: Subset '{subset}' for key '{key}' should be a list.")
                    for v in value:
                        if restriction is not None:
                            if "allowed" not in restriction and "forbidden" not in restriction:
                                sys.exit(
                                    f"Helper {self.parser.get_name()}: No restrictions were registered for key '{key}', please remove this field from the configuration")

                            if "allowed" in restriction and "forbidden" in restriction:
                                sys.exit(
                                    f"Helper {self.parser.get_name()}: It is not possible to configure allowed and forbidden values for the same argument for key '{key}'")

                            if "allowed" in restriction:
                                for allowed in restriction["allowed"]:
                                    if not isinstance(allowed, type(convert_string_to_subset(v))):
                                        sys.exit(
                                            f"Helper {self.parser.get_name()}: The allowed value '{allowed}' does not match the type of the subset value '{v}' for key '{key}'")
                            elif "forbidden" in restriction:
                                for forbidden in restriction["forbidden"]:
                                    if not isinstance(forbidden, type(convert_string_to_subset(v))):
                                        sys.exit(
                                            f"Helper {self.parser.get_name()}: The forbidden value '{forbidden}' does not match the type of the subset value '{v}' for key '{key}'")

    def verify_target_field(self):
        if self.parser.get_helper_type() != "map":
            tests = self.parser.get_tests()
            if tests:
                for test in tests:
                    if 'target_field' not in test:
                        sys.exit(
                            f"Helper {self.parser.get_name()}: 'target_field' atributte is requeried into 'test' for filter and transformation helpers")

    def evaluator(self, file_path: Path):
        """
        Evaluates the configuration file.

        Args:
            file_path (Path): The path to the configuration file.
        """
        self.parser.load_yaml_from_file(file_path)
        self.verify_name()
        self.verify_metadata()
        self.verify_helper_type()
        self.verify_type()
        self.verify_subset()
        self.verify_source()
        self.verify_target_field()
        self.check_consistency_between_type_and_subset()
        self.verify_arguments_names_in_all_places()
        self.verify_output()
        self.check_consistency_between_output_and_expected_type()
        self.verify_variadic_in_test()
        self.verify_restrictions()
        self.verify_skip()
        self.all_valid_data.append(self.parser.get_yaml_data())
