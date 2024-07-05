from helper_test_generator.parser import Parser
from helper_test_shared.utils import *
from pathlib import Path


class Validator:
    def __init__(self, parser: Parser):
        self.parser = parser
        self.all_valid_data = []

    def get_all_valid_data(self):
        return self.all_valid_data

    def verify_type(self):
        for type_ in self.parser.get_types():
            if isinstance(type_, list):
                for internal_type in type_:
                    if internal_type not in TYPE_MAPPING:
                        sys.exit(f"Helper {self.parser.get_name()}: Type '{internal_type}' is not supported")
            else:
                if type_ not in TYPE_MAPPING:
                    sys.exit(f"Helper {self.parser.get_name()}: Type '{type_}' is not supported")

    def verify_subset(self):
        for subset in self.parser.get_subset():
            if subset not in SUBSET_MAPPING:
                sys.exit(f"Helper {self.parser.get_name()}: Subset '{subset}' is not supported")

    def verify_source(self):
        for source in self.parser.get_sources():
            if source not in SOURCE_MAPPING:
                sys.exit(f"Helper {self.parser.get_name()}: Source '{source}' is not supported")

    def verify_name(self):
        self.parser.get_name()

    def verify_helper_type(self):
        if not self.parser.has_helper_type():
            sys.exit(f"Helper {self.parser.get_name()}: the helper_type property is required")
        if self.parser.get_helper_type() not in ["map", "filter", "transformation"]:
            sys.exit(
                f"Helper {self.parser.get_name()}: invalid value for helper_type. allowed values are ['map', 'filter'', 'transformation']")

    def verify_skip(self):
        skips_allowed = ["success_cases", "different_type",
                         "different_source", "different_target_field_type", "allowed"]
        if not isinstance(self.parser.get_skips(), list):
            sys.exit(f"Helper {self.parser.get_name()}: Only array is supported in the skip property")

        for skip in self.parser.get_skips():
            if skip not in skips_allowed:
                sys.exit(f"Helper {self.parser.get_name()}: Skip {skip} is not supported")

    def check_consistency_between_type_and_subset(self) -> None:
        for type_, subset in zip(self.parser.get_types(), self.parser.get_subset()):
            if not isinstance(type_, list):
                #     for internal_type in type_:
                #         new_type_ = convert_string_to_type(internal_type)
                #         new_subset = convert_string_to_subset(subset)
                #         if new_type_ == Number:
                #             if new_subset is not int and new_subset is not float and new_subset is not Double:
                #                 sys.exit(
                #                     f"Helper {self.parser.get_name()}: There is no consistency between type '{internal_type}' and subset '{subset}'")
                #         if new_type_ == String:
                #             if new_subset is not Hexadecimal and new_subset is not Regex and new_subset is not Ip and new_subset is not str:
                #                 sys.exit(
                #                     f"Helper {self.parser.get_name()}: There is no consistency between type '{internal_type}' and subset '{subset}'")
                #         if new_type_ == bool:
                #             if len(subset) != 0:
                #                 sys.exit(
                #                     f"Helper {self.parser.get_name()}: There is no consistency between type '{internal_type}' and subset '{subset}'")
                # else:
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
        for subset, restriction in zip(self.parser.get_subset(), self.parser.get_restrictions()):
            new_subset = convert_string_to_subset(subset)
            if restriction != None:
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
                    allowed = restriction["allowed"]
                elif "forbidden" in restriction:
                    for forbidden in restriction["forbidden"]:
                        if type(forbidden) != new_subset:
                            sys.exit(
                                f"Helper {self.parser.get_name()}: The forbidden value '{forbidden}' do not have the same type as the argument")

    def evaluator(self, file_path: Path):
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
