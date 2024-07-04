import sys
import random
import re
import json
import yaml
from enum import Enum
import itertools
from pathlib import Path
from typing import Union
import ast

reference_counter = 0


class Source(Enum):
    VALUE = 1
    REFERENCE = 2
    BOTH = 3


class Number(type):
    def __init__(self):
        print("same")


class String(type):
    def __init__(self):
        print("same")


class Boolean(type):
    def __init__(self):
        print("same")


class Object(type):
    def __init__(self):
        print("same")


class Double(Number):
    def __init__(self):
        print("same")


class Hexadecimal:
    def __init__(self, hex_value):
        if not self._validate_hex(hex_value):
            raise ValueError(f"{hex_value} is not a valid hexadecimal number")
        self.hex_value = hex_value.lower()

    def __str__(self):
        return self.hex_value

    @staticmethod
    def _validate_hex(hex_value):
        # Check if the hex_value is a valid hexadecimal string
        if isinstance(hex_value, str) and hex_value.startswith("0x"):
            hex_digits = hex_value[2:]
            return all(c in "0123456789abcdefABCDEF" for c in hex_digits)
        return False

    @staticmethod
    def random_hex(length=8):
        # Generate a random hexadecimal string of the given length
        random_hex_value = "0x" + "".join(
            random.choice("0123456789abcdef") for _ in range(length)
        )
        return Hexadecimal(random_hex_value)


class Ip(str):
    def __init__(self, address):
        if not self._validate_ip(address):
            raise ValueError(f"{address} is not a valid IP address")
        self.address = address

    def __str__(self):
        return self.address

    @staticmethod
    def _validate_ip(address):
        # Regex pattern to validate an IP address
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if pattern.match(address):
            # Check if each octet is between 0 and 255
            octets = address.split(".")
            for octet in octets:
                if not 0 <= int(octet) <= 255:
                    return False
            return True
        return False


class Regex(str):
    def __init__(self, pattern):
        if not self._validate_pattern(pattern):
            raise ValueError("Invalid regular expression pattern")
        self.pattern = pattern
        self.regex = re.compile(pattern)

    def _validate_pattern(self, pattern):
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    def __str__(self):
        return self.pattern


TYPE_MAPPING = {
    "number": Number,
    "string": String,
    "boolean": Boolean,
    "object": Object,
    "array": list
}

SUBSET_MAPPING = {
    "integer": int,
    "string": str,
    "boolean": bool,
    "float": float,
    "double": Double,
    "hexadecimal": Hexadecimal,
    "ip": Ip,
    "regex": Regex,
    "object": dict
}

CORRESPONDENCE_BETWEEN_TYPE_SUBSET = {
    "number": [
        "integer",
        "double",
        "float"
    ],
    "string": [
        "string",
        "hexadecimal",
        "ip",
        "regex"
    ],
    "boolean": ["boolean"],
    "object": [
        "object"
    ],
    "array": [
        "integer",
        "double",
        "float",
        "string",
        "hexadecimal",
        "ip",
        "regex",
        "boolean"
    ]
}

SOURCE_MAPPING = {
    "value": Source.VALUE,
    "reference": Source.REFERENCE,
    "both": Source.BOTH
}


def convert_string_to_type(type_: str) -> type:
    return TYPE_MAPPING.get(type_)


def convert_string_to_subset(subset: str) -> type:
    return SUBSET_MAPPING.get(subset)


def convert_string_to_source(source: str) -> Source:
    return SOURCE_MAPPING.get(source)


def type_to_string(type_: type) -> str:
    type_mapping = {
        Number: "number",
        String: "string",
        str: "string",
        Boolean: "boolean",
        bool: "boolean",
        Object: "object",
        dict: "object",
        list: "array",
        int: "integer",
        float: "float",
        Double: "double",
        Hexadecimal: "hexadecimal",
        Ip: "ip",
        Regex: "regex"
    }

    if type_ not in type_mapping:
        print(type_)
        sys.exit(f"Type '{type_}' is not supported")

    return type_mapping.get(type_)


def change_source(source):
    if source == "value":
        return "reference"
    elif source == "reference":
        return "value"
    else:
        return source


def change_type(type_: Union[str, list]) -> dict:
    correspondence_copy = CORRESPONDENCE_BETWEEN_TYPE_SUBSET.copy()
    try:
        if isinstance(type_, str):
            correspondence_copy.pop(type_)
        else:
            for tp in type_:
                correspondence_copy.pop(tp)
    except KeyError as e:
        sys.exit(f"Error: type not found in correspondence map: {e}")
    return correspondence_copy


class Parser:
    def __init__(self):
        self.yaml_data = {}

    def load_yaml_from_file(self, file_path: str):
        """
        Loads data from a YAML file.

        Args:
            file_path (str): The path to the YAML file.

        Returns:
            dict: The parsed YAML data.

        """
        with open(file_path, "r") as stream:
            try:
                self.yaml_data = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)

    def load_yaml_from_dict(self, yaml_data: dict):
        self.yaml_data = yaml_data

    def get_yaml_data(self):
        return self.yaml_data

    def get_name(self):
        if "name" in self.yaml_data:
            return self.yaml_data["name"]
        sys.exit("Name attribute not found")

    def is_variadic(self) -> bool:
        if "is_variadic" in self.yaml_data:
            return self.yaml_data["is_variadic"]
        sys.exit(f"Variadic attribute not found in {self.get_name()} helper")

    def has_arguments(self):
        if "arguments" in self.yaml_data:
            if len(self.yaml_data["arguments"]) != 0:
                return True
        return False

    def get_minimum_arguments(self):
        minimun_arguments = 0
        if self.has_arguments():
            minimun_arguments = len(self.yaml_data["arguments"])
        return minimun_arguments

    def get_sources(self):
        sources = []
        if self.has_arguments():
            for argument in self.yaml_data["arguments"].values():
                if argument["source"]:
                    sources.append(argument["source"])
        return sources

    def get_types(self):
        types = []
        if self.has_arguments():
            for argument in self.yaml_data["arguments"].values():
                types.append(argument["type"])
        return types

    def get_subset(self):
        types = []
        if self.has_arguments():
            for argument in self.yaml_data["arguments"].values():
                types.append(argument.get("generate", "string"))
        return types

    def get_skips(self) -> list:
        return self.yaml_data.get("skipped", [])

    def get_restrictions(self):
        restrictions = []
        if self.has_arguments():
            for argument in self.yaml_data["arguments"].values():
                restrictions.append(argument.get("restrictions"))
        return restrictions

    def get_allowed_in_dict_format(self) -> dict:
        allowed_args = {}
        if self.has_arguments():
            for index, arg_info in self.yaml_data['arguments'].items():
                if 'restrictions' in arg_info and 'allowed' in arg_info['restrictions']:
                    allowed_args[index - 1] = arg_info['restrictions']['allowed']  # convert 1-based to 0-based index
        return allowed_args

    def get_forbidden_in_dict_format(self) -> dict:
        forbidden_args = {}
        if self.has_arguments():
            for index, arg_info in self.yaml_data['arguments'].items():
                if 'restrictions' in arg_info and 'forbidden' in arg_info['restrictions']:
                    # convert 1-based to 0-based index
                    forbidden_args[index - 1] = arg_info['restrictions']['forbidden']
        return forbidden_args

    def get_allowed(self):
        allowed = {}
        if self.get_minimum_arguments() != 0:
            for id, restriction in enumerate(self.get_restrictions()):
                if restriction != None:
                    if "allowed" in restriction:
                        if id not in allowed:
                            allowed[id] = []
                        allowed[id].append(restriction["allowed"])
        return allowed

    def get_general_restrictions(self):
        general_restrictions = []
        if 'general_restrictions' in self.yaml_data:
            if self.get_minimum_arguments() == 0:
                sys.exit("General restrictions are not allowed without defined arguments")
            else:
                for restriction in self.yaml_data["general_restrictions"]:
                    general_restrictions.append(restriction["arguments"])
        return general_restrictions

    def has_target_field(self):
        return "target_field" in self.yaml_data

    def get_target_field_type(self):
        if self.has_target_field:
            return self.yaml_data["target_field"]["type"]
        return None

    def get_target_field_subset(self):
        if self.has_target_field:
            return self.yaml_data["target_field"].get("generate", "")
        return None

    def get_tests(self):
        if "test" in self.yaml_data:
            return self.yaml_data["test"]
        return None


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
        self.verify_type()
        self.verify_subset()
        self.verify_source()
        self.check_consistency_between_type_and_subset()
        self.verify_restrictions()
        self.verify_skip()
        self.all_valid_data.append(self.parser.get_yaml_data())


class Argument:
    def __init__(self, value=None) -> None:
        self.value = value
        self.general_restrictions = []
        self.allowed = []

    def configure_generation(
            self, type_: str, subset: str, source: str, restriction: dict, ignore_allowed=False) -> None:
        self.type_ = convert_string_to_type(type_)
        self.subset = convert_string_to_subset(subset)
        self.source = convert_string_to_source(source)
        self.restriction = restriction
        self.ignore_allowed = ignore_allowed
        if self.has_allowed():
            self.allowed = restriction["allowed"]

    def configure_target_field(self, type_: str, subset: str):
        self.type_ = convert_string_to_type(type_)
        self.subset = convert_string_to_subset(subset)
        self.source = Source.VALUE
        self.restriction = None

    def configure_only_value(self, source: str):
        self.source = convert_string_to_source(source)
        self.general_restrictions = ["any"]
        self.allowed = ["any"]
        self.restriction = None
        self.ignore_allowed = False

    def has_allowed(self) -> bool:
        if self.restriction != None:
            return "allowed" in self.restriction
        return False

    def set_general_restrictions(self, general_restrictions: list):
        self.general_restrictions = general_restrictions

    def has_general_restrictions(self) -> bool:
        if len(self.general_restrictions) == 0:
            return False
        return True

    def generate_random_value(self):
        if self.type_ == Number:
            return self.generate_random_number()
        elif self.type_ == String:
            return self.generate_random_string()
        elif self.type_ == Boolean:
            return self.generate_random_boolean()
        elif self.type_ == list:
            return self.generate_random_list()
        elif self.type_ == Object:
            return self.generate_random_object()

    def generate_random_number(self):
        if self.subset == int:
            return random.randint(0, 9)
        elif self.subset == float:
            return random.uniform(0, 9)
        elif self.subset == Double:
            return float(format(random.uniform(0, 9), '.2f'))

    def generate_random_string(self):
        if self.subset == Hexadecimal:
            return Hexadecimal.random_hex().__str__()
        elif self.subset == Ip:
            return Ip(random.choice(["111.111.1.11", "222.222.2.22"])).__str__()
        elif self.subset == Regex:
            return json.dumps(Regex("^(bye pcre\\d)$").__str__())
        else:
            return "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(random.randint(1, 10)))

    def generate_random_boolean(self):
        return True

    def generate_random_list(self):
        subset_value_mapping = {
            int: lambda: random.randint(0, 9),
            float: lambda: random.uniform(0, 9),
            Double: lambda: float(format(random.uniform(0, 9), '.2f')),
            str: lambda: "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(random.randint(1, 10))),
            Hexadecimal: lambda: Hexadecimal.random_hex().__str__(),
            Ip: lambda: Ip(random.choice(["111.111.1.11", "222.222.2.22"])).__str__(),
            Regex: lambda: json.dumps(Regex("^(bye pcre\\d)$").__str__()),
            bool: lambda: True,
            dict: lambda: {"key": "value"}
        }

        if self.subset not in subset_value_mapping:
            sys.exit("Subset is not supported for array")

        return [subset_value_mapping.get(self.subset)()]

    def generate_random_object(self):
        return {"key": "value"}

    def generate_value(self):
        if (not self.has_allowed() and not self.has_general_restrictions()) or self.ignore_allowed:
            return self.generate_random_value()
        else:
            return self.value

    def generate_reference(self):
        global reference_counter
        reference_counter += 1
        if (not self.has_allowed() and not self.has_general_restrictions()) or self.ignore_allowed:
            return {
                "name": f"ref{reference_counter}",
                "value": self.generate_random_value()
            }
        else:
            return {
                "name": f"ref{reference_counter}",
                "value": self.value
            }

    def is_reference(self, value):
        if isinstance(value, dict):
            if "name" in value:
                return True
        return False

    def get(self, is_target_field=False):
        if self.source == Source.VALUE:
            if not is_target_field:
                return json.dumps(self.generate_value())
            return self.generate_value()
        elif self.source == Source.REFERENCE:
            return self.generate_reference()
        elif self.source == Source.BOTH:
            return random.choice([self.generate_value(), self.generate_reference()])


class Template:
    def __init__(self, parser: Parser):
        self.parser = parser

    def generate_raw_template(self, my_sources=[]) -> list:
        sources = []
        if not my_sources:
            sources = self.parser.get_sources()
        else:
            sources = my_sources
        sources_expanded = []
        for source in sources:
            if source == "both":
                sources_expanded.append(["value", "reference"])
            else:
                sources_expanded.append(source)

        # If an element is a list, we treat it as a single element
        data_processed = [x if isinstance(x, list) else [x] for x in sources_expanded]

        # Generate all possible combinations
        combinations = list(itertools.product(*data_processed))
        return combinations

    def enrichment_template(self):
        # Get the sources from the yaml configuration
        raw_combinations = self.generate_raw_template()

        allowed_args = self.parser.get_allowed_in_dict_format()
        # If no allowed restrictions are found, return the raw combinations
        if not allowed_args:
            return raw_combinations

        # Process combinations
        processed_combinations = []
        for comb in raw_combinations:
            comb_list = [list(comb)]
            for arg_index, allowed_values in allowed_args.items():
                new_comb_list = []
                for partial_comb in comb_list:
                    for allowed in allowed_values:
                        new_partial_comb = list(partial_comb)
                        new_partial_comb[arg_index] = (allowed, new_partial_comb[arg_index])
                        new_comb_list.append(new_partial_comb)
                comb_list = new_comb_list
            processed_combinations.extend([tuple(comb) for comb in comb_list])

        return processed_combinations

    def generate_exception_arguments(self) -> list:
        # Get the raw combinations from the sources
        raw_combinations = self.generate_raw_template()
        exception_conditions = self.parser.get_general_restrictions()

        # If no exception conditions are found, return the raw combinations
        if not exception_conditions:
            return raw_combinations

        # Process combinations based on exception conditions
        processed_combinations = []
        for comb in raw_combinations:
            comb_list = [list(comb)]
            for condition in exception_conditions:
                new_comb_list = []
                for partial_comb in comb_list:
                    new_partial_comb = list(partial_comb)
                    for arg_index, value in condition.items():
                        new_partial_comb[arg_index - 1] = (value, new_partial_comb[arg_index - 1])
                    new_comb_list.append(new_partial_comb)
                comb_list = new_comb_list
            processed_combinations.extend([tuple(comb) for comb in comb_list])

        return processed_combinations

    def generate_template(self):
        if self.parser.get_allowed():
            return self.enrichment_template()
        return self.generate_raw_template()


def check_restrictions(arguments: list, general_restrictions: list, input: dict = {}):
    for general_restriction in general_restrictions:
        for key, value in general_restriction.items():
            if input:
                # Check both input and arguments
                input_values = input.values()
                try:
                    eval_argument = ast.literal_eval(arguments[key - 1])
                except (ValueError, SyntaxError):
                    eval_argument = arguments[key - 1]  # Use the raw string if eval fails

                if eval_argument != value and value not in input_values:
                    break
            else:
                # Check only arguments
                try:
                    eval_argument = ast.literal_eval(arguments[key - 1])
                except (ValueError, SyntaxError):
                    eval_argument = arguments[key - 1]  # Use the raw string if eval fails

                if eval_argument != value:
                    break
        else:
            return True
    return False
