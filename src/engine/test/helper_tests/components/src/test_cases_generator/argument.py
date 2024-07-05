#!/usr/bin/env python3

from definition_types.utils import *
import json

reference_counter = 0


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
