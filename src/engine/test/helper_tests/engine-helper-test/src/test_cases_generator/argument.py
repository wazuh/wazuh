#!/usr/bin/env python3

from definition_types.utils import *
import json

reference_counter = 0


class Argument:
    def __init__(self, value=None) -> None:
        """
        Initializes an Argument instance.

        Args:
            value (optional): Initial value for the argument.
        """
        self.value = value
        self.general_restrictions = []
        self.allowed = []

    def configure_generation(
            self, type_: str, subset: str, source: str, restriction: dict, ignore_allowed=False) -> None:
        """
        Configures the generation parameters for the argument.

        Args:
            type_ (str): Type of the argument.
            subset (str): Subset of the argument.
            source (str): Source of the argument.
            restriction (dict): Restrictions for the argument.
            ignore_allowed (bool, optional): Whether to ignore allowed restrictions.
        """
        self.type_ = convert_string_to_type(type_)
        self.subset = convert_string_to_subset(subset)
        self.source = convert_string_to_source(source)
        self.restriction = restriction
        self.ignore_allowed = ignore_allowed
        if self.has_allowed():
            self.allowed = restriction["allowed"]

    def configure_target_field(self, type_: str, subset: str):
        """
        Configures the argument as a target field.

        Args:
            type_ (str): Type of the argument.
            subset (str): Subset of the argument.
        """
        self.type_ = convert_string_to_type(type_)
        self.subset = convert_string_to_subset(subset)
        self.source = Source.VALUE
        self.restriction = None

    def configure_only_value(self, source: str):
        """
        Configures the argument with only a value source.

        Args:
            source (str): Source of the argument.
        """
        self.source = convert_string_to_source(source)
        self.general_restrictions = ["any"]
        self.allowed = ["any"]
        self.restriction = None
        self.ignore_allowed = False

    def has_allowed(self) -> bool:
        """
        Checks if the argument has allowed restrictions.

        Returns:
            bool: True if allowed restrictions are present, False otherwise.
        """
        if self.restriction != None:
            return "allowed" in self.restriction
        return False

    def set_general_restrictions(self, general_restrictions: list):
        """
        Sets general restrictions for the argument.

        Args:
            general_restrictions (list): List of general restrictions.
        """
        self.general_restrictions = general_restrictions

    def has_general_restrictions(self) -> bool:
        """
        Checks if the argument has general restrictions.

        Returns:
            bool: True if general restrictions are present, False otherwise.
        """
        if len(self.general_restrictions) == 0:
            return False
        return True

    def generate_random_value(self):
        """
        Generates a random value based on the argument's type and subset.

        Returns:
            object: Generated random value.
        """
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
        """
        Generates a random number based on the argument's subset.

        Returns:
            int or float: Generated random number.
        """
        if self.subset == int:
            return random.randint(0, 9)
        elif self.subset == float:
            return random.uniform(0, 9)
        elif self.subset == Double:
            return float(format(random.uniform(0, 9), '.2f'))

    def generate_random_string(self):
        """
        Generates a random string based on the argument's subset.

        Returns:
            str: Generated random string.
        """
        if self.subset == Hexadecimal:
            return Hexadecimal.random_hex().__str__()
        elif self.subset == Ip:
            return Ip(random.choice(["111.111.1.11", "222.222.2.22"])).__str__()
        elif self.subset == Regex:
            return json.dumps(Regex("^(bye pcre\\d)$").__str__())
        else:
            return "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(random.randint(2, 10)))

    def generate_random_boolean(self):
        """
        Generates a random boolean value.

        Returns:
            bool: Generated random boolean.
        """
        return True

    def generate_random_list(self):
        """
        Generates a random list based on the argument's subset.

        Returns:
            list: Generated random list.
        """
        subset_value_mapping = {
            int: lambda: random.randint(0, 9),
            float: lambda: random.uniform(0, 9),
            Double: lambda: float(format(random.uniform(0, 9), '.2f')),
            str: lambda: "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(random.randint(2, 10))),
            Hexadecimal: lambda: Hexadecimal.random_hex().__str__(),
            Ip: lambda: Ip(random.choice(["111.111.1.11", "222.222.2.22"])).__str__(),
            Regex: lambda: json.dumps(Regex("^(bye pcre\\d)$").__str__()),
            bool: lambda: True,
            dict: lambda: {"key": "value"}
        }

        if self.subset != "all":
            if self.subset not in subset_value_mapping:
                sys.exit("Subset is not supported for array")
            return [subset_value_mapping.get(self.subset)()]
        return [subset_value_mapping.get(random.choice([int, float, Double, str, dict, bool]))()]

    def generate_random_object(self):
        """
        Generates a random object.

        Returns:
            dict: Generated random object.
        """
        return {"key": "value"}

    def generate_value(self):
        """
        Generates either a random value or returns the configured value.

        Returns:
            object: Generated random value or configured value.
        """
        if (not self.has_allowed() and not self.has_general_restrictions()) or self.ignore_allowed:
            return self.generate_random_value()
        else:
            return self.value

    def generate_reference(self):
        """
        Generates a reference object.

        Returns:
            dict: Generated reference object.
        """
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
        """
        Checks if a value is a reference.

        Args:
            value (any): Value to check.

        Returns:
            bool: True if the value is a reference, False otherwise.
        """
        if isinstance(value, dict):
            if "name" in value:
                return True
        return False

    def get(self, is_target_field=False):
        """
        Retrieves the value or reference based on the argument's source.

        Args:
            is_target_field (bool, optional): Indicates if the value is for a target field.

        Returns:
            str or dict: Generated value or reference.
        """
        if self.source == Source.VALUE:
            if not is_target_field:
                return json.dumps(self.generate_value())
            return self.generate_value()
        elif self.source == Source.REFERENCE:
            return self.generate_reference()
        elif self.source == Source.BOTH:
            return random.choice([self.generate_value(), self.generate_reference()])
