#!/usr/bin/env python3

from enum import Enum
import random
import re

MAXIMUM_NUMBER_OF_ARGUMENTS = 40


class Source(Enum):
    """
    Enumeration for different sources.
    """
    VALUE = 1
    REFERENCE = 2
    BOTH = 3


class Number(type):
    """
    Base class for number types.
    """
    pass


class String(type):
    """
    Base class for string types.
    """
    pass


class Boolean(type):
    """
    Base class for boolean types.
    """
    pass


class Object(type):
    """
    Base class for object types.
    """
    pass


class Double(Number):
    """
    Class for double precision number type.
    """
    pass


class Hexadecimal:
    """
    Class representing a hexadecimal value.
    """

    def __init__(self, hex_value):
        if not self._validate_hex(hex_value):
            raise ValueError(f"{hex_value} is not a valid hexadecimal number")
        self.hex_value = hex_value.lower()

    def __str__(self):
        return self.hex_value

    @staticmethod
    def _validate_hex(hex_value):
        """
        Validates if a string is a hexadecimal value.

        Args:
            hex_value (str): The string to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        if isinstance(hex_value, str) and hex_value.startswith("0x"):
            hex_digits = hex_value[2:]
            return all(c in "0123456789abcdefABCDEF" for c in hex_digits)
        return False

    @staticmethod
    def random_hex(length=8):
        """
        Generates a random hexadecimal value.

        Args:
            length (int): Length of the hexadecimal value.

        Returns:
            Hexadecimal: The generated random hexadecimal value.
        """
        random_hex_value = "0x" + "".join(
            random.choice("0123456789abcdef") for _ in range(length)
        )
        return Hexadecimal(random_hex_value)


class Ip(str):
    """
    Class representing an IP address.
    """

    def __init__(self, address):
        if not self._validate_ip(address):
            raise ValueError(f"{address} is not a valid IP address")
        self.address = address

    def __str__(self):
        return self.address

    @staticmethod
    def _validate_ip(address):
        """
        Validates if a string is an IP address.

        Args:
            address (str): The string to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if pattern.match(address):
            octets = address.split(".")
            for octet in octets:
                if not 0 <= int(octet) <= 255:
                    return False
            return True
        return False


class Regex(str):
    """
    Class representing a regular expression.
    """

    def __init__(self, pattern):
        if not self._validate_pattern(pattern):
            raise ValueError("Invalid regular expression pattern")
        self.pattern = pattern
        self.regex = re.compile(pattern)

    def _validate_pattern(self, pattern):
        """
        Validates if a string is a regular expression.

        Args:
            pattern (str): The string to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
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
