#!/usr/bin/env python3

from enum import Enum
import random
import re

MAXIMUM_NUMBER_OF_ARGUMENTS = 40


class Source(Enum):
    VALUE = 1
    REFERENCE = 2
    BOTH = 3


class Number(type):
    pass
    # def __init__(self):
    #     print("same")


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
