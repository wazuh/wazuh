#!/usr/bin/env python3

from .types import *
from typing import Union
import sys
import ast


def convert_string_to_type(type_: str) -> type:
    """
    Converts a string to a corresponding type.

    Args:
        type_ (str): The string representation of the type.

    Returns:
        type: The corresponding type.
    """
    return TYPE_MAPPING.get(type_)


def convert_string_to_subset(subset: str) -> type:
    """
    Converts a string to a corresponding subset type.

    Args:
        subset (str): The string representation of the subset type.

    Returns:
        type: The corresponding subset type.
    """
    if subset != "all":
        return SUBSET_MAPPING.get(subset)
    return subset


def convert_string_to_source(source: str) -> Source:
    """
    Converts a string to a corresponding source enum.

    Args:
        source (str): The string representation of the source.

    Returns:
        Source: The corresponding source enum.
    """
    return SOURCE_MAPPING.get(source)


def type_to_string(type_: type) -> str:
    """
    Converts a type to its string representation.

    Args:
        type_ (type): The type to convert.

    Returns:
        str: The string representation of the type.
    """
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


def change_source(source: str) -> str:
    """
    Changes the source value.

    Args:
        source (str): The current source.

    Returns:
        str: The changed source.
    """
    if source == "value":
        return "reference"
    elif source == "reference":
        return "value"
    else:
        return source


def change_type(type_: Union[str, list]) -> dict:
    """
    Removes specific types from the correspondence map.

    Args:
        type_ (Union[str, list]): The type or list of types to remove.

    Returns:
        dict: The updated correspondence map.
    """
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


def check_restrictions(arguments: list, general_restrictions: list, input: dict = {}) -> bool:
    """
    Checks if the arguments meet the general restrictions.

    Args:
        arguments (list): The list of arguments to check.
        general_restrictions (list): The list of general restrictions.
        input (dict, optional): Additional input to consider. Defaults to {}.

    Returns:
        bool: True if the arguments meet the restrictions, False otherwise.
    """
    for general_restriction in general_restrictions:
        if general_restriction:
            for index, (key, value) in enumerate(general_restriction.items()):
                if input:
                    # Check both input and arguments
                    input_values = input.values()
                    try:
                        eval_argument = ast.literal_eval(arguments[index])
                    except (ValueError, SyntaxError):
                        eval_argument = arguments[index]  # Use the raw string if eval fails

                    if eval_argument != value and value not in input_values:
                        break
                else:
                    # Check only arguments
                    try:
                        eval_argument = ast.literal_eval(arguments[index])
                    except (ValueError, SyntaxError):
                        eval_argument = arguments[index]  # Use the raw string if eval fails

                    if eval_argument != value:
                        break
            else:
                return True
    return False
