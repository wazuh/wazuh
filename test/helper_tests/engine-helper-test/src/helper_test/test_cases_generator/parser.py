#!/usr/bin/env python3

import yaml
import sys


class Parser:
    def __init__(self):
        """
        Initializes the Parser class with an empty dictionary for YAML data.
        """
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
        """
        Loads YAML data from a dictionary.

        Args:
            yaml_data (dict): The YAML data in dictionary format.
        """
        self.yaml_data = yaml_data

    def get_yaml_data(self):
        """
        Returns the loaded YAML data.

        Returns:
            dict: The YAML data.
        """
        return self.yaml_data

    def get_name(self):
        """
        Retrieves the name from the YAML data.

        Returns:
            str: The name attribute.

        Exits:
            If the name attribute is not found.
        """
        if "name" in self.yaml_data:
            return self.yaml_data["name"]
        sys.exit("Name attribute not found")

    def is_variadic(self) -> bool:
        """
        Checks if the helper is variadic.

        Returns:
            bool: True if variadic, otherwise exits.
        """
        if "is_variadic" in self.yaml_data:
            return self.yaml_data["is_variadic"]
        sys.exit(f"Variadic attribute not found in {self.get_name()} helper")

    def has_arguments(self):
        """
        Checks if the YAML data contains arguments.

        Returns:
            bool: True if arguments are present and not empty, otherwise False.
        """
        if "arguments" in self.yaml_data:
            if len(self.yaml_data["arguments"]) != 0:
                return True
        return False

    def get_minimum_arguments(self):
        """
        Gets the minimum number of arguments.

        Returns:
            int: The number of arguments.
        """
        minimum_arguments = 0
        if self.has_arguments():
            minimum_arguments = len(self.yaml_data["arguments"])
        return minimum_arguments

    def get_sources(self):
        """
        Retrieves sources from the arguments.

        Returns:
            list: List of sources.
        """
        sources = []
        if self.has_arguments():
            for argument in self.yaml_data["arguments"].values():
                if argument["source"]:
                    sources.append(argument["source"])
        return sources

    def get_types(self):
        """
        Retrieves types from the arguments.

        Returns:
            list: List of types.
        """
        types = []
        if self.has_arguments():
            for argument in self.yaml_data["arguments"].values():
                types.append(argument["type"])
        return types

    def get_subset(self):
        """
        Retrieves subsets from the arguments.

        Returns:
            list: List of subsets.
        """
        types = []
        if self.has_arguments():
            for argument in self.yaml_data["arguments"].values():
                types.append(argument.get("generate", "string"))
        return types

    def get_skips(self) -> list:
        """
        Retrieves the list of skipped items.

        Returns:
            list: List of skipped items.
        """
        return self.yaml_data.get("skipped", [])

    def get_restrictions(self):
        """
        Retrieves restrictions from the arguments.

        Returns:
            list: List of restrictions.
        """
        restrictions = []
        if self.has_arguments():
            for argument in self.yaml_data["arguments"].values():
                restrictions.append(argument.get("restrictions"))
        return restrictions

    def get_allowed_in_dict_format(self) -> dict:
        """
        Retrieves allowed arguments in dictionary format.

        Returns:
            dict: Dictionary of allowed arguments.
        """
        allowed_args = {}
        if self.has_arguments():
            for index, (arg_name, arg_info) in enumerate(self.yaml_data['arguments'].items()):
                if 'restrictions' in arg_info and 'allowed' in arg_info['restrictions']:
                    allowed_args[index] = arg_info['restrictions']['allowed']
        return allowed_args

    def get_forbidden_in_dict_format(self) -> dict:
        """
        Retrieves forbidden arguments in dictionary format.

        Returns:
            dict: Dictionary of forbidden arguments.
        """
        forbidden_args = {}
        if self.has_arguments():
            for index, (arg_name, arg_info) in enumerate(self.yaml_data['arguments'].items()):
                if 'restrictions' in arg_info and 'forbidden' in arg_info['restrictions']:
                    forbidden_args[index] = arg_info['restrictions']['forbidden']
        return forbidden_args

    def get_allowed(self):
        """
        Retrieves allowed arguments.

        Returns:
            dict: Dictionary of allowed arguments.
        """
        allowed = {}
        if self.get_minimum_arguments() != 0:
            for id, restriction in enumerate(self.get_restrictions()):
                if restriction is not None:
                    if "allowed" in restriction:
                        if id not in allowed:
                            allowed[id] = []
                        allowed[id].append(restriction["allowed"])
        return allowed

    def get_general_restrictions(self):
        """
        Retrieves general restrictions.

        Returns:
            list: List of general restrictions.

        Exits:
            If general restrictions are found without defined arguments.
        """
        general_restrictions = []
        if 'general_restrictions' in self.yaml_data:
            if self.get_minimum_arguments() == 0:
                sys.exit("General restrictions are not allowed without defined arguments")
            else:
                for restriction in self.yaml_data["general_restrictions"]:
                    general_restrictions.append(restriction.get("arguments", {}))
        return general_restrictions

    def get_general_restrictions_details(self):
        general_restrictions = []
        if 'general_restrictions' in self.yaml_data:
            if self.get_minimum_arguments() == 0:
                sys.exit("General restrictions are not allowed without defined arguments")
            else:
                for restriction in self.yaml_data["general_restrictions"]:
                    general_restrictions.append(restriction["details"])
        return general_restrictions

    def has_target_field(self):
        """
        Checks if a target field is present.

        Returns:
            bool: True if target field is present, otherwise False.
        """
        return "target_field" in self.yaml_data

    def get_target_field_type(self):
        """
        Retrieves the type of the target field.

        Returns:
            str: The type of the target field, or None if not present.
        """
        if self.has_target_field:
            return self.yaml_data["target_field"]["type"]
        return None

    def get_target_field_subset(self):
        """
        Retrieves the subset of the target field.

        Returns:
            str: The subset of the target field, or an empty string if not present.
        """
        if self.has_target_field:
            return self.yaml_data["target_field"].get("generate", "")
        return None

    def get_tests(self):
        """
        Retrieves test data.

        Returns:
            dict: The test data, or None if not present.
        """
        if "test" in self.yaml_data:
            return self.yaml_data["test"]
        return None

    def has_helper_type(self):
        """
        Checks if a helper type is present.

        Returns:
            bool: True if helper type is present, otherwise False.
        """
        return "helper_type" in self.yaml_data

    def get_helper_type(self):
        """
        Retrieves the helper type.

        Returns:
            str: The helper type, or None if not present.
        """
        if self.has_helper_type():
            return self.yaml_data["helper_type"]
        return None

    def get_metadata(self) -> dict:
        return self.yaml_data.get("metadata", {})

    def get_arguments(self) -> dict:
        return self.yaml_data.get("arguments", {})

    def get_name_id_arguments(self) -> dict:
        name_id_arguments = {}
        arguments = self.get_arguments()
        if len(arguments) != 0:
            for id, (key, value) in enumerate(self.get_arguments().items()):
                name_id_arguments[key] = id
        return name_id_arguments

    def get_output(self):
        return self.yaml_data.get("output", "")
