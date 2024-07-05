import yaml
import sys


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

    def has_helper_type(self):
        return "helper_type" in self.yaml_data

    def get_helper_type(self):
        if self.has_helper_type():
            return self.yaml_data["helper_type"]
        return None
