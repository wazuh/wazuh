#!/usr/bin/env python3

from pathlib import Path
from .test_data import TestData
from .buildtime_cases import BuildtimeCases
from .runtime_cases import RuntimeCases
from .parser import Parser
from .validator import Validator
from definition_types.utils import *
import yaml
import shutil


class Generator:
    def __init__(self):
        self.parser = Parser()
        self.validator = Validator(self.parser)
        self.testData = TestData(self.parser, self.validator)
        self.buildtimeCases = BuildtimeCases(self.testData)
        self.runtimeCases = RuntimeCases(self.testData)

    def clean_output_directory(self, output_directory: Path):
        for item in output_directory.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)

    def scan_and_verify_all_files(self, input_file_path: Path):
        input_file_path = input_file_path.resolve()
        if input_file_path.exists():
            self.validator.evaluator(input_file_path)
        else:
            sys.exit(f"Input file {input_file_path} does not exist.")

    def generate_output_file(self, output_directory: Path):
        for valid_data in self.validator.get_all_valid_data():
            self.parser.load_yaml_from_dict(valid_data)
            self.helper_type = self.parser.get_helper_type()
            self.testData.set_helper_type(self.helper_type)
            self.buildtimeCases.set_parser(self.parser)
            self.buildtimeCases.runner()
            self.runtimeCases.set_parser(self.parser)
            self.runtimeCases.runner()

            output_file_path = output_directory / f"{self.parser.get_name()}.yml"
            tests = self.testData.get_all_tests()
            tests["helper_type"] = self.helper_type
            with open(output_file_path, "w") as file:
                yaml.dump(tests, file)
            tests["build_test"].clear()
            tests["run_test"].clear()
