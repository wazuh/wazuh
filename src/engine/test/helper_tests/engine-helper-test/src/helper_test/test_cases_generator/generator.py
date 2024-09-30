#!/usr/bin/env python3

from pathlib import Path
from helper_test.test_cases_generator.test_data import TestData
from helper_test.test_cases_generator.buildtime_cases import BuildtimeCases
from helper_test.test_cases_generator.runtime_cases import RuntimeCases
from helper_test.test_cases_generator.parser import Parser
from helper_test.test_cases_generator.validator import Validator
from helper_test.definition_types.utils import *
import yaml
import shutil


class Generator:
    def __init__(self):
        """
        Initializes the Generator class with instances of Parser, Validator, TestData,
        BuildtimeCases, and RuntimeCases.
        """
        self.parser = Parser()
        self.validator = Validator(self.parser)
        self.testData = TestData(self.parser, self.validator)
        self.buildtimeCases = BuildtimeCases(self.testData)
        self.runtimeCases = RuntimeCases(self.testData)

    def clean_output_directory(self, output_directory: Path):
        """
        Cleans the output directory by removing all files, symlinks, and directories.

        :param output_directory: Path to the output directory to be cleaned.
        """
        for item in output_directory.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)

    def scan_and_verify_all_files(self, input_file_path: Path):
        """
        Scans and verifies all files in the input file path.

        :param input_file_path: Path to the input file to be scanned and verified.
        """
        input_file_path = input_file_path.resolve()
        if input_file_path.exists():
            self.validator.evaluator(input_file_path)
        else:
            sys.exit(f"Input file {input_file_path} does not exist.")

    def generate_output_file(self, output_directory: Path):
        """
        Generates output files based on validated data and saves them in the output directory.

        :param output_directory: Path to the directory where output files will be saved.
        """
        for valid_data in self.validator.get_all_valid_data():
            self.parser.load_yaml_from_dict(valid_data)
            self.helper_type = self.parser.get_helper_type()
            self.testData.set_helper_type(self.helper_type)
            self.buildtimeCases.set_parser(self.parser)
            self.buildtimeCases.runner()
            self.runtimeCases.set_parser(self.parser)
            self.runtimeCases.runner()

            output_file_path = (output_directory /
                                f"{self.parser.get_name()}.yml").resolve()
            print(f"Generating output file: {output_file_path}")
            tests = self.testData.get_all_tests()
            tests["helper_type"] = self.helper_type
            with open(output_file_path, "w") as file:
                yaml.dump(tests, file)
            tests["build_test"].clear()
            tests["run_test"].clear()
