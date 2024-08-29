#!/usr/bin/env python3

import argparse
from pathlib import Path
import tempfile
from runner import __main__
import sys
import subprocess


class Config:
    """
    A class to store the configuration of the test runner.
    """
    environment_directory: str = ""
    binary_path: str = ""
    input: str = ""
    output: str = ""


config = Config()


def parse_arguments():
    """
    Parses command-line arguments for configuring the environment and selecting test cases to display.
    """
    parser = argparse.ArgumentParser(description="Generate and run all helper test cases")
    parser.add_argument("-e", "--environment", required=True, help="Environment directory")
    parser.add_argument("-b", "--binary", required=True, help="Path to the binary file")

    parser.add_argument(
        "-i", "--input", required=True,
        help="Absolute or relative path where of the directory where the helper configurations are located")
    parser.add_argument("-o", "--output", required=True,
                        help="Absolute or relative path where the test cases were generated")

    args = parser.parse_args()

    config.environment_directory = args.environment
    config.binary_path = args.binary

    config.input = args.input
    config.output = args.output


def main():
    parse_arguments()
    input = Path(config.input).resolve()
    outputs = []
    for subdir in input.iterdir():
        output_directory = Path(config.output).resolve() / subdir.name
        output_directory.mkdir(parents=True, exist_ok=True)
        outputs.append(output_directory)
        command = f'engine-helper-test-generator --folder_path {subdir} -o {output_directory.as_posix()}'
        try:
            subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            sys.exit(e.stderr)

    environment = Path(config.environment_directory).as_posix()
    binary = Path(config.binary_path).resolve()
    for output in outputs:
        for file in output.iterdir():
            command = f'engine-helper-test-runner -e {environment} -b {binary} --input_file_path {file} --failure_cases'
            print(f"Executing - {file.name}")
            try:
                subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                sys.exit(e.stderr)
