#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
from test_cases_generator.parser import Parser
from .documentation import *
from .exporter import IExporter
from .types import *
import subprocess


def parse_arguments() -> argparse.Namespace:
    arg_parser = argparse.ArgumentParser(description="Generates files containing documentation for a given helper")
    arg_parser.add_argument(
        "--input_file_path",
        help="Absolute or relative path where the description of the helper function is located",
    )
    arg_parser.add_argument(
        "--folder_path",
        help="Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located",
    )
    arg_parser.add_argument(
        "--exporter",
        help="Absolute or relative path of the directory where the generated test files will be located",
    )
    arg_parser.add_argument(
        "-o",
        "--output_path",
        help="Absolute or relative path of the directory where the generated documentation files will be located",
    )

    args = arg_parser.parse_args()

    if args.input_file_path and args.folder_path:
        arg_parser.error("Only one of --input_file_path or --folder_path can be specified.")

    return args


def generate_documentation(parser: Parser, exporter: IExporter, file: Path, output_path: Path):
    parser.load_yaml_from_file(file)
    documentation = parse_yaml_to_documentation(parser)
    exporter.create_document(documentation)
    exporter.save(output_path)


def main():
    args = parse_arguments()
    parser = Parser()
    exporter_type = args.exporter if args.exporter else "mark_down"
    output_path = Path(args.output_path if args.output_path else "/tmp/documentation")
    exporter = ExporterFactory.get_exporter(exporter_type)
    if args.input_file_path:
        command = f'engine-helper-test-validator --input_file_path {args.input_file_path}'
        try:
            subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            sys.exit(e.stderr)
        generate_documentation(parser, exporter, Path(args.input_file_path), output_path)
    elif args.folder_path:
        folder_path = Path(args.folder_path)
        yaml_files = folder_path.rglob('*.yml')
        yaml_files = list(yaml_files) + list(folder_path.rglob('*.yaml'))

        if not yaml_files:
            sys.exit("No YAML files found in the specified directory.")

        for file in yaml_files:
            command = f'engine-helper-test-validator --input_file_path {file}'
            try:
                subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                sys.exit(e.stderr)
            generate_documentation(parser, exporter, file, output_path)

    else:
        sys.exit("It is necessary to indicate a file or directory that contains a configuration yaml")
