#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
from test_cases_generator.parser import Parser
from .documentation import *
from .exporter import IExporter
from .types import *
import tempfile


def parse_arguments() -> argparse.Namespace:
    arg_parser = argparse.ArgumentParser(description="Generates files containing test cases for a given helper")
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
        help="Absolute or relative path of the directory where the generated test files will be located",
    )

    args = arg_parser.parse_args()

    if args.input_file_path and args.folder_path:
        arg_parser.error("Only one of --input_file_path or --folder_path can be specified.")

    return args


def is_temp_path(path_str):
    path = Path(path_str).resolve()
    temp_dir = Path(tempfile.gettempdir()).resolve()
    return str(path).startswith(str(temp_dir))


def generate_documentation(parser: Parser, exporter: IExporter, file: Path, output_dir: Path):
    parser.load_yaml_from_file(file)
    documentation = parse_yaml_to_documentation(parser)
    exporter.create_document(documentation)
    exporter.save(output_dir)


def main():
    args = parse_arguments()
    parser = Parser()
    exporter_type = args.exporter if args.exporter else "mark_down"
    output_dir = Path(args.output_path if args.output_path else "/tmp/documentation")
    exporter = ExporterFactory.get_exporter(exporter_type)
    if args.input_file_path:
        generate_documentation(parser, exporter, Path(args.input_file_path), output_dir)
    elif args.folder_path:
        for file in Path(args.folder_path).iterdir():
            if file.is_file() and (file.suffix in ['.yml', '.yaml']):
                generate_documentation(parser, exporter, file, output_dir)
    else:
        sys.exit("It is necessary to indicate a file or directory that contains a configuration yaml")

    print("Success validation")
