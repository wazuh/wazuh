#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path
from helper_test_generator.generator import Generator
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


def main():
    args = parse_arguments()

    generator = Generator()
    if is_temp_path(args.output_path):
        output_directory = Path(args.output_path)
        output_directory.mkdir(parents=True, exist_ok=True)
        generator.clean_output_directory(output_directory)
        if args.input_file_path:
            generator.scan_and_verify_all_files(Path(args.input_file_path))
        elif args.folder_path:
            for file in Path(args.folder_path).iterdir():
                if file.is_file() and (file.suffix in ['.yml', '.yaml']):
                    generator.scan_and_verify_all_files(file)
        else:
            sys.exit("It is necessary to indicate a file or directory that contains a configuration yaml")
        generator.generate_output_file(output_directory)
    else:
        sys.exit("the output directory must be a temporary one")


if __name__ == '__main__':
    sys.exit(main())
