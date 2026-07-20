import sys
import tempfile
from pathlib import Path

from helper_test.test_cases_generator.generator import Generator


def configure(subparsers):
    parser = subparsers.add_parser('generate-tests',
                                   help="Generates files containing test cases for a given helper"
                                   )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--input-file",
        help="Absolute or relative path where the description of the helper function is located")
    group.add_argument(
        "--input-dir",
        help="Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located")

    parser.add_argument(
        "-o",
        "--output-path",
        required=True,
        help="Absolute or relative path of the directory where the generated test files will be located")

    parser.set_defaults(func=run)


def is_temp_path(path_str):
    path = Path(path_str).resolve()
    temp_dir = Path(tempfile.gettempdir()).resolve()
    return str(path).startswith(str(temp_dir))


def generate(input_path: Path, output_path: Path):
    print("Validating input...")
    if not input_path.exists():
        raise FileNotFoundError(f"File {input_path} does not exist")

    if input_path.is_dir() and not list(input_path.rglob("*.yml")):
        raise FileNotFoundError(
            f"{input_path} does not contain any .yml files")

    if not is_temp_path(output_path):
        raise ValueError("Output path must be a temporary directory")
    print("Input validated successfully.")

    generator = Generator()

    print(f'Cleaning output folder: {output_path}')
    output_path.mkdir(parents=True, exist_ok=True)
    generator.clean_output_directory(output_path)
    print('Output folder cleaned.')

    print('Scanning and verifying input files...')
    if input_path.is_file():
        print(input_path)
        generator.scan_and_verify_all_files(input_path)
    else:
        for file in input_path.rglob("*.yml"):
            print(file)
            generator.scan_and_verify_all_files(file)
    print('Input files scanned and verified.')

    print('Generating output files...')
    generator.generate_output_file(output_path)
    print(f'Output files generated in {output_path}')


def run(args):
    input_file = Path(args.get('input_file')).resolve() if args.get(
        'input_file') else None
    input_dir = Path(args.get('input_dir')).resolve() if args.get(
        'input_dir') else None
    output_path = Path(args.get('output_path')).resolve()

    try:
        generate(input_file or input_dir, output_path)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

    sys.exit(0)
