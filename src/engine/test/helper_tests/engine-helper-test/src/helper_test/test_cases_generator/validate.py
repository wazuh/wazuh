import sys
from pathlib import Path

from helper_test.test_cases_generator.parser import Parser
from helper_test.test_cases_generator.validator import Validator


def configure(subparsers):
    parser = subparsers.add_parser('validate',
                                   help="Validates that the helper descriptions comply with the schema"
                                   )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--input-file",
        help="Absolute or relative path where the description of the helper function is located",
    )
    group.add_argument(
        "--input-dir",
        help="Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located",
    )

    parser.set_defaults(func=run)


def validate(input_path: Path):
    parser = Parser()
    validator = Validator(parser)

    print("Validating input...")
    if not input_path.exists():
        raise FileNotFoundError(f"File {input_path} does not exist")

    if input_path.is_dir() and not list(input_path.rglob("*.yml")):
        raise FileNotFoundError(
            f"{input_path} does not contain any .yml files")
    print("Input validated successfully.")

    print("Validating helper descriptions...")
    if input_path.is_file():
        print(input_path)
        validator.evaluator(input_path)
    else:
        for file in input_path.rglob("*.yml"):
            print(file)
            validator.evaluator(file)
    print("Files validated successfully.")


def run(args):
    input_file = Path(args.get('input_file')).resolve() if args.get(
        'input_file') else None
    folder_path = Path(args.get('input_dir')).resolve() if args.get(
        'input_dir') else None

    try:
        validate(input_file or folder_path)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

    sys.exit(0)
