import sys
from pathlib import Path

from helper_test.documentation_generator.exporter import IExporter
from helper_test.documentation_generator.types import *
from helper_test.documentation_generator.documentation import *
from helper_test.test_cases_generator.validate import validate as validate_helper_desc


def configure(subparsers):
    parser = subparsers.add_parser('generate-doc',
                                   help="Generates files containing documentation for a given helper")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--input-file",
        help="Absolute or relative path where the description of the helper function is located",
    )
    group.add_argument(
        "--input-dir",
        help="Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located",
    )

    parser.add_argument(
        "--exporter",
        help="Absolute or relative path of the directory where the generated test files will be located",
        default="mark_down"
    )

    parser.add_argument(
        "-o",
        "--output-path",
        required=True,
        help="Absolute or relative path of the directory where the generated documentation files will be located",
    )

    parser.set_defaults(func=run)


def generate_documentation(parser: Parser, exporter: IExporter, file: Path, output_path: Path):
    print(f"Loading file: {file}")
    parser.load_yaml_from_file(file.as_posix())
    documentation = parse_yaml_to_documentation(parser)
    exporter.create_document(documentation)
    print(f"Saving documentation to {output_path}")
    exporter.save(output_path)


def generate(input_path: Path, exporter_type: str, output_path: Path):
    print("Validating input...")
    if not input_path.exists():
        raise FileNotFoundError(f"File {input_path} does not exist")

    if input_path.is_dir() and not list(input_path.rglob("*.yml")):
        raise FileNotFoundError(
            f"{input_path} does not contain any .yml files")
    print("Input validated successfully.")

    validate_helper_desc(input_path)

    print("Generating documentation...")
    exporter = ExporterFactory.get_exporter(exporter_type)
    parser = Parser()

    if input_path.is_file():
        generate_documentation(parser, exporter, input_path, output_path)
    else:
        for file in input_path.rglob("*.yml"):
            generate_documentation(parser, exporter, file, output_path)
    print("Documentation generated successfully.")


def run(args):
    input_file = Path(args.get('input_file')).resolve() if args.get(
        'input_file') else None
    input_dir = Path(args.get('input_dir')).resolve() if args.get(
        'input_dir') else None
    exporter_type = args.get('exporter')
    output_path = Path(args.get('output_path')).resolve()

    try:
        generate(input_file or input_dir, exporter_type, output_path)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

    sys.exit(0)
