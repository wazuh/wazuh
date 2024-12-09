from helper_test.documentation_generator.html_generator import HTMLGenerator
from helper_test.documentation_generator.pdf_generator import PDFGenerator
from helper_test.documentation_generator.mark_down_generator import MarkdownGenerator
from helper_test.documentation_generator.exporter import *
from helper_test.documentation_generator.types import *
from helper_test.test_cases_generator.parser import Parser


class ExporterFactory():
    @staticmethod
    def get_exporter(type_: str) -> IExporter:
        if convert_str_to_exporter_type(type_) == ExporterType.PDF:
            return PDFGenerator()
        elif convert_str_to_exporter_type(type_) == ExporterType.HTML:
            return HTMLGenerator()
        elif convert_str_to_exporter_type(type_) == ExporterType.MARK_DOWN:
            return MarkdownGenerator()


def parse_yaml_to_documentation(parser: Parser):
    output = None
    target_field = None

    metadata = Metadata(
        parser.get_metadata()["description"],
        parser.get_metadata()["keywords"])

    arguments = {name: Argument(parser.get_types()[index], parser.get_sources()[index], parser.get_subset(
    )[index], parser.get_restrictions()[index]) for index, (name, arg_info) in enumerate(parser.get_arguments().items())}

    if parser.get_helper_type() == "map":
        output = Output(parser.get_output()[
                        "type"], parser.get_output().get("subset"))

    if parser.get_helper_type() != "map":
        target_field = TargetField(
            parser.get_target_field_type(), parser.get_target_field_subset())

    # TODO: Implement this
    # examples = [
    #     Example(
    #         test['arguments'],
    #         test['should_pass'],
    #         test['description'],
    #         test.get('skipped', False),
    #         test.get('expected')) for test in parser.get_tests()]

    documentation = Documentation(
        name=parser.get_name(),
        helper_type=parser.get_helper_type(),
        is_variadic=parser.is_variadic(),
        metadata=metadata,
        arguments=arguments,
        output=output,
        target_field=target_field,
        general_restrictions=parser.get_general_restrictions_details(),
        examples=[]
    )

    return documentation
