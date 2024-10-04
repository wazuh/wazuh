from helper_test.documentation_generator.types import Documentation
from helper_test.documentation_generator.exporter import *
from collections import defaultdict
from pathlib import Path


class MarkdownGenerator(IExporter):
    def __init__(self):
        self.content = []
        # Structure to organize by type and keyword
        self.all_contents = defaultdict(lambda: defaultdict(list))
        self.helper_name = ""

    def create_signature(self, doc: Documentation):
        self.content.append(f"```\n")
        if not doc.is_variadic:
            self.content.append(
                f"field: {doc.name}({', '.join(str(v) for v in doc.arguments)})")
        else:
            self.content.append(
                f"field: {doc.name}({', '.join(str(v) for v in doc.arguments)}, [...])")
        self.content.append(f"```\n")

    def create_table(self, arguments: dict, headers: list):
        """
        Create a table in Markdown format.

        :param arguments: Dictionary of arguments.
        :return: Table string in Markdown format.
        """
        header_row = '| ' + ' | '.join(headers) + ' |'
        separator_row = '| ' + \
            ' | '.join(['-' * len(header) for header in headers]) + ' |'

        rows = []
        for name, info in arguments.items():
            row = []
            row.append(name)

            if isinstance(info.arg_type, list):
                row.append(', '.join(info.arg_type))
            else:
                row.append(info.arg_type)

            if info.source == "both":
                row.append("value or reference")
            else:
                row.append(info.source)

            if info.restrictions:
                row.append(', '.join(info.restrictions["allowed"]) if isinstance(
                    info.restrictions["allowed"], list) else str(info.restrictions["allowed"]))
            else:
                if isinstance(info.arg_type, list):
                    row.append("Any object")
                elif info.arg_type == "object":
                    row.append("Any object")
                elif info.generate == "integer":
                    row.append("Integers between `-2^63` and `2^63-1`")
                elif info.generate == "string":
                    row.append("Any string")
                elif info.generate == "ip":
                    row.append("Any IP")
                elif info.generate == "regex":
                    row.append("Any regex")
                elif info.generate == "hexadecimal":
                    row.append("Any hexadecimal")
                elif info.generate == "boolean":
                    row.append("Any boolean")
                elif info.generate == "all":
                    row.append("[number, string, boolean, object, array]")
            rows.append(row)
        data_rows = ['| ' + ' | '.join(row) + ' |' for row in rows]

        self.content.append('\n'.join([header_row, separator_row] + data_rows))
        self.content.append("\n")

    def create_output_table(self, output, headers: list):
        """
        Create a table in Markdown format.

        :param arguments: Dictionary of arguments.
        :return: Table string in Markdown format.
        """
        header_row = '| ' + ' | '.join(headers) + ' |'
        separator_row = '| ' + \
            ' | '.join(['-' * len(header) for header in headers]) + ' |'

        rows = []
        row = []
        if isinstance(output.type_, list):
            row.append(f"[{', '.join(output.type_)}]")
            row.append("-")
        else:
            row.append(output.type_)
            if output.type_ == "object":
                row.append("Any object")
            elif output.subset == "integer":
                row.append("Integers between `-2^63` and `2^63-1`")
            elif output.subset == "string":
                row.append("Any string")
            elif output.subset == "ip":
                row.append("Any IP")
            elif output.subset == "boolean":
                row.append("Any boolean")
            elif output.subset == "hexadecimal":
                row.append("Any hexadecimal")
            elif output.subset == "all":
                row.append("[number, string, boolean, object, array]")
        rows.append(row)
        data_rows = ['| ' + ' | '.join(row) + ' |' for row in rows]

        self.content.append('\n'.join([header_row, separator_row] + data_rows))
        self.content.append("\n")

    def create_document(self, doc: Documentation):
        """
        Creates a Markdown document for a given helper function's documentation.

        This method is responsible for generating a detailed Markdown documentation
        for a helper function, including its signature, arguments, target field, outputs,
        description, keywords, and general notes. The content generated is stored in
        the `all_contents` dictionary, categorized by helper type and name.

        :param doc: An instance of the Documentation class, containing all necessary
                    information about the helper function to document.
        """
        self.content = []
        self.helper_name = doc.name
        self.content.append(f"# {doc.name}\n")

        self.content.append(f"## Signature\n")
        self.create_signature(doc)

        if len(doc.arguments) > 0:
            self.content.append(f"## Arguments\n")
            headers = ["parameter", "Type", "Source", "Accepted values"]
            self.create_table(doc.arguments, headers)

        if doc.target_field:
            self.content.append(f"## Target Field\n")
            headers = ["Type", "Possible values"]
            self.create_output_table(doc.target_field, headers)

        if doc.output:
            self.content.append(f"## Outputs\n")
            headers = ["Type", "Possible values"]
            self.create_output_table(doc.output, headers)

        self.content.append(f"## Description\n")
        self.content.append(f"{doc.description}\n")
        self.content.append(f"**Keywords**\n")
        for keyword in doc.keywords:
            self.content.append(f"- `{keyword}` \n")

        if doc.general_restrictions:
            self.content.append(f"## Notes\n")
            for general_restriction in doc.general_restrictions:
                self.content.append(f"- {general_restriction}\n")

        self.all_contents[doc.helper_type][doc.name] = {
            "keywords": doc.keywords,
            "content": '\n'.join(self.content)
        }

    def save(self, output_dir: Path):
        """
        Saves all generated documentation to Markdown files.

        This method writes the summary, index, and detailed documentation of all
        helper functions to a specified output directory. It also creates a separate
        file that organizes helpers by their associated keywords.

        :param output_dir: A Path object representing the directory where the
                        documentation files should be saved.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        documentation_file = output_dir / "README.md"

        with open(documentation_file, 'w') as file:
            file.write("# Summary\n")
            file.write(
                "This documentation provides an overview of the auxiliary functions available. "
                "Auxiliary functions are modular components designed to perform specific operations on "
                "decoders or rules. Depending on their purpose, they are categorized "
                "into transformation, filter, or mapping functions.\n\n"
            )
            file.write("# Index\n")

            for helper_type, helpers in sorted(self.all_contents.items()):
                file.write(f"## {helper_type.capitalize()}\n")
                for helper_name in sorted(helpers.keys()):
                    file.write(f"- [{helper_name}](#{helper_name.lower()})\n")

            for helper_type, helpers in sorted(self.all_contents.items()):
                for helper_name, helper_info in sorted(helpers.items()):
                    file.write(helper_info["content"])
                    file.write("\n---\n")

        keyword_file = output_dir / "keyword_table.md"
        with open(keyword_file, 'w') as file:
            file.write("# By Keyword\n")
            file.write("| Helper | Keywords |\n")
            file.write("| ------ | -------- |\n")

            for helper_type, helpers in sorted(self.all_contents.items()):
                for helper_name, helper_info in sorted(helpers.items()):
                    keywords = ', '.join(sorted(set(helper_info["keywords"])))
                    file.write(
                        f"| [{helper_name}](documentation.md#{helper_name.lower()}) | {keywords} |\n")
