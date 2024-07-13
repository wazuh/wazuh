from .types import Documentation
from .exporter import *


class MarkdownGenerator(IExporter):
    def __init__(self):
        self.content = []
        self.helper_name = ""

    def create_signature(self, doc: Documentation):
        self.content.append(f"```\n")
        if not doc.is_variadic:
            self.content.append(f"field: {doc.name}({', '.join(str(v) for v in doc.arguments)})")
        else:
            self.content.append(f"field: {doc.name}({', '.join(str(v) for v in doc.arguments)}, [...])")
        self.content.append(f"```\n")

    def create_table(self, arguments: dict, headers: list):
        """
        Create a table in Markdown format.

        :param arguments: Dictionary of arguments.
        :return: Table string in Markdown format.
        """
        # Create the header row
        header_row = '| ' + ' | '.join(headers) + ' |'
        separator_row = '| ' + ' | '.join(['-' * len(header) for header in headers]) + ' |'

        # Create the data rows
        rows = []
        for name, info in arguments.items():
            row = []  # Create a new list for each argument
            row.append(name)

            # Handle arg_type being a list or a string
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
                if info.arg_type == "object":
                    row.append("Any object")
                elif info.arg_type == "array":
                    row.append("Any array")
                elif info.generate == "integer":
                    row.append("Integers between `-2^63` and `2^63-1`")
                elif info.generate == "string":
                    row.append("Any string")
                elif info.generate == "ip":
                    row.append("Any IP")

            rows.append(row)
        data_rows = ['| ' + ' | '.join(row) + ' |' for row in rows]

        # Merge all rows
        self.content.append('\n'.join([header_row, separator_row] + data_rows))
        self.content.append("\n")

    def create_output_table(self, output, headers: list):
        """
        Create a table in Markdown format.

        :param arguments: Dictionary of arguments.
        :return: Table string in Markdown format.
        """
        # Create the header row
        header_row = '| ' + ' | '.join(headers) + ' |'
        separator_row = '| ' + ' | '.join(['-' * len(header) for header in headers]) + ' |'

        # Create the data rows
        rows = []
        row = []  # Create a new list for each argument
        row.append(output.type_)
        if output.type_ == "object":
            row.append("Any object")
        elif output.type_ == "array":
            row.append("Any array")
        elif output.subset == "integer":
            row.append("Integers between `-2^63` and `2^63-1`")
        elif output.subset == "string":
            row.append("Any string")
        elif output.subset == "ip":
            row.append("Any IP")
        rows.append(row)
        data_rows = ['| ' + ' | '.join(row) + ' |' for row in rows]

        # Merge all rows
        self.content.append('\n'.join([header_row, separator_row] + data_rows))
        self.content.append("\n")

    def create_document(self, doc: Documentation):
        self.content = []
        self.helper_name = doc.name
        self.content.append(f"# {doc.name}\n")

        self.content.append(f"## Signature\n")
        self.create_signature(doc)

        self.content.append(f"## Arguments\n")
        headers = ["parameter", "Type", "Source", "Accepted values"]
        self.create_table(doc.arguments, headers)

        self.content.append(f"## Outputs\n")
        headers = ["Type", "Posible values"]
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

        # self.content.append("\n### Examples\n")
        # for idx, example in enumerate(doc.examples, start=1):
        #     self.content.append(f"**Example {idx}**:")
        #     self.content.append("  - **Arguments**:")
        #     for arg, value in example.arguments.items():
        #         self.content.append(f"    - `{arg}`: `{value}`")
        #     self.content.append(f"  - **Should Pass**: `{example.should_pass}`")
        #     if example.skipped:
        #         self.content.append(f"  - **Skipped**: `{example.skipped}`")
        #     if example.expected is not None:
        #         self.content.append(f"  - **Expected**: `{example.expected}`")
        #     self.content.append(f"  - **Description**: {example.description}\n")

    def save(self, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        with open((output_dir / self.helper_name).as_posix() + ".md", 'w') as file:
            file.write('\n'.join(self.content))
