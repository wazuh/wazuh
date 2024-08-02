from .types import Documentation
from .exporter import *
from collections import defaultdict


class MarkdownGenerator(IExporter):
    def __init__(self):
        self.content = []
        self.all_contents = defaultdict(lambda: defaultdict(list))  # Structure to organize by type and keyword
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

        # Merge all rows
        self.content.append('\n'.join([header_row, separator_row] + data_rows))
        self.content.append("\n")

    def create_document(self, doc: Documentation):
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
            headers = ["Type", "Posible values"]
            self.create_output_table(doc.target_field, headers)

        if doc.output:
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

        # Organiza el contenido por tipo de helper y luego por keyword
        for keyword in doc.keywords:
            self.all_contents[doc.helper_type][keyword].append('\n'.join(self.content))

    def save(self, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)

        home_file = output_dir / "index.md"
        with open(home_file, 'w') as file:
            file.write("# Helper Types\n")
            for helper_type in sorted(self.all_contents.keys()):
                file.write(f"- [{helper_type}](./{helper_type}/index.md)\n")

        for helper_type, keywords in self.all_contents.items():
            type_dir = output_dir / helper_type
            type_dir.mkdir(parents=True, exist_ok=True)

            type_index_file = type_dir / "index.md"
            with open(type_index_file, 'w') as file:
                file.write(f"# {helper_type}\n")
                file.write(f"## Keywords\n")
                for keyword in sorted(keywords.keys()):
                    file.write(f"- [{keyword}](./{keyword}.md)\n")

            for keyword, docs in keywords.items():
                keyword_file = type_dir / f"{keyword}.md"
                with open(keyword_file, 'w') as file:
                    for doc in docs:
                        file.write(doc)
                        file.write("\n---\n")
