# SPDX-License-Identifier: AGPL-3.0-or-later
from helper_test.documentation_generator.types import Documentation, Example
from helper_test.documentation_generator.exporter import *
from helper_test.runner import get_helper_test_kvdb_resource
from collections import defaultdict
from pathlib import Path
from typing import List
import json
import re
import yaml

class MarkdownGenerator(IExporter):
    def __init__(self):
        self.content = []
        # Structure to organize by type and keyword
        self.all_contents = defaultdict(lambda: defaultdict(list))
        self.helper_name = ""

    def create_signature(self, doc: Documentation):
        # An optional argument is shown in brackets, like the variadic tail.
        names = [f"[{name}]" if getattr(arg, "optional", False) else str(name)
                 for name, arg in doc.arguments.items()]
        self.content.append(f"```\n")
        if not doc.is_variadic:
            self.content.append(
                f"field: {doc.name}({', '.join(names)})")
        else:
            self.content.append(
                f"field: {doc.name}({', '.join(names)}, [...])")
        self.content.append(f"```\n")

    @staticmethod
    def _ordered_example_arguments(doc: Documentation, arguments: dict) -> list:
        """
        Order an example's arguments as the test runner passes them to the helper
        (RuntimeCases.order_argument_list): declared arguments in declaration order, then the
        variadic extras ordered by their numeric `_<n>` suffix. The YAML key order is not the
        call order, so rendering it verbatim would show a call the tests never make.
        """
        declared_order = {name: index for index, name in enumerate(doc.arguments)}
        declared = sorted(((k, v) for k, v in arguments.items() if k in declared_order),
                          key=lambda kv: declared_order[kv[0]])
        suffix = re.compile(r'_(\d+)$')
        extras = sorted(((k, v) for k, v in arguments.items()
                         if k not in declared_order and suffix.search(k)),
                        key=lambda kv: int(suffix.search(kv[0]).group(1)))
        return declared + extras

    def _format_call_arg(self, v):
        """
        Format a single call argument for the helper invocation in Markdown.

        :param v: Argument value to render (may be None, bool, number, str, list, dict).
        :return: String representation suitable for use inside the helper call.
        """
        if v is None:
            return "null"
        # The engine's helper parser reads objects, arrays and booleans as JSON (the test
        # generator passes them through json.dumps); a Python repr ({'k': 'v'}, True) is not JSON.
        # Compact separators keep ": " out of the call so it stays a plain YAML scalar.
        if isinstance(v, (bool, dict, list)):
            return json.dumps(v, separators=(',', ':'))
        return repr(v)

    @staticmethod
    def _yaml_scalar(value: str) -> str:
        """
        Render a helper call as a YAML scalar, single-quoting it only when a plain scalar
        would not load back as the same string.
        """
        try:
            if yaml.safe_load(f"k: {value}") == {"k": value}:
                return value
        except yaml.YAMLError:
            pass
        return "'" + value.replace("'", "''") + "'"

    @staticmethod
    def _accepted_values(info) -> str:
        """
        Describe the values an unrestricted argument accepts. The declared type decides first:
        the parser reports a `generate` subset of "string" for every argument that sets none
        (booleans and arrays included), so the subset only refines a number or a string.
        """
        arg_type, generate = info.arg_type, info.generate
        # A documentation-only `accepted_values` text overrides the one derived from the type.
        if getattr(info, "accepted_values", None):
            return info.accepted_values
        if isinstance(arg_type, list):
            return "Any value of the listed types"
        if generate == "all":
            return "[number, string, boolean, object, array]"
        if arg_type == "object":
            return "Any object"
        if arg_type == "array":
            return "Any array"
        if arg_type == "boolean":
            return "Any boolean"
        if arg_type == "number":
            return "Integers between `-2^63` and `2^63-1`" if generate == "integer" else "Any number"
        return {
            "ip": "Any IP",
            "regex": "Any regex",
            "hexadecimal": "Any hexadecimal",
        }.get(generate, "Any string")

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
            row.append(f"{name} (optional)" if getattr(info, "optional", False) else name)

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
                row.append(self._accepted_values(info))
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
        if getattr(output, "path", None):
            row.append(output.path)
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
            # No (or an unlisted) subset: fall back on the declared type so the row keeps its cell.
            elif output.type_ == "boolean":
                row.append("Any boolean")
            elif output.type_ in ("number", "double", "float"):
                row.append("Any number")
            elif output.type_ == "array":
                row.append("Any array")
            else:
                row.append("Any string")
        rows.append(row)
        data_rows = ['| ' + ' | '.join(row) + ' |' for row in rows]

        self.content.append('\n'.join([header_row, separator_row] + data_rows))
        self.content.append("\n")

    def create_tests_table(self, doc: Documentation):
        """
        Creates a human-readable report for test cases with examples, descriptions, usage, and expected results.
        :param doc: Documentation object containing examples, arguments, and metadata of the helper.
        """

        helper_type = doc.helper_type
        self.content.append(f"## Examples\n")

        is_variadic = any(arg_name.endswith("...") for arg_name in doc.arguments.keys())
        variadic_base_name = None
        if is_variadic:
            variadic_base_name = [arg_name[:-3] for arg_name in doc.arguments.keys() if arg_name.endswith("...")][0]

        for idx, example in enumerate(doc.examples, start=1):
            self.content.append(f"### Example {idx}\n")

            description = example.description or "No description provided."

            args_values = []
            event_data = {}

            if doc.arguments:
                for key, arg in self._ordered_example_arguments(doc, example.arguments or {}):
                    arg_key_for_source = key
                    if is_variadic and key.startswith(variadic_base_name):
                        arg_key_for_source = variadic_base_name + "..."

                    arg_def = doc.arguments.get(arg_key_for_source, None)
                    arg_source = getattr(arg_def, "source", "value") if arg_def else "value"

                    if isinstance(arg, dict) and "source" in arg:
                        if arg["source"] == "reference":
                            args_values.append(f"${key}")
                            event_data[key] = arg.get("value")
                        else:
                            args_values.append(self._format_call_arg(arg.get("value")))
                    else:
                        if arg_source == "reference":
                            args_values.append(f"${key}")
                            event_data[key] = arg
                        elif arg_source == "both":
                            if idx % 2 == 1:
                                args_values.append(self._format_call_arg(arg))
                            else:
                                args_values.append(f"${key}")
                                event_data[key] = arg
                        else:
                            args_values.append(self._format_call_arg(arg))

            if getattr(example, "target_field", None):
                target_field_name = getattr(doc.target_field, "path", None) or "target_field"
                event_data[target_field_name] = example.target_field

            call_str = f"{doc.name}({', '.join(args_values)})" if args_values else f"{doc.name}()"
            call_str = self._yaml_scalar(call_str)
            target_field_name = getattr(doc.target_field, "path", None) or "target_field"

            self.content.append(f"{description}\n")
            self.content.append(f"#### Asset\n")

            if helper_type == "filter":
                self.content.append("```yaml\ncheck:\n  - " + target_field_name + ": " + call_str + "\n```\n")
            else:
                self.content.append("```yaml\nnormalize:\n  - map:\n      - " + target_field_name + ": " + call_str + "\n```\n")

            self.content.append("#### Input Event\n")
            self.content.append("```json\n" + json.dumps(event_data, indent=2) + "\n```\n")

            if helper_type == "filter":
                result_msg = "The check was successful" if example.should_pass else "The check was performed with errors"
                self.content.append(f"*{result_msg}*\n")
            else:
                # An `expected` of "" is the test runner's "not asserted" marker (it checks only a
                # truthy expected), not a value the helper writes: a failing example keeps the
                # input event, and a passing one has no asserted outcome to show.
                unasserted = isinstance(example.expected, str) and example.expected == ""
                final_event = dict(event_data)
                if example.expected is not None and not unasserted:
                    if example.should_pass or doc.helper_type == "transformation":
                        final_event[target_field_name] = example.expected

                if all(v is None for v in final_event.values()):
                    final_event = {}

                if not (unasserted and example.should_pass):
                    self.content.append("#### Outcome Event\n")
                    self.content.append("```json\n" + json.dumps(final_event, indent=2) + "\n```\n")

                result_msg = "The operation was successful" if example.should_pass else "The operation was performed with errors"
                self.content.append(f"*{result_msg}*\n")

        self.content.append("\n")

    def uses_test_kvdb(self, doc: Documentation) -> bool:
        """
        Return whether the helper documentation should include the helper test KVDB resource.
        """
        return doc.name.startswith("kvdb_") or "kvdb" in doc.keywords

    def create_test_kvdb_section(self):
        """
        Add the KVDB resource used by KVDB helper examples.
        """
        self.content.append("## Test KVDB\n")
        self.content.append("The examples for this helper use the following KVDB resource during tests:\n")
        self.content.append("```json\n" + json.dumps(get_helper_test_kvdb_resource(), indent=2) + "\n```\n")

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
            headers = ["Path", "Type", "Possible values"] if getattr(doc.target_field, "path", None) else ["Type", "Possible values"]
            self.create_output_table(doc.target_field, headers)

        if doc.output:
            self.content.append(f"## Outputs\n")
            headers = ["Type", "Possible values"]
            self.create_output_table(doc.output, headers)

        self.content.append(f"## Description\n")
        self.content.append(f"{doc.description}\n")
        self.content.append(f"## Keywords\n")
        for keyword in doc.keywords:
            self.content.append(f"- `{keyword}` \n")

        if doc.general_restrictions:
            self.content.append(f"## Notes\n")
            for general_restriction in doc.general_restrictions:
                self.content.append(f"- {general_restriction}\n")

        if doc.examples:
            self.create_tests_table(doc)

        if self.uses_test_kvdb(doc):
            self.create_test_kvdb_section()

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
        documentation_file = output_dir / "ref-helper-functions.md"

        with open(documentation_file, 'w') as file:
            file.write("# Summary\n\n")
            file.write(
                "This documentation provides an overview of the auxiliary functions available. "
                "Auxiliary functions are modular components designed to perform specific operations on "
                "decoders or rules. Depending on their purpose, they are categorized "
                "into transformation, filter, or mapping functions.\n\n"
            )
            file.write("## Index\n\n")

            for helper_type, helpers in sorted(self.all_contents.items()):
                file.write(f"### {helper_type.capitalize()}\n\n")
                for helper_name in sorted(helpers.keys()):
                    file.write(f"- [{helper_name}](#{helper_name.lower()})\n")
                file.write("\n")

            for helper_type, helpers in sorted(self.all_contents.items()):
                for helper_name, helper_info in sorted(helpers.items()):
                    file.write(helper_info["content"])
                    file.write("\n---\n")

        # TODO: temporary disability
        # keyword_file = output_dir / "keyword_table.md"
        # with open(keyword_file, 'w') as file:
        #     file.write("# By Keyword\n")
        #     file.write("| Helper | Keywords |\n")
        #     file.write("| ------ | -------- |\n")

        #     for helper_type, helpers in sorted(self.all_contents.items()):
        #         for helper_name, helper_info in sorted(helpers.items()):
        #             keywords = ', '.join(sorted(set(helper_info["keywords"])))
        #             file.write(
        #                 f"| [{helper_name}](ref-helper-functions.md#{helper_name.lower()}) | {keywords} |\n")
