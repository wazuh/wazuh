# SPDX-License-Identifier: AGPL-3.0-or-later
from helper_test.documentation_generator.types import Documentation, Example
from helper_test.documentation_generator.exporter import *
from helper_test.runner import get_helper_test_kvdb_resource
from helper_test.test_cases_generator.parser import HELPER_GROUPS
from collections import defaultdict
from pathlib import Path
from typing import List
import json
import re
import yaml

# Opening paragraph of the generated reference.
REFERENCE_INTRO = (
    "This reference lists every helper function available to decoders, filters and outputs. "
    "Check helpers are used in `check` stages and `first_of` branches; map helpers are used in "
    "`map` stages (some modify the target field in place)."
)

# Index headings that are not the capitalized group name.
GROUP_TITLES = {"kvdb": "KVDB"}


class MarkdownGenerator(IExporter):
    def __init__(self):
        self.content = []
        # Documents organized by group, then by helper name
        self.all_contents = defaultdict(dict)
        self.helper_name = ""

    @staticmethod
    def _target_field_name(doc: Documentation) -> str:
        """
        Name of the target field shown in the signature and the examples: the fixed path the
        helper requires when it declares one, a generic `target_field` otherwise.
        """
        return getattr(doc.target_field, "path", None) or "target_field"

    @staticmethod
    def _kind(doc: Documentation) -> str:
        """
        User-facing kind of the helper: a transform is a map helper that modifies its target in place.
        """
        return "check" if doc.helper_type == "check" else "map"

    def create_kind(self, doc: Documentation):
        if doc.helper_type == "check":
            self.content.append("**Kind:** check helper (used in `check`)\n")
        else:
            self.content.append("**Kind:** map helper (used in `map`)\n")
            if doc.helper_type == "transform":
                self.content.append("**Modifies the target in place:** yes\n")

    def create_signature(self, doc: Documentation):
        # An optional argument is shown in brackets, like the variadic tail.
        names = [f"[{name}]" if getattr(arg, "optional", False) else str(name)
                 for name, arg in doc.arguments.items()]
        if doc.is_variadic:
            names.append("[...]")
        target_field_name = self._target_field_name(doc)
        if doc.helper_type == "check":
            # A check helper receives the field it evaluates as its first argument.
            signature = f"check: {doc.name}({', '.join([f'${target_field_name}'] + names)})"
        else:
            signature = f"{target_field_name}: {doc.name}({', '.join(names)})"
        self.content.append("```\n" + signature + "\n```\n")

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

            target_field_name = self._target_field_name(doc)
            if getattr(example, "target_field", None) is not None:
                event_data[target_field_name] = example.target_field

            call_str = f"{doc.name}({', '.join(args_values)})" if args_values else f"{doc.name}()"
            call_str = self._yaml_scalar(call_str)

            self.content.append(f"{description}\n")
            self.content.append(f"#### Asset\n")

            if helper_type == "check":
                self.content.append("```yaml\ncheck:\n  - " + target_field_name + ": " + call_str + "\n```\n")
            else:
                self.content.append("```yaml\nnormalize:\n  - map:\n      - " + target_field_name + ": " + call_str + "\n```\n")

            self.content.append("#### Input Event\n")
            self.content.append("```json\n" + json.dumps(event_data, indent=2) + "\n```\n")

            if helper_type == "check":
                result_msg = "The check was successful" if example.should_pass else "The check was performed with errors"
                self.content.append(f"*{result_msg}*\n")
            else:
                # An `expected` of "" is the test runner's "not asserted" marker (it checks only a
                # truthy expected), not a value the helper writes: a failing example keeps the
                # input event, and a passing one has no asserted outcome to show.
                unasserted = isinstance(example.expected, str) and example.expected == ""
                final_event = dict(event_data)
                if example.expected is not None and not unasserted:
                    if example.should_pass or doc.helper_type == "transform":
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
        return doc.group == "kvdb"

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
        for a helper function, including its kind, signature, arguments, target field or
        output, description, failure conditions, general notes and examples. The content
        generated is stored in the `all_contents` dictionary, categorized by group and name.

        :param doc: An instance of the Documentation class, containing all necessary
                    information about the helper function to document.
        """
        self.content = []
        self.helper_name = doc.name
        self.content.append(f"# {doc.name}\n")

        self.create_kind(doc)

        self.content.append(f"## Signature\n")
        self.create_signature(doc)

        if len(doc.arguments) > 0:
            self.content.append(f"## Arguments\n")
            headers = ["parameter", "Type", "Source", "Accepted values"]
            self.create_table(doc.arguments, headers)

        if doc.target_field:
            self.content.append(f"## Target field\n")
            headers = ["Path", "Type", "Possible values"] if getattr(doc.target_field, "path", None) else ["Type", "Possible values"]
            self.create_output_table(doc.target_field, headers)

        if doc.output:
            self.content.append(f"## Output\n")
            headers = ["Type", "Possible values"]
            self.create_output_table(doc.output, headers)

        self.content.append(f"## Description\n")
        self.content.append(f"{doc.description}\n")

        if doc.fails_when:
            self.content.append(f"## Fails when\n")
            self.content.append('\n'.join(f"- {condition}" for condition in doc.fails_when) + "\n")

        if doc.general_restrictions:
            self.content.append(f"## Notes\n")
            for general_restriction in doc.general_restrictions:
                self.content.append(f"- {general_restriction}\n")

        if doc.examples:
            self.create_tests_table(doc)

        if self.uses_test_kvdb(doc):
            self.create_test_kvdb_section()

        self.all_contents[doc.group][doc.name] = {
            "kind": self._kind(doc),
            "content": '\n'.join(self.content)
        }

    def _ordered_groups(self) -> list:
        """
        Groups with at least one document, in the reference order; a group the validator does
        not know (it cannot pass validation, so this is only defensive) goes last, alphabetically.
        """
        known = [group for group in HELPER_GROUPS if group in self.all_contents]
        unknown = sorted(group for group in self.all_contents if group not in HELPER_GROUPS)
        return known + unknown

    @staticmethod
    def _group_title(group: str) -> str:
        return GROUP_TITLES.get(group, str(group).capitalize())

    def save(self, output_dir: Path):
        """
        Saves all generated documentation to a single Markdown file.

        This method writes the summary, the index (helpers grouped by `metadata.group`) and
        the detailed documentation of all helper functions, in the same order, to
        `ref-helper-functions.md` in the output directory.

        :param output_dir: A Path object representing the directory where the
                        documentation file should be saved.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        documentation_file = output_dir / "ref-helper-functions.md"

        with open(documentation_file, 'w') as file:
            file.write("# Summary\n\n")
            file.write(REFERENCE_INTRO + "\n\n")
            file.write("## Index\n\n")

            for group in self._ordered_groups():
                file.write(f"### {self._group_title(group)}\n\n")
                for helper_name, helper_info in sorted(self.all_contents[group].items()):
                    file.write(
                        f"- [{helper_name}](#{helper_name.lower()}) — {helper_info['kind']}\n")
                file.write("\n")

            for group in self._ordered_groups():
                for helper_name, helper_info in sorted(self.all_contents[group].items()):
                    file.write(helper_info["content"])
                    file.write("\n---\n")
