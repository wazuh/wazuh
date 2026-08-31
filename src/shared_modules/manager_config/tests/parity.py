#!/usr/bin/env python3
"""Parity check: jsonschema.Draft4Validator vs the manager_config vectors.

Usage: parity.py <schema.json> <vectors dir>
Exit 0 when every vector under valid/ validates, every vector under invalid/ fails with the expected
JSON pointer and keyword (expected/<name>.json), and YAML-level rejections (keyword "yaml") are
rejected by the loader. Semantics rules (keyword "semantics") are library-only and are skipped here.

The loader follows the YAML 1.2 core schema: only true/false are booleans (PyYAML alone would turn
`yes`/`no`/`on`/`off` into booleans, which is exactly what the schema must reject). This loader is the
reference for the Python framework (plan E4a).
"""
import json
import re
import sys
from pathlib import Path

import jsonschema
import yaml


class Yaml12Loader(yaml.SafeLoader):
    """SafeLoader with the YAML 1.1 bool/null resolvers replaced by the YAML 1.2 core ones."""


# Drop every implicit resolver for bool and rebuild it with true/false only.
Yaml12Loader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
Yaml12Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


class StrictComposer:
    """Reject anchors/aliases and explicit tags: they have no place in the manager file."""

    @staticmethod
    def check(text):
        for event in yaml.parse(text, Loader=Yaml12Loader):
            if isinstance(event, yaml.AliasEvent):
                raise ValueError("aliases are not allowed")
            anchor = getattr(event, "anchor", None)
            if anchor is not None:
                raise ValueError("anchors are not allowed")
            tag = getattr(event, "tag", None)
            if tag is not None and tag.startswith("tag:yaml.org,2002:"):
                raise ValueError("explicit tags are not allowed")


def load(text):
    documents = list(yaml.load_all(text, Loader=Yaml12Loader))
    if len(documents) > 1:
        raise ValueError("exactly one YAML document is required")
    StrictComposer.check(text)
    if not documents or documents[0] is None:
        return {}  # empty file / only comments: every option takes its default
    return documents[0]


def first_error(validator, document):
    errors = sorted(validator.iter_errors(document), key=lambda e: (len(e.absolute_path), str(e.absolute_path)))
    if not errors:
        return None
    error = errors[0]
    pointer = "".join(f"/{part}" for part in error.absolute_path)
    # Pointer convention of the library (rapidjson): point at the offending element, not at its container.
    if error.validator == "additionalProperties" and isinstance(error.instance, dict):
        known = set(error.schema.get("properties", {}))
        extra = sorted(k for k in error.instance if k not in known)
        if extra:
            pointer += f"/{extra[0]}"
    elif error.validator == "uniqueItems" and isinstance(error.instance, list):
        seen = []
        for index, item in enumerate(error.instance):
            if item in seen:
                pointer += f"/{index}"
                break
            seen.append(item)
    return pointer, error.validator


def main():
    schema_path, vectors = Path(sys.argv[1]), Path(sys.argv[2])
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft4Validator.check_schema(schema)
    validator = jsonschema.Draft4Validator(schema)
    failures = []
    for path in sorted((vectors / "valid").glob("*.yml")):
        try:
            err = first_error(validator, load(path.read_text()))
        except Exception as exc:  # noqa: BLE001
            err = ("", f"yaml: {exc}")
        if err:
            failures.append(f"{path.name}: expected valid, got {err}")
    for path in sorted((vectors / "invalid").glob("*.yml")):
        expected = json.loads((vectors / "expected" / f"{path.stem}.json").read_text())
        if expected["keyword"] == "semantics":
            continue
        try:
            document = load(path.read_text())
        except Exception:  # noqa: BLE001
            if expected["keyword"] != "yaml":
                failures.append(f"{path.name}: rejected by the YAML loader, expected {expected}")
            continue
        if expected["keyword"] == "yaml":
            failures.append(f"{path.name}: expected a YAML-level rejection, the loader accepted it")
            continue
        err = first_error(validator, document)
        if err is None:
            failures.append(f"{path.name}: expected {expected}, got valid")
        elif err != (expected["pointer"], expected["keyword"]):
            failures.append(f"{path.name}: expected {expected}, got {{'pointer': '{err[0]}', 'keyword': '{err[1]}'}}")
    for failure in failures:
        print("PARITY FAIL", failure)
    print(f"parity: {len(failures)} discrepancias")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
