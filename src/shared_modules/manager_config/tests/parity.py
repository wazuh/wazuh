#!/usr/bin/env python3
"""Parity check: jsonschema.Draft4Validator vs the manager_config vectors.

Usage: parity.py <schema.json> <vectors dir>
Exit 0 when every vector under valid/ validates, every vector under invalid/ fails with the expected
JSON pointer and keyword (expected/<name>.json), and XML-level rejections (keyword "xml") are rejected
by the loader. Semantics rules (keyword "semantics") are library-only and are skipped here.

The loader mirrors the library's schema-driven typing over strict XML (expat rejects raw '&', '--'
inside comments and a second root on its own): yes/no become booleans, digit-only text becomes an
integer where the schema allows one, repeated or comma-separated values become arrays, the attribute
forms of the dialect (<backup database="...">, <disconnected_time enabled="...">) become nested
objects, and lowercase enums are normalized. It is the reference for the Python framework (stage E4)
and the seed of the 5.0->5.1 conversion tool.
"""
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import jsonschema

INT_RE = re.compile(r"^[-+]?(0|[1-9][0-9]*)$")
LIST_ITEM = {"hosts": "host", "certificate_authorities": "ca", "nodes": "node"}
VALUE_AS_KEY = {"backup": "database"}


def deref(schema, root):
    for _ in range(8):
        if not isinstance(schema, dict) or "$ref" not in schema:
            return schema
        node = root
        for part in schema["$ref"].lstrip("#/").split("/"):
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                return None
        schema = node
    return schema


def allowed_at(schema, root, out=None, depth=0):
    """Merge type/enum/items/properties across $ref and allOf/anyOf/oneOf, like the library does."""
    if out is None:
        out = {"types": set(), "enum": None, "items": None, "properties": None}
    schema = deref(schema, root)
    if not isinstance(schema, dict) or depth > 8:
        return out
    kind = schema.get("type")
    for name in kind if isinstance(kind, list) else ([kind] if kind else []):
        out["types"].add(name)
    if "enum" in schema:
        out["enum"] = schema["enum"]
    if "items" in schema:
        out["items"] = schema["items"]
    if "properties" in schema:
        out["properties"] = schema["properties"]
        out["types"].add("object")
    for combinator in ("allOf", "anyOf", "oneOf"):
        for branch in schema.get(combinator, []):
            allowed_at(branch, root, out, depth + 1)
    return out


def prop_schema(allowed, key):
    properties = allowed.get("properties") or {}
    return properties.get(key)


def typed_scalar(text, allowed, root):
    if "boolean" in allowed["types"] and text.lower() in ("yes", "no"):
        return text.lower() == "yes"
    if ("integer" in allowed["types"] or "number" in allowed["types"]) and INT_RE.match(text):
        return int(text)
    if allowed["enum"]:
        matches = [value for value in allowed["enum"] if isinstance(value, str) and value.lower() == text.lower()]
        if text not in allowed["enum"] and len(matches) == 1:
            return matches[0]
    return text


def leaf_text(element):
    return element.text or ""


def has_text(element):
    if element.text and element.text.strip():
        return True
    return any(child.tail and child.tail.strip() for child in element)


def element_to_value(element, schema, root):
    allowed = allowed_at(schema, root)
    if element.attrib:
        key_attribute = VALUE_AS_KEY.get(element.tag)
        if key_attribute and key_attribute in element.attrib and len(element.attrib) == 1:
            key = element.attrib[key_attribute]
            inner_allowed = allowed_at(prop_schema(allowed, key), root)
            if len(element):
                return {key: children_to_object(element, inner_allowed, root)}
            return {key: typed_scalar(leaf_text(element), inner_allowed, root)}
        value = {
            name: typed_scalar(text, allowed_at(prop_schema(allowed, name), root), root)
            for name, text in element.attrib.items()
        }
        if len(element):
            value.update(children_to_object(element, allowed, root))
        elif leaf_text(element).strip():
            value["value"] = typed_scalar(leaf_text(element), allowed_at(prop_schema(allowed, "value"), root), root)
        return value
    if len(element):
        if "array" in allowed["types"]:
            expected = LIST_ITEM.get(element.tag)
            items = allowed_at(allowed["items"], root)
            values = []
            for child in element:
                if expected and child.tag != expected:
                    raise ValueError(f"unexpected <{child.tag}> inside <{element.tag}>")
                if len(child):
                    raise ValueError("list items must be plain values")
                values.append(typed_scalar(leaf_text(child), items, root))
            return values
        return children_to_object(element, allowed, root)
    text = leaf_text(element)
    if "array" in allowed["types"]:
        items = allowed_at(allowed["items"], root)
        return [typed_scalar(token.strip(), items, root) for token in text.split(",")] if text.strip() else []
    if "object" in allowed["types"] and not text.strip():
        return {}
    return typed_scalar(text, allowed, root)


def children_to_object(element, allowed, root):
    if has_text(element):
        raise ValueError(f"unexpected text content inside <{element.tag}>")
    out = {}
    for child in element:
        child_schema = prop_schema(allowed, child.tag)
        if child.tag in out:
            existing = out[child.tag]
            child_allowed = allowed_at(child_schema, root)
            if isinstance(existing, list) and not len(child) and not child.attrib:
                existing.append(typed_scalar(leaf_text(child), allowed_at(child_allowed["items"], root), root))
                continue
            raise ValueError(f"duplicate element <{child.tag}>")
        out[child.tag] = element_to_value(child, child_schema, root)
    return out


def load(text, schema):
    root_element = ET.fromstring(text)  # expat: strict XML (raw '&', '--' in comments, second root...)
    if root_element.tag != "wazuh_config":
        raise ValueError(f"the root element must be <wazuh_config>, found <{root_element.tag}>")
    if root_element.attrib:
        raise ValueError("the <wazuh_config> root element takes no attributes")
    return children_to_object(root_element, allowed_at(schema, schema), schema)


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
    for path in sorted((vectors / "valid").glob("*.conf")):
        try:
            err = first_error(validator, load(path.read_text(), schema))
        except Exception as exc:  # noqa: BLE001
            err = ("", f"xml: {exc}")
        if err:
            failures.append(f"{path.name}: expected valid, got {err}")
    for path in sorted((vectors / "invalid").glob("*.conf")):
        expected = json.loads((vectors / "expected" / f"{path.stem}.json").read_text())
        if expected["keyword"] == "semantics":
            continue
        try:
            document = load(path.read_text(), schema)
        except Exception:  # noqa: BLE001
            if expected["keyword"] != "xml":
                failures.append(f"{path.name}: rejected by the XML loader, expected {expected}")
            continue
        if expected["keyword"] == "xml":
            failures.append(f"{path.name}: expected an XML-level rejection, the loader accepted it")
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
