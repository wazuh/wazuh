#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check that the helpers registered in register.hpp and the helper descriptions are the same set.

Every ``registry->template add<builders::OpBuilderEntry>("<name>", ...)`` entry of the registry must have a
description ``<kind>/<name>.yml`` and vice versa. The implicit ``filter`` and ``map`` entries have no description.
"""
import argparse
import pathlib
import re
import sys

ENTRY = re.compile(r'add<builders::OpBuilderEntry>\(\s*"([a-z0-9_]+)"')
IMPLICIT = {"filter", "map"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--registry", required=True, type=pathlib.Path, help="path of register.hpp")
    parser.add_argument("--descriptions", required=True, type=pathlib.Path,
                        help="directory holding the <kind>/<name>.yml descriptions")
    args = parser.parse_args()

    registered = set(ENTRY.findall(args.registry.read_text())) - IMPLICIT
    described = {path.stem for path in args.descriptions.glob("*/*.yml")}

    missing_description = sorted(registered - described)
    missing_registration = sorted(described - registered)
    for name in missing_description:
        print(f"registered helper without description: {name}")
    for name in missing_registration:
        print(f"description without registered helper: {name}")
    if missing_description or missing_registration:
        return 1
    print(f"{len(registered)} helpers registered and described")
    return 0


if __name__ == "__main__":
    sys.exit(main())
