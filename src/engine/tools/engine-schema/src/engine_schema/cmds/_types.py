from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Set, Union


def _collect_types(mapping: Dict[str, Any], types: Set[str]) -> None:
    """Recursively collect field types from the mappings definition."""
    for definition in mapping.values():
        if not isinstance(definition, dict):
            continue
        field_type = definition.get('type')
        if isinstance(field_type, str):
            types.add(field_type)
        props = definition.get('properties')
        if isinstance(props, dict):
            _collect_types(props, types)
        items = definition.get('items')
        if isinstance(items, dict):
            item_props = items.get('properties')
            if isinstance(item_props, dict):
                _collect_types(item_props, types)


def update_types_file(mappings_wrapper: Dict[str, Any], output_path: Union[Path, str]) -> None:
    """Persist the list of field types extracted from the generated mappings."""

    output_path = Path(output_path)
    mappings = mappings_wrapper.get('template', {}).get('mappings', {}).get('properties')
    if not isinstance(mappings, dict):
        print('Warning: cannot update ecs_types.json (missing template.mappings.properties)')
        return

    types: Set[str] = set()
    _collect_types(mappings, types)
    sorted_types = sorted(types)

    output_path = output_path.expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open('w', encoding='utf-8') as fp:
        json.dump(sorted_types, fp, indent=2)
        fp.write('\n')

    print(f'Updated "{output_path}" with {len(sorted_types)} field types.')
