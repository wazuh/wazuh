import json

import yaml


def load_json_content(raw: str) -> str:
    try:
        json.loads(raw)
        return raw
    except json.JSONDecodeError:
        pass

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ValueError(f"Payload is not valid JSON or YAML: {e}")

    if not isinstance(data, dict):
        raise ValueError("Payload must be a JSON object (top-level must be an object).")

    return json.dumps(data, separators=(",", ":"))
