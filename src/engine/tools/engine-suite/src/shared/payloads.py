import datetime
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

    def _default(value):
        if isinstance(value, (datetime.date, datetime.datetime)):
            return value.isoformat()

        raise TypeError(f"YAML value of type {type(value).__name__!r} is not JSON serializable")

    return json.dumps(data, separators=(",", ":"), default=_default)
