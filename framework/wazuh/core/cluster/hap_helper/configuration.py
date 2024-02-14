import json
from os import path

import jsonschema
import yaml
from wazuh.core.cluster.hap_helper.exception import HAPHelperError


def validate_custom_configuration(custom_configuration: dict):
    with open(
        path.join(path.abspath((path.dirname(__file__))), 'data', 'configuration_schema.json'), 'r'
    ) as schema_file:
        json_schema = json.loads(schema_file.read())

    try:
        jsonschema.validate(instance=custom_configuration, schema=json_schema)
    except jsonschema.ValidationError as validation_err:
        raise HAPHelperError(101, extra_msg=f"({'> '.join(validation_err.path)}) {validation_err.message}")


def merge_configurations(default: dict, config: dict) -> dict:
    for key, value in config.items():
        if isinstance(value, dict):
            default[key] = merge_configurations(default.get(key, {}), value)
        else:
            default[key] = value
    return default


def parse_configuration(custom_configuration_path: str = '') -> dict:
    with open(
        path.join(path.abspath((path.dirname(__file__))), 'data', 'configuration.yaml'), 'r'
    ) as default_conf_file:
        default_configuration = yaml.safe_load(default_conf_file)

    if not custom_configuration_path:
        return default_configuration

    with open(custom_configuration_path, 'r') as custom_conf_file:
        custom_configuration = yaml.safe_load(custom_conf_file)

    validate_custom_configuration(custom_configuration)
    return merge_configurations(default_configuration, custom_configuration)
