import json
from typing import Any
import re

class EngineMock:

    configs = dict()
    path = '/var/ossec/engine_conf'

    def get_config(self, name: str = None) -> dict[str, Any]:
        if name is not None:
            return self.configs[name]
        else:
            data = json.dumps(self.configs)
            return json.loads(data)

    def update_config(self, name: str, content: str, save: bool = None):
        self.configs[name] = content

        if save:
            with open(self.path, 'w+', encoding='utf-8') as f:
                f.write(json.dumps(self.configs))

ENGINE = EngineMock()


def get_runtime_config(name: str = None) -> dict[str, Any]:
    """Get the runtime configuration of the manager.

    Parameters
    ----------
    name : str
        Name of the configuration option.

    Returns
    -------
    dict[str, Any]
        A dictionary with the status, error and content. If no name is provided, the whole configuration is returned.
    """
    # TODO: use socket to send the command instead of the mock
    resp = {'status': 'OK', 'error': None}
    try:
        resp['content'] = ENGINE.get_config(name)
    except Exception as exc:
        resp = {'status': 'ERROR', 'error': f'The specified configuration does not exist: {exc}'}

    return resp

def update_runtime_config(name: str, content: str, save: bool = False):
    """Update the runtime configuration of the manager.

    Parameters
    ----------
    name : str
        Name of the configuration option.
    content : str
        Value of the configuration option.
    save : bool
        Save the configuration to disk.

    Returns
    -------
    dict[str, Any]
        Engine response.
    """
    # TODO: use socket to send the command instead of the mock
    ENGINE.update_config(name, content, save)

def parse_content(content: str) -> str:
    """Parse the Engine runtime configuration to JSON

    Parameters
    ----------
    content : str
        Engine runtime configuration content.
        
    Returns
    -------
    str
        JSON-encoded object.
    """
    # Parse the data string and create a dictionary
    pattern = r'([\w.]+)=("[^"]*"|\d+)'
    content_dict = dict(re.findall(pattern, content.strip()))
    result = {}

    for keys, value in content_dict.items():
        # Remove double quotes and convert strings to numbers
        value = value.replace('"', '')
        if value.isdigit():
            value = int(value)
        dotted_str_to_dict(result, keys, value)

    return json.dumps(result)

def dotted_str_to_dict(result: dict, keys: str, value: Any):
    """Coverts dot delimited string to a dictionary

    Parameters
    ----------
    result : dict
        Final dictionary containing keys and value.
    keys : str
        Dot delimited key.
    value : Any
        Value of the key.
    """
    if "." in keys:
        key, rest = keys.split(".", 1)
        if key not in result:
            result[key] = {}
        dotted_str_to_dict(result[key], rest, value)
    else:
        result[keys] = value