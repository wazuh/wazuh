import json
from typing import Any

class EngineMock:

    configs = dict()
    path = '/var/ossec/engine_conf'

    def get_config(self, name: str = None) -> dict[str, Any]:
        resp = {'status': 1, 'error': None}
        if name is not None:
            resp['content'] = self.configs[name]
        else:
            resp['content'] = json.dumps(self.configs)

        return resp

    def update_config(self, name: str, content: str, save: bool = None) -> object:
        self.configs[name] = content

        if save:
            try:
                with open(self.path, 'w', encoding='utf-8') as f:
                    f.write(json.dumps(self.configs))
            except Exception as e:
                raise e
        
        return {'status': 1, 'error': None}


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
    return ENGINE.get_config(name)

def update_runtime_config(name: str, content: str, save: bool = False) -> dict[str, Any]:
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
    return ENGINE.update_config(name, content, save)
