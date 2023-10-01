import json
from importlib.metadata import files

class CrudIntegration:
    def __init__(self):
        pass

    def get_integration_file(self):
        _files = files('engine-suite')
        _file = [file for file in _files if 'integrations.json' in str(file)][0]

        return _file

    def get_integrations(self):
        _file = self.get_integration_file()
        content = _file.read_text()

        try:
            content_json = json.loads(content)
        except ValueError:
            print('Error while reading JSON file')

        return content_json

    def get_integration(self, integration_name: str):
        integrations = self.get_integrations()
        if integration_name in integrations:
            return integrations[integration_name]
        else:
            return None

    def save_integration(self, integration_name: str, format: str, origin: str):
        _file = self.get_integration_file()
        with open('./integrations.json') as fp:
            listJson = json.load(fp)

        if not format and not integration_name:
            print('To save the integration, the integration-name and format parameters cannot be empty.')
            return

        if origin and format:
            content = {
                f'{integration_name}':
                {
                    "format": format,
                    "origin": origin
                }
            }
        else:
            content = {
                f'{integration_name}':
                {
                    "format": format
                }
            }
        listJson.append(content)
        with open('./integrations.json', 'w') as json_file:
            json.dump(listJson, json_file, indent=4, separators=(',',': '))
