import json
from engine_test.event_format import Formats
from engine_test.config import Config

from importlib.metadata import files

class CrudIntegration:
    def __init__(self):
        self.formats = []
        self.formats.append(Formats.AUDIT.value['name'])
        self.formats.append(Formats.COMMAND.value['name'])
        self.formats.append(Formats.FULL_COMMAND.value['name'])
        self.formats.append(Formats.EVENTCHANNEL.value['name'])
        self.formats.append(Formats.JSON.value['name'])
        self.formats.append(Formats.MACOS.value['name'])
        self.formats.append(Formats.MULTI_LINE.value['name'])
        self.formats.append(Formats.SYSLOG.value['name'])
        self.formats.append(Formats.REMOTE_SYSLOG.value['name'])

    def get_integrations(self):
        json_content = ""
        with open(Config.get_config_file()) as fp:
            try:
                json_content = json.load(fp)
            except Exception as ex:
                print('Error while reading JSON file: {}'.format(ex))
                exit(1)

        return json_content

    def get_integration(self, integration_name: str):
        integrations = self.get_integrations()
        if integration_name in integrations:
            return integrations[integration_name]
        else:
            return None

    def save_integration(self, integration_name: str, format: str, origin: str):
        if not format and not integration_name:
            print('To save the integration, the integration-name and format parameters cannot be empty.')
            return False

        if self.get_integration(integration_name) != None:
            print('The integration already exists!')
            return False

        if format not in self.formats:
            print('The format is invalid!')
            return False

        try:
            with open(Config.get_config_file()) as fp:
                json_content = json.load(fp)
        except Exception as ex:
            print('Error while reading configuration file: {}'.format(ex))
            return False

        # TODO: implement "lines" parameter for multi-line format

        if origin and format:
            content = {
                "format": format,
                "origin": origin
                }
        else:
            content = { "format": format }

        try:
            json_content[integration_name] = content
        except KeyError as ex:
            print('Error saving integration. Error: {}'.format(ex))
            return False

        try:
            with open(Config.get_config_file(), 'w') as json_file:
                json.dump(json_content, json_file, indent=4, separators=(',',': '))
        except Exception as ex:
            print('Error while writing configuration file: {}'.format(ex))
            return False

        print('Integration added successfully.')
        return True

    def delete_integration(self, integration_name: str):
        try:
            with open(Config.get_config_file()) as fp:
                json_content = json.load(fp)
        except Exception as ex:
            print('Error while reading configuration file: {}'.format(ex))
            return False

        if not integration_name:
            print('To delete the integration, the integration-name parameter cannot be empty.')
            return False

        try:
            del json_content[integration_name]
        except KeyError:
            print('Integration not found!')
            return False

        try:
            with open(Config.get_config_file(), 'w') as json_file:
                json.dump(json_content, json_file, indent=4, separators=(',',': '))

            print('Integration removed successfully.')
        except Exception as ex:
            print('Error while writing configuration file: {}'.format(ex))
            return False

        return True
