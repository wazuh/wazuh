import json
from os.path import exists
from pathlib import Path
from engine_test.event_format import Formats
from engine_test.config import Config

from importlib.metadata import files


class CrudIntegration:
    def __init__(self):
        self.formats = Formats.get_formats()

    def get_integrations(self):
        json_content = ""
        try:
            with open(Config.get_config_file()) as fp:
                    json_content = json.load(fp)
        except json.JSONDecodeError as ex:
            print('Error while reading config as JSON file: {}'.format(ex))
            exit(1)
        except Exception as ex:
            print('Error while reading config file: {}'.format(ex))
            exit(1)

        return json_content

    def get_integration(self, integration_name: str):
        integrations = self.get_integrations()
        if integration_name in integrations:
            return integrations[integration_name]
        else:
            return None

    def save_integration(self, integration_name: str, format: str, origin: str, lines: str = None):
        if not format and not integration_name:
            print('To save the integration, the integration-name and format parameters cannot be empty.')
            return False

        if exists(Config.get_config_file()) and self.get_integration(integration_name) != None:
            print('The integration already exists.')
            return False

        if format not in self.formats:
            print('The format is invalid.')
            return False

        try:
            with open(Config.get_config_file()) as fp:
                json_content = json.load(fp)
        except FileNotFoundError:
            print('Configuration file not found. Creating a new one.')
            json_content = {}
        except Exception as ex:
            print('Error while reading configuration file: {}'.format(ex))
            return False

        if origin and format:
            content = {
                "format": format,
                "origin": origin
            }
        else:
            content = {"format": format}

        if (Formats.MULTI_LINE.value['name'] == format):
            if (lines != None):
                content['lines'] = lines
            else:
                print("Parameter 'lines' is mandatory for multi-line format.")
                return False
        try:
            json_content[integration_name] = content
        except KeyError as ex:
            print('Error saving integration. Error: {}'.format(ex))
            return False

        try:
            with open(Config.get_config_file(), 'w') as json_file:
                json.dump(json_content, json_file, indent=4, separators=(',', ': '))
                json_file.write('\n')
        except Exception as ex:
            print('Error while writing configuration file: {}'.format(ex))
            return False

        print(f"Integration '{integration_name}' added successfully.")
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
            print('Integration not found.')
            return False

        try:
            with open(Config.get_config_file(), 'w') as json_file:
                json.dump(json_content, json_file, indent=4, separators=(',', ': '))

            print('Integration removed successfully.')
        except Exception as ex:
            print('Error while writing configuration file: {}'.format(ex))
            return False

        return True

    def import_integration(self, integration_config: str):

        #TODO FIX This
        try:
            with open(integration_config) as fp:
                json_content = json.load(fp)
        except Exception as ex:
            print('Error while reading configuration file: {}'.format(ex))
            exit(1)

        for item in json_content:
            try:
                integration_name = item
                format = json_content[item]['format']
                origin = json_content[item]['origin'] if 'origin' in json_content[item] else None
                lines = None

                message = f"Adding integration '{item}' with format '{format}'"

                if (Formats.MULTI_LINE.value['name'] == format):
                    lines = json_content[item]['lines']

                print(message)
                self.save_integration(integration_name, format, origin, lines)
            except Exception as ex:
                print(f'Error importing file: {ex}')
