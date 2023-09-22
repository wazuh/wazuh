import json
from os import path
from importlib.metadata import files
from engine_test.events_collector import EventsCollector
from engine_test.formats.syslog import SyslogFormat
from engine_test.formats.json import JsonFormat
from engine_test.formats.eventchannel import EventChannelFormat
from engine_test.formats.macos import MacosFormat
from engine_test.formats.remote_syslog import RemoteSyslogFormat
from engine_test.formats.audit import AuditFormat
from engine_test.formats.command import CommandFormat
from engine_test.formats.full_command import FullCommandFormat
from engine_test.formats.multi_line import MultilineFormat
from engine_test.event_format import Formats

from engine_test.api_connector import ApiConnector

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
