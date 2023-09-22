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
from engine_test.crud_integration import CrudIntegration

from engine_test.api_connector import ApiConnector

class Integration(CrudIntegration):
    def __init__(self, args):
        self.args = args
        self.api_client = ApiConnector()

    def run(self):
        integration_name = self.args['integration-name']
        integration = self.get_integration(integration_name)
        print (integration)
        if not integration:
            print("Integration not found!")
            exit(1)

        # Get the format of integration
        format = self.get_format(integration)
        if not format:
            print("Format of integration not found!")
            exit(2)

        while (True):
            # Collect the events
            events = EventsCollector.collect()

            print("\nTest output: \n")
            for event in events:
                response = self.api_client.send_event(event, self.args)
                print (response)

    def get_format(self, integration):
        if integration['format'] == Formats.SYSLOG.value['name']:
            return SyslogFormat(integration, self.args)
        if integration['format'] == Formats.JSON.value['name']:
            return JsonFormat(integration, self.args)
        if integration['format'] == Formats.EVENTCHANNEL.value['name']:
            return EventChannelFormat(integration, self.args)
        if integration['format'] == Formats.MACOS.value['name']:
            return MacosFormat(integration, self.args)
        if integration['format'] == Formats.REMOTE_SYSLOG.value['name']:
            return RemoteSyslogFormat(integration, self.args)
        if integration['format'] == Formats.AUDIT.value['name']:
            return AuditFormat(integration, self.args)
        if integration['format'] == Formats.COMMAND.value['name']:
            return CommandFormat(integration, self.args)
        if integration['format'] == Formats.FULL_COMMAND.value['name']:
            return FullCommandFormat(integration, self.args)
        if integration['format'] == Formats.MULTI_LINE.value['name']:
            return MultilineFormat(integration, self.args)
