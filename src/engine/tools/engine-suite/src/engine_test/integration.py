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

        # Get the integration
        integration_name = self.args['integration-name']
        self.integration = self.get_integration(integration_name)
        if not self.integration:
            print("Integration not found!")
            exit(1)
        print ('{}'.format(self.integration))

        # Get the format of integration
        self.format = self.get_format(self.integration)
        if not self.format:
            print("Format of integration not found!")
            exit(2)
        else:
            self.args['origin'] = self.format.get_full_location(self.args)

        # Client to API TEST
        self.api_client = ApiConnector(args)

    def run(self):
        events_parsed = []
        try:
            while (True):
                # Get the events in single o multiline format
                events = EventsCollector.collect(self.format)

                for event in events:
                    response = self.process_event(event, self.format)
                    events_parsed.append(response)
        except Exception as ex:
            print("An error occurred while trying to process the events. Error: {}".format(ex))
        finally:
            self.write_output_file(events_parsed)
            self.api_client.delete_session()

    def process_event(self, event, format):
        event = format.format_event(event)
        response = self.api_client.send_event(event)
        return response

    def write_output_file(self, events_parsed):
        try:
            if self.args['output_file'] and len(events_parsed) > 0:
                with open(self.args['output_file'], 'a') as f:
                    for event in events_parsed:
                        f.write(f"{event}\n")
                print("File output writed correctly.")
        except Exception as ex:
            print("Failed to register the output file. Error: {}".format(ex))

    def get_format(self, integration):
        try:
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
                return MultilineFormat(integration, self.args, integration['lines'])
        except Exception as ex:
            print("An error occurred while trying to obtain the integration format. Error: {}".format(ex))
