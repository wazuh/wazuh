import json
import yaml
import sys
try:
    from yaml import CDumper as BaseDumper
except ImportError:
    from yaml import Dumper as BaseDumper

from google.protobuf.json_format import MessageToDict

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

from api_communication.proto import tester_pb2 as api_tester

class EngineDumper(BaseDumper):
    def represent_scalar(self, tag, value, style=None):
        # If the value contains a single quote, force double quotes
        if style is None and "'" in value:
            style = '"'
        # If the value contains a line break, force literal style
        if '\n' in value:
            style = '|'
        return super(EngineDumper, self).represent_scalar(tag, value, style)

class Integration(CrudIntegration):
    def __init__(self, args):
        self.args = args

        # Get the integration
        try:
            integration_name = self.args['integration-name']
        except KeyError as ex:
            print("Integration name not foud. Error: {}".format(ex))
            exit(1)

        self.integration = self.get_integration(integration_name)
        if not self.integration:
            print("Integration not found!")
            exit(1)

        # Get the format of integration
        self.format = self.get_format(self.integration)
        if not self.format:
            print("Format of integration not found!")
            exit(1)

        self.args['full_location'] = self.format.get_full_location(self.args)
        # TODO: move escape :| :
        # Client to API TEST
        self.api_client = ApiConnector(args)
        self.api_client.create_session()

    def run(self):
        events_parsed = []
        try:
            while True:
                try:
                    events = []
                    # Get the events
                    events = EventsCollector.collect(self.format)
                    # Split the events
                    events = self.format.get_events(events)
                    # Format each event
                    events = [self.format.format_event(event) for event in events]
                    # Remove invalid events
                    events = list(filter(None, events))

                    if len(events) > 0:
                        for event in events:
                            response = self.process_event(event, self.format)
                            events_parsed.append(response)
                except KeyboardInterrupt as ex:
                    break

                if not sys.stdin.isatty():
                    break

        except Exception as ex:
            print("An error occurred while trying to process the events of the integration. Error: {}".format(ex))
            ex.with_traceback(None)

        finally:
            self.write_output_file(events_parsed)
            self.api_client.delete_session()

    def process_event(self, event, format):

        # Get the values to send
        response : api_tester.RunPost_Response()
        response = self.api_client.tester_run(event)
        # Output string to json
        rawOutput = json.loads(response.result.output)

        hasTrace : bool = len(response.result.asset_traces) > 0
        rawTraces = response.result.asset_traces if hasTrace else []

        # TODO: Move to centralize integration configuration
        # Get the conditions to print the output
        isJsonOutput : bool = self.args['json_format']
        showTrace: bool = self.args['verbose'] or self.args['full_verbose']
        # Set the keys to print the output
        keyOutput = 'output'
        keyTraces = 'traces'

        response = ""
        if isJsonOutput:
            if showTrace:
                rawTraces = [MessageToDict(trace) for trace in rawTraces]
                response = json.dumps({keyOutput: rawOutput, keyTraces: rawTraces}, separators=(',',':'))
            else:
                response = json.dumps(rawOutput, separators=(',',':'), sort_keys=True)

        else:
            response += "---\n"
            if showTrace:
                # Traces
                response += keyTraces + ":"
                if not hasTrace:
                    response += " No traces generated for this event.\n\n"
                else:
                    response += "\n"
                    for traceObjt in rawTraces:
                        t : str = "[🟢] " if traceObjt.success else "[🔴] "
                        t += traceObjt.asset
                        t += " -> success" if traceObjt.success else " -> failed"
                        t += "\n"
                        for trace in traceObjt.traces:
                            t += "  ↳ " + trace + "\n"
                        response += t
                    response += "\n"
                # Output
                response += self.response_to_yml({keyOutput: rawOutput}) + "\n"
            else:
                response += self.response_to_yml(rawOutput) + "\n"

        if not self.args['output_file']:
            print ("{}".format(response))

        return response

    def response_to_yml(self, response):
        response = yaml.dump(response, sort_keys=True, Dumper=EngineDumper, allow_unicode=True)
        return response

    def write_output_file(self, events_parsed):
        try:
            if self.args['output_file'] and len(events_parsed) > 0:
                with open(self.args['output_file'], 'a') as f:
                    for event in events_parsed:
                        f.write(f"{event}\n")
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
