import json
import yaml
import sys

# Todo: Use the shared Dumper class after CLI is merged
try:
    from yaml import CDumper as BaseDumper
except ImportError:
    from yaml import Dumper as BaseDumper

from google.protobuf.json_format import MessageToDict

from engine_test.input_collector import InputEventCollector

from engine_test.event_parsers.single_line import SingleLineParser
from engine_test.event_parsers.multi_line import MultilineParser
from engine_test.event_parsers.eventchannel import EventChannelParser

from engine_test.conf.integration import Formats, IntegrationConf

from engine_test.api_connector import ApiConnector

from api_communication.proto import tester_pb2 as api_tester

class EngineDumper(BaseDumper): # TODO Use the shared Dumper class
    def represent_scalar(self, tag, value, style=None):
        # If the value contains a single quote, force double quotes
        if style is None and "'" in value:
            style = '"'
        # If the value contains a line break, force literal style
        if '\n' in value:
            style = '|'
        return super(EngineDumper, self).represent_scalar(tag, value, style)


class Integration():
    def __init__(self, args: dict, integration: IntegrationConf):
        self.args = args
        self.iconf: IntegrationConf = integration

        # Get the format of integration
        self.event_parser = self.get_parser(self.iconf)

        # Client to API TEST
        self.api_client = ApiConnector(args)
        self.api_client.create_session()

    def run(self):
        events_parsed = []
        json_header = self.iconf.get_template().get_header() + "\n"
        try:
            while True:
                try:
                    events = []
                    # Collect the events
                    events = InputEventCollector.collect(Formats.is_collected_as_multiline(self.iconf.format))
                    # Parse the events, split them
                    events = self.event_parser.split_events(events)
                    # Remove invalid events
                    events = list(filter(None, events))
                    # Create ndjson events and add the header to each event
                    events = [json_header + self.iconf.get_template().get_event(event) for event in events]

                    # Process the events
                    if len(events) > 0:
                        for event in events:
                            response = self.process_event(event)
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

    def process_event(self, event):

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

    def get_parser(self, iconf : IntegrationConf):
        try:
            if iconf.format == Formats.SINGLE_LINE:
                return SingleLineParser()
            elif iconf.format == Formats.MULTI_LINE:
                return MultilineParser(iconf.lines)
            elif iconf.format == Formats.WINDOWS_EVENTCHANNEL:
                return EventChannelParser()
            else:
                raise Exception(f"Invalid format: {format}")
        except Exception as ex:
            print("An error occurred while trying to obtain the integration format. Error: {}".format(ex))
