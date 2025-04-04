import json
import yaml

# Todo: Use the shared Dumper class after CLI is merged
try:
    from yaml import CDumper as BaseDumper
except ImportError:
    from yaml import Dumper as BaseDumper

from google.protobuf.json_format import MessageToDict


from engine_test.event_splitters.base_splitter import SplitterEvent

from engine_test.conf.integration import IntegrationConf

from engine_test.api_connector import ApiConnector

from api_communication.proto import tester_pb2 as api_tester

from abc import ABC, abstractmethod

# TODO Use the shared Dumper class after cli is merged, change name to this file
class EngineDumper(BaseDumper): # TODO Use the shared Dumper class
    def represent_scalar(self, tag, value, style=None):
        # If the value contains a single quote, force double quotes
        if style is None and "'" in value:
            style = '"'
        # If the value contains a line break, force literal style
        if '\n' in value:
            style = '|'
        return super(EngineDumper, self).represent_scalar(tag, value, style)

class BaseIntegrationTester(ABC):
    def __init__(self, args: dict):
        self.args = args
        self.api_client = ApiConnector(args)
        self.api_client.create_session()

    def process_event(self, event):
        '''
        Process the event through the API and return the response
        '''

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

    @abstractmethod
    def run(self):
        '''
        Run the integration test
        '''
        pass
