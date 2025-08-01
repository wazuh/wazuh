import sys

from engine_test.base_tester_integration import BaseIntegrationTester

from engine_test.input_collector import InputEventCollector

from engine_test.event_splitters.base_splitter import SplitterEvent
from engine_test.event_splitters.single_line import SingleLineSplitter
from engine_test.event_splitters.multi_line import MultilineSplitter
from engine_test.event_splitters.dynamic_multi_line import DynamicMultilineSplitter
from engine_test.event_splitters.eventchannel import EventChannelSplitter

from engine_test.conf.integration import Formats, IntegrationConf

from engine_test.api_connector import ApiConnector


class IntegrationTester(BaseIntegrationTester):
    '''
    Class to test the integration with the API
    '''
    def __init__(self, args: dict, integration: IntegrationConf):
        '''
        Receive the arguments and the integration configuration
        '''
        super().__init__(args)
        self.args = args
        self.iconf: IntegrationConf = integration

        # Get the format of integration
        self.event_parser = self.get_splitter(self.iconf)

    def run(self):
        '''
        Run the integration test
        '''
        events_parsed = []
        json_header = self.iconf.get_template().get_header() + "\n"
        json_subheader = self.iconf.get_template().get_subheader() + "\n"
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
                    events = [json_header + json_subheader + self.iconf.get_template().get_event(event) for event in events]

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


    def get_splitter(self, iconf : IntegrationConf) -> SplitterEvent:
        '''
        Get the parser according to the integration configuration
        '''
        try:
            if iconf.format == Formats.SINGLE_LINE:
                return SingleLineSplitter()
            elif iconf.format == Formats.MULTI_LINE:
                return MultilineSplitter(iconf.lines)
            elif iconf.format == Formats.DYNAMIC_MULTI_LINE:
                return DynamicMultilineSplitter()
            elif iconf.format == Formats.WINDOWS_EVENTCHANNEL:
                return EventChannelSplitter()
            else:
                raise Exception(f"Invalid format: {format}")
        except Exception as ex:
            print("An error occurred while trying to obtain the integration format. Error: {}".format(ex))
