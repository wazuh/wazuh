import sys

from engine_test.base_tester_integration import BaseIntegrationTester

from engine_test.input_collector import InputEventCollector

from engine_test.event_splitters.dynamic_multi_line import DynamicMultilineSplitter

from engine_test.conf.integration import Formats

from engine_test.api_connector import ApiConnector

class RawIntegrationTester(BaseIntegrationTester):
    '''
    Class to test the integration with the API
    '''
    def __init__(self, args: dict):
        '''
        Receive the arguments and the integration configuration
        '''
        super().__init__(args)
        self.args = args

        # Get the format of integration
        self.event_parser = DynamicMultilineSplitter()

        # Client to API TEST
        self.api_client = ApiConnector(args)
        self.api_client.create_session()

    def run(self):
        events_parsed = []
        try:
            while True:
                try:
                    events = InputEventCollector.collect(
                        Formats.is_collected_as_multiline(Formats.DYNAMIC_MULTI_LINE)
                    )
                    events = self.event_parser.split_events(events)
                    events = list(filter(None, events))

                    for event in events:
                        lines = event.strip().splitlines()
                        header = lines[0]
                        subheader = lines[1]
                        for single_event in lines[2:]:
                            full_event = "\n".join([header, subheader, single_event])
                            response = self.process_event(full_event)
                            events_parsed.append(response)

                except KeyboardInterrupt:
                    break

                if not sys.stdin.isatty():
                    break

        except Exception as ex:
            print("Error processing streamed NDJSON events. Error: {}".format(ex))

        finally:
            self.write_output_file(events_parsed)
            self.api_client.delete_session()
