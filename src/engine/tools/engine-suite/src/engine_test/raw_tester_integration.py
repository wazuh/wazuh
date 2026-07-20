import sys

from engine_test.base_tester_integration import BaseIntegrationTester

from engine_test.input_collector import InputEventCollector

from engine_test.conf.integration import CollectModes, IntegrationConf

class RawIntegrationTester(BaseIntegrationTester):
    '''
    Class to test the integration with the API
    '''
    def __init__(self, args: dict, integration: IntegrationConf):
        '''
        Receive the arguments and the integration configuration
        '''
        super().__init__(args)
        self.args = args

        self.args = args
        self.iconf: IntegrationConf = integration

        # Get the format of integration
        self.event_parser = self.get_splitter(self.iconf)

    def run(self):
        events_parsed = []
        try:
            while True:
                try:
                    events = InputEventCollector.collect(CollectModes.is_collected_as_multiline(self.iconf.collect_mode))
                    events = self.event_parser.split_events(events)
                    events = list(filter(None, events))

                    for raw_event in filter(None, events):
                        # Send the raw event string for parsing
                        response = self.process_event(raw_event)
                        events_parsed.append(response)

                except KeyboardInterrupt:
                    break

                if not sys.stdin.isatty():
                    break

        except Exception as ex:
            print("An error occurred while trying to process the events of the integration. Error: {}".format(ex))
            ex.with_traceback(None)

        finally:
            self.write_output_file(events_parsed)
            self.api_client.delete_session()
