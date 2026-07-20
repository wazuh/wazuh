import sys

from engine_test.base_tester_integration import BaseIntegrationTester

from engine_test.input_collector import InputEventCollector

from engine_test.conf.integration import CollectModes, IntegrationConf


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
        try:
            while True:
                try:
                    events = []
                    # Collect the events
                    events = InputEventCollector.collect(CollectModes.is_collected_as_multiline(self.iconf.collect_mode))
                    # Parse the events, split them
                    events = self.event_parser.split_events(events)
                    # Remove invalid events
                    for raw in filter(None, events):
                        # Retrieve template for static fields
                        tmpl = self.iconf.get_template()
                        evt_cfg = tmpl.dump_template()["event"]
                        queue = evt_cfg["queue"]
                        location = evt_cfg["location"]

                        # Escape ':' in location per protocol
                        location_escaped = location.replace(':', '|:')

                        # Build raw event: first byte = queue id
                        raw_event = f"{queue}:{location_escaped}:{tmpl.get_event(raw)}"

                        # Send the raw event string for parsing
                        response = self.process_event(raw_event)
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
