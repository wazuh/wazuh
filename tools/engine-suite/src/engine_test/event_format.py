from enum import Enum
from engine_test.parser import Parser



class EventFormat:
    def __init__(self, integration, args):
        self.parser = Parser()
        self.config = self.update_args(integration, args)


    def format_event(self, event):
        # To remove \n of event(s) from file
        return event.strip()

    def get_events(self, events):
        return events

