from engine_test.parser import Parser
from engine_test.event_format import EventFormat, Formats

class FullCommandFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.FULL_COMMAND.value['queue']

    def get_events(self, events):
        events_multiline = []
        events_multiline.append(events)
        return events_multiline

    def format_event(self, event):
        origin = self.config['origin']
        event_parsed = '\n'.join([line for line in event])
        return f"ossec: output: '{origin}':{event_parsed}"

    def is_multiline(self):
        return Formats.FULL_COMMAND.value['multiline']
