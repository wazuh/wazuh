from engine_test.parser import Parser
from engine_test.event_format import EventFormat, Formats

class FullCommandFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.FULL_COMMAND.value['queue']

    def format_event(self, event):
        origin = self.config['origin']
        event = super().format_event(event)
        return f"ossec: output: '{origin}': {event}"

    def is_multiline(self):
        return Formats.FULL_COMMAND.value['multiline']
