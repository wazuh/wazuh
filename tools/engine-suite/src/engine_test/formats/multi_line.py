import json
from engine_test.event_format import EventFormat, Formats

class MultilineFormat(EventFormat):
    def __init__(self, integration, args, lines):
        super().__init__(integration, args)
        self.config['queue'] = Formats.MULTI_LINE.value['queue']

        # Quantity of lines to group an event
        self.config['lines'] = lines

    def format_event(self, event):
        return event

    def get_events(self, events):
        lines = 0
        event = ''
        events_formated = []
        for line in events:
            event = event + line
            lines = lines + 1
            # Only add if the number of lines is full, the rest are discarded
            if lines == self.config['lines']:
                events_formated.append(event)
                event = ''
                lines = 0
            else:
                event = event + ' '

        return events_formated
