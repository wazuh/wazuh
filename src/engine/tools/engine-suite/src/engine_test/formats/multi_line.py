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

        events_formated = []
        maxLines = int(self.config['lines'])
        # Group events by maxLines
        for event in events:
            clean_event = event.strip()
            # Split event by lines
            lines = clean_event.splitlines()
            chunks = []
            for i in range(0, len(lines), maxLines):
                chunk = lines[i:i + maxLines]
                if len(chunk) == maxLines:
                    events_formated.append(' '.join(chunk))

        return events_formated

    def is_multiline(self):
        return Formats.MULTI_LINE.value['multiline']
