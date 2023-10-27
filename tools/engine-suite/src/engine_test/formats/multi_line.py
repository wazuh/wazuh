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
        maxLines = int(self.config['lines'])
        events_formated = []

        for event in events:
            # split event in lines
            lines = event.strip().splitlines()

            # group lines into chunks of maximum size maxLines
            chunks = [lines[i:i + maxLines] for i in range(0, len(lines), maxLines)]

            # join the lines of each chunk into a single formatted event,
            # but only if the chunk has exactly maxLines lines
            events_formated.extend([' '.join(chunk) for chunk in chunks if len(chunk) == maxLines])

        return events_formated


    def is_multiline(self):
        return Formats.MULTI_LINE.value['multiline']
