import json
from engine_test.parser import Parser
from engine_test.event_format import EventFormat, Formats

class JsonFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.JSON.value['queue']

    def format_event(self, event):
        event = super().format_event(event)

        # Try parse event as json
        try:
            event = json.loads(event)
        except ValueError:
            return None

        # Logcollector only reads json objects
        if not isinstance(event, dict):
            return None

        # Dump event as json
        return json.dumps(event, separators=(',', ':'))

    def is_multiline(self):
        return Formats.JSON.value['multiline']
