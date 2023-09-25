import json
from engine_test.parser import Parser
from engine_test.event_format import EventFormat, Formats

class JsonFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.JSON.value['queue']

    def parse_event(self, event, config):
        event = self.format_event(event)
        return Parser.get_event_ossec_format(event, config)

    def format_event(self, event):
        json_object = json.loads(event)
        return json.dumps(json_object, separators=(',',':'))