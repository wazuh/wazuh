from enum import Enum
from engine_test.parser import Parser

class Formats(Enum):
    AUDIT = { "name": "audit", "queue": 49, "multiline": True }
    COMMAND = { "name": "command", "queue": 49, "multiline": False }
    EVENTCHANNEL = { "name": "eventchannel", "origin": "EventChannel", "queue": 102, "multiline": True }
    FULL_COMMAND = { "name": "full_command", "queue": 49, "multiline": True }
    JSON = { "name": "json", "queue": 49, "multiline": False }
    MACOS = { "name": "macos", "origin": "macos", "queue": 49, "multiline": False }
    MULTI_LINE = { "name": "multi-line", "queue": 49, "multiline": True }
    SYSLOG = { "name": "syslog", "queue": 49, "multiline": False }
    REMOTE_SYSLOG = { "name": "remote-syslog", "queue": 50, "multiline": False }

    def get_formats():
        formats = []
        for format in Formats:
            formats.append(format.value["name"])
        return formats

class EventFormat:
    def __init__(self, integration, args):
        self.parser = Parser()
        self.config = self.update_args(integration, args)

    def get_full_location(self, args):
        return self.parser.get_full_location(args['agent_id'], args['agent_name'], args['agent_ip'], args['origin'])

    def update_args(self, integration, args):
        if args['origin'] == None and 'origin' in integration:
            args['origin'] = integration['origin']
        return args

    def format_event(self, event):
        # To remove \n of event(s) from file
        return event.strip()

    def get_events(self, events):
        return events

    def is_multiline(self):
        return False
