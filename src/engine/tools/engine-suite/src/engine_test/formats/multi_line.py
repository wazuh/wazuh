import json
from engine_test.parser import Parser
from engine_test.event_format import EventFormat, Formats

class MultilineFormat(EventFormat):
    def __init__(self, integration, args, lines):
        super().__init__(integration, args)
        self.config['queue'] = Formats.MULTI_LINE.value['queue']

        # Quantity of lines to group an event
        self.config['lines'] = lines

    def parse_events(self, events, config):
        # TODO: parse multiples events of command
        return self.parse_event(events, config)

    def parse_event(self, event, config):
        event_parsed = []
        event = self.parse_multiline(event, config)
        event = Parser.get_event_ossec_format(event, config)
        event_parsed.append(event)
        return event_parsed

    def parse_multiline(self, event, config):
        agent_id = Parser.get_agent_id(config['agent_id'])
        agent_name = Parser.get_agent_name(config['agent_name'])
        agent_ip = Parser.get_agent_ip(config['agent_ip'])
        origin = Parser.get_origin(config['origin'])
        queue = Parser.get_queue(config['queue'])
        header = Parser.get_header_ossec_format(queue, agent_id, agent_name, agent_ip, origin)
        return '{}:{}'.format(header, self.format_event(event))

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
