from engine_test.parser import Parser
from engine_test.event_format import EventFormat, Formats

class SyslogFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.SYSLOG.value['queue']

    def parse_event(self, event, config):
        event = self.format_event(event)
        return Parser.get_event_ossec_format(event, self.config)

    def format_event(self, event):
        return Parser.parse_syslog_format(event)
