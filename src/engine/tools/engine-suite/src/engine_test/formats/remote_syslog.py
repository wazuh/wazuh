from engine_test.parser import Parser
from engine_test.event_format import EventFormat, Formats

class RemoteSyslogFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.REMOTE_SYSLOG.value['queue']

    def parse_event(self, event, config):
        queue = Parser.get_queue(config['queue'])
        origin = Parser.get_origin(config['origin'])
        header = "{}:{}".format(queue, origin)
        return "{}:{}".format(header, Parser.parse_syslog_format(event))
