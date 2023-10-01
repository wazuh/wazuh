from engine_test.event_format import EventFormat, Formats

class RemoteSyslogFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.REMOTE_SYSLOG.value['queue']

    def parse_event(self, event, config):
        queue = self.parser.get_queue(config['queue'])
        origin = self.parser.get_origin(config['origin'])
        header = "{}:{}".format(queue, origin)
        return "{}:{}".format(header, self.parser.parse_syslog_format(event))

    def format_event(self, event):
        return self.parser.parse_syslog_format(event)

    def get_full_location(self, args):
        origin = self.parser.get_origin(args['origin'])
        return "{}".format(origin)
