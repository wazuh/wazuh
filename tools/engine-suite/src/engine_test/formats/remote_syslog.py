from engine_test.event_format import EventFormat, Formats

class RemoteSyslogFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.REMOTE_SYSLOG.value['queue']

    def format_event(self, event):
        return self.parser.parse_syslog_format(event)

    def get_full_location(self, args):
        origin = self.parser.get_origin(args['origin'])
        return "{}".format(origin)
