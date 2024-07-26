import re
from engine_test.event_format import EventFormat, Formats

class RemoteSyslogFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.REMOTE_SYSLOG.value['queue']

    def format_event(self, event):
        event = super().format_event(event)
        # Remove PRI from event: rfc3164 section-4.1.1
        pri_pattern = re.compile(r'^<\d+>')
        event = pri_pattern.sub('', event)
        return event

    def get_full_location(self, args):
        origin = self.parser.get_origin(args['origin'])
        return "{}".format(origin)

    def is_multiline(self):
        return Formats.REMOTE_SYSLOG.value['multiline']
