from engine_test.event_format import EventFormat, Formats

class SyslogFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        

    def format_event(self, event):
        return super().format_event(event)
