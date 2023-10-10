import json
from engine_test.event_format import EventFormat, Formats

class AuditFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.AUDIT.value['queue']

    def is_multiline(self):
        return Formats.AUDIT.value['multiline']