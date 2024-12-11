import json
from engine_test.event_format import EventFormat, Formats

class MacosFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.MACOS.value['queue']
        self.config['origin'] = Formats.MACOS.value['origin']

    def is_multiline(self):
        return Formats.MACOS.value['multiline']
