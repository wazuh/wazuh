from engine_test.event_format import EventFormat, Formats

class CommandFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.COMMAND.value['queue']

    def format_event(self, event):
        event = super().format_event(event)
        origin = self.config['origin']
        return f"ossec: output: '{origin}': {event}"

    def is_multiline(self):
        return Formats.COMMAND.value['multiline']
