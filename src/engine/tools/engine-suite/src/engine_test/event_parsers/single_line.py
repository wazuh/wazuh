class SingleLineParser:
    def __init__(self):
        pass

    def format_event(self, event):
        # To remove \n of event(s) from file
        return event.strip()

    def get_events(self, events):
        return events
