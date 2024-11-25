class SingleLineParser:
    def __init__(self):
        pass

    def split_events(self, events: list[str]) -> list[str]:
        # To remove \n of event(s) from file
        return [event.strip() for event in events]
