
from engine_test.event_splitters.base_splitter import SplitterEvent

class DynamicMultilineSplitter(SplitterEvent):
    def __init__(self, delimiter='\n---EOE---\n'):
        self.delimiter: str = delimiter

        if self.delimiter == '':
            raise ValueError("The delimiter cannot be empty.")

    def split_events(self, events: list[str]) -> list[str]:

        events_formated = []

        for event in events:
            # Split the event string by the divider and strip each part to remove leading/trailing whitespaces
            split_events = [part.strip() for part in event.split(self.delimiter)]
            # Extend the split_events list by adding non-empty parts
            events_formated.extend([part for part in split_events if part])


        return events_formated
