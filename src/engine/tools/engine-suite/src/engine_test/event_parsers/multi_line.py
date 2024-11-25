import json

class MultilineParser():
    def __init__(self, event_lines: int):
        self.maxLines : int = event_lines

        if self.maxLines < 0:
            raise ValueError("The number of lines must be greater than 0.")

    def split_events(self, events: list[str]) -> list[str]:

        events_formated = []

        for event in events:
            # split event in lines
            lines = event.strip().splitlines()

            # group lines into chunks of maximum size maxLines
            chunks = [lines[i:i + self.maxLines] for i in range(0, len(lines), self.maxLines)]

            # join the lines of each chunk into a single formatted event,
            # but only if the chunk has exactly self.maxLines lines
            events_formated.extend([' '.join(chunk) for chunk in chunks if len(chunk) == self.maxLines])

        return events_formated
