from enum import Enum
import sys

class EventsCollector:
    def collect(format) -> []:
        print("\nEnter any events (CTRL+D to finish):")
        final_events = []
        for line in sys.stdin.read().splitlines():
            final_events.append(line)
        return format.get_events(final_events)
