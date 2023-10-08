from enum import Enum
import sys

class EventsCollector:
    def collect(interactive, format, event = None) -> []:
        final_events = []
        if not interactive:
            if event == None:
                final_events = sys.stdin.readlines()
            else:
                final_events.append(event)
        else:
            print("\nEnter any events (CTRL+D to finish):")
            for line in sys.stdin.read().splitlines():
                final_events.append(line)
        return format.get_events(final_events)
