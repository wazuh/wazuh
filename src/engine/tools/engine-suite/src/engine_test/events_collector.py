from enum import Enum
import sys

class EventsCollector:
    def collect() -> []:
        print("Enter any events (CTRL+D to finish):\n")
        final_events = []
        for line in sys.stdin.read().splitlines():
            final_events.append(line)
        return final_events