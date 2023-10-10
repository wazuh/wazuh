
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
            if (format.is_multiline()):
                print("\nEnter any events [CTRL + D to send event, CTRL + C to finish]:")
                for line in sys.stdin.read().splitlines():
                    if (line.strip() != ""):
                        final_events.append(line)
            else:
                print("\nEnter any events [ENTER to send event, CTRL+C to finish]:")
                event = sys.stdin.readline()
                if (event.strip() != ""):
                    final_events.append(event)

        return format.get_events(final_events)
