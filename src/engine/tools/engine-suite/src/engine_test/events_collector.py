
import io
import sys

class EventsCollector:
    def collect(format) -> list:
        is_user_input : bool = sys.stdin.isatty()
        events = []

        # If is a terminal
        if is_user_input:
            event = ""
            while event == "" or event == "\n":
                if format.is_singleline():
                    print("\nEnter any events [ENTER to send event, CTRL+C to finish]:\n")
                    event = sys.stdin.readline()
                else:
                    print("\nEnter any events [CTRL + D to send event, CTRL + C to finish]:\n")
                    event = sys.stdin.read()
            print("\n")
            events.append(event)
        # If is a pipe
        else:
            if format.is_singleline():
                events = sys.stdin.readlines()
                # Ignore empty lines
                events = list(filter(lambda event: event != "\n", events))
            else:
                events.append(sys.stdin.read())

        return events
