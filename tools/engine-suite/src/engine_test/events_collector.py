
import io
import sys

class EventsCollector:
    def collect(format) -> list:
        is_user_input : bool = sys.stdin.isatty()
        events = []

        # If is a terminal
        if is_user_input:
            event = ""
            while event == "": # TODO Better filter
                if format.is_singleline():
                    print("Enter any events [ENTER to send event, CTRL+C to finish]:\n")
                    event = sys.stdin.readline()
                else:
                    print("Enter any events [CTRL + D to send event, CTRL + C to finish]:\n")
                    event = sys.stdin.read()
            print("\n")
            events.append(event)
        # If is a pipe
        else:
            if format.is_singleline():
                events = sys.stdin.readlines()
            else:
                events.append(sys.stdin.read())

        # TODO Check empty file with pipe
        return format.get_events(events)
