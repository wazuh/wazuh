from engine_test.event_format import EventFormat, Formats

class EventChannelFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.EVENTCHANNEL.value['queue']
        self.config['origin'] = Formats.EVENTCHANNEL.value['origin']

    def parse_events(self, events, config):
        return self.parse_event(events, config)

    def parse_event(self, event, config):
        event_parsed = []
        event = self.parse_eventchannel_format(event)
        event = self.parser.get_event_ossec_format(event, config)
        event_parsed.append(event)
        return event_parsed

    def parse_eventchannel_format(self, event):
        message = ""
        eventXML = ""

        if type(event) == list:
            # Unique event
            event_len = range(10, len(event))
            has_event = False

            for i in event_len:
                if has_event:
                    eventXML += event[i]
                if event[i] == "Event Xml:":
                    has_event = True
                if has_event == False:
                    message += event[i]
            eventXML += event[i]
        else:
            eventXML += event

        return '{{"Message":"{}","Event":"{}"}}'.format(message, eventXML.replace("\"", "'"))

    def format_event(self, event):
        return self.parse_eventchannel_format(event)

    def get_events(self, events):
        events_open_tag = '<Events>'
        events_close_tag = '</Events>'
        event_open_tag = '<Event '
        events_multiline = []

        # Remove header from events
        if events[0].startswith('<?xml'):
            del events[0]

        if len(events) > 0 and events[0].startswith(events_open_tag):
            len_events = len(events)

            # Remove <Events> tag
            events[0] = events[0][len(events_open_tag): len(events[0])]

            # Remove </Events> tag
            events[len_events-1] = events[len_events-1][0: events[len_events-1].index(events_close_tag)]

            # Unify events
            event = ''.join([line for line in events])

            # Split and build each event
            result = event.split(event_open_tag)
            for line in result:
                events_multiline.append('{}{}'.format(event_open_tag, line))

        else:
            events_multiline.append(events)

        return events_multiline
