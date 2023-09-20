from engine_test.parser import Parser
from engine_test.event_format import EventFormat, Formats

class EventChannelFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.EVENTCHANNEL.value['queue']
        self.config['origin'] = Formats.EVENTCHANNEL.value['origin']

    def parse_events(self, events, config):
        # TODO: parse multiples events of windows
        return self.parse_event(events, config)

    def parse_event(self, event, config):
        event_parsed = []
        event = self.parse_eventchannel_format(event)
        event = Parser.get_event_ossec_format(event, config)
        event_parsed.append(event)
        return event_parsed

    def parse_eventchannel_format(self, event):
        event_len = range(10, len(event))
        has_event = False
        message = ""
        eventXML = ""

        for i in event_len:
            if has_event:
                eventXML += event[i]
            if event[i] == "Event Xml:":
                has_event = True
            if has_event == False:
                message += event[i]

        return '{{"Message":"{}","Event":"{}"}}'.format(message, eventXML.replace("\"", "'"))

    def parse_eventchannel_format2(source, event, config):
        message = ""
        eventXML = ""
        has_description = False
        has_event = False
        for line in event:
            if has_event:
                eventXML += line
            if line.startswith("<Event") or line.startswith("Event Xml"):
                has_event = True
                has_description = False
            if has_description:
                message += line
            if line.startswith("Description:"):
                has_description = True
            if line.startswith("</Event>"):
                break
        return '{{"Message":"{}","Event":"{}"}}'.format(message, eventXML.replace("\"", "'"))
