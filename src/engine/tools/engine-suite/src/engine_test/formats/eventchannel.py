import re
from lxml import etree as ET

from engine_test.event_format import EventFormat, Formats

class EventChannelFormat(EventFormat):
    def __init__(self, integration, args):
        super().__init__(integration, args)
        self.config['queue'] = Formats.EVENTCHANNEL.value['queue']
        self.config['origin'] = Formats.EVENTCHANNEL.value['origin']

    def format_event(self, event):
        return event

    def get_xml(self, event):
        xml_start = event.find('<Event')
        if xml_start == -1:
            print("XML 'Event' or 'Events' tag not found in '{}'".format(event))
            return None

        xml = event[xml_start:]

        try:
            return ET.fromstring(xml)
        except ET.XMLSyntaxError as ex:
            print("XML ParseError: {}. The event will be ignored.".format(ex))
            return None

    def get_events(self, raw_inputs):
        event_list = []
        # to remove the XML header if it exists
        xml_header_regex = re.compile(r'<\?xml.*?\?>\s*')
        # TODO: check if namespace needs to be added
        # if namespace is not registered, register it
        # etree.register_namespace('xmlns', 'http://schemas.microsoft.com/win/2004/08/events/event')

        # Extract the XML from the event
        for raw_input in raw_inputs:
            root = self.get_xml(raw_input)
            if root is None:
                continue
            tag_name = root.tag.split('}')[-1]
            if tag_name == 'Events':
                for event in root:
                    event_string = ET.tostring(event, method='xml', encoding='utf-8').decode('utf-8')
                    event_string = xml_header_regex.sub('', event_string)
                    event_list.append(event_string)
            # Si el XML representa un solo evento
            elif tag_name == 'Event':
                event_string = ET.tostring(root, method='xml', encoding='utf-8').decode('utf-8')
                event_string = xml_header_regex.sub('', event_string)
                event_list.append(event_string)
            else:
                print("XML root tag is not 'Events' or 'Event'")

        return event_list

    def is_multiline(self):
        return Formats.EVENTCHANNEL.value['multiline']
