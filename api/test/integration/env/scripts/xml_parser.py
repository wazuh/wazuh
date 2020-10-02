
import sys

import xml.etree.ElementTree as ET


def parse_section(og_root, section):
    try:
        children = next(iter(og_root.iter(section.tag)))
    except StopIteration:
        og_root.append(section)
        original_xml.write(or_xml_name)
        return

    previous_tail = children.tail
    children.clear()

    if len(section) > 0:
        for element in section:
            element.tail = ''
            children.append(element)
    else:
        children.text = section.text

    children.tail = previous_tail


if __name__ == '__main__':
    # First argument is original XML
    # Second argument is an XML file with the full section to modify

    or_xml_name = sys.argv[1]
    new_xml_name = sys.argv[2]

    original_xml = ET.parse(or_xml_name)
    new_xml_sections = ET.parse(new_xml_name)

    for new_section in new_xml_sections.getroot():
        parse_section(original_xml.getroot(), new_section)

    original_xml.write(or_xml_name)
