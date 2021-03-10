
import sys

from xml.etree.ElementTree import parse


def sanitize_xml(file):
    new_file = list()
    with open(file, 'r') as f:
        for line in f.readlines():
            new_file.append(line)
            if '</ossec_config>' in line:
                break

    return new_file


def parse_section(og_root, section):
    try:
        children = next(iter(og_root.iter(section.tag)))
    except StopIteration:
        og_root.append(section)
        original_xml.write(or_xml_name)
        return

    if len(section) > 0:
        for element in section:
            try:
                subelement = next(iter(children.iter(element.tag)))
                subelement.text = element.text
            except StopIteration:
                children.append(element)
    else:
        children.text = section.text


if __name__ == '__main__':
    # First argument is original XML
    # Second argument is an XML file with the full section to modify

    or_xml_name = sys.argv[1]
    new_xml_name = sys.argv[2]

    sanitized_file = sanitize_xml(or_xml_name)

    with open(or_xml_name, 'w') as f:
        f.writelines(sanitized_file)

    original_xml = parse(or_xml_name)
    new_xml_sections = parse(new_xml_name)

    for new_section in new_xml_sections.getroot():
        parse_section(original_xml.getroot(), new_section)

    original_xml.write(or_xml_name)
