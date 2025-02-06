
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


def parse_section(original, new_section):
    """Replace element in 'original' with the content of 'section'.

    Parameters
    ----------
    original : ElementTree
        Original XML where to search and replace the content of 'section'.
    new_section : ElementTree
        ElementTree element which replaces its equivalent in 'original'.
    """

    def element_finder(full_tree, element_to_search):
        """Return ET element inside 'full_tree'. If 'element_to_search' contains an attribute, it is used too.

        Parameters
        ----------
        full_tree : ElementTree
            Full xml where to search the element.
        element_to_search : ElementTree
            Element to be searched inside 'full_tree'.

        Returns
        -------
        ElementTree, None
            The ET element inside 'full_tree'. None if not found.
        """
        if element_to_search.attrib:
            result = full_tree.find('.//{tag}[@{attrib_key}="{attrib_value}"]'.format(
                tag=element_to_search.tag, attrib_key=next(iter(element_to_search.attrib.keys())),
                attrib_value=next(iter(element_to_search.attrib.values())))
            )
            # If element with same tag and attribute is not found in 'full_tree', look for element with
            # same tag and value (text).
            result = next(
                (full_tree_element for full_tree_element in iter(full_tree.iter(element_to_search.tag))
                 if full_tree_element.text == element_to_search.text),
                None) if result is None else result
        else:
            result = full_tree.find('.//{tag}'.format(tag=element_to_search.tag))

        return result

    section_in_og_root = element_finder(original, new_section)
    if section_in_og_root is None:
        original.append(new_section)
        original_xml.write(og_xml_name)
        return

    if len(new_section) > 0:
        for element in new_section:
            if len(element) == 0:
                subelement = element_finder(section_in_og_root, element)
                if subelement is None:
                    section_in_og_root.append(element)
                    continue
                subelement.text = element.text
                subelement.attrib = element.attrib
            else:
                parse_section(section_in_og_root, element)
    else:
        section_in_og_root.text = new_section.text


if __name__ == '__main__':
    # First argument is original XML
    # Second argument is an XML file with the full section to modify
    # This script ADDS and MODIFIES XML sections, but it does not delete any.

    og_xml_name = sys.argv[1]
    new_xml_name = sys.argv[2]

    sanitized_file = sanitize_xml(og_xml_name)

    with open(og_xml_name, 'w') as f:
        f.writelines(sanitized_file)

    original_xml = parse(og_xml_name)
    new_xml_sections = parse(new_xml_name)

    for section in new_xml_sections.getroot():
        parse_section(original_xml.getroot(), section)

    original_xml.write(og_xml_name)
