# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import sys
from copy import deepcopy
from typing import List

import xml.etree.ElementTree as ET

from wazuh_testing.constants.paths.configurations import WAZUH_CONF_PATH

from . import file


def get_wazuh_conf() -> List[str]:
    """
    Get current `ossec.conf` file content.

    Returns
        List of str: A list containing all the lines of the `ossec.conf` file.
    """
    return file.read_file_lines(WAZUH_CONF_PATH)


def write_wazuh_conf(wazuh_conf: List[str]) -> None:
    """
    Write a new configuration in 'ossec.conf' file.

    Args:
        wazuh_conf (list or str): Lines to be written in the ossec.conf file.
    """
    file.write_file(WAZUH_CONF_PATH, wazuh_conf)


def set_section_wazuh_conf(sections: List[dict], template: List[str] = None) -> List[str]:
    """
    Set a configuration in a section of Wazuh. It replaces the content if it exists.

    Args:
        sections (list): List of dicts with section and new elements
        section (str, optional): Section of Wazuh configuration to replace. Default `'syscheck'`
        new_elements (list, optional) : List with dictionaries for settings elements in the section. Default `None`
        template (list of string, optional): File content template

    Returns:
        List of str: List of str with the custom Wazuh configuration.
    """

    def create_elements(section: ET.Element, elements: List):
        """
        Insert new elements in a Wazuh configuration section.

        Args:
            section (ET.Element): Section where the element will be inserted.
            elements (list): List with the new elements to be inserted.
        Returns:
            ET.ElementTree: Modified Wazuh configuration.
        """
        tag = None
        for element in elements:
            for tag_name, properties in element.items():
                tag = ET.SubElement(section, tag_name)
                new_elements = properties.get('elements')
                attributes = properties.get('attributes')
                if attributes is not None:
                    for attribute in attributes:
                        if isinstance(attribute, dict):  # noqa: E501
                            for attr_name, attr_value in attribute.items():
                                tag.attrib[attr_name] = str(attr_value)
                if new_elements:
                    create_elements(tag, new_elements)
                else:
                    tag.text = str(properties.get('value'))
                    attributes = properties.get('attributes')
                    if attributes:
                        for attribute in attributes:
                            if attribute is not None and isinstance(attribute, dict):  # noqa: E501
                                for attr_name, attr_value in attribute.items():
                                    tag.attrib[attr_name] = str(attr_value)
                tag.tail = "\n    "
        tag.tail = "\n  "

    def purge_multiple_root_elements(str_list: List[str], root_delimeter: str = "</ossec_config>") -> List[str]:
        """
        Remove from the list all the lines located after the root element ends.

        This operation is needed before attempting to convert the list to ElementTree because if the ossec.conf had more
        than one `<ossec_config>` element as root the conversion would fail.

        Args:
            str_list (list or str): The content of the ossec.conf file in a list of str.
            root_delimeter (str, optional: The expected string to identify when the first root element ends,
            by default "</ossec_config>"

        Returns:
            list of str : The first N lines of the specified str_list until the root_delimeter is found. The rest of
            the list will be ignored.
        """
        line_counter = 0
        for line in str_list:
            line_counter += 1
            if root_delimeter in line:
                return str_list[0:line_counter]
        else:
            return str_list

    def to_elementTree(str_list: List[str]) -> ET.ElementTree:
        """
        Turn a list of str into an ElementTree object.

        As ElementTree does not support xml with more than one root element this function will parse the list first with
        `purge_multiple_root_elements` to ensure there is only one root element.

        Args:
            str_list (list of str): A list of strings with every line of the ossec conf.

        Returns:
            ElementTree: A ElementTree object with the data of the `str_list`
        """
        str_list = purge_multiple_root_elements(str_list)
        return ET.ElementTree(ET.fromstringlist(str_list))

    def to_str_list(elementTree: ET.ElementTree) -> List[str]:
        """
        Turn an ElementTree object into a list of str.

        Args:
            elementTree (ElementTree): A ElementTree object with all the data of the ossec.conf.

        Returns:
            (list of str): A list of str containing all the lines of the ossec.conf.
        """
        return ET.tostringlist(elementTree.getroot(), encoding="unicode")

    def find_module_config(wazuh_conf: ET.ElementTree, section: str, attributes: List[dict]) -> ET.ElementTree:
        r"""
        Check if a certain configuration section exists in ossec.conf and returns the corresponding block if exists.
        (This extra function has been necessary to implement it to configure the wodle blocks, since they have the same
        section but different attributes).

        Args:
            wazuh_conf (ElementTree): An ElementTree object with all the data of the ossec.conf
            section (str): Name of the tag or configuration section to search for. For example: vulnerability_detector
            attributes (list of dict): List with section attributes. Needed to check if the section exists with all the
            searched attributes and values. For example (wodle section) [{'name': 'syscollector'}]
        Returns:
            ElementTree: An ElementTree object with the section data found in ossec.conf. None if nothing was found.
        """
        if attributes is None:
            return wazuh_conf.find(section)
        else:
            attributes_query = ''.join([f"[@{attribute}='{value}']" for index, _ in enumerate(attributes)
                                        for attribute, value in attributes[index].items()])
            query = f"{section}{attributes_query}"

            try:
                return wazuh_conf.find(query)
            except AttributeError:
                return None

    # Get Wazuh configuration as a list of str
    raw_wazuh_conf = get_wazuh_conf() if template is None else template
    # Generate a ElementTree representation of the previous list to work with its sections
    wazuh_conf = to_elementTree(purge_multiple_root_elements(raw_wazuh_conf))
    for section in sections:
        attributes = section.get('attributes')
        section_conf = find_module_config(
            wazuh_conf, section['section'], attributes)
        # Create section if it does not exist, clean otherwise
        if not section_conf:
            section_conf = ET.SubElement(
                wazuh_conf.getroot(), section['section'])
            section_conf.text = '\n    '
            section_conf.tail = '\n\n  '
        else:
            prev_text = section_conf.text
            prev_tail = section_conf.tail
            section_conf.clear()
            section_conf.text = prev_text
            section_conf.tail = prev_tail

        # Insert section attributes
        if attributes:
            for attribute in attributes:
                if attribute is not None and isinstance(attribute, dict):  # noqa: E501
                    for attr_name, attr_value in attribute.items():
                        section_conf.attrib[attr_name] = str(attr_value)

        # Insert elements
        new_elements = section.get('elements', list())
        if new_elements:
            create_elements(section_conf, new_elements)

    return to_str_list(wazuh_conf)


def expand_placeholders(mutable_obj, placeholders=None):
    """
    Search for placeholders and replace them by a value inside mutable_obj.

    Args:
        mutable_obj (mutable object):  Target object where the replacements are performed.
        placeholders (dict): Each key is a placeholder and its value is the replacement. Default `None`

    Returns:
        Reference: Reference to `mutable_obj`
    """
    placeholders = {} if placeholders is None else placeholders
    if isinstance(mutable_obj, list):
        for index, value in enumerate(mutable_obj):
            if isinstance(value, (dict, list)):
                expand_placeholders(
                    mutable_obj[index], placeholders=placeholders)
            elif value in placeholders:
                mutable_obj[index] = placeholders[value]

    elif isinstance(mutable_obj, dict):
        for key, value in mutable_obj.items():
            if isinstance(value, (dict, list)):
                expand_placeholders(
                    mutable_obj[key], placeholders=placeholders)
            elif value in placeholders:
                mutable_obj[key] = placeholders[value]

    return mutable_obj


def add_metadata(dikt, metadata=None):
    """
    Create a new key 'metadata' in dict if not already exists and updates it with metadata content.

    Args:
        dikt (dict):  Target dict to update metadata in.
        metadata (dict, optional):  Dict including the new properties to be saved in the metadata key.
    """
    if metadata is not None:
        new_metadata = dikt['metadata'] if 'metadata' in dikt else {}
        new_metadata.update(metadata)
        dikt['metadata'] = new_metadata


def process_configuration(config, placeholders=None, metadata=None):
    """
    Get a new configuration replacing placeholders and adding metadata.

    Both placeholders and metadata should have equal length.

    Args:
        config (dict): Config to be enriched.
        placeholders (dict, optional): Dict with the replacements.
        metadata (list of dict, optional): List of dicts with the metadata keys to include in config.

    Returns:
        dict: Dict with enriched configuration.
    """
    new_config = expand_placeholders(
        deepcopy(config), placeholders=placeholders)
    add_metadata(new_config, metadata=metadata)

    return new_config


def load_configuration_template(data_file_path, configuration_parameters=[], configuration_metadata=[]):
    """Load different configurations of Wazuh from a YAML file.

    Args:
        data_file_path (str): Full path of the YAML file to be loaded.
        configuration_parameters (list(dict)) : List of dicts where each dict represents a replacement.
        configuration_metadata (list(dict)): Custom metadata to be inserted in the configuration.

    Returns:
        list(dict): List containing wazuh configurations in dictionary form.

    Raises:
        ValueError: If the length of `params` and `metadata` are not equal.
    """
    if len(configuration_parameters) != len(configuration_metadata):
        raise ValueError(f"configuration_parameters and configuration_metadata should have the same data length "
                         f"{len(configuration_parameters)} != {len(configuration_metadata)}")

    configuration = file.read_yaml(data_file_path)

    if sys.platform == 'darwin':
        configuration = set_correct_prefix(configuration, PREFIX)

    return [process_configuration(configuration[0], placeholders=replacement, metadata=meta)
            for replacement, meta in zip(configuration_parameters, configuration_metadata)]


def get_test_cases_data(data_file_path):
    """Load a test case template file and get its data.

    Template example file: tests/integration/vulnerability_detector/test_providers/data/test_cases/test_enabled.yaml

    Args:
        data_file_path (str): Test case template file path.

    Returns:
        (list(dict), list(dict), list(str)): Configurations, metadata and test case names.
    """
    test_cases_data = file.read_yaml(data_file_path)
    configuration_parameters = []
    configuration_metadata = []
    test_cases_ids = []

    for test_case in test_cases_data:
        configuration_parameters.append(test_case['configuration_parameters'])
        metadata_parameters = {
            'name': test_case['name'], 'description': test_case['description']}
        metadata_parameters.update(test_case['metadata'])
        configuration_metadata.append(metadata_parameters)
        test_cases_ids.append(test_case['name'])

    return configuration_parameters, configuration_metadata, test_cases_ids
