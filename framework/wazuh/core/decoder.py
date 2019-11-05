# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from enum import Enum

from wazuh import common
from wazuh.core.rule import item_format
from wazuh.exception import WazuhError, WazuhInternalError
from wazuh.utils import load_wazuh_xml


class Status(Enum):
    S_ENABLED = 'enabled'
    S_DISABLED = 'disabled'
    S_ALL = 'all'
    SORT_FIELDS = ['file', 'path', 'name', 'position', 'status']


def add_detail(detail, value, details):
    """
    Add a decoder detail (i.e. regex, order, prematch, etc.).

    :param detail: Detail name.
    :param value: Detail value.
    :param details: Details dict.
    """
    # We return regex detail in an array
    if detail == 'regex':
        if detail in details:
            details[detail].append(value)
        else:
            details[detail] = [value]
    else:
        details[detail] = value


def check_status(status):
    if status is None:
        return Status.S_ALL.value
    elif status in [Status.S_ALL.value, Status.S_ENABLED.value, Status.S_DISABLED.value]:
        return status
    else:
        raise WazuhError(1202)


def load_decoders_from_file(decoder_file, decoder_path, decoder_status):
    try:
        decoders = list()
        position = 0
        root = load_wazuh_xml(os.path.join(common.ossec_path, decoder_path, decoder_file))

        for xml_decoder in list(root):
            # New decoder
            if xml_decoder.tag.lower() == "decoder":
                decoder = {'file': decoder_file, 'path': decoder_path, 'status': decoder_status,
                           'name': xml_decoder.attrib['name'], 'position': position, 'details': dict()}
                position += 1

                for k in xml_decoder.attrib:
                    if k != 'name':
                        decoder['details'][k] = xml_decoder.attrib[k]

                for xml_decoder_tags in list(xml_decoder):
                    add_detail(xml_decoder_tags.tag.lower(), xml_decoder_tags.text, decoder['details'])
                decoders.append(decoder)
    except OSError:
        raise WazuhError(1502, extra_message=os.path.join('WAZUH_HOME', decoder_path, decoder_file))
    except Exception:
        raise WazuhInternalError(1501, extra_message=os.path.join('WAZUH_HOME', decoder_path, decoder_file))

    return decoders


def read_decoders_files():
    tmp_data = list()
    tags = ['decoder_include', 'decoder_exclude']
    exclude_filenames = list()
    for tag in tags:
        if tag in ruleset_conf:
            item_status = Status.S_DISABLED if tag == 'decoder_exclude' else Status.S_ENABLED
            items = ruleset_conf[tag] if type(ruleset_conf[tag]) is list else [ruleset_conf[tag]]

            for item in items:
                item_name = os.path.basename(item)
                full_dir = os.path.dirname(item)
                item_dir = os.path.relpath(full_dir if full_dir else common.ruleset_rules_path,
                                           start=common.ossec_path)
                if tag == 'decoder_exclude':
                    exclude_filenames.append(item_name)
                else:
                    tmp_data.append({'file': item_name, 'path': item_dir, 'status': item_status})

    tag = 'decoder_dir'
    if tag in ruleset_conf:
        items = ruleset_conf[tag] if type(ruleset_conf[tag]) is list else [ruleset_conf[tag]]

        for item_dir in items:
            all_decoders = "{0}/{1}/*.xml".format(common.ossec_path, item_dir)
            item_format(tmp_data, all_decoders, exclude_filenames)
