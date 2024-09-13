# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import logging
import os
import re
import sys
from configparser import NoOptionError, RawConfigParser
from io import StringIO
from os import path as os_path
from types import MappingProxyType
from typing import Union

from defusedxml.ElementTree import tostring
from wazuh.core import common, wazuh_socket
from wazuh.core.exception import WazuhError, WazuhInternalError, WazuhResourceNotFound
from wazuh.core.InputValidator import InputValidator
from wazuh.core.utils import load_wazuh_xml, load_wazuh_yaml, validate_wazuh_configuration, get_group_file_path

logger = logging.getLogger('wazuh')

# Aux functions

# Type of configuration sections:
#   * Duplicate -> there can be multiple independent sections. Must be returned as multiple json entries.
#   * Merge -> there can be multiple sections but all are dependent with each other. Must be returned as a single json
#   entry.
#   * Last -> there can be multiple sections in the configuration but only the last one will be returned.
#   The rest are ignored.
CONF_SECTIONS = MappingProxyType({
    'active-response': {'type': 'duplicate', 'list_options': []},
    'command': {'type': 'duplicate', 'list_options': []},
    'agentless': {'type': 'duplicate', 'list_options': []},
    'localfile': {'type': 'duplicate', 'list_options': ["filter", "ignore"]},
    'remote': {'type': 'duplicate', 'list_options': []},
    'syslog_output': {'type': 'duplicate', 'list_options': []},
    'integration': {'type': 'duplicate', 'list_options': []},

    'alerts': {'type': 'merge', 'list_options': []},
    'client': {'type': 'merge', 'list_options': []},
    'database_output': {'type': 'merge', 'list_options': []},
    'email_alerts': {
        'type': 'merge',
        'list_options': ['email_to']
    },
    'reports': {
        'type': 'merge',
        'list_options': ['email_to']
    },
    'global': {
        'type': 'merge',
        'list_options': ['white_list']
    },
    'open-scap': {
        'type': 'merge',
        'list_options': ['content']
    },
    'cis-cat': {
        'type': 'merge',
        'list_options': ['content']
    },
    'syscollector': {
        'type': 'merge',
        'list_options': []
    },
    'rootcheck': {
        'type': 'merge',
        'list_options': ['rootkit_files', 'rootkit_trojans', 'windows_audit', 'system_audit', 'windows_apps',
                         'windows_malware']
    },
    'ruleset': {
        'type': 'merge',
        'list_options': ['include', 'rule', 'rule_dir', 'decoder', 'decoder_dir', 'list', 'rule_exclude',
                         'decoder_exclude']
    },
    'syscheck': {
        'type': 'merge',
        'list_options': ['directories', 'ignore', 'nodiff']
    },
    'auth': {
        'type': 'merge',
        'list_options': []
    },

    'cluster': {
        'type': 'last',
        'list_options': ['nodes']
    },
    'osquery': {
        'type': 'merge',
        'list_options': ['pack']
    },
    'labels': {
        'type': 'duplicate',
        'list_options': ['label']
    },
    'sca': {
        'type': 'merge',
        'list_options': ['policies']
    },
    'vulnerability-detection': {
        'type': 'last',
        'list_options': []
    },
    'indexer': {
        'type': 'last',
        'list_options': ['hosts']
    }
})

GETCONFIG_COMMAND = "getconfig"
UPDATE_CHECK_OSSEC_FIELD = 'update_check'
GLOBAL_KEY = 'global'
YES_VALUE = 'yes'
CTI_URL_FIELD = 'cti-url'
DEFAULT_CTI_URL = 'https://cti.wazuh.com'


def _insert(json_dst: dict, section_name: str, option: str, value: str):
    """Insert element (option:value) in a section (json_dst) called section_name.

    Parameters
    ----------
    json_dst : dict
        Destination.
    section_name : str
        Name of the section.
    option : str
        Option to be updated or added.
    value : str
        Value of the option to be updated / added.
    """

    if not value:
        return

    if option in json_dst:
        if type(json_dst[option]) is list:
            json_dst[option].append(value)  # Append new values
        else:
            json_dst[option] = value  # Update values
    else:
        if option in CONF_SECTIONS.get(section_name, {}).get('list_options', []):
            json_dst[option] = [value]  # Create as list
        else:
            json_dst[option] = value  # Update values


def _insert_section(json_dst: dict, section_name: str, section_data: dict):
    """Insert a new section (section_data) called section_name in json_dst.

    Parameters
    ----------
    json_dst : dict
        Destination.
    section_name : str
        Name of the section.
    section_data : dict
        Section be added.
    """

    if CONF_SECTIONS.get(section_name, {}).get('type') == 'duplicate':
        if section_name in json_dst:
            json_dst[section_name].append(section_data)  # Append new values
        else:
            json_dst[section_name] = [section_data]  # Create as list
    elif CONF_SECTIONS.get(section_name, {}).get('type') == 'merge':
        if section_name in json_dst:
            for option in section_data:
                if option in json_dst[section_name] and option in CONF_SECTIONS[section_name].get('list_options', []):
                    json_dst[section_name][option].extend(section_data[option])  # Append new values
                else:
                    json_dst[section_name][option] = section_data[option]  # Update values
        else:
            json_dst[section_name] = section_data  # Create
    elif CONF_SECTIONS.get(section_name, {}).get('type') == 'last':
        if section_name in json_dst:
            # if the option already exists it is overwritten. But a warning is shown.
            logger.warning(f'There are multiple {section_name} sections in configuration. Using only last section.')
        json_dst[section_name] = section_data  # Create


def _read_option(section_name: str, opt: str) -> tuple:
    """Read an option (inside a section) and returns the name and the value.

    Parameters
    ----------
    section_name : str
        Name of the section to be read.
    opt : str
        Option to be read.

    Returns
    -------
    tuple
        Name and value of the option.
    """

    opt_name = opt.tag.lower()

    if section_name == 'open-scap':
        if opt.attrib:
            opt_value = {}
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
            # profiles
            profiles_list = []
            for profiles in opt.iter():
                profiles_list.append(profiles.text)

            if profiles_list:
                opt_value['profiles'] = profiles_list
        else:
            opt_value = opt.text
    elif section_name == 'syscheck' and opt_name == 'directories':
        opt_value = []

        json_attribs = {}
        for a in opt.attrib:
            json_attribs[a] = opt.attrib[a]

        if opt.text:
            for path in opt.text.split(','):
                json_path = json_attribs.copy()
                json_path['path'] = path.strip()
                opt_value.append(json_path)
    elif (section_name == 'syscheck' and opt_name in ('synchronization', 'whodata')) or \
        (section_name == 'cluster' and opt_name == 'haproxy_helper'):
        opt_value = {}
        for child in opt:
            child_section, child_config = _read_option(child.tag.lower(), child)
            opt_value[child_section] = child_config.split(',') if child_config.find(',') > 0 else child_config
    elif (section_name == 'cluster' and opt_name == 'nodes') or \
            (section_name == 'haproxy_helper' and opt_name == 'excluded_nodes') or \
            (section_name == 'sca' and opt_name == 'policies') or \
            (section_name == 'indexer' and opt_name == 'hosts')    :
        opt_value = [child.text for child in opt]
    elif section_name == 'labels' and opt_name == 'label':
        opt_value = {'value': opt.text}
        for a in opt.attrib:
            opt_value[a] = opt.attrib[a]
    elif section_name == 'localfile' and opt_name == 'query':
        # Remove new lines, empty spaces and backslashes
        regex = rf'<{opt_name}>(.*)</{opt_name}>'
        opt_value = re.match(regex,
                             re.sub('(?:(\n) +)', '',
                                    tostring(opt, encoding='unicode').replace('\\<', '<').replace('\\>', '>')
                                    ).strip()).group(1)
    elif section_name == 'remote' and opt_name == 'protocol':
        opt_value = [elem.strip() for elem in opt.text.split(',')]
    else:
        if opt.attrib or list(opt):
            opt_value = {}
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
            if list(opt):
                for child in opt:
                    child_section, child_config = _read_option(child.tag.lower(), child)
                    try:
                        opt_value[child_section].append(child_config)
                    except KeyError:
                        opt_value[child_section] = [child_config]

            else:
                opt_value['item'] = opt.text
        else:
            opt_value = opt.text

    return opt_name, _replace_custom_values(opt_value)


def _replace_custom_values(opt_value: Union[list, dict, str]) -> Union[list, dict, str]:
    """Replace custom values introduced by 'load_wazuh_xml' with their real values.

    Parameters
    ----------
    opt_value : list or dict or str
        Value to be replaced.
    """
    if type(opt_value) is list:
        for i in range(0, len(opt_value)):
            opt_value[i] = _replace_custom_values(opt_value[i])
    elif type(opt_value) is dict:
        for key in opt_value.keys():
            opt_value[key] = _replace_custom_values(opt_value[key])
    elif type(opt_value) is str:
        return opt_value.replace('_custom_amp_lt_', '&lt;').replace('_custom_amp_gt_', '&gt;')
    return opt_value


def _conf2json(src_xml: str, dst_json: dict):
    """Parse src_xml to JSON. It is inserted in dst_json.

    Parameters
    ----------
    src_xml : str
        Configuration to be parsed to JSON.
    dst_json : dict
        Destination.
    """

    for section in list(src_xml):
        section_name = section.attrib['name'] if section.tag.lower() == 'wodle' else section.tag.lower()
        section_json = {}

        for option in list(section):
            option_name, option_value = _read_option(section_name, option)
            if type(option_value) is list and not (section_name == 'remote' and option_name == 'protocol'):
                for ov in option_value:
                    _insert(section_json, section_name, option_name, ov)
            else:
                _insert(section_json, section_name, option_name, option_value)

        _insert_section(dst_json, section_name, section_json)


def _ossecconf2json(xml_conf: str) -> dict:
    """Return ossec.conf in JSON from XML.

    Parameters
    ----------
    xml_conf : str
        Configuration to be parsed to JSON.

    Returns
    -------
    dict
        Final JSON with the ossec.conf content.
    """
    final_json = {}

    for root in list(xml_conf):
        if root.tag.lower() == "ossec_config":
            _conf2json(root, final_json)

    return final_json


# Main functions
def get_ossec_conf(section: str = None, field: str = None, conf_file: str = common.OSSEC_CONF,
                   from_import: bool = False, distinct: bool = False) -> dict:
    """Return ossec.conf (manager) as dictionary.

    Parameters
    ----------
    section : str
        Filters by section (i.e. rules).
    field : str
        Filters by field in section (i.e. included).
    conf_file : str
        Path of the configuration file to read. Default: common.OSSEC_CONF
    from_import : bool
        This flag indicates whether this function has been called from a module load (True) or from a function (False).
    distinct : bool
        Look for distinct values.

    Raises
    ------
    WazuhError(1101)
        Requested component does not exist.
    WazuhError(1102)
        Invalid section.
    WazuhError(1103)
        Invalid field in section.
    WazuhError(1106)
        Requested section not present in configuration.

    Returns
    -------
    dict
        ossec.conf (manager) as dictionary.
    """
    try:
        # Read XML
        xml_data = load_wazuh_xml(conf_file)

        # Parse XML to JSON
        data = _ossecconf2json(xml_data)
    except Exception as e:
        if not from_import:
            raise WazuhError(1101, extra_message=str(e))
        else:
            print(f"wazuh-apid: There is an error in the ossec.conf file: {str(e)}")
            sys.exit(0)

    if section:
        try:
            data = {section: data[section]}
        except KeyError as e:
            if section not in CONF_SECTIONS.keys():
                raise WazuhError(1102, extra_message=e.args[0])
            else:
                raise WazuhError(1106, extra_message=e.args[0])

    if section and field:
        try:
            if isinstance(data[section], list):
                data = {section: [{field: item[field]} for item in data[section]]}
            else:
                field_data = data[section][field]
                if distinct and section == 'ruleset':
                    if field in ('decoder_dir', 'rule_dir'):
                        # Remove duplicates
                        values = []
                        [values.append(x) for x in field_data if x not in values]
                        field_data = values

                data = {section: {field: field_data}}
        except KeyError:
            raise WazuhError(1103)

    return data


def get_group_conf(group_id: str = None, raw: bool = False) -> Union[dict, str]:
    """Return group configuration as dictionary.

    Parameters
    ----------
    group_id : str
        ID of the group with the configuration we want to get.
    raw : bool
        Respond in raw format.

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhError(1006)
        group configuration does not exist or there is a problem with the permissions.

    Returns
    -------
    dict or str
        Group configuration as dictionary.
    """
    filepath = get_group_file_path(group_id)
    if not os_path.exists(filepath):
        raise WazuhResourceNotFound(1710, group_id)

    if raw:
        try:
            # Read RAW file
            with open(filepath, 'r') as raw_data:
                data = raw_data.read()
                return data
        except Exception as e:
            raise WazuhError(1006, str(e))

    # Parse YAML
    data = load_wazuh_yaml(filepath)

    return {'total_affected_items': len(data), 'affected_items': data}


def parse_internal_options(high_name: str, low_name: str) -> str:
    """Parse internal_options.conf file.

    Parameters
    ----------
    high_name : str
        Name of the daemon with the option we want to parse.
    low_name : str
        Option we want to parse.

    Raises
    ------
    WazuhInternalError(1107)
        Internal options file not found.
    WazuhInternalError(1108)
        Value not found in internal_options.conf.

    Returns
    -------
    str
        Value of the internal_options.conf option.
    """

    def get_config(config_path: str) -> dict:
        """Read configuration given by its path.

        Parameters
        ----------
        config_path : str
            Configuration path.

        Returns
        -------
        dict
            Configuration as a dictionary.
        """
        with open(config_path) as f:
            str_config = StringIO('[root]\n' + f.read())

        config = RawConfigParser()
        config.read_file(str_config)

        return config

    if not os_path.exists(common.INTERNAL_OPTIONS_CONF):
        raise WazuhInternalError(1107)

    # Check if the option exists at local internal options
    if os_path.exists(common.LOCAL_INTERNAL_OPTIONS_CONF):
        try:
            return get_config(common.LOCAL_INTERNAL_OPTIONS_CONF).get('root', f'{high_name}.{low_name}')
        except NoOptionError:
            pass

    try:
        return get_config(common.INTERNAL_OPTIONS_CONF).get('root', f'{high_name}.{low_name}')
    except NoOptionError as e:
        raise WazuhInternalError(1108, e.args[0])


def get_internal_options_value(high_name: str, low_name: str, max_: int, min_: int) -> int:
    """Get value of a specific internal option from internal_options.conf.

    Parameters
    ----------
    high_name : str
        Name of the daemon with the option we want to get.
    low_name : str
        Option we want to get.
    max_ : int
        Maximum value of the option.
    min_ : int
        Minimum value of the option.

    Raises
    ------
    WazuhError(1109)
        Option must be a digit.
    WazuhError(1110)
        Option value is out of the limits.

    Returns
    -------
    int
        Value of the internal_options.conf option.
    """
    option = parse_internal_options(high_name, low_name)
    if not option.isdigit():
        raise WazuhError(1109, f'Option: {high_name}.{low_name}. Value: {option}')

    option = int(option)
    if option < min_ or option > max_:
        raise WazuhError(1110, f'Max value: {max_}. Min value: {min_}. Found: {option}.')

    return option


def update_group_configuration(group_id: str, file_content: str) -> str:
    """Update group configuration.

    Parameters
    ----------
    group_id : str
        Group to update.
    file_content : str
        File content of the new configuration in a string.

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhInternalError(1006)
        Error writing file.

    Returns
    -------
    str
        Confirmation message.
    """
    filepath = get_group_file_path(group_id)

    if not os_path.exists(filepath):
        raise WazuhResourceNotFound(1710, group_id)

    validate_wazuh_configuration(file_content)

    try:
        with open(filepath, 'w') as f:
            f.write(file_content)
    except Exception as e:
        raise WazuhError(1006, extra_message=str(e))

    return 'Agent configuration was successfully updated'


def update_group_file(group_id: str, file_data: str) -> str:
    """Update a group file.

    Parameters
    ----------
    group_id : str
        Group to update.
    file_data : str
        Upload data.

    Raises
    ------
    WazuhError(1722)
        If there was a validation error.
    WazuhResourceNotFound(1710)
        Group was not found.
    WazuhError(1112)
        Empty files are not supported.

    Returns
    -------
    str
        Confirmation message in string.
    """
    if not InputValidator().group(group_id):
        raise WazuhError(1722)

    if not os_path.exists(get_group_file_path(group_id)):
        raise WazuhResourceNotFound(1710, group_id)

    if len(file_data) == 0:
        raise WazuhError(1112)

    return update_group_configuration(group_id, file_data)


def get_active_configuration(component: str, configuration: str, agent_id: str = None) -> dict:
    """Get an agent's component active configuration.

    Parameters
    ----------
    agent_id : str
        Agent ID. All possible values from 001 onwards.
    component : str
        Selected agent's component.
    configuration : str
        Configuration to get, written on disk.

    Raises
    ------
    WazuhError(1307)
        If the component or configuration are not specified.
    WazuhError(1101)
        If the specified component is not valid.
    WazuhError(1121)
        If the component is not properly configured.
    WazuhInternalError(1121)
        If the socket cant be created.
    WazuhInternalError(1118)
        If the socket is not able to receive a response.
    WazuhError(1117)
        If there's no such file or directory in agent node, or the socket cannot send the request.
    WazuhError(1116)
        If the reply from the node contains an error.

    Returns
    -------
    dict
        The active configuration the agent is currently using.
    """
    sockets_json_protocol = {'remote', 'analysis', 'wdb'}
    component_socket_mapping = {'agent': 'analysis', 'agentless': 'agentless', 'analysis': 'analysis', 'auth': 'auth',
                                'com': 'com', 'csyslog': 'csyslog', 'integrator': 'integrator',
                                'logcollector': 'logcollector', 'mail': 'mail', 'monitor': 'monitor',
                                'request': 'remote', 'syscheck': 'syscheck', 'wazuh-db': 'wdb', 'wmodules': 'wmodules'}
    component_socket_dir_mapping = {'agent': 'sockets', 'agentless': 'sockets', 'analysis': 'sockets',
                                    'auth': 'sockets', 'com': 'sockets', 'csyslog': 'sockets', 'integrator': 'sockets',
                                    'logcollector': 'sockets', 'mail': 'sockets', 'monitor': 'sockets',
                                    'request': 'sockets', 'syscheck': 'sockets', 'wazuh-db': 'db',
                                    'wmodules': 'sockets'}

    if not component or not configuration:
        raise WazuhError(1307)

    # Check if the component is correct
    components = component_socket_mapping.keys()
    if component not in components:
        raise WazuhError(1101, f'Valid components: {", ".join(components)}')

    def get_active_configuration_manager():
        """Get manager active configuration."""
        # Communicate with the socket that corresponds to the component requested
        dest_socket = os_path.join(common.WAZUH_PATH, "queue", component_socket_dir_mapping[component],
                                   component_socket_mapping[component])

        # Verify component configuration
        if not os.path.exists(dest_socket):
            raise WazuhError(1121,
                             extra_message=f"Please verify that the component '{component}' is properly configured")

        # Simple socket message
        if component_socket_mapping[component] not in sockets_json_protocol:
            msg = f"{GETCONFIG_COMMAND} {configuration}"

            # Socket connection
            try:
                s = wazuh_socket.WazuhSocket(dest_socket)
            except WazuhInternalError:
                raise
            except Exception as unhandled_exc:
                raise WazuhInternalError(1121, extra_message=str(unhandled_exc))

            # Send message
            s.send(msg.encode())

            # Receive response
            try:
                # Receive data length
                rec_msg_ok, rec_msg = s.receive().decode().split(" ", 1)
            except ValueError:
                raise WazuhInternalError(1118, extra_message="Data could not be received")
            finally:
                s.close()

            return rec_msg_ok, rec_msg

        # JSON socket message
        else:  # component_socket_mapping[component] in sockets_json_protocol
            msg = wazuh_socket.create_wazuh_socket_message(origin={'module': common.origin_module.get()},
                                                           command=GETCONFIG_COMMAND,
                                                           parameters={'section': configuration})

            # Socket connection
            try:
                s = wazuh_socket.WazuhSocketJSON(dest_socket)
            except WazuhInternalError:
                raise
            except Exception as unhandled_exc:
                raise WazuhInternalError(1121, extra_message=str(unhandled_exc))

            # Send message
            s.send(msg)

            # Receive response
            try:
                response = s.receive(raw=True)
            except ValueError:
                raise WazuhInternalError(1118, extra_message="Data could not be received")
            finally:
                s.close()

            return response['error'], response['data']

    def get_active_configuration_agent():
        """Get agent active configuration"""
        # Always communicate with remote socket
        dest_socket = common.REMOTED_SOCKET

        # Simple socket message
        msg = f"{str(agent_id).zfill(3)} {component} {GETCONFIG_COMMAND} {configuration}"

        # Socket connection
        try:
            s = wazuh_socket.WazuhSocket(dest_socket)
        except WazuhInternalError:
            raise
        except Exception as unhandled_exc:
            raise WazuhInternalError(1121, extra_message=str(unhandled_exc))

        # Send message
        s.send(msg.encode())

        # Receive response
        try:
            # Receive data length
            rec_msg_ok, rec_msg = s.receive().decode().split(" ", 1)
        except ValueError:
            raise WazuhInternalError(1118, extra_message="Data could not be received")
        finally:
            s.close()

        return rec_msg_ok, rec_msg

    rec_error, rec_data = get_active_configuration_agent() if agent_id else get_active_configuration_manager()

    if rec_error == 'ok' or rec_error == 0:
        data = json.loads(rec_data) if isinstance(rec_data, str) else rec_data

        # Include password if auth->use_password enabled and authd.pass file exists
        if data.get('auth', {}).get('use_password') == 'yes':
            try:
                with open(os_path.join(common.WAZUH_PATH, "etc", "authd.pass"), 'r') as f:
                    data['authd.pass'] = f.read().rstrip()
            except IOError:
                pass

        return data
    else:
        raise WazuhError(1117 if "No such file or directory" in rec_data or "Cannot send request" in rec_data else 1116,
                         extra_message=f'{component}:{configuration}')


def write_ossec_conf(new_conf: str):
    """Replace the current wazuh configuration (ossec.conf) with the provided configuration.

    Parameters
    ----------
    new_conf : str
        The new configuration to be applied.

    Raises
    ------
    WazuhError(1126)
        Error updating ossec configuration.
    """
    try:
        with open(common.OSSEC_CONF, 'w') as f:
            f.writelines(new_conf)
    except Exception as e:
        raise WazuhError(1126, extra_message=str(e))


def update_check_is_enabled() -> bool:
    """Read the ossec.conf and check UPDATE_CHECK_OSSEC_FIELD value.

    Returns
    -------
    bool
        True if UPDATE_CHECK_OSSEC_FIELD is 'yes' or isn't present, else False.
    """
    try:
        global_configurations = get_ossec_conf(section=GLOBAL_KEY).get(GLOBAL_KEY, {})
        return global_configurations.get(UPDATE_CHECK_OSSEC_FIELD, YES_VALUE) == YES_VALUE
    except WazuhError as e:
        if e.code != 1106:
            raise e
        return True


def get_cti_url() -> str:
    """Get the CTI service URL from the configuration.

    Returns
    -------
    str
        CTI service URL. The default value is returned if CTI_URL_FIELD isn't present.
    """
    try:
        return get_ossec_conf(section=GLOBAL_KEY).get(GLOBAL_KEY, {}).get(CTI_URL_FIELD, DEFAULT_CTI_URL)
    except WazuhError as e:
        if e.code != 1106:
            raise e
        return DEFAULT_CTI_URL
