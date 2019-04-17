# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import random
import re
import socket
import subprocess
import time
from collections import OrderedDict
from datetime import datetime
from glob import glob
from os import remove, chmod
from os.path import exists, join
from shutil import move, Error
from typing import Dict
from xml.dom.minidom import parseString
from xml.parsers.expat import ExpatError
from typing import Dict
import fcntl

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.utils import previous_month, cut_array, sort_array, search_array, tail, load_wazuh_xml
from wazuh import configuration

_re_logtest = re.compile(r"^.*(?:ERROR: |CRITICAL: )(?:\[.*\] )?(.*)$")
execq_lockfile = join(common.ossec_path, "var/run/.api_execq_lock")


def status() -> Dict:
    """
    Returns the Manager processes that are running.
    :return: Dictionary (keys: status, daemon).
    """

    processes = ['ossec-agentlessd', 'ossec-analysisd', 'ossec-authd', 'ossec-csyslogd', 'ossec-dbd', 'ossec-monitord',
                 'ossec-execd', 'ossec-integratord', 'ossec-logcollector', 'ossec-maild', 'ossec-remoted',
                 'ossec-reportd', 'ossec-syscheckd', 'wazuh-clusterd', 'wazuh-modulesd', 'wazuh-db']

    data, pidfile_regex, run_dir = {}, re.compile(r'.+\-(\d+)\.pid$'), join(common.ossec_path, 'var/run')
    for process in processes:
        pidfile = glob(join(run_dir, f"{process}-*.pid"))
        if exists(join(run_dir, f'{process}.failed')):
            data[process] = 'failed'
        elif exists(join(run_dir, f'.restart')):
            data[process] = 'restarting'
        elif exists(join(run_dir, f'{process}.start')):
            data[process] = 'starting'
        elif pidfile:
            process_pid = pidfile_regex.match(pidfile[0]).group(1)
            # if a pidfile exists but the process is not running, it means the process crashed and
            # wasn't able to remove its own pidfile.
            data[process] = 'running' if exists(join('/proc', process_pid)) else 'failed'
        else:
            data[process] = 'stopped'

    return data


def __get_ossec_log_fields(log):
    regex_category = re.compile(r"^(\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d)\s(\S+)(?:\[.*)?:\s(DEBUG|INFO|CRITICAL|ERROR|WARNING):(.*)$")

    match = re.search(regex_category, log)

    if match:
        date = match.group(1)
        category = match.group(2)
        type_log = match.group(3)
        description = match.group(4)

        if "rootcheck" in category:  # Unify rootcheck category
            category = "ossec-rootcheck"

    else:
        return None

    return datetime.strptime(date, '%Y/%m/%d %H:%M:%S'), category, type_log.lower(), description


def ossec_log(type_log='all', category='all', months=3, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Gets logs from ossec.log.

    :param type_log: Filters by log type: all, error or info.
    :param category: Filters by log category (i.e. ossec-remoted).
    :param months: Returns logs of the last n months. By default is 3 months.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    logs = []

    first_date = previous_month(months)
    statfs_error = "ERROR: statfs('******') produced error: No such file or directory"

    for line in tail(common.ossec_log, 2000):
        log_fields = __get_ossec_log_fields(line)
        if log_fields:
            log_date, log_category, level, description = log_fields

            if log_date < first_date:
                continue

            if category != 'all':
                if log_category:
                    if log_category != category:
                        continue
                else:
                    continue

            log_line = {'timestamp': str(log_date), 'tag': log_category, 'level': level, 'description': description}
            if type_log == 'all':
                logs.append(log_line)
            elif type_log.lower() == level.lower():
                if "ERROR: statfs(" in line:
                    if statfs_error in logs:
                        continue
                    else:
                        logs.append(statfs_error)
                else:
                    logs.append(log_line)
            else:
                continue
        else:
            if logs and line and log_category == logs[-1]['tag'] and level == logs[-1]['level']:
                logs[-1]['description'] += "\n" + line

    if search:
        logs = search_array(logs, search['value'], search['negation'])

    if sort:
        if sort['fields']:
            logs = sort_array(logs, order=sort['order'], sort_by=sort['fields'])
        else:
            logs = sort_array(logs, order=sort['order'], sort_by=['timestamp'])
    else:
        logs = sort_array(logs, order='desc', sort_by=['timestamp'])

    return {'items': cut_array(logs, offset, limit), 'totalItems': len(logs)}


def ossec_log_summary(months=3):
    """
    Summary of ossec.log.

    :param months: Check logs of the last n months. By default is 3 months.
    :return: Dictionary by categories.
    """
    categories = {}

    first_date = previous_month(months)

    with open(common.ossec_log) as f:
        lines_count = 0
        for line in f:
            if lines_count > 50000:
                break
            lines_count = lines_count + 1

            line = __get_ossec_log_fields(line)

            # multine logs
            if line is None:
                continue

            log_date, category, log_type, _, = line

            if log_date < first_date:
                break

            if category:
                if category in categories:
                    categories[category]['all'] += 1
                else:
                    categories[category] = {'all': 1, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 0}
                categories[category][log_type] += 1
            else:
                continue
    return categories


def upload_file(tmp_file, path, content_type, overwrite=False):
    """
    Updates a group file

    :param tmp_file: Relative path of file name from origin
    :param path: Path of destination of the new file
    :param content_type: Content type of file from origin
    :param overwrite: True for updating existing files, False otherwise
    :return: Confirmation message in string
    """
    try:
        # if file already exists and overwrite is False, raise exception
        if not overwrite and exists(join(common.ossec_path, path)):
            raise WazuhException(1905)

        try:
            with open(join(common.ossec_path, tmp_file)) as f:
                file_data = f.read()
        except IOError:
            raise WazuhException(1005)
        except Exception:
            raise WazuhException(1000)

        if len(file_data) == 0:
            raise WazuhException(1112)

        if content_type == 'application/xml':
            return upload_xml(file_data, path)
        elif content_type == 'application/octet-stream':
            return upload_list(file_data, path)
        else:
            raise WazuhException(1016)
    finally:
        # delete temporary file from API
        try:
            remove(join(common.ossec_path, tmp_file))
        except OSError:
            raise WazuhException(1903)


def upload_xml(xml_file, path):
    """
    Updates XML files (rules and decoders)
    :param xml_file: content of the XML file
    :param path: Destination of the new XML file
    :return: Confirmation message
    """
    # path of temporary files for parsing xml input
    tmp_file_path = '{}/tmp/api_tmp_file_{}_{}.xml'.format(common.ossec_path, time.time(), random.randint(0, 1000))

    # create temporary file for parsing xml input
    try:
        with open(tmp_file_path, 'w') as tmp_file:
            # beauty xml file
            xml = parseString('<root>' + xml_file + '</root>')
            # remove first line (XML specification: <? xmlversion="1.0" ?>), <root> and </root> tags, and empty lines
            indent = '  '  # indent parameter for toprettyxml function
            pretty_xml = '\n'.join(filter(lambda x: x.strip(), xml.toprettyxml(indent=indent).split('\n')[2:-2])) + '\n'
            # revert xml.dom replacings
            # (https://github.com/python/cpython/blob/8e0418688906206fe59bd26344320c0fc026849e/Lib/xml/dom/minidom.py#L305)
            pretty_xml = pretty_xml.replace("&amp;", "&").replace("&lt;", "<").replace("&quot;", "\"", ) \
                .replace("&gt;", ">").replace('&apos;', "'")
            # delete two first spaces of each line
            final_xml = re.sub(fr'^{indent}', '', pretty_xml, flags=re.MULTILINE)
            tmp_file.write(final_xml)
        chmod(tmp_file_path, 0o640)
    except IOError:
        raise WazuhException(1005)
    except ExpatError:
        raise WazuhException(1113)
    except Exception as e:
        raise WazuhException(1000, str(e))

    try:
        # check xml format
        try:
            load_wazuh_xml(tmp_file_path)
        except Exception as e:
            raise WazuhException(1113, str(e))

        # move temporary file to group folder
        try:
            new_conf_path = join(common.ossec_path, path)
            move(tmp_file_path, new_conf_path)
        except Error:
            raise WazuhException(1016)
        except Exception:
            raise WazuhException(1000)

        return 'File updated successfully'

    except Exception as e:
        # remove created temporary file if an exception happens
        remove(tmp_file_path)
        raise e


def upload_list(list_file, path):
    """
    Updates CDB lists
    :param list_file: content of the list
    :param path: Destination of the new list file
    :return: Confirmation message.
    """
    # path of temporary file
    tmp_file_path = '{}/tmp/api_tmp_file_{}_{}.txt'.format(common.ossec_path, time.time(), random.randint(0, 1000))

    try:
        # create temporary file
        with open(tmp_file_path, 'w') as tmp_file:
            # write json in tmp_file_path
            for element in list_file.splitlines():
                # skip empty lines
                if not element:
                    continue
                tmp_file.write(element.strip() + '\n')
        chmod(tmp_file_path, 0o640)
    except IOError:
        raise WazuhException(1005)
    except Exception:
        raise WazuhException(1000)

    # move temporary file to group folder
    try:
        new_conf_path = join(common.ossec_path, path)
        move(tmp_file_path, new_conf_path)
    except Error:
        raise WazuhException(1016)
    except Exception:
        raise WazuhException(1000)

    return 'File updated successfully'


def get_file(path, validation=False):
    """
    Returns the content of a file.
    :param path: Relative path of file from origin
    :return: Content file.
    """

    full_path = join(common.ossec_path, path)

    # validate CDB lists files
    if validation and re.match(r'^etc/lists', path) and not validate_cdb_list(path):
        raise WazuhException(1800, {'path': path})

    # validate XML files
    if validation and not validate_xml(path):
        raise WazuhException(1113)

    try:
        with open(full_path) as f:
            output = f.read()
    except IOError:
        raise WazuhException(1005)

    return output

def validate_xml(path):
    """
    Validates a XML file
    :param path: Relative path of file from origin
    :return: True if XML is OK, False otherwise
    """
    full_path = join(common.ossec_path, path)
    try:
        with open(full_path) as f:
            parseString('<root>' + f.read() + '</root>')
    except IOError:
        raise WazuhException(1005)
    except ExpatError:
        return False

    return True

def validate_cdb_list(path):
    """
    Validates a CDB list
    :param path: Relative path of file from origin
    :return: True if CDB list is OK, False otherwise
    """
    full_path = join(common.ossec_path, path)
    regex_cdb = re.compile(r'^[^:]+:[^:]*$')
    try:
        with open(full_path) as f:
            for line in f:
                # skip empty lines
                if not line.strip():
                    continue
                if not re.match(regex_cdb, line):
                    return False
    except IOError:
        raise WazuhException(1005)

    return True


def delete_file(path):
    """
    Deletes a file.

    Returns a confirmation message if success, otherwise it raises
    a WazuhException
    :param path: Relative path of the file to be deleted
    :return: string Confirmation message
    """
    full_path = join(common.ossec_path, path)

    if exists(full_path):
        try:
            remove(full_path)
        except IOError:
            raise WazuhException(1907)
    else:
        raise WazuhException(1906)

    return 'File was deleted'


def restart():
    """
    Restart Wazuh manager.

    :return: Confirmation message.
    """
    lock_file = open(execq_lockfile, 'a+')
    fcntl.lockf(lock_file, fcntl.LOCK_EX)
    try:
        # execq socket path
        socket_path = common.EXECQ
        # msg for restarting Wazuh manager
        msg = 'restart-wazuh '
        # initialize socket
        if exists(socket_path):
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                conn.connect(socket_path)
            except socket.error:
                raise WazuhException(1902)
        else:
            raise WazuhException(1901)

        try:
            conn.send(msg.encode())
            conn.close()
        except socket.error as e:
            raise WazuhException(1014, str(e))
    finally:
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file.close()

    return "Restarting manager"


def _check_wazuh_xml(files):
    """
    Check Wazuh XML format from a list of files.

    :param files: List of files to check.
    :return: None
    """
    for f in files:
        try:
            subprocess.check_output(['{}/bin/verify-agent-conf'.format(common.ossec_path), '-f', f],
                                    stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            # extract error message from output. Example of raw output 2019/01/08 14:51:09 verify-agent-conf: ERROR:
            # (1230): Invalid element in the configuration: 'agent_conf'.\n2019/01/08 14:51:09 verify-agent-conf:
            # ERROR: (1207): Syscheck remote configuration in
            # '/var/ossec/tmp/api_tmp_file_2019-01-08-01-1546959069.xml' is corrupted.\n\n Example of desired output:
            # Invalid element in the configuration: 'agent_conf'. Syscheck remote configuration in
            # '/var/ossec/tmp/api_tmp_file_2019-01-08-01-1546959069.xml' is corrupted.
            output_regex = re.findall(pattern=r"\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} verify-agent-conf: ERROR: "
                                              r"\(\d+\): ([\w \/ \_ \- \. ' :]+)", string=e.output.decode())
            raise WazuhException(1114, ' '.join(output_regex))
        except Exception as e:
            raise WazuhException(1743, str(e))


def validation():
    """
    Check if Wazuh configuration is OK.

    :return: Confirmation message.
    """
    lock_file = open(execq_lockfile, 'a+')
    fcntl.lockf(lock_file, fcntl.LOCK_EX)
    try:
        # sockets path
        api_socket_path = join(common.ossec_path, 'queue/alerts/execa')
        execq_socket_path = common.EXECQ
        # msg for checking Wazuh configuration
        execq_msg = 'check-manager-configuration '

        # remove api_socket if exists
        try:
            remove(api_socket_path)
        except OSError as e:
            if exists(api_socket_path):
                raise WazuhException(1014, str(e))

        # up API socket
        try:
            api_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            api_socket.bind(api_socket_path)
            # timeout
            api_socket.settimeout(5)
        except socket.error:
            raise WazuhException(1013)

        # connect to execq socket
        if exists(execq_socket_path):
            try:
                execq_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                execq_socket.connect(execq_socket_path)
            except socket.error:
                raise WazuhException(1013)
        else:
            raise WazuhException(1901)

        # send msg to execq socket
        try:
            execq_socket.send(execq_msg.encode())
            execq_socket.close()
        except socket.error as e:
            raise WazuhException(1014, str(e))
        finally:
            execq_socket.close()

        # if api_socket receives a message, configuration is OK
        try:
            buffer = bytearray()
            # receive data
            datagram = api_socket.recv(4096)
            buffer.extend(datagram)
        except socket.timeout as e:
            raise WazuhException(1014, str(e))
        finally:
            api_socket.close()
            # remove api_socket
            if exists(api_socket_path):
                remove(api_socket_path)

        try:
            response = _parse_execd_output(buffer.decode('utf-8').rstrip('\0'))
        except (KeyError, json.decoder.JSONDecodeError) as e:
            raise WazuhException(1904, str(e))
    finally:
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file.close()

    return response


def _parse_execd_output(output: str) -> Dict:
    """
    Parses output from execd socket to fetch log message and remove log date, log daemon, log level, etc.
    :param output: Raw output from execd
    :return: Cleaned log message in a dictionary structure
    """
    json_output = json.loads(output)
    error_flag = json_output['error']
    if error_flag != 0:
        errors = []
        log_lines = json_output['message'].splitlines(keepends=False)
        for line in log_lines:
            match = _re_logtest.match(line)
            if match:
                errors.append(match.group(1))
        errors = list(OrderedDict.fromkeys(errors))
        response = {'status': 'KO', 'details': errors}
    else:
        response = {'status': 'OK'}

    return response


def get_config(component, config):
    """
    Returns active configuration loaded in manager
    """
    return configuration.get_active_configuration(agent_id='000', component=component, configuration=config)
