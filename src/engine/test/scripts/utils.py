#!/usr/bin/python

import platform    # For getting the operating system name
import os, sys, stat
import random
import string
import datetime
import shutil
import xml.etree.ElementTree as ET
from subprocess import Popen, PIPE, check_call, check_output, call, DEVNULL
from typing import Any, List, Set
from time import sleep
import json

WAZUH_PATH = os.path.join('/','Library', 'Ossec') if platform.system() == "Darwin" else os.path.join('/', 'var', 'ossec')

WAZUH_BIN = os.path.join(WAZUH_PATH, 'bin')
WAZUH_CONF = os.path.join(WAZUH_PATH, 'etc', 'ossec.conf')
WIN_WAZUH_PATH = os.path.join('C:','Program Files (x86)','ossec-agent')
WIN_WAZUH_CONF = os.path.join(WIN_WAZUH_PATH, 'ossec.conf')
WAZUH_SOURCES = os.path.join('/', 'wazuh')
WAZUH_SOURCE_REPOSITORY = 'https://github.com/wazuh/wazuh.git'
GEN_OSSEC = os.path.join(WAZUH_SOURCES, 'gen_ossec.sh')
DEVNULL = open(os.devnull, 'w')

stat_modes = [
  stat.S_ISUID,
  stat.S_ISGID,
  stat.S_ENFMT,
  stat.S_ISVTX,
  stat.S_IREAD,
  stat.S_IWRITE,
  stat.S_IEXEC,
  stat.S_IRWXU,
  stat.S_IRUSR,
  stat.S_IWUSR,
  stat.S_IXUSR,
  stat.S_IRWXG,
  stat.S_IRGRP,
  stat.S_IWGRP,
  stat.S_IXGRP,
  stat.S_IRWXO,
  stat.S_IROTH,
  stat.S_IWOTH,
  stat.S_IXOTH
]

log_examples = [
    'Aug 14 10:15:25 junction.example.com smtpd[28882]: smtp-in: Failed command on session 1f55bdcdf16e28a3: "MAIL FROM:<root@junction.example.com>  " => 421 4.3.0: Temporary Error\n',
    'date=2016-06-15 time=10:42:31 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=event subtype=vpn level=error vd="root" logdesc="IPsec DPD failed" msg="IPsec DPD failure" action=dpd remip=1.2.3.4 locip=4.3.2.1 remport=500 locport=500 outintf="wan1" cookies="fsdagfdfgfdgfdg/qwerweafasfefsd" user="N/A" group="N/A" xauthuser="N/A" xauthgroup="N/A" assignip=N/A vpntunnel="BW" status=dpd_failure\n',
    '2018 Dec 05 08:22:48 WinEvtLog: System: INFORMATION(104): Microsoft-Windows-Eventlog: joesmith: ABCNET: Samuel.abcnet.org: The Microsoft-Windows-IdCtrls/Operational log file was cleared.\n',
    'Nov 22 14:33:52 2019 : grg121 : HOST=archlinux : TTY=pts/6 ; PWD=/home/grg121 ; USER=root ; COMMAND=/usr/bin/su\n'
]


def wait_for_messages_at(log_file, expected_messages, timeout=10000):
    """
    Parse <log_file> until <expected_message> is present,
    blocking the execution of the script meanwhile
    <timeout> in seconds to stop if the target is no reachable
    """

    with open(log_file) as f:

        start_time = datetime.datetime.now()
        end_time = start_time + datetime.timedelta(seconds=timeout)

        print(f"Waiting for messages: {expected_messages}")

        f.seek(0,2)
        founds = False

        while not founds and datetime.datetime.now() < end_time:
            line = f.readline()
            if not line:
                continue
            for message in expected_messages:
                if message in line:
                    expected_messages.remove(message)
                    print(f"Waiting for messages: {expected_messages}")

            if len(expected_messages) == 0:
                founds = True

            sleep(1)

def random_string(lenght=12):
  return ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k = lenght))


def write_random_data(filename, size=200):
  with open(filename, 'a') as f:
    random_data = random_string(size)
    f.write(random_data)


def overwrite_file(filename, size=200):
  write_random_data("tmp")
  shutil.copy("tmp", filename)


def write_logs_to_file(filename, size, mode='w', as_json=False):
    """
    Add big random letters/alphabets to a file
    :param filename: the filename
    :param size: the size in bytes
    :param mode: append/write (a/w)
    :return: void
    """

    if(as_json):
        data = '{"timestamp":"2016-05-02T17:46:48.515262+0000","flow_id":1234,"in_iface":"eth0","event_type":"alert","src_ip":"16.10.10.10","src_port":5555,"dest_ip":"16.10.10.11","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2019236,"rev":3,"signature":"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Version Number","category":"Attempted Administrator Privilege Gain","severity":1},"payload":"abcde","payload_printable":"hi test","stream":0,"host":"suricata.com"}'
    else:
        data = ""
        for i in range(size):
            data += log_examples[i % len(log_examples)]

    with open(filename, mode) as f:
        f.write(data)


def random_file_mode(filename):
  os.chmod(filename, random.choice(stat_modes))


def random_owner(filename):
  os.chown(filename, random.randint(1000,1050),random.randint(1000,1050))


def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower()=='windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]

    return call(command,  stdout=DEVNULL, stderr=DEVNULL) == 0


def indent(elem, level=0):
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i


def restart_wazuh():
    """
    Restart Wazuh service.
    """
    if sys.platform == 'win32':
        os.system('net stop wazuh')
        os.system('net start wazuh')
    else:
        command = os.path.join(WAZUH_PATH, 'bin/wazuh-control')
        arguments = ['restart']
        check_call([command] + arguments, stdout=DEVNULL, stderr=DEVNULL)


def stop_wazuh():
    """
    Stop Wazuh service.
    """
    if sys.platform == 'win32':
        os.system('net stop wazuh')
    else:
        command = os.path.join(WAZUH_PATH, 'bin/wazuh-control')
        arguments = ['stop']
        check_call([command] + arguments, stdout=DEVNULL, stderr=DEVNULL)


def write_wazuh_conf(wazuh_conf: ET.ElementTree):
    """
    Write a new configuration in 'ossec.conf' file.
    """
    dest_file = WIN_WAZUH_CONF if sys.platform == 'Win32' else WAZUH_CONF
    return wazuh_conf.write(dest_file, encoding='utf-8')



def get_wazuh_conf() -> ET.ElementTree:
    """
    Get current 'ossec.conf' file.
    :return: ElemenTree with current Wazuh configuration
    """
    conf_file = WIN_WAZUH_CONF if sys.platform == 'Win32' else WAZUH_CONF
    return ET.parse(conf_file)


def clean_section_wazuh_conf(section: str) -> ET.ElementTree:
    """
    Clean all the configuration blocks refered to the selected section on wazuh conf
    :param section: Section of Wazuh configuration to replace
    """

    # get Wazuh configuration
    wazuh_conf = get_wazuh_conf()

    root = wazuh_conf.getroot()

    # clean section if exists

    for section_conf in root.findall(section):
        root.remove(section_conf)

    indent(root)

    write_wazuh_conf(wazuh_conf)


def set_section_wazuh_conf(wazuh_conf: ET.ElementTree, section: str,
                           new_elements: List = None) -> ET.ElementTree:
    """
    Set a configuration in a section of Wazuh. It replaces the content if it exists.
    :param wazuh_conf: ElementTree with the base wazuh conf to add section options
    :param section: Section of Wazuh configuration to replace
    :param new_elements: List with dictionaries for settings elements in the section
    :return: ElementTree with the custom Wazuh configuration
    """
    def create_elements(section: ET.Element, elements: List):
        """
        Insert new elements in a Wazuh configuration section.
        :param section: Section where the element will be inserted
        :param elements: List with the new elements to be inserted
        """

        for element in elements:
            for tag_name, properties in element.items():
                tag = ET.SubElement(section, tag_name)
                new_elements = properties.get('elements')
                if new_elements:
                    create_elements(tag, new_elements)
                else:
                    tag.text = properties.get('value')
                    attributes = properties.get('attributes')
                    if attributes is not None:
                        for attribute in attributes:
                            if isinstance(attribute, dict):
                                tag.attrib = { **tag.attrib, **attribute }

    root = wazuh_conf.getroot()

    section_conf = ET.SubElement(wazuh_conf.getroot(), section)

    # insert elements
    if new_elements is not None:
        create_elements(section_conf, new_elements)

    indent(root)

    return wazuh_conf
