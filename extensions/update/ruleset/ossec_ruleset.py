#!/usr/bin/env python
# OSSEC Ruleset Installer and Updater

# v2.2 2016/01/27
# Created by Wazuh, Inc. <info@wazuh.com>.
# jesus@wazuh.com
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

# Requirements:
#  Python 2.6 or later
#  OSSEC 2.8 or later
#  root privileges

# Instructions:
#  sudo mkdir /var/ossec/updater/ruleset && cd /var/ossec/updater/ruleset
#  sudo wget https://raw.githubusercontent.com/wazuh/ossec-rules/master/ossec_ruleset.py
#  sudo chmod +x ossec_ruleset.py
#  sudo ./ossec_ruleset.py --help

import os
import sys
import getopt
import shutil
import glob
import re
import fileinput
import signal
from datetime import date
import zipfile
import pwd
import grp
import contextlib
import filecmp
import time
import datetime

try:
    from urllib2 import urlopen, URLError, HTTPError
except:
    # Python 3
    from urllib.request import urlopen


# Log class
class LogFile(object):
    """Print to stdout and file"""

    def __init__(self, name=None, tag="my_log"):
        self.__stdout = True
        self.__log_file = True
        self.__tag = tag
        try:
            self.__logger = open(name, 'a')
        except:
            print("Error opening log '{0}'".format(name))
            sys.exit(2)

    def set_ouput(self, stdout=True, log_file=True):
        self.__stdout = stdout
        self.__log_file = log_file

    def log(self, message):
        self.__write_stdout(message)
        self.__write_log(message)

    def logfile(self, message):
        self.__write_log(message)

    def logstdout(self, message):
        self.__write_stdout(message)

    def __write_stdout(self, message):
        if self.__stdout:
            print(message)

    def __write_log(self, message):
        if self.__log_file:
            timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
            new_msg = re.sub('[\n\t]', '', message)
            log = "{0}:{1}={2}".format(self.__tag, timestamp, new_msg)
            self.__logger.write("{0}\n".format(log))

    def __del__(self):
        self.__logger.close()


# Aux functions

def regex_in_file(regex, filepath):
    with open(filepath) as f:
        m = re.search(regex, f.read())
        if m:
            return True
        else:
            return False


def replace_text_in_file(old_text_init, old_text_end, new_text, filepath):
    replace = False

    f = open(filepath)
    text = f.read()
    f.close()

    if old_text_init in text and old_text_end in text:
        for line in fileinput.input(filepath, inplace=True):
            if old_text_init in line.strip():
                replace = True
            elif old_text_end in line.strip():
                replace = False
                print(new_text)
                continue

            if not replace:
                print(line.rstrip("\n"))
        fileinput.close()

        return True
    else:
        return False


def write_before_line(line_search, new_text, filepath):
    for line in fileinput.input(filepath, inplace=True):
        if line_search in line.strip():
            print(new_text)
        print(line.rstrip("\n"))
    fileinput.close()


def write_after_line(line_search, new_text, filepath):
    for line in fileinput.input(filepath, inplace=True):
        print(line.rstrip("\n"))
        if line_search in line.strip():
            print(new_text)
    fileinput.close()


def swap_lines(line_search_1, line_search_2, filepath):
    """
    Swap lines in file, if line_search1 before line_search2
    :param filepath:
    :param line_search_2:
    :param line_search_1:
    """
    count = 0
    count1 = 0
    count2 = 0
    for line in fileinput.input(filepath):
        count += 1
        if line_search_1.strip() in line.strip():
            count1 = count
        elif line_search_2.strip() in line.strip():
            count2 = count
    fileinput.close()

    if 0 < count1 < count2:
        for line in fileinput.input(filepath, inplace=True):
            if line_search_1.strip() in line.strip():
                print(line_search_2)
            elif line_search_2.strip() in line.strip():
                print(line_search_1)
            else:
                print(line.rstrip("\n"))
        fileinput.close()


def get_previous_line(line_search, filepath):
    previous_line = None
    for line in fileinput.input(filepath):
        if line_search in line.strip():
            break
        previous_line = line
    fileinput.close()
    return previous_line


def remove_line(line_search, filepath):
    for line in fileinput.input(filepath, inplace=True):
        if line_search in line.strip():
            continue
        else:
            print(line.rstrip("\n"))
    fileinput.close()


def signal_handler(n_signal, frame):
    sys.exit(0)


def get_item_between_label(label, filepath):
    f = open(filepath)

    label_s = "<{0}>".format(label)
    label_e = "</{0}>".format(label)
    lines = []
    save_lines = False
    for line in f.readlines():
        if save_lines:
            match = re.search(r'\s*<.+>(.+)</.+>', line)
            if match:
                lines.append(match.group(1))

        if label_s in line:
            save_lines = True
        elif label_e in line:
            break

    f.close()

    return lines


def download_file(url, output_file):
    try:
        f = urlopen(url)

        with open(output_file, "wb") as local_file:
            local_file.write(f.read())

    except HTTPError as e:
        logger.log("\tHTTP Error {0}: {1}".format(e.code, url))
        sys.exit(2)
    except URLError as e:
        logger.log("\tURL Error - {0}: {1}".format(e.reason, url))
        sys.exit(2)
    except Exception as e:
        logger.log("\tDownload Error:{0}.\nExit.".format(e))
        sys.exit(2)


def chown_r(path, uid, gid):
    if os.path.isdir(path):
        os.chown(path, uid, gid)
        for item in os.listdir(path):
            itempath = os.path.join(path, item)
            if os.path.isfile(itempath):
                os.chown(itempath, uid, gid)
            elif os.path.isdir(itempath):
                chown_r(itempath, uid, gid)


def compare_files(file1, file2):
    """
    :param file1: File to be compared
    :param file2: File to be compared
    :return: Return true if file1 is equal to file2, and false otherwise. Also return false if file2 does not exist.
    """
    if os.path.isfile(file1) and os.path.isfile(file2):
        same = filecmp.cmp(file1, file2)
    else:
        same = False

    #  if not same:
    #    print("False: {0} - {1}".format(file1, file2))
    return same


def compare_folders(folder1, folder2, pattern_files):
    """
    :param folder1: Folder to be compared
    :param folder2: Folder to be compared
    :param pattern_files: Unix style pathname pattern
    :return: True when all pattern_files in folder1 exist in folder2 and are equal, false otherwise.
             Also return false if folder2 does not exist.
    Note: This function use global variable 'ossec_version',
    """

    if os.path.exists(folder1) and os.path.exists(folder2):
        pattern_folder1 = "{0}/{1}".format(folder1, pattern_files)
        folder1_files = sorted(glob.glob(pattern_folder1))

        for file_f1 in folder1_files:
            # File 2
            split = file_f1.split("/")
            filename = split[len(split) - 1]
            file_f2 = "{0}/{1}".format(folder2, filename)

            # File 1: Fix for compatibility :(
            if ossec_version == "old" and filename == "openldap_decoders.xml":
                file_f1 = "{0}/compatibility/{1}".format(folder1, filename)

            same = compare_files(file_f1, file_f2)
            if not same:
                break
    else:
        same = False

    return same


# Ruleset functions

def get_ossec_version():
    try:
        ossec_v = "old"
        f_ossec = open("{0}/etc/ossec-init.conf".format(ossec_path))

        for line in f_ossec.readlines():
            if "WAZUH_VERSION" in line:
                ossec_v = line
                break
        f_ossec.close()
    except:
        ossec_v = "old"

    return ossec_v


def get_ruleset_version():
    try:
        f_version = open(version_path)
        rs_version = f_version.read().rstrip('\n')
        f_version.close()
    except:
        rs_version = "0.100"

    return rs_version


def get_ruleset_from_menu(type_ruleset):
    """
    :param type_ruleset: rules, rootchecks, all
    :return: ruleset to install
    """
    directories = []

    ruleset_menu = {"rules": [], "rootchecks": []}

    if type_ruleset == "rules" or type_ruleset == "all":
        directories.append(new_rules_path)
    if type_ruleset == "rootchecks" or type_ruleset == "all":
        directories.append(new_rootchecks_path)

    for directory in directories:
        if not os.path.exists(directory):
            logger.log("\nError: No folder {0}".format(directory))
            sys.exit(2)

        last_path = directory.split("/")[-1]
        if last_path == "rootcheck":
            type_directory = "rootchecks"
        else:
            type_directory = "rules"

        ruleset_select = []

        # Get name of the new rules/rootchecks
        menu_ruleset_dir = ["Select ALL"]
        for name in os.listdir(directory):
            if os.path.isdir(os.path.join(directory, name)):
                menu_ruleset_dir.append(name)

        # OSSEC is already installed -> remove from menu_ruleset
        if "ossec" in menu_ruleset_dir:
            menu_ruleset_dir.remove("ossec")

        str_msg_show = "\nPress any key to show the available {0}...".format(type_directory)
        try:
            raw_input(str_msg_show)
        except:
            # Python 3
            input(str_msg_show)

        title_str = "OSSEC Wazuh Ruleset, {0}\n\nUse ENTER key to select/unselect {1}:\n".format(today_date,
                                                                                                 type_directory)

        menu_ruleset = sorted(menu_ruleset_dir)
        if menu_ruleset:
            toggle = []
            for i in range(len(menu_ruleset)):
                toggle.append(' ')

            read_input = True
            while read_input:
                os.system("clear")
                print(title_str)

                i = 1
                for rule in sorted(menu_ruleset):
                    print("{0}. [{1}] {2}".format(i, toggle[i - 1], rule))
                    i += 1
                print("{0}. Confirm and continue.".format(i))

                str_option = "\nOption [1-{0}]: ".format(i)
                try:
                    ans = raw_input(str_option)
                except:
                    # Python 3
                    ans = input(str_option)
                try:
                    option = int(ans) - 1
                except Exception:
                    continue

                if 0 <= option < len(menu_ruleset):
                    if toggle[option] == "X":
                        toggle[option] = " "
                        if option == 0:  # Unselect ALL
                            for j in range(len(toggle)):
                                toggle[j] = " "
                    else:
                        toggle[option] = "X"
                        if option == 0:  # Select ALL
                            for j in range(len(toggle)):
                                toggle[j] = "X"
                elif option == (i - 1):  # Option Done
                    read_input = False

            for i in range(len(toggle)):
                if toggle[i] == "X":
                    ruleset_select.append(menu_ruleset[i])
            if "Select ALL" in ruleset_select:
                ruleset_select.remove("Select ALL")

            ruleset_menu[type_directory] = ruleset_select

    print("")
    return ruleset_menu


def get_ruleset_from_file(filename, type_r):
    """
    :param filename: File with ruleset to install. Format:
        # comment
        \n
        rules:name_rule
        rootchecks:name_rootcheck
    :param type_r: rules (get rules) rootchecks (get rootchecks)
    :return: ruleset to install
    """

    logger.log("\nReading configuration file '{0}'.".format(filename))

    ruleset_file = {"rules": [], "rootchecks": []}
    rules_file = []
    rootchecks_file = []
    try:
        file_config = open(filename)
        i = 1
        for line in file_config:
            if re.match("(^rootchecks|rules):.+", line) is not None:
                if "rules" in line:
                    rules_file.append(line.split(":")[1].rstrip('\n').strip())
                elif "rootchecks" in line:
                    rootchecks_file.append(line.split(":")[1].rstrip('\n').strip())
            elif re.match("^#.*", line) is not None or re.match("^\s*\n", line) is not None:
                continue
            else:
                logger.log("\tSyntax Error in line [{0}]: ->{1}<-".format(i, line))
                sys.exit(2)
            i += 1
        file_config.close()
    except Exception as e:
        logger.log("\tError reading config file: '{0}'.\nExit.".format(e))
        sys.exit(2)

    if rules_file:
        if "ossec" in rules_file:
            logger.log("\tError reading config file: \"ossec\" item found. \t\tIt is assumed that the default rootchecks are installed.\t\tIf you want to update it, please use the option -u")
            sys.exit(2)

        if not os.path.exists(new_rules_path):
            logger.log("\tError: No folder '{0}' found".format(new_rules_path))
            sys.exit(2)
        new_ruleset = os.listdir(new_rules_path)

        for rs_f in rules_file:
            if rs_f not in new_ruleset:
                logger.log("\tError: '{0}' not in folder '{1}'".format(rs_f, new_rules_path))
                sys.exit(2)

    if rootchecks_file:
        if "ossec" in rootchecks_file:
            logger.log("\tError reading config file: \"ossec\" item found. \t\tIt is assumed that the default rootchecks are installed. \t\tIf you want to update it, please use the option -u")
            sys.exit(2)

        if not os.path.exists(new_rootchecks_path):
            logger.log("\tError: No folder '{0}'".format(new_rootchecks_path))
            sys.exit(2)
        new_ruleset = os.listdir(new_rootchecks_path)

        for rs_f in rootchecks_file:
            if rs_f not in new_ruleset:
                logger.log("\tError: '{0}' not in folder '{1}'".format(rs_f, new_rootchecks_path))
                sys.exit(2)

    if type_r == "rules" or type_r == "all":
        ruleset_file["rules"] = rules_file
    if type_r == "rootchecks" or type_r == "all":
        ruleset_file["rootchecks"] = rootchecks_file

    logger.log("\t[Done]")
    return ruleset_file


def get_ruleset_from_update(type_ruleset):
    ruleset_update = {"rules": [], "rootchecks": []}

    logger.log("\nDownloading new ruleset.")

    # Download new ruleset and extract all files

    output = "{0}/ruleset.zip".format(downloads_directory)

    if not os.path.exists(downloads_directory):
        os.makedirs(downloads_directory)

    download_file(url_ruleset, output)

    old_extracted_files = "{0}/ossec-rules/".format(downloads_directory)
    if os.path.exists(old_extracted_files):
        shutil.rmtree(old_extracted_files)

    try:
        with contextlib.closing(zipfile.ZipFile(output)) as z:
            z.extractall(downloads_directory)
    except Exception as e:
        logger.log("\tError extracting file '{0}': {1}.".format(output, e))
        sys.exit(2)

    # Get ruleset to update
    rules_update = []
    rootchecks_update = []
    global restart_ossec

    if type_ruleset == "rules" or type_ruleset == "all":
        download_rules_path = "{0}/ossec-rules/rules-decoders".format(downloads_directory)
        for new_rule in os.listdir(download_rules_path):
            if new_rule == "ossec":
                download_decoders_dir = "{0}/{1}/decoders".format(download_rules_path, new_rule)
                decoders_dir = "{0}/etc/ossec_decoders".format(ossec_path)
                decoders_equal = compare_folders(download_decoders_dir, decoders_dir, "*_decoders.xml")

                download_rules_dir = "{0}/{1}/rules".format(download_rules_path, new_rule)
                rules_dir = "{0}/rules".format(ossec_path)
                rules_equal = compare_folders(download_rules_dir, rules_dir, "*_rules.xml")

                # print("{0}: d {1} r {2}".format(new_rule, decoders_equal, rules_equal))
                if not decoders_equal or not rules_equal:
                    rules_update.append(new_rule)
                    restart_ossec = True
            else:
                download_decoders_dir = "{0}/{1}/{1}_decoders.xml".format(download_rules_path, new_rule)
                decoders_dir = "{0}/etc/wazuh_decoders/{1}_decoders.xml".format(ossec_path, new_rule)
                decoders_equal = compare_files(download_decoders_dir, decoders_dir)

                download_rules_dir = "{0}/{1}/{1}_rules.xml".format(download_rules_path, new_rule)
                rules_dir = "{0}/rules/{1}_rules.xml".format(ossec_path, new_rule)
                rules_equal = compare_files(download_rules_dir, rules_dir)

                # print("{0}: d {1} r {2}".format(new_rule, decoders_equal, rules_equal))
                if not decoders_equal or not rules_equal:
                    rules_update.append(new_rule)
                    if regex_in_file("\s*<include>{0}_rules.xml</include>".format(new_rule), ossec_conf):
                        restart_ossec = True

    if type_ruleset == "rootchecks" or type_ruleset == "all":
        download_rootchecks_path = "{0}/ossec-rules/rootcheck".format(downloads_directory)
        for new_rc in os.listdir(download_rootchecks_path):
            if new_rc == "ossec":
                download_rootchecks_dir = "{0}/{1}".format(download_rootchecks_path, new_rc)
                rootchecks_dir = "{0}/etc/shared".format(ossec_path)
                rootchecks_equal = compare_folders(download_rootchecks_dir, rootchecks_dir, "*.txt")

                # print("{0}: rc ossec {1} ".format(new_rc, rootchecks_equal))
                if not rootchecks_equal:
                    rootchecks_update.append(new_rc)
                    restart_ossec = True
            else:
                download_rootchecks_dir = "{0}/{1}".format(download_rootchecks_path, new_rc)
                rootchecks_dir = "{0}/etc/shared/{1}".format(ossec_path, new_rc)
                rootchecks_equal = compare_folders(download_rootchecks_dir, rootchecks_dir, "*.*")

                # print("{0}: rc {1} ".format(new_rc, rootchecks_equal))
                if not rootchecks_equal:
                    rootchecks_update.append(new_rc)

                    if regex_in_file("\s*<.+>{0}/.+</.+>".format(rootchecks_dir), ossec_conf):
                        restart_ossec = True

    # Save ruleset
    ruleset_update["rules"] = rules_update
    ruleset_update["rootchecks"] = rootchecks_update

    # Update main directory and remove Downloads
    src_dir = "{0}/ossec-rules/rules-decoders".format(downloads_directory)
    if os.path.exists(new_rules_path):
        shutil.rmtree(new_rules_path)
    shutil.copytree(src_dir, new_rules_path)

    src_dir = "{0}/ossec-rules/rootcheck".format(downloads_directory)
    if os.path.exists(new_rootchecks_path):
        shutil.rmtree(new_rootchecks_path)
    shutil.copytree(src_dir, new_rootchecks_path)

    shutil.copyfile("{0}/ossec-rules/VERSION".format(downloads_directory), version_path)

    new_python_script = "{0}/ossec-rules/ossec_ruleset.py".format(downloads_directory)
    if os.path.isfile(new_python_script):
        shutil.copyfile(new_python_script, script_path)

    if os.path.exists(downloads_directory):
        shutil.rmtree(downloads_directory)

    global ruleset_version
    ruleset_version = get_ruleset_version()

    logger.log("\t[Done]\n")
    return ruleset_update


def setup_wazuh_directory_structure():
    """
    Wazuh Directory Structure:
        <rules>
            <decoder_dir>etc/ossec_decoders</decoder_dir>
            <decoder_dir>etc/wazuh_decoders</decoder_dir>
            <decoder>etc/local_decoder.xml</decoder>
            <!--OSSEC Rules -->
            <include>*_rules.xml</include>
            <!--Wazuh Rules -->
            <include>*_rules.xml</include>
            <!--Local Rules -->
            <include>local_rules.xml</include>
        </rules>
    """

    # Check if decoders in wazuh structure
    try:
        # OSSEC Decoders
        # If exists decoder.xml -> Move to /etc/ossec_decoders
        old_decoder = "{0}/etc/decoder.xml".format(ossec_path)
        des_folder = "{0}/etc/ossec_decoders".format(ossec_path)
        if os.path.exists(old_decoder):
            if not os.path.exists(des_folder):
                os.makedirs(des_folder)
                logger.log("\tNew directory created for OSSEC decoders: '{0}'".format(des_folder))

            dest_file = "{0}/decoder.xml".format(des_folder)
            shutil.move(old_decoder, dest_file)

            chown_r(des_folder, root_uid, ossec_gid)

            logger.log("\t\t'{0}' moved to '{1}'".format(old_decoder, dest_file))

            # Remove <decoder>etc/decoder.xml</decoder> from ossec.conf if exists
            str_default_decoder = "<decoder>etc/decoder.xml</decoder>"
            if regex_in_file(str_default_decoder, ossec_conf):
                remove_line(str_default_decoder, ossec_conf)
                logger.log("\tLine removed in ossec.conf: '{0}'".format(str_default_decoder))
        elif not os.path.exists(des_folder):
            logger.log("\tError: It seems that we could not identify your installation. Install the ruleset manually or contact us for assistance.")
            sys.exit(1)

        str_decoder = "<decoder_dir>etc/ossec_decoders</decoder_dir>"
        if not regex_in_file(str_decoder, ossec_conf):
            write_after_line("<rules>", "    {0}".format(str_decoder), ossec_conf)
            logger.log("\tNew line in ossec.conf: '{0}'".format(str_decoder))

        # Wazuh decoders
        # Create folder for wazuh decoders
        wazuh_decoders = "{0}/etc/wazuh_decoders".format(ossec_path)
        if not os.path.exists(wazuh_decoders):
            os.makedirs(wazuh_decoders)
            chown_r(wazuh_decoders, root_uid, ossec_gid)
            logger.log("\tNew directory created for WAZUH decoders: '{0}'".format(wazuh_decoders))

        str_decoder_wazuh = "<decoder_dir>etc/wazuh_decoders</decoder_dir>"
        if not regex_in_file(str_decoder_wazuh, ossec_conf):
            write_after_line(str_decoder, "    {0}".format(str_decoder_wazuh), ossec_conf)
            logger.log("\tNew line in ossec.conf: '{0}'".format(str_decoder_wazuh))

        # Local decoder
        path_decoder_local = "{0}/etc/local_decoder.xml".format(ossec_path)
        # Create Local Decoder
        if not os.path.exists(path_decoder_local):      # It does not exist
            create_local_decoder = True
        elif os.stat(path_decoder_local).st_size == 0:  # It exists but empty
            create_local_decoder = True
        else:
            create_local_decoder = False                # It exists and not empty

        if create_local_decoder:
            # Create local decoder
            text = ("<!-- Local Decoders -->\n"
                    "<decoder name=\"local_decoder_example\">\n"
                    "    <program_name>local_decoder_example</program_name>\n"
                    "</decoder>\n")
            f_local_decoder = open(path_decoder_local, 'a')
            f_local_decoder.write(text)
            f_local_decoder.close()
            logger.log("\t{0} created".format(path_decoder_local))
            os.chown(path_decoder_local, root_uid, ossec_gid)

        str_decoder_local = "<decoder>etc/local_decoder.xml</decoder>"
        if not regex_in_file(str_decoder_local, ossec_conf):
            write_after_line(str_decoder_wazuh, "    {0}".format(str_decoder_local), ossec_conf)
            logger.log("\tNew line in ossec.conf: '{0}'".format(str_decoder_local))

        # Order check: Local decoder -> decoder_local after decoder_wazuh
        swap_lines("    {0}".format(str_decoder_local), "    {0}".format(str_decoder_wazuh), ossec_conf)

        # Order check: Local rules
        previous_end_rules = get_previous_line("</rules>", ossec_conf)
        local_rules = "<include>local_rules.xml</include>"

        if regex_in_file(local_rules, ossec_conf):
            # local_rules.xml always before "</rules>"
            if local_rules not in previous_end_rules:
                remove_line(local_rules, ossec_conf)
                write_before_line("</rules>", "    {0}".format(local_rules), ossec_conf)
                logger.log("\tChanged line in ossec.conf: '{0}'".format(local_rules))
        else:  # Include local_rules and create local_rules.xml (if necessary)
            text = ("\n"
                    "<group name=\"local,syslog,\">\n"
                    "\n"
                    "    <!--\n"
                    "    Example\n"
                    "    -->\n"
                    "    <rule id=\"100020\" level=\"0\">\n"
                    "        <if_sid>5711</if_sid>\n"
                    "        <user>falSe_User_xyzabc_123987</user>\n"
                    "        <description>Ignore sshd failed logins for this user.</description>\n"
                    "    </rule>\n"
                    "\n"
                    "</group>\n"
                    "\n")
            path_local_rules = "{0}/rules/local_rules.xml".format(ossec_path)

            if not os.path.isfile(path_local_rules):
                f_local_rules = open(path_local_rules, 'a')
                f_local_rules.write(text)
                f_local_rules.close()
                logger.log("\t{0} created".format(path_local_rules))

                os.chown(path_local_rules, root_uid, ossec_gid)

            write_before_line("</rules>", "    {0}".format(local_rules), ossec_conf)
            logger.log("\tNew line in ossec.conf: '{0}'".format(local_rules))

        # OSSEC.CONF
        os.chown(ossec_conf, root_uid, ossec_gid)

    except Exception as e:
        logger.log("\tError checking directory structure: {0}.\n".format(e))
        sys.exit(2)


def setup_decoders(decoder):
    if decoder == "ossec":
        new_decoders_path = "{0}/ossec/decoders/*_decoders.xml".format(new_rules_path)
        ossec_decoders = sorted(glob.glob(new_decoders_path))

        for ossec_decoder in ossec_decoders:
            # Do not copy folders or local_decoder.xml
            if os.path.isfile(ossec_decoder) and "local_decoder.xml" not in ossec_decoder:
                split = ossec_decoder.split("/")
                filename = split[len(split) - 1]
                dest_file = "{0}/etc/ossec_decoders/{1}".format(ossec_path, filename)
                shutil.copyfile(ossec_decoder, dest_file)
                os.chown(dest_file, root_uid, ossec_gid)

        # Remove decoder.xml inside /etc/ossec_decoders if exists
        old_decoder = "{0}/etc/ossec_decoders/decoder.xml".format(ossec_path)
        if os.path.exists(old_decoder):
            os.remove(old_decoder)

    else:
        new_decoder = "{0}/{1}/{1}_decoders.xml".format(new_rules_path, decoder)
        dest_new_decoder = "{0}/etc/wazuh_decoders/{1}_decoders.xml".format(ossec_path, decoder)
        shutil.copyfile(new_decoder, dest_new_decoder)
        os.chown(dest_new_decoder, root_uid, ossec_gid)


def setup_rules(rule):
    if rule == "ossec":
        new_ossec_rules_path = "{0}/ossec/rules/*rules*.xml".format(new_rules_path)
        ossec_rules = sorted(glob.glob(new_ossec_rules_path))

        for ossec_rule in ossec_rules:
            # Do not copy folders or local_rules.xml
            if os.path.isfile(ossec_rule) and "local_rules.xml" not in ossec_rule:
                split = ossec_rule.split("/")
                filename = split[len(split) - 1]
                dest_file = "{0}/rules/{1}".format(ossec_path, filename)
                shutil.copyfile(ossec_rule, dest_file)
                os.chown(dest_file, root_uid, ossec_gid)

    else:
        src_file = "{0}/{1}/{1}_rules.xml".format(new_rules_path, rule)
        dest_file = "{0}/rules/{1}_rules.xml".format(ossec_path, rule)
        shutil.copyfile(src_file, dest_file)
        os.chown(dest_file, root_uid, ossec_gid)


def setup_roochecks(rootcheck):
    src_dir = "{0}/{1}".format(new_rootchecks_path, rootcheck)

    if rootcheck == "ossec":
        for new_ossec_rc in os.listdir(src_dir):
            if os.path.isfile("{0}/{1}".format(src_dir, new_ossec_rc)):
                src_file = "{0}/{1}".format(src_dir, new_ossec_rc)
                dest_file = "{0}/etc/shared/{1}".format(ossec_path, new_ossec_rc)
                shutil.copyfile(src_file, dest_file)
                os.chown(dest_file, root_uid, ossec_gid)
    else:
        dest_dir = "{0}/etc/shared/{1}".format(ossec_path, rootcheck)
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        shutil.copytree(src_dir, dest_dir)
        chown_r(dest_dir, root_uid, ossec_gid)


def setup_ossec_conf(item, type_item):
    # Include Rules & Rootchecks

    # Note: It is assumed that the default rules/rootchecks are included in ossec.conf
    if item == "ossec":
        return

    if type_item == "rule":
        # General
        if not regex_in_file("\s*<include>{0}_rules.xml</include>".format(item), ossec_conf):
            logger.log("\t\tNew rule in ossec.conf: '{0}'.".format(item))
            write_before_line("<include>local_rules.xml</include>", '    <include>{0}_rules.xml</include>'.format(item), ossec_conf)
    elif type_item == "rootcheck":
        types_rc = ["rootkit_files", "rootkit_trojans", "system_audit", "win_applications", "win_audit",
                    "win_malware"]

        dest_dir = "{0}/etc/shared/{1}".format(ossec_path, item)

        for new_rc in os.listdir(dest_dir):
            new_rc = "{0}/{1}".format(dest_dir, new_rc)
            # logger.log("\t\t{0}".format(new_rc))

            rc_include = None
            for type_rc in types_rc:
                if type_rc in new_rc:
                    rc_include = "<{0}>{1}</{0}>".format(type_rc, new_rc)
                    break

            if not rc_include:
                logger.log("\t\tError in file {0}: Wrong filename.".format(new_rc))
                logger.log("\t\tFilename must start with:")
                for t_rc in types_rc:
                    logger.log("\t\t\t{0}".format(t_rc))
                sys.exit(2)

            rc_include_search = "\s*{0}".format(rc_include)
            rc_include_new = "    {0}".format(rc_include)

            if not regex_in_file(rc_include_search, ossec_conf):
                logger.log("\t\tNew rootcheck in ossec.conf: '{0}'.".format(new_rc))
                write_before_line("</rootcheck>", rc_include_new, ossec_conf)

    os.chown(ossec_conf, root_uid, ossec_gid)


def do_backups():

    try:
        # Create folder backups
        if not os.path.exists(bk_directory):
            os.makedirs(bk_directory)

        # Create folder /backups/YYYYMMDD_i
        last_bk = sorted(os.listdir(bk_directory))
        if last_bk:
            i = int(last_bk[-1].split("_")[-1]) + 1
        else:
            i = 0
        bk_subdirectory = "{0}/{1}_{2}".format(bk_directory, today_date, str(i).zfill(2))
        os.makedirs(bk_subdirectory)

        # Backup etc
        src_dir = "{0}/etc".format(ossec_path)
        dest_dir = "{0}/etc".format(bk_subdirectory)
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        shutil.copytree(src_dir, dest_dir)

        # Backup rules
        src_dir = "{0}/rules".format(ossec_path)
        dest_dir = "{0}/rules".format(bk_subdirectory)
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        shutil.copytree(src_dir, dest_dir)

        # Remove old backups
        sub_bk_directories = sorted(os.listdir(bk_directory))
        n_bk = len(sub_bk_directories)

        if n_bk >= MAX_BACKUPS:
            n_remove = n_bk - MAX_BACKUPS
            for old_bk in sub_bk_directories[0:n_remove]:
                path = os.path.join(bk_directory, old_bk)
                shutil.rmtree(path)

    except Exception as e:
        logger.log("Error - Backup:{0}.\nExit.".format(e))
        sys.exit(2)

    return bk_subdirectory


def restore_backups(backup_id):

    if not os.path.exists(bk_directory):
        logger.log("\tNo backups to restore.")
        logger.logfile("Ending ossec_ruleset.py")
        sys.exit()

    if backup_id == "0":
        all_backups = sorted(os.listdir(bk_directory))

        i = 0
        print("\tList of current backups:")
        for subdir_bk in all_backups:
            print("\t\t{0}: {1}".format(i, subdir_bk))
            i += 1
        last_item = i-1

        get_input = True
        str_ans = "\n\tPlease, choose which backup you want to restore [0 - {0}]: ".format(last_item)
        str_error = "\t\tSelect an option between 0 and {0}.".format(last_item)
        while get_input:
            try:
                ans = raw_input(str_ans)
            except:
                # Python 3
                ans = input(str_ans)

            try:
                option = int(ans)
                if 0 <= option <= last_item:
                    get_input = False
                else:
                    print(str_error)
            except ValueError:
                print(str_error)

        bk_restore = all_backups[option]
    else:
        bk_restore_dir = "{0}/{1}".format(bk_directory, backup_id)
        if not os.path.exists(bk_restore_dir):
            logger.log("\tError: No backups with name '{0}'.".format(backup_id))
            sys.exit(2)

        bk_restore = backup_id

    logger.log("\n\tThe backup '{0}' will be restored.".format(bk_restore))

    etc_restore = "{0}/{1}/etc".format(bk_directory, bk_restore)
    rules_restore = "{0}/{1}/rules".format(bk_directory, bk_restore)
    if not os.path.exists(etc_restore) or not os.path.exists(rules_restore):
        logger.log("\t\tError: Folder '{0}' or '{1}' not found.".format(etc_restore, rules_restore))
        sys.exit(2)

    etc_dest = "{0}/etc".format(ossec_path)
    logger.log("\t\tRestoring folder: '{0}' -> '{1}'".format(etc_restore, etc_dest))
    if os.path.exists(etc_dest):
        shutil.rmtree(etc_dest)
    shutil.copytree(etc_restore, etc_dest)
    chown_r(etc_dest, root_uid, ossec_gid)
    logger.log("\t\t\t[Done]")

    rules_dest = "{0}/rules".format(ossec_path)
    logger.log("\t\tRestoring folder: '{0}' -> '{1}'".format(rules_restore, rules_dest))
    if os.path.exists(rules_dest):
        shutil.rmtree(rules_dest)
    shutil.copytree(rules_restore, rules_dest)
    chown_r(rules_dest, root_uid, ossec_gid)
    logger.log("\t\t\t[Done]")


def get_ruleset(type_ruleset, r_action):
    """
    :param type_ruleset: "rules" or "rootchecks"
    :param r_action: "manual", "file:filepath.ext" or "update"
    :return: List of ruleset to install / update
    """
    if r_action == "manual":
        n_ruleset = get_ruleset_from_menu(type_ruleset)
    elif "file:" in r_action:
        filename = r_action.split(":")[1].rstrip('\n')
        n_ruleset = get_ruleset_from_file(filename, type_ruleset)
    elif r_action == "update":
        n_ruleset = get_ruleset_from_update(type_ruleset)
    else:
        n_ruleset = []

    return n_ruleset


def setup_ruleset_r(target_rules, r_action):
    """
    :param r_action: manual, file, update
    :param target_rules: rules to install
    :rtype: list
    """

    str_title = "updated" if r_action == "update" else "installed"

    logger.log("\nThe following rules will be {0}:".format(str_title))
    for rule in target_rules:
        logger.log("\t{0}".format(rule))
    logger.logstdout("")

    instructions = []
    for item in target_rules:
        logger.log("{0}:".format(item))

        # Decoders
        logger.log("\tCopying decoders.")
        setup_decoders(item)
        logger.log("\t\t[Done]")

        # Rules
        logger.log("\tCopying rules.")
        setup_rules(item)
        logger.log("\t\t[Done]")

        # ossec.conf
        if r_action != "update":
            logger.log("\tActivating rules in ossec.conf.")
            setup_ossec_conf(item, "rule")
            logger.log("\t\t[Done]")
        # special case: update auditd
        if r_action == "update" and item == "ossec":
            if not regex_in_file("\s*<include>auditd_rules.xml</include>", "{0}/etc/ossec.conf".format(ossec_path)):
                logger.log("\tActivating rules in ossec.conf.")
                setup_ossec_conf("auditd", "rule")
                logger.log("\t\t[Done]")

        # Info
        if r_action != "update":
            if item == "puppet":
                msg = "The rules of Puppet are installed but you need to perform a manual step. You will find detailed information in file \"./rules-decoders/puppet/puppet_instructions.md\""
                logger.log("\t**Manual steps**:\n\t\t{0}".format(msg))
                instructions.append("{0}: {1}".format(item, msg))

    return instructions


def setup_ruleset_rc(target_rootchecks, r_action):
    """
    :param r_action: manual, file, update
    :param target_rootchecks: rootchecks to install
    Important: Filenames must contain the following strings at the beginning:
        rootkit_files
        rootkit_trojans
        system_audit
        win_applications
        win_audit
        win_malware

        *except for default ossec rootchecks
    """

    str_title = "updated" if r_action == "update" else "installed"
    logger.log("\nThe following rootchecks will be {0}:".format(str_title))
    for t_rootcheck in target_rootchecks:
        logger.log("\t{0}".format(t_rootcheck))
    logger.logstdout("")

    for item in target_rootchecks:
        logger.log("{0}:".format(item))

        # Rootchecks
        logger.log("\tCopying rootchecks.")
        setup_roochecks(item)
        logger.log("\t\t[Done]")

        # ossec.conf
        if r_action != "update":
            logger.log("\tActivating rootchecks in ossec.conf.")
            setup_ossec_conf(item, "rootcheck")
            logger.log("\t\t[Done]")


def compatibility_with_old_versions():

    # OpenLDAP
    # Old decoders have not <accumulate> tag
    src_file = "{0}/ossec/decoders/compatibility/openldap_decoders.xml".format(new_rules_path)
    dest_file = "{0}/etc/ossec_decoders/openldap_decoders.xml".format(ossec_path)
    shutil.copyfile(src_file, dest_file)


# Main

def usage():
    msg = """
OSSEC Wazuh Ruleset installer & updater v2.2
Github repository: https://github.com/wazuh/ossec-rules
Full documentation: http://documentation.wazuh.com/en/latest/ossec_ruleset.html

Usage: ./ossec_ruleset.py -r [-u | -f conf.txt] [-s] # Rules
       ./ossec_ruleset.py -c [-u | -f conf.txt] [-s] # Rootchecks
       ./ossec_ruleset.py -a [-u | -f conf.txt] [-s] # All: Rules & Rootchecks
       ./ossec_ruleset.py -b [list | backup_name]    # Restore backup

Select ruleset:
\t-r, --rules
\t-c, --rootchecks
\t-a, --all

Select action:
\tno arguments\tInteractive menu for selection of rules and rootchecks to install.
\t-f, --file\tUse a configuration file to select rules and rootchecks to install.
\t-u, --update\tUpdate existing ruleset.

Aditional params:
\t-s, --silent\tForce OSSEC restart when required.
\t-b, --backups\tRestore backups. Use 'list' to show the backups list available.

Configuration file syntax using option -f:
\t# Commented line
\trules:new_rule_name
\trootchecks:new_rootcheck_name

##############################################################################################
Examples:
Manually choose rules to install: ./ossec_ruleset.py -r
Update rules: ./ossec_ruleset.py -r -u
Use a configuration file to select rules to install: ./ossec_ruleset.py -r -f new_rules.conf
\tnew_rules.conf content example:\n\trules:puppet\n\trules:netscaler

Show backups list and select backup to restore: ./ossec_ruleset.py -b list
Restore a specific backup: ./ossec_ruleset.py -b 20151203_00
##############################################################################################
"""
    print(msg)


if __name__ == "__main__":
    # Config
    MAX_BACKUPS = 50
    url_ruleset = "http://ossec.wazuh.com/ruleset/ruleset.zip"
    # url_ruleset = "http://ossec.wazuh.com/ruleset/ruleset_development.zip"

    # Vars
    ossec_path = "/var/ossec"
    ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)
    updater_path = "{0}/update/ruleset".format(ossec_path)
    # updater_path = "."
    bk_directory = "{0}/backups".format(updater_path)
    log_path = "{0}/ossec_ruleset.log".format(updater_path)
    version_path = "{0}/VERSION".format(updater_path)
    script_path = "{0}/ossec_ruleset.py".format(updater_path)
    new_rules_path = "{0}/rules-decoders".format(updater_path)
    new_rootchecks_path = "{0}/rootcheck".format(updater_path)
    downloads_directory = "{0}/downloads".format(updater_path)
    today_date = date.today().strftime('%Y%m%d')
    ruleset_version = "0.100"  # Default
    ruleset_type = ""
    action = "manual"
    manual_steps = []
    silent = False
    mandatory_args = 0
    restart_ossec = False
    backups = False

    # Capture Cntrl + C
    signal.signal(signal.SIGINT, signal_handler)

    # Check sudo
    if os.geteuid() != 0:
        print("You need root privileges to run this script. Please try again, using 'sudo'. Exiting.")
        sys.exit()

    # Check arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "rcauhsb:f:",
                                   ["rules", "rootchecks", "all", "update", "help", "silent", "backups=", "file="])
        if not opts or not (1 <= len(opts) <= 3):
            print("Incorrect number of arguments. Expected 1 or 2 arguments.\nTry './ossec_ruleset.py --help' for more information.")
            sys.exit()
    except getopt.GetoptError as err:
        print(str(err))
        print("Try './ossec_ruleset.py --help' for more information.")
        sys.exit(2)

    for o, a in opts:
        if o in ("-r", "--rules"):
            ruleset_type = "rules"
            mandatory_args += 1
        elif o in ("-c", "--rootchecks"):
            ruleset_type = "rootchecks"
            mandatory_args += 1
        elif o in ("-a", "--all"):
            ruleset_type = "all"
            mandatory_args += 1
        elif o in ("-u", "--update"):
            action = "update"
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-s", "--silent"):
            silent = True
        elif o in ("-b", "--backups"):
            backups = True
            action = a
            mandatory_args += 1
        elif o in ("-f", "--file"):
            action = "file:{0}".format(a)
        else:
            usage()
            sys.exit()

    if backups and not (len(opts) == 1 or silent):
        print("Try with: ./ossec_ruleset.py -b list or ./ossec_ruleset.py -b backup_name")
        print("Try './ossec_ruleset.py --help' for more information.")
        sys.exit()

    if mandatory_args != 1:
        print("Mandatory arguments: -r | -c | -a | -b")
        usage()
        sys.exit()

    str_mode = "updated" if action == "update" else "installed"

    # Create folder updater_path
    if not os.path.exists(updater_path):
        os.makedirs(updater_path)

    # Log
    logger = LogFile(log_path, "wazuh_ossec_ruleset")

    logger.logfile("Starting ossec_ruleset.py")

    # Get uid:gid = root:ossec
    try:
        root_uid = pwd.getpwnam("root").pw_uid
        ossec_gid = grp.getgrnam("ossec").gr_gid
    except:
        logger.log("Error: No user 'root' or group 'ossec' found.")
        sys.exit(2)

    # Get ruleset version from file VERSION
    ruleset_version = get_ruleset_version()

    # Get OSSEC Version
    ossec_version = get_ossec_version()

    # Restart ossec when install ruleset.
    # When it is an update -> restart_ossec is changed in get_rulset_from_update()
    if action != "update":
        restart_ossec = True

    # Title
    logger.log("\nOSSEC Wazuh Ruleset [{0}], {1}\n".format(ruleset_version, today_date))
    logger.log("Note: All necessary files will be saved at '{0}'".format(updater_path))

    # Backups
    logger.log("\nCreating a backup for folders '{0}/etc' and '{0}/rules'.".format(ossec_path))
    dir_bk = do_backups()
    logger.log("\tBackup folder: {0}\n\t[Done]".format(dir_bk))

    # Restore backups
    if backups:
        logger.log("\nRestore Tool:")
        if action != "list":
            restore_backups(action)
        else:
            restore_backups("0")
        logger.log("\t[Done]")
    else:
        # Setup Wazuh structure: /etc/ossec_decoders/, /etc/wazuh_decoders/, /etc/local_decoders.xml
        logger.log("\nChecking directory structure.")
        setup_wazuh_directory_structure()
        logger.log("\t[Done]")

        # Get new ruleset
        if ruleset_type != "all":
            ruleset = get_ruleset(ruleset_type, action)[ruleset_type]

            if not ruleset:
                logger.log("\nNo new {0} to be {1}.".format(ruleset_type, str_mode))
                logger.logfile("Ending ossec_ruleset.py")
                sys.exit()
        else:
            ruleset = get_ruleset("all", action)
            rules = ruleset["rules"]
            rootchecks = ruleset["rootchecks"]

            if not rules:
                logger.log("\nNo new rules to be {0}.".format(str_mode))
            if not rootchecks:
                logger.log("\nNo new rootchecks to be {0}.".format(str_mode))

            if not rules and not rootchecks:
                logger.logfile("Ending ossec_ruleset.py")
                sys.exit()

        # Setup ruleset
        if ruleset_type == "all":
            if rules:
                manual_steps = setup_ruleset_r(rules, action)
            if rootchecks:
                setup_ruleset_rc(rootchecks, action)
        elif ruleset_type == "rules":
            manual_steps = setup_ruleset_r(ruleset, action)
        elif ruleset_type == "rootchecks":
            setup_ruleset_rc(ruleset, action)

        # PATCH for OSSEC != Wazuh
        if ossec_version == "old" and action == "update" and ruleset_type != "rootchecks":
            compatibility_with_old_versions()

    # Restart ossec
    if restart_ossec:
        if not silent:
            logger.log("\nOSSEC requires a restart to apply changes.")
            str_msg = "Do you want to restart OSSEC now? [y/N]: "
            try:
                ans_restart = raw_input(str_msg)
            except:
                # Python 3
                ans_restart = input(str_msg)
        else:
            ans_restart = "y"
    else:
        ans_restart = "n"

    # Messages
    ret = 0
    if backups:
        success_msg = "\n\n**Backup successfully**"
    else:
        success_msg = "\n\n**Ruleset({0}) {1} successfully**".format(ruleset_version, str_mode)

    if ans_restart == "y" or ans_restart == "Y":
        logger.log("\nRestarting OSSEC.")
        ret = os.system("{0}/bin/ossec-control restart".format(ossec_path))
        if ret != 0:
            logger.log("\n**Something went wrong**")
            logger.log("Please check your config. logtest can be useful: {0}/bin/ossec-logtest".format(ossec_path))
            logger.log("\n\n**Ruleset error**")
        else:
            logger.log(success_msg)
    else:
        if restart_ossec:
            logger.log("\nDo not forget to restart OSSEC to apply changes.")
        logger.log(success_msg)

    if manual_steps:
        logger.log("\nDo not forget the manual steps:")
        for step in manual_steps:
            logger.log("\t{0}".format(step))

    logger.log("\n\nWazuh.com")
    logger.logfile("Ending ossec_ruleset.py")
