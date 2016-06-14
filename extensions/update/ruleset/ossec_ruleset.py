#!/usr/bin/env python
# OSSEC Ruleset Update

# v2.3.1 2016/04/05
# Created by Wazuh, Inc. <info@wazuh.com>.
# jesus@wazuh.com
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

# Requirements:
#  Python 2.6 or later
#  OSSEC 2.8 or later
#  root privileges

# Instructions:
#  http://wazuh-documentation.readthedocs.org/en/latest/ossec_ruleset.html#automatic-installation

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

    def __init__(self, name=None, tag="my_log"):
        self.__stdout = True
        self.__file = True
        self.__debug_mode = False
        self.__tag = tag

        try:
            self.__logger = open(name, 'a')
        except:
            print("Error opening log '{0}'".format(name))
            sys.exit(2)

    def set_ouput(self, log_stdout=True, log_file=True, log_debug=False):
        self.__stdout = log_stdout
        self.__file = log_file
        self.__debug_mode = log_debug

    def set_debug(self, debug_mode):
        self.__debug_mode = debug_mode

    def log(self, message):
        """
        Print to STDOUT and FILE
        :param message: text
        """
        self.__write_stdout(message)
        self.__write_file(message)

    def file(self, message):
        self.__write_file(message)

    def stdout(self, message):
        self.__write_stdout(message)

    def debug(self, message):
        if self.__debug_mode:
            count_init = 0
            char_init = ""

            try:
                if message[0] == '\t' or message[0] == '\n':
                    special_char = message[0]

                    for c in message:
                        if c == special_char:
                            count_init += 1
                        else:
                            break
                    char_init = special_char * count_init
            except:
                char_init = ""

            print("{0}Debug: {1}".format(char_init, message[count_init:]))

    def __write_stdout(self, message):
        if self.__stdout:
            print(message)

    def __write_file(self, message):
        if self.__file:
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


def get_stdin(msg):
    try:
        stdin = raw_input(msg)
    except:
        # Python 3
        stdin = input(msg)
    return stdin


# Ruleset functions


def signal_handler(n_signal, frame):
    sys.exit(0)


def get_ossec_version():
    try:
        ossec_v = "old"
        f_ossec = open("{0}/etc/ossec-init.conf".format(ossec_path))

        for line in f_ossec.readlines():
            if "WAZUH_VERSION" in line:
                ossec_v = line.strip("\n")
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


def do_backups():

    try:
        # Create folder backups
        if not os.path.exists(bk_directory):
            os.makedirs(bk_directory)

        # # Create folder /backups/YYYYMMDD_i
        sub_bk_directories = sorted(os.listdir(bk_directory))
        if "old" in sub_bk_directories:
            sub_bk_directories.remove("old")

        if len(sub_bk_directories) >= MAX_BACKUPS:
            logger.log("\tLimit of backups ({0}) reached. Removing old backups.".format(MAX_BACKUPS))
            for old_bk in sub_bk_directories[0:-1]:
                path = os.path.join(bk_directory, old_bk)
                shutil.rmtree(path)

            bk_old = "{0}/{1}".format(bk_directory, "old")
            if os.path.exists(bk_old):
                shutil.rmtree(bk_old)
            os.makedirs(bk_old)

            path_last_bk = "{0}/{1}".format(bk_directory, sub_bk_directories[-1])
            new_path_lat_bk = "{0}/{1}".format(bk_old, sub_bk_directories[-1])
            logger.log("\tMoving last backup: {0} -> old/{0}".format(sub_bk_directories[-1]))
            shutil.move(path_last_bk, new_path_lat_bk)

            i = 1  # Reset
        else:
            if sub_bk_directories:
                i = int(sub_bk_directories[-1].split("_")[-1]) + 1  # Next
            else:
                i = 1  # First

        bk_subdirectory = "{0}/{1}_{2}".format(bk_directory, today_date, str(i).zfill(3))
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

    except Exception as e:
        logger.log("Error - Backup:{0}.\nExit.".format(e))
        sys.exit(2)

    return bk_subdirectory


def restore_backups(backup_id):

    if not os.path.exists(bk_directory):
        logger.log("\tNo backups to restore.")
        logger.file("Ending ossec_ruleset.py")
        sys.exit()

    if backup_id == "0":
        all_backups = sorted(os.listdir(bk_directory))

        i = 0
        print("\tList of current backups:")
        for subdir_bk in all_backups:
            print("\t\t{0}: {1}".format(i, subdir_bk))
            i += 1
        last_item = i - 1

        get_input = True
        str_ans = "\n\tPlease, choose which backup you want to restore [0 - {0}]: ".format(last_item)
        str_error = "\t\tSelect an option between 0 and {0}.".format(last_item)
        while get_input:
            ans = get_stdin(str_ans)
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

        # Remove etc/shared/ssh (old version of ssh rootcheck)
        old_ssh_rootcheck = "{0}/etc/shared/ssh".format(ossec_path)
        if os.path.exists(old_ssh_rootcheck):
            shutil.rmtree(old_ssh_rootcheck)

        # OSSEC.CONF
        os.chown(ossec_conf, root_uid, ossec_gid)

    except Exception as e:
        logger.log("\tError checking directory structure: {0}.\n".format(e))
        sys.exit(2)


def download_ruleset():
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

    # Update main directory
    shutil.copyfile("{0}/ossec-rules/VERSION".format(downloads_directory), version_path)

    new_python_script = "{0}/ossec-rules/ossec_ruleset.py".format(downloads_directory)
    if os.path.isfile(new_python_script):
        shutil.copyfile(new_python_script, script_path)

    global ruleset_version
    ruleset_version = get_ruleset_version()


def copy_ruleset(directory):
    # New ruleset
    if not os.path.exists(directory):
        logger.log("Error - Directory doest not exist: '{0}'.\nExit.".format(directory))
        sys.exit(2)

    old_extracted_files = "{0}/ossec-rules/".format(downloads_directory)
    if os.path.exists(old_extracted_files):
        shutil.rmtree(old_extracted_files)

    # Copy to downloads directory
    if not os.path.exists(downloads_directory):
        os.makedirs(downloads_directory)

    shutil.copytree(directory, "{0}/ossec-rules".format(downloads_directory))

    # Check new ruleset
    check_files = ["rootcheck", "rules-decoders", "VERSION"]
    for cf in check_files:
        if not os.path.exists("{0}/ossec-rules/{1}".format(downloads_directory, cf)):
            logger.log("Error - '{0}' doest not exist at '{1}'.\nExit.".format(cf, directory))
            sys.exit(2)

    # Update main directory
    shutil.copyfile("{0}/ossec-rules/VERSION".format(downloads_directory), version_path)

    new_python_script = "{0}/ossec-rules/ossec_ruleset.py".format(downloads_directory)
    if os.path.isfile(new_python_script):
        shutil.copyfile(new_python_script, script_path)

    global ruleset_version
    ruleset_version = get_ruleset_version()


def get_ruleset_to_update(no_checks=False):
    ruleset_update = {"rules": [], "rootchecks": []}
    rules_update = []
    rootchecks_update = []
    global restart_ossec

    if type_ruleset == "rules" or type_ruleset == "all":

        if not os.path.exists(new_rules_path):
            logger.log("\tError: No rules found. Maybe failed download.")
            sys.exit(2)

        for new_rule in os.listdir(new_rules_path):
            if no_checks:
                rules_update.append(new_rule)
            else:  # Compare: New / Changed files
                if new_rule == "ossec":
                    new_decoders_dir = "{0}/{1}/decoders".format(new_rules_path, new_rule)
                    decoders_dir = "{0}/etc/ossec_decoders".format(ossec_path)
                    decoders_equal = compare_folders(new_decoders_dir, decoders_dir, "*_decoders.xml")

                    new_rules_dir = "{0}/{1}/rules".format(new_rules_path, new_rule)
                    rules_dir = "{0}/rules".format(ossec_path)
                    rules_equal = compare_folders(new_rules_dir, rules_dir, "*_rules.xml")

                    logger.debug("\tRule '{0}': DecoderOK: {1} | RulesOK: {2}".format(new_rule, decoders_equal, rules_equal))
                    if not decoders_equal or not rules_equal:
                        rules_update.append(new_rule)
                        restart_ossec = True
                        logger.debug("\t\tAdding rule '{0}'. *Restart OSSEC*".format(new_rule))
                else:
                    new_decoders_dir = "{0}/{1}/{1}_decoders.xml".format(new_rules_path, new_rule)
                    decoders_dir = "{0}/etc/wazuh_decoders/{1}_decoders.xml".format(ossec_path, new_rule)
                    decoders_equal = compare_files(new_decoders_dir, decoders_dir)

                    new_rules_dir = "{0}/{1}/{1}_rules.xml".format(new_rules_path, new_rule)
                    rules_dir = "{0}/rules/{1}_rules.xml".format(ossec_path, new_rule)
                    rules_equal = compare_files(new_rules_dir, rules_dir)

                    logger.debug("\tRule '{0}': DecoderOK: {1} | RulesOK: {2}".format(new_rule, decoders_equal, rules_equal))
                    if not decoders_equal or not rules_equal:
                        rules_update.append(new_rule)
                        if regex_in_file("\s*<include>{0}_rules.xml</include>".format(new_rule), ossec_conf):
                            restart_ossec = True
                            logger.debug("\t\tAdding rule '{0}'. *Restart OSSEC*".format(new_rule))

    if type_ruleset == "rootchecks" or type_ruleset == "all":

        if not os.path.exists(new_rootchecks_path):
            logger.log("\tError: No rootchecks found. Maybe failed download.")
            sys.exit(2)

        for new_rc in os.listdir(new_rootchecks_path):
            if no_checks:
                rootchecks_update.append(new_rc)
            else:  # Compare: New / Changed files
                new_rootchecks_file = "{0}/{1}".format(new_rootchecks_path, new_rc)
                rootchecks_file = "{0}/etc/shared/{1}".format(ossec_path, new_rc)
                rootchecks_equal = compare_files(new_rootchecks_file, rootchecks_file)

                if not rootchecks_equal:
                    rootchecks_update.append(new_rc)
                    if regex_in_file("\s*<.+>{0}</.+>".format(rootchecks_file), ossec_conf):
                        restart_ossec = True
                        logger.debug("\t\tAdding rootcheck '{0}'. *Restart OSSEC*".format(new_rc))

    # Save ruleset
    ruleset_update["rules"] = sorted(rules_update)
    ruleset_update["rootchecks"] = sorted(rootchecks_update)

    return ruleset_update


def activate_from_menu(ruleset_show):
    update_ruleset = {'rules': [], 'rootchecks': []}

    for type_r in ruleset_show:
        if ruleset_show[type_r] and (type_ruleset == type_r or type_ruleset == "all"):

            menu = sorted(ruleset_show[type_r])
            if "ossec" in menu:
                menu.remove("ossec")
            menu.insert(0, "Select ALL")

            get_stdin("\nPress any key to show the {0} to activate...".format(type_r))

            title_str = "OSSEC Wazuh Ruleset, {0}\n\nSelect {1} to activate.\nUse ENTER key to select/unselect {1}:\n".format(today_date, type_r)

            toggle = []
            for i in range(len(menu)):
                toggle.append(' ')

            read_input = True
            while read_input:
                os.system("clear")
                print(title_str)

                i = 1
                for rule in sorted(menu):
                    print("{0}. [{1}] {2}".format(i, toggle[i - 1], rule))
                    i += 1
                print("{0}. Confirm and continue.".format(i))

                ans = get_stdin("\nOption [1-{0}]: ".format(i))

                try:
                    option = int(ans) - 1
                except Exception:
                    continue

                if 0 <= option < len(menu):
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
                    update_ruleset[type_r].append(menu[i])
            if "Select ALL" in update_ruleset[type_r]:
                update_ruleset[type_r].remove("Select ALL")

    return update_ruleset


def activate_from_file(new_ruleset):
    update_ruleset = {'rules': [], 'rootchecks': []}

    if new_ruleset['rules'] or new_ruleset['rootchecks']:
        logger.log("\nReading configuration file '{0}'.".format(activate_file))

        rules_file = []
        rootchecks_file = []
        try:
            file_config = open(activate_file)
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
                    logger.log("\tSyntax Error in line [{0}]: ->{1}<-".format(i, line.rstrip("\n")))
                    sys.exit(2)
                i += 1
            file_config.close()
        except Exception as e:
            logger.log("\tError reading config file: '{0}'.\nExit.".format(e))
            sys.exit(2)

        for rule_file in rules_file:
            for rule in new_ruleset['rules']:
                if rule_file == rule:
                    update_ruleset['rules'].append(rule_file)

        for rootcheck_file in rootchecks_file:
            for rootcheck in new_ruleset['rootchecks']:
                if rootcheck_file == rootcheck:
                    update_ruleset['rootchecks'].append(rootcheck_file)

        logger.log("\t[Done]")

    return update_ruleset


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
    new_rootcheck = "{0}/{1}".format(new_rootchecks_path, rootcheck)
    old_rootcheck = "{0}/etc/shared/{1}".format(ossec_path, rootcheck)
    shutil.copyfile(new_rootcheck, old_rootcheck)
    os.chown(old_rootcheck, root_uid, ossec_gid)


def setup_ossec_conf(item, type_item):
    # Include Rules & Rootchecks

    # Note: It is assumed that the default rules/rootchecks are included in ossec.conf
    if item == "ossec":
        return

    if type_item == "rule":
        if not regex_in_file("\s*<include>{0}_rules.xml</include>".format(item), ossec_conf):
            logger.log("\t\tNew rule in ossec.conf: '{0}'.".format(item))
            write_before_line("<include>local_rules.xml</include>", '    <include>{0}_rules.xml</include>'.format(item), ossec_conf)
    elif type_item == "rootcheck":
        if not regex_in_file("<rootcheck>", ossec_conf) or regex_in_file("\s*<rootcheck>\s*\n\s*<disabled>\s*yes", ossec_conf):
            logger.log("\t\tRootchecks disabled in ossec.conf -> no activate rootchecks.")
            return

        types_rc = ["rootkit_files", "rootkit_trojans", "system_audit", "windows_malware", "windows_audit", "windows_apps"]
        types_rc_files = ["win_malware_", "win_audit_", "win_applications_", "cis_"]
        types_all = types_rc + types_rc_files

        new_rc = "{0}/etc/shared/{1}".format(ossec_path, item)

        rc_include = None
        for type_rc in types_all:
            if item.startswith(type_rc):
                # special case (default rootcheck files)
                if type_rc == "win_malware_":
                    type_rc = "windows_malware"
                elif type_rc == "win_audit_":
                    type_rc = "windows_audit"
                elif type_rc == "win_applications_":
                    type_rc = "windows_apps"
                elif type_rc == "cis_":
                    type_rc = "system_audit"

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


def setup_ruleset_r(target_rules, activated_rules):
    logger.log("\nThe following rules will be updated:")
    for rule in target_rules:
        logger.log("\t{0}".format(rule))
    logger.stdout("")

    instructions = []
    for item in target_rules:
        activating_shown = False
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
        if item in activated_rules:
            logger.log("\tActivating rules in ossec.conf.")
            activating_shown = True
            setup_ossec_conf(item, "rule")

        # special case: auditd, usb
        if item == "ossec":
            special_cases = ["auditd", "usb", "opensmtpd"]
            for special_case in special_cases:
                if not regex_in_file("\s*<include>{0}_rules.xml</include>".format(special_case), "{0}/etc/ossec.conf".format(ossec_path)):
                    if not activating_shown:
                        logger.log("\tActivating rules in ossec.conf.")
                        activating_shown = True
                    setup_ossec_conf(special_case, "rule")

        if activating_shown:
            logger.log("\t\t[Done]")

        # Info
        if item == "puppet":
            msg = "The rules of Puppet are installed but you need to perform a manual step. You will find detailed information in our documentation: http://wazuh-documentation.readthedocs.org/en/latest/ossec_ruleset.html#puppet"
            logger.log("\t**Manual steps**:\n\t\t{0}".format(msg))
            instructions.append("{0}: {1}".format(item, msg))

    return instructions


def setup_ruleset_rc(target_rootchecks, activated_rootchecks):

    logger.log("\nThe following rootchecks will be updated:")
    for t_rootcheck in target_rootchecks:
        logger.log("\t{0}".format(t_rootcheck))
    logger.stdout("")

    for item in target_rootchecks:
        logger.log("{0}:".format(item))

        # Rootchecks
        logger.log("\tCopying rootchecks.")
        setup_roochecks(item)
        logger.log("\t\t[Done]")

        # ossec.conf
        if item in activated_rootchecks:
            logger.log("\tActivating rootchecks in ossec.conf.")
            setup_ossec_conf(item, "rootcheck")
            logger.log("\t\t[Done]")


def compatibility_with_old_versions():

    # OpenLDAP
    # Old decoders have not <accumulate> tag
    src_file = "{0}/ossec/decoders/compatibility/openldap_decoders.xml".format(new_rules_path)
    dest_file = "{0}/etc/ossec_decoders/openldap_decoders.xml".format(ossec_path)
    shutil.copyfile(src_file, dest_file)


def clean_directory():
    if os.path.exists(downloads_directory):
        shutil.rmtree(downloads_directory)


# Main

def usage():
    msg = """
OSSEC Wazuh Ruleset Update v2.3.1
Github repository: https://github.com/wazuh/ossec-rules
Full documentation: http://documentation.wazuh.com/en/latest/ossec_ruleset.html

Usage: ./ossec_ruleset.py                 # Update Rules & Rootchecks
       ./ossec_ruleset.py -a              # Update and prompt menu to activate new Rules & Rootchecks
       ./ossec_ruleset.py -s              # Update Rules & Rootchecks - Silent Mode
       ./ossec_ruleset.py -b 20160201_000 # Restore specific backup

Select ruleset:
\t-r, --rules\tUpdate rules
\t-c, --rootchecks\tUpdate rootchecks
\t*If not -r or -c indicated, rules and rootchecks will be updated.

Activate:
\t-a, --activate\tPrompt a interactive menu for selection of rules and rootchecks to activate.
\t-A, --activate-file\tUse a configuration file to select rules and rootchecks to activate.
\t*If not -a or -A indicated, NEW rules and rootchecks will NOT activated.

Restart:
\t-s, --restart\tRestart OSSEC when required.
\t-S, --no-restart\tDo not restart OSSEC when required.

Backups:
\t-b, --backups\tRestore backups. Use 'list' to show the backups list available.

Additional Params:
\t-f, --force-update\tForce to update all rules and rootchecks. By default, only it is updated the new/changed rules/rootchecks.
\t-d, --directory\tUse the ruleset specified at 'directory'. Directory structure should be the same that ossec-rules repository.

Configuration file syntax using option -A:
\t# Commented line
\trules:rule_name
\trootchecks:rootcheck_name
"""
    print(msg)


if __name__ == "__main__":
    # Config
    MAX_BACKUPS = 50
    url_ruleset = "http://ossec.wazuh.com/ruleset/ruleset.zip"
    # url_ruleset = "http://ossec.wazuh.com/ruleset/ruleset_development.zip"
    ossec_path = "/var/ossec"
    ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)
    updater_path = "{0}/update/ruleset".format(ossec_path)
    bk_directory = "{0}/backups".format(updater_path)
    log_path = "{0}/ossec_ruleset.log".format(updater_path)
    version_path = "{0}/VERSION".format(updater_path)
    script_path = "{0}/ossec_ruleset.py".format(updater_path)
    downloads_directory = "{0}/downloads".format(updater_path)
    new_rules_path = "{0}/ossec-rules/rules-decoders".format(downloads_directory)
    new_rootchecks_path = "{0}/ossec-rules/rootcheck".format(downloads_directory)

    # Vars
    today_date = date.today().strftime('%Y%m%d')
    manual_steps = []
    restart_ossec = False
    type_ruleset = "all"  # rules, rootchecks, all
    backup_name = "N/A"
    activate_file = "N/A"
    activate_args = 0
    mandatory_args = 0
    action_activate = "no-activate"  # no-activate, menu, file
    action_restart = "ask-restart"  # ask-restart, restart, no-restart
    restart_args = 0
    action_backups = False
    action_force = False
    action_download = "download"  # download, path

    # Capture Cntrl + C
    signal.signal(signal.SIGINT, signal_handler)

    # Check sudo
    if os.geteuid() != 0:
        print("You need root privileges to run this script. Please try again, using 'sudo'. Exiting.")
        sys.exit()

    # Check arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "rcb:aA:sSfd:h",
                                   ["rules", "rootchecks", "backups=", "activate", "activate-file=", "restart", "no-restart", "force-update", "directory", "help"])
        if len(opts) > 5:
            print("Incorrect number of arguments.\nTry './ossec_ruleset.py --help' for more information.")
            sys.exit()
    except getopt.GetoptError as err:
        print(str(err))
        print("Try './ossec_ruleset.py --help' for more information.")
        sys.exit(2)

    for o, a in opts:
        if o in ("-r", "--rules"):
            type_ruleset = "rules"
            mandatory_args += 1
        elif o in ("-c", "--rootchecks"):
            type_ruleset = "rootchecks"
            mandatory_args += 1
        elif o in ("-b", "--backups"):
            action_backups = "backups"
            backup_name = a
            mandatory_args += 1
        elif o in ("-a", "--activate"):
            action_activate = "menu"
            activate_args += 1
        elif o in ("-A", "--activate-file"):
            action_activate = "file"
            activate_file = a
            activate_args += 1
        elif o in ("-s", "--restart"):
            action_restart = "restart"
            restart_args += 1
        elif o in ("-S", "--no-restart"):
            action_restart = "no-restart"
            restart_args += 1
        elif o in ("-f", "--force-update"):
            action_force = True
        elif o in ("-d", "--directory"):
            action_download = a
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        else:
            usage()
            sys.exit()

    if mandatory_args > 1 or restart_args > 1 or activate_args > 1:
        print("Bad arguments combination.\nTry './ossec_ruleset.py --help' for more information.")
        sys.exit(2)

    # Create folder updater_path
    if not os.path.exists(updater_path):
        os.makedirs(updater_path)

    # Log
    logger = LogFile(log_path, "wazuh_ossec_ruleset")
    # logger.set_debug(True)

    logger.debug("Args:")
    logger.debug("\ttype_ruleset: '{0}'\n\taction_backups: '{1}'\n\tbackup_name: '{2}'\n\tmandatory_args: '{3}'\n\taction_activate: '{4}'\n\tactivate_file: '{5}'\n\tactivate_args: '{6}'\n\taction_restart: '{7}'\n\trestart_args: '{8}'\n\taction_force: '{9}'".format(type_ruleset, action_backups, backup_name, mandatory_args, action_activate, activate_file, activate_args, action_restart, restart_args, action_force))
    logger.file("Starting ossec_ruleset.py")

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

    logger.debug("\nRuleset version: '{0}'\tOSSEC Version: '{1}'".format(ruleset_version, ossec_version))

    # Title
    logger.log("\nOSSEC Wazuh Ruleset [{0}], {1}".format(ruleset_version, today_date))

    # Backups
    logger.log("\nCreating a backup for folders '{0}/etc' and '{0}/rules'.".format(ossec_path))
    dir_bk = do_backups()
    logger.log("\tBackup folder: {0}\n\t[Done]".format(dir_bk))

    # Restore backups
    if action_backups:
        logger.log("\nRestore Tool:")
        if backup_name != "list":
            restore_backups(backup_name)
        else:
            restore_backups("0")
        logger.log("\t[Done]")
    else:
        # Setup Wazuh structure: /etc/ossec_decoders/, /etc/wazuh_decoders/, /etc/local_decoders.xml
        logger.log("\nChecking directory structure.")
        setup_wazuh_directory_structure()
        logger.log("\t[Done]")

        # Download ruleset
        if action_download == "download":
            logger.log("\nDownloading new ruleset.")
            download_ruleset()
        else:
            logger.log("\nObtaining new ruleset.")
            copy_ruleset(action_download)
        logger.log("\t[Done]")

        # Checks
        logger.log("\nChecking new ruleset.")
        ruleset_to_update = get_ruleset_to_update(action_force)
        if action_force:
            restart_ossec = True
        logger.debug("\t*Ruleset to update*: {0}".format(ruleset_to_update))
        logger.log("\t[Done]")

        if not ruleset_to_update['rules'] and not ruleset_to_update['rootchecks']:
            # Clean directory
            logger.log("\nCleaning directory.")
            clean_directory()
            logger.log("\t[Done]")

            logger.log("\n*Your ruleset is up to date.*")
            logger.log("\n\nWazuh.com")
            logger.file("Ending ossec_ruleset.py")
            sys.exit()
        if not ruleset_to_update['rules'] and type_ruleset != "rootchecks":
            logger.log("\n*Your rules are up to date.*")
        if not ruleset_to_update['rootchecks'] and type_ruleset != "rules":
            logger.log("\n*Your rootchecks are up to date.*")

        # Activate ruleset (no-activate, menu, file)
        if action_activate == "menu":
            activated_ruleset = activate_from_menu(ruleset_to_update)
        elif action_activate == "file":
            activated_ruleset = activate_from_file(ruleset_to_update)
        else:  # no-activate
            activated_ruleset = {'rules': [], 'rootchecks': []}

        if activated_ruleset['rules'] or activated_ruleset['rootchecks']:
            restart_ossec = True

        # Update
        logger.debug("\tActivated ruleset: {0}".format(activated_ruleset))
        if ruleset_to_update['rules']:
            setup_ruleset_r(ruleset_to_update['rules'], activated_ruleset['rules'])
        if ruleset_to_update['rootchecks']:
            setup_ruleset_rc(ruleset_to_update['rootchecks'], activated_ruleset['rootchecks'])

        # PATCH for OSSEC != Wazuh
        if ossec_version == "old" and type_ruleset != "rootchecks":
            compatibility_with_old_versions()

        # Clean directory
        logger.log("\nCleaning directory.")
        clean_directory()
        logger.log("\t[Done]")

    # Restart ossec
    if restart_ossec:
        if action_restart == "ask-restart":
            logger.log("\nOSSEC requires a restart to apply changes.")
            ans_restart = get_stdin("Do you want to restart OSSEC now? [y/N]: ")
        elif action_restart == "restart":
            ans_restart = "y"
        elif action_restart == "no-restart":
            ans_restart = "n"
    else:
        ans_restart = "n"

    # Messages
    ret = 0
    if action_backups == "backups":
        success_msg = "\n\n**Backup successfully**"
    else:
        success_msg = "\n\n**Ruleset({0}) updated successfully**".format(ruleset_version)

    if ans_restart == "y" or ans_restart == "Y":
        logger.log("\nRestarting OSSEC.")
        ret = os.system("{0}/bin/ossec-control restart".format(ossec_path))
        if ret != 0:
            logger.log("\n**Something went wrong**")
            logger.log("Please check your config. logtest can be useful: {0}/bin/ossec-logtest".format(ossec_path))
            logger.log("\n\n**Ruleset error**")
        else:
            logger.log(success_msg)
    else:  # n
        if restart_ossec:
            logger.log("\nDo not forget to restart OSSEC to apply changes.")
        logger.log(success_msg)

    if manual_steps:
        logger.log("\nDo not forget the manual steps:")
        for step in manual_steps:
            logger.log("\t{0}".format(step))

    logger.log("\n\nWazuh.com")
    logger.file("Ending ossec_ruleset.py")
