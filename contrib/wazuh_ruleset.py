#!/usr/bin/env python
# OSSEC Ruleset Update

# v3.0.0 2016/12/15
# Created by Wazuh, Inc. <info@wazuh.com>.
# jesus@wazuh.com
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

# Requirements:
#  Python 2.6 or newer
#  Wazuh
#  root privileges
# http://wazuh-documentation.readthedocs.io/en/latest/wazuh_ruleset.html

import os
import sys
import glob
import shutil
import contextlib
import fileinput
from zipfile import ZipFile
from datetime import datetime, date
from time import time
from re import sub, search
from json import dumps
from getopt import GetoptError, getopt
from signal import signal, SIGINT
from pwd import getpwnam
from grp import getgrnam
from filecmp import cmp

try:
    from urllib2 import urlopen, URLError, HTTPError
except:
    from urllib.request import urlopen  # Python 3


# Log class
class RulesetLogger:
    O_STDOUT = 1
    O_FILE = 2
    O_ALL = 3

    def __init__(self, tag, filename=None, flag=3, debug=False):
        self.tag = tag
        self.flag = flag
        self.debug_mode = debug
        try:
            self.logger = open(filename, 'a')
        except:
            print("Error opening log '{0}'".format(filename))
            sys.exit(1)

    def log(self, msg):
        if self.flag == RulesetLogger.O_ALL or self.flag == RulesetLogger.O_STDOUT:
            print(msg)

        if self.flag == RulesetLogger.O_ALL or self.flag == RulesetLogger.O_FILE:
            self.__write_file(msg)

    def debug(self, msg):
        if self.debug_mode:
            print("DEBUG: {0}".format(msg))

    def __write_file(self, message):
        timestamp = datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S')
        new_msg = sub('[\n\t]', '', message)
        log = "{0} [{1}]: {2}".format(self.tag, timestamp, new_msg)
        self.logger.write("{0}\n".format(log))

    def __del__(self):
        self.logger.close()


# Aux functions
def chown_r(path, uid, gid):
    if os.path.isdir(path):
        os.chown(path, uid, gid)
        for item in os.listdir(path):
            itempath = os.path.join(path, item)
            if os.path.isfile(itempath):
                os.chown(itempath, uid, gid)
            elif os.path.isdir(itempath):
                chown_r(itempath, uid, gid)


def copy_files_folder(src, dst):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            copy_files_folder(s, d)
        else:
            shutil.copyfile(s, d)
            os.chown(d, root_uid, ossec_gid)


def download_file(url, output_file):
    try:
        f = urlopen(url)

        with open(output_file, "wb") as local_file:
            local_file.write(f.read())

    except HTTPError as e:
        exit(2, "\tHTTP Error {0}: {1}".format(e.code, url))
    except URLError as e:
        exit(2, "\tURL Error - {0}: {1}".format(e.reason, url))
    except Exception as e:
        exit(2, "\tDownload Error:{0}.\nExit.".format(e))


def compare_files(file1, file2):
    """
    :param file1: File to be compared
    :param file2: File to be compared
    :return: Returns true if file1 is equal to file2, and false otherwise. Also returns false if file2 does not exist.
    """

    if os.path.isfile(file1) and os.path.isfile(file2):
        same = cmp(file1, file2)
    else:
        same = False

    return same


def regex_in_file(regex, filepath):
    with open(filepath) as f:
        m = search(regex, f.read())
        if m:
            return True
        else:
            return False


def get_stdin(msg):
    try:
        stdin = raw_input(msg)
    except:
        # Python 3
        stdin = input(msg)
    return stdin
# END Aux functions


# Functions
def signal_handler(n_signal, frame):
    logger.log("Exiting SIGINT: {0} - {1}.".format(n_signal, frame))
    sys.exit(1)


def exit(code, msg=None):
    logger.log("ERROR: {0}".format(msg))

    if json_output:
        json_res = {'error': code}
        msg_res = msg.replace('\t', '').replace('\n', '')
        if code == 0:
            json_res['data'] = msg_res
        else:
            json_res['message'] = msg_res

        print(dumps(json_res))

    sys.exit(code)


def get_ossec_version():
    try:
        ossec_v = "old"
        is_wazuh = False
        init_file = "{0}/etc/ossec-init.conf".format(ossec_path)

        f_ossec = open(init_file)
        for line in f_ossec.readlines():
            line_lower = line.lower()

            if "wazuh_version=\"" in line_lower:
                is_wazuh = True
                ossec_v = line.strip("\n").split("=")[1]
                break
            elif "name=\"wazuh\"" in line_lower:
                is_wazuh = True
            elif "version=\"" in line_lower:
                ossec_v = line.strip("\n").split("=")[1]

        f_ossec.close()

        return is_wazuh, ossec_v
    except:
        exit(2, "Reading '{0}'.".format(init_file))


def previous_checks():
    # Get uid:gid = root:ossec
    try:
        global root_uid
        global ossec_gid
        root_uid = getpwnam("root").pw_uid
        ossec_gid = getgrnam("ossec").gr_gid
    except:
        exit(2, "No user 'root' or group 'ossec' found.")

    # Check if wazuh is installed
    global ossec_version
    is_wazuh, ossec_version = get_ossec_version()

    if not is_wazuh:
        exit(2, "OSSEC {0} detected. This script only supports Wazuh v1.2 or newer.".format(ossec_version))
    else:
        if float(ossec_version[2:5]) < 1.2:
            exit(2, "Wazuh {0} detected. This script only supports Wazuh v1.2 or newer.".format(ossec_version))


def get_ruleset_version():
    try:
        f_version = open(ruleset_version_path)
        rs_version = f_version.read().rstrip('\n')
        f_version.close()
    except:
        rs_version = "0.100"

    return rs_version


def get_backup_list():
    list_bk = []

    if os.path.exists(bk_directory):
        list_bk = sorted(os.listdir(bk_directory), reverse=True)
        if "old" in list_bk:
            list_bk.remove("old")

    return list_bk


def backup_item(type_item, item, dest, pattern=None):
    if not os.path.exists(item):
        return -1

    if type_item == "folder":
        if not pattern:
            if os.path.exists(dest):
                shutil.rmtree(dest)
            shutil.copytree(item, dest)
        else:
            folder_files = sorted(glob.glob("{0}/{1}".format(item, pattern)))
            for folder_file in folder_files:
                dest_filename = folder_file.split("/")[-1]
                shutil.copyfile(folder_file, "{0}/{1}".format(dest, dest_filename))
        chown_r(dest, root_uid, ossec_gid)
    else:
        shutil.copyfile(item, dest)
        os.chown(dest, root_uid, ossec_gid)


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

        os.makedirs("{0}/etc/shared".format(bk_subdirectory))

        # Backups
        # decoders
        backup_item("folder", "{0}".format(dst_decoders_path), "{0}/ruleset/decoders".format(bk_subdirectory))

        # rules
        backup_item("folder", "{0}".format(dst_rules_path), "{0}/ruleset/rules".format(bk_subdirectory))

        # decoder.xml
        backup_item("file", "{0}/etc/decoder.xml".format(ossec_path), "{0}/etc/decoder.xml".format(bk_subdirectory))

        # ossec.conf
        backup_item("file", "{0}/etc/ossec.conf".format(ossec_path), "{0}/etc/ossec.conf".format(bk_subdirectory))

        # shared/*txt
        backup_item("folder", "{0}/etc/shared".format(ossec_path), "{0}/etc/shared".format(bk_subdirectory), "*.txt")

        return bk_subdirectory

    except Exception as e:
        exit(2, "Creating Backup: {0}.".format(e))


def restore_backups(backup_id):

    if not os.path.exists(bk_directory):
        exit(2, "\tNo backups to restore.")

    bk_restore_dir = "{0}/{1}".format(bk_directory, backup_id)
    if not os.path.exists(bk_restore_dir):
        exit(2, "\tNo backups with name '{0}'.".format(backup_id))

    logger.log("\tThe backup '{0}' will be restored.".format(backup_id))

    etc_restore = "{0}/{1}/etc".format(bk_directory, backup_id)
    rules_restore = "{0}/{1}/ruleset".format(bk_directory, backup_id)
    if not os.path.exists(etc_restore) or not os.path.exists(rules_restore):
        exit(2, "\t\tFolder '{0}' or '{1}' not found.".format(etc_restore, rules_restore))

    etc_dest = "{0}/etc".format(ossec_path)
    logger.log("\t\tRestoring files in '{0}' -> '{1}'".format(etc_restore, etc_dest))
    copy_files_folder(etc_restore, etc_dest)

    rules_dest = "{0}/ruleset".format(ossec_path)
    logger.log("\t\tRestoring folder: '{0}' -> '{1}'".format(rules_restore, rules_dest))
    copy_files_folder(rules_restore, rules_dest)


def download_ruleset():
    output = "{0}/ruleset.zip".format(downloads_directory)

    if not os.path.exists(downloads_directory):
        os.makedirs(downloads_directory)

    download_file(url_ruleset, output)

    old_extracted_files = "{0}/wazuh-ruleset/".format(downloads_directory)
    if os.path.exists(old_extracted_files):
        shutil.rmtree(old_extracted_files)

    try:
        with contextlib.closing(ZipFile(output)) as z:
            z.extractall(downloads_directory)
    except Exception as e:
        exit(2, "\tError extracting file '{0}': {1}.".format(output, e))

    if 'stable.zip' in url_ruleset:
        os.rename("{0}/wazuh-ruleset-stable".format(downloads_directory), "{0}/wazuh-ruleset".format(downloads_directory))
    elif 'development.zip' in url_ruleset:
        os.rename("{0}/wazuh-ruleset-development".format(downloads_directory), "{0}/wazuh-ruleset".format(downloads_directory))
    elif 'master.zip' in url_ruleset:
        os.rename("{0}/wazuh-ruleset-master".format(downloads_directory), "{0}/wazuh-ruleset".format(downloads_directory))
    else:
        exit(2, "Invalid downloaded file: {0}".format(url_ruleset))

    # Update main directory
    shutil.copyfile("{0}/wazuh-ruleset/VERSION".format(downloads_directory), ruleset_version_path)

    new_python_script = "{0}/wazuh-ruleset/wazuh_ruleset.py".format(downloads_directory)
    if os.path.isfile(new_python_script):
        shutil.copyfile(new_python_script, script_path)

    global ruleset_version
    ruleset_version = get_ruleset_version()


def copy_ruleset(directory):
    # New ruleset
    if not os.path.exists(directory):
        exit(2, "Directory doest not exist: '{0}'.\nExit.".format(directory))

    old_extracted_files = "{0}/wazuh-ruleset/".format(downloads_directory)
    if os.path.exists(old_extracted_files):
        shutil.rmtree(old_extracted_files)

    # Copy to downloads directory
    if not os.path.exists(downloads_directory):
        os.makedirs(downloads_directory)

    shutil.copytree(directory, "{0}/wazuh-ruleset/".format(downloads_directory))

    # Check new ruleset
    check_files = ["rootchecks", "rules", "decoders", "VERSION"]
    for cf in check_files:
        if not os.path.exists("{0}/wazuh-ruleset/{1}".format(downloads_directory, cf)):
            exit(2, "'{0}' doest not exist at '{1}'.\nExit.".format(cf, directory))

    # Update main directory
    shutil.copyfile("{0}/wazuh-ruleset/VERSION".format(downloads_directory), ruleset_version_path)

    new_python_script = "{0}/wazuh-ruleset/wazuh_ruleset.py".format(downloads_directory)
    if os.path.isfile(new_python_script):
        shutil.copyfile(new_python_script, script_path)

    global ruleset_version
    ruleset_version = get_ruleset_version()


def get_ruleset_to_update(no_checks=False):
    ruleset_update = {"rules": [], "rootchecks": []}
    rules_update = []
    decoders_update = []
    rootchecks_update = []
    restart_ossec_needed = False

    # Rules
    if not os.path.exists(source_rules_path):
        exit(2, "\tError: No rules found. Maybe failed download.")

    for new_rule in glob.glob("{0}/*_rules.xml".format(source_rules_path)):
        filename = new_rule.split("/")[-1]

        if "local_rules.xml" in new_rule:
            continue

        if no_checks:
            rules_update.append(filename)
            restart_ossec_needed = True
        else:  # Compare: New / Changed files
            rules_file = "{0}/{1}".format(dst_rules_path, filename)
            rules_equal = compare_files(new_rule, rules_file)

            if not rules_equal:
                logger.debug("\tRule '{0}' == Rule '{1}'?\t{2}.".format(new_rule, rules_file, rules_equal))
                rules_update.append(filename)
                restart_ossec_needed = True

    # Decoders
    if not os.path.exists(source_decoders_path):
        exit(2, "\tError: No decoders found. Maybe failed download.")

    for new_decoder in glob.glob("{0}/*_decoders.xml".format(source_decoders_path)):
        filename = new_decoder.split("/")[-1]

        if "local_decoder.xml" in new_decoder:
            continue

        if no_checks:
            decoders_update.append(filename)
            restart_ossec_needed = True
        else:  # Compare: New / Changed files
            decoders_file = "{0}/{1}".format(dst_decoders_path, filename)
            decoders_equal = compare_files(new_decoder, decoders_file)

            if not decoders_equal:
                logger.debug("\tDecoders '{0}' == Decoders '{1}'?\t{2}.".format(new_decoder, decoders_file, decoders_equal))
                decoders_update.append(filename)
                restart_ossec_needed = True

    # Rootchecks
    if not os.path.exists(source_rootchecks_path):
        exit(2, "\tError: No rootchecks found. Maybe failed download.")

    for new_rc in os.listdir(source_rootchecks_path):
        if no_checks:
            rootchecks_update.append(new_rc)
            restart_ossec_needed = True
        else:  # Compare: New / Changed files
            new_rootchecks_file = "{0}/{1}".format(source_rootchecks_path, new_rc)
            rootchecks_file = "{0}/etc/shared/{1}".format(ossec_path, new_rc)
            rootchecks_equal = compare_files(new_rootchecks_file, rootchecks_file)

            if not rootchecks_equal:
                logger.debug("\tRootchecks '{0}' == Rootchecks '{1}'?\t{2}.".format(new_rootchecks_file, rootchecks_file, rootchecks_equal))
                rootchecks_update.append(new_rc)

                # Restart ossec just if the rootcheck is enabled in ossec.conf
                # The script does not activate the rootchecks.
                if regex_in_file("\s*<.+>.*{0}</.+>".format(rootchecks_file), ossec_conf):
                    restart_ossec_needed = True

    # Save ruleset
    ruleset_update["rules"] = sorted(rules_update)
    ruleset_update["decoders"] = sorted(decoders_update)
    ruleset_update["rootchecks"] = sorted(rootchecks_update)

    return ruleset_update, restart_ossec_needed


def update_rules(rules):
    if not rules:
        logger.log("\n*You already have the latest version of rules.*")
    else:
        logger.log("\nThe following rules will be updated:")
        for rule in rules:
            logger.log("\t{0}".format(rule))

            src_rule = "{0}/{1}".format(source_rules_path, rule)
            dst_rule = "{0}/{1}".format(dst_rules_path, rule)

            if "local_rules.xml" not in src_rule and os.path.isfile(src_rule):
                shutil.copyfile(src_rule, dst_rule)
                os.chown(dst_rule, root_uid, ossec_gid)


def update_decoders(decoders):
    if not decoders:
        logger.log("\n*You already have the latest version of decoders.*")
    else:
        logger.log("\nThe following decoders will be updated:")
        for decoder in decoders:
            logger.log("\t{0}".format(decoder))

            src_decoder = "{0}/{1}".format(source_decoders_path, decoder)
            dst_decoder = "{0}/{1}".format(dst_decoders_path, decoder)

            if "local_decoder.xml" not in src_decoder and os.path.isfile(src_decoder):
                shutil.copyfile(src_decoder, dst_decoder)
                os.chown(dst_decoder, root_uid, ossec_gid)


def update_rootchecks(rootchecks):
    if not rootchecks:
        logger.log("\n*You already have the latest version of rootchecks.*")
    else:
        logger.log("\nThe following rootchecks will be updated:")
        for rootcheck in rootchecks:
            logger.log("\t{0}".format(rootcheck))

            src_rootcheck = "{0}/{1}".format(source_rootchecks_path, rootcheck)
            dst_rootcheck = "{0}/etc/shared/{1}".format(ossec_path, rootcheck)

            if os.path.isfile(src_rootcheck):
                shutil.copyfile(src_rootcheck, dst_rootcheck)
                os.chown(dst_rootcheck, root_uid, ossec_gid)


def usage():
    msg = """
    OSSEC Wazuh Ruleset Update v3.0.0
    Github repository: https://github.com/wazuh/wazuh-ruleset
    Full documentation: http://documentation.wazuh.com/en/latest/wazuh_ruleset.html

    Usage: ./wazuh_ruleset.py                  # Update Decoders, Rules and Rootchecks
           ./wazuh_ruleset.py -b list          # Show backup list
           ./wazuh_ruleset.py -b 20160901_001  # Restore specific backup

    Restart:
    \t-s, --restart       Restart OSSEC when required.
    \t-S, --no-restart    Do not restart OSSEC when required.

    Source:
    \t-p, --path          Update ruleset from path (instead of download it).

    Backups:
    \t-b , --backups      Restore backups. Use 'list' to show the backups list available.

    Additional Params:
    \t-f, --force-update  Force to update the ruleset. By default, only it is updated the new/changed decoders/rules/rootchecks.
    \t-o, --ossec-path    Set OSSEC path. Default: '/var/ossec'
    \t-j, --json          JSON output. It should be used with '-s' or '-S' argument.
    \t-d, --debug         Debug mode.
    """
    print(msg)


def main():
    global restart_ossec
    global json_data

    logger.log("### Wazuh Ruleset ###\n")

    # Checks
    previous_checks()
    logger.log("Wazuh Version: {0}".format(ossec_version))

    # Backups actions
    if action_backup != "no-backup":
        if action_backup == "list":
            backup_list = get_backup_list()
            if backup_list:
                logger.log("\nList of available backups:")
                for bk_item in backup_list:
                    logger.log("\t{0}".format(bk_item))
                success_msg = "\nUse argument \"-b YYYYMMDD_i\" to restore a backup."
            else:
                success_msg = "\nNo backups to restore."

            restart_ossec = False
            json_data['list'] = backup_list
        else:
            dir_bk = do_backups()
            logger.log("\nBackup directoy: {0}\n".format(dir_bk))
            json_data['backup_directory'] = dir_bk

            logger.log("Restore tool:")
            restore_backups(action_backup)
            restart_ossec = True
            success_msg = "\n**Backup restored successfully**"
    else:  # Ruleset actions
        dir_bk = do_backups()
        logger.log("\nBackup directory: {0}\n".format(dir_bk))
        json_data['backup_directory'] = dir_bk

        # Title
        ruleset_version_old = get_ruleset_version()

        # Download ruleset
        if action_download == "download":
            logger.log("Downloading new ruleset [{0}].".format(url_ruleset))
            download_ruleset()
        else:
            logger.log("Obtaining new ruleset from path [{0}].".format(action_download))
            copy_ruleset(action_download)  # action_download = directory

        logger.log("\nWazuh Ruleset [{0}] -> [{1}]".format(ruleset_version_old, ruleset_version))

        # Checks
        logger.log("\nChecking new ruleset.")
        ruleset_to_update, restart_ossec_required = get_ruleset_to_update(action_force)
        if restart_ossec_required:
            restart_ossec = True

        # Update
        if not ruleset_to_update['rules'] and not ruleset_to_update['decoders'] and not ruleset_to_update['rootchecks']:
            success_msg = "\n*You already have the latest version of ruleset.*"
        else:
            update_rules(ruleset_to_update['rules'])
            update_decoders(ruleset_to_update['decoders'])
            update_rootchecks(ruleset_to_update['rootchecks'])

            success_msg = "\n**Ruleset {0} updated to {1} successfully**".format(ruleset_version_old, ruleset_version)

        # Clean directory
        logger.log("\nCleaning directory.")
        if os.path.exists(downloads_directory):
            shutil.rmtree(downloads_directory)

    # Messages and restart OSSEC
    ans_restart = "n"
    json_data['need_restart'] = "no"
    if restart_ossec:
        json_data['need_restart'] = "yes"
        if action_restart == "ask-restart":
            logger.log("\nOSSEC requires a restart to apply changes.")
            ans_restart = get_stdin("Do you want to restart OSSEC now? [y/N]: ")
        elif action_restart == "restart":
            ans_restart = "y"

    json_error = 0
    if ans_restart == "y" or ans_restart == "Y":
        logger.log("\nRestarting OSSEC.")
        json_data['restarted'] = "yes"

        no_output = ""
        if json_output:
            no_output = " > /dev/null 2>&1"

        ret = 0
        ret = os.system("{0}/bin/ossec-control restart{1}".format(ossec_path, no_output))
        if ret != 0:
            json_data['restart_status'] = "fail"
            logger.log("\n**Something went wrong**")
            logger.log("Please check your configuration. logtest can be useful: {0}/bin/ossec-logtest".format(ossec_path))
            logger.log("\n\n**ERROR: OSSEC restart failed**")
            success_msg = success_msg.replace("successfully", "failed")
            json_data['status'] = "fail"
        else:
            json_data['restart_status'] = "success"
            logger.log(success_msg)
    else:  # n
        json_data['restarted'] = "no"
        if restart_ossec:
            logger.log("\nDo not forget to restart OSSEC to apply changes.")
            json_data['status'] = "success-restart_required"
        logger.log(success_msg)

    json_data['msg'] = success_msg.replace("\n", "").replace("*", "")

    if json_output:
        print(dumps({'error': 0, 'data': json_data}))

    logger.log("\n### END ###")


# END functions

if __name__ == "__main__":
    # Sudo / Root
    if os.geteuid() != 0:
        print("You need root privileges to run this script. Please try again, using 'sudo'. Exiting.")
        sys.exit(1)

    # Config
    MAX_BACKUPS = 50
    #url_ruleset = "https://github.com/wazuh/wazuh-ruleset/archive/stable.zip"
    #url_ruleset = "https://github.com/wazuh/wazuh-ruleset/archive/development.zip"
    url_ruleset = "https://github.com/wazuh/wazuh-ruleset/archive/master.zip"

    # Paths
    ossec_path = "/var/ossec"
    update_path = "{0}/update/ruleset".format(ossec_path)
    ruleset_log = "{0}/logs/ruleset.log".format(ossec_path)
    ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)
    ruleset_version_path = "{0}/VERSION".format(update_path)
    bk_directory = "{0}/backups".format(update_path)
    script_path = "{0}/wazuh_ruleset.py".format(update_path)
    downloads_directory = "{0}/downloads".format(update_path)
    source_rules_path = "{0}/wazuh-ruleset/rules".format(downloads_directory)
    source_decoders_path = "{0}/wazuh-ruleset/decoders".format(downloads_directory)
    source_rootchecks_path = "{0}/wazuh-ruleset/rootchecks".format(downloads_directory)
    dst_rules_path = "{0}/ruleset/rules".format(ossec_path)
    dst_decoders_path = "{0}/ruleset/decoders".format(ossec_path)

    # Vars
    today_date = date.today().strftime('%Y%m%d')
    restart_ossec = False
    json_data = {'msg': "", 'restarted': "", 'restart_status': "N/A", 'need_restart': "", 'status': "success"}
    json_output = False
    action_backup = "no-backup"
    action_restart = "ask-restart"  # ask-restart, restart, no-restart
    action_force = False
    action_download = "download"  # download, path
    restart_args = 0
    debug_mode = False

    # Arguments
    try:
        opts, args = getopt(sys.argv[1:], "b:p:o:sSfdjh", ["backups=", "path=", "ossec-path=", "restart", "no-restart", "force-update", "debug", "json", "help"])
        if len(opts) > 6:
            print("Incorrect number of arguments.\nTry './wazuh_ruleset.py --help' for more information.")
            sys.exit(1)
    except GetoptError as err:
        print("str(err)" + "\n" + "Try './wazuh_ruleset.py --help' for more information.")
        sys.exit(1)

    for o, a in opts:
        if o in ("-b", "--backups"):
            action_backup = a
        elif o in ("-p", "--path"):
            action_download = a
        elif o in ("-o", "--ossec-path"):
            ossec_path = a
            if not os.path.exists(ossec_path):
                print("ERROR: '{0}' does not exist.".format(ossec_path))
                sys.exit(1)
        elif o in ("-s", "--restart"):
            action_restart = "restart"
            restart_args += 1
        elif o in ("-S", "--no-restart"):
            action_restart = "no-restart"
            restart_args += 1
        elif o in ("-f", "--force-update"):
            action_force = True
        elif o in ("-d", "--debug"):
            debug_mode = True
        elif o in ("-j", "--json"):
            json_output = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit(0)
        else:
            usage()
            sys.exit(1)

    if restart_args > 1:
        print("Bad arguments combination.\nTry './wazuh_ruleset.py --help' for more information.")
        sys.exit(1)

    # Logger
    if json_output:
        logger = RulesetLogger(tag="Wazuh-Ruleset", filename=ruleset_log, flag=RulesetLogger.O_FILE, debug=debug_mode)
    else:
        logger = RulesetLogger(tag="Wazuh-Ruleset", filename=ruleset_log, flag=RulesetLogger.O_ALL, debug=debug_mode)

    # Capture Cntrl + C
    signal(SIGINT, signal_handler)

    try:
        main()
    except Exception as e:
        exit(2, "Unkown: {0}.\nExiting.".format(e))
