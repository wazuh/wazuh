#!/usr/bin/env python
# Wazuh Ruleset Update

# v3.0.0 2016/12/23
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
import contextlib
from glob import glob
from zipfile import ZipFile
from getopt import GetoptError, getopt
from signal import signal, SIGINT
from datetime import datetime, date
from pwd import getpwnam
from grp import getgrnam
from shutil import copyfile, copytree, rmtree
from re import sub, search
from filecmp import cmp
from time import time
from json import dumps

try:
    from urllib2 import urlopen, URLError, HTTPError
except:
    from urllib.request import urlopen  # Python 3


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
def chown(path, uid, gid):
    os.chown(path, uid, gid)

    if os.path.isdir(path):
        for item in os.listdir(path):
            itempath = os.path.join(path, item)
            if os.path.isfile(itempath):
                os.chown(itempath, uid, gid)
            elif os.path.isdir(itempath):
                chown(itempath, uid, gid)


def chmod(path, mode):
    os.chmod(path, mode)

    if os.path.isdir(path):
        for item in os.listdir(path):
            itempath = os.path.join(path, item)
            if os.path.isfile(itempath):
                os.chmod(itempath, mode)
            elif os.path.isdir(itempath):
                chmod(itempath, mode)


def mkdir(path):
    if not os.path.exists(path):
        os.makedirs(path)
        chown(path, root_uid, ossec_gid)
        chmod(path, file_permissions)


def rename(src, dst):
    os.rename(src, dst)
    chown(dst, root_uid, ossec_gid)
    chmod(dst, file_permissions)


def copy(src, dst, executable=False):
    if os.path.isfile(src):
        copyfile(src, dst)
    else:
        copytree(src, dst)

    chown(dst, root_uid, ossec_gid)
    if executable:
        chmod(dst, file_permissions_x)
    else:
        chmod(dst, file_permissions)


def rm(path):
    if os.path.exists(path):
        rmtree(path)


def signal_handler(n_signal, frame):
    sys.exit(1)


def get_stdin(msg):
    try:
        stdin = raw_input(msg)
    except:
        # Python 3
        stdin = input(msg)
    return stdin


def regex_in_file(regex, filepath):
    with open(filepath) as f:
        m = search(regex, f.read())
        if m:
            return True
        else:
            return False


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


def exit(code, msg=None):
    logger.log("ERROR: {0}".format(msg))

    if arguments['json']:
        json_res = {'error': code}
        msg_res = msg.replace('\t', '').replace('\n', '')
        if code == 0:
            json_res['data'] = msg_res
        else:
            json_res['message'] = msg_res

        print(dumps(json_res))

    sys.exit(code)


# Functions
def get_branch():
    git_wazuh_ruleset = "./.git/HEAD"
    git_wazuh = "../../../.git/HEAD"
    branch_file = None

    if os.path.isfile('VERSION') and os.path.isfile(git_wazuh_ruleset):  # wazuh-ruleset
        branch_file = git_wazuh_ruleset
    elif os.path.isfile('RULESET_VERSION') and os.path.isfile(git_wazuh):  # wazuh
        branch_file = git_wazuh

    try:
        with open(branch_file, "r") as f:
            lines = f.readlines()

        current_branch = lines[0].split('/')[-1].strip()
    except:
        current_branch = 'stable'  # standalone script

    return current_branch


def get_ossec_version():
    init_file = "{0}/etc/ossec-init.conf".format(ossec_path)

    try:
        ossec_v = "old"
        is_wazuh = False

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


def get_ruleset_version():
    try:
        f_version = open(ossec_ruleset_version_path)
        rs_version = f_version.read().strip("\n").split("=")[1][2:-1]
        f_version.close()
    except:
        rs_version = "N/A"

    return rs_version


def get_new_ruleset(source):
    mkdir(update_downloads)
    rm(update_ruleset)

    if source == 'download':
        branch = get_branch()  # 'stable' 'master' 'development'
        url_ruleset = "https://github.com/wazuh/wazuh-ruleset/archive/{0}.zip".format(branch)
        ruleset_zip = "{0}/ruleset.zip".format(update_downloads)

        # Download
        try:
            f_url = urlopen(url_ruleset)
            with open(ruleset_zip, "wb") as f_local:
                f_local.write(f_url.read())
        except HTTPError as e:
            exit(2, "\tHTTP Error {0}: {1}".format(e.code, url_ruleset))
        except URLError as e:
            exit(2, "\tURL Error - {0}: {1}".format(e.reason, url_ruleset))
        except Exception as e:
            exit(2, "\tDownload Error:{0}.\nExit.".format(e))

        # Extract
        try:
            with contextlib.closing(ZipFile(ruleset_zip)) as z:
                z.extractall(update_downloads)
        except Exception as e:
            exit(2, "\tError extracting file '{0}': {1}.".format(ruleset_zip, e))

        # Rename
        rename("{0}/wazuh-ruleset-{1}".format(update_downloads, branch), update_ruleset)

    else:
        # New ruleset
        if not os.path.exists(source):
            exit(2, "Directory doest not exist: '{0}'.\nExit.".format(source))

        # Copy
        copy(source, update_ruleset)

        # Check new ruleset
        check_files = ["rootchecks", "rules", "decoders", "VERSION"]
        for cf in check_files:
            if not os.path.exists("{0}/{1}".format(update_ruleset, cf)):
                exit(2, "'{0}' doest not exist at '{1}'.\nExit.".format(cf, source))

    # Update main directory
    copy("{0}/VERSION".format(update_ruleset), ossec_ruleset_version_path)
    copy("{0}/update_ruleset.py".format(update_ruleset), ossec_update_script, executable=True)

    return get_ruleset_version()


def get_ruleset_to_update(no_checks=False):
    ruleset_update = {"rules": [], "decoders": [], "rootchecks": []}
    restart_ossec_needed = False

    for item in ruleset_update.keys():
        if item == 'rules':
            src = "{0}/*.xml".format(update_rules)
            dst = ossec_rules
        elif item == 'decoders':
            src = "{0}/*.xml".format(update_decoders)
            dst = ossec_decoders
        elif item == 'rootchecks':
            src = "{0}/*.txt".format(update_rootchecks)
            dst = ossec_rootchecks

        for src_item in glob(src):
            filename = src_item.split("/")[-1]

            if no_checks:
                ruleset_update[item].append(filename)
                restart_ossec_needed = True
            else:  # Compare: New / Changed files
                dst_item = "{0}/{1}".format(dst, filename)
                item_equal = compare_files(src_item, dst_item)

                if not item_equal:
                    if arguments['debug']:
                        logger.debug("\t{0} '{1}' == {0} '{2}'?\t{3}.".format(item, src_item, dst_item, item_equal))
                    ruleset_update[item].append(filename)

                    if item != 'rootchecks':
                        restart_ossec_needed = True
                    else:
                        # Restart ossec just if the rootcheck is enabled in ossec.conf
                        # The script does not activate the rootchecks.
                        if regex_in_file("\s*<.+>.*{0}</.+>".format(filename), ossec_conf):
                            restart_ossec_needed = True

    # Save ruleset
    ruleset_update["rules"] = sorted(ruleset_update["rules"])
    ruleset_update["decoders"] = sorted(ruleset_update["decoders"])
    ruleset_update["rootchecks"] = sorted(ruleset_update["rootchecks"])

    return ruleset_update, restart_ossec_needed


def upgrade_ruleset(ruleset):

    rm(update_backups)
    mkdir(update_backups)
    mkdir(update_backups_rules)
    mkdir(update_backups_decoders)
    mkdir(update_backups_rootchecks)

    for item in ruleset.keys():
        if not ruleset[item]:
            logger.log("You already have the latest version of {0}.".format(item))
            continue

        if item == 'rules':
            src = update_rules
            dst = ossec_rules
            backup = update_backups_rules
        elif item == 'decoders':
            src = update_decoders
            dst = ossec_decoders
            backup = update_backups_decoders
        elif item == 'rootchecks':
            src = update_rootchecks
            dst = ossec_rootchecks
            backup = update_backups_rootchecks

        logger.log("\nThe following {0} will be updated:".format(item))
        for filename in ruleset[item]:
            logger.log("\t{0}".format(filename))
            src_file = "{0}/{1}".format(src, filename)
            dst_file = "{0}/{1}".format(dst, filename)
            dst_backup = "{0}/{1}".format(backup, filename)
            copy(dst_file, dst_backup)
            copy(src_file, dst_file)


def restore_backups():
    for src in [update_backups_rules, update_backups_decoders, update_backups_rootchecks]:
        type_item = src.split('/')[-1]
        if type_item == 'rules':
            dst = ossec_rules
        elif type_item == 'decoders':
            dst = ossec_decoders
        elif type_item == 'rootchecks':
            dst = ossec_rootchecks

        backups_items = os.listdir(src)

        if backups_items:
            logger.log("\t{0}:".format(type_item))
        else:
            logger.log("\t{0}: Empty".format(type_item))

        for backup_item in backups_items:
            logger.log("\t\t{0}".format(backup_item))
            src_file = "{0}/{1}".format(src, backup_item)
            dst_file = "{0}/{1}".format(dst, backup_item)
            copy(src_file, dst_file)


def main():
    status = {'restart_required': False, 'restarted': False, 'success': False, 'msg': ""}

    # Previous checks
    is_wazuh, ossec_version = get_ossec_version()

    if not is_wazuh:
        exit(2, "OSSEC {0} detected. This script only supports Wazuh v2.0 or newer.".format(ossec_version))
    else:
        if float(ossec_version[2:5]) < 2.0:
            exit(2, "Wazuh {0} detected. This script only supports Wazuh v2.0 or newer.".format(ossec_version))

    # Main
    logger.log("### Wazuh ruleset ###")

    if arguments['backups']:
        logger.log("Restoring ruleset backup:")
        restore_backups()
        status['restart_required'] = True
        status['msg'] = "\nBackup restored successfully"
    else:
        # Get ruleset
        status['old_version'] = get_ruleset_version()
        status['new_version'] = get_new_ruleset(arguments['source'])
        ruleset_to_update, status['restart_required'] = get_ruleset_to_update(arguments['force'])

        # Update
        if not ruleset_to_update['rules'] and not ruleset_to_update['decoders'] and not ruleset_to_update['rootchecks']:
            status['msg'] = "\nYou already have the latest version of ruleset."
        else:
            upgrade_ruleset(ruleset_to_update)
            status['msg'] = "\nRuleset {0} updated to {1} successfully".format(status['old_version'], status['new_version'])

        rm(update_downloads)

    # Restart & messages
    if status['restart_required']:
        logger.log("\nOSSEC requires a restart to apply changes.")

        ans_restart = 'n'
        if arguments['restart'] == 'ask':
            ans_restart = get_stdin("Do you want to restart OSSEC now? [y/N]: ")
        else:
            ans_restart = 'n' if not arguments['restart'] else 'y'

        if ans_restart == "y" or ans_restart == "Y":
            no_output = ""
            if arguments['json']:
                no_output = " > /dev/null 2>&1"

            ret = 0
            ret = os.system("{0}/bin/ossec-control restart{1}".format(ossec_path, no_output))
            if ret != 0:
                exit(2, "OSSEC restart failed")
            status['restarted'] = True
        else:
            logger.log("Do not forget to restart OSSEC to apply changes.")

    logger.log(status['msg'])

    status['success'] = True

    if arguments['json']:
        print(dumps({'error': 0, 'data': status}))


def usage():
    msg = """
    Update ruleset v3.0.0
    Github repository: https://github.com/wazuh/wazuh-ruleset
    Full documentation: http://documentation.wazuh.com/en/latest/wazuh_ruleset.html

    Usage: ./update_ruleset.py                  # Update Decoders, Rules and Rootchecks
           ./update_ruleset.py -b               # Restore last backup

    Restart:
    \t-r, --restart       Restart OSSEC when required.
    \t-R, --no-restart    Do not restart OSSEC when required.

    Backups:
    \t-b , --backups      Restore last backup.

    Additional Params:
    \t-f, --force-update  Force to update the ruleset. By default, only it is updated the new/changed decoders/rules/rootchecks.
    \t-o, --ossec-path    Set OSSEC path. Default: '/var/ossec'
    \t-s, --source        Select ruleset source path (instead of download it).
    \t-j, --json          JSON output. It should be used with '-s' or '-S' argument.
    \t-d, --debug         Debug mode.
    """
    print(msg)


if __name__ == "__main__":

    if os.geteuid() != 0:
        print("You need root privileges to run this script. Please try again, using 'sudo'. Exiting.")
        sys.exit(1)

    file_permissions = 0o640
    file_permissions_x = 0o740
    try:
        root_uid = getpwnam("root").pw_uid
        ossec_gid = getgrnam("ossec").gr_gid
    except:
        sys.exit(1)

    # Arguments
    arguments = {'ossec_path': '/var/ossec', 'source': 'download', 'restart': 'ask', 'backups': False, 'force': False, 'debug': False, 'json': False}
    restart_args = 0

    try:
        opts, args = getopt(sys.argv[1:], "s:o:brRfdjh", ["backups", "source=", "ossec_path=", "restart", "no-restart", "force-update", "debug", "json", "help"])
        if len(opts) > 6:
            print("Incorrect number of arguments.\nTry './update_ruleset.py --help' for more information.")
            sys.exit(1)
    except GetoptError as err:
        print(str(err) + "\n" + "Try './update_ruleset.py --help' for more information.")
        sys.exit(1)

    for o, a in opts:
        if o in ("-b", "--backups"):
            arguments['backups'] = True
        elif o in ("-s", "--source"):
            arguments['source'] = a
        elif o in ("-o", "--ossec-path"):
            arguments['ossec_path'] = a
            if not os.path.exists(arguments['ossec_path']):
                print("ERROR: '{0}' does not exist.".format(arguments['ossec_path']))
                sys.exit(1)
        elif o in ("-r", "--restart"):
            arguments['restart'] = True
            restart_args += 1
        elif o in ("-R", "--no-restart"):
            arguments['restart'] = False
            restart_args += 1
        elif o in ("-f", "--force-update"):
            arguments['force'] = True
        elif o in ("-d", "--debug"):
            arguments['debug'] = True
        elif o in ("-j", "--json"):
            arguments['json'] = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit(0)
        else:
            usage()
            sys.exit(1)

    if restart_args > 1:
        print("Bad arguments combination.\nTry './update_ruleset.py --help' for more information.")
        sys.exit(1)

    # Capture Cntrl + C
    signal(SIGINT, signal_handler)

    ossec_path = arguments['ossec_path']
    ossec_ruleset_log = "{0}/logs/ruleset.log".format(ossec_path)
    ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)
    ossec_rootchecks = "{0}/etc/shared".format(ossec_path)
    ossec_update_script = "{0}/bin/update_ruleset.py".format(ossec_path)
    ossec_ruleset = "{0}/ruleset".format(ossec_path)
    ossec_rules = "{0}/rules".format(ossec_ruleset)
    ossec_decoders = "{0}/decoders".format(ossec_ruleset)
    ossec_ruleset_version_path = "{0}/VERSION".format(ossec_ruleset)

    update_downloads = "{0}/tmp/ruleset/downloads".format(ossec_path)
    update_ruleset = "{0}/wazuh-ruleset".format(update_downloads)
    update_rules = "{0}/rules".format(update_ruleset)
    update_decoders = "{0}/decoders".format(update_ruleset)
    update_rootchecks = "{0}/rootchecks".format(update_ruleset)
    update_backups = "{0}/tmp/ruleset/backups".format(ossec_path)
    update_backups_decoders = "{0}/decoders".format(update_backups)
    update_backups_rules = "{0}/rules".format(update_backups)
    update_backups_rootchecks = "{0}/rootchecks".format(update_backups)

    if arguments['json']:
        logger = RulesetLogger(tag="Wazuh-Ruleset", filename=ossec_ruleset_log, flag=RulesetLogger.O_FILE, debug=arguments['debug'])
    else:
        logger = RulesetLogger(tag="Wazuh-Ruleset", filename=ossec_ruleset_log, flag=RulesetLogger.O_ALL, debug=arguments['debug'])

    logger.debug("Arguments: {0}".format(arguments))

    try:
        main()
    except Exception as e:
        exit(2, "Unkown: {0}.\nExiting.".format(e))
