#!/usr/bin/env python
# Wazuh Ruleset Update

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

# Requirements:
#  Python 2.6 or newer
#  Wazuh
#  root privileges
# http://wazuh-documentation.readthedocs.io/en/latest/wazuh_ruleset.html

import contextlib
import os
import sys
from datetime import datetime
from filecmp import cmp
from getopt import GetoptError, getopt
from glob import glob
from grp import getgrnam
from json import dumps
from pwd import getpwnam
from re import sub, search
from shutil import copyfile, copytree, rmtree
from signal import signal, SIGINT
from time import time
from zipfile import ZipFile

import requests

# Set framework path
from wazuh.core import common
from wazuh.core.cluster.utils import read_config


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
            chown(filename, root_uid, ossec_gid)
            chmod(filename, 0o660)
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


def mkdir(path, perm=0o640):
    if not os.path.exists(path):
        os.makedirs(path)
        chown(path, root_uid, ossec_gid)
        chmod(path, perm)


def rename(src, dst, perm=0o640):
    os.rename(src, dst)
    chown(dst, root_uid, ossec_gid)
    chmod(dst, perm)


def copy(src, dst, perm=0o640):
    if os.path.isfile(src):
        copyfile(src, dst)
    else:
        copytree(src, dst)

    if perm == 0o750:
        chown(dst, root_uid, root_uid)
        chmod(dst, perm)
    else:
        chown(dst, root_uid, ossec_gid)
        chmod(dst, perm)


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
        current_branch = get_version_major_minor()  # standalone script

    return current_branch


def get_ossec_version():
    init_file = "{0}/etc/ossec-init.conf".format(common.ossec_path)

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


def get_version_major_minor():
    _, version = get_ossec_version()
    parts = version[2:-1].split('.')
    return '.'.join(parts[:-1])


def get_ruleset_version():
    try:
        with open(ossec_ruleset_version_path) as version_file:
            lines = version_file.readlines()
        rs_version = lines[0].split("=")[1].strip("\n\"")
    except:
        rs_version = "N/A"

    return rs_version


def get_new_ruleset(source, url, branch_name=None):
    mkdir(update_downloads)
    rm(update_ruleset)

    if source == 'download':
        if branch_name:
            branch = branch_name
        else:
            branch = get_branch()  # 'stable' 'master' 'development'

        if url:
            url_ruleset = url
        else:
            url_ruleset = "https://github.com/wazuh/wazuh-ruleset/archive/{0}.zip".format(branch)

        ruleset_zip = "{0}/ruleset.zip".format(update_downloads)

        logger.debug("Downloading ruleset from {0}.".format(url_ruleset, ))

        # Download
        try:
            f_url = requests.get(url_ruleset)
        except requests.exceptions.RequestException as e:
            exit(2, "\tDownload Error:{0}.\nExit.".format(e))

        if f_url.ok:
            with open(ruleset_zip, "wb") as f_local:
                for chunk in f_url.iter_content(chunk_size=128):
                    f_local.write(chunk)
        else:
            error = "Can't download the ruleset file from {}".format(url_ruleset)

        # Extract
        try:
            with contextlib.closing(ZipFile(ruleset_zip)) as z:
                zip_dir = search('^wazuh-ruleset-{0}([0-9a-z-]+)?$'.format(branch), z.namelist()[0].strip('/')).group(0)
                z.extractall(update_downloads)
        except Exception as e:
            exit(2, "\tError extracting file '{0}': {1}.".format(ruleset_zip, e))

        # Rename
        rename("{0}/{1}".format(update_downloads, zip_dir), update_ruleset)

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
    try:
        if os.path.isfile("{0}/update_ruleset".format(update_ruleset)):
            copy("{0}/update_ruleset".format(update_ruleset), ossec_update_script, 0o750)
        else:
            copy("{0}/update_ruleset.py".format(update_ruleset), ossec_update_script, 0o750)
    except Exception as e:
        exit(2, "Upgrade aborted: Update ruleset not found.")

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

        perm = 0o640
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
            perm = 0o660

        logger.log("\nThe following {0} will be updated:".format(item))
        for filename in ruleset[item]:
            logger.log("\t{0}".format(filename))
            src_file = "{0}/{1}".format(src, filename)
            dst_file = "{0}/{1}".format(dst, filename)
            dst_backup = "{0}/{1}".format(backup, filename)
            if os.path.exists(dst_file):
                copy(dst_file, dst_backup, perm)
            copy(src_file, dst_file, perm)

    msg = ""
    for type_r in deprecated.keys():
        if type_r == 'rules':
            path_file = ossec_rules
            path_file_bk = update_backups_rules
        elif type_r == 'decoders':
            path_file = ossec_decoders
            path_file_bk = update_backups_decoders

        for item in deprecated[type_r]:
            deprecated_file = "{0}/{1}".format(path_file, item)
            deprecated_file_bk = "{0}/{1}".format(path_file_bk, item)
            if os.path.exists(deprecated_file):
                msg += "\t{0}\n".format(deprecated_file)
                copy(deprecated_file, deprecated_file_bk)
                os.remove(deprecated_file)

    if msg:
        logger.log("\nThe following deprecated files will be removed:\n{0}".format(msg))


def restore_backups():
    error_msg = "ERROR: No backups availables. Exiting..."
    try:
        directories = os.listdir(update_backups)
        if directories != []:
            for src in [update_backups_rules, update_backups_decoders, update_backups_rootchecks]:
                type_item = src.split('/')[-1]
                if type_item == 'rules':
                    dst = ossec_rules
                elif type_item == 'decoders':
                    dst = ossec_decoders
                elif type_item == 'rootchecks':
                    dst = ossec_rootchecks

                # try:
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
        else:
            raise Exception(error_msg)
    except Exception as e:
        logger.log("{0}".format(error_msg))
        sys.exit(1)


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
        # version temporary backup

        copy(ossec_ruleset_version_path, ossec_ruleset_version_path + '-old')
        try:
            copy(ossec_update_script, ossec_update_script + '-old', 0o750)
        except:
            copy(ossec_update_script + ".py", ossec_update_script + '-old', 0o750)
        # Get ruleset
        status['old_version'] = get_ruleset_version()
        status['new_version'] = get_new_ruleset(arguments['source'], arguments['url'], arguments['branch-name'])
        # Compare major
        old_version = ossec_version.replace('"', '')
        if not same_major_minor(old_version, status['new_version']):
            copy(ossec_ruleset_version_path + '-old', ossec_ruleset_version_path)
            copy(ossec_update_script + '-old', ossec_update_script, 0o750)
            os.remove(ossec_update_script + '-old')
            os.remove(ossec_ruleset_version_path + '-old')
            exit(2, "Upgrade aborted: Unexpected version in the new ruleset. " + \
                 "Expected version {0}. Found version {1}".format(old_version[:-1] + 'x',
                                                                  status['new_version']))
        # remove temporary files
        os.remove(ossec_update_script + '-old')
        os.remove(ossec_ruleset_version_path + '-old')

        ruleset_to_update, status['restart_required'] = get_ruleset_to_update(arguments['force'])

        # Update
        if not ruleset_to_update['rules'] and not ruleset_to_update['decoders'] and not ruleset_to_update['rootchecks']:
            status['msg'] = "\nYou already have the latest version of ruleset."
        else:
            upgrade_ruleset(ruleset_to_update)
            status['msg'] = "\nRuleset {0} updated to {1} successfully".format(status['old_version'],
                                                                               status['new_version'])

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


def same_major_minor(old_version, new_version):
    old_major, old_minor, old_patch = old_version.split(".")
    new_major, new_minor, new_patch = new_version.split(".")

    old_patch, new_patch = old_patch.split("-")[0], new_patch.split("-")[0]

    if old_major == new_major and old_minor == new_minor and old_patch <= new_patch:
        return True
    else:
        return False


def usage():
    branch = get_branch()  # 'stable' 'master' 'development'
    msg = """
    Update ruleset
    Github repository: https://github.com/wazuh/wazuh-ruleset
    Full documentation: https://documentation.wazuh.com/current/user-manual/ruleset/index.html

    Usage: ./update_ruleset                  # Update Decoders, Rules and Rootchecks
           ./update_ruleset -b               # Restore last backup

    Restart:
    \t-r, --restart       Restart OSSEC when required.
    \t-R, --no-restart    Do not restart OSSEC when required.

    Backups:
    \t-b , --backups      Restore last backup.

    Additional Params:
    \t-f, --force-update  Force to update the ruleset. By default, only it is updated the new/changed decoders/rules/rootchecks.
    \t-s, --source        Select ruleset source path (instead of download it).
    \t-j, --json          JSON output. It should be used with '-s' argument.
    \t-d, --debug         Debug mode.
    \t-u, --url           URL of ruleset zip (default: https://github.com/wazuh/wazuh-ruleset/archive/$BRANCH-NAME.zip)
    \t                    It requires -n parameter.
    \t-n, --branch-name   Branch name (default: {0})
    """.format(branch)
    print(msg)


if __name__ == "__main__":
    cluster_config = read_config()

    if cluster_config['node_type'] != 'master' and not cluster_config['disabled']:
        executable_name = "update_ruleset"
        master_ip = cluster_config['nodes'][0]
        print("Wazuh is running in cluster mode: {EXECUTABLE_NAME} is not available in worker nodes. "
              "Please, try again in the master node: {MASTER_IP}".format(EXECUTABLE_NAME=executable_name,
                                                                         MASTER_IP=master_ip))
        sys.exit(1)

    if os.geteuid() != 0:
        print("You need root privileges to run this script. Please try again, using 'sudo'. Exiting.")
        sys.exit(1)

    try:
        root_uid = getpwnam("root").pw_uid
        ossec_gid = getgrnam("ossec").gr_gid
    except:
        sys.exit(1)

    # Arguments
    arguments = {'source': 'download', 'restart': 'ask', 'backups': False, 'force': False, 'debug': False,
                 'json': False, 'branch-name': False, 'url': False}
    restart_args = 0

    try:
        opts, args = getopt(sys.argv[1:], "s:o:n:u:brRfdjh",
                            ["backups", "source=", "ossec_path=", "restart", "no-restart", "force-update", "debug",
                             "json", "help", "branch-name=", "url="])
        if len(opts) > 6:
            print("Incorrect number of arguments.\nTry './update_ruleset --help' for more information.")
            sys.exit(1)
    except GetoptError as err:
        print(str(err) + "\n" + "Try './update_ruleset --help' for more information.")
        sys.exit(1)

    branch_found = False
    url_found = False

    for o, a in opts:
        if o in ("-b", "--backups"):
            arguments['backups'] = True
        elif o in ("-s", "--source"):
            arguments['source'] = a
        elif o in ("-o", "--ossec-path"):
            print("WARNING: Deprecated argument -o, --ossec_path. Using {}.".format(common.ossec_path))
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
        elif o in ("-n", "--branch-name"):
            arguments['branch-name'] = a
            branch_found = True
        elif o in ("-u", "--url"):
            arguments['url'] = a
            url_found = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit(0)
        else:
            usage()
            sys.exit(1)

    if url_found and not branch_found:
        zip_file = arguments['url'].split('/')[-1]
        arguments['branch-name'] = zip_file[:-4]
        print("Warning: Branch argument is missing. Using the branch from the url.")
        print("Branch name: {0}".format(arguments['branch-name']))

        # print("Bad arguments combination.\nURL parameter should be specified with a Branch name.")
        # sys.exit(1)

    if restart_args > 1:
        print("Bad arguments combination.\nTry './update_ruleset --help' for more information.")
        sys.exit(1)

    # Capture Cntrl + C
    signal(SIGINT, signal_handler)

    ossec_path = common.ossec_path
    ossec_ruleset_log = "{0}/logs/ruleset.log".format(ossec_path)
    ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)
    ossec_rootchecks = "{0}/etc/rootcheck".format(ossec_path)
    ossec_update_script = sys.argv[0]
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

    deprecated = {'rules': ['0355-amazon-ec2_rules.xml', '0370-amazon-iam_rules.xml', '0465-amazon-s3_rules.xml',
                            '0470-suricata_rules.xml', '0520-vulnerability-detector.xml',
                            '0565-ms_ipsec_rules_json.xml'],
                  'decoders': ['0020-amazon_decoders.xml', '0005-json_decoders.xml']}

    if arguments['json']:
        logger = RulesetLogger(tag="Wazuh-Ruleset", filename=ossec_ruleset_log, flag=RulesetLogger.O_FILE,
                               debug=arguments['debug'])
    else:
        logger = RulesetLogger(tag="Wazuh-Ruleset", filename=ossec_ruleset_log, flag=RulesetLogger.O_ALL,
                               debug=arguments['debug'])

    logger.debug("Arguments: {0}".format(arguments))

    try:
        main()
    except Exception as e:
        exit(2, "Unknown: {0}.\nExiting.".format(e))
