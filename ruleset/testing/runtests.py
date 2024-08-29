#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation

from __future__ import division
from collections import OrderedDict
import xml.etree.ElementTree as ET
import ConfigParser
import subprocess
import os
import sys
import shutil
import argparse
import re
import signal

from coverage import get_rule_ids
from coverage import get_parent_decoder_names



class MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(MultiOrderedDict, self).__setitem__(key, value)


def getWazuhInfo(wazuh_home):
    wazuh_control = os.path.join(wazuh_home, "bin", "wazuh-control")
    wazuh_env_vars = {}
    try:
        proc = subprocess.Popen([wazuh_control, "info"], stdout=subprocess.PIPE)
        (stdout, stderr) = proc.communicate()
    except Exception as e:
        print("Seems like there is no Wazuh installation.")
        return None

    env_variables = stdout.rsplit("\n")
    env_variables.remove("")
    for env_variable in env_variables:
        key, value = env_variable.split("=")
        wazuh_env_vars[key] = value.replace("\"", "")

    return wazuh_env_vars


def provisionDR():
    base_dir = os.path.dirname(os.path.realpath(__file__))
    rules_dir = os.path.join(base_dir, "ruleset")
    decoders_dir = os.path.join(base_dir, "ruleset")

    for file in os.listdir(rules_dir):
        file_fullpath = os.path.join(rules_dir, file)
        if os.path.isfile(file_fullpath) and re.match(r'^test_(.*_)?rules.xml$', file):
            shutil.copy2(file_fullpath, args.wazuh_home + "/etc/rules")

    for file in os.listdir(decoders_dir):
        file_fullpath = os.path.join(decoders_dir, file)
        if os.path.isfile(file_fullpath) and re.match(r'^test_(.*_)?decoders.xml$', file):
            shutil.copy2(file_fullpath, args.wazuh_home + "/etc/decoders")



def cleanDR():
    rules_dir = args.wazuh_home + "/etc/rules"
    decoders_dir = args.wazuh_home + "/etc/decoders"

    for file in os.listdir(rules_dir):
        file_fullpath = os.path.join(rules_dir, file)
        if os.path.isfile(file_fullpath) and re.match(r'^test_(.*_)?rules.xml$', file):
            os.remove(file_fullpath)

    for file in os.listdir(decoders_dir):
        file_fullpath = os.path.join(decoders_dir, file)
        if os.path.isfile(file_fullpath) and re.match(r'^test_(.*_)?decoders.xml$', file):
            os.remove(file_fullpath)



def enable_win_eventlog_test_actions(tree):
    base_rule = tree.find('.//rule[@id="60000"]')
    base_rule.remove(base_rule.find(".//decoded_as"))
    base_rule.remove(base_rule.find(".//category"))
    decoded_as = ET.SubElement(base_rule, "decoded_as")
    decoded_as.text = "json"


def disable_win_eventlog_test_actions(tree):
    base_rule = tree.find('.//rule[@id="60000"]')
    base_rule.remove(base_rule.find(".//decoded_as"))
    decoded_as = ET.SubElement(base_rule, "decoded_as")
    decoded_as.text = "windows_eventchannel"
    category = ET.SubElement(base_rule, "category")
    category.text = "ossec"


def modify_win_eventlog_testing(action):
    win_base_rules_file = "/var/ossec/ruleset/rules/0575-win-base_rules.xml"
    actions = {"enable": enable_win_eventlog_test_actions, "disable": disable_win_eventlog_test_actions}
    tree = ET.parse(win_base_rules_file)
    actions[action](tree)
    tree.write(win_base_rules_file)


def enable_win_eventlog_tests():
    modify_win_eventlog_testing("enable")


def disable_win_eventlog_tests():
    modify_win_eventlog_testing("disable")


def gather_failed_test_data(std_out, alert, rule, decoder, section, line_name):
    failed_test = {"expected_level": alert,
                   "expected_rule":  rule,
                   "expected_decoder": decoder,
                   "section": section,
                   "line_name": line_name,
                   "actual_rule": "",
                   "actual_level": "",
                   "description": ""}

    if re.search(r'No decoder matched.', std_out):
        failed_test["actual_decoder"] = ""
    else:
        decoder_search = re.search(r"Completed decoding.\n\tname:\s*\'(?P<decoder>[\w-]*)", std_out)
        failed_test["actual_decoder"] = decoder_search.group("decoder")

        if re.search(r"Phase 3: Completed filtering \(rules\)", std_out):
            rule_search = re.search(r"Completed filtering \(rules\)\.\n\tid:\s+\'(?P<rule_id>\d+)\W+level:\s*'(?P<level>\d+)\W+description:\s+'(?P<description>.*?)'", std_out)
            failed_test["actual_rule"] = rule_search.group("rule_id")
            failed_test["actual_level"] = rule_search.group("level")
            failed_test["description"] = rule_search.group("description")

    return failed_test


class OssecTester(object):

    def __init__(self, bdir):
        self._error = False
        self._debug = False
        self._quiet = False
        self._ossec_path = bdir + "/bin/"
        self._test_path = "./tests"
        self._execution_data = {}
        self._failed_tests = []
        self.tested_rules = set()
        self.tested_decoders = set()

    def buildCmd(self, rule, alert, decoder):
        cmd = ['%s/wazuh-logtest' % (self._ossec_path), ]
        cmd += ['-U', "%s:%s:%s" % (rule, alert, decoder)]
        return cmd

    def runTest(self, log, rule, alert, decoder, section, name, negate=False):
        test_status = "failed"
        self.tested_rules.add(rule)
        self.tested_decoders.add(decoder)
        p = subprocess.Popen(
            self.buildCmd(rule, alert, decoder),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            shell=False,
            universal_newlines=True)
        std_out = p.communicate(log)[0]
        if (p.returncode != 0 and not negate) or (p.returncode == 0 and negate):
            self._error = True
            print("")
            print("-" * 60)
            print("Failed: Exit code = %s" % (p.returncode))
            print("        Alert     = %s" % (alert))
            print("        Rule      = %s" % (rule))
            print("        Decoder   = %s" % (decoder))
            print("        Section   = %s" % (section))
            print("        line name = %s" % (name))
            print(" ")
            self._failed_tests.append(gather_failed_test_data(std_out, alert, rule, decoder, section, name))
        elif self._debug:
            print("Exit code= %s" % (p.returncode))
            print(std_out)
        else:
            sys.stdout.write(".")
            test_status = "passed"
            sys.stdout.flush()
        return test_status

    def run(self, selective_test=False, geoip=False):
        for a_ini_file in os.listdir(self._test_path):
            a_ini_file = os.path.join(self._test_path, a_ini_file)
            if a_ini_file.endswith(".ini"):
                if selective_test and not a_ini_file.endswith(selective_test):
                    continue
                if geoip is False and a_ini_file.endswith("geoip.ini"):
                    continue
                self._execution_data[a_ini_file] = {"passed": 0, "failed": 0}
                print("- [ File = %s ] ---------" % (a_ini_file))
                tGroup = ConfigParser.RawConfigParser(dict_type=MultiOrderedDict)
                tGroup.read([a_ini_file])
                tSections = tGroup.sections()
                for t in tSections:
                    rule = tGroup.get(t, "rule")
                    alert = tGroup.get(t, "alert")
                    decoder = tGroup.get(t, "decoder")
                    for (name, value) in tGroup.items(t):
                        if name.startswith("log "):
                            if self._debug:
                                print("-" * 60)
                            if name.endswith("pass"):
                                neg = False
                            elif name.endswith("fail"):
                                neg = True
                            else:
                                neg = False
                            self._execution_data[a_ini_file][self.runTest(value, rule, alert, decoder, t, name, negate=neg)] += 1
                print("\n\n")
        return self._error

    def print_results(self):
        template = "|{: ^25}|{: ^10}|{: ^10}|{: ^10}|"
        print(template.format("File", "Passed", "Failed", "Status"))
        print(template.format("--------", "--------", "--------", "--------"))
        template = "|{: <25}|{: ^10}|{: ^10}|{: ^10}|"
        for test_name in self._execution_data:
            passed_count = self._execution_data[test_name]["passed"]
            failed_count = self._execution_data[test_name]["failed"]
            status = u'\u274c'.encode('utf-8') if (failed_count > 0) else u'\u2705'.encode('utf-8')
            print(template.format(test_name, passed_count, failed_count, status))

        if len(self._failed_tests):
            template = "|{: <10} |{: ^25}|{: ^25}|"
            print("\n\nFailing tests summary:")
            for failed_test in self._failed_tests:
                if failed_test["actual_decoder"] == "":
                    summary = "Log was unable to be decoded"
                elif failed_test["actual_decoder"] != failed_test["expected_decoder"]:
                    summary = "Log decoded by unexpected decoder. Expected: " + failed_test["expected_decoder"] + ". Got: " + failed_test["actual_decoder"]
                elif failed_test["actual_rule"] != failed_test["expected_rule"]:
                    summary = "Hit a different rule. Expected: " + failed_test["expected_rule"] + ". Got: " + failed_test["actual_rule"]
                elif failed_test["actual_level"] != failed_test["expected_level"]:
                    summary = "Unexpected alert level. Expected: " + failed_test["expected_level"] + ". Got: " + failed_test["actual_level"]

                print("----------------------------------------")
                print("Failed test: " + failed_test["section"])
                print("Failed log: " + failed_test["line_name"])
                print("Summary: " + summary)
                print(template.format("", "Expected", "Result"))
                print(template.format("------", "------", "------"))
                print(template.format("Decoder", failed_test["expected_decoder"], failed_test["actual_decoder"]))
                print(template.format("Rule", failed_test["expected_rule"], failed_test["actual_rule"]))
                print(template.format("Level", failed_test["expected_level"], failed_test["actual_level"]))


def cleanup(*args):
    cleanDR()
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script tests Wazuh rules.')
    parser.add_argument('--path', '-p', default='/var/ossec', dest='wazuh_home',
                        help='Use -p or --path to specify Wazuh installation path')
    parser.add_argument('--geoip', '-g', action='store_true', dest='geoip',
                        help='Use -g or --geoip to enable geoip tests (default: False)')
    parser.add_argument('--testfile', '-t', action='store', type=str, dest='testfile',
                        help='Use -t or --testfile to pass the ini file to test')
    parser.add_argument('--skip-windows-eventchannel', '-s', action='store_false', dest='windows_tests',
                        help='Use -s or --skip-windows-eventchannel to avoid modifying windows event channel rules for testing.')
    args = parser.parse_args()
    selective_test = False
    if args.testfile:
        selective_test = args.testfile
        if not selective_test.endswith('.ini'):
            selective_test += '.ini'

    wazuh_info = getWazuhInfo(args.wazuh_home)
    if wazuh_info is None:
        sys.exit(1)

    for sig in (signal.SIGABRT, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cleanup)

    if args.windows_tests:
        enable_win_eventlog_tests()

    provisionDR()
    OT = OssecTester(args.wazuh_home)
    error = OT.run(selective_test, args.geoip)

    cleanDR()
    if args.windows_tests:
        disable_win_eventlog_tests()

    rules = get_rule_ids("/var/ossec/ruleset/rules/")
    decoders = get_parent_decoder_names("/var/ossec/ruleset/decoders/")

    template = "|{: ^10}|{: ^10}|{: ^10}|{: ^10}|"
    print(template.format("Component", "Tested", "Total", "Coverage"))
    print(template.format("--------", "--------", "--------", "--------"))
    template = "|{: ^10}|{: ^10}|{: ^10}|{: ^10.2%}|"
    print(template.format("Rules", len(OT.tested_rules), len(rules), len(OT.tested_rules)/len(rules)))
    print(template.format("Decoders", len(OT.tested_decoders), len(decoders), len(OT.tested_decoders)/len(decoders)))
    print("\n")

    OT.print_results()

    if error:
        sys.exit(1)
