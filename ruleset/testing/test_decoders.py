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

def decoded_fields(std_out):
    fields = None

    if re.search(r'No decoder matched.', std_out):
        return fields
    else:
        decoder_section = re.search(r"Completed decoding.\n\s+(?P<section>(.|\n)*)\*\*Phase 3: Completed filtering", std_out)
        decoder_fields_text = decoder_section.group("section")
        fields = re.findall("(\S+): (.+)\n", decoder_fields_text)

    return fields


class OssecTester(object):

    def __init__(self, bdir):
        self._error = False
        self._ossec_path = bdir + "/bin/"
        self._test_path = "./decoder_tests"


    def buildCmd(self):
        cmd = ['%s/wazuh-logtest' % (self._ossec_path), ]
        return cmd

    def runTest(self, log):
        p = subprocess.Popen(
            self.buildCmd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            shell=False,
            universal_newlines=True)
        std_out = p.communicate(log)[0]
        sys.stdout.write(".")
        sys.stdout.flush()
        return decoded_fields(std_out)


    def run(self, selective_test=False):
        for a_ini_file in os.listdir(self._test_path):
            a_ini_file = os.path.join(self._test_path, a_ini_file)
            if a_ini_file.endswith(".ini"):
                if selective_test and not a_ini_file.endswith(selective_test):
                    continue

                print("- [ File = %s ] ---------" % (a_ini_file))
                tGroup = ConfigParser.RawConfigParser(dict_type=MultiOrderedDict)
                tGroup.read([a_ini_file])
                tSections = tGroup.sections()
                for t in tSections:
                    log = tGroup.get(t, "log")
                    fields_tuples = self.runTest(log)
                    if fields_tuples:
                        if len(fields_tuples)+1 == len(tGroup.items(t)):
                            for field, value in fields_tuples:
                                try:
                                    if tGroup.get(t,field) != value:
                                        print("\nFailed: ["+t+"]")
                                        print("For field "+field+" expected value was:"+tGroup.get(t,field))
                                        print("Decoded value was: "+ value)
                                        self._error = True
                                except Exception as e:
                                    print("\nFailed: ["+t+"]")
                                    print("Unexpected field was decoded")
                                    print(e)
                                    self._error = True
                        else:
                            if len(fields_tuples)+1 > len(tGroup.items(t)):
                                print("\nFailed: ["+t+"]")
                                print("Decoded more fields than expected")
                            else:
                                print("\nFailed: ["+t+"]")
                                print("Decoded less fields than expected")
                            print("Expected fields/values: "+str(tGroup.items(t)))
                            print("Decoded fields/values: "+str(fields_tuples))
                            self._error = True

                    else:
                        print("\nFailed: ["+t+"]")
                        print("No fields were decoded from log!")
                        self._error = True

                print("\n\n")


def cleanup(*args):
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script tests Wazuh rules.')
    parser.add_argument('--path', '-p', default='/var/ossec', dest='wazuh_home',
                        help='Use -p or --path to specify Wazuh installation path')
    parser.add_argument('--testfile', '-t', action='store', type=str, dest='testfile',
                        help='Use -t or --testfile to pass the ini file to test')

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


    OT = OssecTester(args.wazuh_home)
    error = OT.run(selective_test)

#     rules = get_rule_ids("/var/ossec/ruleset/rules/")
#     decoders = get_parent_decoder_names("/var/ossec/ruleset/decoders/")
#
#     template = "|{: ^10}|{: ^10}|{: ^10}|{: ^10}|"
#     print(template.format("Component", "Tested", "Total", "Coverage"))
#     print(template.format("--------", "--------", "--------", "--------"))
#     template = "|{: ^10}|{: ^10}|{: ^10}|{: ^10.2%}|"
#     print(template.format("Rules", len(OT.tested_rules), len(rules), len(OT.tested_rules)/len(rules)))
#     print(template.format("Decoders", len(OT.tested_decoders), len(decoders), len(OT.tested_decoders)/len(decoders)))
#     print("\n")


    if error:
        sys.exit(1)
