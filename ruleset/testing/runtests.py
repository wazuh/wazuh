#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation

import ConfigParser
import subprocess
import os
import sys
from collections import OrderedDict
import shutil
import argparse
import re
import signal

rules_test_fname_pattern = re.compile('^test_(.*?)_rules.xml$')
decoders_test_fname_pattern = re.compile('^test_(.*?)_decoders.xml$')

class MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(MultiOrderedDict, self).__setitem__(key, value)


def getOssecConfig(initconf, path):
    if os.path.isfile(path):
        with open(path) as f:
            for line in f.readlines():
                key, value = line.rstrip("\n").split("=")
                initconf[key] = value.replace("\"", "")
        if initconf["NAME"] != "Wazuh" or not os.path.exists(initconf["DIRECTORY"]):
            print "Seems like there is no correct Wazuh installation "
            sys.exit(1)
    else:
        print "Seems like there is no Wazuh installation or ossec-init.conf is missing."
        sys.exit(1)


def provisionDR():
    base_dir = os.path.dirname(os.path.realpath(__file__))
    rules_dir = os.path.join(base_dir, "rules")
    decoders_dir = os.path.join(base_dir, "decoders") 

    for file in os.listdir(rules_dir):
        file_fullpath = os.path.join(rules_dir, file)
        if os.path.isfile(file_fullpath) and re.match(r'^test_(.*?)_rules.xml$',file):
            shutil.copy2(file_fullpath , ossec_init["DIRECTORY"] + "/etc/rules")

    for file in os.listdir(decoders_dir):
        file_fullpath = os.path.join(decoders_dir, file)
        if os.path.isfile(file_fullpath) and re.match(r'^test_(.*?)_decoders.xml$',file):
            shutil.copy2(file_fullpath , ossec_init["DIRECTORY"] + "/etc/decoders")

def cleanDR():
    rules_dir = ossec_init["DIRECTORY"] + "/etc/rules"
    decoders_dir = ossec_init["DIRECTORY"] + "/etc/decoders"

    for file in os.listdir(rules_dir):
        file_fullpath = os.path.join(rules_dir, file)
        if os.path.isfile(file_fullpath) and re.match(r'^test_(.*?)_rules.xml$',file):
            os.remove(file_fullpath)

    for file in os.listdir(decoders_dir):
        file_fullpath = os.path.join(decoders_dir, file)
        if os.path.isfile(file_fullpath) and re.match(r'^test_(.*?)_decoders.xml$',file):
            os.remove(file_fullpath)

def restart_analysisd():
    print "Restarting wazuh-manager..."
    ret = os.system('systemctl restart wazuh-manager')

class OssecTester(object):
    def __init__(self, bdir):
        self._error = False
        self._debug = False
        self._quiet = False
        self._ossec_path = bdir + "/bin/"
        self._test_path = "./tests"

    def buildCmd(self, rule, alert, decoder):
        cmd = ['%s/wazuh-logtest' % (self._ossec_path), ]
        cmd += ['-q']
        cmd += ['-U', "%s:%s:%s" % (rule, alert, decoder)]
        return cmd

    def runTest(self, log, rule, alert, decoder, section, name, negate=False):
        p = subprocess.Popen(
            self.buildCmd(rule, alert, decoder),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            shell=False)
        std_out = p.communicate(log)[0]
        if (p.returncode != 0 and not negate) or (p.returncode == 0 and negate):
            self._error = True
            print ""
            print "-" * 60
            print "Failed: Exit code = %s" % (p.returncode)
            print "        Alert     = %s" % (alert)
            print "        Rule      = %s" % (rule)
            print "        Decoder   = %s" % (decoder)
            print "        Section   = %s" % (section)
            print "        line name = %s" % (name)
            print " "
            print std_out
        elif self._debug:
            print "Exit code= %s" % (p.returncode)
            print std_out
        else:
            sys.stdout.write(".")
            sys.stdout.flush()

    def run(self, selective_test=False, geoip=False, custom=False):
        for aFile in os.listdir(self._test_path):
            if re.match(r'^test_(.*?).ini$',aFile) and not custom:
                continue
            aFile = os.path.join(self._test_path, aFile)
            if aFile.endswith(".ini"):
                if selective_test and not aFile.endswith(selective_test):
                    continue
                if geoip is False and aFile.endswith("geoip.ini"):
                    continue
                print "- [ File = %s ] ---------" % (aFile)
                tGroup = ConfigParser.RawConfigParser(dict_type=MultiOrderedDict)
                tGroup.read([aFile])
                tSections = tGroup.sections()
                for t in tSections:
                    rule = tGroup.get(t, "rule")
                    alert = tGroup.get(t, "alert")
                    decoder = tGroup.get(t, "decoder")
                    for (name, value) in tGroup.items(t):
                        if name.startswith("log "):
                            if self._debug:
                                print "-" * 60
                            if name.endswith("pass"):
                                neg = False
                            elif name.endswith("fail"):
                                neg = True
                            else:
                                neg = False
                            self.runTest(value, rule, alert, decoder,
                                         t, name, negate=neg)
                print ""
                print ""
        return self._error

def cleanup(*args):
    cleanDR()
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script tests Wazuh rules.')
    parser.add_argument('--geoip', '-g', action='store_true', dest='geoip',
                        help='Use -g or --geoip to enable geoip tests (default: False)')
    parser.add_argument('--testfile', '-t', action='store', type=str, dest='testfile',
                        help='Use -t or --testfile to pass the ini file to test')
    parser.add_argument('--custom-ruleset', '-c', action='store_true', dest='custom',
                        help='Use -c or --custom-ruleset to test custom rules and decoders. WARNING: This will cause wazuh-manager restart')
    args = parser.parse_args()
    selective_test = False
    if args.testfile:
        selective_test = args.testfile
        if not selective_test.endswith('.ini'):
            selective_test += '.ini'
    ossec_init = {}
    initconfigpath = "/etc/ossec-init.conf"
    getOssecConfig(ossec_init, initconfigpath)
    for sig in (signal.SIGABRT, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cleanup)
    if args.custom:
        provisionDR()
        restart_analysisd()
    OT = OssecTester(ossec_init["DIRECTORY"])
    error = OT.run(selective_test, args.geoip, args.custom)
    if args.custom:
        cleanDR()
        restart_analysisd()
    if error:
        sys.exit(1)
