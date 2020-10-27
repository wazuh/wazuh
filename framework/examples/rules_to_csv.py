#!/usr/bin/env python

###
#  Copyright (C) 2015-2020, Wazuh Inc.All rights reserved.
#  Wazuh.com
#
#  This program is free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###

# Instructions:
#  - Use the embedded interpreter to run the script: {wazuh_path}/framework/python/bin/python3 rules_to_csv.py

import csv
import sys

import wazuh.rule

if __name__ == '__main__':

    row_list = [['ID', 'description', 'level', 'filename', 'status', 'details', 'groups', 'relative_dirname', 'gdpr',
                 'gdpr13', 'hipaa', 'mitre', 'nist_800_53', 'pci_dss', 'tsc']]
    n_rules = 5000
    if len(sys.argv) > 1:
        n_rules = int(sys.argv[1])

    for step in range(0, n_rules, 500):
        result = wazuh.rule.get_rules(limit=500, offset=step).render()
        if not result:
            break

        for rule in result['data']['affected_items']:
            row_list.append([rule['id'], rule['description'], rule['level'], rule['filename'], rule['status'],
                             rule['details'], rule['groups'], rule['relative_dirname'], rule['gdpr'], rule['gpg13'],
                             rule['hipaa'], rule['mitre'], rule['nist_800_53'], rule['pci_dss'], rule['tsc']])

    with open('rules.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(row_list)

    print("Done")
