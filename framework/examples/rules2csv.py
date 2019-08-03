#!/usr/bin/env python

###
#  Copyright (C) 2015-2019, Wazuh Inc.All rights reserved.
#  Wazuh.com
#
#  This program is a free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###

# Instructions:
#  - Configure the framework_path variable.
#  Optional:
#  - Configure the python path. Example for python27 package in Centos6
#    - export PATH=$PATH:/opt/rh/python27/root/usr/bin
#    - export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/rh/python27/root/usr/lib64
#  - Use the wazuh sqlite lib
#    - export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/var/ossec/framework/lib

from sys import path, exit
# cwd = /var/ossec/api/framework/examples
#framework_path = '{0}'.format(path[0][:-9])
# cwd = /var/ossec/api
#framework_path = '{0}/framework'.format(path[0])
# Default path
framework_path = '/var/ossec/api/framework'
path.append(framework_path)

try:
    from wazuh.rule import Rule
except Exception as e:
    print("No module 'wazuh' found.")
    exit()

print("file;id;description;level;status;groups;pci;details")
for rule in Rule.get_rules(status='enabled', limit=None, sort={"fields":["file"],"order":"asc"})['items']:
    print("{0};{1};{2};{3};{4};{5};{6};{7}".format(rule.file, rule.id, rule.description, rule.level, rule.status, rule.groups, rule.pci, rule.details))
