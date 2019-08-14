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
import json
# cwd = /var/ossec/api/framework/examples
#framework_path = '{0}'.format(path[0][:-9])
# cwd = /var/ossec/api
#framework_path = '{0}/framework'.format(path[0])
# Default path
framework_path = '/var/ossec/api/framework'
path.append(framework_path)

try:
    from wazuh import Wazuh
    from wazuh.agent import Agent
except Exception as e:
    print("No module 'wazuh' found.")
    exit()

if __name__ == "__main__":

    # Creating wazuh object
    # It is possible to specify the ossec path (path argument) or get /etc/ossec-init.conf (get_init argument)
    print("\nWazuh:")
    myWazuh = Wazuh(get_init=True)
    print(myWazuh)

    print("\nAgents:")
    agents = Agent.get_agents_overview()
    print(json.dumps(agents, indent=4, sort_keys=True))
