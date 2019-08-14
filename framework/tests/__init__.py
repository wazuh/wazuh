#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import unittest
import test_agent

def main():
    print("Wazuh HIDS Library Tests")
    agent_suite = test_agent.load_tests()
    alltests = unittest.TestSuite([agent_suite])
    unittest.TextTestRunner(verbosity=2).run(alltests)
    # print(alltests.run(unittest.TestResult()))
