#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath('.'))
from wazuh.agent import Agent

class NewAgentTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.agent = Agent()  # Test add
        self.id = self.agent.add('TestAgent', 'any')

    @classmethod
    def tearDownClass(self):
        self.agent.remove()  # Test remove

    def test_valid_id(self):
        self.assertIsInstance(int(self.id), int, 'Returned ID is not valid')

    def test_get_key(self):
        self.assertTrue(self.agent.get_key(), 'Invalid key')

    def test_get(self):
        self.agent.get()
        self.assertEqual(self.agent.name, 'TestAgent')


class AgentTestCase(unittest.TestCase):

    def test_agent_overview(self):
        agents = Agent.get_agents_overview()
        self.assertGreater(agents['totalItems'], 1)
        self.assertTrue(agents['items'], 'No agents: items')

def load_tests():
    test_cases = [NewAgentTestCase, AgentTestCase]
    suite = unittest.TestSuite()
    for test_class in test_cases:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    return suite

if __name__ == '__main__':
    #unittest.main()
    suite = load_tests()
    unittest.TextTestRunner(verbosity=2).run(suite)
