# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import operator
from unittest import TestCase

from wazuh.core.InputValidator import InputValidator


class TestInputValidator(TestCase):

    def test_check_name(self):
        result = InputValidator().check_name('test')
        self.assertEqual(result, True)

        result = InputValidator().check_name('test', '')
        self.assertEqual(result, False)

        result = InputValidator().check_name('?')
        self.assertEqual(result, False)

    def test_check_length(self):
        result = InputValidator().check_length('test')
        self.assertEqual(result, True)

        result = InputValidator().check_length('test', 3)
        self.assertEqual(result, False)

        result = InputValidator().check_length('test', 4, operator.eq)
        self.assertEqual(result, True)

    def test_group(self):
        result = InputValidator().group('test')
        self.assertEqual(result, True)

        result = InputValidator().group(['test1', 'test2'])
        self.assertEqual(result, True)

        result = InputValidator().group('TesT')
        self.assertEqual(result, True)

        result = InputValidator().group(['teSt1', 'test2', 'Test3', 'test_1', 'test-1'])
        self.assertEqual(result, True)

        result = InputValidator().group('.')
        self.assertEqual(result, False)

        result = InputValidator().group(['', '..', '.group', 'group.conf'])
        self.assertEqual(result, False)
