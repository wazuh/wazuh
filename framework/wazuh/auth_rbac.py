#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from wazuh.RBAC import RBAC


class RBAChecker:
    _logics = ['AND', 'OR', 'NOT']
    _functions = ['MATCH', 'MATCH$', 'FIND', 'FIND$']
    deep_value = list()

    def __init__(self, auth_context):
        self.authorization_context = json.loads(auth_context)
        with RBAC.RolesManager() as rm:
            self.roles_list = rm.get_roles()
            for role in self.roles_list:
                role.rule = json.loads(role.rule)

    def get_authorization_context(self):
        return self.authorization_context

    def get_roles(self):
        return self.roles_list

    @staticmethod
    def check_regex(expression):
        if isinstance(expression, str):
            if not expression.startswith("r'"):
                return False
            try:
                regex = ''.join(expression[2:-1])
                re.compile(regex)
                return True
            except:
                return False
        return False

    def match_item(self, dict_object, auth_context=None, mode='MATCH'):
        if auth_context is None:
            auth_context = self.authorization_context
        result = 0
        if isinstance(dict_object, dict) and isinstance(auth_context, dict):
            for key_rule, value_rule in dict_object.items():
                if self.check_regex(key_rule):
                    regex = re.compile(''.join(key_rule[2:-1]))
                    for key_auth in auth_context.keys():
                        if regex.match(key_auth):
                            result += self.match_item(dict_object[key_rule], auth_context[key_auth], mode)
                if key_rule in auth_context.keys():
                    result += self.match_item(dict_object[key_rule], auth_context[key_rule], mode)
        else:
            if isinstance(dict_object, list):
                dict_object = sorted(dict_object)
            if isinstance(auth_context, list):
                auth_context = sorted(auth_context)
            if self.check_regex(dict_object):
                regex = re.compile(''.join(dict_object[2:-1]))
                if not isinstance(auth_context, list):
                    auth_context = [auth_context]
                for context in auth_context:
                    if regex.match(context):
                        return 1
            if dict_object == auth_context:
                return 1
            if isinstance(dict_object, str):
                dict_object = [dict_object]
            if isinstance(dict_object, list) and isinstance(auth_context, list):
                counter = 0
                for index, value in enumerate(auth_context):
                    for v in dict_object:
                        if self.check_regex(v):
                            regex = re.compile(''.join(v[2:-1]))
                            if regex.match(value):
                                counter += 1
                        else:
                            if value == v:
                                counter += 1
                        if mode == self._functions[0]:  # MATCH
                            if counter == len(dict_object):
                                return 1
                        elif mode == self._functions[1]:  # MATCH$
                            if counter == len(auth_context) and counter == len(v):
                                return 1
        if isinstance(dict_object, dict):
            if result == len(dict_object.keys()):
                return True

        return False

    def finditem_recursive(self, dict_object, auth_context=None, mode='FIND'):
        if auth_context is None:
            auth_context = self.authorization_context
        if mode == self._functions[2]:
            mode = 'MATCH'
        elif mode == self._functions[3]:
            mode = 'MATCH$'

        result = self.match_item(dict_object, auth_context, mode)
        if result:
            return True

        for key, value in auth_context.items():
            if self.match_item(dict_object, value, mode):
                return True

        return False

    def make_boolean_dict(self, rule):
        for rule_key, rule_value in rule.items():
            if rule_key in self._logics:  # Logical operation
                result = 0
                if isinstance(rule_value, list):
                    for element in rule_value:
                        result += self.make_boolean_dict(element)
                elif isinstance(rule_value, dict):
                    result += self.make_boolean_dict(rule_value)
                if rule_key == self._logics[0]:  # AND
                    if result == len(rule_value):
                        return True
                elif rule_key == self._logics[1]:  # OR
                    if result > 0:
                        return True
                elif rule_key == self._logics[2]:  # NOT
                    if result == len(rule_value):
                        return False
                    else:
                        return True
            elif rule_key in self._functions:  # Function
                if rule_key == self._functions[0] or rule_key == self._functions[1]:  # MATCH, MATCH$
                    if self.match_item(dict_object=rule[rule_key], mode=rule_key):
                        return 1
                elif rule_key == self._functions[2] or rule_key == self._functions[3]:  # FIND, FIND$
                    if self.finditem_recursive(dict_object=rule[rule_key], mode=rule_key):
                        return 1

        return False

    def run(self):
        list_roles = list()
        for role in self.roles_list:
            if self.make_boolean_dict(role.rule):
                list_roles.append(role.name)

        return list_roles


if __name__ == '__main__':
    authorization_context = {
                                "disabled": False,
                                "name": "Bill",
                                "department": [
                                    "Commercial", "Technical"
                                ],
                                "bindings": {
                                    "authLevel": [
                                        "basic", "advanced-agents", "administrator"
                                    ],
                                    "area": [
                                        "agents", "syscheck", "syscollector"
                                    ]
                                },
                                "test": {
                                    "new": {
                                        "test2": ["new"]
                                    },
                                    "test": "new2"
                                }
                            }

    authorization_context_regEx = {
                                    "disabled": False,
                                    "name": "Bill",
                                    "department": [
                                        "Commercial", "Technical5"
                                    ],
                                    "bindings": {
                                        "authLevel": [
                                            "basic", "advanced-agents"
                                        ],
                                        "area": [
                                            "agents", "syscheck", "syscollector"
                                        ]
                                    },
                                    "test": {
                                        "new": {
                                            "test2": ["new"]
                                        },
                                        "test": "new2"
                                    }
                                }

    authorization_context_regExKey = {
                                        "disabled": False,
                                        "name": "Bill",
                                        "office": "20",
                                        "department": [
                                            "Technical"
                                        ],
                                        "bindings": {
                                            "authLevel": [
                                                "basic", "advanced-agents", "administrator"
                                            ],
                                            "area": [
                                                "agents", "syscheck", "syscollector"
                                            ]
                                        },
                                        "test": {
                                            "new": {
                                                "test2": ["new"]
                                            },
                                            "test": "new2"
                                        }
                                    }

    authorization_context = json.dumps(authorization_context_regExKey)

    checker = RBAChecker(authorization_context)
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    authorization_context = json.loads(authorization_context)
    print('\nSmall tests:')
    mode = 'MATCH'
    print('\t[INFO] Mode {}: {}'.format(mode, checker.match_item(
        {"name": "Bill"})))
    mode = 'MATCH$'
    print('\t[INFO] Mode {}: {}'.format(mode, checker.match_item(
        {"disabled": False, "name": "Bill", "department": ["Technical"]}, authorization_context, mode)))
    mode = 'FIND'
    print('\t[INFO] Mode {}: {}'.format(mode, checker.finditem_recursive(
        {"disabled": False, "name": "Bill", "department": ["Technical"]}, authorization_context, mode)))
    mode = 'FIND$'
    print('\t[INFO] Mode {}: {}'.format(mode, checker.finditem_recursive(
        {"area": ["syscheck", "agents", "syscollector"]}, authorization_context, mode)))
    print('\t[INFO] Final evaluation: {}'.format(checker.make_boolean_dict({
                                                                    "OR": [
                                                                            {"MATCH$": {
                                                                                "name": "Bill",
                                                                                "disabled": False,
                                                                                "department": ["Technical"]
                                                                                }
                                                                            },
                                                                            {"NOT":
                                                                                {"MATCH$": {
                                                                                    "name": "Bill",
                                                                                    "disabled": False,
                                                                                    "department": ["Technical", "Comercial"]
                                                                                    }
                                                                                }
                                                                            }
                                                                        ]
                                                                    })
    ))
    roles = checker.run()
    print('\n[INFO] Your roles are: {}\n'.format(', '.join(roles)))
