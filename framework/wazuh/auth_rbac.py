#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import copy
from wazuh.RBAC import RBAC
from wazuh.RBAC.RBAC import Roles


class RBAChecker:
    _logics = ['AND', 'OR', 'NOT', '==']
    deep_value = list()

    def __init__(self, auth_context):
        self.authorization_context = [json.loads(auth_context)]
        with RBAC.RolesManager() as rm:
            self.roles_list = rm.get_roles()
            for role in self.roles_list:
                role.rule = json.loads(role.rule)

    def get_authorization_context(self):
        return self.authorization_context

    def get_roles(self):
        return self.roles_list

    def check_logic(self, role):
        for key in role.rule.keys():
            if key in self._logics:
                return True

        return False

    def run(self):
        list_roles = list()
        for role in self.roles_list:
            if self.check_logic(role):
                boolean_dict = self.make_boolean_dict(role.rule)
                for key, value in boolean_dict.items():
                    if self.check_total_dict(key, value):
                        list_roles.append(role.name)
            else:
                result = self.check(role)
                if result:
                    list_roles.append(result)

        print('[INFO] Your role is {}'.format(', '.join(list_roles)))

    # Logical operations
    def finditem(self, dictionary, key, value):
        if not isinstance(value, list):
            value = [value]
        for val in value:
            for k, v in dictionary.items():
                if isinstance(v, list):
                    for va in v:
                        if isinstance(va, dict):
                            finded = self.finditem(va, key, value)
                            if finded:
                                return self.finditem(va, key, value)
                        if k == key and val == va:
                            return True
                if k == key and v == val:
                    return True
                else:
                    if isinstance(v, dict):
                        return self.finditem(v, key, val)

        return False

    def make_boolean_dict(self, rule, logical_operation=None):
        for rule_key, rule_value in rule.items():
            modified = False
            is_list = False
            if isinstance(rule_value, str):
                if logical_operation == self._logics[0]:  # AND
                    if not self.finditem(self.authorization_context[0], rule_key, rule_value):
                        rule[rule_key] = False
                        modified = True
                elif logical_operation == self._logics[1]:  # OR
                    if self.finditem(self.authorization_context[0], rule_key, rule_value):
                        rule[rule_key] = True
                        modified = True
            elif isinstance(rule_value, list):
                logical_operation = rule_key
                for clause in rule_value:
                    if isinstance(clause, dict):
                        is_list = True
                        self.make_boolean_dict(clause, logical_operation)
            if not modified and not is_list:
                if logical_operation == self._logics[0]:
                    rule[rule_key] = True
                elif logical_operation == self._logics[1]:
                    rule[rule_key] = False

        return rule

    def check_boolean_dict(self, rule, logical_operation=None):
        result = 0
        for key, value in rule.items():
            if isinstance(value, bool):
                if value:
                    result += 1
                if logical_operation == self._logics[0]:
                    if result == len(rule.keys()):
                        return True
                elif logical_operation == self._logics[1]:
                    if result > 0:
                        return True
        return False

    def check_total_dict(self, key, list_clauses):
        result = 0
        for clause in list_clauses:
            if isinstance(clause, dict):
                clause_counter = 0
                for k, value in clause.items():
                    if isinstance(value, list):
                        if k in self._logics:
                            result += self.check_total_dict(k, value)
                        else:
                            result += self.check_total_dict(key, value)
                    elif isinstance(value, bool):
                        if value:
                            clause_counter += 1
                    if clause_counter == len(clause.keys()):
                        result += 1
        if key == self._logics[0]:
            if result == len(list_clauses):
                return True
        if key == self._logics[1]:
            if result > 0:
                return True

        return False

    # No logical operations
    def gen_dict_extract(self, key, var=None):
        if var == 'auth' or var is None:
            var = self.authorization_context
        elif var == 'roles':
            var = self.roles_list
        if hasattr(var, 'items'):
            var = [var]
        if isinstance(var, Roles):
            var = [var.rule]
        if isinstance(var, str):
            yield var
        else:
            for dictionary in var:
                if isinstance(dictionary, Roles):
                    dictionary = dictionary.rule
                for k, v in dictionary.items():
                    if not RBAChecker.check_regex(key):
                        if k == key:
                            yield v
                        if isinstance(v, dict):
                            for result in self.gen_dict_extract(key, v):
                                yield result
                        elif isinstance(v, list):
                            for d in v:
                                for result in self.gen_dict_extract(key, d):
                                    yield result
                    else:
                        regex = re.compile(key[2:-1])
                        if regex.match(k):
                            yield v
                        if isinstance(v, dict):
                            for result in self.gen_dict_extract(key, v):
                                yield result
                        elif isinstance(v, list):
                            for d in v:
                                for result in self.gen_dict_extract(key, d):
                                    yield result

    @staticmethod
    def check_regex(regex):
        if not regex.startswith("r'"):
            return False
        try:
            regex = ''.join(regex[2:-1])
            re.compile(regex)
            return True
        except:
            return False

    @staticmethod
    def process_str(occur, key, role):
        try:
            if isinstance(occur, str) and isinstance(role.rule[key], str):
                if occur == role.rule[key]:
                    return role.name
            # elif isinstance(occur, list) and isinstance(role.rule[key], str):
            #     if role.rule[key] in occur:
            #         return role.name
        except:
            pass

        return False

    @staticmethod
    def process_regex(occur, key, role):
        regex = re.compile(''.join(role.rule[key][2:-1]))
        if isinstance(occur, str):
            if regex.match(occur):
                return role.name
        elif isinstance(occur, list) and isinstance(role.rule[key], str):
            for element in occur:
                if regex.match(element):
                    return role.name
        return False

    def check(self, role):
        role_name = None
        counter = 0
        str_saved = None
        for key in role.rule:
            occurs = self.gen_dict_extract(key)
            try:
                for occur in occurs:
                    if not RBAChecker.check_regex(role.rule[key]):
                        processed_str = RBAChecker.process_str(occur, key, role)
                        if processed_str:
                            str_saved = processed_str
                            counter += 1
                    # The rule has regex
                    else:
                        processed_regex = RBAChecker.process_regex(occur, key, role)
                        if processed_regex:
                            str_saved = processed_regex
                            counter += 1
                if counter >= len(role.rule):
                    role_name = str_saved
            except:
                pass

        return role_name


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
    checker.run()
