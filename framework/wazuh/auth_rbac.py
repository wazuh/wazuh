#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from wazuh.RBAC import RBAC
from wazuh.RBAC.RBAC import Roles


class RBAChecker:
    _logics = ['AND', 'OR', 'NOT', '==']

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

    def check_logic_operations(self):
        role_name = set()
        logic_dict = dict()
        logic_dict['result'] = dict
        for logic in self._logics:
            for role in self.roles_list:
                for operators in self.gen_dict_extract(logic, role):
                    if logic == self._logics[0]:
                        if len(logic_dict.keys()) == 0:
                            logic_dict[logic] = 1
                        else:
                            logic_dict['result'][logic] = [logic_dict['result'], 1]
                        if not self.in_auth(operators):
                            try:
                                logic_dict[logic][-1] = 0
                            except:
                                logic_dict[logic] = 0
                    elif logic == self._logics[1]:
                        if len(logic_dict.keys()) == 0:
                            logic_dict[logic] = 0
                        else:
                            logic_dict['result'][logic] = [logic_dict['result'], 0]
                        if self.in_auth(operators):
                            try:
                                logic_dict[logic][-1] = 1
                            except:
                                logic_dict[logic] = 1

        print(logic_dict)

    def in_auth(self, operators):
        size_operator = len(operators)
        counter_match = 0
        checked = list()
        for operator in operators:
            for key in operator.keys():
                occurs = self.gen_dict_extract(key)
                for occur in occurs:
                    if isinstance(occur, str):
                        occur = [occur]
                    for element in occur:
                        if operator[key] == element and element not in checked:
                            counter_match += 1
                            checked.append(element)

        if counter_match == size_operator:
            return True

        return False

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

    def check(self):
        role_name = set()
        for role in self.roles_list:
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
                        role_name.add(str_saved)
                except:
                    pass
        if len(role_name) == 0:
            print('[INFO] You dont have a role in the system')
        else:
            print('[INFO] Your role is {}'.format(', '.join(role_name)))


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
    import pydevd_pycharm
    pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    checker.check()
    checker.check_logic_operations()
