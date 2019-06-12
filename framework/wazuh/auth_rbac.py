#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from wazuh.RBAC import RBAC


class RBAChecker:

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

    def gen_dict_extract(self, key, var=None):
        if var == 'auth' or var is None:
            var = self.authorization_context
        elif var == 'roles':
            var = self.roles_list
        if hasattr(var, 'items'):
            var = [var]
        if isinstance(var, str):
            yield var
        else:
            for dictionary in var:
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
        if isinstance(occur, str) and isinstance(role.rule[key], str):
            if occur == role.rule[key]:
                return role.name
        elif isinstance(occur, list) and isinstance(role.rule[key], str):
            if role.rule[key] in occur:
                return role.name
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
            for key in role.rule:
                occurs = self.gen_dict_extract(key)
                try:
                    for occur in occurs:
                        if not RBAChecker.check_regex(role.rule[key]):
                            processed_str = RBAChecker.process_str(occur, key, role)
                            if processed_str:
                                role_name.add(processed_str)
                        # The rule has regex
                        else:
                            processed_regex = RBAChecker.process_regex(occur, key, role)
                            if processed_regex:
                                role_name.add(processed_regex)

                except:
                    print('Empty generator!')
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
        "department4": [
            "Commercial"
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

    authorization_context = json.dumps(authorization_context_regExKey)

    checker = RBAChecker(authorization_context)
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    checker.check()
