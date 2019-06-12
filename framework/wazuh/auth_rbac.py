#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
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
                    if k == key:
                        yield v
                    if isinstance(v, dict):
                        for result in self.gen_dict_extract(key, v):
                            yield result
                    elif isinstance(v, list):
                        for d in v:
                            for result in self.gen_dict_extract(key, d):
                                yield result

    def check(self):
        role_name = set()
        for role in self.roles_list:
            for key in role.rule:
                occurs = self.gen_dict_extract(key)
                try:
                    for occur in occurs:
                        if isinstance(occur, str) and isinstance(role.rule[key], str):
                            if occur == role.rule[key]:
                                role_name.add(role.name)
                        elif isinstance(occur, list) and isinstance(role.rule[key], str):
                            if role.rule[key] in occur:
                                role_name.add(role.name)
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


    authorization_context = json.dumps(authorization_context)

    checker = RBAChecker(authorization_context)
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)
    checker.check()
