#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from wazuh.RBAC import RBAC


class RBAChecker:

    def __init__(self, authorization_context):
        self.authorization_context = json.loads(authorization_context)
        with RBAC.RolesManager() as rm:
            self.roles_list = rm.get_roles()
            for role in self.roles_list:
                role.rule = json.loads(role.rule)

    def get_authorization_context(self):
        return self.authorization_context

    def get_roles(self):
        return self.roles_list

    def check(self):
        for role in self.roles_list:
            for key in self.authorization_context.keys():
                print(key)



if __name__ == '__main__':
    authorization_context = {
                                "disabled": False,
                                "name": "Bill",
                                "department": [
                                    "Commercial", "Technical"
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
                                    }
                                }
                            }

    authorization_context = json.dumps(authorization_context)

    checker = RBAChecker(authorization_context)

    print(checker.check())
