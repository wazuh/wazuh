#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from wazuh.RBAC import RBAC


class RBAChecker:
    _logical_operators = ['AND', 'OR', 'NOT']
    _functions = ['MATCH', 'MATCH$', 'FIND', 'FIND$']
    # Regex schema ----> "r'REGULAR_EXPRESSION'"
    _regex_prefix = "r'"
    _initial_index_for_regex = 2

    # If we don't pass it the role to check, it will take all of the system.
    def __init__(self, auth_context, role=None):
        self.authorization_context = json.loads(auth_context)
        if role is None:
            with RBAC.RolesManager() as rm:
                self.roles_list = rm.get_roles()
                for role in self.roles_list:
                    role.rule = json.loads(role.rule)
        else:
            self.roles_list = [role]
            self.roles_list[0].rule = json.loads(role.rule)

    # Get the authorization context
    def get_authorization_context(self):
        return self.authorization_context

    # Get all roles
    def get_roles(self):
        return self.roles_list

    # Checks if a certain string is a regular expression
    def check_regex(self, expression):
        if isinstance(expression, str):
            if not expression.startswith(self._regex_prefix):
                return False
            try:
                regex = ''.join(expression[self._initial_index_for_regex:-2])
                re.compile(regex)
                return True
            except:
                return False
        return False

    # This function will go through all authorization contexts and system roles
    # recursively until it finds the structure indicated in dict_object
    def match_item(self, dict_object, auth_context=None, mode='MATCH'):
        auth_context = self.authorization_context if auth_context is None else auth_context
        result = 0
        if isinstance(dict_object, dict) and isinstance(auth_context, dict):
            for key_rule, value_rule in dict_object.items():
                if self.check_regex(key_rule):
                    regex = re.compile(''.join(key_rule[2:-2]))
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
                regex = re.compile(''.join(dict_object[2:-2]))
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
                            regex = re.compile(''.join(v[2:-2]))
                            if regex.match(value):
                                counter += 1
                        else:
                            if value == v:
                                counter += 1
                        if mode == self._functions[0]:  # MATCH
                            if counter == len(dict_object):
                                return 1
                        elif mode == self._functions[1]:  # MATCH$
                            if counter == len(auth_context) and counter == len(dict_object):
                                return 1
        if isinstance(dict_object, dict):
            if result == len(dict_object.keys()):
                return True

        return False

    # This function will use the match and will launch it recursively on
    # all the authorization context tree, on all the levels.
    def find_item(self, dict_object, auth_context=None, mode='FIND'):
        auth_context = self.authorization_context if auth_context is None else auth_context
        if mode == self._functions[2]:  # FIND
            mode = 'MATCH'
        elif mode == self._functions[3]:  # FIND$
            mode = 'MATCH$'

        result = self.match_item(dict_object, auth_context, mode)
        if result:
            return True

        for key, value in auth_context.items():
            if self.match_item(dict_object, value, mode):
                return True
            elif isinstance(value, dict):
                if self.find_item(dict_object, value, mode=mode):
                    return True
            elif isinstance(value, list):
                for v in value:
                    if isinstance(v, dict):
                        if self.find_item(dict_object, v, mode=mode):
                            return True

        return False

    # This is the controller of the match of the roles with the authorization context,
    # this function is the one that will launch the others.
    def check_rule(self, rule):
        for rule_key, rule_value in rule.items():
            if rule_key in self._logical_operators:  # Logical operation
                result = 0
                if isinstance(rule_value, list):
                    for element in rule_value:
                        result += self.check_rule(element)
                elif isinstance(rule_value, dict):
                    result += self.check_rule(rule_value)
                if rule_key == self._logical_operators[0]:  # AND
                    if result == len(rule_value):
                        return True
                elif rule_key == self._logical_operators[1]:  # OR
                    if result > 0:
                        return True
                elif rule_key == self._logical_operators[2]:  # NOT
                    if result == len(rule_value):
                        return False
                    else:
                        return True
            elif rule_key in self._functions:  # Function
                if rule_key == self._functions[0] or rule_key == self._functions[1]:  # MATCH, MATCH$
                    if self.match_item(dict_object=rule[rule_key], mode=rule_key):
                        return 1
                elif rule_key == self._functions[2] or rule_key == self._functions[3]:  # FIND, FIND$
                    if self.find_item(dict_object=rule[rule_key], mode=rule_key):
                        return 1

        return False

    # Main loop, in which the process starts, a list will be filled with the names of the roles that the user has.
    def run(self):
        list_roles = list()
        for role in self.roles_list:
            list_roles.append(role.name) if self.check_rule(role.rule) else None

        return list_roles


# This is for test
# if __name__ == '__main__':
#     authorization_context = {
#         "disabled": False,
#         "name": "Bill",
#         "office": "20",
#         "department": [
#             "Technical"
#         ],
#         "bindings": {
#             "authLevel": [
#                 "basic", "advanced-agents", "administrator"
#             ],
#             "area": [
#                 "agents", "syscheck", "syscollector"
#             ]
#         },
#         "test": {
#             "new": {
#                 "test2": ["new"]
#             },
#             "test": "new2"
#         }
#     }
#
#     authorization_context = json.dumps(authorization_context)
#     checker = RBAChecker(authorization_context)
#     authorization_context = json.loads(authorization_context)
#     roles = checker.run()
#     print('\n[INFO] Your roles are: {}\n'.format(', '.join(roles)))
