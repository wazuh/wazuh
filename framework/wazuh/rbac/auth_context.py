#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re

from wazuh.rbac import orm


class RBAChecker:
    # These are the logical operations available in our system:
    #    AND: All the clauses that it encloses must be certain so that the operation is evaluated as certain.
    #    OR: At least one of the clauses it contains must be correct for the operator to be evaluated as True.
    #    NOT: The clause enclosed by the NOT operator must give False for it to be evaluated as True.
    # All these operations can be nested
    _logical_operators = ['AND', 'OR', 'NOT']
    # These are the functions available in our RBAC login system:
    #   MATCH: This operation checks that the clause or clauses that it encloses are in the authorization context
    #       that comes to us. If there is no occurrence, return False. If any clause in the context authorization
    #       encloses our MATCH, it will return True because it is encapsulated in a larger set.
    #   MATCH$: It works like the previous operation with the difference that it is more strict. In this case the
    #       occurrence must be exact, it will be evaluated as False although the clause is included in a larger one
    #       in the authorization context.
    #   FIND: Recursively launches the MATCH function to search for all levels of authorization context, the operation
    #       is the same, if there is at least one occurrence, the function will return True
    #   FIND$: Just like the previous one, in this case the function MATCH$ is recursively executed.
    _functions = ['MATCH', 'MATCH$', 'FIND', 'FIND$']
    # Regex schema ----> "r'REGULAR_EXPRESSION', this is the wildcard for detecting regular expressions"
    _initial_index_for_regex = 2
    _regex_prefix = "r'"

    # If we don't pass it the role to check, it will take all of the system.
    def __init__(self, auth_context, role=None):
        self.authorization_context = json.loads(auth_context)
        # All roles in the system
        if role is None:
            with orm.RolesManager() as rm:
                self.roles_list = rm.get_roles()
                for role in self.roles_list:
                    role.rule = json.loads(role.rule)
        else:
            # One single role
            if not isinstance(role, list):
                self.roles_list = [role]
                self.roles_list[0].rule = json.loads(role.rule)
            # role is a list of roles
            else:
                self.roles_list = role
                for role in self.roles_list:
                    role.rule = json.loads(role.rule)

    # Return the authorization context
    def get_authorization_context(self):
        return self.authorization_context

    # Return all roles
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
    # recursively until it finds the structure indicated in role_chunk
    def match_item(self, role_chunk, auth_context=None, mode='MATCH'):
        auth_context = self.authorization_context if auth_context is None else auth_context
        validator_counter = 0
        # We're not in the deep end yet.
        if isinstance(role_chunk, dict) and isinstance(auth_context, dict):
            for key_rule, value_rule in role_chunk.items():
                if self.check_regex(key_rule):
                    regex = re.compile(''.join(key_rule[2:-2]))
                    for key_auth in auth_context.keys():
                        if regex.match(key_auth):
                            validator_counter += self.match_item(role_chunk[key_rule], auth_context[key_auth], mode)
                if key_rule in auth_context.keys():
                    validator_counter += self.match_item(role_chunk[key_rule], auth_context[key_rule], mode)
        # It's a possible end
        else:
            if isinstance(role_chunk, list):
                role_chunk = sorted(role_chunk)
            if isinstance(auth_context, list):
                auth_context = sorted(auth_context)
            if self.check_regex(role_chunk):
                regex = re.compile(''.join(role_chunk[2:-2]))
                if not isinstance(auth_context, list):
                    auth_context = [auth_context]
                for context in auth_context:
                    if regex.match(context):
                        return 1
            if role_chunk == auth_context:
                return 1
            if isinstance(role_chunk, str):
                role_chunk = [role_chunk]
            if isinstance(role_chunk, list) and isinstance(auth_context, list):
                counter = 0
                for index, value in enumerate(auth_context):
                    for v in role_chunk:
                        if self.check_regex(v):
                            regex = re.compile(''.join(v[2:-2]))
                            if regex.match(value):
                                counter += 1
                        else:
                            if value == v:
                                counter += 1
                        if mode == self._functions[0]:  # MATCH
                            if counter == len(role_chunk):
                                return 1
                        elif mode == self._functions[1]:  # MATCH$
                            if counter == len(auth_context) and counter == len(role_chunk):
                                return 1
        if isinstance(role_chunk, dict):
            if validator_counter == len(role_chunk.keys()):
                return True

        return False

    # This function will use the match function and will launch it recursively on
    # all the authorization context tree, on all the levels.
    def find_item(self, role_chunk, auth_context=None, mode='FIND'):
        auth_context = self.authorization_context if auth_context is None else auth_context
        if mode == self._functions[2]:  # FIND
            mode = self._functions[0]  # MATCH
        elif mode == self._functions[3]:  # FIND$
            mode = self._functions[1]  # MATCH$

        validator_counter = self.match_item(role_chunk, auth_context, mode)
        if validator_counter:
            return True

        for key, value in auth_context.items():
            if self.match_item(role_chunk, value, mode):
                return True
            elif isinstance(value, dict):
                if self.find_item(role_chunk, value, mode=mode):
                    return True
            elif isinstance(value, list):
                for v in value:
                    if isinstance(v, dict):
                        if self.find_item(role_chunk, v, mode=mode):
                            return True

        return False

    # This is the controller for the match of the roles with the authorization context,
    # this function is the one that will launch the others.
    def check_rule(self, rule):
        for rule_key, rule_value in rule.items():
            if rule_key in self._logical_operators:  # Logical operation
                validator_counter = 0
                if isinstance(rule_value, list):
                    for element in rule_value:
                        validator_counter += self.check_rule(element)
                elif isinstance(rule_value, dict):
                    validator_counter += self.check_rule(rule_value)
                if rule_key == self._logical_operators[0]:  # AND
                    if validator_counter == len(rule_value):
                        return True
                elif rule_key == self._logical_operators[1]:  # OR
                    if validator_counter > 0:
                        return True
                elif rule_key == self._logical_operators[2]:  # NOT
                    if validator_counter == len(rule_value):
                        return False
                    else:
                        return True
            elif rule_key in self._functions:  # Function
                if rule_key == self._functions[0] or rule_key == self._functions[1]:  # MATCH, MATCH$
                    if self.match_item(role_chunk=rule[rule_key], mode=rule_key):
                        return 1
                elif rule_key == self._functions[2] or rule_key == self._functions[3]:  # FIND, FIND$
                    if self.find_item(role_chunk=rule[rule_key], mode=rule_key):
                        return 1

        return False

    # Main loop, in which the process starts, a list will be filled with the names of the roles that the user has.
    def run(self):
        list_roles = list()
        for role in self.roles_list:
            list_roles.append(role.name) if self.check_rule(role.rule) else None

        return list_roles
