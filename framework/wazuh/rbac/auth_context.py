#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re

from wazuh.rbac import orm


class RBAChecker:
    _logical_operators = ['AND', 'OR', 'NOT']
    _functions = ['MATCH', 'MATCH$', 'FIND', 'FIND$']
    # Regex schema ----> "r'REGULAR_EXPRESSION'"
    _regex_prefix = "r'"
    _initial_index_for_regex = 2

    # If we don't pass it the role to check, it will take all of the system.
    def __init__(self, auth_context, role=None, testing=False):
        if testing:
            return
        self.authorization_context = json.loads(auth_context)
        if role is None:
            with orm.RolesManager() as rm:
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

    # A list will be filled with the names of the roles that the user has.
    def get_user_roles(self):
        list_roles = list()
        for role in self.roles_list:
            list_roles.append([role.id, role.name]) if self.check_rule(role.rule) else None

        return list_roles

    def run(self):
        user_roles = self.get_user_roles()
        user_policies = []
        with orm.RolesPoliciesManager() as rpm:
            for role in user_roles:
                user_policies.append(policy for policy in rpm.get_all_policies_from_role(role[0]))
            user_policies = set(user_policies)

        return user_policies

    # This is for TESTING. This method returns a list of hardcoded policies for testing
    def run_testing(self):
        policies = [
            {
                "actions": ["syscheck:put", "syscheck:get", "syscheck:delete"],
                "resources": ["agent:id:*"],
                "effect": "allow"
            },
            {
                "actions": ["lists:get"],
                "resources": ["list:path:*"],
                "effect": "allow"
            },
            {
                "actions": ["active_response:command"],
                "resources": ["agent:id:001"],
                "effect": "allow"
            },
            {
                "actions": ["active_response:command"],
                "resources": ["agent:id:*"],
                "effect": "allow"
            },
            {
                "actions": ["active_response:command"],
                "resources": ["agent:id:*"],
                "effect": "allow"
            },
            {
                "actions": ["active_response:command"],
                "resources": ["agent:id:001", "agent:id:002", "agent:id:003"],
                "effect": "deny"
            },
            {
                "actions": ["active_response:command"],
                "resources": ["agent:id:*"],
                "effect": "allow"
            },
            {
                "actions": ["active_response:command"],
                "resources": ["agent:id:001", "agent:id:002", "agent:id:*", "agent:id:002", "agent:id:003"],
                "effect": "deny"
            }
        ]

        return policies

    @staticmethod
    def convert_to_json_serializable(optimize_policies):
        for key, value in optimize_policies.items():
            for key_resource, value_resource in value.items():
                for key_effect, key_value in value_resource.items():
                    optimize_policies[key][key_resource][key_effect] = list(key_value)

        return optimize_policies

    @staticmethod
    def create_initial_dict(mode, resource, odict):
        if mode == 'white':
            odict[resource] = {
                'allow': set(),
                'deny': {'*'}
            }
        elif mode == 'black':
            odict[resource] = {
                'allow': {'*'},
                'deny': set()
            }

        return odict

    @staticmethod
    def white_process(resource_value, effect, odict):
        if effect == 'allow':
            if resource_value in odict['deny']:
                odict['deny'].remove(resource_value)
            if resource_value == '*':
                odict['deny'].clear()
                odict['allow'].clear()
            if '*' not in odict['allow']:
                odict['allow'].add(resource_value)
        elif effect == 'deny':
            if resource_value in odict['allow']:
                odict['allow'].remove(resource_value)
            if resource_value == '*':
                odict['deny'].clear()
                odict['allow'].clear()
            if '*' not in odict['deny']:
                odict['deny'].add(resource_value)

    @staticmethod
    def black_process(resource_value, effect, odict):
        if effect == 'deny':
            if resource_value in odict['allow']:
                odict['allow'].remove(resource_value)
            elif resource_value == '*':
                odict['allow'].clear()
                odict['deny'].clear()
            if '*' not in odict['deny']:
                odict['deny'].add(resource_value)
        elif effect == 'allow':
            if resource_value in odict['deny']:
                odict['deny'].remove(resource_value)
            elif resource_value == '*':
                odict['allow'].clear()
                odict['deny'].clear()
            if '*' not in odict['allow']:
                odict['allow'].add(resource_value)

    @staticmethod
    def modify_odict(mode, action, resources, effect, odict):
        for resource in resources:
            resource_name = ':'.join(resource.split(':')[0:-1])
            resource_value = resource.split(':')[-1]
            if resource_name not in odict[action].keys():
                RBAChecker.create_initial_dict(mode, resource_name, odict[action])

            if mode == 'white':
                RBAChecker.white_process(resource_value, effect, odict[action][resource_name])
            elif mode == 'black':
                RBAChecker.black_process(resource_value, effect, odict[action][resource_name])

    @staticmethod
    def process_policy(mode, policy, odict):
        for action in policy['actions']:
            if action not in odict.keys():
                odict[action] = dict()
            RBAChecker.modify_odict(mode, action, policy['resources'], policy['effect'], odict)

    def optimize_resources(self, mode='white'):
        # For production, change run_testing() for run()
        policies = self.run_testing()
        odict = dict()

        for policy in policies:
            RBAChecker.process_policy(mode, policy, odict)
        RBAChecker.convert_to_json_serializable(odict)

        return odict
