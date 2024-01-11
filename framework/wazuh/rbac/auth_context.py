# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
from collections import defaultdict
from typing import Union

from wazuh.rbac import orm


class RBAChecker:
    """
    The logical operations available in our system:
        AND: All the clauses that it encloses must be certain so that the operation is evaluated as certain.
        OR: At least one of the clauses it contains must be correct for the operator to be evaluated as True.
        NOT: The clause enclosed by the NOT operator must give False for it to be evaluated as True.
        All these operations can be nested
    These are the functions available in our role based login system:
        MATCH: This operation checks that the clause or clauses that it encloses are in the authorization context
          that comes to us. If there is no occurrence, return False. If any clause in the context authorization
          encloses our MATCH, it will return True because it is encapsulated in a larger set.
        MATCH$: It works like the previous operation with the difference that it is more strict. In this case the
          occurrence must be exact, it will be evaluated as False although the clause is included in a larger one
          in the authorization context.
        FIND: Recursively launches the MATCH function to search for all levels of authorization context, the
          operation is the same, if there is at least one occurrence, the function will return True
        FIND$: Just like the previous one, in this case the function MATCH$ is recursively executed.
    Regex schema ----> "r'REGULAR_EXPRESSION', this is the wildcard for detecting regular expressions"
    """
    _logical_operators = ['AND', 'OR', 'NOT']
    _functions = ['MATCH', 'MATCH$', 'FIND', 'FIND$']
    _initial_index_for_regex = 2
    _regex_prefix = "r'"

    # If we don't pass it the role to check, it will take all of the system.
    def __init__(self, auth_context: Union[dict, str] = None, role: Union[list, orm.Roles] = None, user_id: int = None):
        """Class constructor to match the roles of the system with a given authorization context.

        Parameters
        ----------
        auth_context : dict or str
            Authorization context to be checked.
        role : list or orm.Roles
            Roles(list)/Role/None(All roles in the system) to be checked against the authorization context.
        user_id : int
            Current user_id.
        """
        self.user_id = user_id
        if auth_context is None:
            auth_context = '{}'
        try:
            self.authorization_context = json.loads(auth_context)
        except TypeError:
            self.authorization_context = auth_context

        if role is None:
            # All system's roles
            with orm.RolesManager() as rm:
                roles_list = list(map(orm.Roles.to_dict, rm.get_roles()))
        else:
            roles_list = [role] if not isinstance(role, list) else role

        with orm.RolesManager() as rm:
            with orm.RulesManager() as rum:
                processed_roles_list = list()
                for role in roles_list:
                    rules = list()
                    for rule in rm.get_role_id(role_id=role['id'])['rules']:
                        rules.append(rum.get_rule(rule))
                    if len(rules) > 0:
                        processed_roles_list.append(role)
                        processed_roles_list[-1]['rules'] = rules

        self.roles_list = processed_roles_list

    def get_authorization_context(self) -> str:
        """Return the authorization context.

        Returns
        -------
        str
            Provided authorization context.
        """
        return self.authorization_context

    def get_roles(self) -> list:
        """Return all roles.

        Returns
        -------
        list
            List of roles to handle.
        """
        return self.roles_list

    @staticmethod
    def preprocess_to_list(role_chunk: list, auth_chunk: list) -> tuple:
        """Assign the correct type to authorization context and role chunks.

        Parameters
        ----------
        role_chunk : list
            Role chunk.
        auth_chunk : list
            Authorization context chunk.

        Returns
        -------
        tuple
            List with role_chunk and auth_chunk processed.
        """
        role_chunk = sorted(role_chunk) if isinstance(role_chunk, list) else role_chunk
        auth_chunk = sorted(auth_chunk) if isinstance(auth_chunk, list) else auth_chunk

        return role_chunk, auth_chunk

    def process_lists(self, role_chunk: list, auth_context: list, mode: str) -> int:
        """Process lists of role chunks and authorization context chunks

        Parameters
        ----------
        role_chunk : list
            List inside the role.
        auth_context : list
            List inside the auth_context.
        mode : str
            Mode to match both lists.

        Returns
        -------
        int
            1 or 0, 1 if the function is evaluated as True else return False.
        """
        counter = 0
        for index, value in enumerate(auth_context):
            for v in role_chunk:
                regex = self.check_regex(v)
                if regex:
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

        return 0

    def set_mode(self, mode: str, role_id: int = None) -> str:
        """Link the FIND/FIND$ modes with their respective functions (MATCH/MATCH$).

        Parameters
        ----------
        mode : str
            FIND/FIND$.
        role_id : int
            Actual role id to be checked.

        Returns
        -------
        str
            mode: FIND -> MATCH | FIND$ -> MATCH$.
        """
        if mode == self._functions[2]:  # FIND
            mode = self._functions[0]  # MATCH
        elif mode == self._functions[3]:  # FIND$
            mode = self._functions[1]  # MATCH$

        return mode

    def check_logic_operation(self, rule_key: str, rule_value: dict, validator_counter: int) -> Union[bool, None]:
        """Evaluate a specified logic operation role-auth_context.

        Parameters
        ----------
        rule_key : str
            Possible logic operation.
        rule_value : dict
            Clause to be evaluated.
        validator_counter : int
            Number of successes within the logical operation.

        Returns
        -------
        bool or None
            True/False/None, it is possible that the database has been modified externally to Wazuh, Potential Security
            Breach, Currently, if this is the case and the unknown role is invalid, it will not cause any problems to
            the system, it will be ignored.
        """
        if rule_key == self._logical_operators[0]:  # AND
            if validator_counter == len(rule_value):
                return True
        elif rule_key == self._logical_operators[1]:  # OR
            if validator_counter > 0:
                return True
        elif rule_key == self._logical_operators[2]:  # NOT
            return False if validator_counter == len(rule_value) else True

        return None

    def check_regex(self, expression: str) -> Union[re.Pattern, bool]:
        """Check if a certain string is a regular expression.

        Parameters
        ----------
        expression : str
            Regular expression to be checked.

        Returns
        -------
        re.Pattern or bool
            Compiled regex if a valid regex is provided else return False.
        """
        if isinstance(expression, str):
            if not expression.startswith(self._regex_prefix):
                return False
            try:
                regex = ''.join(expression[self._initial_index_for_regex:-2])
                regex = re.compile(regex)
                return regex
            except:
                return False
        return False

    def match_item(self, role_chunk: Union[list, dict], auth_context: Union[list, dict] = None,
                   mode: str = 'MATCH') -> Union[int, bool]:
        """This function will go through all authorization contexts and system roles recursively until it finds the
        structure indicated in role_chunk.

        Parameters
        ----------
        role_chunk : list or dict
            Chunk of one stored role in the class.
        auth_context : list or dict
            Received authorization context.
        mode : str
            MATCH or MATCH$.

        Returns
        -------
        int or bool
            True or 1 if match else False or 0.
        """
        auth_context = self.authorization_context if auth_context is None else auth_context
        validator_counter = 0
        # We're not in the deep end yet.
        if isinstance(role_chunk, dict) and isinstance(auth_context, dict):
            for key_rule, value_rule in role_chunk.items():
                regex = self.check_regex(key_rule)
                if regex:
                    for key_auth in auth_context.keys():
                        if regex.match(key_auth):
                            validator_counter += self.match_item(role_chunk[key_rule], auth_context[key_auth], mode)
                if key_rule in auth_context.keys():
                    validator_counter += self.match_item(role_chunk[key_rule], auth_context[key_rule], mode)
        # It's a possible end
        else:
            role_chunk, auth_context = self.preprocess_to_list(role_chunk, auth_context)
            regex = self.check_regex(role_chunk)
            if regex:
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
                return self.process_lists(role_chunk, auth_context, mode)
        if isinstance(role_chunk, dict):
            if validator_counter == len(role_chunk.keys()):
                return True

        return False

    def find_item(self, role_chunk: Union[list, dict], auth_context: dict = None, mode: str = 'FIND',
                  role_id: int = None) -> bool:
        """This function will use the match function and will launch it recursively on all the authorization context
        tree, on all the levels.

        Parameters
        ----------
        role_chunk : list or dict
            Chunk of one stored role in the class.
        auth_context : dict
            Received authorization context.
        mode : str
            FIND -> MATCH | FIND$ -> MATCH$.
        role_id : int
            ID of the current role.

        Returns
        -------
        bool
            True if the item was found, false otherwise.
        """
        auth_context = self.authorization_context if auth_context is None else auth_context
        mode = self.set_mode(mode, role_id)

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

    def check_rule(self, rule: dict, role_id: int = None) -> Union[bool, int]:
        """This is the controller for the match of the roles with the authorization context,
        this function is the one that will launch the others.

        Parameters
        ----------
        rule : dict
            The rule of the current role.
        role_id : int
            ID of the current role.

        Returns
        -------
        bool or int
            True or 1 if the authorization context matched the role, or False or 0 otherwise.
        """
        for rule_key, rule_value in rule.items():
            if rule_key in self._logical_operators:  # The current key is a logical operator
                validator_counter = 0
                if isinstance(rule_value, list):
                    for element in rule_value:
                        validator_counter += self.check_rule(element)
                elif isinstance(rule_value, dict):
                    validator_counter += self.check_rule(rule_value)
                result = self.check_logic_operation(rule_key, rule_value, validator_counter)
                if isinstance(result, bool):
                    return result
            elif rule_key in self._functions:  # The current key is a function
                if rule_key == self._functions[0] or rule_key == self._functions[1]:  # MATCH, MATCH$
                    if self.match_item(role_chunk=rule[rule_key], mode=rule_key):
                        return 1
                elif rule_key == self._functions[2] or rule_key == self._functions[3]:  # FIND, FIND$
                    if self.find_item(role_chunk=rule[rule_key], mode=rule_key, role_id=role_id):
                        return 1

        return False

    def get_user_roles(self) -> list:
        """This function will return a list of role IDs if these match with the authorization context.

        Returns
        -------
        list
            List or role IDs matching the auth context.
        """
        list_roles = list()
        for role in self.roles_list:
            for rule in role['rules']:
                # wazuh-wui has id 2
                if (rule['id'] > orm.MAX_ID_RESERVED or self.user_id == 2) and self.check_rule(rule['rule']):
                    list_roles.append(role['id'])
                    break

        return list_roles

    def run_auth_context(self) -> defaultdict:
        """This function will return the final policies of a user according to the roles matching the authorization
        context.

        Returns
        -------
        defaultdict
            Final policies of a user according to the roles matching the authorization context.
        """
        user_roles = self.get_user_roles()
        user_roles_policies = defaultdict(list)
        with orm.RolesPoliciesManager() as rpm:
            for role in user_roles:
                for policy in rpm.get_all_policies_from_role(role):
                    user_roles_policies['policies'].append(json.loads(policy.policy))
                user_roles_policies['roles'].append(role)

        return user_roles_policies

    def run_auth_context_roles(self) -> list:
        """This function will return the roles of a user matching the authorization context.

        Returns
        -------
        list
            List or role IDs matching the auth context.
        """
        user_roles = self.get_user_roles()

        return user_roles

    @staticmethod
    def run_user_role_link(user_id: int) -> defaultdict:
        """This function will return the final policies of a user according to its roles in the RBAC database.

        Parameters
        ----------
        user_id : int
            User to get the policies from.

        Returns
        -------
        defaultdict
            Final policies of a user according to its roles in the RBAC database.
        """
        with orm.UserRolesManager() as urm:
            user_roles = list(role for role in urm.get_all_roles_from_user(user_id=user_id))
        user_roles_policies = defaultdict(list)
        with orm.RolesPoliciesManager() as rpm:
            for role in user_roles:
                for policy in rpm.get_all_policies_from_role(role_id=role.id):
                    user_roles_policies['policies'].append(policy.to_dict()['policy'])
                user_roles_policies['roles'].append(role.id)

        return user_roles_policies

    @staticmethod
    def run_user_role_link_roles(user_id: int) -> list:
        """This function will return the roles in the RBAC database for a user.

        Parameters
        ----------
        user_id : int
            User to get the roles from.

        Returns
        -------
        list
            List of roles related to the user.
        """
        with orm.UserRolesManager() as urm:
            user_roles = list(role.id for role in urm.get_all_roles_from_user(user_id=user_id))

        return user_roles


def get_policies_from_roles(roles: list = None) -> list:
    """This function will return the final policies of a user according to its roles.

    Parameters
    ----------
    roles : list
        List of roles.

    Returns
    -------
    list
        Policies of a user according to a list of roles.
    """
    policies = list()
    with orm.RolesPoliciesManager() as rpm:
        for role in roles:
            for policy in rpm.get_all_policies_from_role(role):
                policies.append(json.loads(policy.policy))

    return policies
