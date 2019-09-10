# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json

from wazuh.rbac import orm


def get_role_from_database(role_id):
    with orm.RolesManager() as rm:
        role = rm.get_role_id(role_id)
        if role is not None:
            return_role = role.to_dict()
            return_role['rule'] = json.loads(return_role['rule'])
            # It is necessary to load the policies (json.loads) for a correct visualization
            for index, policy in enumerate(return_role['policies']):
                return_role['policies'][index]['policy'] = \
                    json.loads(return_role['policies'][index]['policy'])
            # Removes the policies field because when creating a role it is not connected to any of them.
            if len(return_role['policies']) == 0:
                return_role.pop('policies', None)
    return None


def get_roles_from_database():
    data = list()
    with orm.RolesManager() as rm:
        roles = rm.get_roles()
        for role in roles:
            dict_role = role.to_dict()
            dict_role.pop('policies', None)
            dict_role['rule'] = json.loads(dict_role['rule'])
            data.append(dict_role)
    return data


def remove_role_from_database(role_id):
    response = dict()
    with orm.RolesManager() as rm:
        if rm.delete_role(role_id):
            response['removed_roles'] = [int(role_id)]
        else:
            response['incorrect_roles'] = [int(role_id)]
    return response


def remove_roles_from_database(list_roles):
    status_correct = list()
    response = dict()

    with orm.RolesManager() as rm:
        if len(list_roles) > 0:
            for role in list_roles:
                if rm.delete_role(role):
                    status_correct.append(int(role))
            response['removed_roles'] = status_correct
            # Symmetric difference: The symmetric difference of two sets A and B is
            # the set of elements which are in either of the sets A or B but not in both.
            response['incorrect_roles'] = list(set(list_roles) ^ set(status_correct))
        else:
            response['removed_roles'] = rm.delete_all_roles()
    return response


def add_role_to_database(name, rule):
    with orm.RolesManager() as rm:
        status = rm.add_role(name=name, rule=rule)
    return status, rm.get_role(name=name).id


def update_role_to_database(role_id, name, rule):
    with orm.RolesManager() as rm:
        status = rm.update_role(role_id=role_id, name=name, rule=rule)
    return status


def get_policy_from_database(policy_id):
    with orm.PoliciesManager() as pm:
        policy = pm.get_policy_by_id(policy_id)
        if policy is not None:
            return_policy = policy.to_dict()
            return_policy['policy'] = json.loads(return_policy['policy'])
            # It is necessary to load the roles (json.loads) for a correct visualization
            for index, role in enumerate(return_policy['roles']):
                return_policy['roles'][index]['rule'] = \
                    json.loads(return_policy['roles'][index]['rule'])
            # Removes the roles field because when creating a policy it is not connected to any of them.
            if len(return_policy['roles']) == 0:
                return_policy.pop('roles', None)
    return None


def get_policies_from_database():
    data = list()
    with orm.PoliciesManager() as pm:
        policies = pm.get_policies()
        for policy in policies:
            dict_policy = policy.to_dict()
            dict_policy.pop('roles', None)
            dict_policy['policy'] = json.loads(dict_policy['policy'])
            data.append(dict_policy)
    return data


def remove_policy_from_database(policy_id):
    response = dict()
    with orm.PoliciesManager() as pm:
        if pm.delete_policy(policy_id):
            response['removed_policies'] = [int(policy_id)]
        else:
            response['incorrect_policies'] = [int(policy_id)]
    return response


def remove_policies_from_database(list_policies):
    status_correct = list()
    response = dict()

    with orm.PoliciesManager() as pm:
        if len(list_policies) > 0:
            for policy in list_policies:
                if pm.delete_policy(policy):
                    status_correct.append(int(policy))
            response['removed_policies'] = status_correct
            # Symmetric difference: The symmetric difference of two sets A and B is
            # the set of elements which are in either of the sets A or B but not in both.
            response['incorrect_policies'] = list(set(list_policies) ^ set(status_correct))
        else:
            response['removed_policies'] = pm.delete_all_policies()
    return response


def add_policy_to_database(name, policy):
    with orm.PoliciesManager() as pm:
        status = pm.add_policy(name=name, policy=policy)
    return status, pm.get_policy(name=name).id


def update_policy_to_database(policy_id, name, policy):
    with orm.PoliciesManager() as pm:
        status = pm.update_policy(policy_id=policy_id, name=name, policy=policy)
    return status