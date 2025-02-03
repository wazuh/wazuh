import logging
import sys
import json
import random
import string
import os

# Set framework path
sys.path.append(os.path.dirname(sys.argv[0]) + "/../framework")

USER_FILE_PATH = "/var/ossec/api/configuration/admin.json"
SPECIAL_CHARS = "@$!%*?&-_"


try:
    from wazuh.rbac.orm import check_database_integrity
    from wazuh.security import (
        create_user,
        get_users,
        get_roles,
        set_user_role,
        update_user,
    )
except ModuleNotFoundError as e:
    logging.error("No module 'wazuh' found.")
    sys.exit(1)


def read_user_file(path=USER_FILE_PATH):
    with open(path) as user_file:
        data = json.load(user_file)
        return data["username"], data["password"]


def db_users():
    users_result = get_users()
    return {user["username"]: user["id"] for user in users_result.affected_items}


def db_roles():
    roles_result = get_roles()
    return {role["name"]: role["id"] for role in roles_result.affected_items}

def disable_user(uid):
    random_pass = "".join(
                random.choices(
                    string.ascii_uppercase
                    + string.ascii_lowercase
                    + string.digits
                    + SPECIAL_CHARS,
                    k=8,
                )
            )
    # assure there must be at least one character from each group
    random_pass = random_pass + ''.join([random.choice(chars) for chars in [string.ascii_lowercase, string.digits, string.ascii_uppercase, SPECIAL_CHARS]])
    random_pass = ''.join(random.sample(random_pass,len(random_pass)))
    update_user(
        user_id=[
            str(uid),
        ],
        password=random_pass,
    )


if __name__ == "__main__":
    if not os.path.exists(USER_FILE_PATH):
        # abort if no user file detected
        sys.exit(0)
    username, password = read_user_file()

    # create RBAC database
    check_database_integrity()

    initial_users = db_users()
    if username not in initial_users:
        # create a new user
        create_user(username=username, password=password)
        users = db_users()
        uid = users[username]
        roles = db_roles()
        rid = roles["administrator"]
        set_user_role(
            user_id=[
                str(uid),
            ],
            role_ids=[
                str(rid),
            ],
        )
    else:
        # modify an existing user ("wazuh" or "wazuh-wui")
        uid = initial_users[username]
        update_user(
            user_id=[
                str(uid),
            ],
            password=password,
        )
    # disable unused default users
    for def_user in ['wazuh', 'wazuh-wui']:
        if def_user != username:
            disable_user(initial_users[def_user])
