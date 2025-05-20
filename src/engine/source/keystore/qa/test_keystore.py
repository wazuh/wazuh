# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from subprocess import Popen, PIPE
import logging
import os
import pytest
from pathlib import Path

LOGGER = logging.getLogger(__name__)
KEYSTORE_BINARY = "./wazuh-keystore"
KEYSTORE_TESTTOOL_BINARY = "./wazuh-keystore_tool"
KEYSTORE_DB_PATH = "./keystore"

# Helper methods

def run_command(command):
    """ Runs a command using subprocess.Popen and returns the stdout. In case of failure, it logs the error and fails the test.

    Args:
        command (str): The command to run

    Returns:
        str: The stdout of the command
    """
    with Popen(command, stdout=PIPE, stderr=PIPE, shell=True) as process:
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            LOGGER.error("Error running command: %s", command)
            LOGGER.error("stdout: %s", stdout.decode())
            LOGGER.error("stderr: %s", stderr.decode())
            pytest.fail()
    return stdout.decode()

def get_password():
    """ Runs the testtool to get the password from the keystore and returns it.

    Returns:
        str: The password stored in the keystore stripped of any leading/trailing whitespaces.
    """
    command = [KEYSTORE_TESTTOOL_BINARY, "-k", "password", "-p", KEYSTORE_DB_PATH]
    command = " ".join(command)

    output = run_command(command)
    index = output.find("password:")
    return output[index + 9:].strip()

def set_password(password):
    """ Sets the password in the keystore using the keystore binary and the value parameter.

    Args:
        password (str): The password to set in the keystore.
    """
    command = [KEYSTORE_BINARY, "-k", "password", "-v", f"'{password}'", "-p", KEYSTORE_DB_PATH]
    command = " ".join(command)
    run_command(command)

def set_password_echo(password):
    """ Sets the password in the keystore using the keystore binary and the 'echo' command.

    Args:
        password (str): The password to set in the keystore.
    """
    command = ["echo",f"'{password}'", "|" , KEYSTORE_BINARY, "-k", "password", "-p", KEYSTORE_DB_PATH]
    command = " ".join(command)
    run_command(command)

def set_password_from_file(password):
    """ Sets the password in the keystore using the keystore binary and the value from path parameter.

    Args:
        password (str): The password to set in the keystore.
    """
    with open("password.txt", "w", encoding='utf-8') as f:
        f.write(password)
    command = [KEYSTORE_BINARY, "-k", "password", "-vp", "./password.txt", "-p", KEYSTORE_DB_PATH]
    command = " ".join(command)
    run_command(command)
    os.remove("password.txt")

def set_password_redirect_file(password):
    """ Sets the password in the keystore using the keystore binary and redirecting the value from a file.

    Args:
        password (str): The password to set in the keystore.
    """
    with open("password.txt", "w", encoding='utf-8') as f:
        f.write(password)
    command = [KEYSTORE_BINARY, "-k", "password","<","./password.txt", "-p", KEYSTORE_DB_PATH]
    command = " ".join(command)
    run_command(command)
    os.remove("password.txt")

def set_password_cat_file(password):
    """ Sets the password in the keystore using the keystore binary and reading the value from a file with cat.

    Args:
        password (str): The password to set in the keystore.
    """
    with open("password.txt", "w", encoding='utf-8') as f:
        f.write(password)
    command = ["cat", "./password.txt", "|", KEYSTORE_BINARY, "-k", "password", "-p", KEYSTORE_DB_PATH]
    command = " ".join(command)
    run_command(command)
    os.remove("password.txt")

def clear_password():
    """ This method clears the password stored in the keystore.
    """
    command = [KEYSTORE_BINARY, "-k", "password", "-v", "NOT_USED_PASS", "-p", KEYSTORE_DB_PATH]
    command = " ".join(command)
    run_command(command)

# Fixtures

@pytest.fixture(autouse=True, scope='session')
def setup_teardown():
    """ Setup and teardown for all tests. The self-signed certificates are created before the tests, and removed after them.
        Also, the keystore is removed.
    """
    # Setup

    yield

    # Teardown
    os.system(f"rm -rf {KEYSTORE_DB_PATH}")

# Tests

password_list = ["password",
                 "kdashf 781264723(/$%&)(IUGHB/)",
                 """~`R4+$b"Eç-öÇsý~ðe^î4"ôÙÆ-DXõ$ÁW"ô´C©~7ÙU9ZZ9[S£>KPû3ñ{Äñ¦}@ED×DCË`$Ï@©}¸ÉR2ÚðÑqí§XÄ(¬x%ã,ú»cf}céq%~Ð°n¾ëÜKÀ®;sÓí½(Ccô;zÙê³¯â¼{s""",
                 """"NñÚ?e2"CÀ !Û(z"û>ESÊ¥â½°|NØ3~}¬éØ#ÓÐ`\èï9¤ ¢,Ñ|`Éà©jqø!ßõ§JÐØæ"ê¢8åzL)-yE1ª58Ñõ×ùCd;©6^{Ý¬[Æzn&F½²Ð 1á(Çt{*¤}^êt2H¬¢ñ0=âËàÕÐ>àBí"""]

insertion_methods = [set_password,
                     set_password_from_file,
                     set_password_redirect_file,
                     set_password_cat_file,
                     set_password_echo]

@pytest.mark.parametrize("password", password_list)
@pytest.mark.parametrize("insertion_method", insertion_methods)
def test_keystore_parameters(password, insertion_method):
    """ Verifies each password insertion method with different passwords.

    Args:
        password (str): The password to insert and verify in the keystore.
        insertion_method: The method to insert the password in the keystore.
    """
    insertion_method(password)
    pass_from_DB = get_password()
    clear_password()
    assert pass_from_DB == password
