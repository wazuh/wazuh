# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import sys
from unittest.mock import patch, MagicMock, AsyncMock

import pytest


class Arguments:
    def __init__(self, reset_force=False, func=None, user=None, password_file=None, passwords_file=None):
        self.reset_force = reset_force
        self.func = func
        self.user = user
        self.password_file = password_file
        self.passwords_file = passwords_file


with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from scripts import rbac_control
        from wazuh.tests.test_security import db_setup # noqa


@patch('scripts.rbac_control.sys.exit')
def test_signal_handler(mock_exit):
    """Check if exit is called in the `signal_handler` function."""
    rbac_control.signal_handler('test', 'test')
    mock_exit.assert_called_once_with(1)


@pytest.mark.asyncio
@pytest.mark.parametrize("user_input", ["NewPassword1!", ""])
@patch("builtins.print")
@patch("yaml.safe_load", return_value={"default_users": ["testing_user"]})
@patch("scripts.rbac_control.cluster_utils.forward_function")
async def test_restore_default_passwords(forward_mock: AsyncMock, safe_load_mock, print_mock, user_input, db_setup):
    """Check if the `restore_default_passwords` uses the correct parameters when called.

    Parameters
    ----------
    user_input : str
        Mocked password.
    """
    security, _, _ = db_setup
    with patch("getpass.getpass", return_value=user_input):
        await rbac_control.restore_default_passwords(Arguments())
        if user_input != "":
            # `current_user` is required for the default users, whose IDs are reserved ones.
            forward_mock.assert_called_with(security.update_user,
                                            f_kwargs={'user_id': '1', 'password': user_input,
                                                      'current_user': 'testing_user'},
                                            request_type="local_master")
            assert "testing_user" in print_mock.call_args[0][0]
            assert "UPDATED" in print_mock.call_args[0][0]
        else:
            forward_mock.assert_not_called()
            print_mock.assert_not_called()


@pytest.mark.asyncio
@patch("builtins.print")
@patch("yaml.safe_load", return_value={"default_users": ["testing_user", "other_user"]})
@patch("scripts.rbac_control.cluster_utils.forward_function")
async def test_restore_default_passwords_from_file(forward_mock: AsyncMock, safe_load_mock, print_mock, tmp_path,
                                                   db_setup):
    """Check that `restore_default_passwords` applies every password of a passwords file."""
    security, _, _ = db_setup
    passwords_file = tmp_path / 'passwords.json'
    passwords_file.write_text(json.dumps({'other_user': 'NewPassword1!', 'testing_user': 'NewPassword2!'}))

    await rbac_control.restore_default_passwords(Arguments(passwords_file=str(passwords_file)))

    # Each user is updated with its own password and ID, which is its position in the defaults file.
    assert [call.kwargs['f_kwargs'] for call in forward_mock.call_args_list] == [
        {'user_id': '2', 'password': 'NewPassword1!', 'current_user': 'other_user'},
        {'user_id': '1', 'password': 'NewPassword2!', 'current_user': 'testing_user'},
    ]
    assert all(call.args[0] == security.update_user for call in forward_mock.call_args_list)


@pytest.mark.asyncio
@patch("builtins.print")
@patch("yaml.safe_load", return_value={"default_users": ["testing_user", "other_user"]})
@patch("scripts.rbac_control.cluster_utils.forward_function")
async def test_restore_default_passwords_single_user(forward_mock: AsyncMock, safe_load_mock, print_mock, tmp_path,
                                                     db_setup):
    """Check that `restore_default_passwords` only updates the requested user from a password file."""
    security, _, _ = db_setup
    password_file = tmp_path / 'password.txt'
    # The trailing newline of a text file is not part of the password.
    password_file.write_text('NewPassword1!\n')

    await rbac_control.restore_default_passwords(Arguments(user='other_user', password_file=str(password_file)))

    forward_mock.assert_called_once_with(security.update_user,
                                         f_kwargs={'user_id': '2', 'password': 'NewPassword1!',
                                                   'current_user': 'other_user'},
                                         request_type="local_master")


@pytest.mark.asyncio
@pytest.mark.parametrize("arguments, expected_error", [
    ({'user': 'not_a_default_user'}, "is not an RBAC default user"),
    ({'password_file': 'password.txt'}, "needs the user it applies to"),
    ({'user': 'testing_user', 'passwords_file': 'passwords.json'}, "cannot be combined"),
])
@patch("builtins.print")
@patch("yaml.safe_load", return_value={"default_users": ["testing_user"]})
@patch("scripts.rbac_control.cluster_utils.forward_function")
async def test_restore_default_passwords_invalid_arguments(forward_mock: AsyncMock, safe_load_mock, print_mock,
                                                           arguments, expected_error, db_setup):
    """Check that `restore_default_passwords` rejects invalid argument combinations without updating anything.

    Parameters
    ----------
    arguments : dict
        Arguments given to the script.
    expected_error : str
        Fragment expected in the printed error.
    """
    with pytest.raises(SystemExit) as exit_error:
        await rbac_control.restore_default_passwords(Arguments(**arguments))

    assert exit_error.value.code == 1
    assert expected_error in print_mock.call_args[0][0]
    forward_mock.assert_not_called()


@pytest.mark.asyncio
@patch("builtins.print")
@patch("getpass.getpass", return_value="NewPassword1!")
@patch("yaml.safe_load", return_value={"default_users": ["testing_user"]})
async def test_restore_default_passwords_exceptions(safe_load_mock, getpass_mock, print_mock):
    """Check the `restore_default_passwords` function behaviour when receiving exceptions."""
    exception_message = "Random exception message"
    with patch("scripts.rbac_control.cluster_utils.forward_function", return_value=Exception(exception_message)):
        # A failed update must be reported through the exit status, not only printed.
        with pytest.raises(SystemExit) as exit_error:
            await rbac_control.restore_default_passwords(Arguments())

        assert exit_error.value.code == 1
        assert "testing_user" in print_mock.call_args[0][0]
        assert exception_message in print_mock.call_args[0][0]


@pytest.mark.asyncio
@pytest.mark.parametrize("user_input", ["RESET", "whatever"])
@patch("builtins.print")
@patch("scripts.rbac_control.cluster_utils.forward_function")
async def test_reset_rbac_database(forward_mock, print_mock, user_input, db_setup):
    """Check if the `restore_default_passwords` uses the correct parameters when called.

    Parameters
    ----------
    user_input : str
        Mocked password.
    """
    _, _, core_security = db_setup
    with patch("builtins.input", return_value=user_input):
        if user_input == "RESET":
            await rbac_control.reset_rbac_database(Arguments())
            forward_mock.assert_called_with(core_security.rbac_db_factory_reset, request_type="local_master")
            assert "Successfully reset RBAC database" in print_mock.call_args[0][0]
        else:
            with pytest.raises(SystemExit):
                await rbac_control.reset_rbac_database(Arguments())
                forward_mock.assert_not_called()
                assert "RBAC database reset aborted." in print_mock.call_args[0][0]


@pytest.mark.asyncio
@patch("builtins.print")
@patch("builtins.input", return_value="RESET")
async def test_reset_rbac_database_exceptions(input_mock, print_mock):
    """Check the `restore_default_passwords` function behaviour when receiving exceptions."""
    exception_message = "Random exception message"
    with patch("scripts.rbac_control.cluster_utils.forward_function", return_value=Exception(exception_message)):
        await rbac_control.reset_rbac_database(Arguments())
        assert "RBAC database reset failed" in print_mock.call_args[0][0]
        assert exception_message in print_mock.call_args[0][0]


@patch("scripts.rbac_control.sys.exit")
def test_get_script_arguments(exit_mock):
    """Test exit conditions for the `get_script_arguments` function."""
    with patch("scripts.rbac_control.sys.argv", new=["script", "at_least_one_argument"]):
        # Valid number of script arguments
        rbac_control.get_script_arguments()
        exit_mock.assert_called_with(2)

    # Invalid number of script arguments
    with patch("scripts.rbac_control.sys.argv", new=["script"]):
        rbac_control.get_script_arguments()
        exit_mock.assert_called_with(0)


@pytest.mark.asyncio
@patch("scripts.rbac_control.sys.exit")
@patch("scripts.rbac_control.sys.argv", new=["script", "at_least_one_argument"])
@patch("scripts.rbac_control.restore_default_passwords")
@patch("scripts.rbac_control.reset_rbac_database")
async def test_main(reset_mock, restore_mock, exit_mock):
    """Test all the possible options for the `main` function depending on user input."""
    # change-password
    rbac_control.args = Arguments(func=rbac_control.restore_default_passwords)
    await rbac_control.main()
    restore_mock.assert_called_once()
    restore_mock.reset_mock()
    reset_mock.assert_not_called()
    exit_mock.assert_called_with(0)

    # factory-reset
    rbac_control.args = Arguments(func=rbac_control.reset_rbac_database)
    await rbac_control.main()
    reset_mock.assert_called_once()
    reset_mock.reset_mock()
    restore_mock.assert_not_called()
    exit_mock.assert_called_with(0)
