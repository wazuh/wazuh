# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import io
import json
import os
import sys

import yaml
from unittest.mock import patch, MagicMock, AsyncMock, call

import pytest


def _provisioned(path) -> dict:
    """Read back the file `set-password` writes, in the shape the credentials tooling shares."""
    document = yaml.safe_load(path.read_text())
    return {entry['name']: entry['password'] for entry in document['manager']}


class Arguments:
    def __init__(self, reset_force=False, func=None, user=None, password_file=None, passwords_file=None,
                 local=False):
        self.reset_force = reset_force
        self.func = func
        self.user = user
        self.password_file = password_file
        self.passwords_file = passwords_file
        self.local = local


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
@pytest.mark.parametrize("user_input", ["New-Password1!", ""])
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
    # A fresh import, not a reference captured earlier: `db_setup` reloads `wazuh.rbac.orm` per test,
    # and an earlier test's import of `wazuh.core.security` can still hold a function object from a
    # previous reload.
    from wazuh.core.security import ensure_rbac_database
    passwords_file = tmp_path / 'passwords.json'
    passwords_file.write_text(json.dumps({'other_user': 'New-Password1!', 'testing_user': 'New-Password2!'}))

    await rbac_control.restore_default_passwords(Arguments(passwords_file=str(passwords_file)))

    # The RBAC database is ensured to exist first (a no-op on a node where it already does), then
    # each user is updated with its own password and ID, which is its position in the defaults file.
    assert forward_mock.call_args_list[0] == call(ensure_rbac_database, request_type="local_master")
    assert [c.kwargs['f_kwargs'] for c in forward_mock.call_args_list[1:]] == [
        {'user_id': '2', 'password': 'New-Password1!', 'current_user': 'other_user'},
        {'user_id': '1', 'password': 'New-Password2!', 'current_user': 'testing_user'},
    ]
    assert all(c.args[0] == security.update_user for c in forward_mock.call_args_list[1:])


@pytest.mark.asyncio
@patch("builtins.print")
@patch("yaml.safe_load", return_value={"default_users": ["testing_user", "other_user"]})
@patch("wazuh.core.cluster.utils.forward_function")
async def test_restore_default_passwords_local(forward_mock, safe_load_mock, print_mock, tmp_path, db_setup):
    """`--local` routes every call as `local_any`, the only routing that reaches a worker's own database.

    `local_master` on a worker executes on the master, so without the flag the command silently retargets
    and still reports success.
    """
    from wazuh.core.security import ensure_rbac_database
    passwords_file = tmp_path / 'passwords.json'
    passwords_file.write_text(json.dumps({'testing_user': 'New-Password1!'}))

    await rbac_control.restore_default_passwords(Arguments(passwords_file=str(passwords_file), local=True))

    assert forward_mock.call_args_list[0] == call(ensure_rbac_database, request_type="local_any")
    assert all(c.kwargs['request_type'] == "local_any" for c in forward_mock.call_args_list[1:])


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
    password_file.write_text('New-Password1!\n')

    await rbac_control.restore_default_passwords(Arguments(user='other_user', password_file=str(password_file)))

    # First call ensures the RBAC database exists, second applies the requested password.
    assert forward_mock.call_count == 2
    forward_mock.assert_called_with(security.update_user,
                                    f_kwargs={'user_id': '2', 'password': 'New-Password1!',
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
@patch("getpass.getpass", return_value="New-Password1!")
@patch("yaml.safe_load", return_value={"default_users": ["testing_user"]})
async def test_restore_default_passwords_exceptions(safe_load_mock, getpass_mock, print_mock):
    """Check the `restore_default_passwords` function behaviour when the update itself fails."""
    exception_message = "Random exception message"
    # First call (ensure the RBAC database exists) succeeds; the update call fails. A callable
    # side_effect is used, not a plain list: with a list, unittest.mock raises an Exception item
    # instead of returning it, which does not match forward_function's real contract of returning
    # the exception rather than propagating it.
    responses = iter([MagicMock(), Exception(exception_message)])
    with patch("scripts.rbac_control.cluster_utils.forward_function",
              side_effect=lambda *args, **kwargs: next(responses)):
        # A failed update must be reported through the exit status, not only printed.
        with pytest.raises(SystemExit) as exit_error:
            await rbac_control.restore_default_passwords(Arguments())

        assert exit_error.value.code == 1
        assert "testing_user" in print_mock.call_args[0][0]
        assert exception_message in print_mock.call_args[0][0]


@pytest.mark.asyncio
@patch("builtins.print")
@patch("getpass.getpass", return_value="New-Password1!")
@patch("yaml.safe_load", return_value={"default_users": ["testing_user"]})
async def test_restore_default_passwords_ensure_db_fails(safe_load_mock, getpass_mock, print_mock):
    """A node whose RBAC database cannot be ensured to exist (e.g. a worker) aborts before any update."""
    exception_message = "Random exception message"
    with patch("scripts.rbac_control.cluster_utils.forward_function",
              return_value=Exception(exception_message)) as forward_mock:
        with pytest.raises(SystemExit) as exit_error:
            await rbac_control.restore_default_passwords(Arguments())

        assert exit_error.value.code == 1
        assert exception_message in print_mock.call_args[0][0]
        # No update was attempted: only the ensure-DB call was made.
        forward_mock.assert_called_once()
        assert forward_mock.call_args.kwargs == {'request_type': 'local_master'}


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
        # Non-zero too: an installer chains this call on the exit status
        with pytest.raises(SystemExit):
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


@pytest.mark.asyncio
@patch("builtins.print")
async def test_preseed_default_password(print_mock, tmp_path, db_setup):
    """Each execution provisions one user and keeps the ones already provisioned.

    A password is set per execution, and the API refuses a file that does not name every default user, so
    the file has to be merged rather than overwritten.
    """
    preseeded_file = tmp_path / "wazuh-preseeded-passwords.yml"

    with patch("wazuh.rbac.orm.PRESEEDED_PASSWORDS_FILE", new=str(preseeded_file)), \
            patch("wazuh.rbac.orm.DB_FILE", new=str(tmp_path / "absent.db")), \
            patch("shutil.chown"), patch("wazuh.core.common.wazuh_gid", return_value=os.getgid()), \
            patch("wazuh.rbac.orm.wazuh_uid", return_value=os.getuid()), \
            patch("wazuh.rbac.orm.wazuh_gid", return_value=os.getgid()), \
            patch("scripts.rbac_control.sys.stdin") as stdin_mock:
        stdin_mock.readline.side_effect = ["Pr3seeded-Pass!\n", "An0ther-Pass!\n"]
        await rbac_control.preseed_default_password(Arguments(user="wazuh"))
        assert _provisioned(preseeded_file) == {"wazuh": "Pr3seeded-Pass!"}
        # Incomplete until the second user is provisioned, and the command says so
        assert any("Still missing" in c.args[0] for c in print_mock.call_args_list)

        await rbac_control.preseed_default_password(Arguments(user="wazuh-wui"))

    assert _provisioned(preseeded_file) == {"wazuh": "Pr3seeded-Pass!", "wazuh-wui": "An0ther-Pass!"}
    assert oct(preseeded_file.stat().st_mode)[-3:] == "640"


@pytest.mark.asyncio
@patch("builtins.print")
async def test_preseed_default_password_drops_a_foreign_entry(print_mock, tmp_path, db_setup):
    """Merging keeps only the default users.

    An entry naming anything else, left by another tool, would survive every merge and make the API refuse
    the file at every start, with no call to this command able to correct it.
    """
    preseeded_file = tmp_path / "wazuh-preseeded-passwords.yml"
    preseeded_file.write_text(yaml.safe_dump({'manager': [{'name': 'otro', 'password': 'Whatever-Pass1.'}]}))
    preseeded_file.chmod(0o640)

    with patch("wazuh.rbac.orm.PRESEEDED_PASSWORDS_FILE", new=str(preseeded_file)), \
            patch("wazuh.rbac.orm.DB_FILE", new=str(tmp_path / "absent.db")), \
            patch("shutil.chown"), patch("wazuh.core.common.wazuh_gid", return_value=os.getgid()), \
            patch("wazuh.rbac.orm.wazuh_uid", return_value=os.getuid()), \
            patch("wazuh.rbac.orm.wazuh_gid", return_value=os.getgid()), \
            patch("scripts.rbac_control.sys.stdin", new=io.StringIO("Pr3seeded-Pass!\n")):
        await rbac_control.preseed_default_password(Arguments(user="wazuh"))

    assert _provisioned(preseeded_file) == {"wazuh": "Pr3seeded-Pass!"}


@pytest.mark.asyncio
@patch("builtins.print")
async def test_preseed_default_password_refuses_an_untrusted_file(print_mock, tmp_path, db_setup):
    """A file the API would refuse is not merged and vouched for: it is refused here too."""
    preseeded_file = tmp_path / "wazuh-preseeded-passwords.yml"
    preseeded_file.write_text(yaml.safe_dump({'manager': [{'name': 'wazuh-wui', 'password': 'Whatever-Pass1.'}]}))
    preseeded_file.chmod(0o644)

    with patch("wazuh.rbac.orm.PRESEEDED_PASSWORDS_FILE", new=str(preseeded_file)), \
            patch("wazuh.rbac.orm.DB_FILE", new=str(tmp_path / "absent.db")), \
            patch("wazuh.rbac.orm.wazuh_uid", return_value=os.getuid()), \
            patch("wazuh.rbac.orm.wazuh_gid", return_value=os.getgid()), \
            patch("scripts.rbac_control.sys.stdin", new=io.StringIO("Pr3seeded-Pass!\n")):
        with pytest.raises(SystemExit):
            await rbac_control.preseed_default_password(Arguments(user="wazuh"))

    assert "readable by others" in print_mock.call_args[0][0]
    assert _provisioned(preseeded_file) == {"wazuh-wui": "Whatever-Pass1."}


@pytest.mark.asyncio
@pytest.mark.parametrize("user,password,reason", [
    ("wazuh-wu", "Pr3seeded-Pass!", "is not an RBAC default user"),
    ("wazuh", "short", "does not satisfy the API password policy"),
    ("wazuh", "nouppercaseordigit!", "does not satisfy the API password policy"),
])
@patch("builtins.print")
async def test_preseed_default_password_refused(print_mock, tmp_path, user, password, reason, db_setup):
    """A refused input writes nothing: the file the API reads is never left in a state it rejects."""
    preseeded_file = tmp_path / "wazuh-preseeded-passwords.yml"

    with patch("wazuh.rbac.orm.PRESEEDED_PASSWORDS_FILE", new=str(preseeded_file)), \
            patch("wazuh.rbac.orm.DB_FILE", new=str(tmp_path / "absent.db")), \
            patch("scripts.rbac_control.sys.stdin", new=io.StringIO(f"{password}\n")):
        with pytest.raises(SystemExit):
            await rbac_control.preseed_default_password(Arguments(user=user))

    assert not preseeded_file.exists()
    assert reason in print_mock.call_args[0][0]


@pytest.mark.asyncio
@patch("builtins.print")
async def test_preseed_default_password_takes_the_first_stdin_line(print_mock, tmp_path, db_setup):
    """Only the first line of the standard input, without the newline `echo` adds, which the policy rejects."""
    preseeded_file = tmp_path / "wazuh-preseeded-passwords.yml"

    with patch("wazuh.rbac.orm.PRESEEDED_PASSWORDS_FILE", new=str(preseeded_file)), \
            patch("wazuh.rbac.orm.DB_FILE", new=str(tmp_path / "absent.db")), \
            patch("shutil.chown"), patch("wazuh.core.common.wazuh_gid", return_value=os.getgid()), \
            patch("wazuh.rbac.orm.wazuh_uid", return_value=os.getuid()), \
            patch("wazuh.rbac.orm.wazuh_gid", return_value=os.getgid()), \
            patch("scripts.rbac_control.sys.stdin", new=io.StringIO("Fr0m-Stdin-Pass!\nignored\n")):
        await rbac_control.preseed_default_password(Arguments(user="wazuh"))

    assert _provisioned(preseeded_file) == {"wazuh": "Fr0m-Stdin-Pass!"}


@pytest.mark.asyncio
@patch("builtins.print")
async def test_preseed_default_password_reports_existing_database(print_mock, tmp_path, db_setup):
    """Provisioning a node whose database exists writes the file but does not change the password in use."""
    preseeded_file = tmp_path / "wazuh-preseeded-passwords.yml"
    existing_db = tmp_path / "rbac.db"
    existing_db.touch()

    with patch("wazuh.rbac.orm.PRESEEDED_PASSWORDS_FILE", new=str(preseeded_file)), \
            patch("wazuh.rbac.orm.DB_FILE", new=str(existing_db)), \
            patch("shutil.chown"), patch("wazuh.core.common.wazuh_gid", return_value=os.getgid()), \
            patch("wazuh.rbac.orm.wazuh_uid", return_value=os.getuid()), \
            patch("wazuh.rbac.orm.wazuh_gid", return_value=os.getgid()), \
            patch("scripts.rbac_control.sys.stdin", new=io.StringIO("Pr3seeded-Pass!\n")):
        await rbac_control.preseed_default_password(Arguments(user="wazuh"))

    assert preseeded_file.exists()
    assert "does not change the password in use" in print_mock.call_args[0][0]


@pytest.mark.asyncio
@patch("builtins.print")
@patch("yaml.safe_load", return_value={"default_users": ["wazuh", "wazuh-wui"]})
@patch("wazuh.core.cluster.utils.forward_function")
async def test_restore_default_passwords_refuses_before_applying(forward_mock, safe_load_mock, print_mock,
                                                                 tmp_path, db_setup):
    """A password the policy rejects stops the run before any user is updated.

    `update_user` rejects it too, but only once the users read before it have already been applied.
    """
    passwords_file = tmp_path / "passwords.json"
    passwords_file.write_text(json.dumps({"wazuh": "V4lid-Password!", "wazuh-wui": "short"}))

    with pytest.raises(SystemExit):
        await rbac_control.restore_default_passwords(Arguments(passwords_file=str(passwords_file)))

    forward_mock.assert_not_called()
    assert "does not satisfy the API password policy" in print_mock.call_args[0][0]
