"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import sys
import subprocess
import os
import sqlite3
from pathlib import Path

from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.modulesd.syscollector import patterns
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.utils import callbacks
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.utils.services import control_service
from wazuh_testing.constants.daemons import WAZUH_MANAGER, API_DAEMONS_REQUIREMENTS
from wazuh_testing.logger import logger
from wazuh_testing.utils import configuration, database, file, mocking, services


# Syscollector database paths
SYSCOLLECTOR_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'syscollector', 'db', 'local.db')

# Helper function to print table sizes
def print_db_table_sizes(db_path: str, message: str = ""):
    if message:
        print(f"\n--- {message} ---")
    else:
        print("\n--- DB Table Sizes ---")
    
    if not os.path.exists(db_path):
        print(f"Database file not found at: {db_path}")
        print("---------------------\n")
        return

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        tables = [
            'dbsync_osinfo', 'dbsync_hwinfo', 'dbsync_packages', 'dbsync_hotfixes',
            'dbsync_processes', 'dbsync_ports', 'dbsync_network_iface', 
            'dbsync_network_protocol', 'dbsync_network_address', 'dbsync_groups',
            'dbsync_users', 'dbsync_services', 'dbsync_browser_extensions'
        ]
        
        for table in tables:
            try:
                count = cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                print(f"Table {table}: {count} rows")
            except sqlite3.OperationalError as e:
                print(f"Table {table}: Not found or error - {e}")
            except Exception as e:
                print(f"Table {table}: Error querying count - {e}")
    except Exception as e:
        print(f"Error connecting to database {db_path}: {e}")
    finally:
        if conn:
            conn.close()
    print("---------------------\n")

@pytest.fixture()
def db_verifier():
    def _db_verifier_helper(message: str = ""):
        print_db_table_sizes(SYSCOLLECTOR_DB_PATH, message)
    return _db_verifier_helper

# Fixtures
@pytest.fixture()
def wait_for_syscollector_enabled():
    '''
    Wait for the syscollector module to start.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_MODULE_STARTED), timeout=60 if sys.platform == WINDOWS else 10)
    assert log_monitor.callback_result


def populate_syscollector_db():
    """
    Fixture to populate the syscollector database with dummy data before test.
    This ensures that when collectors are disabled, there will be data to clean.
    """
    # Ensure parent directory exists
    db_dir = Path(SYSCOLLECTOR_DB_PATH).parent
    db_dir.mkdir(parents=True, exist_ok=True)

    # Create and populate database
    conn = sqlite3.connect(SYSCOLLECTOR_DB_PATH)
    cursor = conn.cursor()

    try:
        # Create tables for each collector type
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS dbsync_osinfo (
                hostname TEXT,
                architecture TEXT,
                os_name TEXT,
                os_version TEXT,
                os_codename TEXT,
                os_major TEXT,
                os_minor TEXT,
                os_patch TEXT,
                os_build TEXT,
                os_platform TEXT,
                os_type TEXT,
                os_kernel_name TEXT,
                os_kernel_release TEXT,
                os_kernel_version TEXT,
                os_distribution_release TEXT,
                os_full TEXT,
                checksum TEXT,
                version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                PRIMARY KEY (os_name, os_version)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_hwinfo (
                serial_number TEXT,
                cpu_name TEXT,
                cpu_cores INTEGER,
                cpu_speed DOUBLE,
                memory_total INTEGER,
                memory_free INTEGER,
                memory_used INTEGER,
                checksum TEXT,
                version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                PRIMARY KEY (serial_number)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_packages(
                name TEXT,
                version_ TEXT,
                vendor TEXT,
                installed TEXT,
                path TEXT,
                architecture TEXT,
                category TEXT,
                description TEXT,
                size BIGINT,
                priority TEXT,
                multiarch TEXT,
                source TEXT,
                type TEXT,
                checksum TEXT,
                version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                PRIMARY KEY (name,version_,architecture,type,path)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_hotfixes(
                hotfix_name TEXT,
                checksum TEXT,
                version INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (hotfix_name)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_processes (
                pid TEXT,
                name TEXT,
                state TEXT,
                parent_pid BIGINT,
                utime BIGINT,
                stime BIGINT,
                command_line TEXT,
                args TEXT,
                args_count BIGINT,
                start BIGINT,
                checksum TEXT,
                version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                PRIMARY KEY (pid)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_ports (
                   network_transport TEXT,
                   source_ip TEXT,
                   source_port BIGINT,
                   destination_ip TEXT,
                   destination_port BIGINT,
                   host_network_egress_queue BIGINT,
                   host_network_ingress_queue BIGINT,
                   file_inode BIGINT,
                   interface_state TEXT,
                   process_pid BIGINT,
                   process_name TEXT,
                   checksum TEXT,
                   version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                   PRIMARY KEY (file_inode, network_transport, source_ip, source_port)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_network_iface (
                   interface_name TEXT,
                   interface_alias TEXT,
                   interface_type TEXT,
                   interface_state TEXT,
                   interface_mtu INTEGER,
                   host_mac TEXT,
                   host_network_egress_packages INTEGER,
                   host_network_ingress_packages INTEGER,
                   host_network_egress_bytes INTEGER,
                   host_network_ingress_bytes INTEGER,
                   host_network_egress_errors INTEGER,
                   host_network_ingress_errors INTEGER,
                   host_network_egress_drops INTEGER,
                   host_network_ingress_drops INTEGER,
                   checksum TEXT,
                   version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                   PRIMARY KEY (interface_name,interface_alias,interface_type)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_network_protocol (
                   interface_name TEXT,
                   network_type TEXT,
                   network_gateway TEXT,
                   network_dhcp INTEGER,
                   network_metric TEXT,
                   checksum TEXT,
                   version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                   PRIMARY KEY (interface_name,network_type)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_network_address (
                   interface_name TEXT,
                   network_type INTEGER,
                   network_ip TEXT,
                   network_netmask TEXT,
                   network_broadcast TEXT,
                   checksum TEXT,
                   version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                   PRIMARY KEY (interface_name,network_type,network_ip)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_groups (
                group_id BIGINT,
                group_name TEXT,
                group_description TEXT,
                group_id_signed BIGINT,
                group_uuid TEXT,
                group_is_hidden INTEGER,
                group_users TEXT,
                checksum TEXT,
                version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                PRIMARY KEY (group_name)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_users (
                    user_name TEXT,
                    user_full_name TEXT,
                    user_home TEXT,
                    user_id BIGINT,
                    user_uid_signed BIGINT,
                    user_uuid TEXT,
                    user_groups TEXT,
                    user_group_id BIGINT,
                    user_group_id_signed BIGINT,
                    user_created DOUBLE,
                    user_roles TEXT,
                    user_shell TEXT,
                    user_type TEXT,
                    user_is_hidden INTEGER,
                    user_is_remote INTEGER,
                    user_last_login BIGINT,
                    user_auth_failed_count BIGINT,
                    user_auth_failed_timestamp DOUBLE,
                    user_password_last_change DOUBLE,
                    user_password_expiration_date INTEGER,
                    user_password_hash_algorithm TEXT,
                    user_password_inactive_days INTEGER,
                    user_password_max_days_between_changes INTEGER,
                    user_password_min_days_between_changes INTEGER,
                    user_password_status TEXT,
                    user_password_warning_days_before_expiration INTEGER,
                    process_pid BIGINT,
                    host_ip TEXT,
                    login_status INTEGER,
                    login_tty TEXT,
                    login_type TEXT,
                    checksum TEXT,
                    version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                    PRIMARY KEY (user_name)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_services (
                    service_id TEXT,
                    service_name TEXT,
                    service_description TEXT,
                    service_type TEXT,
                    service_state TEXT,
                    service_sub_state TEXT,
                    service_enabled TEXT,
                    service_start_type TEXT,
                    service_restart TEXT,
                    service_frequency BIGINT,
                    service_starts_on_mount INTEGER,
                    service_starts_on_path_modified TEXT,
                    service_starts_on_not_empty_directory TEXT,
                    service_inetd_compatibility INTEGER,
                    process_pid BIGINT,
                    process_executable TEXT,
                    process_args TEXT,
                    process_user_name TEXT,
                    process_group_name TEXT,
                    process_working_dir TEXT,
                    process_root_dir TEXT,
                    file_path TEXT,
                    service_address TEXT,
                    log_file_path TEXT,
                    error_log_file_path TEXT,
                    service_exit_code INTEGER,
                    service_win32_exit_code INTEGER,
                    service_following TEXT,
                    service_object_path TEXT,
                    service_target_ephemeral_id BIGINT,
                    service_target_type TEXT,
                    service_target_address TEXT,
                    checksum TEXT,
                    version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                    PRIMARY KEY (service_id, file_path)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS dbsync_browser_extensions (
                    browser_name TEXT,
                    user_id TEXT,
                    package_name TEXT,
                    package_id TEXT,
                    package_version_ TEXT,
                    package_description TEXT,
                    package_vendor TEXT,
                    package_build_version TEXT,
                    package_path TEXT,
                    browser_profile_name TEXT,
                    browser_profile_path TEXT,
                    package_reference TEXT,
                    package_permissions TEXT,
                    package_type TEXT,
                    package_enabled INTEGER,
                    package_visible INTEGER,
                    package_autoupdate INTEGER,
                    package_persistent INTEGER,
                    package_from_webstore INTEGER,
                    browser_profile_referenced INTEGER,
                    package_installed TEXT,
                    file_hash_sha256 TEXT,
                    checksum TEXT,
                    version INTEGER NOT NULL DEFAULT 1, db_status_field_dm INTEGER DEFAULT 1,
                    PRIMARY KEY (browser_name,user_id,browser_profile_path,package_name,package_version_)) WITHOUT ROWID;
        ''')

        # Insert dummy data
        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_osinfo (hostname, architecture, os_name, os_version, os_codename, os_major, os_minor, os_patch, os_build, os_platform, os_type, os_kernel_name, os_kernel_release, os_kernel_version, os_distribution_release, os_full, checksum)
            VALUES ('test-host', 'x86_64', 'Ubuntu', '20.04', 'focal', '20', '04', '0', '0', 'ubuntu', 'linux', 'Linux', '5.4.0-100-generic', '#113-Ubuntu SMP Thu Feb 3 18:43:29 UTC 2022', '20.04', 'Ubuntu 20.04.4 LTS', 'os_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_hwinfo (serial_number, cpu_name, cpu_cores, cpu_speed, memory_total, memory_free, memory_used, checksum)
            VALUES ('TEST123456', 'Intel Core i7', 8, 3.6, 16384, 8192, 8192, 'hw_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_packages (name, version_, vendor, installed, path, architecture, category, description, size, priority, multiarch, source, type, checksum)
            VALUES ('test-package', '1.0.0', 'TestVendor', 'yes', '/usr/bin/test-package', 'x86_64', 'utils', 'A test package', 1024, 'optional', 'no', 'test-repo', 'deb', 'pkg_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_hotfixes (hotfix_name, checksum)
            VALUES ('KB1234567', 'hotfix_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_processes (pid, name, state, parent_pid, utime, stime, command_line, args, args_count, start, checksum)
            VALUES ('1234', 'test_process', 'S', 1, 100, 50, '/bin/test_process', '-v', 1, 1640995200, 'proc_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_ports (network_transport, source_ip, source_port, destination_ip, destination_port, host_network_egress_queue, host_network_ingress_queue, file_inode, interface_state, process_pid, process_name, checksum)
            VALUES ('tcp', '127.0.0.1', 8080, '0.0.0.0', 0, 0, 0, 12345, 'LISTEN', 1234, 'test_process', 'port_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_network_iface (interface_name, interface_alias, interface_type, interface_state, interface_mtu, host_mac, host_network_egress_packages, host_network_ingress_packages, host_network_egress_bytes, host_network_ingress_bytes, host_network_egress_errors, host_network_ingress_errors, host_network_egress_drops, host_network_ingress_drops, checksum)
            VALUES ('eth0', 'eth0:1', 'ethernet', 'UP', 1500, '00:11:22:33:44:55', 1000, 2000, 1024000, 2048000, 0, 0, 0, 0, 'iface_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_network_protocol (interface_name, network_type, network_gateway, network_dhcp, network_metric, checksum)
            VALUES ('eth0', 'ipv4', '192.168.1.1', 1, '100', 'proto_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_network_address (interface_name, network_type, network_ip, network_netmask, network_broadcast, checksum)
            VALUES ('eth0', 0, '192.168.1.100', '255.255.255.0', '192.168.1.255', 'addr_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_groups (group_id, group_name, group_description, group_id_signed, group_uuid, group_is_hidden, group_users, checksum)
            VALUES (1000, 'testgroup', 'Test Group', 1000, '1234-5678-90ab-cdef', 0, 'testuser', 'group_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_users (user_name, user_full_name, user_home, user_id, user_uid_signed, user_uuid, user_groups, user_group_id, user_group_id_signed, user_created, user_roles, user_shell, user_type, user_is_hidden, user_is_remote, user_last_login, user_auth_failed_count, user_auth_failed_timestamp, user_password_last_change, user_password_expiration_date, user_password_hash_algorithm, user_password_inactive_days, user_password_max_days_between_changes, user_password_min_days_between_changes, user_password_status, user_password_warning_days_before_expiration, process_pid, host_ip, login_status, login_tty, login_type, checksum)
            VALUES ('testuser', 'Test User', '/home/testuser', 1000, 1000, 'user-uuid-1234', 'testgroup', 1000, 1000, 1640995200.0, 'admin', '/bin/bash', 'user', 0, 0, 1641081600, 0, 0.0, 1640995200.0, 0, 'sha512', 0, 90, 0, 'active', 7, 0, '127.0.0.1', 1, 'tty1', 'local', 'user_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_services (service_id, service_name, service_description, service_type, service_state, service_sub_state, service_enabled, service_start_type, service_restart, service_frequency, service_starts_on_mount, service_starts_on_path_modified, service_starts_on_not_empty_directory, service_inetd_compatibility, process_pid, process_executable, process_args, process_user_name, process_group_name, process_working_dir, process_root_dir, file_path, service_address, log_file_path, error_log_file_path, service_exit_code, service_win32_exit_code, service_following, service_object_path, service_target_ephemeral_id, service_target_type, service_target_address, checksum)
            VALUES ('service_1', 'test_service', 'A test service', 'simple', 'running', 'active', 'enabled', 'auto', 'on-failure', 0, 0, '', '', 0, 1234, '/usr/bin/test_service', '-d', 'root', 'root', '/', '/', '/etc/systemd/system/test_service.service', '', '', '', 0, 0, '', '', 0, '', '', 'service_checksum_1')
        ''')

        cursor.execute('''
            INSERT OR IGNORE INTO dbsync_browser_extensions (browser_name, user_id, package_name, package_id, package_version_, package_description, package_vendor, package_build_version, package_path, browser_profile_name, browser_profile_path, package_reference, package_permissions, package_type, package_enabled, package_visible, package_autoupdate, package_persistent, package_from_webstore, browser_profile_referenced, package_installed, file_hash_sha256, checksum)
            VALUES ('chrome', 'user1', 'Test Extension', 'abcdefghijklmno', '1.0.0', 'A test extension', 'Test Vendor', '1.0.0', '/path/to/extension', 'Default', '/home/user1/.config/google-chrome/Default', '', '', 'extension', 1, 1, 1, 1, 1, 1, 'yes', 'sha256hash', 'ext_checksum_1')
        ''')

        conn.commit()

        # Verify data insertion
        print_db_table_sizes(SYSCOLLECTOR_DB_PATH, "DB Population Verification")
    except Exception as e:
        pytest.fail(f"Failed to populate syscollector database: {e}")
    finally:
        conn.close()


@pytest.fixture()
def custom_daemons_handler(request: pytest.FixtureRequest) -> None:
    """Helper function to handle Wazuh daemons.

    It uses `daemons_handler_configuration` of each module in order to configure the behavior of the fixture.

    The  `daemons_handler_configuration` should be a dictionary with the following keys:
        daemons (list, optional): List with every daemon to be used by the module. In case of empty a ValueError
            will be raised
        all_daemons (boolean): Configure to restart all wazuh services. Default `False`.
        ignore_errors (boolean): Configure if errors in daemon handling should be ignored. This option is available
        in order to use this fixture along with invalid configuration. Default `False`

    Args:
        request (pytest.FixtureRequest): Provide information about the current test function which made the request.
    """
    daemons = []
    ignore_errors = False
    all_daemons = False

    if config := getattr(request.module, 'daemons_handler_configuration', None):
        if 'daemons' in config:
            daemons = config['daemons']
            if not daemons or len(daemons) == 0 or type(daemons) not in [list, tuple]:
                logger.error('Daemons list/tuple is not set')
                raise ValueError

        if 'all_daemons' in config:
            logger.debug(f"Wazuh control set to {config['all_daemons']}")
            all_daemons = config['all_daemons']

        if 'ignore_errors' in config:
            logger.debug(f"Ignore error set to {config['ignore_errors']}")
            ignore_errors = config['ignore_errors']
    else:
        logger.debug("Wazuh control set to 'all_daemons'")
        all_daemons = True

    try:
        if all_daemons:
            logger.debug('Stopping wazuh using wazuh-control')
            services.control_service('stop')
        else:
            for daemon in daemons:
                logger.debug(f"Stopping {daemon}")
                services.control_service('stop', daemon=daemon)

    except ValueError as value_error:
        logger.error(f"{str(value_error)}")
        if not ignore_errors:
            raise value_error
    except subprocess.CalledProcessError as called_process_error:
        logger.error(f"{str(called_process_error)}")
        if not ignore_errors:
            raise called_process_error

    # Ensures at least one entry in each syscollector table
    populate_syscollector_db()

    try:
        if all_daemons:
            logger.debug('Starting wazuh using wazuh-control')
            services.control_service('start')
        else:
            for daemon in daemons:
                logger.debug(f"Starting {daemon}")
                services.control_service('start', daemon=daemon)

    except ValueError as value_error:
        logger.error(f"{str(value_error)}")
        if not ignore_errors:
            raise value_error
    except subprocess.CalledProcessError as called_process_error:
        logger.error(f"{str(called_process_error)}")
        if not ignore_errors:
            raise called_process_error

    yield

    if all_daemons:
        logger.debug('Stopping wazuh using wazuh-control')
        services.control_service('stop')
    else:
        if daemons == API_DAEMONS_REQUIREMENTS: daemons.reverse()  # Stop in reverse, otherwise the next start will fail
        for daemon in daemons:
            logger.debug(f"Stopping {daemon}")
            services.control_service('stop', daemon=daemon)
