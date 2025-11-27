"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import sys
import os
import sqlite3
from pathlib import Path

from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.modulesd.syscollector import patterns
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.utils import callbacks
from wazuh_testing.constants.platforms import WINDOWS


# Syscollector database paths
SYSCOLLECTOR_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'syscollector', 'db', 'local.db')


# Fixtures
@pytest.fixture()
def wait_for_syscollector_enabled():
    '''
    Wait for the syscollector module to start.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_MODULE_STARTED), timeout=60 if sys.platform == WINDOWS else 10)
    assert log_monitor.callback_result


@pytest.fixture()
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
        # Hardware table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_hwinfo (
                scan_id INTEGER,
                scan_time TEXT,
                board_serial TEXT,
                cpu_name TEXT,
                cpu_cores INTEGER,
                cpu_mhz REAL,
                ram_total INTEGER,
                ram_free INTEGER,
                ram_usage INTEGER,
                checksum TEXT PRIMARY KEY
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_hwinfo
            (scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum)
            VALUES (1, '2024/11/26 00:00:00', 'TEST123', 'Intel Core i7', 8, 2400.0, 16384, 8192, 50, 'hw_checksum_1')
        ''')

        # OS table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_osinfo (
                scan_id INTEGER,
                scan_time TEXT,
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
                sysname TEXT,
                release TEXT,
                version TEXT,
                os_release TEXT,
                os_display_version TEXT,
                checksum TEXT PRIMARY KEY,
                reference TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_osinfo
            (scan_id, scan_time, hostname, architecture, os_name, os_version, checksum)
            VALUES (1, '2024/11/26 00:00:00', 'test-host', 'x86_64', 'Ubuntu', '20.04', 'os_checksum_1')
        ''')

        # Packages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_programs (
                scan_id INTEGER,
                scan_time TEXT,
                format TEXT,
                name TEXT,
                priority TEXT,
                section TEXT,
                size INTEGER,
                vendor TEXT,
                install_time TEXT,
                version TEXT,
                architecture TEXT,
                multiarch TEXT,
                source TEXT,
                description TEXT,
                location TEXT,
                checksum TEXT PRIMARY KEY,
                item_id TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_programs
            (scan_id, scan_time, format, name, version, architecture, checksum, item_id)
            VALUES (1, '2024/11/26 00:00:00', 'deb', 'test-package', '1.0', 'amd64', 'pkg_checksum_1', 'pkg_1')
        ''')

        # Processes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_processes (
                scan_id INTEGER,
                scan_time TEXT,
                pid TEXT,
                name TEXT,
                state TEXT,
                ppid INTEGER,
                utime INTEGER,
                stime INTEGER,
                cmd TEXT,
                argvs TEXT,
                euser TEXT,
                ruser TEXT,
                suser TEXT,
                egroup TEXT,
                rgroup TEXT,
                sgroup TEXT,
                fgroup TEXT,
                priority INTEGER,
                nice INTEGER,
                size INTEGER,
                vm_size INTEGER,
                resident INTEGER,
                share INTEGER,
                start_time INTEGER,
                pgrp INTEGER,
                session INTEGER,
                nlwp INTEGER,
                tgid INTEGER,
                tty INTEGER,
                processor INTEGER,
                checksum TEXT PRIMARY KEY
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_processes
            (scan_id, scan_time, pid, name, state, ppid, checksum)
            VALUES (1, '2024/11/26 00:00:00', '1', 'systemd', 'S', 0, 'proc_checksum_1')
        ''')

        # Network interface table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_netiface (
                scan_id INTEGER,
                scan_time TEXT,
                name TEXT PRIMARY KEY,
                adapter TEXT,
                type TEXT,
                state TEXT,
                mtu INTEGER,
                mac TEXT,
                tx_packets INTEGER,
                rx_packets INTEGER,
                tx_bytes INTEGER,
                rx_bytes INTEGER,
                tx_errors INTEGER,
                rx_errors INTEGER,
                tx_dropped INTEGER,
                rx_dropped INTEGER,
                checksum TEXT,
                item_id TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_netiface
            (scan_id, scan_time, name, type, state, mac, checksum, item_id)
            VALUES (1, '2024/11/26 00:00:00', 'eth0', 'ethernet', 'up', '00:00:00:00:00:00', 'iface_checksum_1', 'iface_1')
        ''')

        # Network protocol table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_netproto (
                iface TEXT,
                type TEXT,
                gateway TEXT,
                dhcp TEXT,
                metric INTEGER,
                checksum TEXT PRIMARY KEY,
                item_id TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_netproto
            (iface, type, gateway, dhcp, checksum, item_id)
            VALUES ('eth0', 'ipv4', '192.168.1.1', 'enabled', 'proto_checksum_1', 'proto_1')
        ''')

        # Network address table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_netaddr (
                iface TEXT,
                proto INTEGER,
                address TEXT,
                netmask TEXT,
                broadcast TEXT,
                checksum TEXT PRIMARY KEY,
                item_id TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_netaddr
            (iface, proto, address, netmask, broadcast, checksum, item_id)
            VALUES ('eth0', 0, '192.168.1.100', '255.255.255.0', '192.168.1.255', 'addr_checksum_1', 'addr_1')
        ''')

        # Ports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_ports (
                scan_id INTEGER,
                scan_time TEXT,
                protocol TEXT,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                tx_queue INTEGER,
                rx_queue INTEGER,
                inode INTEGER,
                state TEXT,
                pid INTEGER,
                process TEXT,
                checksum TEXT PRIMARY KEY,
                item_id TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_ports
            (scan_id, scan_time, protocol, local_ip, local_port, state, checksum, item_id)
            VALUES (1, '2024/11/26 00:00:00', 'tcp', '0.0.0.0', 22, 'listening', 'port_checksum_1', 'port_1')
        ''')

        # Hotfixes table (Windows only, but we create it anyway)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_hotfixes (
                scan_id INTEGER,
                scan_time TEXT,
                hotfix TEXT PRIMARY KEY,
                checksum TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_hotfixes
            (scan_id, scan_time, hotfix, checksum)
            VALUES (1, '2024/11/26 00:00:00', 'KB123456', 'hotfix_checksum_1')
        ''')

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_users (
                scan_id INTEGER,
                scan_time TEXT,
                user TEXT,
                gid INTEGER,
                passwd TEXT,
                comment TEXT,
                home TEXT,
                shell TEXT,
                uid INTEGER PRIMARY KEY,
                checksum TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_users
            (scan_id, scan_time, user, gid, home, shell, uid, checksum)
            VALUES (1, '2024/11/26 00:00:00', 'testuser', 1000, '/home/testuser', '/bin/bash', 1000, 'user_checksum_1')
        ''')

        # Groups table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_groups (
                scan_id INTEGER,
                scan_time TEXT,
                group_name TEXT,
                gid INTEGER PRIMARY KEY,
                checksum TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_groups
            (scan_id, scan_time, group_name, gid, checksum)
            VALUES (1, '2024/11/26 00:00:00', 'testgroup', 1000, 'group_checksum_1')
        ''')

        # Services table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_services (
                scan_id INTEGER,
                scan_time TEXT,
                name TEXT PRIMARY KEY,
                display_name TEXT,
                description TEXT,
                state TEXT,
                start_type TEXT,
                path TEXT,
                checksum TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_services
            (scan_id, scan_time, name, display_name, state, start_type, checksum)
            VALUES (1, '2024/11/26 00:00:00', 'test-service', 'Test Service', 'running', 'auto', 'service_checksum_1')
        ''')

        # Browser extensions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sys_browser_extensions (
                scan_id INTEGER,
                scan_time TEXT,
                name TEXT,
                version TEXT,
                browser TEXT,
                uid TEXT PRIMARY KEY,
                checksum TEXT
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO sys_browser_extensions
            (scan_id, scan_time, name, version, browser, uid, checksum)
            VALUES (1, '2024/11/26 00:00:00', 'test-extension', '1.0', 'chrome', 'ext_1', 'ext_checksum_1')
        ''')

        conn.commit()
    except Exception as e:
        pytest.fail(f"Failed to populate syscollector database: {e}")
    finally:
        conn.close()

    yield SYSCOLLECTOR_DB_PATH


@pytest.fixture()
def clean_syscollector_db():
    """
    Fixture to delete the syscollector database file after test.
    """
    yield

    try:
        if os.path.exists(SYSCOLLECTOR_DB_PATH):
            os.remove(SYSCOLLECTOR_DB_PATH)
    except Exception as e:
        pytest.fail(f"Failed to delete syscollector DB file at {SYSCOLLECTOR_DB_PATH}: {e}")
