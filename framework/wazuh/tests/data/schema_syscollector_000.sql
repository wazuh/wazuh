/*
 * SQL Schema SCA tests
 * Copyright (C) 2015, Wazuh Inc.
 * March 21, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

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
    os_build TEXT,
    os_platform TEXT,
    sysname TEXT,
    release TEXT,
    version TEXT,
    os_release TEXT,
    os_display_version TEXT,
    PRIMARY KEY (scan_id, os_name)
);

CREATE TABLE IF NOT EXISTS sys_hwinfo (
    scan_id INTEGER,
    scan_time TEXT,
    board_serial TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER CHECK (cpu_cores > 0),
    cpu_mhz REAL CHECK (cpu_mhz > 0),
    ram_total INTEGER CHECK (ram_total > 0),
    ram_free INTEGER CHECK (ram_free > 0),
    ram_usage INTEGER CHECK (ram_usage >= 0 AND ram_usage <= 100),
    PRIMARY KEY (scan_id, board_serial)
);

CREATE TABLE IF NOT EXISTS sys_programs (
    scan_id INTEGER,
    scan_time TEXT,
    format TEXT,
    name TEXT,
    priority TEXT,
    section TEXT,
    size INTEGER CHECK (size >= 0),
    vendor TEXT,
    install_time TEXT,
    version TEXT,
    architecture TEXT,
    multiarch TEXT,
    source TEXT,
    description TEXT,
    location TEXT,
    triaged INTEGER(1),
    PRIMARY KEY (scan_id, name, version, architecture, format, location)
);

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
    PRIMARY KEY (scan_id, pid)
);

CREATE INDEX IF NOT EXISTS processes_id ON sys_processes (scan_id);

CREATE INDEX IF NOT EXISTS programs_id ON sys_programs (scan_id);

CREATE TABLE IF NOT EXISTS sys_ports (
    scan_id INTEGER,
    scan_time TEXT,
    protocol TEXT,
    local_ip TEXT,
    local_port INTEGER CHECK (local_port >= 0),
    remote_ip TEXT,
    remote_port INTEGER CHECK (remote_port >= 0),
    tx_queue INTEGER,
    rx_queue INTEGER,
    inode INTEGER,
    state TEXT,
    PID INTEGER,
    process TEXT
);

CREATE INDEX IF NOT EXISTS ports_id ON sys_ports (scan_id);

CREATE TABLE IF NOT EXISTS sys_netiface (
    scan_id INTEGER,
    scan_time TEXT,
    name TEXT,
    adapter TEXT,
    type TEXT,
    state TEXT,
    mtu INTEGER CHECK (mtu > 0),
    mac TEXT,
    tx_packets INTEGER,
    rx_packets INTEGER,
    tx_bytes INTEGER,
    rx_bytes INTEGER,
    tx_errors INTEGER,
    rx_errors INTEGER,
    tx_dropped INTEGER,
    rx_dropped INTEGER,
    PRIMARY KEY (scan_id, name)
);

CREATE INDEX IF NOT EXISTS netiface_id ON sys_netiface (scan_id);

CREATE TABLE IF NOT EXISTS sys_netproto (
    scan_id INTEGER REFERENCES sys_netiface (scan_id),
    iface TEXT REFERENCES sys_netiface (name),
    type TEXT,
    gateway TEXT,
    dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown',
    metric INTEGER,
    PRIMARY KEY (scan_id, iface, type)
);

CREATE INDEX IF NOT EXISTS netproto_id ON sys_netproto (scan_id);


CREATE TABLE IF NOT EXISTS sys_netaddr (
    scan_id INTEGER REFERENCES sys_netproto (scan_id),
    iface TEXT REFERENCES sys_netproto (iface),
    proto TEXT REFERENCES sys_netproto (type),
    address TEXT,
    netmask TEXT,
    broadcast TEXT,
    PRIMARY KEY (scan_id, iface, proto, address)
);

CREATE INDEX IF NOT EXISTS netaddr_id ON sys_netaddr (scan_id);

CREATE TABLE IF NOT EXISTS sys_hotfixes (
    scan_id INTEGER,
    scan_time TEXT,
    hotfix TEXT,
    PRIMARY KEY (scan_id)
);

CREATE INDEX IF NOT EXISTS hotfixes_id ON sys_hotfixes (scan_id);


INSERT INTO sys_osinfo VALUES (2011369005, '2019/03/21 10:25:00', 'master', 'x86_64', 'Ubuntu',
                               '18.04.2 LTS (Bionic Beaver)', 'Bionic Beaver', '18', '04', null, 'ubuntu', 'Linux',
                               '4.15.0-46-generic', '#49-Ubuntu SMP Wed Feb 6 09:33:07 UTC 2019', 'Ubuntu 20.04', null);

INSERT INTO sys_osinfo VALUES (2011369001, '2019/03/21 10:25:00', 'agent', 'x86_64', 'Centos',
                               '18.04.2 LTS (Bionic Beaver)', 'Bionic Beaver', '18', '04', null, 'Centos', 'Linux',
                               '4.15.0-46-generic', '#49-Ubuntu SMP Wed Feb 6 09:33:07 UTC 2019', 'Debian 10', null);

INSERT INTO sys_hwinfo VALUES (2089525312, '2019/03/21 11:25:00', '0', 'Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz', 2,
                               1992.001, 492832, 64032, 88);

INSERT INTO sys_programs VALUES (95033803, '2019/03/21 13:25:00', 'deb', 'wazuh-manager', 'extra', 'admin', 320462,
                                 'Wazuh', null, '3.9.0-1', 'amd64', null, null,
                                 'Wazuh helps you to gain security visibility into your infrastructure by monitoring hosts at an operating system and application level. It provides the following capabilities: log analysis, file integrity monitoring, intrusions detection and policy and compliance monitoring',
                                 null, 0);
INSERT INTO sys_programs VALUES (95033803, '2019/03/21 13:25:00', 'deb', 'curl', 'optional', 'web', 386,
                                 'Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>', null, '7.58.0-2ubuntu3.6',
                                 'amd64', 'foreign', null, 'command line tool for transferring data with URL syntax',
                                 null, 0);
INSERT INTO sys_programs VALUES (95033803, '2019/03/21 13:25:00', 'deb', 'libpcre3', 'required', 'libs', 665,
                                 'Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>', null, '2:8.39-9', 'amd64',
                                 'same', 'pcre3', 'Old Perl 5 Compatible Regular Expression Library - runtime files',
                                 null, 0);
INSERT INTO sys_programs VALUES (1554688024, '2019/03/21 14:18:35', 'deb', 'libnewt0.52', 'important', 'libs', 188,
                                 'Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>', null, '0.52.20-1ubuntu1',
                                 'amd64', 'same', 'newt', 'Not Eriks Windowing Toolkit - text mode windowing with slang',
                                 null, 0);

INSERT INTO sys_processes VALUES (1794805470, '2019/03/21 13:25:06', 8012, 'python3', 'S', 1, 850, 111,
                                  '/var/ossec/framework/python/bin/python3', '/var/ossec/framework/scripts/wazuh_clusterd.py',
                                  'ossec', 'ossec', 'ossec', 'ossec', 'ossec', 'ossec', 'ossec', 20, 0, 30264, 121056,
                                  5621, 1211, 15073, 8011, 8011, 1, 8012, 0, 0);
INSERT INTO sys_processes VALUES (1794805470, '2019/03/21 13:25:06', 1, 'systemd', 'S', 0, 146, 744, '/sbin/init', null,
                                  'root', 'root', 'root', 'root', 'root', 'root', 'root', 20, 0, 56348, 225392, 1968,
                                  1348, 6, 1, 1, 1, 1, 0, 1);
INSERT INTO sys_processes VALUES (1794805470, '2019/03/21 13:25:06', 12, 'cpuhp/0', 'S', 2, 0, 0, null, null, 'root',
                                  'root', 'root', 'root', 'root', 'root', 'root', 20, 0, 0, 0, 0, 0, 8, 0, 0, 1, 12, 0,
                                  0);
INSERT INTO sys_processes VALUES (1521105854, '2019/03/21 14:18:43', 12159, 'sftp-server', 'S', 12056, 0, 0,
                                  '/usr/lib/openssh/sftp-server', null, 'vagrant', 'vagrant', 'vagrant', 'vagrant',
                                  'vagrant', 'vagrant', 'vagrant', 20, 0, 3265, 13060, 498, 467, 1361072, 12159, 12159,
                                  1, 12159, 0, 1);

INSERT INTO sys_ports VALUES (1662320195, '2019/03/21 14:18:43', 'tcp', '0.0.0.0', 22, '0.0.0.0', 0, 0, 0, 18662,
                              'listening', null, null);
INSERT INTO sys_ports VALUES (1662320195, '2019/03/21 14:18:43', 'tcp', '10.0.2.15', 22, '10.0.2.2', 63954, 0, 0,
                              118343, 'established', null, null);
INSERT INTO sys_ports VALUES (1662320195, '2019/03/21 14:18:43', 'udp', '127.0.0.53', 53, '0.0.0.0', 0, 0, 0, 277490,
                              null, null, null);
INSERT INTO sys_ports VALUES (1662320195, '2019/03/21 14:18:43', 'tcp6', '::', 22, '::', 0, 0, 0, 18664, 'listening',
                              null, null);

INSERT INTO sys_netiface VALUES (1068672241, '2019/03/21 14:18:35', 'enp0s3', null, 'ethernet', 'up', 1500,
                                 '02:27:c3:d8:5a:c8', 33402, 95186, 3960190, 85014393, 0, 0, 0, 0);
INSERT INTO sys_netiface VALUES (1068672241, '2019/03/21 14:18:35', 'enp0s8', null, 'ethernet', 'up', 1500,
                                 '08:00:27:52:24:b6', 626, 21, 209292, 1932, 0, 0, 0, 0);

INSERT INTO sys_netproto VALUES (1068672241, 'enp0s3', 'ipv4', '10.0.2.2', 'enabled', 100);
INSERT INTO sys_netproto VALUES (1068672241, 'enp0s3', 'ipv6', null, 'enabled', null);
INSERT INTO sys_netproto VALUES (1068672241, 'enp0s8', 'ipv4', 'unknown', 'enabled', null);
INSERT INTO sys_netproto VALUES (1068672241, 'enp0s8', 'ipv6', null, 'enabled', null);

INSERT INTO sys_netaddr VALUES (1068672241, 'enp0s3', 'ipv4', '10.0.2.15', '255.255.255.0', '10.0.2.255');
INSERT INTO sys_netaddr VALUES (1068672241, 'enp0s3', 'ipv6', 'fe80::27:c3ff:fed8:5ac8', 'ffff:ffff:ffff:ffff::', null);
INSERT INTO sys_netaddr VALUES (1068672241, 'enp0s8', 'ipv4', '172.17.0.100', '255.255.255.0', '172.17.0.255');
INSERT INTO sys_netaddr VALUES (1068672241, 'enp0s8', 'ipv6', 'fe80::a00:27ff:fe52:24b6', 'ffff:ffff:ffff:ffff::', null);

INSERT INTO sys_hotfixes VALUES (1068372250, '2019/03/21 14:18:35', 'Hotfix mocked');
