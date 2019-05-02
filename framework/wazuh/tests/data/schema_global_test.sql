/*
 * SQL Schema agent tests
 * Copyright (C) 2015-2019, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE IF NOT EXISTS agent (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT,
    register_ip TEXT,
    internal_key TEXT,
    os_name TEXT,
    os_version TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_codename TEXT,
    os_build TEXT,
    os_platform TEXT,
    os_uname TEXT,
    os_arch TEXT,
    version TEXT,
    config_sum TEXT,
    merged_sum TEXT,
    manager_host TEXT,
    node_name TEXT DEFAULT 'unknown',
    date_add TEXT NOT NULL,
    last_keepalive TEXT,
    status TEXT NOT NULL CHECK (status IN ('empty', 'pending', 'updated')) DEFAULT 'empty',
    fim_offset INTEGER NOT NULL DEFAULT 0,
    reg_offset INTEGER NOT NULL DEFAULT 0,
    `group` TEXT DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS agent_name ON agent (name);
CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip);

CREATE TABLE IF NOT EXISTS `group`
    (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT
    );

CREATE TABLE IF NOT EXISTS belongs
    (
    id_agent INTEGER,
    id_group INTEGER,
    PRIMARY KEY (id_agent, id_group)
);

-- manager
INSERT INTO agent (id, name, ip, os_name, os_version, os_major, os_minor, os_codename, os_platform, os_uname, os_arch,
                   version, manager_host, node_name, date_add, last_keepalive, status, `group`) VALUES
                   (0,'master','127.0.0.1','Ubuntu','18.04.1 LTS','18','04','Bionic Beaver','ubuntu',
                   'Linux |master |4.15.0-43-generic |#46-Ubuntu SMP Thu Dec 6 14:45:28 UTC 2018 |x86_64','x86_64',
                   'Wazuh v3.9.0','master','node01',datetime(CURRENT_TIMESTAMP, '-10 days', 'localtime'),'9999-12-31 23:59:59',
                    'updated',NULL);

-- Connected agent with IP and Registered IP filled
INSERT INTO agent (id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename,
                   os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add,
                   last_keepalive, status) VALUES (1,'agent-1','172.17.0.202','any',
                   'b3650e11eba2f27er4d160c69de533ee7eed601636a85ba2455d53a90927747f', 'Ubuntu','18.04.1 LTS','18','04',
                   'Bionic Beaver','ubuntu',
                   'Linux |agent-1 |4.15.0-43-generic |#46-Ubuntu SMP Thu Dec 6 14:45:28 UTC 2018 |x86_64','x86_64',
                   'Wazuh v3.8.2','ab73af41699f13fdd81903b5f23d8d00','f8d49771911ed9d5c45b03a40babd065','master',
                   'node01',datetime(CURRENT_TIMESTAMP, '-4 days', 'localtime'),
                    datetime(CURRENT_TIMESTAMP, '-5 seconds', 'localtime'),'updated');

-- Connected agent with just Registered IP filled
INSERT INTO agent (id, name, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename,
                   os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add,
                   last_keepalive, status) VALUES (2,'agent-2','172.17.0.201',
                   'b3650e11eba2f27er4d160c69de533ee7eed6016fga85ba2455d53a90927747f', 'Ubuntu','18.04.1 LTS','18','04',
                   'Bionic Beaver','ubuntu',
                   'Linux |agent-1 |4.15.0-43-generic |#46-Ubuntu SMP Thu Dec 6 14:45:28 UTC 2018 |x86_64','x86_64',
                   'Wazuh v3.6.2','ab73af41699f13fgt81903b5f23d8d00','f8d49771911ed9d5c45bdfa40babd065','master',
                   'node01',datetime(CURRENT_TIMESTAMP, '-3 days', 'localtime'),
                    datetime(CURRENT_TIMESTAMP, '-10 minutes', 'localtime'),'updated');

-- Never connected agent
INSERT INTO agent (id, name, register_ip, internal_key, date_add, `group`) VALUES (3,'nc-agent','any',
                   'f304f582f2417a3fddad69d9ae2b4f3b6e6fda788229668af9a6934d454ef44d',
                   datetime(CURRENT_TIMESTAMP, '-3 days', 'localtime'), NULL);

-- Pending agent
INSERT INTO agent (id, name, register_ip, internal_key, manager_host, date_add, last_keepalive, `group`) VALUES
                  (4,'pending-agent', 'any', '2855bcf49273c759ef5b116829cc582f153c6c199df7676e53d5937855ff5902', '',
                   datetime(CURRENT_TIMESTAMP, '-1 minute', 'localtime'), datetime(CURRENT_TIMESTAMP, '-10 seconds', 'localtime'), NULL);


-- Disconnected agent
INSERT INTO agent (id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename,
                   os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add,
                   last_keepalive, status) VALUES (5,'agent-5','172.17.0.300','172.17.0.300',
                   'b3650e11eba2f27er4d160c69de533ee7eed601636a42ba2455d53a90927747f', 'Ubuntu','18.04.1 LTS','18','04',
                   'Bionic Beaver','ubuntu',
                   'Linux |agent-1 |4.15.0-43-generic |#46-Ubuntu SMP Thu Dec 6 14:45:28 UTC 2018 |x86_64','x86_64',
                   'Wazuh v3.8.2','ab73af41699f13fdd81903b5f23d8d00','f8d49771911ed9d5c45b03a40babd065','master',
                   'node01',datetime(CURRENT_TIMESTAMP, '-5 days', 'localtime'),
                    datetime(CURRENT_TIMESTAMP, '-1 hour', 'localtime'),'updated');
