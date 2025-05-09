/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * April 3, 2025.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

/* FIM and syscollector will be indexed. We clean the data. No real schema change.*/
DELETE FROM fim_entry;
DELETE FROM sys_netiface;
DELETE FROM sys_netproto;
DELETE FROM sys_netaddr;
DELETE FROM sys_osinfo;
DELETE FROM sys_hwinfo;
DELETE FROM sys_ports;
DELETE FROM sys_programs;
DELETE FROM sys_hotfixes;
DELETE FROM sys_processes;
DELETE FROM scan_info WHERE module IN ('fim', 'syscollector');
DELETE FROM sync_info;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 15);

INSERT INTO scan_info (module) VALUES ('fim');
INSERT INTO scan_info (module) VALUES ('syscollector');
INSERT INTO sync_info (component) VALUES ('fim');
INSERT INTO sync_info (component) VALUES ('fim_file');
INSERT INTO sync_info (component) VALUES ('fim_registry');
INSERT INTO sync_info (component) VALUES ('fim_registry_key');
INSERT INTO sync_info (component) VALUES ('fim_registry_value');
INSERT INTO sync_info (component) VALUES ('syscollector-processes');
INSERT INTO sync_info (component) VALUES ('syscollector-packages');
INSERT INTO sync_info (component) VALUES ('syscollector-hotfixes');
INSERT INTO sync_info (component) VALUES ('syscollector-ports');
INSERT INTO sync_info (component) VALUES ('syscollector-netproto');
INSERT INTO sync_info (component) VALUES ('syscollector-netaddress');
INSERT INTO sync_info (component) VALUES ('syscollector-netinfo');
INSERT INTO sync_info (component) VALUES ('syscollector-hwinfo');
INSERT INTO sync_info (component) VALUES ('syscollector-osinfo');

COMMIT;
