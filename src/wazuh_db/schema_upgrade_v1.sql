/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2019, Wazuh Inc.
 * December, 2018.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

ALTER TABLE fim_entry ADD COLUMN attributes INTEGER DEFAULT 0;

DROP TABLE IF EXISTS _sys_netaddr;

CREATE TABLE IF NOT EXISTS _sys_netaddr (
    scan_id INTEGER REFERENCES sys_netproto (scan_id),
    iface TEXT REFERENCES sys_netproto (iface),
    proto TEXT REFERENCES sys_netproto (type),
    address TEXT,
    netmask TEXT,
    broadcast TEXT,
    PRIMARY KEY (scan_id, iface, proto, address)
);

PRAGMA foreign_keys = OFF;

DROP TABLE sys_netaddr;

ALTER TABLE _sys_netaddr RENAME TO sys_netaddr;

PRAGMA foreign_keys = ON;

INSERT INTO metadata (key, value) VALUES ('db_version', '1');

END;