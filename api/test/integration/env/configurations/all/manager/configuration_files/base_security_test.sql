/*
 * SQL Schema all denied tests
 * Copyright (C) 2015, Wazuh Inc.
 * February 12, 2021.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

/* Testing user without any role assigned (no permissions) */
INSERT INTO users VALUES(99,'testing','pbkdf2:sha256:150000$OMVAATei$cb30da77537eea26b964265dab6f403e9499f18522c7cc9e6ba2cb2d33694e1f',0,'1970-01-01 00:00:00');

COMMIT;
