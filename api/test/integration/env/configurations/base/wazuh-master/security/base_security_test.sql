/*
 * SQL Schema security tests
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

/* Testing user */
INSERT INTO users VALUES('testing','pbkdf2:sha256:150000$OMVAATei$cb30da77537eea26b964265dab6f403e9499f18522c7cc9e6ba2cb2d33694e1f',0,'1970-01-01 00:00:00');

/* Testing role */
INSERT INTO roles VALUES(99,'testing','{"FIND": {"r''^testing$''": ["testing"]}}','1970-01-01 00:00:00');

/* Testing roles-policies links */
INSERT INTO roles_policies VALUES(99,99,1,0,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(100,99,3,1,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(101,99,4,2,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(102,99,9,3,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(103,99,6,4,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(104,99,7,5,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(105,99,8,6,'1970-01-01 00:00:00');

/* Testing user-role link */
INSERT INTO user_roles VALUES(99,'testing',99,0,'1970-01-01 00:00:00');

COMMIT;
