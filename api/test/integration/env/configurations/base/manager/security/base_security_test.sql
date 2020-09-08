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
INSERT INTO users VALUES(99,'testing','pbkdf2:sha256:150000$OMVAATei$cb30da77537eea26b964265dab6f403e9499f18522c7cc9e6ba2cb2d33694e1f',0,'1970-01-01 00:00:00');

/* Testing role */
INSERT INTO roles VALUES(99,'testing','1970-01-01 00:00:00');

/* Testing rule */
INSERT INTO rules VALUES(99,'testing','{"FIND": {"r''testing''": "integration"}}','1970-01-01 00:00:00');

/* Testing roles-policies links */
INSERT INTO roles_policies VALUES(1000,99,1,0,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1001,99,2,1,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1002,99,3,2,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1003,99,6,3,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1004,99,7,4,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1005,99,8,5,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1006,99,20,6,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1007,99,21,7,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1008,99,22,8,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1009,99,23,9,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1010,99,11,10,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1011,99,12,11,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1012,99,14,12,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1013,99,15,13,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1014,99,13,14,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1015,99,18,15,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1016,99,19,16,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(1017,99,16,17,'1970-01-01 00:00:00');

/* Testing role-rules link */
INSERT INTO roles_rules VALUES(99,99,99,'1970-01-01 00:00:00');

/* Testing user-role link */
INSERT INTO user_roles VALUES(99,99,99,0,'1970-01-01 00:00:00');

COMMIT;
