/*
 * SQL Schema security tests
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */
--
-- CREATE TABLE users (username VARCHAR(32) NOT NULL, password VARCHAR(256), auth_context BOOLEAN DEFAULT FALSE NOT NULL, created_at DATETIME, PRIMARY KEY (username));
--
-- CREATE TABLE roles (id INTEGER NOT NULL, name VARCHAR(20), rule TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT name_role UNIQUE (name), CONSTRAINT role_definition UNIQUE (rule));
--
-- CREATE TABLE policies (id INTEGER NOT NULL, name VARCHAR(20), policy TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT name_policy UNIQUE (name),	CONSTRAINT policy_definition UNIQUE (policy));
--
-- CREATE TABLE roles_policies (id INTEGER NOT NULL, role_id INTEGER, policy_id INTEGER, level INTEGER, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT role_policy UNIQUE (role_id, policy_id), FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE, FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE CASCADE);
--
-- CREATE TABLE user_roles (id INTEGER NOT NULL, user_id INTEGER, role_id INTEGER, level INTEGER,	created_at DATETIME, PRIMARY KEY (id), CONSTRAINT user_role UNIQUE (user_id, role_id), FOREIGN KEY(user_id) REFERENCES users (username) ON DELETE CASCADE, FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE);

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

/* Testing user */
INSERT INTO users VALUES('testing','pbkdf2:sha256:150000$OMVAATei$cb30da77537eea26b964265dab6f403e9499f18522c7cc9e6ba2cb2d33694e1f',0,'1970-01-01 00:00:00');

/* Testing role */
INSERT INTO roles VALUES(99,'testing','{"FIND": {"r''^testing$''": ["testing"]}}','1970-01-01 00:00:00');

/* Testing roles-policies links */
INSERT INTO roles_policies VALUES(17,99,1,0,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(18,99,3,1,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(19,99,4,2,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(20,99,9,3,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(21,99,6,4,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(22,99,7,5,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(23,99,8,6,'1970-01-01 00:00:00');

/* Testing user-role link */
INSERT INTO user_roles VALUES(3,'testing',99,0,'1970-01-01 00:00:00');

COMMIT;
