/*
 * SQL Schema security tests
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE users (username VARCHAR(32) NOT NULL, password VARCHAR(256), auth_context BOOLEAN DEFAULT FALSE NOT NULL, created_at DATETIME, PRIMARY KEY (username));

CREATE TABLE roles (id INTEGER NOT NULL, name VARCHAR(20), rule TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT name_role UNIQUE (name), CONSTRAINT role_definition UNIQUE (rule));

CREATE TABLE policies (id INTEGER NOT NULL, name VARCHAR(20), policy TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT name_policy UNIQUE (name),	CONSTRAINT policy_definition UNIQUE (policy));

CREATE TABLE roles_policies (id INTEGER NOT NULL, role_id INTEGER, policy_id INTEGER, level INTEGER, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT role_policy UNIQUE (role_id, policy_id), FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE, FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE CASCADE);

CREATE TABLE user_roles (id INTEGER NOT NULL, user_id INTEGER, role_id INTEGER, level INTEGER,	created_at DATETIME, PRIMARY KEY (id), CONSTRAINT user_role UNIQUE (user_id, role_id), FOREIGN KEY(user_id) REFERENCES users (username) ON DELETE CASCADE, FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE);

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

INSERT INTO users VALUES('wazuh','pbkdf2:sha256:150000$9t52lMSc$d554357cbfdbbf1273abd417369dfd6ae865ae1a652938c7a46eb64d283f21d9',0,'2020-03-31 11:41:50.713705');
INSERT INTO users VALUES('wazuh-wui','pbkdf2:sha256:150000$4auJCTdt$04cdc511a603da1bd10eaede1c30f8c1a06d7912f65fdf977da81c22c46df970',1,'2020-03-31 11:41:50.813904');

INSERT INTO roles VALUES(1,'administrator','{"FIND": {"r''^auth[a-zA-Z]+$''": ["full_admin"]}}','2020-03-31 11:41:50.840134');
INSERT INTO roles VALUES(2,'readonly','{"FIND": {"r''^auth[a-zA-Z]+$''": ["readonly"]}}','2020-03-31 11:41:50.851744');
INSERT INTO roles VALUES(3,'users_admin','{"FIND": {"r''^auth[a-zA-Z]+$''": ["users_admin"]}}','2020-03-31 11:41:50.860923');
INSERT INTO roles VALUES(4,'agents_readonly','{"FIND": {"r''^auth[a-zA-Z]+$''": ["agents_readonly"]}}','2020-03-31 11:41:50.874979');
INSERT INTO roles VALUES(5,'agents_admin','{"FIND": {"r''^auth[a-zA-Z]+$''": ["agents_admin"]}}','2020-03-31 11:41:50.889540');
INSERT INTO roles VALUES(6,'cluster_readonly','{"FIND": {"r''^auth[a-zA-Z]+$''": ["cluster_readonly"]}}','2020-03-31 11:41:50.903301');
INSERT INTO roles VALUES(7,'cluster_admin','{"FIND": {"r''^auth[a-zA-Z]+$''": ["cluster_admin"]}}','2020-03-31 11:41:50.916122');

INSERT INTO policies VALUES(1,'agents_all','{"actions": ["agent:read", "agent:create", "agent:delete", "agent:modify_group", "agent:restart", "agent:upgrade", "group:read", "group:delete", "group:create", "group:update_config", "group:modify_assignments"], "resources": ["agent:id:*", "group:id:*"], "effect": "allow"}','2020-03-31 11:41:50.967333');
INSERT INTO policies VALUES(2,'agents_read','{"actions": ["agent:read", "group:read"], "resources": ["agent:id:*", "group:id:*"], "effect": "allow"}','2020-03-31 11:41:50.977211');
INSERT INTO policies VALUES(3,'agents_commands','{"actions": ["active_response:send_command"], "resources": ["agent:id:*"], "effect": "allow"}','2020-03-31 11:41:50.989241');
INSERT INTO policies VALUES(4,'security_all','{"actions": ["security:read", "security:create", "security:update", "security:delete"], "resources": ["role:id:*", "policy:id:*", "user:id:*"], "effect": "allow"}','2020-03-31 11:41:51.000714');
INSERT INTO policies VALUES(5,'users_all','{"actions": ["security:read", "security:create", "security:update", "security:delete"], "resources": ["user:id:*"], "effect": "allow"}','2020-03-31 11:41:51.012433');
INSERT INTO policies VALUES(6,'ciscat_read','{"actions": ["ciscat:read"], "resources": ["agent:id:*"], "effect": "allow"}','2020-03-31 11:41:51.024947');
INSERT INTO policies VALUES(7,'decoders_read','{"actions": ["decoders:read"], "resources": ["decoder:file:*"], "effect": "allow"}','2020-03-31 11:41:51.038825');
INSERT INTO policies VALUES(8,'rules_read','{"actions": ["rules:read"], "resources": ["rules:file:*"], "effect": "allow"}','2020-03-31 11:41:51.052835');
INSERT INTO policies VALUES(9,'cluster_all','{"actions": ["cluster:read_config", "cluster:restart", "cluster:status", "cluster:read_file", "cluster:upload_file", "cluster:delete_file", "manager:read_config", "manager:delete_file", "manager:read_file", "manager:upload_file", "manager:restart"], "resources": ["file:path:*", "node:id:*", "node:id:*&file:path:*"], "effect": "allow"}','2020-03-31 11:41:51.067165');
INSERT INTO policies VALUES(10,'cluster_read','{"actions": ["cluster:read_config", "cluster:status", "cluster:read_file", "manager:read_config", "manager:read_file"], "resources": ["file:path:*", "node:id:*", "node:id:*&file:path:*"], "effect": "allow"}','2020-03-31 11:41:51.080980');

INSERT INTO roles_policies VALUES(1,1,1,0,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(2,1,3,1,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(3,1,4,2,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(4,1,9,3,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(5,1,6,4,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(6,1,7,5,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(7,1,8,6,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(8,2,2,0,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(9,2,6,1,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(10,2,7,2,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(11,2,8,3,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(12,3,5,0,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(13,4,2,0,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(14,5,1,0,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(15,6,10,0,'2020-03-31 11:41:50.517771');
INSERT INTO roles_policies VALUES(16,7,9,0,'2020-03-31 11:41:50.517771');

INSERT INTO user_roles VALUES(1,'wazuh',1,0,'2020-03-31 11:41:50.521106');
INSERT INTO user_roles VALUES(2,'wazuh-wui',2,0,'2020-03-31 11:41:50.521106');
COMMIT;
